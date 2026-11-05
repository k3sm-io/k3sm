/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/interconnect"
)

// Pod opt-in to an interconnect.
//
// A pod annotated k3sm.io/interconnects: <name>[,…] gets, at create, a second
// address on the node's interconnect: a free slot of the node's /24, a /32
// alias the root helper puts on bridge0, the K3SM_INTERCONNECT_* env the pod
// shim reads, and the k3sm.io/InterconnectAttached pod condition. The node
// reads neither the Interconnect nor MLXModel; every fact the attach needs
// rides the desired annotation the server writes on this node's own Node
// (netv1alpha1.InterconnectDesired).
//
// Every refusal is named, recorded as a Warning Event, and decided by the
// interconnect's fallback: network starts the pod without the address and the
// condition False; none holds the create. The fallback lives in the desired
// annotation, which only an armed member node carries, so fallback none is
// enforced on armed member nodes only: on a node that is not a member the pod
// cannot learn it, and the attach degrades to network (with the Warning Event).
//
// The source pin the env sets up is attribution by cooperation, not an
// identity boundary: any process on the host may bind any bridge0 alias. The
// authority to use the cable is the admin's arming act; the checks here bound
// which pods attach for trusted tenancy.

// Reasons the attach condition and Event carry beyond the apis-defined
// InterconnectUnsupportedRuntime and InterconnectSlotsExhausted. A refusal by
// the root helper carries the helper's own reason (wire.ReasonOf, or
// interconnect.ReasonHelperTooOld).
const (
	// ReasonInterconnectNotMember: this node's desired annotation does not name
	// any interconnect the pod asked for (unarmed, excluded, or not a member).
	ReasonInterconnectNotMember = "InterconnectNotMember"
	// ReasonInterconnectNamespaceNotAllowed: the interconnect's
	// allowedNamespaces does not list the pod's namespace.
	ReasonInterconnectNamespaceNotAllowed = "InterconnectNamespaceNotAllowed"
	// ReasonInterconnectNoHelper: this node runs without the root helper, which
	// alone can put an interconnect alias on bridge0.
	ReasonInterconnectNoHelper = "InterconnectNoHelper"
	// ReasonInterconnectHelperError: the root helper failed without a named
	// reason.
	ReasonInterconnectHelperError = "InterconnectHelperError"
	// ReasonInterconnectModelMismatch: a pod restored on slot 1 (an MLX rank's
	// slot) has a controller ownerReference that names no MLXModel the desired
	// annotation lists by namespace, name and UID, so it was demoted.
	ReasonInterconnectModelMismatch = "InterconnectModelMismatch"
	// ReasonInterconnectFailed is the Warning Event reason of every refused
	// attach; its message names the specific reason and the fallback taken.
	ReasonInterconnectFailed = "InterconnectAttachFailed"

	// runtimeClassContainerVM is the container-vm RuntimeClass (one Linux VM per container), refused like vm.
	runtimeClassContainerVM = "container-vm"
	// envInterconnectPrefix names every variable the attach owns in a pod that
	// asked for an interconnect.
	envInterconnectPrefix = "K3SM_INTERCONNECT_"
	// interconnectRemoveTimeout bounds an alias removal that has no caller
	// context (the ctx-less teardown, a demotion found on a status tick).
	interconnectRemoveTimeout = 15 * time.Second
)

// errInterconnectDesiredUnknown holds a create while this node's own Node is
// not in its cache yet: deciding membership on missing information would start
// a pod without the address it asked for.
var errInterconnectDesiredUnknown = errors.New("interconnect attach: this node's desired interconnect is not known yet")

// InterconnectAliasClient is the root helper's interconnect alias surface
// (darwin-net's wire.Client): it derives every address itself from the slot.
type InterconnectAliasClient interface {
	EnsureInterconnectAlias(ctx context.Context, slot int) (netip.Addr, error)
	RemoveInterconnectAlias(ctx context.Context, slot int) error
}

// InterconnectConfig wires the pod interconnect attach.
type InterconnectConfig struct {
	// Aliases is the root helper; nil (a node without one) refuses every
	// attach with ReasonInterconnectNoHelper.
	Aliases InterconnectAliasClient
	// Desired returns this node's k3sm.io/interconnect-desired annotation and
	// whether the node's own Node is known (an informer that has synced and
	// holds it). nil reads as known and absent: no attach succeeds.
	Desired func() (value string, synced bool)
}

// interconnectRecord is one pod's attach outcome, kept for the pod's life.
type interconnectRecord struct {
	attached bool
	slot     int
	addr     netip.Addr
	cond     corev1.PodCondition
	// provisional marks a slot-1 pod restored before the desired annotation
	// was readable; recheck verifies its model and demotes it on a mismatch.
	provisional bool
	// pod is the restored pod's identity and controller reference, which the
	// provisional re-check reads (nil when not provisional).
	pod *corev1.Pod
}

// interconnectAttacher owns the node's pod slots 1..MaxInterconnectSlot.
//
// Locking: opMu serialises attach, restore, recheck and detach, and is held
// across the root-helper call, so a slot is never handed out while its alias is
// being added or removed. mu guards slots and pods for the status and env
// readers, which never wait on the helper. opMu is always taken before mu.
type interconnectAttacher struct {
	cfg InterconnectConfig
	rec record.EventRecorder
	log *slog.Logger
	now func() time.Time

	opMu sync.Mutex
	// lastParseErr is the last unreadable desired value's error, so it is
	// warned once per change. Guarded by opMu.
	lastParseErr string

	mu    sync.Mutex
	slots [netv1alpha1.MaxInterconnectSlot + 1]string // slot -> pod id; slot 0 is never used
	pods  map[string]*interconnectRecord              // pod id -> outcome
}

func newInterconnectAttacher(cfg InterconnectConfig, rec record.EventRecorder, log *slog.Logger) *interconnectAttacher {
	return &interconnectAttacher{cfg: cfg, rec: rec, log: log, now: time.Now, pods: map[string]*interconnectRecord{}}
}

// requestedInterconnects returns the names the pod's k3sm.io/interconnects
// annotation lists, or nil when it asks for none.
func requestedInterconnects(pod *corev1.Pod) []string {
	var out []string
	for _, n := range strings.Split(pod.Annotations[netv1alpha1.AnnotationInterconnects], ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// interconnectUnsupportedRuntime reports whether the pod runs in a guest (vm or
// container-vm), which the interconnect does not reach at v1.
func interconnectUnsupportedRuntime(pod *corev1.Pod) bool {
	if rc := pod.Spec.RuntimeClassName; rc != nil && (*rc == string(runtimev1.HandlerVM) || *rc == runtimeClassContainerVM) {
		return true
	}
	backend, err := podSandboxBackend(pod)
	return err == nil && backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM
}

// isMLXRank reports whether the pod's controller ownerReference is an MLXModel
// (group mlx.k3sm.io) that the desired annotation lists by the pod's own
// namespace, the reference's name and its UID, all three. The kind and group
// alone are spoofable by any pod author, and so is a real UID copied from
// another model's rank; only the full match against the server's list of
// existing interconnect MLXModels grants slot 1.
func isMLXRank(pod *corev1.Pod, desired netv1alpha1.InterconnectDesired) bool {
	ref := metav1.GetControllerOf(pod)
	if !isMLXOwnerShape(ref) {
		return false
	}
	return desired.HasMLXModel(pod.Namespace, ref.Name, string(ref.UID))
}

func isMLXOwnerShape(ref *metav1.OwnerReference) bool {
	if ref == nil || ref.Kind != "MLXModel" {
		return false
	}
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	return err == nil && gv.Group == mlxv1alpha1.GroupName
}

// slotOf returns the slot an interconnect address encodes, the inverse of
// netv1alpha1.InterconnectSlotAddress, and false for any other address.
func slotOf(addr netip.Addr) (int, bool) {
	if !addr.Is4() || !netip.MustParsePrefix(netv1alpha1.InterconnectCIDR).Contains(addr) {
		return 0, false
	}
	o := int(addr.As4()[3])
	if o < 1 {
		return 0, false
	}
	idx, slot := (o-1)/(netv1alpha1.MaxInterconnectSlot+1), (o-1)%(netv1alpha1.MaxInterconnectSlot+1)
	if a, err := netv1alpha1.InterconnectSlotAddress(idx, slot); err != nil || a != addr {
		return 0, false
	}
	return slot, true
}

// helperReason names a root-helper error.
func helperReason(err error) string {
	switch {
	case errors.Is(err, wire.ErrHelperTooOld):
		return interconnect.ReasonHelperTooOld
	case wire.ReasonOf(err) != "":
		return wire.ReasonOf(err)
	default:
		return ReasonInterconnectHelperError
	}
}

// readDesired returns this node's desired annotation: known false while the
// node's own Node is not in the cache, member false when it is absent or
// unreadable. An unreadable value is warned once per change. Called with opMu
// held.
func (a *interconnectAttacher) readDesired() (d netv1alpha1.InterconnectDesired, known, member bool) {
	if a.cfg.Desired == nil {
		return d, true, false
	}
	value, synced := a.cfg.Desired()
	if !synced {
		return d, false, false
	}
	if value == "" {
		a.lastParseErr = ""
		return d, true, false
	}
	d, err := netv1alpha1.ParseInterconnectDesired(value)
	if err != nil {
		// Treated as absent, the node's safe reading; the server overwrites it.
		if msg := err.Error(); msg != a.lastParseErr {
			a.lastParseErr = msg
			a.log.Warn("interconnect: this node's desired annotation is unreadable; treating the node as not a member", "err", err)
		}
		return netv1alpha1.InterconnectDesired{}, true, false
	}
	a.lastParseErr = ""
	return d, true, true
}

// attachFailure is a refused attach: the reason the condition and Event carry,
// a human message, and the fallback that decides between starting the pod
// without the address and holding it.
type attachFailure struct {
	reason, message string
	fallback        netv1alpha1.InterconnectFallback
}

// attach runs the create-time attach for pod, once per pod: a later call
// returns the recorded outcome. It returns nil for a pod that asks for no
// interconnect or whose attach is recorded (attached, or refused under
// fallback network, where the pod starts without the address). Every refusal
// records a Warning Event. It returns an error to hold the create under
// fallback none, and while the desired annotation is not known yet.
func (a *interconnectAttacher) attach(ctx context.Context, pod *corev1.Pod) error {
	names := requestedInterconnects(pod)
	if len(names) == 0 {
		return nil
	}
	id := string(pod.UID)
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.mu.Lock()
	_, done := a.pods[id]
	a.mu.Unlock()
	if done {
		return nil
	}
	r, fail, err := a.tryAttach(ctx, pod, names)
	if err != nil {
		return err
	}
	if fail != nil {
		a.log.Warn("interconnect attach refused", "namespace", pod.Namespace, "name", pod.Name,
			"reason", fail.reason, "fallback", string(fail.fallback), "detail", fail.message)
		if fail.fallback == netv1alpha1.InterconnectFallbackNone {
			a.rec.Event(pod, corev1.EventTypeWarning, ReasonInterconnectFailed,
				fmt.Sprintf("%s: %s; the pod is held because the interconnect's fallback is none", fail.reason, fail.message))
			return fmt.Errorf("interconnect attach for %s/%s: %s: %s (fallback none)", pod.Namespace, pod.Name, fail.reason, fail.message)
		}
		a.rec.Event(pod, corev1.EventTypeWarning, ReasonInterconnectFailed,
			fmt.Sprintf("%s: %s; the pod starts without an interconnect address (fallback network)", fail.reason, fail.message))
		r = &interconnectRecord{cond: a.condition(corev1.ConditionFalse, fail.reason,
			fail.message+"; the pod runs without an interconnect address (fallback network)")}
	}
	a.mu.Lock()
	a.pods[id] = r
	a.mu.Unlock()
	return nil
}

// tryAttach checks and, when every check passes, takes a slot and its alias.
// Called with opMu held.
func (a *interconnectAttacher) tryAttach(ctx context.Context, pod *corev1.Pod, names []string) (*interconnectRecord, *attachFailure, error) {
	desired, known, member := a.readDesired()
	if !known {
		return nil, nil, fmt.Errorf("%s/%s: %w", pod.Namespace, pod.Name, errInterconnectDesiredUnknown)
	}
	// A non-member node cannot know the interconnect's fallback, so it
	// degrades to network there (see the file comment).
	fallback := netv1alpha1.InterconnectFallbackNetwork
	if member {
		fallback = desired.Fallback
		named := false
		var dropped []string
		for _, n := range names {
			if n == desired.Interconnect {
				named = true
			} else {
				dropped = append(dropped, n)
			}
		}
		if named && len(dropped) > 0 {
			a.log.Warn("interconnect attach: the pod names interconnects this node is not a member of; attaching only to the node's own", "namespace", pod.Namespace, "name", pod.Name, "interconnect", desired.Interconnect, "dropped", strings.Join(dropped, ","))
		}
		member = named
	}
	// After the desired read, so the refusal follows the interconnect's
	// fallback like every other one.
	if interconnectUnsupportedRuntime(pod) {
		return nil, &attachFailure{netv1alpha1.ReasonInterconnectUnsupportedRuntime,
			"the vm and container-vm RuntimeClasses cannot attach to an interconnect", fallback}, nil
	}
	if !member {
		return nil, &attachFailure{ReasonInterconnectNotMember,
			fmt.Sprintf("this node is not an armed member of %s", strings.Join(names, ",")), fallback}, nil
	}
	if !desired.NamespaceAllowed(pod.Namespace) {
		return nil, &attachFailure{ReasonInterconnectNamespaceNotAllowed,
			fmt.Sprintf("interconnect %s does not allow namespace %s", desired.Interconnect, pod.Namespace), fallback}, nil
	}
	if a.cfg.Aliases == nil {
		return nil, &attachFailure{ReasonInterconnectNoHelper,
			"this node runs without the k3sm-netd root helper", fallback}, nil
	}
	slot, ok := a.reserve(string(pod.UID), isMLXRank(pod, desired))
	if !ok {
		return nil, &attachFailure{netv1alpha1.ReasonInterconnectSlotsExhausted,
			"no free interconnect slot on this node", fallback}, nil
	}
	addr, err := a.cfg.Aliases.EnsureInterconnectAlias(ctx, slot)
	if err == nil {
		if got, ok := slotOf(addr); !ok || got != slot {
			err = fmt.Errorf("the root helper answered slot %d with %s, not that slot's interconnect address", slot, addr)
		}
	}
	if err != nil {
		a.release(slot)
		return nil, &attachFailure{helperReason(err), fmt.Sprintf("the root helper refused slot %d: %v", slot, err), fallback}, nil
	}
	a.log.Info("interconnect attached", "namespace", pod.Namespace, "name", pod.Name,
		"interconnect", desired.Interconnect, "slot", slot, "address", addr.String())
	return &interconnectRecord{attached: true, slot: slot, addr: addr,
		cond: a.condition(corev1.ConditionTrue, desired.Interconnect, addr.String())}, nil, nil
}

// reserve takes a free slot for pod id: slot 1 for a verified MLX rank (and
// only then), else the lowest free of 2..MaxInterconnectSlot. A rank whose
// slot 1 is taken gets none: the MLX hostfile names slot 1.
func (a *interconnectAttacher) reserve(id string, mlxRank bool) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mlxRank {
		if a.slots[netv1alpha1.InterconnectSlotMLXRank] != "" {
			return 0, false
		}
		a.slots[netv1alpha1.InterconnectSlotMLXRank] = id
		return netv1alpha1.InterconnectSlotMLXRank, true
	}
	for s := netv1alpha1.InterconnectSlotFirstPod; s <= netv1alpha1.MaxInterconnectSlot; s++ {
		if a.slots[s] == "" {
			a.slots[s] = id
			return s, true
		}
	}
	return 0, false
}

func (a *interconnectAttacher) release(slot int) {
	a.mu.Lock()
	a.slots[slot] = ""
	a.mu.Unlock()
}

// restore rebuilds the bookkeeping of a pod that survived a node-daemon
// restart (the re-attach path) from the attach condition its published status
// carries: the address names the slot, which is re-reserved and its alias
// re-ensured, so a restarted daemon never hands the slot out twice.
//
// It applies the create-time refusals that can be decided from the pod: a vm
// or container-vm pod is not restored, and a slot-1 pod must name an MLXModel
// the desired annotation lists (isMLXRank). The desired annotation may not be
// readable this early; a slot-1 pod is then restored provisionally and
// re-checked by recheck once it is. A refused pod is demoted: its alias is
// removed, its slot freed, and its condition goes False with the reason, so
// the next box built for it carries no interconnect env.
func (a *interconnectAttacher) restore(ctx context.Context, pod *corev1.Pod) {
	if len(requestedInterconnects(pod)) == 0 {
		return
	}
	c := findPodCondition(pod.Status.Conditions, corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached))
	if c == nil || c.Status != corev1.ConditionTrue {
		return
	}
	addr, err := netip.ParseAddr(c.Message)
	if err != nil {
		return
	}
	slot, ok := slotOf(addr)
	if !ok || slot == netv1alpha1.InterconnectSlotNode {
		a.log.Warn("interconnect restore: the pod's attach condition names no pod slot; not restored", "namespace", pod.Namespace, "name", pod.Name, "address", c.Message)
		return
	}
	id := string(pod.UID)
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.mu.Lock()
	_, done := a.pods[id]
	taken := a.slots[slot] != "" && a.slots[slot] != id
	a.mu.Unlock()
	if done || taken {
		return
	}

	switch {
	case interconnectUnsupportedRuntime(pod):
		a.demote(ctx, pod, slot, netv1alpha1.ReasonInterconnectUnsupportedRuntime,
			"the vm and container-vm RuntimeClasses cannot attach to an interconnect")
		return
	case slot == netv1alpha1.InterconnectSlotMLXRank:
		desired, known, member := a.readDesired()
		if known && (!member || !isMLXRank(pod, desired)) {
			a.demote(ctx, pod, slot, ReasonInterconnectModelMismatch,
				"slot 1 needs a controller MLXModel the interconnect lists by namespace, name and UID")
			return
		}
		if !known {
			r := &interconnectRecord{attached: true, slot: slot, addr: addr, cond: *c.DeepCopy(), provisional: true, pod: pod.DeepCopy()}
			a.hold(id, slot, r)
			a.log.Info("interconnect restore: slot 1 restored provisionally until this node's desired annotation is known", "namespace", pod.Namespace, "name", pod.Name)
			a.ensureRestored(ctx, pod, slot, addr)
			return
		}
	}
	a.hold(id, slot, &interconnectRecord{attached: true, slot: slot, addr: addr, cond: *c.DeepCopy()})
	a.ensureRestored(ctx, pod, slot, addr)
}

// hold records r for pod id on slot. Called with opMu held.
func (a *interconnectAttacher) hold(id string, slot int, r *interconnectRecord) {
	a.mu.Lock()
	a.slots[slot] = id
	a.pods[id] = r
	a.mu.Unlock()
}

// ensureRestored re-ensures a restored pod's alias, best effort: its processes
// are already bound to the address. Called with opMu held.
func (a *interconnectAttacher) ensureRestored(ctx context.Context, pod *corev1.Pod, slot int, addr netip.Addr) {
	if a.cfg.Aliases == nil {
		return
	}
	if got, err := a.cfg.Aliases.EnsureInterconnectAlias(ctx, slot); err != nil || got != addr {
		a.log.Warn("interconnect restore: could not re-ensure the pod's alias", "namespace", pod.Namespace, "name", pod.Name, "slot", slot, "address", addr.String(), "got", got.String(), "err", err)
	}
}

// demote refuses a restored (or provisional) pod: it removes the slot's alias
// unless another pod holds the slot, frees the slot, and records the
// condition False with reason, with a Warning Event. Called with opMu held.
func (a *interconnectAttacher) demote(ctx context.Context, pod *corev1.Pod, slot int, reason, msg string) {
	id := string(pod.UID)
	a.mu.Lock()
	ours := a.slots[slot] == "" || a.slots[slot] == id
	a.mu.Unlock()
	if ours && a.cfg.Aliases != nil {
		if err := a.cfg.Aliases.RemoveInterconnectAlias(ctx, slot); err != nil {
			a.log.Warn("interconnect demote: the root helper did not remove the alias", "namespace", pod.Namespace, "name", pod.Name, "slot", slot, "reason", helperReason(err), "err", err)
		}
	}
	a.mu.Lock()
	if a.slots[slot] == id {
		a.slots[slot] = ""
	}
	a.pods[id] = &interconnectRecord{cond: a.condition(corev1.ConditionFalse, reason, msg+"; the pod's interconnect address was removed")}
	a.mu.Unlock()
	a.log.Warn("interconnect: a restored pod was refused and demoted", "namespace", pod.Namespace, "name", pod.Name, "slot", slot, "reason", reason)
	a.rec.Event(pod, corev1.EventTypeWarning, ReasonInterconnectFailed, fmt.Sprintf("%s: %s; its interconnect address was removed", reason, msg))
}

// recheck verifies every provisionally restored slot-1 pod once this node's
// desired annotation is readable, and demotes the ones whose controller names
// no listed MLXModel. It is cheap when nothing is provisional.
func (a *interconnectAttacher) recheck(ctx context.Context) {
	a.mu.Lock()
	var pending []*interconnectRecord
	for _, r := range a.pods {
		if r.provisional {
			pending = append(pending, r)
		}
	}
	a.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	desired, known, member := a.readDesired()
	if !known {
		return
	}
	for _, r := range pending {
		id := string(r.pod.UID)
		a.mu.Lock()
		cur := a.pods[id]
		a.mu.Unlock()
		if cur != r {
			continue // detached or replaced since
		}
		if member && isMLXRank(r.pod, desired) {
			a.mu.Lock()
			r.provisional, r.pod = false, nil
			a.mu.Unlock()
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, interconnectRemoveTimeout)
		a.demote(rctx, r.pod, r.slot, ReasonInterconnectModelMismatch,
			"slot 1 needs a controller MLXModel the interconnect lists by namespace, name and UID")
		cancel()
	}
}

// detach removes the pod's alias (slots 1..MaxInterconnectSlot only, never the
// node's slot 0) and frees its slot. The slot stays taken until the removal
// returns, so it is never handed to another pod while its alias is going away.
// A removal error is logged; the slot is freed anyway, and a later attach of
// that slot re-ensures the alias, so nothing is allocated twice.
func (a *interconnectAttacher) detach(pod *corev1.Pod) {
	id := string(pod.UID)
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.mu.Lock()
	r := a.pods[id]
	a.mu.Unlock()
	if r == nil {
		return
	}
	if r.attached && r.slot >= netv1alpha1.InterconnectSlotMLXRank && r.slot <= netv1alpha1.MaxInterconnectSlot && a.cfg.Aliases != nil {
		// The release seam is ctx-less (releasePodNetwork), so the removal runs
		// under its own bound, like the pod network's teardown leg.
		ctx, cancel := context.WithTimeout(context.Background(), interconnectRemoveTimeout)
		err := a.cfg.Aliases.RemoveInterconnectAlias(ctx, r.slot)
		cancel()
		if err != nil {
			a.log.Warn("interconnect detach: the root helper did not remove the pod's alias", "namespace", pod.Namespace, "name", pod.Name, "slot", r.slot, "reason", helperReason(err), "err", err)
		}
	}
	a.mu.Lock()
	if r.attached && a.slots[r.slot] == id {
		a.slots[r.slot] = ""
	}
	delete(a.pods, id)
	a.mu.Unlock()
}

// record returns a copy of the pod's attach outcome, or nil.
func (a *interconnectAttacher) record(id string) *interconnectRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.pods[id]
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

func (a *interconnectAttacher) condition(status corev1.ConditionStatus, reason, msg string) corev1.PodCondition {
	return corev1.PodCondition{
		Type:               corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached),
		Status:             status,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: metav1.NewTime(a.now()),
	}
}

// applyCondition puts the pod's attach condition on st, replacing any copy.
// A pod with no recorded outcome gets none.
func (a *interconnectAttacher) applyCondition(id string, st *corev1.PodStatus) {
	r := a.record(id)
	if r == nil {
		return
	}
	for i := range st.Conditions {
		if st.Conditions[i].Type == r.cond.Type {
			st.Conditions[i] = r.cond
			return
		}
	}
	st.Conditions = append(st.Conditions, r.cond)
}

// injectEnv sets the pod's interconnect env on every container of box, AFTER
// the pod's own env. K3SM_INTERCONNECT_IP and K3SM_INTERCONNECT_CIDRS are
// stripped from EVERY pod, and every K3SM_INTERCONNECT_* variable from a pod
// that asked for an interconnect, so no pod can pin its source to an address
// it was not given. Only an attached pod gets the two back, from
// podnet.InterconnectEnv beside the bind-discipline env (the shim honours them
// only with K3SM_POD_IP).
func (a *interconnectAttacher) injectEnv(pod *corev1.Pod, box *runtimev1.PodBox) {
	requested := len(requestedInterconnects(pod)) > 0
	var env map[string]string
	if r := a.record(string(pod.UID)); requested && r != nil && r.attached {
		env = podnet.InterconnectEnv(r.addr, []netip.Prefix{netip.MustParsePrefix(netv1alpha1.InterconnectCIDR)})
		if env == nil {
			a.log.Warn("interconnect env: the attached address is not an interconnect source; no env injected", "namespace", pod.Namespace, "name", pod.Name, "address", r.addr.String())
		}
	}
	strip := func(name string) bool {
		if name == podnet.EnvInterconnectIP || name == podnet.EnvInterconnectCIDRs {
			return true
		}
		return requested && strings.HasPrefix(name, envInterconnectPrefix)
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	set := func(c *runtimev1.Container) {
		kept := c.Env[:0]
		for _, e := range c.Env {
			if !strip(e.GetName()) {
				kept = append(kept, e)
			}
		}
		c.Env = kept
		for _, k := range keys {
			c.Env = append(c.Env, &runtimev1.EnvVar{Name: k, Value: env[k]})
		}
	}
	for _, c := range box.GetInitContainers() {
		set(c)
	}
	for _, c := range box.GetContainers() {
		set(c)
	}
	for _, c := range box.GetEphemeralContainers() {
		set(c)
	}
}
