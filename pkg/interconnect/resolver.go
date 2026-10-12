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

package interconnect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	coordinationlisters "k8s.io/client-go/listers/coordination/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	crdconfig "k3sm.io/apis/config/crd"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"

	"k3sm.io/k3sm/pkg/crdensure"
)

const (
	// LeaseName is the coordination Lease that elects the one server whose
	// resolver writes, the k3sm-helm-controller mechanism reused: on an HA
	// control plane two resolvers would otherwise race the status and the
	// desired annotations.
	LeaseName = "k3sm-interconnect-resolver"
	// LeaseNamespace is the Lease's namespace.
	LeaseNamespace = "kube-system"

	// ResyncInterval is the resolver's periodic reconcile, which is also what
	// promotes a held member once UpHold has passed.
	ResyncInterval = 10 * time.Second

	// nodeLeaseNamespace holds every node's heartbeat Lease.
	nodeLeaseNamespace = corev1.NamespaceNodeLease
	// defaultNodeLeaseSeconds is the kubelet lease duration when a Lease
	// carries none.
	defaultNodeLeaseSeconds = 40

	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second

	// ConditionIndexInRange is the status condition naming members whose
	// cluster index is beyond the interconnect ceiling.
	ConditionIndexInRange = "IndexInRange"
	reasonAllInRange      = "AllMembersInRange"

	eventReportRejected = "InterconnectReportRejected"
	eventMemberUp       = "InterconnectMemberUp"
	eventMemberDown     = "InterconnectMemberDown"
	eventMemberLoop     = "InterconnectMemberLoop"
	eventComponent      = "k3sm-interconnect"
	eventNoClusterIndex = "InterconnectNoClusterIndex"
	eventUnrecordedArm  = "InterconnectArmedUnrecorded"

	// ConditionIndexUnique is the status condition naming nodes that share a
	// cluster index.
	ConditionIndexUnique = "IndexUnique"
	reasonAllUnique      = "AllIndicesUnique"
	// ReasonDuplicateClusterIndex marks two Nodes holding one cluster index.
	ReasonDuplicateClusterIndex = "DuplicateClusterIndex"
)

// Indices is the cluster index of every node that has one, and why each node
// that should have one does not.
type Indices struct {
	// Index maps a node to its cluster index.
	Index map[string]int
	// Invalid maps a node to the reason its pod /24 yields no index.
	Invalid map[string]string
}

// ResolverConfig is the server resolver's wiring.
type ResolverConfig struct {
	// Client is the server's in-process admin client.
	Client kubernetes.Interface
	// Store reads and writes the Interconnect object.
	Store Store
	// CRD ensures the Interconnect CRD; nil skips the ensure.
	CRD crdensure.CRDClient
	// Indices returns every node's cluster index (from its pod /24), and the
	// nodes whose pod /24 yields none.
	Indices func(ctx context.Context) (Indices, error)
	// Identity names this server in the leader Lease.
	Identity string
	// MLXModels lists the MLXModels that use an interconnect (MLXModelLister),
	// which the desired annotation carries so a node can verify a slot-1 pod's
	// owner without reading MLXModel. nil means none. A failed read writes no
	// new or changed desired value (removals still apply), so a node never
	// loses a model on missing information.
	MLXModels func(ctx context.Context) ([]netv1alpha1.InterconnectModelRef, error)
	// Recorder records Node Events; nil builds one over Client.
	Recorder record.EventRecorder
	// Metrics receives member and rejection metrics; nil records none.
	Metrics *Metrics
	// Log is the logger; nil uses slog.Default.
	Log *slog.Logger
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Resolver is the server-side reconcile of the Interconnect: it validates the
// node reports, writes status, auto-creates the object disabled, and owns the
// desired annotation on every Node.
type Resolver struct {
	cfg ResolverConfig

	nodes  corelisters.NodeLister
	leases coordinationlisters.LeaseLister
	synced func() bool

	// mu guards the event dedup state below (Reconcile runs on one goroutine,
	// but tests and the lead loop must not race it).
	mu       sync.Mutex
	rejected map[string]string
	invalid  map[string]string
	// dropped is the last count of MLXModels left out of the desired
	// annotation to fit its bounds, so the warning fires once per change.
	dropped int

	// ensureCRD and startBackoff are Run's start-up step and its first retry
	// wait; tests replace them.
	ensureCRD    func(ctx context.Context) error
	startBackoff time.Duration
}

// NewResolver returns a Resolver. Its listers are bound by Run, or by a test
// through SetListers.
func NewResolver(cfg ResolverConfig) *Resolver {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r := &Resolver{cfg: cfg, rejected: map[string]string{}, invalid: map[string]string{}, startBackoff: startBackoffBase}
	r.ensureCRD = func(ctx context.Context) error {
		if cfg.CRD == nil {
			return nil
		}
		_, err := crdensure.Ensure(ctx, cfg.CRD, crdconfig.InterconnectCRD(), crdensure.Options{Log: cfg.Log})
		return err
	}
	return r
}

const (
	// startBackoffBase and startBackoffMax bound Run's start-up retry: a CRD
	// the apiserver will not take yet is retried, never a reason to disable the
	// resolver for the life of the process.
	startBackoffBase = 2 * time.Second
	startBackoffMax  = time.Minute
	// reconcileTimeout bounds one reconcile, so writes started while leading
	// end inside the margin between a failed renewal (renewDeadline) and the
	// Lease's expiry (leaseDuration).
	reconcileTimeout = leaseDuration - renewDeadline - time.Second
)

// start runs the start-up step until it succeeds or ctx ends, waiting
// startBackoff, doubling to startBackoffMax, between tries. A failure is
// warned once per distinct error.
func (r *Resolver) start(ctx context.Context) error {
	wait := r.startBackoff
	var last string
	for {
		err := r.ensureCRD(ctx)
		if err == nil {
			if last != "" {
				r.cfg.Log.Info("interconnect resolver: the Interconnect CRD is ensured; starting")
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if msg := err.Error(); msg != last {
			last = msg
			r.cfg.Log.Warn("interconnect resolver waiting: ensure the Interconnect CRD", "err", err, "retry", wait)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		wait = min(wait*2, startBackoffMax)
	}
}

// SetListers binds the node and node-Lease listers and the sync predicate.
func (r *Resolver) SetListers(nodes corelisters.NodeLister, leases coordinationlisters.LeaseLister, synced func() bool) {
	r.nodes, r.leases, r.synced = nodes, leases, synced
}

// Run ensures the Interconnect CRD (on every server; the apply is idempotent),
// retrying with capped backoff until it takes, then campaigns for the resolver
// Lease and reconciles while it leads, until ctx ends. A lost Lease ends one
// term and the server campaigns again.
func (r *Resolver) Run(ctx context.Context) error {
	if err := r.start(ctx); err != nil {
		return nil // ctx ended
	}
	if r.cfg.Recorder == nil {
		b := record.NewBroadcaster()
		b.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: r.cfg.Client.CoreV1().Events("")})
		defer b.Shutdown()
		r.cfg.Recorder = b.NewRecorder(scheme.Scheme, corev1.EventSource{Component: eventComponent})
	}
	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Name: LeaseName, Namespace: LeaseNamespace},
		Client:     r.cfg.Client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: r.cfg.Identity},
	}
	for ctx.Err() == nil {
		if err := r.campaign(ctx, lock); err != nil {
			return err
		}
	}
	return nil
}

// drainOnRelease is the Lease lock with one change: a release (the update that
// clears the holder, which client-go sends from inside its renew loop when
// leadership is cancelled, BEFORE it cancels the leading callback's context)
// first stops the leading work and waits for its in-flight reconcile. So this
// server has stopped writing before another can take the Lease from a release.
type drainOnRelease struct {
	resourcelock.Interface
	drain func()
}

// Update implements resourcelock.Interface.
func (d drainOnRelease) Update(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	if ler.HolderIdentity == "" {
		d.drain()
	}
	return d.Interface.Update(ctx, ler)
}

// campaign runs one leader-election term and returns once the leading work
// has drained (the helm controller's term shape, with the release drained).
func (r *Resolver) campaign(ctx context.Context, lock resourcelock.Interface) error {
	var (
		mu        sync.Mutex
		started   bool
		stopped   bool
		stopLead  context.CancelFunc
		done      = make(chan struct{})
		drainOnce sync.Once
	)
	drain := func() {
		drainOnce.Do(func() {
			mu.Lock()
			stopped = true
			wait, cancel := started, stopLead
			mu.Unlock()
			if cancel != nil {
				cancel()
			}
			if wait {
				<-done
			}
		})
	}
	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            drainOnRelease{Interface: lock, drain: drain},
		Name:            LeaseName,
		LeaseDuration:   leaseDuration,
		RenewDeadline:   renewDeadline,
		RetryPeriod:     retryPeriod,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(lctx context.Context) {
				leadCtx, cancel := context.WithCancel(lctx)
				defer cancel()
				mu.Lock()
				if stopped {
					mu.Unlock()
					return
				}
				started, stopLead = true, cancel
				mu.Unlock()
				defer close(done)
				r.cfg.Log.Info("interconnect resolver: leading", "lease", LeaseNamespace+"/"+LeaseName, "identity", r.cfg.Identity)
				r.lead(leadCtx)
			},
			OnStoppedLeading: func() {},
		},
	})
	if err != nil {
		return fmt.Errorf("interconnect resolver: leader election: %w", err)
	}
	le.Run(ctx)
	drain()
	return nil
}

// lead runs the Node and node-Lease informers and reconciles on every Node
// change and every ResyncInterval until ctx ends.
func (r *Resolver) lead(ctx context.Context) {
	nf := informers.NewSharedInformerFactory(r.cfg.Client, 0)
	lf := informers.NewSharedInformerFactoryWithOptions(r.cfg.Client, 0, informers.WithNamespace(nodeLeaseNamespace))
	nodeInf := nf.Core().V1().Nodes()
	leaseInf := lf.Coordination().V1().Leases()
	kick := make(chan struct{}, 1)
	nudge := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	_, _ = nodeInf.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { nudge() },
		UpdateFunc: func(_, _ any) { nudge() },
		DeleteFunc: func(any) { nudge() },
	})
	r.SetListers(nodeInf.Lister(), leaseInf.Lister(), func() bool {
		return nodeInf.Informer().HasSynced() && leaseInf.Informer().HasSynced()
	})
	nf.Start(ctx.Done())
	lf.Start(ctx.Done())
	defer nf.Shutdown()
	defer lf.Shutdown()
	cache.WaitForCacheSync(ctx.Done(), nodeInf.Informer().HasSynced, leaseInf.Informer().HasSynced)

	tick := time.NewTicker(ResyncInterval)
	defer tick.Stop()
	var lastErr string
	for {
		rctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
		err := r.Reconcile(rctx)
		cancel()
		switch {
		case err == nil:
			lastErr = ""
		case ctx.Err() != nil:
			return
		case err.Error() != lastErr:
			lastErr = err.Error()
			r.cfg.Log.Warn("interconnect resolver: reconcile", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-tick.C:
		}
	}
}

// Reconcile resolves one snapshot and writes the result. It acts only on a
// synced, non-empty node cache and only after reading the Interconnect object
// successfully: an unsynced or empty cache, a failed index listing or a failed
// read changes nothing, so nothing is ever cleared on missing information.
func (r *Resolver) Reconcile(ctx context.Context) error {
	if r.synced == nil || !r.synced() {
		return nil
	}
	nodes, err := r.nodes.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	if len(nodes) == 0 {
		return nil
	}
	indices, err := r.cfg.Indices(ctx)
	if err != nil {
		return fmt.Errorf("list node cluster indices: %w", err)
	}
	r.recordInvalidIndices(nodes, indices.Invalid)
	now := r.cfg.Now()
	in := Input{Now: now}
	for _, n := range nodes {
		idx, ok := indices.Index[n.Name]
		if !ok {
			idx = NoIndex
		}
		in.Nodes = append(in.Nodes, NodeInput{
			Name:   n.Name,
			Index:  idx,
			Fresh:  r.fresh(n.Name, now),
			Report: n.Annotations[netv1alpha1.AnnotationInterconnectReport],
		})
	}
	sort.Slice(in.Nodes, func(i, j int) bool { return in.Nodes[i].Name < in.Nodes[j].Name })

	ic, err := r.cfg.Store.Get(ctx, Name)
	if apierrors.IsNotFound(err) {
		// A read that SUCCEEDED and found no object (deleted, its CRD deleted,
		// a datastore restore) means disarmed: no node keeps a desired
		// annotation. A read error never gets here.
		res := Resolve(in)
		r.recordRejections(nodes, res.Rejected)
		clearErr := r.clearDesired(ctx, nodes)
		if !res.HasPeer {
			return clearErr
		}
		return errors.Join(clearErr, r.autoCreate(ctx))
	}
	if err != nil {
		return fmt.Errorf("read interconnect %s: %w", Name, err)
	}

	spec := ic.Spec
	if err := ic.Validate(); err != nil {
		// The CRD schema should make this unreachable; if it is not, the safe
		// reading of a spec this binary cannot trust is "disabled".
		r.cfg.Log.Warn("interconnect resolver: the Interconnect spec is invalid; treating it as disabled", "err", err)
		spec.Enabled = false
	}
	in.Spec = spec
	in.Prev = ic.Status.Members
	res := Resolve(in)
	r.recordRejections(nodes, res.Rejected)

	statusErr := r.writeStatus(ctx, ic, res, now)
	models, modelErr := r.mlxModels(ctx)
	desiredErr := r.writeDesired(ctx, nodes, ic, res, models, modelErr == nil)
	return errors.Join(statusErr, modelErr, desiredErr)
}

// mlxModels reads the interconnect-using MLXModels, sorted by namespace and
// name so the desired value compares stably across reconciles. An entry with
// an empty field, or repeating an earlier namespace/name or UID, is dropped.
func (r *Resolver) mlxModels(ctx context.Context) ([]netv1alpha1.InterconnectModelRef, error) {
	if r.cfg.MLXModels == nil {
		return nil, nil
	}
	in, err := r.cfg.MLXModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("list interconnect MLXModels: %w", err)
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Namespace != in[j].Namespace {
			return in[i].Namespace < in[j].Namespace
		}
		return in[i].Name < in[j].Name
	})
	out := make([]netv1alpha1.InterconnectModelRef, 0, len(in))
	names := make(map[string]bool, len(in))
	uids := make(map[string]bool, len(in))
	for _, m := range in {
		key := m.Namespace + "/" + m.Name
		if m.Namespace == "" || m.Name == "" || m.UID == "" || names[key] || uids[m.UID] {
			continue
		}
		names[key], uids[m.UID] = true, true
		out = append(out, m)
	}
	return out, nil
}

// clearDesired deletes the desired annotation from every Node that carries one.
func (r *Resolver) clearDesired(ctx context.Context, nodes []*corev1.Node) error {
	var errs []error
	for _, n := range nodes {
		if _, has := n.Annotations[netv1alpha1.AnnotationInterconnectDesired]; has {
			errs = append(errs, PatchNodeAnnotation(ctx, r.cfg.Client, n.Name, netv1alpha1.AnnotationInterconnectDesired, ""))
		}
	}
	if len(errs) > 0 {
		r.cfg.Log.Warn("interconnect resolver: no Interconnect object; cleared every desired annotation", "nodes", len(errs))
	}
	return errors.Join(errs...)
}

// recordInvalidIndices warns and records one Node Event per node whose pod /24
// yields no cluster index, once per change of its reason.
func (r *Resolver) recordInvalidIndices(nodes []*corev1.Node, invalid map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range nodes {
		reason, ok := invalid[n.Name]
		if !ok {
			delete(r.invalid, n.Name)
			continue
		}
		if r.invalid[n.Name] == reason {
			continue
		}
		r.invalid[n.Name] = reason
		r.cfg.Log.Warn("interconnect resolver: node has no cluster index; it cannot be an interconnect member", "node", n.Name, "reason", reason)
		r.event(n.Name, corev1.EventTypeWarning, eventNoClusterIndex, "this node's pod /24 yields no cluster index, so it has no interconnect address: "+reason)
	}
}

// fresh reports whether node's heartbeat Lease is current at now.
func (r *Resolver) fresh(node string, now time.Time) bool {
	if r.leases == nil {
		return false
	}
	l, err := r.leases.Leases(nodeLeaseNamespace).Get(node)
	if err != nil {
		return false
	}
	return leaseFresh(l, now)
}

func leaseFresh(l *coordinationv1.Lease, now time.Time) bool {
	if l.Spec.RenewTime == nil {
		return false
	}
	secs := int32(defaultNodeLeaseSeconds)
	if l.Spec.LeaseDurationSeconds != nil && *l.Spec.LeaseDurationSeconds > 0 {
		secs = *l.Spec.LeaseDurationSeconds
	}
	return now.Before(l.Spec.RenewTime.Add(time.Duration(secs) * time.Second))
}

// autoCreate creates the Interconnect with its defaults and enabled false
// (plan I1): nothing gets an address until an admin arms it.
func (r *Resolver) autoCreate(ctx context.Context) error {
	ic := &netv1alpha1.Interconnect{
		ObjectMeta: metav1.ObjectMeta{Name: Name},
		Spec: netv1alpha1.InterconnectSpec{
			Medium:   netv1alpha1.MediumThunderbolt,
			Fallback: netv1alpha1.InterconnectFallbackNetwork,
			Enabled:  false,
		},
	}
	if _, err := r.cfg.Store.Create(ctx, ic); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("auto-create interconnect %s: %w", Name, err)
	}
	r.cfg.Log.Info("interconnect resolver: a node reported a cabled Thunderbolt peer; created the Interconnect disabled (an admin arms it with `k3sm interconnect enable`)", "interconnect", Name)
	return nil
}

// recordRejections counts and reports each newly rejected report once: the
// counter and the Node Event fire when a node's rejection reason changes, not
// on every resync.
func (r *Resolver) recordRejections(nodes []*corev1.Node, rejected map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	present := map[string]bool{}
	for _, n := range nodes {
		present[n.Name] = true
		reason, ok := rejected[n.Name]
		if !ok {
			delete(r.rejected, n.Name)
			continue
		}
		if r.rejected[n.Name] == reason {
			continue
		}
		r.rejected[n.Name] = reason
		r.cfg.Metrics.Rejected(reason)
		r.cfg.Log.Warn("interconnect resolver: ignored a node's interconnect report", "node", n.Name, "reason", reason)
		r.event(n.Name, corev1.EventTypeWarning, eventReportRejected, "the server ignored this node's interconnect report: "+reason)
	}
	for n := range r.rejected {
		if !present[n] {
			delete(r.rejected, n)
		}
	}
}

func (r *Resolver) event(node, typ, reason, msg string) {
	if r.cfg.Recorder == nil {
		return
	}
	ref := &corev1.ObjectReference{Kind: "Node", Name: node, UID: types.UID(node)}
	r.cfg.Recorder.Event(ref, typ, reason, msg)
}

// writeStatus writes the resolved members, segments and the index condition,
// keeping the fields other writers own (armedBy, armedAt, attachedPods). A
// conflict is returned and retried by the next reconcile; the persisted
// lastTransition makes the retry compute the same hysteresis.
func (r *Resolver) writeStatus(ctx context.Context, ic *netv1alpha1.Interconnect, res Result, now time.Time) error {
	next := ic.DeepCopy()
	next.Status.Members = res.Members
	next.Status.Segments = res.Segments
	cond := metav1.Condition{
		Type:               ConditionIndexInRange,
		Status:             metav1.ConditionTrue,
		Reason:             reasonAllInRange,
		Message:            "every member has a cluster index within the interconnect range",
		ObservedGeneration: ic.Generation,
		LastTransitionTime: metav1.NewTime(now),
	}
	if len(res.OutOfRange) > 0 {
		cond.Status = metav1.ConditionFalse
		cond.Reason = netv1alpha1.ReasonInterconnectIndexOutOfRange
		cond.Message = fmt.Sprintf("members with a cluster index above %d have no interconnect address and stay down: %s",
			netv1alpha1.MaxInterconnectNodeIndex, strings.Join(res.OutOfRange, ", "))
	}
	meta.SetStatusCondition(&next.Status.Conditions, cond)
	uniq := metav1.Condition{
		Type:               ConditionIndexUnique,
		Status:             metav1.ConditionTrue,
		Reason:             reasonAllUnique,
		Message:            "no two nodes share a cluster index",
		ObservedGeneration: ic.Generation,
		LastTransitionTime: metav1.NewTime(now),
	}
	if len(res.DuplicateIndex) > 0 {
		uniq.Status = metav1.ConditionFalse
		uniq.Reason = ReasonDuplicateClusterIndex
		uniq.Message = "nodes sharing a cluster index would derive one interconnect address and stay down: " + strings.Join(res.DuplicateIndex, ", ")
	}
	meta.SetStatusCondition(&next.Status.Conditions, uniq)

	// Armed without a record (kubectl edit or patch rather than
	// `k3sm interconnect enable`): record that the arming identity is unknown.
	unrecorded := ic.Spec.Enabled && ic.Status.ArmedBy == ""
	if unrecorded {
		next.Status.ArmedBy = UnknownIdentity
		at := metav1.NewTime(now)
		next.Status.ArmedAt = &at
	}

	up := map[string]bool{}
	for _, m := range res.Members {
		up[m.Node] = m.State == netv1alpha1.InterconnectMemberUp
	}
	r.cfg.Metrics.SetMembers(up)
	r.cfg.Metrics.SetAttachedPods(ic.Status.AttachedPods)

	if equality.Semantic.DeepEqual(ic.Status, next.Status) {
		return nil
	}
	if _, err := r.cfg.Store.UpdateStatus(ctx, next); err != nil {
		return fmt.Errorf("write interconnect %s status: %w", ic.Name, err)
	}
	if unrecorded {
		r.cfg.Log.Warn("interconnect armed without a recorded identity (not through `k3sm interconnect enable`); armedBy set to unknown", "interconnect", ic.Name)
		if r.cfg.Recorder != nil {
			r.cfg.Recorder.Event(&corev1.ObjectReference{
				APIVersion: netv1alpha1.SchemeGroupVersion.String(), Kind: "Interconnect", Name: ic.Name, UID: ic.UID,
			}, corev1.EventTypeWarning, eventUnrecordedArm,
				"interconnect armed without a recorded identity: opted-in pod traffic crosses the cable in plaintext, and any device on a cabled port can reach and spoof interconnect addresses")
		}
	}
	r.reportTransitions(ic.Status.Members, res.Members)
	return nil
}

// reportTransitions turns every member state change into a Node Event, a Warn
// line and a transitions count.
func (r *Resolver) reportTransitions(prev, next []netv1alpha1.InterconnectMember) {
	was := map[string]netv1alpha1.InterconnectMemberState{}
	for _, m := range prev {
		was[m.Node] = m.State
	}
	for _, m := range next {
		old, ok := was[m.Node]
		if ok && old == m.State {
			continue
		}
		if !ok && m.State == netv1alpha1.InterconnectMemberDown {
			continue
		}
		r.cfg.Metrics.Transition(m.Node)
		reason := eventMemberDown
		switch m.State {
		case netv1alpha1.InterconnectMemberUp:
			reason = eventMemberUp
		case netv1alpha1.InterconnectMemberLoop:
			reason = eventMemberLoop
		}
		r.cfg.Log.Warn("interconnect member state changed", "node", m.Node, "from", string(old), "to", string(m.State), "segment", m.Segment)
		r.event(m.Node, corev1.EventTypeWarning, reason, fmt.Sprintf("interconnect member %s: %s -> %s", Name, old, m.State))
	}
}

// writeDesired makes every Node's desired annotation agree with the
// resolution: the encoded desired value on the nodes that must carry it, no
// annotation anywhere else. A node-edited value that disagrees is overwritten.
//
// The value carries the Interconnect's allowedNamespaces and the
// interconnect-using MLXModels (plan I9: a node reads neither object), so a
// change in either rewrites it. modelsKnown false (a failed MLXModel read)
// writes no new or changed value and only removes annotations, so a node never
// loses a model on missing information.
func (r *Resolver) writeDesired(ctx context.Context, nodes []*corev1.Node, ic *netv1alpha1.Interconnect, res Result, models []netv1alpha1.InterconnectModelRef, modelsKnown bool) error {
	var (
		want    string
		wantErr error
	)
	if modelsKnown {
		want, wantErr = r.desiredValue(ic, models)
	}
	var errs []error
	if wantErr != nil {
		errs = append(errs, wantErr)
	}
	canWrite := modelsKnown && wantErr == nil
	for _, n := range nodes {
		cur, has := n.Annotations[netv1alpha1.AnnotationInterconnectDesired]
		switch {
		case res.Desired[n.Name] && canWrite && cur != want:
			errs = append(errs, PatchNodeAnnotation(ctx, r.cfg.Client, n.Name, netv1alpha1.AnnotationInterconnectDesired, want))
		case !res.Desired[n.Name] && has:
			errs = append(errs, PatchNodeAnnotation(ctx, r.cfg.Client, n.Name, netv1alpha1.AnnotationInterconnectDesired, ""))
		}
	}
	return errors.Join(errs...)
}

// desiredValue encodes the desired annotation for ic with models (sorted).
// When the models do not fit the annotation's bounds (MaxInterconnectListItems,
// the 4 KiB cap), the tail is left out, warned once per change: a left-out
// model's rank gets no slot 1, which fails closed. The allowed namespaces are
// never trimmed, because an empty list means every namespace.
func (r *Resolver) desiredValue(ic *netv1alpha1.Interconnect, models []netv1alpha1.InterconnectModelRef) (string, error) {
	d := netv1alpha1.InterconnectDesired{
		Schema:            netv1alpha1.InterconnectAnnotationSchema,
		Interconnect:      ic.Name,
		Fallback:          ic.Spec.EffectiveFallback(),
		AllowedNamespaces: ic.Spec.AllowedNamespaces,
	}
	n := min(len(models), netv1alpha1.MaxInterconnectListItems)
	for ; n >= 0; n-- {
		if n > 0 {
			d.MLXModels = models[:n]
		} else {
			d.MLXModels = nil
		}
		v, err := d.Encode()
		if err == nil {
			r.noteDroppedModels(len(models) - n)
			return v, nil
		}
		if n == 0 {
			return "", fmt.Errorf("encode the desired annotation: %w", err)
		}
	}
	return "", errors.New("encode the desired annotation: unreachable")
}

// noteDroppedModels warns when the count of MLXModels left out of the desired
// annotation changes.
func (r *Resolver) noteDroppedModels(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n == r.dropped {
		return
	}
	r.dropped = n
	if n > 0 {
		r.cfg.Log.Warn("interconnect resolver: more interconnect MLXModels than the desired annotation carries; their ranks get no slot 1", "left_out", n, "max", netv1alpha1.MaxInterconnectListItems)
	}
}
