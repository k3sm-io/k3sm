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

package runtimeclass

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Name is the name (and handler) of the node.k8s.io/v1 RuntimeClass k3sm
// provisions for the Virtualization.framework micro-VM backend. A pod opts in with
// spec.runtimeClassName: vm. It is sourced from the apis handler constant so the
// RuntimeClass, its handler, and the apis handler→backend table never drift.
const Name = string(runtimev1.HandlerVM)

// LabelVirtualization is the node label the vm RuntimeClass pins its
// scheduling.nodeSelector to: a node carries it (value LabelTrue) iff it can run
// the Virtualization.framework micro-VM backend. Absent ⇒ no VZ node ⇒ a vm pod
// stays Unschedulable (the fail-closed posture for a non-VZ cluster). cmd/k3sm sets
// the node label from the node's VZ availability; this package and the node command
// share the key so the RuntimeClass selector and the node label never drift.
const LabelVirtualization = "k3sm.io/virtualization"

// LabelRosetta is the node label advertising that this node can translate
// **darwin/amd64 Mach-O** pod payloads via host Rosetta 2 on the NATIVE
// host-process spine (no VM involved). A node carries it (value LabelTrue) iff
// runtimed's RosettaHostAvailable condition is TRUE; absent ⇒ the node can run only
// native darwin/arm64 payloads. It is a plain capability label with NO RuntimeClass
// attached — a pod that needs a translated payload selects it directly (see the
// paired-selector note below).
//
// INTERIM SEMANTIC — ADVERTISED, NOT YET HONORED: this label truthfully describes the
// HOST's capability and makes the node selectable, but k3sm does NOT yet consume it
// when pulling an image. The pull-time platform policy still passes HostRosetta=false,
// so a darwin/amd64-ONLY image is refused with image.ErrNoPlatformMatch (an
// ImagePullBackOff pod), by design: executing a translated Mach-O under Seatbelt is
// unproven, and selecting amd64 payloads before that is proven would drop the AMFI
// kernel backstop the signature policy relies on (an unsigned x86_64 Mach-O runs where
// an unsigned arm64 one is SIGKILLed). Do NOT "fix" that by wiring HostRosetta here.
// The same statement is in docs/user/vm-runtimeclass.md for operators.
//
// Rosetta capability NEVER widens kubernetes.io/arch or NodeInfo.Architecture: both
// stay the machine's NATIVE arch (arm64). Do NOT "fix" the gap by making the arch
// label report amd64 — every generic client (the scheduler's arch nodeAffinity,
// `kubectl get node -L kubernetes.io/arch`, any chart that keys off it) reads those
// as the machine's real ISA, so a translated capability advertised there would be a
// lie to all of them. The k3sm.io/* capability key is the truthful place to express
// "can additionally run amd64 by translation".
const LabelRosetta = "k3sm.io/rosetta"

// LabelRosettaLinux is the node label advertising that this node can run
// **linux/amd64 ELF** pod payloads in a Virtualization.framework Linux guest via
// Rosetta for Linux. Its value is a CONJUNCTION:
//
//	LabelRosettaLinux ⇔ VMBackendAvailable ∧ RosettaGuestAvailable
//
// because Rosetta for Linux translates INSIDE a guest — with no vm backend there is
// no guest to translate in. So a node with Rosetta installed but no VZ capability
// (unsupported hardware, or the process lacking com.apple.security.virtualization)
// carries LabelRosetta but NOT LabelRosettaLinux. The conjunction is composed in
// cmd/k3sm (applyRosettaLabels) from the two independent runtimed conditions; do not
// collapse it to the guest condition alone.
//
// INTERIM SEMANTIC — ADVERTISED, NOT YET HONORED: like LabelRosetta, this label
// truthfully describes the host's capability and makes the node selectable, but k3sm
// does NOT yet consume it. A pod also needs spec.runtimeClassName: vm to reach a guest
// at all, the vm path is EXPERIMENTAL, and the guest lane's image pull is unbuilt (the
// pull-time policy passes GuestRosetta=false, so a linux/amd64-only image is refused
// with image.ErrNoPlatformMatch). The Linux-guest payload path is unbuilt; until
// then treat this key as an advertisement of host capability, not of a runnable
// workload. The same statement is in docs/user/vm-runtimeclass.md for operators.
//
// The same arch-label rule as LabelRosetta applies: this never changes
// kubernetes.io/arch or NodeInfo.Architecture (still arm64), and it never changes
// kubernetes.io/os either — the NODE is darwin even when the payload runs in a Linux
// guest, so a pod selecting this capability must ALSO keep
// kubernetes.io/os=darwin (pkg/policy's darwin-selector admission policy rejects a
// pod that drops the os key with a 422). See docs/user/vm-runtimeclass.md.
const LabelRosettaLinux = "k3sm.io/rosetta-linux"

// LabelVMArtifacts is the node label advertising that this node holds the pinned
// Linux guest boot artifacts — the kernel and the initramfs named by the in-code
// digest pin — materialised and digest-verified on this daemon start.
//
// It is the ADVERTISEMENT half of the VMArtifactsAvailable capability, minted by
// cmd/k3sm from provider.NodeCapabilities.VMArtifacts, and it follows the same
// presence-only, delete-on-loss discipline as every key above.
//
// IT IS DELIBERATELY NOT ON THE vm RuntimeClass NODESELECTOR, which stays pinned
// to LabelVirtualization alone. The two facts are independent (see
// provider.NodeCapabilities.VMArtifacts), and a vm pod genuinely needs both — but
// adding a second required key to the shipped RuntimeClass would change the
// scheduling contract of every existing vm pod in a commit whose subject is the
// artifact feeder. What this key buys today is a TRUTHFUL answer to "why did my
// vm pod land here and fail closed", which is exactly the question the artifact
// half of the failure produces and the virtualization label cannot answer.
//
// Like its siblings it never changes kubernetes.io/arch or kubernetes.io/os: the
// node is darwin, whatever the guest it can boot.
const LabelVMArtifacts = "k3sm.io/vm-artifacts"

// LabelTrue is the value LabelVirtualization, LabelRosetta, and LabelRosettaLinux
// carry on a capable node — and the value this RuntimeClass's nodeSelector requires.
// Every one of them is PRESENCE-only: a node that loses the capability has the key
// DELETED, never set to "false" (see cmd/k3sm's applyVirtualizationLabel /
// applyRosettaLabels).
const LabelTrue = "true"

// managedLabel marks the RuntimeClass this package provisions, matching pkg/rbac /
// pkg/policy so k3sm-managed objects are greppable and distinct from operator- or
// apiserver-authored ones.
const managedLabel = "k3sm.io/managed"

// vmMemoryOverhead is the vm RuntimeClass's Overhead.PodFixed memory term: a
// conservative host-side scheduler-ACCOUNTING floor for the per-pod cost of an Apple
// Virtualization.framework micro-VM that lives OUTSIDE the pod's guest RAM — the VMM
// host-process RSS (~50–150Mi) plus the guest Linux kernel baseline (~50–100Mi). The
// scheduler subtracts Overhead.PodFixed from node allocatable when admitting a vm
// pod, so without it the scheduler accounts ZERO micro-VM overhead and oversubscribes
// the node. It is a deliberately conservative floor to be REFINED by a VZ-boot
// lab run, NOT a measured exact figure. 256Mi (not 128Mi: 128Mi would be consumed by the
// VMM process alone, re-admitting the very oversubscription this fixes; cf. Kata
// Containers' 160–256Mi defaults).
//
// MEMORY-ONLY by design — there is deliberately no PodFixed[cpu]. k3sm CPU is
// best-effort QoS, not CFS-enforced (see ../provider/translate.go podQOSClass),
// so a cpu Overhead term would misrepresent a
// reservation k3sm cannot enforce; a cpu term is additive later only if the lab
// justifies it.
//
// THREE DISTINCT memory figures must not be conflated (a future maintainer must NOT
// double-count — the provider must never fold this overhead into the guest RAM):
//   - Overhead.PodFixed[memory] (HERE) — host-side scheduler ACCOUNTING for the VMM,
//     subtracted from node allocatable; never allocated to the guest.
//   - podVMMemoryBytes (../provider/translate.go) — the GUEST RAM allocation handed to
//     VZ, summed from the pod's containers.
//   - memory_limit_bytes (../provider/translate.go podMemoryLimitBytes) — the
//     host-PROCESS OOM ceiling.
//
// resource.Quantity is a struct (not a constant-expressible type), so this is a
// package var, never a const.
var vmMemoryOverhead = resource.MustParse("256Mi")

// Provision idempotently provisions the vm RuntimeClass: a node.k8s.io/v1
// RuntimeClass named "vm" with handler "vm", a scheduling.nodeSelector requiring
// LabelVirtualization=LabelTrue (so a pod with spec.runtimeClassName: vm is scheduled
// ONLY onto a node that advertises the Virtualization.framework backend — the kube
// RuntimeClass admission plugin merges the selector into the pod), and an
// Overhead.PodFixed memory floor (vmMemoryOverhead) so the scheduler ACCOUNTS the
// micro-VM's host-side cost instead of oversubscribing the node. It is safe to call on
// every server start and authors only the k3sm-named "vm" object.
//
// It is Create-tolerate-AlreadyExists and never LISTs to decide what to provision
// (matching pkg/rbac under the pinned kine, where ConsistentListFromCache is GA-locked
// true and a watch-cache LIST can read stale). On AlreadyExists it RECONCILES the
// k3sm-owned MANAGED SHAPE onto the persisted object — the "vm" RuntimeClass lives in
// kine across restarts, so a cluster first provisioned by an older k3sm (which had no
// Overhead, and never re-pinned the nodeSelector) or hand-edited by an operator is
// repaired in place. The reconcile does a direct, consistent Get (never a stale-prone
// LIST) and repairs two MUTABLE dimensions with a per-key FLOOR-merge, never a wholesale
// clobber:
//
//   - scheduling.nodeSelector (reconcileManagedShape) — each k3sm-owned key that is
//     missing or wrong is (re)set; operator-added keys are PRESERVED (a wholesale replace
//     with {virtualization:true} would strip an operator key and WIDEN vm placement,
//     relaxing the confinement the selector exists to enforce).
//   - Overhead.PodFixed (reconcileOverhead) — each term below its floor is raised; an
//     operator who RAISED a term stays raised; unrelated keys are preserved.
//
// The two repairs COMPOSE by call-then-accumulate (each is evaluated into its own bool,
// then OR-ed — never reconcileManagedShape(...) || reconcileOverhead(...), whose Go
// short-circuit would SKIP the second repair whenever the first fired, persisting a
// half-repaired object). An already-current object makes NO Update (no churn / HA-churn on
// restart).
//
// The RuntimeClass handler is IMMUTABLE at the apiserver, so a wrong handler is
// COMPARE-and-WARNED, never Update-repaired: an Update carrying a handler change is
// rejected Invalid (not a Conflict — RetryOnConflict does not retry it) and would reject
// the WHOLE Update, including the security-critical nodeSelector repair. A wrong handler is
// already fail-closed at runtime — runtimed resolves the POD's own handler through the
// compile-time apis table (an unknown handler is runtimev1.ErrUnknownHandler, a refusal),
// not through this object — so k3sm logs the anomaly and repairs what it legally can.
//
// The Get→reconcile→Update runs inside a bounded retry.RetryOnConflict so a simultaneous
// multi-server (HA) upgrade converges in-call rather than leaving the optimistic-concurrency
// loser to wait for its next restart. If the class is DELETED between the Create and the
// Get (TOCTOU), it re-lays the FULL desired shape (handler + nodeSelector + Overhead — a
// partial re-create would break fail-closed VZ scheduling); a self-authored full-shape
// re-create is already correct and needs no follow-on reconcile. If a concurrent creator
// won that re-create (AlreadyExists), it does ONE bounded, consistent re-Get and reconciles
// that object's shape — never an unbounded create→AlreadyExists→re-Get loop (RetryOnConflict
// bounds only Conflict, not a create/delete race, which would otherwise livelock). A missing
// or stale RuntimeClass is itself fail-closed — a vm pod naming an absent class is rejected
// at admission, and zero accounted overhead only oversubscribes — so unlike pkg/rbac the
// caller treats an error as log-and-continue.
func Provision(ctx context.Context, cs kubernetes.Interface) error {
	_, err := cs.NodeV1().RuntimeClasses().Create(ctx, desiredRuntimeClass(), metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create vm runtime class: %w", err)
	}
	// The class already exists — reconcile the k3sm-owned managed shape (nodeSelector) and
	// the Overhead floor onto it. Retry on the optimistic-concurrency conflict a simultaneous
	// multi-server (HA) upgrade produces: re-Get consistently, re-evaluate, re-Update, so the
	// repair converges in-call rather than waiting for the loser's next restart. A consistent
	// Get (never a stale-prone LIST) is required under the pinned kine (ConsistentListFromCache
	// GA-locked true).
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := cs.NodeV1().RuntimeClasses().Get(ctx, Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// Deleted between Create and Get (TOCTOU) — re-lay the FULL desired shape
			// (handler + nodeSelector + Overhead; a partial re-create would break the
			// fail-closed VZ-node scheduling).
			_, cerr := cs.NodeV1().RuntimeClasses().Create(ctx, desiredRuntimeClass(), metav1.CreateOptions{})
			if cerr == nil {
				// A self-authored full-shape Create is already correct — no reconcile.
				return nil
			}
			if !apierrors.IsAlreadyExists(cerr) {
				return fmt.Errorf("re-create vm runtime class: %w", cerr)
			}
			// A concurrent creator (an HA peer) won the re-create race: the object was
			// deleted and relaid concurrently. Do ONE bounded, consistent re-Get and heal
			// THAT object's shape — never loop the create→AlreadyExists→re-Get dance
			// (RetryOnConflict bounds only Conflict, not a create/delete race, so an
			// unbounded re-Get retry would livelock).
			slog.InfoContext(ctx, "vm runtime class was deleted and re-created concurrently; reconciling the concurrent object", "name", Name)
			concurrent, gerr := cs.NodeV1().RuntimeClasses().Get(ctx, Name, metav1.GetOptions{})
			if apierrors.IsNotFound(gerr) {
				// Deleted AGAIN before the re-Get — a missing class is itself fail-closed
				// at admission, so leave it to the next Provision rather than spin.
				slog.InfoContext(ctx, "vm runtime class vanished again after a concurrent re-create; leaving it to the next Provision", "name", Name)
				return nil
			}
			if gerr != nil {
				return fmt.Errorf("re-get vm runtime class after concurrent re-create: %w", gerr)
			}
			return reconcileExisting(ctx, cs, concurrent)
		}
		if err != nil {
			return fmt.Errorf("get vm runtime class for reconcile: %w", err)
		}
		return reconcileExisting(ctx, cs, existing)
	}); err != nil {
		return fmt.Errorf("reconcile vm runtime class: %w", err)
	}
	return nil
}

// reconcileExisting repairs an already-existing "vm" RuntimeClass toward the k3sm-owned
// managed shape (scheduling.nodeSelector, via reconcileManagedShape) and the host-side
// Overhead floor (reconcileOverhead), issuing at MOST ONE Update. The two repairs COMPOSE
// by call-then-accumulate: each is evaluated into its own bool BEFORE they are OR-ed, so
// neither is skipped by a `||` short-circuit when the other already reported a change (which
// would persist a half-repaired object). It returns the RAW Update error so a Conflict stays
// visible to the enclosing retry.RetryOnConflict; an already-current object makes no Update.
func reconcileExisting(ctx context.Context, cs kubernetes.Interface, existing *nodev1.RuntimeClass) error {
	desired := desiredRuntimeClass()
	shapeChanged := reconcileManagedShape(ctx, existing, desired)
	overheadChanged := reconcileOverhead(existing, desired.Overhead)
	if !shapeChanged && !overheadChanged {
		slog.DebugContext(ctx, "vm runtime class already current", "name", Name)
		return nil
	}
	// existing.Handler is deliberately NEVER assigned (reconcileManagedShape compare-and-warns it —
	// RuntimeClass.Handler is immutable at the apiserver), so this Update carries the stored handler
	// UNCHANGED. That is load-bearing: a wrong-handler class's nodeSelector/Overhead repair still
	// lands, because the apiserver's immutable-field check rejects only a handler CHANGE. Do NOT add
	// existing.Handler = desired.Handler here or in reconcileManagedShape.
	if _, err := cs.NodeV1().RuntimeClasses().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return err // a Conflict is retried by the enclosing RetryOnConflict; other errors propagate
	}
	slog.InfoContext(ctx, "reconciled vm runtime class managed shape onto pre-existing class",
		"name", Name, "nodeSelectorRepaired", shapeChanged, "overheadRepaired", overheadChanged,
		"podFixedMemory", vmMemoryOverhead.String())
	return nil
}

// desiredRuntimeClass builds the k3sm-managed "vm" RuntimeClass: handler "vm", a
// scheduling.nodeSelector pinning it to VZ-capable nodes, and the host-side memory
// Overhead floor (desiredOverhead). It is the single shape the create path lays down
// and the reconcile path measures an existing object against.
func desiredRuntimeClass() *nodev1.RuntimeClass {
	return &nodev1.RuntimeClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   Name,
			Labels: map[string]string{managedLabel: "true"},
		},
		Handler: string(runtimev1.HandlerVM),
		Scheduling: &nodev1.Scheduling{
			NodeSelector: map[string]string{LabelVirtualization: LabelTrue},
		},
		Overhead: desiredOverhead(),
	}
}

// desiredOverhead is the vm RuntimeClass's host-side scheduler-accounting Overhead:
// PodFixed memory == vmMemoryOverhead, memory-ONLY (no cpu term — see vmMemoryOverhead).
// A fresh value per call so the create and reconcile paths never alias one Overhead.
func desiredOverhead() *nodev1.Overhead {
	return &nodev1.Overhead{PodFixed: corev1.ResourceList{corev1.ResourceMemory: vmMemoryOverhead}}
}

// reconcileOverhead raises rc's host-side Overhead.PodFixed to the desired floor, per
// key: for each key in desired.PodFixed, if rc lacks it OR carries less than desired, it
// is set to desired (allocating Overhead/PodFixed as needed). Keys NOT in desired are
// preserved, and a key already at or above its floor is left untouched (an operator who
// raised it stays raised; Cmp >= 0). The single desiredOverhead() key set thus drives
// both the staleness check and the set, so a future cpu term auto-extends this with no
// other edit. It returns whether it changed rc (false => already current => no Update).
func reconcileOverhead(rc *nodev1.RuntimeClass, desired *nodev1.Overhead) (changed bool) {
	for name, want := range desired.PodFixed {
		if rc.Overhead != nil {
			if cur, ok := rc.Overhead.PodFixed[name]; ok && cur.Cmp(want) >= 0 {
				continue // already at/above floor — preserve (operator may have raised it)
			}
		}
		if rc.Overhead == nil {
			rc.Overhead = &nodev1.Overhead{}
		}
		if rc.Overhead.PodFixed == nil {
			rc.Overhead.PodFixed = corev1.ResourceList{}
		}
		rc.Overhead.PodFixed[name] = want
		changed = true
	}
	return changed
}

// reconcileManagedShape repairs the k3sm-OWNED, MUTABLE managed shape of rc toward desired
// — today the scheduling.nodeSelector — and COMPARE-and-WARNS the IMMUTABLE handler without
// ever mutating it. It returns whether it changed rc's mutable shape; a handler mismatch is
// logged but NEVER counted as a change, so it can never trigger an Update.
//
// nodeSelector is a per-key FLOOR-merge (mirrors reconcileOverhead, NOT a wholesale clobber):
// for each k3sm-owned key in desired.Scheduling.NodeSelector (today just
// LabelVirtualization=LabelTrue), a key rc is missing or carries a WRONG value for is (re)set
// — allocating Scheduling/NodeSelector as needed — while a key already correct is left
// untouched (idempotent: no Update, no HA-churn on restart) and operator-added keys are
// PRESERVED. A wholesale replace with exactly {virtualization:true} would strip an
// operator-added key and WIDEN vm placement, relaxing the confinement this selector exists to
// enforce. Iterating desired's map (the single source of k3sm-owned keys) auto-extends this if
// a k3sm-owned key is added later.
//
// The handler is IMMUTABLE at the apiserver (validated on update): an Update carrying a
// changed handler is rejected Invalid — NOT a Conflict, so NOT retried by RetryOnConflict —
// and would reject the WHOLE Update, including the security-critical nodeSelector repair. So a
// wrong handler is logged as an operator anomaly, never repaired here; it is already
// fail-closed at runtime because runtimed resolves the POD's own handler through the
// compile-time apis table (an unknown handler is runtimev1.ErrUnknownHandler, a refusal — not
// this object). An operator changes a handler by deleting and recreating the class.
func reconcileManagedShape(ctx context.Context, rc, desired *nodev1.RuntimeClass) (changed bool) {
	if desired.Scheduling != nil {
		for key, want := range desired.Scheduling.NodeSelector {
			if rc.Scheduling != nil && rc.Scheduling.NodeSelector[key] == want {
				continue // already correct — preserve (idempotent, no churn)
			}
			if rc.Scheduling == nil {
				rc.Scheduling = &nodev1.Scheduling{}
			}
			if rc.Scheduling.NodeSelector == nil {
				rc.Scheduling.NodeSelector = map[string]string{}
			}
			rc.Scheduling.NodeSelector[key] = want
			changed = true
		}
	}
	if rc.Handler != desired.Handler {
		// Immutable at the apiserver — compare-and-warn ONLY, never Update-repair (an Update
		// carrying the change is rejected Invalid and would block the nodeSelector repair).
		slog.WarnContext(ctx, "vm runtime class has an unexpected immutable handler; NOT repairing it (RuntimeClass.Handler is immutable at the apiserver, an Update would be rejected Invalid and block the nodeSelector repair). Runtime dispatch is already fail-closed on an unknown handler (runtimev1.ErrUnknownHandler); an operator must delete and recreate the class to change its handler",
			"name", Name, "handler", rc.Handler, "wantHandler", desired.Handler)
	}
	return changed
}
