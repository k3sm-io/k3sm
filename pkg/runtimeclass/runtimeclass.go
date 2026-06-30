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

// LabelTrue is the value LabelVirtualization carries on a VZ-capable node — and the
// value this RuntimeClass's nodeSelector requires.
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
// the node. It is a deliberately conservative floor to be REFINED by the M5 VZ-boot
// lab, NOT a measured exact figure. 256Mi (not 128Mi: 128Mi would be consumed by the
// VMM process alone, re-admitting the very oversubscription this fixes; cf. Kata
// Containers' 160–256Mi defaults).
//
// MEMORY-ONLY by design — there is deliberately no PodFixed[cpu]. k3sm CPU is
// best-effort QoS, not CFS-enforced (see ../provider/translate.go podQOSClass and
// ../../docs/stockkitty-readiness.md), so a cpu Overhead term would misrepresent a
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
// Overhead: the "vm" RuntimeClass persists in kine across restarts, so a cluster first
// provisioned WITHOUT the overhead (pre-B24, or by an operator) would otherwise
// oversubscribe forever. It does a direct, consistent Get (never a stale-prone LIST)
// and Updates ONLY when the host-side floor is missing or below vmMemoryOverhead,
// preserving handler/scheduling; an already-current Overhead makes NO Update call (no
// churn on every restart). A missing or stale RuntimeClass is itself fail-closed — a vm
// pod naming an absent class is rejected at admission, and zero accounted overhead only
// oversubscribes — so unlike pkg/rbac the caller treats an error as log-and-continue.
func Provision(ctx context.Context, cs kubernetes.Interface) error {
	_, err := cs.NodeV1().RuntimeClasses().Create(ctx, desiredRuntimeClass(), metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create vm runtime class: %w", err)
	}
	// The class already exists — reconcile its host-side Overhead onto the existing
	// object. Get is direct and consistent (a watch-cache LIST can read stale under the
	// pinned kine); Update only when the floor is missing or below desired.
	existing, err := cs.NodeV1().RuntimeClasses().Get(ctx, Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get vm runtime class for overhead reconcile: %w", err)
	}
	if overheadCurrent(existing) {
		slog.DebugContext(ctx, "vm runtime class overhead already current", "name", Name)
		return nil
	}
	existing.Overhead = desiredOverhead()
	if _, err := cs.NodeV1().RuntimeClasses().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("reconcile vm runtime class overhead: %w", err)
	}
	slog.InfoContext(ctx, "reconciled vm runtime class overhead onto pre-existing class",
		"name", Name, "podFixedMemory", vmMemoryOverhead.String())
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

// overheadCurrent reports whether rc already carries at least the desired host-side
// memory Overhead floor: Overhead.PodFixed[memory] present and >= vmMemoryOverhead. A
// nil Overhead, an absent memory entry, or a value below the floor is stale and must be
// reconciled. It is a FLOOR comparison (Cmp >= 0), never exact equality, so a fresh
// create is idempotent (256Mi vs 256Mi ⇒ no Update), an operator who RAISED the
// overhead above the k3sm floor is left untouched, and a future lab-refined increase
// still reconciles upward.
func overheadCurrent(rc *nodev1.RuntimeClass) bool {
	if rc.Overhead == nil {
		return false
	}
	q, ok := rc.Overhead.PodFixed[corev1.ResourceMemory]
	if !ok {
		return false
	}
	return q.Cmp(vmMemoryOverhead) >= 0
}
