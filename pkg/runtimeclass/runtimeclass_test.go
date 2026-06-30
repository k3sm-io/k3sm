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
	"testing"

	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestVMRuntimeClassNodeSelector is the M5.1 proof that Provision lays down the
// node.k8s.io/v1 RuntimeClass "vm" with handler "vm" AND a scheduling.nodeSelector
// pinning it to VZ-capable nodes (k3sm.io/virtualization=true) — the fail-closed
// scheduling gate that keeps a vm pod off a non-VZ node. The handler matches the
// apis handler→backend table (runtimev1.HandlerVM) so dispatch and scheduling agree.
func TestVMRuntimeClassNodeSelector(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	rc, err := cs.NodeV1().RuntimeClasses().Get(ctx, Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get vm runtime class: %v", err)
	}
	if rc.Name != Name {
		t.Errorf("runtime class name = %q, want %q", rc.Name, Name)
	}
	if Name != "vm" {
		t.Errorf("Name const = %q, want the literal vm an operator sets via spec.runtimeClassName (== runtimev1.HandlerVM)", Name)
	}
	if rc.Handler != string(runtimev1.HandlerVM) {
		t.Errorf("handler = %q, want %q (the apis handler that maps to SANDBOX_BACKEND_VM)", rc.Handler, runtimev1.HandlerVM)
	}
	if rc.Scheduling == nil {
		t.Fatal("scheduling must be set so the class pins vm pods to VZ-capable nodes")
	}
	if got := rc.Scheduling.NodeSelector[LabelVirtualization]; got != LabelTrue {
		t.Errorf("scheduling.nodeSelector[%s] = %q, want %q (the VZ-capability gate)", LabelVirtualization, got, LabelTrue)
	}
	if len(rc.Scheduling.NodeSelector) != 1 {
		t.Errorf("nodeSelector = %v, want exactly the single virtualization key (minimal)", rc.Scheduling.NodeSelector)
	}
	if rc.Labels[managedLabel] != "true" {
		t.Errorf("runtime class must carry the %s=true managed label, got %v", managedLabel, rc.Labels)
	}
}

// TestVMRuntimeClassProvisionIdempotent confirms a re-run is an AlreadyExists no-op:
// no error and exactly one RuntimeClass (a double-create would surface as an error
// or a duplicate), so the provisioning is safe on every server restart.
func TestVMRuntimeClassProvisionIdempotent(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("second Provision (idempotent): %v", err)
	}

	list, err := cs.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list runtime classes: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != Name {
		t.Errorf("runtime classes = %d, want exactly [vm] (no duplicate on re-provision)", len(list.Items))
	}
}

// TestVMRuntimeClassOverhead is the B24 proof that the vm RuntimeClass carries a
// host-side scheduler-accounting Overhead.PodFixed memory floor (so the scheduler
// stops accounting ZERO micro-VM overhead and oversubscribing the node), on BOTH the
// fresh-create path and the upgrade/reconcile path — the latter being the case that a
// create-tolerate-AlreadyExists Provision leaves INERT, since the "vm" RuntimeClass
// persists in kine across restarts. The memory floor is asserted with Quantity.Cmp
// (>= vmMemoryOverhead, never exact equality: the value is lab-refined) and is
// MEMORY-ONLY (no PodFixed[cpu]: k3sm CPU is best-effort QoS, not a CFS reservation).
func TestVMRuntimeClassOverhead(t *testing.T) {
	ctx := context.Background()

	// assertOverheadFloor asserts rc carries the memory-only host-side Overhead floor:
	// PodFixed[memory] present and >= vmMemoryOverhead (a FLOOR, never exact equality),
	// and NO PodFixed[cpu].
	assertOverheadFloor := func(t *testing.T, rc *nodev1.RuntimeClass) {
		t.Helper()
		if rc.Overhead == nil {
			t.Fatalf("Overhead is nil; want PodFixed[memory] >= %s so the scheduler accounts the micro-VM's host-side cost", vmMemoryOverhead.String())
		}
		mem, ok := rc.Overhead.PodFixed[corev1.ResourceMemory]
		if !ok {
			t.Fatalf("Overhead.PodFixed[memory] absent; want >= %s", vmMemoryOverhead.String())
		}
		if mem.Cmp(vmMemoryOverhead) < 0 {
			t.Errorf("Overhead.PodFixed[memory] = %s, want >= %s (the conservative micro-VM floor)", mem.String(), vmMemoryOverhead.String())
		}
		if _, ok := rc.Overhead.PodFixed[corev1.ResourceCPU]; ok {
			t.Errorf("Overhead.PodFixed[cpu] is set; want memory-ONLY (k3sm CPU is best-effort QoS, not a CFS reservation)")
		}
	}

	get := func(t *testing.T, cs kubernetes.Interface) *nodev1.RuntimeClass {
		t.Helper()
		rc, err := cs.NodeV1().RuntimeClasses().Get(ctx, Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get vm runtime class: %v", err)
		}
		return rc
	}

	// countUpdates installs a pass-through reactor that counts Update calls on
	// runtimeclasses (it returns handled=false so the default tracker still performs
	// the update). It lets the subtests prove the reconcile MECHANISM — exactly one
	// Update on upgrade, zero on an already-current re-provision (no churn).
	countUpdates := func(cs *fake.Clientset, n *int) {
		cs.PrependReactor("update", "runtimeclasses", func(k8stesting.Action) (bool, runtime.Object, error) {
			*n++
			return false, nil, nil
		})
	}

	t.Run("create lays down the overhead floor", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		assertOverheadFloor(t, get(t, cs))
	})

	// upgrade is the reconcile proof: a cluster provisioned before B24 carries a "vm"
	// RuntimeClass with NO Overhead (it persists in kine across restarts). Provision
	// MUST Get+Update it to carry the floor — create-only logic leaves Overhead==nil and
	// this subtest stays RED.
	t.Run("upgrade reconciles overhead onto a pre-existing class", func(t *testing.T) {
		cs := fake.NewClientset()
		preexisting := &nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{
				Name:   Name,
				Labels: map[string]string{managedLabel: "true"},
			},
			Handler: string(runtimev1.HandlerVM),
			Scheduling: &nodev1.Scheduling{
				NodeSelector: map[string]string{LabelVirtualization: LabelTrue},
			},
			// Overhead deliberately nil — the pre-B24 shape.
		}
		if _, err := cs.NodeV1().RuntimeClasses().Create(ctx, preexisting, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed pre-existing vm runtime class: %v", err)
		}
		if seeded := get(t, cs); seeded.Overhead != nil {
			t.Fatalf("seed sanity: Overhead = %v, want nil (the pre-B24 shape)", seeded.Overhead)
		}

		var updates int
		countUpdates(cs, &updates)
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision over pre-existing class: %v", err)
		}
		if updates != 1 {
			t.Errorf("reconcile issued %d Update call(s), want exactly 1 (the reconcile path must reach the existing object)", updates)
		}
		reconciled := get(t, cs)
		assertOverheadFloor(t, reconciled)
		// Reconcile touches only Overhead — handler + scheduling must survive.
		if reconciled.Handler != string(runtimev1.HandlerVM) {
			t.Errorf("handler = %q after reconcile, want %q (reconcile must preserve it)", reconciled.Handler, runtimev1.HandlerVM)
		}
		if reconciled.Scheduling == nil || reconciled.Scheduling.NodeSelector[LabelVirtualization] != LabelTrue {
			t.Errorf("scheduling.nodeSelector lost in reconcile: %+v", reconciled.Scheduling)
		}
	})

	t.Run("idempotent: a second provision over a current class issues no update", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("first Provision: %v", err)
		}
		// Count only the SECOND provision — the first is a Create, not an Update.
		var updates int
		countUpdates(cs, &updates)
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("second Provision (idempotent): %v", err)
		}
		if updates != 0 {
			t.Errorf("second Provision issued %d Update call(s) on an already-current class, want 0 (no churn)", updates)
		}
		assertOverheadFloor(t, get(t, cs))
	})
}
