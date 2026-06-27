package runtimeclass

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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
