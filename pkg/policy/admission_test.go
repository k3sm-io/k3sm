package policy

import (
	"context"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestEnsureDarwinAdmissionProvisions verifies the os=darwin policy + binding are
// created with a Deny action and a CEL expression that requires the
// kubernetes.io/os=darwin nodeSelector (the intent guard).
func TestEnsureDarwinAdmissionProvisions(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()

	if err := EnsureDarwinAdmission(ctx, cs); err != nil {
		t.Fatalf("EnsureDarwinAdmission: %v", err)
	}

	pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, darwinPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(pol.Spec.Validations) == 0 {
		t.Fatal("policy has no validations")
	}
	expr := pol.Spec.Validations[0].Expression
	if !strings.Contains(expr, "nodeSelector") || !strings.Contains(expr, "darwin") {
		t.Errorf("CEL expression does not require the os=darwin nodeSelector: %q", expr)
	}
	if pol.Spec.FailurePolicy == nil || *pol.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Error("failure policy must be Fail (reject on misconfig)")
	}
	if len(pol.Spec.MatchConstraints.ResourceRules) == 0 {
		t.Fatal("policy must match pods on CREATE")
	}

	bind, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, darwinBindingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if bind.Spec.PolicyName != darwinPolicyName {
		t.Errorf("binding points at %q, want %q", bind.Spec.PolicyName, darwinPolicyName)
	}
	foundDeny := false
	for _, a := range bind.Spec.ValidationActions {
		if a == admissionregistrationv1.Deny {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Error("binding must Deny on validation failure")
	}
}

// TestEnsureDarwinAdmissionIdempotent confirms re-provisioning tolerates the
// existing objects (server restart should not error).
func TestEnsureDarwinAdmissionIdempotent(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := EnsureDarwinAdmission(ctx, cs); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if err := EnsureDarwinAdmission(ctx, cs); err != nil {
		t.Fatalf("second provision (idempotent): %v", err)
	}
}

// TestEnsureNoForeignUserAdmission verifies the foreign-user policy is created
// with a Deny binding and a CEL expression that pins runAsUser/fsGroup to the
// allowed (_k3sm) uid across the pod and container security contexts — so a pod
// requesting a foreign uid is rejected, not silently coerced.
func TestEnsureNoForeignUserAdmission(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()

	const allowedUID int64 = 271
	if err := EnsureNoForeignUserAdmission(ctx, cs, allowedUID); err != nil {
		t.Fatalf("EnsureNoForeignUserAdmission: %v", err)
	}

	pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, foreignUserPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(pol.Spec.Validations) == 0 {
		t.Fatal("policy has no validations")
	}
	expr := pol.Spec.Validations[0].Expression
	for _, want := range []string{"runAsUser", "fsGroup", "271", "containers.all", "initContainers"} {
		if !strings.Contains(expr, want) {
			t.Errorf("CEL expression missing %q: %q", want, expr)
		}
	}
	if pol.Spec.FailurePolicy == nil || *pol.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Error("failure policy must be Fail")
	}

	bind, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, foreignUserBindingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	foundDeny := false
	for _, a := range bind.Spec.ValidationActions {
		if a == admissionregistrationv1.Deny {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Error("binding must Deny a foreign-user pod")
	}

	// Idempotent on server restart.
	if err := EnsureNoForeignUserAdmission(ctx, cs, allowedUID); err != nil {
		t.Errorf("second provision must be idempotent: %v", err)
	}
}
