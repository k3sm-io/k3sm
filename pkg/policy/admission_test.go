package policy

import (
	"context"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
// with a Deny binding and a CEL expression that pins every uid/gid field
// (runAsUser/runAsGroup/fsGroup/supplementalGroups) to the allowed (_k3sm) id
// across the pod, container, initContainer and ephemeralContainer security
// contexts — so a pod requesting a foreign uid/gid is rejected, not silently
// coerced.
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
	for _, want := range []string{
		"runAsUser", "runAsGroup", "fsGroup", "supplementalGroups",
		"271", "containers.all", "initContainers", "ephemeralContainers",
	} {
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

// assertServiceWarnPolicy is the shared check for the M3.1 advisory Service
// policies: the policy matches Services on CREATE+UPDATE, fails OPEN
// (failurePolicy Ignore, so a CEL error can never reject), the binding action is
// Warn and never Deny (advisory only), and provisioning is idempotent.
func assertServiceWarnPolicy(t *testing.T, policyName, bindingName string, wantInExpr []string, ensure func(kubernetes.Interface) error) {
	t.Helper()
	cs := fake.NewClientset()
	ctx := context.Background()

	if err := ensure(cs); err != nil {
		t.Fatalf("ensure %s: %v", policyName, err)
	}

	pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, policyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy %s: %v", policyName, err)
	}
	if len(pol.Spec.Validations) == 0 {
		t.Fatal("policy has no validations")
	}
	expr := pol.Spec.Validations[0].Expression
	for _, want := range wantInExpr {
		if !strings.Contains(expr, want) {
			t.Errorf("CEL expression missing %q: %q", want, expr)
		}
	}
	// An advisory MUST fail open: failurePolicy Fail would reject the request on a
	// CEL runtime error regardless of the Warn action, turning a warning into a
	// hard failure.
	if pol.Spec.FailurePolicy == nil || *pol.Spec.FailurePolicy != admissionregistrationv1.Ignore {
		t.Errorf("failure policy must be Ignore (advisory fails open), got %v", pol.Spec.FailurePolicy)
	}
	if len(pol.Spec.MatchConstraints.ResourceRules) == 0 {
		t.Fatal("policy must match a resource")
	}
	rule := pol.Spec.MatchConstraints.ResourceRules[0]
	if !containsStr(rule.Resources, "services") {
		t.Errorf("policy must match services, got %v", rule.Resources)
	}
	// CREATE + UPDATE so a `kubectl edit` that introduces the divergence also warns.
	if !containsOp(rule.Operations, admissionregistrationv1.Create) || !containsOp(rule.Operations, admissionregistrationv1.Update) {
		t.Errorf("policy must match CREATE and UPDATE, got %v", rule.Operations)
	}

	bind, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, bindingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get binding %s: %v", bindingName, err)
	}
	if bind.Spec.PolicyName != policyName {
		t.Errorf("binding points at %q, want %q", bind.Spec.PolicyName, policyName)
	}
	foundWarn := false
	for _, a := range bind.Spec.ValidationActions {
		if a == admissionregistrationv1.Deny {
			t.Error("advisory binding must NOT Deny (the field/Service stays valid)")
		}
		if a == admissionregistrationv1.Warn {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Error("binding must Warn on the divergence")
	}

	// Idempotent on server restart.
	if err := ensure(cs); err != nil {
		t.Errorf("second provision must be idempotent: %v", err)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func containsOp(xs []admissionregistrationv1.OperationType, want admissionregistrationv1.OperationType) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestExternalTrafficPolicyLocalWarns verifies the advisory that surfaces the
// externalTrafficPolicy: Local divergence — k3sm's userspace splice does not
// preserve client source IP, so only Cluster is honored. It Warns (never Denies),
// keying on the Local value, and fails open.
func TestExternalTrafficPolicyLocalWarns(t *testing.T) {
	assertServiceWarnPolicy(t, etpLocalPolicyName, etpLocalBindingName,
		[]string{"externalTrafficPolicy", "Local"},
		func(cs kubernetes.Interface) error {
			return EnsureExternalTrafficPolicyLocalWarn(context.Background(), cs)
		})
}

// TestUDPServiceWarns verifies the advisory that surfaces the missing UDP
// datapath — the proxy opens no UDP listener, so a UDP Service silently
// blackholes. It Warns (never Denies) on any UDP port, and fails open.
func TestUDPServiceWarns(t *testing.T) {
	assertServiceWarnPolicy(t, udpServicePolicyName, udpServiceBindingName,
		[]string{"protocol", "UDP", "ports.all"},
		func(cs kubernetes.Interface) error { return EnsureUDPServiceWarn(context.Background(), cs) })
}
