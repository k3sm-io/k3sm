package policy

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// darwinPolicyName / darwinBindingName are the cluster-scoped names of the
// os=darwin admission policy and its binding.
const (
	darwinPolicyName  = "k3sm-require-os-darwin"
	darwinBindingName = "k3sm-require-os-darwin-binding"
)

// foreignUserPolicyName / foreignUserBindingName name the policy that rejects a
// pod requesting a foreign runAsUser/fsGroup.
const (
	foreignUserPolicyName  = "k3sm-reject-foreign-user"
	foreignUserBindingName = "k3sm-reject-foreign-user-binding"
)

// darwinSelectorExpr is the CEL the policy enforces on Pod CREATE: the pod must
// declare nodeSelector kubernetes.io/os=darwin. It tolerates a missing
// nodeSelector map (has(...)). The CEL field-escaping rules apply only to dot
// property ACCESS (object.foo); a string LITERAL used as a map key / `in`
// operand is the real key, so the literal "kubernetes.io/os" is used directly.
// A pod without the selector — i.e. any Linux pod — fails the rule and is denied.
const darwinSelectorExpr = `has(object.spec.nodeSelector) && ` +
	`'kubernetes.io/os' in object.spec.nodeSelector && ` +
	`object.spec.nodeSelector['kubernetes.io/os'] == 'darwin'`

// EnsureDarwinAdmission idempotently provisions the os=darwin
// ValidatingAdmissionPolicy and its binding so non-darwin Pods are rejected at
// admission. It is safe to call on every server start: an AlreadyExists is
// treated as success.
func EnsureDarwinAdmission(ctx context.Context, cs kubernetes.Interface) error {
	api := cs.AdmissionregistrationV1()

	failFail := admissionregistrationv1.Fail
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   darwinPolicyName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &failFail,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				}},
			},
			Validations: []admissionregistrationv1.Validation{{
				Expression: darwinSelectorExpr,
				Message:    "k3sm: pods must target a darwin node via nodeSelector kubernetes.io/os=darwin",
				Reason:     reasonInvalid(),
			}},
		},
	}

	if _, err := api.ValidatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create os=darwin admission policy: %w", err)
	}

	deny := admissionregistrationv1.Deny
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   darwinBindingName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        darwinPolicyName,
			ValidationActions: []admissionregistrationv1.ValidationAction{deny},
		},
	}
	if _, err := api.ValidatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create os=darwin admission binding: %w", err)
	}
	return nil
}

// foreignUserExpr is the CEL the foreign-user policy enforces on Pod CREATE: it
// admits a pod ONLY if every runAsUser/fsGroup it declares (pod-level
// securityContext + each container/initContainer securityContext) equals
// allowedUID — the single identity every k3sm pod runs as (the _k3sm daemon;
// there is no per-pod uid isolation). A pod that omits these fields inherits the
// daemon identity and is admitted; a pod asking for ANY other uid/gid is denied
// rather than silently coerced (which would mislead the workload, and on the
// unprivileged daemon would wedge at runtime since a credential drop requires
// root). The OR short-circuits guard the optional-field access (a missing
// securityContext never reaches the field comparison).
func foreignUserExpr(allowedUID int64) string {
	psc := "object.spec.securityContext"
	return fmt.Sprintf(
		"(!has(%[1]s) || !has(%[1]s.runAsUser) || %[1]s.runAsUser == %[2]d) && "+
			"(!has(%[1]s) || !has(%[1]s.fsGroup) || %[1]s.fsGroup == %[2]d) && "+
			"object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.runAsUser) || c.securityContext.runAsUser == %[2]d) && "+
			"(!has(object.spec.initContainers) || object.spec.initContainers.all(c, !has(c.securityContext) || !has(c.securityContext.runAsUser) || c.securityContext.runAsUser == %[2]d))",
		psc, allowedUID)
}

// EnsureNoForeignUserAdmission idempotently provisions the ValidatingAdmissionPolicy
// that REJECTS (server-side, never silently coerces) a pod requesting a
// runAsUser/fsGroup other than allowedUID — the uid every k3sm pod runs as, since
// the runtime offers no per-pod uid isolation. It is the admission counterpart to
// the runtime's privilege-drop refusal; provision it with the control plane's own
// (the _k3sm) uid. Safe to call on every server start (AlreadyExists is success).
func EnsureNoForeignUserAdmission(ctx context.Context, cs kubernetes.Interface, allowedUID int64) error {
	api := cs.AdmissionregistrationV1()

	failFail := admissionregistrationv1.Fail
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   foreignUserPolicyName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &failFail,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				}},
			},
			Validations: []admissionregistrationv1.Validation{{
				Expression: foreignUserExpr(allowedUID),
				Message:    "k3sm: pods may not request a foreign runAsUser/fsGroup — every k3sm pod runs as the _k3sm service user (no per-pod uid isolation)",
				Reason:     reasonInvalid(),
			}},
		},
	}
	if _, err := api.ValidatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create foreign-user admission policy: %w", err)
	}

	deny := admissionregistrationv1.Deny
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   foreignUserBindingName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        foreignUserPolicyName,
			ValidationActions: []admissionregistrationv1.ValidationAction{deny},
		},
	}
	if _, err := api.ValidatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create foreign-user admission binding: %w", err)
	}
	return nil
}

// reasonInvalid returns the StatusReason the policy attaches to a denial
// (Invalid → HTTP 422), so kubectl surfaces a clear rejection.
func reasonInvalid() *metav1.StatusReason {
	r := metav1.StatusReasonInvalid
	return &r
}
