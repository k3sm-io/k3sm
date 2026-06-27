package policy

import (
	"context"
	"fmt"
	"strings"

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
// pod requesting a foreign runAsUser/runAsGroup/fsGroup/supplementalGroups.
const (
	foreignUserPolicyName  = "k3sm-reject-foreign-user"
	foreignUserBindingName = "k3sm-reject-foreign-user-binding"
)

// etpLocalPolicyName / etpLocalBindingName name the Warn policy that surfaces the
// externalTrafficPolicy: Local divergence (no client source-IP preservation).
const (
	etpLocalPolicyName  = "k3sm-warn-service-externaltrafficpolicy-local"
	etpLocalBindingName = "k3sm-warn-service-externaltrafficpolicy-local-binding"
)

// udpServicePolicyName / udpServiceBindingName name the Warn policy that surfaces
// the missing UDP datapath (a UDP Service silently blackholes).
const (
	udpServicePolicyName  = "k3sm-warn-service-udp"
	udpServiceBindingName = "k3sm-warn-service-udp-binding"
)

// etpLocalExpr admits (evaluates true) UNLESS a Service sets
// externalTrafficPolicy: Local. k3sm's userspace L4 splice opens a fresh backend
// connection (see darwin-net proxy.splice), so it does NOT preserve the external
// client's source IP — only externalTrafficPolicy: Cluster is honored. A Local
// Service is not rejected (the field stays valid) but the divergence is surfaced
// to kubectl as a warning. The has() guard tolerates a Service that omits the
// field (every ClusterIP Service), so only an explicit Local triggers the warning.
const etpLocalExpr = `!has(object.spec.externalTrafficPolicy) || object.spec.externalTrafficPolicy != 'Local'`

// udpServiceExpr admits (evaluates true) UNLESS any Service port is UDP. k3sm
// opens no UDP datapath (the proxy binds only TCP listeners — see darwin-net
// proxy.openListener, where a UDP port ensures the lo0 alias but opens no datagram
// socket), so a UDP Service silently blackholes. The warning says so at the API
// rather than leaving the operator to discover it at runtime. The per-port has()
// guard tolerates a port that omits protocol (defaulted to TCP server-side).
const udpServiceExpr = `object.spec.ports.all(p, !has(p.protocol) || p.protocol != 'UDP')`

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
// admits a pod ONLY if every uid/gid it declares equals allowedID — the single
// identity every k3sm pod runs as (the _k3sm daemon; there is no per-pod uid/gid
// isolation). It pins ALL the uid/gid-setting fields, so no container shape leaves
// a gap:
//   - pod-level securityContext: runAsUser, runAsGroup, fsGroup, supplementalGroups
//   - every containers / initContainers / ephemeralContainers securityContext:
//     runAsUser and runAsGroup
//
// A pod that omits these fields inherits the daemon identity and is admitted; a
// pod asking for ANY other uid/gid is denied rather than silently coerced (which
// would mislead the workload, and on the unprivileged daemon would wedge at
// runtime since a credential drop requires root). The OR short-circuits guard the
// optional-field access (a missing securityContext never reaches the comparison);
// supplementalGroups is a list, so .all() requires every entry to be allowedID.
func foreignUserExpr(allowedID int64) string {
	psc := "object.spec.securityContext"
	clauses := []string{
		fmt.Sprintf("(!has(%[1]s) || !has(%[1]s.runAsUser) || %[1]s.runAsUser == %[2]d)", psc, allowedID),
		fmt.Sprintf("(!has(%[1]s) || !has(%[1]s.runAsGroup) || %[1]s.runAsGroup == %[2]d)", psc, allowedID),
		fmt.Sprintf("(!has(%[1]s) || !has(%[1]s.fsGroup) || %[1]s.fsGroup == %[2]d)", psc, allowedID),
		fmt.Sprintf("(!has(%[1]s) || !has(%[1]s.supplementalGroups) || %[1]s.supplementalGroups.all(g, g == %[2]d))", psc, allowedID),
		containersClause("object.spec.containers", allowedID, false),
		containersClause("object.spec.initContainers", allowedID, true),
		containersClause("object.spec.ephemeralContainers", allowedID, true),
	}
	return strings.Join(clauses, " && ")
}

// containersClause builds the CEL clause requiring every container in list to pin
// both runAsUser and runAsGroup to allowedID (or omit them). optional wraps the
// clause in a has(list) guard for the optional initContainers/ephemeralContainers
// lists; the required containers list needs no guard.
func containersClause(list string, allowedID int64, optional bool) string {
	inner := fmt.Sprintf(
		"%[1]s.all(c, (!has(c.securityContext) || !has(c.securityContext.runAsUser) || c.securityContext.runAsUser == %[2]d) && "+
			"(!has(c.securityContext) || !has(c.securityContext.runAsGroup) || c.securityContext.runAsGroup == %[2]d))",
		list, allowedID)
	if optional {
		return fmt.Sprintf("(!has(%s) || %s)", list, inner)
	}
	return inner
}

// EnsureNoForeignUserAdmission idempotently provisions the ValidatingAdmissionPolicy
// that REJECTS (server-side, never silently coerces) a pod requesting any
// runAsUser/runAsGroup/fsGroup/supplementalGroups other than allowedUID — the
// identity every k3sm pod runs as, since the runtime offers no per-pod uid/gid
// isolation. It is the admission counterpart to the runtime's privilege-drop
// refusal; provision it with the control plane's own (the _k3sm) uid. Safe to call
// on every server start (AlreadyExists is success).
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
				Message:    "k3sm: pods may not request a foreign runAsUser/runAsGroup/fsGroup/supplementalGroups — every k3sm pod runs as the _k3sm service user (no per-pod uid/gid isolation)",
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

// EnsureExternalTrafficPolicyLocalWarn idempotently provisions a Warn-action
// ValidatingAdmissionPolicy on Services that set externalTrafficPolicy: Local.
// k3sm's userspace splice does NOT preserve the client source IP (only Cluster is
// honored), so Local is silently downgraded to Cluster at the datapath; the policy
// surfaces that divergence to kubectl WITHOUT rejecting the Service (the field
// stays valid). Safe to call on every server start (AlreadyExists is success).
func EnsureExternalTrafficPolicyLocalWarn(ctx context.Context, cs kubernetes.Interface) error {
	return ensureServiceWarnPolicy(ctx, cs, etpLocalPolicyName, etpLocalBindingName, etpLocalExpr,
		"k3sm: Service externalTrafficPolicy: Local is not honored — the userspace proxy does not preserve client source IP (only Cluster); the field is accepted but treated as Cluster")
}

// EnsureUDPServiceWarn idempotently provisions a Warn-action
// ValidatingAdmissionPolicy on Services with a UDP port. k3sm has no UDP datapath
// yet (the proxy opens no UDP listener), so a UDP Service silently blackholes; the
// policy says so at the API WITHOUT rejecting the Service (UDP support is a
// deferred datapath addition, not an invalid request). Safe to call on every
// server start (AlreadyExists is success).
func EnsureUDPServiceWarn(ctx context.Context, cs kubernetes.Interface) error {
	return ensureServiceWarnPolicy(ctx, cs, udpServicePolicyName, udpServiceBindingName, udpServiceExpr,
		"k3sm: UDP Service ports have no datapath yet — the proxy opens no UDP listener, so a UDP Service silently blackholes")
}

// ensureServiceWarnPolicy idempotently provisions a Warn-action
// ValidatingAdmissionPolicy on Services (CREATE + UPDATE, so a `kubectl edit` that
// introduces the divergence also warns) whose CEL expr, when it evaluates false,
// surfaces message to the client as an HTTP-299 warning WITHOUT rejecting the
// request.
//
// FailurePolicy is Ignore — NOT Fail — precisely because the action is advisory: a
// Fail policy rejects the request when its CEL hits a runtime/typecheck error,
// REGARDLESS of the binding action (admissionregistration/v1 types.go: "If
// failurePolicy=Fail, reject the request"), which would turn an informational
// warning into a hard failure. Ignore guarantees the advisory can only ever warn.
func ensureServiceWarnPolicy(ctx context.Context, cs kubernetes.Interface, policyName, bindingName, expr, message string) error {
	api := cs.AdmissionregistrationV1()

	ignore := admissionregistrationv1.Ignore
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   policyName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &ignore,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"services"},
						},
					},
				}},
			},
			Validations: []admissionregistrationv1.Validation{{
				Expression: expr,
				Message:    message,
			}},
		},
	}
	if _, err := api.ValidatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create service warn policy %s: %w", policyName, err)
	}

	warn := admissionregistrationv1.Warn
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   bindingName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        policyName,
			ValidationActions: []admissionregistrationv1.ValidationAction{warn},
		},
	}
	if _, err := api.ValidatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create service warn binding %s: %w", bindingName, err)
	}
	return nil
}

// reasonInvalid returns the StatusReason the policy attaches to a denial
// (Invalid → HTTP 422), so kubectl surfaces a clear rejection.
func reasonInvalid() *metav1.StatusReason {
	r := metav1.StatusReasonInvalid
	return &r
}
