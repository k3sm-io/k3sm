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

package policy

import (
	"context"
	"fmt"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/ports"
)

// ProviderTaintKey is the key of the NoSchedule taint k3sm places on every node
// (the load-bearing placement guard — see cmd/k3sm configureNode) AND the key the
// provider-toleration Warn VAP keys its CEL on. It is exported and single-sourced
// here so the taint (placement) and the advisory (admission) cannot desync: a rename
// is one edit, not two literals in two packages drifting apart.
const ProviderTaintKey = "k3sm.io/provider"

// darwinPolicyName / darwinBindingName are the cluster-scoped names of the
// os=darwin admission policy and its binding.
const (
	darwinPolicyName  = "k3sm-require-os-darwin"
	darwinBindingName = "k3sm-require-os-darwin-binding"
)

// providerTolerationPolicyName / providerTolerationBindingName name the Warn policy
// that surfaces a pod with no toleration for the provider taint (the scheduler would
// leave it Unschedulable).
const (
	providerTolerationPolicyName  = "k3sm-warn-pod-missing-provider-toleration"
	providerTolerationBindingName = "k3sm-warn-pod-missing-provider-toleration-binding"
)

// foreignUserPolicyName / foreignUserBindingName name the policy that rejects a
// pod requesting a foreign runAsUser/runAsGroup/fsGroup/supplementalGroups.
const (
	foreignUserPolicyName  = "k3sm-reject-foreign-user"
	foreignUserBindingName = "k3sm-reject-foreign-user-binding"
)

// dsTolerationPolicyName / dsTolerationBindingName name the MUTATING policy (B76)
// that injects the provider toleration into DaemonSet-owned pods so they schedule.
const (
	dsTolerationPolicyName  = "k3sm-inject-daemonset-provider-toleration"
	dsTolerationBindingName = "k3sm-inject-daemonset-provider-toleration-binding"
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

// reservedLBPortPolicyName / reservedLBPortBindingName name the DENY policy (B116)
// that rejects a LoadBalancer Service declaring a port k3sm's own wildcard
// listeners occupy.
const (
	reservedLBPortPolicyName  = "k3sm-reject-loadbalancer-reserved-port"
	reservedLBPortBindingName = "k3sm-reject-loadbalancer-reserved-port-binding"
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

// reservedPortClause is the CEL sub-expression testing whether the port of the
// Service port bound to variable p falls in the reserved set: the NodePort range,
// or the kubelet API port. The bounds are INTERPOLATED from their arguments —
// pkg/ports at the one call site — so no reserved-port literal is ever written
// into CEL by hand.
func reservedPortClause(p string, nodePortMin, nodePortMax, kubeletPort int) string {
	return fmt.Sprintf("((%[1]s.port >= %[2]d && %[1]s.port <= %[3]d) || %[1]s.port == %[4]d)",
		p, nodePortMin, nodePortMax, kubeletPort)
}

// reservedLBPortExpr is the CEL the Deny policy enforces on Service CREATE and
// UPDATE. It ADMITS (evaluates true) unless a type: LoadBalancer Service declares
// a spec.ports[].port that k3sm's own wildcard listeners own.
//
// Why the LoadBalancer scope lives INSIDE the validation expression rather than in
// a matchCondition: this expression is the whole rule, so it can be read — and
// evaluated in a test — on its own. Split across a matchCondition, evaluating the
// expression alone would report "rejects a plain NodePort Service", which is the
// exact false verdict this policy must not deliver.
//
// It keys on spec.ports[].port ONLY, never on nodePort: the apiserver ALLOCATES a
// plain NodePort Service's nodePort out of the very range this guards, so keying on
// nodePort — or dropping the type scope — would reject every NodePort Service in the
// cluster. The has() guards tolerate a Service that omits type or ports.
func reservedLBPortExpr(nodePortMin, nodePortMax, kubeletPort int) string {
	return "!has(object.spec.type) || object.spec.type != 'LoadBalancer' || " +
		"!has(object.spec.ports) || " +
		"object.spec.ports.all(p, !" + reservedPortClause("p", nodePortMin, nodePortMax, kubeletPort) + ")"
}

// reservedLBPortMessageExpr renders the rejection message, NAMING the first
// colliding port — the whole reason admission was chosen over refuse-and-park is
// that the operator learns at `kubectl apply` rather than from a silent <pending>.
// It is evaluated only when the validation fails, so the filtered list is non-empty.
//
// The closing sentence keeps operator trust calibrated: this guard covers k3sm's
// RESERVED ports only. Two Services declaring the same ORDINARY LoadBalancer port
// are still first-come — the second one's listener simply fails to bind and its
// status stays empty.
func reservedLBPortMessageExpr(nodePortMin, nodePortMax, kubeletPort int) string {
	return `'k3sm: LoadBalancer port ' + ` +
		`string(object.spec.ports.filter(p, ` + reservedPortClause("p", nodePortMin, nodePortMax, kubeletPort) + `)[0].port) + ` +
		fmt.Sprintf(`' is RESERVED by a k3sm wildcard listener (the NodePort range %d-%d and the kubelet API port %d). `, nodePortMin, nodePortMax, kubeletPort) +
		`k3sm binds LoadBalancer ports on 0.0.0.0 and Go sets no SO_REUSEPORT, so this Service would race a k3sm listener for the same socket ` +
		`— losing the kubelet API port breaks logs/exec/top on this node, and a NodePort-range collision takes down an unrelated ClusterIP. ` +
		`Choose a different spec.ports[].port. Only these RESERVED ports are rejected: two Services sharing an ordinary LoadBalancer port are still first-come.'`
}

// EnsureRejectReservedLoadBalancerPort idempotently provisions the DENY
// ValidatingAdmissionPolicy (+ binding) that REJECTS a type: LoadBalancer Service
// declaring a port k3sm's own wildcard listeners own (pkg/ports.Reserved). It is
// the legible half of a two-point guard: svclb REFUSES to bind such a port at the
// datapath (pkg/svclb), and this policy makes the refusal visible at
// `kubectl apply` instead of as an unexplained <pending>.
//
// CREATE **and** UPDATE: a port edit, or a `type` patch onto an already-admitted
// Service, is an ordinary UPDATE, and svclb reconciles live state — a CREATE-only
// policy would let the collision in through the back door.
//
// MatchConstraints pins `services` ONLY — deliberately NOT `services/status`, or
// this controller's own (and the ingress host's) UpdateStatus writes would be
// evaluated by it on every reconcile.
//
// FailurePolicy is Ignore: a CEL/machinery evaluation error must not turn into a
// cluster-wide denial of Service writes. The trade is explicit — the guard can
// fail open, which is why the datapath refusal in svclb exists as the second
// enforcement point rather than as belt-and-braces.
//
// PROVISIONING CONTRACT (bounded, on purpose): like every sibling Ensure*, this is
// CREATE-IF-ABSENT and NEVER UPDATES. So the CEL is frozen at the moment the policy
// object is first created: the "reserved set cannot desync" property holds for a
// FRESH cluster, but a cluster provisioned before a NodePort-range change keeps the
// old expression until the object is deleted. An Update-on-drift provisioner is a
// reserved follow-up, not an oversight.
func EnsureRejectReservedLoadBalancerPort(ctx context.Context, cs kubernetes.Interface) error {
	api := cs.AdmissionregistrationV1()

	ignore := admissionregistrationv1.Ignore
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   reservedLBPortPolicyName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &ignore,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"services"},
						},
					},
				}},
			},
			Validations: []admissionregistrationv1.Validation{{
				Expression:        reservedLBPortExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort),
				MessageExpression: reservedLBPortMessageExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort),
				Message:           "k3sm: this LoadBalancer Service declares a port reserved by a k3sm wildcard listener (the NodePort range or the kubelet API port); choose a different spec.ports[].port",
				Reason:            reasonInvalid(),
			}},
		},
	}
	if _, err := api.ValidatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create reserved-loadbalancer-port admission policy: %w", err)
	}

	deny := admissionregistrationv1.Deny
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   reservedLBPortBindingName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        reservedLBPortPolicyName,
			ValidationActions: []admissionregistrationv1.ValidationAction{deny},
		},
	}
	if _, err := api.ValidatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create reserved-loadbalancer-port admission binding: %w", err)
	}
	return nil
}

// darwinSelectorExpr is the CEL the policy enforces on Pod CREATE: the pod must
// declare nodeSelector kubernetes.io/os=darwin. It tolerates a missing
// nodeSelector map (has(...)). The CEL field-escaping rules apply only to dot
// property ACCESS (object.foo); a string LITERAL used as a map key / `in`
// operand is the real key, so the literal "kubernetes.io/os" is used directly.
// A pod without the selector — i.e. any Linux pod — fails the rule and is denied.
const darwinSelectorExpr = `has(object.spec.nodeSelector) && ` +
	`'kubernetes.io/os' in object.spec.nodeSelector && ` +
	`object.spec.nodeSelector['kubernetes.io/os'] == 'darwin'`

// providerTolerationExpr is the CEL the provider-toleration Warn policy enforces on
// Pod CREATE. It evaluates TRUE when the pod TOLERATES the provider taint
// (ProviderTaintKey:NoSchedule, value "") — no warning — and FALSE otherwise, when
// the scheduler would leave the pod Unschedulable and the binding warns.
//
// It is the faithful CEL transcription of Kubernetes' Toleration.ToleratesTaint
// (k8s.io/api/core/v1): a toleration tolerates the taint iff its effect matches (or
// is empty), its key matches (or is empty), and EITHER operator==Exists (any value)
// OR operator is Equal/empty AND its value equals the taint's (empty) value. The
// exists() requires SOME toleration to satisfy all three.
//
// CRITICAL — this is the full-match exists() form, NOT the naive
// `!has(object.spec.tolerations)` / `size(...)==0` emptiness shortcut. The default-on
// DefaultTolerationSeconds admission plugin auto-injects NoExecute tolerations
// (node.kubernetes.io/not-ready, …) into nearly every Pod, so an emptiness test would
// see a non-empty list and NEVER warn; and a pod carrying a DIFFERENT-key toleration
// is still Unschedulable here. ProviderTaintKey is interpolated (a const concat) so
// the taint key lives in exactly one place.
const providerTolerationExpr = `has(object.spec.tolerations) && object.spec.tolerations.exists(t, ` +
	`(!has(t.effect) || t.effect == 'NoSchedule') && ` +
	`(!has(t.key) || t.key == '` + ProviderTaintKey + `') && ` +
	`((has(t.operator) && t.operator == 'Exists') || ` +
	`((!has(t.operator) || t.operator == 'Equal') && (!has(t.value) || t.value == ''))))`

// daemonSetOwnedExpr is the matchCondition CEL that fires the B76 mutating policy
// ONLY for a pod created by the DaemonSet controller. It is GROUP-QUALIFIED
// (o.apiVersion.startsWith('apps/')) so a CRD `kind: DaemonSet` in some other API
// group cannot masquerade as a real apps/v1 DaemonSet and steal the injection; and
// it requires o.controller == true so only the managing (controller) ownerReference —
// not a bare owner cross-reference — matches. A ReplicaSet/Job/StatefulSet-owned pod
// (the KCM's other controllers) does NOT match, so it never receives the toleration.
const daemonSetOwnedExpr = `object.metadata.ownerReferences.exists(o, ` +
	`o.kind == 'DaemonSet' && o.controller == true && o.apiVersion.startsWith('apps/'))`

// daemonSetTolerationPatchExpr is the JSONPatch-mutation CEL that APPENDS exactly one
// toleration for the provider taint to a DS-owned pod. A JSONPatch (append to
// /spec/tolerations/-) is used deliberately INSTEAD of an ApplyConfiguration: the
// tolerations list is an ATOMIC list, so an apply-config would REPLACE the whole list
// and clobber the NoExecute tolerations the default-on DefaultTolerationSeconds plugin
// injects (node.kubernetes.io/not-ready, …). The append is idempotent because the
// not-already-tolerating matchCondition (the negation of providerTolerationExpr) only
// lets the mutation run when the pod does not already tolerate the taint. ONLY the
// toleration is injected — never the kubernetes.io/os=darwin nodeSelector: a DaemonSet
// declares its own placement intent, and overriding it here would defeat the DS's
// nodeSelector/affinity (B76 Res.7). ProviderTaintKey is interpolated so the taint key
// lives in exactly one place (single-sourced with the taint the node stamps).
const daemonSetTolerationPatchExpr = `[JSONPatch{op: "add", path: "/spec/tolerations/-", ` +
	`value: Object.spec.tolerations{key: "` + ProviderTaintKey + `", operator: "Exists", effect: "NoSchedule"}}]`

// EnsureDaemonSetTolerationMutation idempotently provisions the B76
// MutatingAdmissionPolicy (+ binding) that injects the provider toleration into
// DaemonSet-owned pods. A DS pod is created by the DaemonSet controller in the
// kube-controller-manager, so the B17 CREATE-Warn advisory never reaches its author and
// the pod would sit Unschedulable against the k3sm.io/provider:NoSchedule taint; this
// policy MUTATES the pod to tolerate it. UNLIKE the Deny/Warn ValidatingAdmissionPolicies
// it CHANGES the stored object. Both matchConditions must hold (DS-owned AND not already
// tolerating); the mutation appends exactly one toleration and NEVER a nodeSelector
// (Res.7). Safe to call on every server start (AlreadyExists is success).
//
// This provisions objects for a BETA API (admissionregistration.k8s.io/v1beta1,
// MutatingAdmissionPolicy) — the executor must enable the v1beta1 runtime-config AND the
// MutatingAdmissionPolicy feature gate on the apiserver (see executor.apiServerArgs) or
// this policy is a runtime no-op.
func EnsureDaemonSetTolerationMutation(ctx context.Context, cs kubernetes.Interface) error {
	api := cs.AdmissionregistrationV1beta1()

	// Ignore — NOT Fail — because this is a scheduling-CONVENIENCE injector, not a
	// guard: MatchConstraints is all Pods/CREATE, so a Fail policy would turn any
	// CEL/beta-machinery evaluation error into a cluster-wide denial of Pod CREATE.
	// Failing open instead degrades to the pre-B76 status quo (the DS pod is created
	// without the toleration and stays Unschedulable — visible and recoverable, no
	// guard bypass: the os=darwin Deny VAP and the provider taint still hold). Mirrors
	// the advisory Warn VAP's deliberate Ignore.
	ignore := admissionregistrationv1beta1.Ignore
	policy := &admissionregistrationv1beta1.MutatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   dsTolerationPolicyName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1beta1.MutatingAdmissionPolicySpec{
			FailurePolicy: &ignore,
			MatchConstraints: &admissionregistrationv1beta1.MatchResources{
				ResourceRules: []admissionregistrationv1beta1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1beta1.RuleWithOperations{
						Operations: []admissionregistrationv1beta1.OperationType{admissionregistrationv1beta1.Create},
						Rule: admissionregistrationv1beta1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				}},
			},
			// BOTH conditions must hold: the pod is DS-owned (group-qualified) AND it does
			// not already tolerate the taint (the negation of the single-sourced
			// providerTolerationExpr — never a second, drifting ToleratesTaint CEL).
			MatchConditions: []admissionregistrationv1beta1.MatchCondition{
				{Name: "is-daemonset-pod", Expression: daemonSetOwnedExpr},
				{Name: "not-already-tolerating", Expression: "!(" + providerTolerationExpr + ")"},
			},
			Mutations: []admissionregistrationv1beta1.Mutation{{
				PatchType: admissionregistrationv1beta1.PatchTypeJSONPatch,
				JSONPatch: &admissionregistrationv1beta1.JSONPatch{Expression: daemonSetTolerationPatchExpr},
			}},
			ReinvocationPolicy: admissionregistrationv1beta1.IfNeededReinvocationPolicy,
		},
	}
	if _, err := api.MutatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create daemonset-toleration mutating policy: %w", err)
	}

	binding := &admissionregistrationv1beta1.MutatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   dsTolerationBindingName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: admissionregistrationv1beta1.MutatingAdmissionPolicyBindingSpec{
			PolicyName: dsTolerationPolicyName,
		},
	}
	if _, err := api.MutatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create daemonset-toleration mutating binding: %w", err)
	}
	return nil
}

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
	return ensureWarnPolicy(ctx, cs, etpLocalPolicyName, etpLocalBindingName, etpLocalExpr,
		"k3sm: Service externalTrafficPolicy: Local is not honored — the userspace proxy does not preserve client source IP (only Cluster); the field is accepted but treated as Cluster",
		"services", admissionregistrationv1.Create, admissionregistrationv1.Update)
}

// EnsureUDPServiceWarn idempotently provisions a Warn-action
// ValidatingAdmissionPolicy on Services with a UDP port. k3sm has no UDP datapath
// yet (the proxy opens no UDP listener), so a UDP Service silently blackholes; the
// policy says so at the API WITHOUT rejecting the Service (UDP support is a
// deferred datapath addition, not an invalid request). Safe to call on every
// server start (AlreadyExists is success).
func EnsureUDPServiceWarn(ctx context.Context, cs kubernetes.Interface) error {
	return ensureWarnPolicy(ctx, cs, udpServicePolicyName, udpServiceBindingName, udpServiceExpr,
		"k3sm: UDP Service ports have no datapath yet — the proxy opens no UDP listener, so a UDP Service silently blackholes",
		"services", admissionregistrationv1.Create, admissionregistrationv1.Update)
}

// EnsureProviderTolerationWarn idempotently provisions a Warn-action
// ValidatingAdmissionPolicy on Pod CREATE that surfaces a pod with NO toleration for
// the provider taint (ProviderTaintKey:NoSchedule, on every k3sm node). Such a pod is
// perfectly valid Kubernetes — it is just left Unschedulable by the scheduler — so
// this is advisory (Warn), NOT Deny: the policy says so at the API rather than leaving
// the operator to discover a silently-Pending pod. The CEL is the faithful
// ToleratesTaint encoding (see providerTolerationExpr), not the emptiness shortcut
// that DefaultTolerationSeconds would defeat. Matched on CREATE ONLY (an UPDATE warn
// would re-fire on every unrelated pod status patch).
//
// Coverage limit (honest): the warning reaches only DIRECTLY-created pods — for a
// Deployment/Job/StatefulSet/etc. the Pod CREATE is issued by the
// kube-controller-manager, so the HTTP-warning header lands on the KCM's API client,
// not the user's kubectl. A bare `kubectl run`/`kubectl apply` of a Pod does surface
// it. Safe to call on every server start (AlreadyExists is success).
func EnsureProviderTolerationWarn(ctx context.Context, cs kubernetes.Interface) error {
	msg := fmt.Sprintf("k3sm: pod has no toleration for the provider taint %[1]s:NoSchedule — "+
		"the scheduler will leave it Unschedulable; add a toleration "+
		"(operator: Exists, or key: %[1]s effect: NoSchedule)", ProviderTaintKey)
	return ensureWarnPolicy(ctx, cs, providerTolerationPolicyName, providerTolerationBindingName,
		providerTolerationExpr, msg, "pods", admissionregistrationv1.Create)
}

// ensureWarnPolicy idempotently provisions a Warn-action ValidatingAdmissionPolicy on
// resource for the given ops whose CEL expr, when it evaluates false, surfaces message
// to the client as an HTTP-299 warning WITHOUT rejecting the request. It is the SINGLE
// source of the advisory invariant for every k3sm Warn VAP (Service divergences and
// the pod-toleration advisory), parameterized only by resource + ops.
//
// FailurePolicy is Ignore — NOT Fail — precisely because the action is advisory: a
// Fail policy rejects the request when its CEL hits a runtime/typecheck error,
// REGARDLESS of the binding action (admissionregistration/v1 types.go: "If
// failurePolicy=Fail, reject the request"), which would turn an informational
// warning into a hard failure. Ignore guarantees the advisory can only ever warn —
// keeping that invariant here, in one place, stops it drifting to Fail per-callsite.
func ensureWarnPolicy(ctx context.Context, cs kubernetes.Interface, policyName, bindingName, expr, message, resource string, ops ...admissionregistrationv1.OperationType) error {
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
						Operations: ops,
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{resource},
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
		return fmt.Errorf("create warn policy %s: %w", policyName, err)
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
		return fmt.Errorf("create warn binding %s: %w", bindingName, err)
	}
	return nil
}

// reasonInvalid returns the StatusReason the policy attaches to a denial
// (Invalid → HTTP 422), so kubectl surfaces a clear rejection.
func reasonInvalid() *metav1.StatusReason {
	r := metav1.StatusReasonInvalid
	return &r
}
