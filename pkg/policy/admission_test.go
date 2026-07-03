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
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
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

// assertWarnPolicy is the shared check for an advisory Warn
// ValidatingAdmissionPolicy: the policy matches resource on EXACTLY ops, fails OPEN
// (failurePolicy Ignore, so a CEL error can never reject), the binding action is
// Warn and never Deny (advisory only), the CEL contains every wantInExpr fragment,
// and provisioning is idempotent. Parameterizing resource+ops keeps the Service
// advisories (services, CREATE+UPDATE) and the pod-toleration advisory (pods, CREATE
// only) on the SAME structural contract — the Ignore/Warn invariant is asserted once.
func assertWarnPolicy(t *testing.T, policyName, bindingName string, wantInExpr []string, resource string, ops []admissionregistrationv1.OperationType, ensure func(kubernetes.Interface) error) {
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
	if !containsStr(rule.Resources, resource) {
		t.Errorf("policy must match %q, got %v", resource, rule.Resources)
	}
	// Operations must match EXACTLY — e.g. the pod-toleration advisory is CREATE-only
	// (an UPDATE warn would re-fire on every unrelated pod status patch).
	if !sameOps(rule.Operations, ops) {
		t.Errorf("policy operations = %v, want exactly %v", rule.Operations, ops)
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
			t.Error("advisory binding must NOT Deny (the field/Service/Pod stays valid)")
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

// assertServiceWarnPolicy is the shared check for the M3.1 advisory Service
// policies: Services matched on CREATE+UPDATE (so a `kubectl edit` that introduces
// the divergence also warns), routed through assertWarnPolicy.
func assertServiceWarnPolicy(t *testing.T, policyName, bindingName string, wantInExpr []string, ensure func(kubernetes.Interface) error) {
	t.Helper()
	assertWarnPolicy(t, policyName, bindingName, wantInExpr, "services",
		[]admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}, ensure)
}

// sameOps reports whether got and want hold exactly the same operation types
// (order-independent, no extras) — so a CREATE-only policy that also matched UPDATE
// would fail the check.
func sameOps(got, want []admissionregistrationv1.OperationType) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !containsOp(got, w) {
			return false
		}
	}
	return true
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

// TestProviderTolerationWarn verifies the advisory that surfaces a pod missing a
// toleration for the provider taint (k3sm.io/provider:NoSchedule, on every node) —
// the scheduler would leave such a pod Unschedulable. It Warns (never Denies), fails
// open, and matches pods on CREATE ONLY (NOT Update). It also pins the CEL to the
// full-match exists() form — the conformance CRITICAL made mechanical: the naive
// !has(object.spec.tolerations)-only / size(...)==0 shortcut would NEVER warn,
// because the default-on DefaultTolerationSeconds plugin auto-injects NoExecute
// tolerations into nearly every Pod (a pod is then non-empty yet still does not
// tolerate THIS NoSchedule taint), and a different-key toleration leaves the pod
// Unschedulable all the same.
func TestProviderTolerationWarn(t *testing.T) {
	// Structure + the three positive semantics pins (exists() full-match form, the
	// ProviderTaintKey value, and the NoSchedule effect), plus pods/CREATE-only.
	assertWarnPolicy(t, providerTolerationPolicyName, providerTolerationBindingName,
		[]string{"exists(", ProviderTaintKey, "NoSchedule"},
		"pods", []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		func(cs kubernetes.Interface) error {
			return EnsureProviderTolerationWarn(context.Background(), cs)
		})

	// ProviderTaintKey is the single source the taint (placement) and the VAP
	// (admission) both read — assert its value is what the placement guard stamps.
	if ProviderTaintKey != "k3sm.io/provider" {
		t.Errorf("ProviderTaintKey = %q, want k3sm.io/provider", ProviderTaintKey)
	}

	// Negative pins: the CEL must NOT degrade to the naive shortcut. A
	// !has(object.spec.tolerations)-only predicate or a size(...)==0 emptiness test
	// would be defeated by the auto-injected NoExecute tolerations and would miss a
	// different-key toleration. (The expr legitimately contains the POSITIVE
	// has(object.spec.tolerations) guard as the exists() precondition; the banned
	// substring is the NEGATED form used as the whole predicate.)
	if strings.Contains(providerTolerationExpr, "!has(object.spec.tolerations)") {
		t.Errorf("CEL must not use the naive !has(object.spec.tolerations) shortcut: %q", providerTolerationExpr)
	}
	if strings.Contains(providerTolerationExpr, "size(") {
		t.Errorf("CEL must not use the naive size() emptiness shortcut: %q", providerTolerationExpr)
	}
}

// TestDaemonSetTolerationInjectedNotNodeSelector is the B76 gate: the MUTATING policy
// EnsureDaemonSetTolerationMutation provisions injects the provider TOLERATION into
// DaemonSet-owned pods and NEVER the os=darwin nodeSelector (Res.7 — a DaemonSet's own
// placement intent must not be overridden). It asserts the concrete
// MutatingAdmissionPolicy object: (a) the JSONPatch mutation injects the provider
// toleration keyed to ProviderTaintKey (Exists/NoSchedule on the tolerations list); (b)
// the NEGATIVE pin — no nodeSelector / no darwin anywhere in the policy; (c) DS-only —
// the matchCondition is group-qualified so a ReplicaSet/Job/StatefulSet owner (or a CRD
// DaemonSet in another group) does not match.
func TestDaemonSetTolerationInjectedNotNodeSelector(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()

	if err := EnsureDaemonSetTolerationMutation(ctx, cs); err != nil {
		t.Fatalf("EnsureDaemonSetTolerationMutation: %v", err)
	}

	pol, err := cs.AdmissionregistrationV1beta1().MutatingAdmissionPolicies().Get(ctx, dsTolerationPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get mutating policy: %v", err)
	}

	// It must match Pods on CREATE (a mutation of an existing pod's placement makes no
	// sense — the DS pod is unschedulable from birth).
	if len(pol.Spec.MatchConstraints.ResourceRules) == 0 {
		t.Fatal("policy must match a resource")
	}
	rule := pol.Spec.MatchConstraints.ResourceRules[0]
	if !containsStr(rule.Resources, "pods") {
		t.Errorf("policy must match pods, got %v", rule.Resources)
	}
	if !sameOps(rule.Operations, []admissionregistrationv1beta1.OperationType{admissionregistrationv1beta1.Create}) {
		t.Errorf("policy operations = %v, want exactly [CREATE]", rule.Operations)
	}
	if pol.Spec.ReinvocationPolicy != admissionregistrationv1beta1.IfNeededReinvocationPolicy {
		t.Errorf("reinvocationPolicy = %q, want IfNeeded", pol.Spec.ReinvocationPolicy)
	}
	// A convenience injector must fail OPEN: with an all-Pods/CREATE MatchConstraints,
	// FailurePolicy Fail would turn any CEL error into a cluster-wide Pod-CREATE denial.
	// Ignore degrades to Unschedulable (no guard bypass — the Deny VAP + taint hold).
	if pol.Spec.FailurePolicy == nil || *pol.Spec.FailurePolicy != admissionregistrationv1beta1.Ignore {
		t.Errorf("failurePolicy = %v, want Ignore (fail open — this is a convenience injector, not a guard)", pol.Spec.FailurePolicy)
	}

	// (a) The mutation injects the provider TOLERATION — keyed to the const, not a bare
	// Exists — via a JSONPatch (NOT an ApplyConfiguration, which would clobber the atomic
	// list). Assert the patch CEL carries ProviderTaintKey + Exists + NoSchedule +
	// tolerations.
	if len(pol.Spec.Mutations) != 1 {
		t.Fatalf("want exactly one mutation, got %d", len(pol.Spec.Mutations))
	}
	mut := pol.Spec.Mutations[0]
	if mut.PatchType != admissionregistrationv1beta1.PatchTypeJSONPatch {
		t.Errorf("patchType = %q, want JSONPatch (ApplyConfiguration would replace the atomic tolerations list)", mut.PatchType)
	}
	if mut.JSONPatch == nil {
		t.Fatal("mutation must carry a JSONPatch (not an ApplyConfiguration)")
	}
	patch := mut.JSONPatch.Expression
	for _, want := range []string{ProviderTaintKey, "Exists", "NoSchedule", "tolerations"} {
		if !strings.Contains(patch, want) {
			t.Errorf("JSONPatch mutation missing %q: %q", want, patch)
		}
	}

	// (b) NEGATIVE PIN (Res.7): the mutation injects ONLY the toleration — the policy
	// references NEITHER a nodeSelector NOR darwin anywhere (patch, matchConditions, or
	// anything else). Injecting the os=darwin selector would override the DS's own
	// placement intent.
	blob := patch
	for _, mc := range pol.Spec.MatchConditions {
		blob += " " + mc.Expression
	}
	for _, banned := range []string{"nodeSelector", "darwin"} {
		if strings.Contains(blob, banned) {
			t.Errorf("Res.7 violated: policy must NOT reference %q (toleration only), got %q", banned, blob)
		}
	}

	// (c) DS-ONLY, group-qualified: the matchCondition requires kind == 'DaemonSet' AND
	// controller == true AND apiVersion.startsWith('apps/') — so a ReplicaSet/Job/
	// StatefulSet owner, or a CRD kind: DaemonSet in some other group, does NOT match.
	var conds string
	for _, mc := range pol.Spec.MatchConditions {
		conds += " " + mc.Expression
	}
	for _, want := range []string{"kind == 'DaemonSet'", "controller == true", "apiVersion.startsWith('apps/')"} {
		if !strings.Contains(conds, want) {
			t.Errorf("matchConditions missing DS-only guard %q: %q", want, conds)
		}
	}

	// The binding points at the policy (mutations are not validated, so no ValidationActions).
	bind, err := cs.AdmissionregistrationV1beta1().MutatingAdmissionPolicyBindings().Get(ctx, dsTolerationBindingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get mutating binding: %v", err)
	}
	if bind.Spec.PolicyName != dsTolerationPolicyName {
		t.Errorf("binding points at %q, want %q", bind.Spec.PolicyName, dsTolerationPolicyName)
	}

	// Idempotent on server restart.
	if err := EnsureDaemonSetTolerationMutation(ctx, cs); err != nil {
		t.Errorf("second provision must be idempotent: %v", err)
	}
}
