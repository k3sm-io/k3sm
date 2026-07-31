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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/ports"
)

// celProgram compiles expr against an `object` variable of dynamic type — the
// shape a ValidatingAdmissionPolicy sees for the admitted resource.
func celProgram(t *testing.T, expr string) cel.Program {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("object", cel.DynType))
	if err != nil {
		t.Fatalf("cel env: %v", err)
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("compile CEL: %v\nexpression:\n%s", iss.Err(), expr)
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program: %v", err)
	}
	return prg
}

// service builds the unstructured Service an admission plugin would evaluate.
func service(svcType string, portNumbers ...int) map[string]any {
	svcPorts := make([]any, 0, len(portNumbers))
	for _, p := range portNumbers {
		svcPorts = append(svcPorts, map[string]any{"port": int64(p), "protocol": "TCP"})
	}
	return map[string]any{
		"spec": map[string]any{"type": svcType, "ports": svcPorts},
	}
}

// TestReservedLoadBalancerPortCELSemantics EVALUATES the Deny policy's CEL (it
// does not merely grep the string): a reserved port on a LoadBalancer Service is
// rejected, the SAME port on a non-LoadBalancer Service is accepted, and an
// ordinary LoadBalancer port is accepted.
//
// The whole rule — including the `type: LoadBalancer` scope — lives in ONE
// expression, so evaluating it alone is faithful. Were the scope split into a
// matchCondition, this harness would have to evaluate matchConditions ∧
// expression together; evaluating the expression alone would then report
// "rejects a plain NodePort Service" and turn the mandated acceptance into a
// false red.
func TestReservedLoadBalancerPortCELSemantics(t *testing.T) {
	prg := celProgram(t, reservedLBPortExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort))

	tests := []struct {
		name      string
		object    map[string]any
		wantAdmit bool
	}{
		{"LB on a NodePort-range port is REJECTED", service("LoadBalancer", 30500), false},
		{"LB on the NodePort range's lower bound is REJECTED", service("LoadBalancer", 30000), false},
		{"LB on the NodePort range's upper bound is REJECTED", service("LoadBalancer", 32767), false},
		{"LB on the kubelet API port is REJECTED", service("LoadBalancer", 10250), false},
		{"LB with one good and one reserved port is REJECTED", service("LoadBalancer", 8080, 10250), false},
		{"an ordinary LB port is admitted", service("LoadBalancer", 8080), true},
		{"LB on 80/443 is admitted (the ingress ports are deliberately NOT reserved)", service("LoadBalancer", 80, 443), true},
		{"LB just outside the range is admitted", service("LoadBalancer", 29999, 32768), true},
		// The load-bearing acceptance: the apiserver ALLOCATES a NodePort
		// Service's nodePort out of the very range this guards, so rejecting a
		// NodePort Service would break every one of them.
		{"a NodePort Service on a reserved port is admitted", service("NodePort", 30500), true},
		{"a ClusterIP Service on the kubelet port is admitted", service("ClusterIP", 10250), true},
		// Tolerated shapes: a Service that omits type or ports.
		{"a Service with no ports is admitted", map[string]any{"spec": map[string]any{"type": "LoadBalancer"}}, true},
		{"a Service with no type is admitted", map[string]any{"spec": map[string]any{"ports": []any{map[string]any{"port": int64(10250)}}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, err := prg.Eval(map[string]any{"object": tt.object})
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			admit, ok := out.Value().(bool)
			if !ok {
				t.Fatalf("CEL returned %T (%v), want bool", out.Value(), out.Value())
			}
			if admit != tt.wantAdmit {
				t.Errorf("admit = %v, want %v", admit, tt.wantAdmit)
			}
		})
	}
}

// TestReservedLoadBalancerPortMessageNamesThePort evaluates the messageExpression
// (only reachable when the validation fails) and proves it NAMES the colliding
// port. Legibility at `kubectl apply` is the entire reason admission was chosen
// over refuse-and-park, so a message that does not name the port fails the point
// of the change.
func TestReservedLoadBalancerPortMessageNamesThePort(t *testing.T) {
	prg := celProgram(t, reservedLBPortMessageExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort))
	out, _, err := prg.Eval(map[string]any{"object": service("LoadBalancer", 8080, 30500)})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	msg, ok := out.Value().(string)
	if !ok {
		t.Fatalf("messageExpression returned %T, want string", out.Value())
	}
	if !strings.Contains(msg, "30500") {
		t.Errorf("message must name the colliding port 30500, got: %s", msg)
	}
	if strings.Contains(msg, "8080") {
		t.Errorf("message must name the COLLIDING port, not the innocent one, got: %s", msg)
	}
	// Trust calibration: the operator must not read this as "k3sm arbitrates all
	// duplicate LB ports".
	if !strings.Contains(msg, "first-come") {
		t.Errorf("message must say that ordinary duplicate LB ports are still first-come, got: %s", msg)
	}
}

// TestReservedLoadBalancerPortCELDerivesItsBounds is the SENTINEL-BOUNDS test.
// Evaluation proves semantics; only varying the source constants proves
// DERIVATION — an expression with 30000-32767 hard-written into it would pass
// every evaluation case above while silently ignoring a future range change.
func TestReservedLoadBalancerPortCELDerivesItsBounds(t *testing.T) {
	const sentinelMin, sentinelMax, sentinelKubelet = 40000, 40001, 44444
	expr := reservedLBPortExpr(sentinelMin, sentinelMax, sentinelKubelet)

	for _, want := range []int{sentinelMin, sentinelMax, sentinelKubelet} {
		if !strings.Contains(expr, strconv.Itoa(want)) {
			t.Errorf("expression must carry the sentinel bound %d, got:\n%s", want, expr)
		}
	}
	for _, forbidden := range []int{ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort} {
		if strings.Contains(expr, strconv.Itoa(forbidden)) {
			t.Errorf("expression must NOT carry the production constant %d — it is hard-written, not derived; got:\n%s", forbidden, expr)
		}
	}

	// And the sentinel expression must actually MEAN the sentinel bounds.
	prg := celProgram(t, expr)
	for _, tc := range []struct {
		port      int
		wantAdmit bool
	}{
		{40000, false}, {40001, false}, {44444, false},
		{39999, true}, {40002, true}, {30500, true}, {10250, true},
	} {
		out, _, err := prg.Eval(map[string]any{"object": service("LoadBalancer", tc.port)})
		if err != nil {
			t.Fatalf("eval port %d: %v", tc.port, err)
		}
		if got := out.Value().(bool); got != tc.wantAdmit {
			t.Errorf("sentinel-bounds CEL: port %d admit = %v, want %v", tc.port, got, tc.wantAdmit)
		}
	}
}

// TestEnsureRejectReservedLoadBalancerPortShape pins the provisioned objects:
// Deny action, failurePolicy Ignore, Create AND Update, and MatchConstraints on
// `services` ONLY.
//
// The services/status exclusion is load-bearing: svclb and the ingress host write
// LB statuses through UpdateStatus on every reconcile, and a policy matching
// services/status would evaluate this rule against each of those writes.
func TestEnsureRejectReservedLoadBalancerPortShape(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	// Idempotent: a second call must tolerate AlreadyExists (every server start).
	for range 2 {
		if err := EnsureRejectReservedLoadBalancerPort(ctx, cs); err != nil {
			t.Fatalf("EnsureRejectReservedLoadBalancerPort: %v", err)
		}
	}

	p, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, reservedLBPortPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if p.Spec.FailurePolicy == nil || *p.Spec.FailurePolicy != admissionregistrationv1.Ignore {
		t.Errorf("failurePolicy = %v, want Ignore (D2: a CEL/machinery error must not deny every Service write)", p.Spec.FailurePolicy)
	}
	rules := p.Spec.MatchConstraints.ResourceRules
	if len(rules) != 1 {
		t.Fatalf("resourceRules = %d, want exactly 1", len(rules))
	}
	gotOps := map[admissionregistrationv1.OperationType]bool{}
	for _, op := range rules[0].Operations {
		gotOps[op] = true
	}
	if !gotOps[admissionregistrationv1.Create] || !gotOps[admissionregistrationv1.Update] {
		t.Errorf("operations = %v, want CREATE and UPDATE (a port edit or a type patch onto an admitted Service is an ordinary UPDATE)", rules[0].Operations)
	}
	for _, r := range rules[0].Resources {
		if r != "services" {
			t.Errorf("resource %q matched: MatchConstraints must pin `services` ONLY — never services/status, or the controllers' own UpdateStatus writes are evaluated by this policy", r)
		}
	}
	if len(p.Spec.Validations) != 1 {
		t.Fatalf("validations = %d, want 1", len(p.Spec.Validations))
	}
	v := p.Spec.Validations[0]
	if v.Expression != reservedLBPortExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort) {
		t.Error("the provisioned expression must be the derived one, not a literal")
	}
	if v.MessageExpression == "" {
		t.Error("a messageExpression naming the colliding port is required")
	}

	b, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, reservedLBPortBindingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if len(b.Spec.ValidationActions) != 1 || b.Spec.ValidationActions[0] != admissionregistrationv1.Deny {
		t.Errorf("validationActions = %v, want [Deny] (the operator decided REJECT, not Warn)", b.Spec.ValidationActions)
	}
	if b.Spec.PolicyName != reservedLBPortPolicyName {
		t.Errorf("binding policyName = %q, want %q", b.Spec.PolicyName, reservedLBPortPolicyName)
	}
}

// TestReservedLoadBalancerPortGolden pins the exact rendered CEL against a golden
// file, so any change to the expression is a visible, reviewed diff rather than an
// invisible semantic drift. Regenerate with -update after a DELIBERATE change.
func TestReservedLoadBalancerPortGolden(t *testing.T) {
	golden := filepath.Join("testdata", "reserved-loadbalancer-port.cel")
	got := reservedLBPortExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort) + "\n" +
		reservedLBPortMessageExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort) + "\n"
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden %s: %v", golden, err)
	}
	if string(want) != got {
		t.Errorf("rendered CEL differs from %s\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
	}
}
