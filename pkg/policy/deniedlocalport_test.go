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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/ports"
)

// kinePort / freePort are the two numbers this file argues about: the default
// loopback datastore listener port a server denies, and its neighbour, which
// nothing denies. They are written here rather than imported from pkg/executor so
// the test states the case it is making (12379 is denied, 12380 is not) instead of
// asserting a constant against itself.
const (
	kinePort = 12379
	freePort = 12380
)

// serviceTargeting builds a Service that PUBLISHES port and forwards to
// targetPort — the shape that separates "the port clients dial" from "the port the
// pod listens on". Only the first is a connect() destination for another pod, so
// only the first may be matched.
func serviceTargeting(svcType string, port, targetPort int) map[string]any {
	return map[string]any{
		"spec": map[string]any{
			"type": svcType,
			"ports": []any{map[string]any{
				"port":       int64(port),
				"targetPort": int64(targetPort),
				"protocol":   "TCP",
			}},
		},
	}
}

// TestReservedPortClauseRejectsDeniedLocalPorts is the B301 gate. It EVALUATES the
// Deny policy's CEL (it does not grep the string) and pins the four decisions the
// policy exists to make:
//
//   - a Service published on a denied local port is REJECTED whatever its type —
//     the deny is enforced by each pod's sandbox on the PORT NUMBER (Seatbelt
//     cannot filter connect() by address), and a ClusterIP VIP is an lo0 alias on
//     the same host, so a ClusterIP is exactly as unreachable as a LoadBalancer.
//     A type gate here would leave the most common Service shape silently broken,
//     which is the whole defect;
//   - the neighbouring port is ADMITTED — the rejection is the denied set, not a
//     range around it;
//   - a Service whose TARGETPORT is the denied number is ADMITTED — targetPort is
//     the port a pod listens on inside its own sandbox, which an outbound-connect()
//     deny does not touch. Rejecting it would reject Services that work;
//   - the two port policies stay INDEPENDENT: a NodePort-range clash is still the
//     sibling's rejection, with the sibling's reason, and this policy admits it.
//     An operator handed the wrong message would go hunting a wildcard listener
//     that is not the problem.
func TestReservedPortClauseRejectsDeniedLocalPorts(t *testing.T) {
	denied := []int{kinePort}
	prg := celProgram(t, deniedLocalPortExpr(denied))

	for _, tt := range []struct {
		name      string
		object    map[string]any
		wantAdmit bool
	}{
		{"a ClusterIP Service on the denied kine port is REJECTED", service("ClusterIP", kinePort), false},
		{"a ClusterIP Service on the neighbouring port is admitted", service("ClusterIP", freePort), true},
		{"a LoadBalancer Service on the denied port is REJECTED by THIS policy", service("LoadBalancer", kinePort), false},
		{"a NodePort Service on the denied port is REJECTED", service("NodePort", kinePort), false},
		{"a Service with one good and one denied port is REJECTED", service("ClusterIP", 8080, kinePort), false},
		{"targetPort on the denied port is admitted (port 8080 is what clients dial)", serviceTargeting("ClusterIP", 8080, kinePort), true},
		{"a LoadBalancer Service in the NodePort range is admitted HERE (the sibling policy owns it)", service("LoadBalancer", 30500), true},
		{"a Service with no ports is admitted", map[string]any{"spec": map[string]any{"type": "ClusterIP"}}, true},
	} {
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

	// The rejection MESSAGE is the deliverable: the whole change is turning a
	// silent unreachability into something the operator reads at `kubectl apply`.
	t.Run("the rejection message names the port, the cause and both remedies", func(t *testing.T) {
		msgPrg := celProgram(t, deniedLocalPortMessageExpr(denied))
		out, _, err := msgPrg.Eval(map[string]any{"object": service("ClusterIP", 8080, kinePort)})
		if err != nil {
			t.Fatalf("eval message: %v", err)
		}
		msg, ok := out.Value().(string)
		if !ok {
			t.Fatalf("messageExpression returned %T, want string", out.Value())
		}
		if !strings.Contains(msg, "12379") {
			t.Errorf("message must name the colliding port 12379, got: %s", msg)
		}
		if strings.Contains(msg, "8080") {
			t.Errorf("message must name the COLLIDING port, not the innocent one, got: %s", msg)
		}
		for _, want := range []string{
			"sandbox",     // the cause: the deny lives in every pod's sandbox
			"PORT NUMBER", // and it is by number, not by address
			"--kine-port", // remedy 2 (remedy 1 is spec.ports[].port, below)
			"per-server",  // the HA caveat: one cluster object, per-server ports
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("message must mention %q, got: %s", want, msg)
			}
		}
		if !strings.Contains(msg, "spec.ports[].port") {
			t.Errorf("message must name the field to change, got: %s", msg)
		}
	})

	// INDEPENDENCE, asserted from the other side: the same NodePort-range clash
	// this policy admits is rejected by the sibling, with the sibling's reason.
	t.Run("a NodePort-range clash still reports the reserved-listener reason", func(t *testing.T) {
		lb := celProgram(t, reservedLBPortExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort))
		out, _, err := lb.Eval(map[string]any{"object": service("LoadBalancer", 30500)})
		if err != nil {
			t.Fatalf("eval sibling: %v", err)
		}
		if out.Value().(bool) {
			t.Fatal("the sibling policy must still reject a LoadBalancer Service in the NodePort range")
		}
		msgPrg := celProgram(t, reservedLBPortMessageExpr(ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort))
		mout, _, err := msgPrg.Eval(map[string]any{"object": service("LoadBalancer", 30500)})
		if err != nil {
			t.Fatalf("eval sibling message: %v", err)
		}
		msg := mout.Value().(string)
		if !strings.Contains(msg, "RESERVED by a k3sm wildcard listener") {
			t.Errorf("the reserved-port rejection must keep its own reason, got: %s", msg)
		}
		if strings.Contains(msg, "sandbox") {
			t.Errorf("the two policies must stay independent: the reserved-port message must not borrow the sandbox reason, got: %s", msg)
		}
	})

	// The empty set: a server that denies no local port rejects nothing. The
	// expression must still COMPILE and admit — an empty disjunction would not.
	t.Run("an empty denied set rejects nothing", func(t *testing.T) {
		empty := celProgram(t, deniedLocalPortExpr(nil))
		for _, obj := range []map[string]any{
			service("ClusterIP", kinePort),
			service("LoadBalancer", kinePort),
			service("NodePort", 30500),
		} {
			out, _, err := empty.Eval(map[string]any{"object": obj})
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if !out.Value().(bool) {
				t.Errorf("an empty denied set must admit everything, rejected: %v", obj)
			}
		}
	})

	// DERIVATION, not just semantics: the CEL must carry the port it was handed,
	// and no default. A hard-written 12379 would pass every case above while
	// ignoring a --kine-port the operator actually moved.
	t.Run("the CEL derives its port from the argument", func(t *testing.T) {
		expr := deniedLocalPortExpr([]int{44444})
		if !strings.Contains(expr, "44444") {
			t.Errorf("expression must carry the port it was handed, got:\n%s", expr)
		}
		if strings.Contains(expr, "12379") {
			t.Errorf("expression must NOT carry a default port — it is hard-written, not derived; got:\n%s", expr)
		}
		sentinel := celProgram(t, expr)
		out, _, err := sentinel.Eval(map[string]any{"object": service("ClusterIP", 44444)})
		if err != nil {
			t.Fatalf("eval sentinel: %v", err)
		}
		if out.Value().(bool) {
			t.Error("the sentinel expression must MEAN its port, not merely contain it")
		}
	})
}

// TestEnsureRejectServiceDeniedLocalPortShape pins the provisioned objects: Deny
// action, failurePolicy Ignore, Create AND Update, MatchConstraints on `services`
// only (never services/status — svclb and the ingress host UpdateStatus on every
// reconcile), and the derived expression rather than a literal.
func TestEnsureRejectServiceDeniedLocalPortShape(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	denied := []int{kinePort}
	// Idempotent: a second call must tolerate AlreadyExists (every server start).
	for range 2 {
		if err := EnsureRejectServiceDeniedLocalPort(ctx, cs, denied); err != nil {
			t.Fatalf("EnsureRejectServiceDeniedLocalPort: %v", err)
		}
	}

	p, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, deniedLocalPortPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if p.Spec.FailurePolicy == nil || *p.Spec.FailurePolicy != admissionregistrationv1.Ignore {
		t.Errorf("failurePolicy = %v, want Ignore (a CEL/machinery error must not deny every Service write)", p.Spec.FailurePolicy)
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
		t.Errorf("operations = %v, want CREATE and UPDATE (a port edit on an admitted Service is an ordinary UPDATE)", rules[0].Operations)
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
	if v.Expression != deniedLocalPortExpr(denied) {
		t.Error("the provisioned expression must be the derived one, not a literal")
	}
	if v.MessageExpression == "" {
		t.Error("a messageExpression naming the colliding port is required")
	}
	if v.Message == "" {
		t.Error("a static fallback Message is required (the messageExpression can fail to evaluate)")
	}

	b, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, deniedLocalPortBindingName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if len(b.Spec.ValidationActions) != 1 || b.Spec.ValidationActions[0] != admissionregistrationv1.Deny {
		t.Errorf("validationActions = %v, want [Deny] (an admitted Service here is an unreachable one)", b.Spec.ValidationActions)
	}
	if b.Spec.PolicyName != deniedLocalPortPolicyName {
		t.Errorf("binding policyName = %q, want %q", b.Spec.PolicyName, deniedLocalPortPolicyName)
	}
}

// TestEnsureRejectServiceDeniedLocalPortRemovesAStaleGuard pins the empty-set
// contract: no denied port, no objects — and a policy provisioned by an earlier
// server is REMOVED rather than left rejecting Services on a port number nothing
// denies any more. A stale Deny VAP is worse than none: it rejects working
// Services with a message about a listener that has moved.
func TestEnsureRejectServiceDeniedLocalPortRemovesAStaleGuard(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()

	// A server that denies nothing, on a cluster that never had the objects:
	// a no-op, and NOT an error (a Delete of an absent object is NotFound).
	if err := EnsureRejectServiceDeniedLocalPort(ctx, cs, nil); err != nil {
		t.Fatalf("empty denied set on a fresh cluster: %v", err)
	}
	if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, deniedLocalPortPolicyName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("an empty denied set must provision no policy, got err = %v", err)
	}

	// Now the stale case: the objects exist from an earlier server.
	if err := EnsureRejectServiceDeniedLocalPort(ctx, cs, []int{kinePort}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := EnsureRejectServiceDeniedLocalPort(ctx, cs, nil); err != nil {
		t.Fatalf("empty denied set over an existing guard: %v", err)
	}
	if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, deniedLocalPortPolicyName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("the stale policy must be removed, got err = %v", err)
	}
	if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, deniedLocalPortBindingName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("the stale binding must be removed, got err = %v", err)
	}
}
