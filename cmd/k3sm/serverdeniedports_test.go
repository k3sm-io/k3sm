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

package main

import (
	"context"
	"go/ast"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/hostnet"
)

// TestServerSingleSourcesTheDeniedLocalPorts pins the ONE property the sandbox
// deny and its admission guard share: they are the same numbers.
//
// The node stamps nodeOptions.deniedLocalPorts into every pod's SBPL; the cluster
// policy rejects a Service published on one of those ports. If the two sites ever
// carry separate literals, the failure is silent in the worst direction — the
// policy rejects Services on a port nothing denies, while the port that IS denied
// stays publishable, which is exactly the defect the policy exists to close.
//
// runServer boots a real control plane, so no unit test can call it; the wiring is
// therefore asserted structurally, by reading server.go (the idiom
// servermeshwiring_test.go establishes). Both assertions are about a single
// expression, so source position is not even needed — only identity.
func TestServerSingleSourcesTheDeniedLocalPorts(t *testing.T) {
	_, body := runServerBody(t)

	// The value handed to the admission provisioning.
	var policyArg string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "provisionClusterPolicies" {
			return true
		}
		for _, arg := range call.Args {
			if s := callText(arg); s != "" {
				policyArg = s
			}
		}
		return true
	})
	if policyArg != "opts.deniedLocalPorts()" {
		t.Errorf("provisionClusterPolicies is handed %q, want opts.deniedLocalPorts() — the policy must carry the ports the node actually denies", policyArg)
	}

	// The value stamped onto the node.
	var nodeStamp string
	ast.Inspect(body, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "deniedLocalPorts" {
			return true
		}
		nodeStamp = callText(kv.Value)
		return true
	})
	if nodeStamp != "opts.deniedLocalPorts()" {
		t.Errorf("nodeOptions.deniedLocalPorts is set from %q, want opts.deniedLocalPorts() — a second literal here is how the SBPL deny and its admission guard drift apart", nodeStamp)
	}

	// And the method itself is the kine port, nothing else.
	if got := (serverOptions{kinePort: 12380}).deniedLocalPorts(); !slices.Equal(got, []int{12380}) {
		t.Errorf("deniedLocalPorts() = %v, want [12380] (the resolved --kine-port)", got)
	}
}

// callText renders `x.f()` as "x.f()" and everything else as "" — the one shape
// this file asserts on, written out rather than pulling in go/printer.
func callText(e ast.Expr) string {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return recv.Name + "." + sel.Sel.Name + "()"
}

// TestBringupDeniedLocalPortPolicyCarriesTheKinePort pins the POLICY PARAMETER,
// not just the policy's presence: the CEL bring-up provisions must embed the port
// this server actually denies, so a `--kine-port 12380` server rejects Services on
// 12380 rather than on the default nobody is listening on.
func TestBringupDeniedLocalPortPolicyCarriesTheKinePort(t *testing.T) {
	const sentinelKinePort = 12385
	mode, err := hostnet.ResolveFor("helper", 501)
	if err != nil {
		t.Fatalf("hostnet.ResolveFor: %v", err)
	}
	cs := fake.NewClientset()
	provisionClusterPolicies(context.Background(), cs, mode, 501,
		serverOptions{kinePort: sentinelKinePort}.deniedLocalPorts(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().
		Get(context.Background(), "k3sm-reject-service-denied-local-port", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("bring-up did not provision the denied-local-port policy: %v", err)
	}
	if len(pol.Spec.Validations) != 1 {
		t.Fatalf("validations = %d, want 1", len(pol.Spec.Validations))
	}
	expr := pol.Spec.Validations[0].Expression
	if !strings.Contains(expr, strconv.Itoa(sentinelKinePort)) {
		t.Errorf("provisioned CEL does not pin this server's kine port %d:\n%s", sentinelKinePort, expr)
	}
}
