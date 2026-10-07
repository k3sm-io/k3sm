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
	"go/ast"
	"testing"
)

// TestServerNetservePolicyClientIsAdmin pins, in runServer's source, that the
// server's datapath is the one that enforces NetworkPolicy and that it does so
// under the admin client. The policy watcher lists and watches NetworkPolicies,
// Pods and Namespaces cluster wide; only the admin identity is granted all three.
// If the datapath's client were ever swapped for a node identity, the watcher
// would be refused on every retry, never sync, and leave every connection
// allowed with no test going red. So the netserve.Config literal must:
//   - set EnforceNetworkPolicy: true and leave PodScopeNode unset;
//   - set Client from a variable assigned exactly once, as the second result of
//     kubeclient.FromPath(exec.Kubeconfig()) (the system:masters kubeconfig the
//     executor writes).
func TestServerNetservePolicyClientIsAdmin(t *testing.T) {
	tr := runServerTrace(t)

	var lit *ast.CompositeLit
	tr.inspect(func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSelector(call.Fun, "netserve", "New") || len(call.Args) != 1 {
			return true
		}
		cl, ok := call.Args[0].(*ast.CompositeLit)
		if !ok || !isSelector(cl.Type, "netserve", "Config") {
			t.Errorf("netserve.New in runServer is not called with a netserve.Config literal")
			return true
		}
		if lit != nil {
			t.Errorf("runServer calls netserve.New more than once")
		}
		lit = cl
		return true
	})
	if lit == nil {
		t.Fatal("runServer contains no netserve.New(netserve.Config{...}) call; this check would be vacuous")
	}

	var clientVar string
	enforce := false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Client":
			id, ok := kv.Value.(*ast.Ident)
			if !ok {
				t.Fatalf("netserve.Config.Client is not a plain variable")
			}
			clientVar = id.Name
		case "EnforceNetworkPolicy":
			id, ok := kv.Value.(*ast.Ident)
			enforce = ok && id.Name == "true"
		case "PodScopeNode":
			t.Error("the server's netserve.Config sets PodScopeNode; the admin client watches every pod")
		}
	}
	if !enforce {
		t.Error("the server's netserve.Config does not set EnforceNetworkPolicy: true; NetworkPolicy would be enforced nowhere")
	}
	if clientVar == "" {
		t.Fatal("the server's netserve.Config sets no Client")
	}

	assigns := 0
	fromAdmin := false
	tr.inspect(func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != clientVar {
				continue
			}
			assigns++
			if i != 1 || len(as.Rhs) != 1 {
				continue
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok || !isSelector(call.Fun, "kubeclient", "FromPath") || len(call.Args) != 1 {
				continue
			}
			arg, ok := call.Args[0].(*ast.CallExpr)
			if ok && isSelector(arg.Fun, "exec", "Kubeconfig") && len(arg.Args) == 0 {
				fromAdmin = true
			}
		}
		return true
	})
	if assigns != 1 {
		t.Errorf("%s is assigned %d times in runServer, want exactly once (from the admin kubeconfig)", clientVar, assigns)
	}
	if !fromAdmin {
		t.Errorf("%s, the server datapath's client, is not the second result of kubeclient.FromPath(exec.Kubeconfig()), the admin kubeconfig", clientVar)
	}
}

// isSelector reports whether e is the qualified selector pkg.name.
func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg
}
