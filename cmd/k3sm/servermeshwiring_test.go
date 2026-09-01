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
	"go/parser"
	"go/token"
	"testing"
)

// This file asserts M14.2's bring-up WIRING structurally, by reading server.go.
//
// runServer boots a real control plane, so no unit test can call it — and this
// repo's recurring defect class is a well-tested helper bring-up never calls
// (B195, B209), or calls in the wrong order. Source position is a sound proxy
// here because every call asserted below sits in runServer's straight-line
// bring-up sequence; there is no loop or branch that could execute them out of
// textual order.

// runServerBody parses server.go and returns runServer's body.
func runServerBody(t *testing.T) (*token.FileSet, *ast.BlockStmt) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "runServer" {
			return fset, fn.Body
		}
	}
	t.Fatal("server.go declares no runServer function")
	return nil, nil
}

// firstCallPositions maps a call name to its FIRST occurrence in body. It records
// both bare identifiers (enrollSelfAndBringUpMesh) and qualified selectors
// (netserve.New), because the ordering M14.2 depends on spans both shapes.
func firstCallPositions(body *ast.BlockStmt) map[string]token.Pos {
	first := map[string]token.Pos{}
	note := func(name string, pos token.Pos) {
		if _, seen := first[name]; !seen {
			first[name] = pos
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			note(fun.Name, call.Pos())
		case *ast.SelectorExpr:
			if pkg, ok := fun.X.(*ast.Ident); ok {
				note(pkg.Name+"."+fun.Sel.Name, call.Pos())
			}
		}
		return true
	})
	return first
}

// TestRunServerEnrollsSelfBeforeTheDatapathAndJoinListener is M14.2 d4's ordering
// pin, and it encodes two distinct reasons:
//
//   - BEFORE netserve.New — mesh.Start plumbs the mesh-egress lo0 alias the
//     proxy's destination-scoped source bind depends on. Built first, the proxy
//     would be handed a source address the host does not yet answer on.
//   - BEFORE startBootstrapServer — EnrollSelf list-back verifies this node's
//     index-0 claim. Opened first, the join listener could hand index 0 to a
//     worker (the free-index scanner has no reason not to), and two peers would
//     claim one AllowedIPs, which wireguard cannot admit.
//
// It also pins the two upstream preconditions the plan names: the enroll runs
// after the RBAC graph and after the MeshPeer CRD ensure — the CRD its very first
// write lands in.
func TestRunServerEnrollsSelfBeforeTheDatapathAndJoinListener(t *testing.T) {
	fset, body := runServerBody(t)
	first := firstCallPositions(body)

	required := []string{
		"rbac.Provision",
		"ensureMeshPeerCRD",
		"newMeshEnroller",
		"enrollSelfAndBringUpMesh",
		"netserve.New",
		"startBootstrapServer",
	}
	for _, name := range required {
		if _, ok := first[name]; !ok {
			t.Fatalf("runServer never calls %s — the M14.2 server-mesh wiring is absent (the server would broker a mesh it is not on)", name)
		}
	}

	mustPrecede := []struct{ before, after, why string }{
		{"rbac.Provision", "enrollSelfAndBringUpMesh", "the enroll writes a MeshPeer under an enforcing Node,RBAC authorizer"},
		{"ensureMeshPeerCRD", "enrollSelfAndBringUpMesh", "the self-enroll is the FIRST MeshPeer written on a fresh cluster"},
		{"newMeshEnroller", "enrollSelfAndBringUpMesh", "the self-enroll goes through the same locked enroller the join RPC uses"},
		{"enrollSelfAndBringUpMesh", "netserve.New", "mesh.Start plumbs the mesh-egress lo0 alias the proxy sources from"},
		{"enrollSelfAndBringUpMesh", "startBootstrapServer", "the index-0 claim must be durable before a worker can be assigned an index"},
	}
	for _, want := range mustPrecede {
		if first[want.before] >= first[want.after] {
			t.Errorf("runServer calls %s at %s, NOT before %s at %s — %s",
				want.before, fset.Position(first[want.before]),
				want.after, fset.Position(first[want.after]), want.why)
		}
	}
}

// TestRunServerSharesOneMeshEnroller pins R8's "same instance": the mutex that
// serializes this node's index-0 claim against a concurrent worker join only does
// anything if both callers hold the SAME enroller. Two constructions would
// contend on nothing.
func TestRunServerSharesOneMeshEnroller(t *testing.T) {
	_, body := runServerBody(t)
	calls := 0
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "newMeshEnroller" {
				calls++
			}
		}
		return true
	})
	if calls != 1 {
		t.Errorf("runServer constructs %d mesh enrollers, want exactly 1 — the self-enroll and the join RPC must contend on ONE mutex", calls)
	}
}

// TestServerMeshBringUpIsLogAndContinue is M14.2 d7 / R12.
//
// Under launchd KeepAlive a fatal error on this path is an unbounded respawn loop
// on the one process that also hosts the apiserver, kine and the scheduler. A
// mesh-only defect must never take the control plane down, so the enroll's error
// is LOGGED — the assertion is the absence of a `return` in its error branch,
// which is exactly what a well-meaning later edit would add.
func TestServerMeshBringUpIsLogAndContinue(t *testing.T) {
	fset, body := runServerBody(t)
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			return true
		}
		calls := false
		ast.Inspect(ifStmt.Init, func(m ast.Node) bool {
			if ident, ok := m.(*ast.Ident); ok && ident.Name == "enrollSelfAndBringUpMesh" {
				calls = true
			}
			return true
		})
		if !calls {
			return true
		}
		found = true
		ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
			if ret, ok := m.(*ast.ReturnStmt); ok {
				t.Errorf("runServer RETURNS at %s when the server mesh bring-up fails; under launchd KeepAlive that is an unbounded respawn loop on the control plane (M14.2 d7 requires log-and-continue)",
					fset.Position(ret.Pos()))
			}
			return true
		})
		logged := false
		ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Error" || sel.Sel.Name == "Warn") {
				logged = true
			}
			return true
		})
		if !logged {
			t.Error("the server mesh bring-up failure branch neither logs nor returns; the failure would be invisible")
		}
		return true
	})
	if !found {
		t.Fatal("runServer does not call enrollSelfAndBringUpMesh inside an error-checked if — the failure posture is unassertable")
	}
}

// TestServerNetserveWiresTheMeshEgressSource is M14.2 d5.
//
// The proxy's mesh-egress source and the peer mesh-egress /32s the NetworkPolicy
// table always-allows were BOTH deliberately left unset on the server, because the
// dialer bound the source unconditionally and any non-local value broke every
// backend dial. With the bind destination-scoped (d1) the wiring is safe, and its
// absence is once again a real gap: cross-node backend dials sourced from the
// kernel default are dropped by the peer's wireguard as outside AllowedIPs.
//
// Asserted on the netserve.Config composite literal inside runServer, so a field
// silently dropped in a later edit reddens here rather than in a two-Mac lab.
func TestServerNetserveWiresTheMeshEgressSource(t *testing.T) {
	_, body := runServerBody(t)
	var cfg *ast.CompositeLit
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "netserve" && sel.Sel.Name == "Config" && cfg == nil {
			cfg = lit
		}
		return true
	})
	if cfg == nil {
		t.Fatal("runServer builds no netserve.Config literal")
	}
	set := map[string]ast.Expr{}
	for _, elt := range cfg.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok {
			set[key.Name] = kv.Value
		}
	}
	for _, field := range []string{"MeshEgressIP", "PeerMeshEgressIPs"} {
		value, ok := set[field]
		if !ok {
			t.Errorf("runServer's netserve.Config does not set %s — the server's Service proxy sources cross-node backend dials from the kernel default, which the peer's wireguard drops", field)
			continue
		}
		if lit, ok := value.(*ast.BasicLit); ok {
			t.Errorf("runServer's netserve.Config sets %s to the literal %s rather than the enrolled value", field, lit.Value)
		}
	}
}
