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

// TestBootstrapListenAddrIsWildcardOnTheMeshPath pins the address the worker-join
// supervisor listens on.
//
// The defect it fixes was invisible to every existing gate because the M14.2 lab
// tier booted with --mesh-ip 127.0.0.1: a supervisor bound to loopback is still
// reachable from the same host, so a single-Mac join succeeded while the only
// posture that matters — a SECOND Mac dialing https://<underlay>:9345 — was
// refused. The first real --mesh-ip 100.64.0.1 boot showed `lsof` reporting the
// supervisor listening on 100.64.0.1:9345 only, an address no un-joined worker can
// route to. A worker has no mesh until this very join completes, which is why
// `k3sm agent --server` documents the underlay and why EnrollSelf advertises an
// underlay MeshPeer endpoint.
//
// The empty case is asserted too, and deliberately closed: no mesh means no
// listener is ever opened, but deriving loopback there keeps a future caller from
// acquiring LAN exposure by accident.
func TestBootstrapListenAddrIsWildcardOnTheMeshPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		meshIP string
		want   string
	}{
		{"a real mesh IP listens on every interface", "100.64.0.1", "0.0.0.0:9345"},
		{"a loopback mesh IP still listens on every interface", "127.0.0.1", "0.0.0.0:9345"},
		{"a single-host mesh IP still listens on every interface", "192.168.0.111", "0.0.0.0:9345"},
		{"no mesh derives loopback, never the wildcard", "", "127.0.0.1:9345"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := bootstrapListenAddr(tc.meshIP); got != tc.want {
				t.Errorf("bootstrapListenAddr(%q) = %q, want %q — a mesh-scoped bind refuses every join from a worker that is not yet on the mesh",
					tc.meshIP, got, tc.want)
			}
		})
	}
}

// TestStartBootstrapServerUsesTheDerivedListenAddr pins the CALL SITE.
//
// bootstrapListenAddr is only worth testing if the supervisor uses it: the
// original defect was literally one net.JoinHostPort(meshIP, …) expression in
// startBootstrapServer, and re-introducing it would leave the table above green
// while every real join is refused again. startBootstrapServer opens a live TLS
// listener, so it cannot be called from a unit test; the http.Server literal it
// builds is read structurally instead.
func TestStartBootstrapServerUsesTheDerivedListenAddr(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "enroll.go", nil, 0)
	if err != nil {
		t.Fatalf("parse enroll.go: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "startBootstrapServer" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("enroll.go declares no startBootstrapServer function")
	}

	var addr ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "http" || sel.Sel.Name != "Server" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Addr" && addr == nil {
				addr = kv.Value
			}
		}
		return true
	})
	if addr == nil {
		t.Fatal("startBootstrapServer builds no http.Server literal with an Addr field")
	}
	call, ok := addr.(*ast.CallExpr)
	if !ok {
		t.Fatalf("startBootstrapServer's http.Server.Addr at %s is not a call to bootstrapListenAddr", fset.Position(addr.Pos()))
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "bootstrapListenAddr" {
		t.Errorf("startBootstrapServer's http.Server.Addr at %s does not call bootstrapListenAddr — a mesh-scoped bind here refuses every underlay join",
			fset.Position(addr.Pos()))
	}
}
