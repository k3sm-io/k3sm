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

// This file asserts the server-mesh bring-up WIRING structurally, by reading runServer's
// trace (servertrace_test.go): runServer's body with its server*.go helpers
// expanded at their call sites, every pinned call in a straight-line sequence.

// TestRunServerEnrollsSelfBeforeTheDatapathAndJoinListener is the ordering
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
// It also pins the upstream preconditions: the enroll runs after the MeshPeer CRD
// ensure (the CRD its very first write lands in), and the RBAC graph exists before
// the join listener opens, because a joining worker's first request is evaluated
// by the Node,RBAC authorizer. The server's own enroll is not ordered after the
// RBAC graph: it rides the system:masters admin client, which that authorizer
// does not evaluate, and it runs before provisioning
// (TestServerBringsTheMeshUpBeforeProvisioning).
func TestRunServerEnrollsSelfBeforeTheDatapathAndJoinListener(t *testing.T) {
	tr := runServerTrace(t)
	first := tr.firstCalls()

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
			t.Fatalf("runServer never calls %s — the server-mesh wiring is absent (the server would broker a mesh it is not on)", name)
		}
	}

	mustPrecede := []struct{ before, after, why string }{
		{"rbac.Provision", "startBootstrapServer", "a joining worker's first request is evaluated by the Node,RBAC authorizer against the graph"},
		{"ensureMeshPeerCRD", "enrollSelfAndBringUpMesh", "the self-enroll is the FIRST MeshPeer written on a fresh cluster"},
		{"newMeshEnroller", "enrollSelfAndBringUpMesh", "the self-enroll goes through the same locked enroller the join RPC uses"},
		{"enrollSelfAndBringUpMesh", "netserve.New", "mesh.Start plumbs the mesh-egress lo0 alias the proxy sources from"},
		{"enrollSelfAndBringUpMesh", "startBootstrapServer", "the index-0 claim must be durable before a worker can be assigned an index"},
	}
	for _, want := range mustPrecede {
		if first[want.before].pos >= first[want.after].pos {
			t.Errorf("runServer calls %s at %s, NOT before %s at %s — %s",
				want.before, tr.where(first[want.before].call),
				want.after, tr.where(first[want.after].call), want.why)
		}
	}
}

// TestRunServerSharesOneMeshEnroller pins R8's "same instance": the mutex that
// serializes this node's index-0 claim against a concurrent worker join only does
// anything if both callers hold the SAME enroller. Two constructions would
// contend on nothing.
func TestRunServerSharesOneMeshEnroller(t *testing.T) {
	calls := 0
	runServerTrace(t).inspect(func(n ast.Node) bool {
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

// TestServerMeshBringUpIsLogAndContinue pins that a mesh-only failure is log-and-continue.
//
// The repo's one rule for a fault on this process: unsurvivable faults exit (a
// dead control-plane child does, and the crash-loop breaker bounds the respawns);
// survivable ones continue. A mesh-only defect is survivable — the apiserver, kine
// and the scheduler serve without it — so the enroll's error is LOGGED. The
// assertion is the absence of a `return` in its error branch, which is exactly
// what a well-meaning later edit would add.
func TestServerMeshBringUpIsLogAndContinue(t *testing.T) {
	tr := runServerTrace(t)
	found := false
	tr.inspect(func(n ast.Node) bool {
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
				t.Errorf("runServer RETURNS at %s when the server mesh bring-up fails; a mesh-only defect is survivable and must not take the control plane down (a mesh-only failure must log and continue)",
					tr.where(ret))
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

// TestServerNetserveWiresTheMeshEgressSource pins the mesh egress source wiring.
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
	var cfg *ast.CompositeLit
	runServerTrace(t).inspect(func(n ast.Node) bool {
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

// TestRunServerEnsuresTheMeshIPAliasBeforeTheControlPlane is the ordering pin for
// the second defect the first real --mesh-ip boot exposed.
//
// runServer hands --mesh-ip to the executor as the apiserver's BindAddress at step
// 1, but until the mesh bring-up wiring the only code that ever plumbed that address was mesh.Start —
// at the mesh bring-up, several phases later. So a mesh IP that is not already a host address
// dies at `listen tcp 100.64.0.1:6444: bind: can't assign requested address`
// before any of this file's other pins can even be reached, and the operator has
// to alias it by hand. The lab tier booted --mesh-ip 127.0.0.1, which every
// host already answers on, so the ordering was never exercised.
//
// The ensure must therefore precede BOTH the executor's construction and its
// Start. Its no-mesh behaviour is not asserted here but in the ensure itself
// (ensureMeshIPAliasWith returns before touching anything on an empty mesh IP);
// what IS asserted structurally is that runServer passes opts.meshIP through
// rather than calling it under some other predicate — the same shape
// ensureMeshPeerCRD uses one phase later.
func TestRunServerEnsuresTheMeshIPAliasBeforeTheControlPlane(t *testing.T) {
	tr := runServerTrace(t)
	first := tr.firstCalls()

	for _, name := range []string{"ensureMeshIPAlias", "executor.NewSupervised", "exec.Start"} {
		if _, ok := first[name]; !ok {
			t.Fatalf("runServer never calls %s — a --mesh-ip the host does not already answer on cannot be bound, so bring-up dies before any other wiring runs", name)
		}
	}
	for _, want := range []struct{ before, after, why string }{
		{"ensureMeshIPAlias", "executor.NewSupervised", "the executor is built with --mesh-ip as the apiserver BindAddress"},
		{"ensureMeshIPAlias", "exec.Start", "the apiserver binds the mesh IP the moment the control plane starts"},
		{"ensureMeshIPAlias", "enrollSelfAndBringUpMesh", "mesh.Start plumbs the same alias far too late to serve the apiserver's bind"},
	} {
		if first[want.before].pos >= first[want.after].pos {
			t.Errorf("runServer calls %s at %s, NOT before %s at %s — %s",
				want.before, tr.where(first[want.before].call),
				want.after, tr.where(first[want.after].call), want.why)
		}
	}

	var call *ast.CallExpr
	tr.inspect(func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := c.Fun.(*ast.Ident); ok && ident.Name == "ensureMeshIPAlias" && call == nil {
			call = c
		}
		return true
	})
	if call == nil {
		t.Fatal("runServer's ensureMeshIPAlias call could not be read back")
	}
	passesMeshIP := false
	for _, arg := range call.Args {
		sel, ok := arg.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "opts" && sel.Sel.Name == "meshIP" {
			passesMeshIP = true
		}
	}
	if !passesMeshIP {
		t.Errorf("runServer's ensureMeshIPAlias at %s is not passed opts.meshIP — the single-node posture's no-op is what keeps this call free there",
			tr.where(call))
	}
}

// TestServerBringsTheMeshUpBeforeProvisioning pins where the mesh comes up in the
// server's bring-up: right after the control plane is healthy and its client is
// built, before the cluster provisioning and the ingest registry.
//
// A worker reaches this server's API over the mesh, so every second between the
// apiserver answering and the wireguard device existing is a second the worker's
// path is down while the server's own probe already says ok. Measured on a
// two-Mac roll, the worker's window ran 14.5 s past the server's own, the time
// the admission policies, the RBAC graph, the add-ons, the helm controller, the
// manifest directory and the registry took before the enroll ran.
//
// Nothing in that provisioning is an input to the enroll: the MeshPeer CRD is
// applied by ensureMeshPeerCRD itself, and the enroll, its node-password bind,
// its range claims and the mesh watch all ride the server's system:masters admin
// client, which the Node,RBAC authorizer does not evaluate. The RBAC graph is a
// precondition of the worker-join listener instead, and that ordering is pinned
// by TestRunServerEnrollsSelfBeforeTheDatapathAndJoinListener.
//
// Moving the enroll earlier must not move it past the two phases that consume
// it, so this pin also holds enrollServerMesh ahead of startServerDatapath (the
// proxy sources from the mesh-egress alias mesh.Start plumbs) and of
// startBootstrapServer (this node's range claim must be durable before a worker
// can be assigned one), the order enrollSelfAndBringUpMesh calls load-bearing.
func TestServerBringsTheMeshUpBeforeProvisioning(t *testing.T) {
	tr := runServerTrace(t)
	first := tr.firstCalls()

	mesh := []string{"ensureMeshPeerCRD", "enrollServerMesh"}
	provisioning := []string{"provisionClusterPolicies", "startServerRegistry"}
	consumers := []string{"startServerDatapath", "startBootstrapServer"}
	for _, name := range append(append(append([]string{}, mesh...), provisioning...), consumers...) {
		if _, ok := first[name]; !ok {
			t.Fatalf("runServer never calls %s; this ordering pin would be vacuous", name)
		}
	}
	for _, m := range mesh {
		for _, p := range provisioning {
			if first[m].pos >= first[p].pos {
				t.Errorf("runServer calls %s at %s, NOT before %s at %s: the worker's path to this API stays down while provisioning runs",
					m, tr.where(first[m].call), p, tr.where(first[p].call))
			}
		}
	}
	for _, c := range consumers {
		if first["enrollServerMesh"].pos >= first[c].pos {
			t.Errorf("runServer calls enrollServerMesh at %s, NOT before %s at %s: the mesh it consumes is not up yet",
				tr.where(first["enrollServerMesh"].call), c, tr.where(first[c].call))
		}
	}
}
