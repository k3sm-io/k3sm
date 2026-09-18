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

package bootstrap_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// peerStoreEnroller is an enroller that KEEPS the peers written through it, so a
// test can ask what a request did to an existing one. The fixed-assignment
// fakeEnroller cannot answer that: it stores nothing the join path writes, and a
// guard about an overwrite has to be able to show the object was not overwritten.
//
// Locking discipline: mu guards peers + enrolls; httptest serves each request on
// its own goroutine.
type peerStoreEnroller struct {
	podCIDR string
	meshIP  string

	mu sync.Mutex
	// peers is the stored MeshPeer spec per node name — the state a join
	// overwrites, and the state a refused join must leave untouched.
	peers map[string]netv1.MeshPeerSpec
	// enrolls counts EVERY Enroll call. A refusal test asserts it stayed zero:
	// the enroll is what writes the peer AND the gate every certificate in this
	// handler is signed after, so "Enroll never ran" is the mechanical form of
	// "nothing was written and nothing was signed".
	enrolls int
}

func newPeerStoreEnroller(podCIDR, meshIP string, seed ...netv1.MeshPeerSpec) *peerStoreEnroller {
	e := &peerStoreEnroller{podCIDR: podCIDR, meshIP: meshIP, peers: map[string]netv1.MeshPeerSpec{}}
	for _, p := range seed {
		e.peers[p.NodeName] = p
	}
	return e
}

// Enroll writes the requesting node's peer, replacing any peer already stored
// under that name — the real enroller's upsert, which is exactly the overwrite
// the self-name guard exists to keep off the control plane's own object.
func (e *peerStoreEnroller) Enroll(_ context.Context, nodeName string, req netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, bootstrap.Allocation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enrolls++
	e.peers[nodeName] = netv1.MeshPeerSpec{
		NodeName:   nodeName,
		PublicKey:  req.PublicKey,
		Endpoint:   req.Endpoint,
		PodCIDR:    e.podCIDR,
		AllowedIPs: []string{e.podCIDR},
		MeshIP:     e.meshIP,
	}.WithDefaults()
	snapshot := make([]netv1.MeshPeerSpec, 0, len(e.peers))
	for _, p := range e.peers {
		snapshot = append(snapshot, p)
	}
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  e.podCIDR,
		MeshIP:   e.meshIP,
		Peers:    snapshot,
	}.WithDefaults(), bootstrap.Allocation{}, nil
}

func (e *peerStoreEnroller) ReleaseAllocation(_ context.Context, _ string, _ bootstrap.Allocation) error {
	return nil
}

func (e *peerStoreEnroller) RefreshEndpoint(_ context.Context, _, _ string) error { return nil }

func (e *peerStoreEnroller) Deregister(_ context.Context, _ string) error { return nil }

// peer returns the stored spec for nodeName.
func (e *peerStoreEnroller) peer(nodeName string) (netv1.MeshPeerSpec, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.peers[nodeName]
	return p, ok
}

// calls returns how many times Enroll ran.
func (e *peerStoreEnroller) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enrolls
}

// TestJoinRefusesTheControlPlaneNodeName is the B348 gate: a worker join that
// claims the CONTROL PLANE's own node name is refused, and refused before
// anything identity-bearing has happened.
//
// The attack it closes needs only a valid worker join token and the server's node
// name, which is "k3sm-" + the hostname and is not a secret. The server enrolls
// itself directly and never passes through this handler, so its own name was
// UNBOUND in the node-password store: the join bound it (first write wins), the
// enroll reused the server's own index-0 assignment, the MeshPeer write replaced
// the control plane's public key and endpoint with the caller's, and the handler
// then signed a system:node:<server> client certificate — full control-plane
// node identity, plus every peer's tunnel to that node redirected.
//
// Fails before the fix: the join is served 200 with a certificate, the stored
// peer carries the caller's key, and the name is bound to the caller's password.
func TestJoinRefusesTheControlPlaneNodeName(t *testing.T) {
	t.Parallel()

	const selfName = "k3sm-host"
	const selfMeshIP = "100.64.0.1"

	// The control plane's own peer, as EnrollSelf wrote it at bring-up.
	selfPeer := netv1.MeshPeerSpec{
		NodeName:   selfName,
		PublicKey:  "c2VydmVyLXB1YmxpYy1rZXktYmFzZTY0LTMyYnl0ZXM9",
		Endpoint:   "192.0.2.10:51820",
		PodCIDR:    "100.64.0.0/24",
		AllowedIPs: []string{"100.64.0.0/24"},
		MeshIP:     selfMeshIP,
	}.WithDefaults()

	t.Run("a join claiming the control plane's own name is refused", func(t *testing.T) {
		t.Parallel()
		enroller := newPeerStoreEnroller("100.64.0.0/24", selfMeshIP, selfPeer)
		rig := newSelfNameJoinServerRig(t, enroller, selfName)

		status, body := rig.post(t, bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodeName:      selfName,
			NodePassword:  "attacker-node-password",
			// A CSR the server would happily sign for this name and address, so
			// the ONLY thing that can refuse this request is the self-name guard.
			// If it stops firing, this row comes back 200 carrying a
			// system:node:k3sm-host credential.
			ClientCSRPEM: nodeCSRPEM(t, selfName, []string{selfName}, []net.IP{net.ParseIP(selfMeshIP)}),
			Mesh: netv1.MeshEnrollRequest{
				NodeName:  selfName,
				PublicKey: "YXR0YWNrZXItcHVibGljLWtleS1iYXNlNjQtMzJieXRlcw==",
				Endpoint:  "192.0.2.66:51820",
			}.WithDefaults(),
		})

		if status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want 403: the control plane's own node name is not joinable", status, body)
		}
		if !strings.Contains(body, "not available") {
			t.Errorf("refusal %q must say the name cannot be joined", body)
		}
		// The refusal must not turn into a disclosure channel: it tells the caller
		// nothing about the allocator, the peer set, or how far the request got.
		for _, leak := range []string{selfPeer.PublicKey, selfPeer.Endpoint, selfPeer.PodCIDR, selfMeshIP} {
			if strings.Contains(body, leak) {
				t.Errorf("refusal %q leaks %q about the control-plane node", body, leak)
			}
		}

		// The control plane's own MeshPeer is BYTE-IDENTICAL — not merely still
		// there. An overwrite that kept the name and replaced the public key and
		// endpoint is the whole attack, and it would pass an existence check.
		got, ok := enroller.peer(selfName)
		if !ok {
			t.Fatal("the control-plane node's MeshPeer is gone after a refused join")
		}
		if !reflect.DeepEqual(got, selfPeer) {
			t.Errorf("the control-plane node's MeshPeer changed:\n got  %+v\n want %+v", got, selfPeer)
		}

		// NOTHING was bound for that name. The binding is the durable half of the
		// attack: whoever holds it is that node on every later join.
		if _, bound := rig.passwords.StoredHash(selfName); bound {
			t.Error("a refused join bound a node-password for the control plane's own name — the next join presenting that password would be accepted as the control plane")
		}

		// THE SIGNER WAS NEVER INVOKED. Both signing calls in handleJoin are
		// downstream of the enroll, and every certificate the handler signs goes
		// into the response, so an enroll count of zero plus a body carrying no
		// certificate is the mechanical statement that nothing was signed. (The
		// ordering that makes the first half of that true is pinned below, in
		// "the refusal precedes everything identity-bearing".)
		if n := enroller.calls(); n != 0 {
			t.Errorf("the enroll ran %d times on a refused join, want 0: the enroll allocates and writes, and every certificate is signed after it", n)
		}
		if strings.Contains(body, "CERTIFICATE") {
			t.Errorf("a refused join returned certificate material: %q", body)
		}
	})

	t.Run("a join naming any other node still succeeds", func(t *testing.T) {
		t.Parallel()
		enroller := newPeerStoreEnroller("100.64.1.0/24", "100.64.1.1", selfPeer)
		rig := newSelfNameJoinServerRig(t, enroller, selfName)

		res, err := bootstrap.Join(context.Background(), bootstrap.JoinOptions{
			Server:       rig.ts.URL,
			Token:        rig.token,
			NodeName:     "worker-1",
			NodePassword: "worker-node-password",
			MeshEndpoint: "192.0.2.50:51820",
			HTTPClient:   rig.ts.Client(),
		})
		if err != nil {
			t.Fatalf("an ordinary worker join must still be served: %v", err)
		}
		leaf := parseCertPEM(t, res.NodeClientCertPEM)
		if leaf.Subject.CommonName != "system:node:worker-1" {
			t.Errorf("issued CN = %q, want system:node:worker-1", leaf.Subject.CommonName)
		}
		if err := leaf.CheckSignatureFrom(rig.signingCA.Cert); err != nil {
			t.Errorf("the node cert must be signed by the signing CA: %v", err)
		}
		if _, bound := rig.passwords.StoredHash("worker-1"); !bound {
			t.Error("an accepted join must bind the node-password for its own name")
		}
		if _, ok := enroller.peer("worker-1"); !ok {
			t.Error("an accepted join must write its own MeshPeer")
		}
		// And it left the control plane's peer alone, because it never named it.
		if got, _ := enroller.peer(selfName); !reflect.DeepEqual(got, selfPeer) {
			t.Errorf("an ordinary join changed the control-plane node's MeshPeer: %+v", got)
		}
	})

	t.Run("the name match is trimmed and case-insensitive", func(t *testing.T) {
		t.Parallel()
		enroller := newPeerStoreEnroller("100.64.0.0/24", selfMeshIP, selfPeer)
		rig := newSelfNameJoinServerRig(t, enroller, selfName)

		// A Kubernetes node name is lowercase RFC-1123, so a request differing
		// only in case or surrounding space is never a second legitimate node —
		// but it WOULD be a one-character bypass of a byte-equality guard.
		for _, claimed := range []string{"K3SM-Host", " k3sm-host", "k3sm-host\n"} {
			status, body := rig.post(t, bootstrap.JoinRequest{
				SchemaVersion: bootstrap.JoinSchemaVersion,
				Token:         rig.token,
				NodeName:      claimed,
				NodePassword:  "attacker-node-password",
				ClientCSRPEM:  nodeCSRPEM(t, claimed, nil, []net.IP{net.ParseIP(selfMeshIP)}),
				Mesh:          netv1.MeshEnrollRequest{NodeName: claimed}.WithDefaults(),
			})
			if status != http.StatusForbidden {
				t.Errorf("node name %q: status = %d (%s), want 403", claimed, status, body)
			}
		}
		if n := enroller.calls(); n != 0 {
			t.Errorf("the enroll ran %d times across the near-miss names, want 0", n)
		}
	})

	t.Run("the refusal precedes everything identity-bearing", func(t *testing.T) {
		t.Parallel()
		// Source order, read off handleJoin. The runtime rows above prove nothing
		// was bound, written or signed for the refused request; this pins WHY —
		// the refusal is textually ahead of the node-password bind, the enroll and
		// both signing calls, all of which sit in handleJoin's straight-line body
		// with no loop or branch that could run them out of order. Without it, a
		// later edit could move the guard below the bind and only the negative
		// assertions above would notice, one fixture at a time.
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "server.go", nil, 0)
		if err != nil {
			t.Fatalf("parse server.go: %v", err)
		}
		var body *ast.BlockStmt
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "handleJoin" {
				body = fn.Body
			}
		}
		if body == nil {
			t.Fatal("server.go declares no handleJoin method")
		}
		first := map[string]token.Pos{}
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			if _, seen := first[name]; name != "" && !seen {
				first[name] = call.Pos()
			}
			return true
		})
		for _, after := range []struct{ call, why string }{
			{"Ensure", "the node-password store must never see the control plane's own name from a join"},
			{"Enroll", "the enroll allocates and writes the MeshPeer the attack overwrites"},
			{"ApproveAndSignNodeCSR", "the system:node client certificate is the credential the attack collects"},
			{"ApproveAndSignKubeletServing", "the kubelet-serving certificate lets the caller answer as the node"},
		} {
			pos, ok := first[after.call]
			if !ok {
				t.Errorf("handleJoin no longer calls %s — this ordering pin has gone vacuous", after.call)
				continue
			}
			guard, ok := first["selfNameClaimed"]
			if !ok {
				t.Fatal("handleJoin no longer calls selfNameClaimed — the control plane's own name is joinable")
			}
			if guard >= pos {
				t.Errorf("the self-name guard is not ahead of %s: %s", after.call, after.why)
			}
		}
	})
}
