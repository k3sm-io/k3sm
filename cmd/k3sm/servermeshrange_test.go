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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
)

// This file is B447: every control-plane server's pod range is the /24 its own
// --mesh-ip names, and that range is reserved — by an atomic claim object — before
// anything is written for it. The two-server lab run is the live proof; these are
// the unit tier.

// The two servers of the HA pair the tests model: the first at index 0, the
// joiner at index 1.
const (
	firstServer  = "studio"
	joinedServer = "laptop"
	joinedMeshIP = "100.64.1.1"
)

var joinedCIDR = netip.MustParsePrefix("100.64.1.0/24")

// joinedClaim is the joining server's member-route claim: its --mesh-ip and an
// endpoint on its etcd peer host.
func joinedClaim() bootstrap.MeshClaim {
	return bootstrap.MeshClaim{MeshIP: joinedMeshIP, PublicKey: testPubKey, Endpoint: "192.0.2.11:51820"}
}

// stubServer returns a REST config whose every request h serves in-process, so
// no socket is opened (handlerTransport).
func stubServer(t *testing.T, h http.Handler) *rest.Config {
	t.Helper()
	return &rest.Config{Host: "http://apiserver.invalid", Transport: handlerTransport{h}}
}

// handlerTransport is an http.RoundTripper that answers every request by calling
// h directly through a recorder: the client stack runs unchanged, the network
// never does.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

// enrollerOverHandler wires a real meshEnroller to a fresh in-process stub
// apiserver (the socket-free twin of enrollerOverStub).
func enrollerOverHandler(t *testing.T) (*meshEnroller, *meshPeerAPIStub) {
	t.Helper()
	api := newMeshPeerAPIStub()
	e, err := newMeshEnroller(stubServer(t, api), quietLogger())
	if err != nil {
		t.Fatalf("newMeshEnroller: %v", err)
	}
	return e, api
}

// TestJoinedServerEnrolsAtItsOwnMeshIndex is the B447 gate. A server joined with
// --mesh-ip 100.64.1.1 enrols at 100.64.1.0/24 — the range its lo0 alias, its netd
// seed and its apiserver bind already use — beside the first server's 100.64.0.0/24,
// which it never touches; and the pod range step 4b leaves for the node passes the
// alias check the node's bring-up runs.
//
// Before B447 every server claimed index 0: the joiner's enrol failed on the first
// server's row and the node's pod range stayed 100.64.0.0/24, which the alias check
// refuses for 100.64.1.1, so the daemon exited.
func TestJoinedServerEnrolsAtItsOwnMeshIndex(t *testing.T) {
	ctx := context.Background()

	t.Run("EnrollSelf at the --mesh-ip range, beside the first server", func(t *testing.T) {
		e, api := enrollerOverHandler(t)
		seedPeer(t, api, firstServer, "100.64.0.0/24")
		before := *api.peer(firstServer)

		selfCIDR, err := serverSelfPodCIDR(joinedMeshIP)
		if err != nil {
			t.Fatalf("serverSelfPodCIDR(%s): %v", joinedMeshIP, err)
		}
		res, err := e.EnrollSelf(ctx, joinedServer, selfCIDR, enrollRequest(joinedServer))
		if err != nil {
			t.Fatalf("EnrollSelf: %v", err)
		}
		if res.PodCIDR != "100.64.1.0/24" || res.MeshIP != joinedMeshIP {
			t.Errorf("enrolled at (%s, %s), want (100.64.1.0/24, %s)", res.PodCIDR, res.MeshIP, joinedMeshIP)
		}
		stored := api.peer(joinedServer)
		if stored == nil {
			t.Fatal("no MeshPeer for the joined server")
		}
		if stored.Labels[meshPeerServerLabel] != "true" {
			t.Errorf("the joined server's MeshPeer is not labelled %s=true: %v", meshPeerServerLabel, stored.Labels)
		}
		if got := stored.Spec.AllowedIPs; len(got) != 1 || got[0] != "100.64.1.0/24" {
			t.Errorf("allowedIPs = %v, want the symmetric [100.64.1.0/24]", got)
		}
		if l := api.lease(meshRangeClaimName(1)); l == nil || claimHolder(l) != joinedServer {
			t.Errorf("the range claim %s is %+v, want held by %s", meshRangeClaimName(1), l, joinedServer)
		}
		if got := *api.peer(firstServer); !reflect.DeepEqual(got, before) {
			t.Errorf("the first server's MeshPeer changed:\n got  %+v\n want %+v", got, before)
		}
	})

	t.Run("step 4b's pod range passes the node's alias check", func(t *testing.T) {
		api := newMeshPeerAPIStub()
		seedPeer(t, api, firstServer, "100.64.0.0/24")
		sm := runEnrollServerMesh(t, api, joinedServer, joinedMeshIP)
		if sm.dataPathRefused != nil {
			t.Fatalf("step 4b refused the data path: %v", sm.dataPathRefused)
		}
		if sm.podCIDR != "100.64.1.0/24" {
			t.Errorf("step 4b left podCIDR %q, want 100.64.1.0/24", sm.podCIDR)
		}
		if err := checkNodeAliasAddr(joinedMeshIP, sm.podCIDR, install.DefaultServiceCIDR); err != nil {
			t.Errorf("the node's alias check refuses %s in step 4b's range %s: %v", joinedMeshIP, sm.podCIDR, err)
		}
		// Why the seed matters: the first-server default is the range the alias
		// check refuses for this mesh IP, which is the exit the joiner used to take.
		if err := checkNodeAliasAddr(joinedMeshIP, defaultNodePodCIDR(), install.DefaultServiceCIDR); err == nil {
			t.Error("the alias check admits the joined server's mesh IP in the first server's range; this subtest would be vacuous")
		}
	})
}

// runEnrollServerMesh runs step 4b for a server named node with --mesh-ip meshIP
// over api, with no datapath, and returns what it left.
func runEnrollServerMesh(t *testing.T, api http.Handler, node, meshIP string) serverMesh {
	t.Helper()
	cfg := stubServer(t, api)
	opts := selfEnrollOptions(t.TempDir(), node)
	opts.meshIP = meshIP
	plan := serverPlan{opts: opts, mode: hostnet.Mode{Backend: hostnet.BackendNone}, serverPKI: serverPKI{hierarchy: &certs.Hierarchy{}}}
	sm, err := enrollServerMesh(context.Background(), plan, cfg, fake.NewClientset(), "", noMeshTeardown, quietLogger())
	if err != nil {
		t.Fatalf("enrollServerMesh: %v", err)
	}
	return sm
}

// TestServerClaimRefusedWhenAWorkerHoldsTheRange: a server never evicts. A worker
// that holds the range the server's --mesh-ip names — through its claim, or as a
// row written before claims existed — refuses the server, on both server paths,
// and the worker's MeshPeer and claim are byte-identical afterwards.
func TestServerClaimRefusedWhenAWorkerHoldsTheRange(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		seed func(t *testing.T, e *meshEnroller, api *meshPeerAPIStub)
	}{
		{"a worker joined through the claims", func(t *testing.T, e *meshEnroller, api *meshPeerAPIStub) {
			seedPeer(t, api, firstServer, "100.64.0.0/24")
			if res, _, err := e.Enroll(ctx, "worker-1", enrollRequest("worker-1")); err != nil || res.PodCIDR != "100.64.1.0/24" {
				t.Fatalf("seed worker: %v %q", err, res.PodCIDR)
			}
		}},
		{"a worker row from before claims", func(t *testing.T, _ *meshEnroller, api *meshPeerAPIStub) {
			seedPeer(t, api, "worker-1", "100.64.1.0/24")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, api := enrollerOverHandler(t)
			tc.seed(t, e, api)
			before := *api.peer("worker-1")
			beforeClaim := api.lease(meshRangeClaimName(1))

			if _, err := e.EnrollSelf(ctx, joinedServer, joinedCIDR, enrollRequest(joinedServer)); !errors.Is(err, ErrMeshIndexClaimed) {
				t.Errorf("EnrollSelf = %v, want ErrMeshIndexClaimed", err)
			}
			if _, err := e.ReserveServerMesh(ctx, joinedServer, joinedClaim()); !errors.Is(err, ErrMeshIndexClaimed) {
				t.Errorf("ReserveServerMesh = %v, want ErrMeshIndexClaimed", err)
			}
			if got := *api.peer("worker-1"); !reflect.DeepEqual(got, before) {
				t.Errorf("the worker's MeshPeer changed:\n got  %+v\n want %+v", got, before)
			}
			if got := api.lease(meshRangeClaimName(1)); !reflect.DeepEqual(got, beforeClaim) {
				t.Errorf("the worker's claim changed:\n got  %+v\n want %+v", got, beforeClaim)
			}
			if api.peer(joinedServer) != nil {
				t.Error("a MeshPeer was written for the refused server")
			}
		})
	}
}

// TestWorkerJoinSkipsAReservedServerRange: a server's reservation — a full one, or
// only its claim (the moment between the claim and the row) — keeps a worker off
// that range; the worker gets the next.
func TestWorkerJoinSkipsAReservedServerRange(t *testing.T) {
	ctx := context.Background()
	t.Run("a reservation with its row", func(t *testing.T) {
		e, api := enrollerOverHandler(t)
		seedPeer(t, api, firstServer, "100.64.0.0/24")
		if _, err := e.ReserveServerMesh(ctx, joinedServer, joinedClaim()); err != nil {
			t.Fatalf("ReserveServerMesh: %v", err)
		}
		res, _, err := e.Enroll(ctx, "worker-1", enrollRequest("worker-1"))
		if err != nil || res.PodCIDR != "100.64.2.0/24" {
			t.Errorf("worker enroll = (%q, %v), want 100.64.2.0/24", res.PodCIDR, err)
		}
	})
	t.Run("a claim with no row yet", func(t *testing.T) {
		e, _ := enrollerOverHandler(t)
		if _, _, err := e.claimRange(ctx, 1, joinedCIDR, joinedServer, rangeClaimMeta{server: true}); err != nil {
			t.Fatalf("claim: %v", err)
		}
		res, _, err := e.Enroll(ctx, "worker-1", enrollRequest("worker-1"))
		if err != nil || res.PodCIDR != "100.64.2.0/24" {
			t.Errorf("worker enroll = (%q, %v), want 100.64.2.0/24", res.PodCIDR, err)
		}
	})
}

// TestLowestFreeNodeIndexNeverReturnsZero: index 0 is the first server's by
// convention and is never handed to a worker, even when no server holds it.
func TestLowestFreeNodeIndexNeverReturnsZero(t *testing.T) {
	for _, existing := range [][]netv1.MeshPeerSpec{
		nil,
		{{NodeName: "w1", PodCIDR: "100.64.1.0/24"}},
		{{NodeName: firstServer, PodCIDR: "100.64.0.0/24"}, {NodeName: joinedServer, PodCIDR: "100.64.1.0/24"}},
	} {
		got, err := lowestFreeNodeIndex(netip.MustParsePrefix("100.64.0.0/10"), existing)
		if err != nil {
			t.Fatalf("lowestFreeNodeIndex: %v", err)
		}
		if got == firstServerIndex {
			t.Errorf("lowestFreeNodeIndex(%v) = 0, the first server's index", existing)
		}
	}
}

// TestWorkerJoinRefusedOverAnyServerPeer: the join path never overwrites a server's
// row — one labelled as a server at any index, or an unlabelled row at index 0 (a
// server that predates the label).
func TestWorkerJoinRefusedOverAnyServerPeer(t *testing.T) {
	ctx := context.Background()
	t.Run("a labelled server row at index 1", func(t *testing.T) {
		e, api := enrollerOverHandler(t)
		if _, err := e.EnrollSelf(ctx, joinedServer, joinedCIDR, enrollRequest(joinedServer)); err != nil {
			t.Fatalf("EnrollSelf: %v", err)
		}
		before := *api.peer(joinedServer)
		if _, _, err := e.Enroll(ctx, joinedServer, enrollRequest(joinedServer)); !errors.Is(err, ErrServerPeerOverwrite) {
			t.Fatalf("Enroll = %v, want ErrServerPeerOverwrite", err)
		}
		if got := *api.peer(joinedServer); !reflect.DeepEqual(got, before) {
			t.Error("the server's row changed")
		}
	})
	t.Run("an unlabelled row at index 0", func(t *testing.T) {
		e, api := enrollerOverHandler(t)
		seedPeer(t, api, firstServer, "100.64.0.0/24")
		if _, _, err := e.Enroll(ctx, firstServer, enrollRequest(firstServer)); !errors.Is(err, ErrServerPeerOverwrite) {
			t.Fatalf("Enroll = %v, want ErrServerPeerOverwrite", err)
		}
	})
}

// TestRejoiningServerReclaimsItsRange: a server that already holds its range
// re-asserts it in place — the same name, the same range and (on the member route)
// the same key. Nothing is ever moved, and a worker's row is never taken: a
// different range, a different key through the member route, or a worker row under
// the name are refused with bootstrap.ErrMeshClaimRefused and change nothing.
func TestRejoiningServerReclaimsItsRange(t *testing.T) {
	ctx := context.Background()

	t.Run("same name, same range, same key: an idempotent re-assertion", func(t *testing.T) {
		e, api := enrollerOverHandler(t)
		if _, err := e.ReserveServerMesh(ctx, joinedServer, joinedClaim()); err != nil {
			t.Fatalf("first reservation: %v", err)
		}
		alloc, err := e.ReserveServerMesh(ctx, joinedServer, joinedClaim())
		if err != nil {
			t.Fatalf("re-reservation: %v", err)
		}
		if alloc.Fresh {
			t.Error("re-asserting an existing row reported a fresh allocation; a failed member add would release the server's real row")
		}
		req := enrollRequest(joinedServer)
		req.Endpoint = "192.0.2.12:51820"
		res, err := e.EnrollSelf(ctx, joinedServer, joinedCIDR, req)
		if err != nil || res.PodCIDR != joinedCIDR.String() {
			t.Fatalf("EnrollSelf = (%q, %v), want the held range", res.PodCIDR, err)
		}
		if got := api.peer(joinedServer); got.Spec.Endpoint != "192.0.2.12:51820" {
			t.Errorf("the endpoint was not updated in place: %q", got.Spec.Endpoint)
		}
		if n := api.leaseCount(); api.lease(meshRangeClaimName(1)) == nil || n != 1 {
			t.Errorf("claims = %d, want the one range claim", n)
		}
	})

	refusals := []struct {
		name string
		seed func(t *testing.T, e *meshEnroller, api *meshPeerAPIStub)
		try  func(e *meshEnroller) error
	}{
		{"a different range is never a move",
			func(t *testing.T, e *meshEnroller, _ *meshPeerAPIStub) {
				if _, err := e.EnrollSelf(ctx, joinedServer, joinedCIDR, enrollRequest(joinedServer)); err != nil {
					t.Fatalf("seed: %v", err)
				}
			},
			func(e *meshEnroller) error {
				_, err := e.EnrollSelf(ctx, joinedServer, netip.MustParsePrefix("100.64.2.0/24"), enrollRequest(joinedServer))
				return err
			}},
		{"a different key through the member route",
			func(t *testing.T, e *meshEnroller, _ *meshPeerAPIStub) {
				if _, err := e.ReserveServerMesh(ctx, joinedServer, joinedClaim()); err != nil {
					t.Fatalf("seed: %v", err)
				}
			},
			func(e *meshEnroller) error {
				c := joinedClaim()
				c.PublicKey = "YW5vdGhlci1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGU9"
				_, err := e.ReserveServerMesh(ctx, joinedServer, c)
				return err
			}},
		{"a worker row under the name",
			func(t *testing.T, _ *meshEnroller, api *meshPeerAPIStub) {
				seedPeer(t, api, joinedServer, "100.64.1.0/24")
			},
			func(e *meshEnroller) error {
				_, err := e.ReserveServerMesh(ctx, joinedServer, joinedClaim())
				return err
			}},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			e, api := enrollerOverHandler(t)
			tc.seed(t, e, api)
			before := *api.peer(joinedServer)
			if err := tc.try(e); !errors.Is(err, bootstrap.ErrMeshClaimRefused) {
				t.Fatalf("err = %v, want bootstrap.ErrMeshClaimRefused", err)
			}
			if got := *api.peer(joinedServer); !reflect.DeepEqual(got, before) {
				t.Errorf("the refused claim changed the row:\n got  %+v\n want %+v", got, before)
			}
			if api.lease(meshRangeClaimName(2)) != nil {
				t.Error("the refused claim took a claim on another range")
			}
		})
	}
}

// TestConcurrentEnrollersNeverShareARange is R1's proof: TWO enrollers — two
// servers, each with its own mutex — serve concurrent worker joins against one
// apiserver. Their only coordination is the claim object's create-if-absent, and no
// /24 ends up held by two names: every peer's range is distinct, and every range's
// claim names the peer that holds it.
func TestConcurrentEnrollersNeverShareARange(t *testing.T) {
	api := newMeshPeerAPIStub()
	cfg := stubServer(t, api)
	var enrollers []*meshEnroller
	for range 2 {
		e, err := newMeshEnroller(cfg, quietLogger())
		if err != nil {
			t.Fatalf("newMeshEnroller: %v", err)
		}
		enrollers = append(enrollers, e)
	}
	seedPeer(t, api, firstServer, "100.64.0.0/24")

	const joins = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, joins)
	for i := range joins {
		name := fmt.Sprintf("worker-%d", i)
		e := enrollers[i%2]
		wg.Go(func() {
			<-start
			if _, _, err := e.Enroll(context.Background(), name, enrollRequest(name)); err != nil {
				errs <- fmt.Errorf("Enroll %s: %w", name, err)
			}
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.peers) != joins+1 {
		t.Fatalf("stored %d peers, want %d", len(api.peers), joins+1)
	}
	holders := map[string]string{}
	for name, p := range api.peers {
		if other, dup := holders[p.Spec.PodCIDR]; dup {
			t.Errorf("%q and %q both hold %s", other, name, p.Spec.PodCIDR)
		}
		holders[p.Spec.PodCIDR] = name
		if name == firstServer {
			continue
		}
		idx, _ := nodeIndexOf(podnet.ClusterPodCIDR, p.Spec.PodCIDR)
		l := api.leases[meshRangeClaimName(idx)]
		if l == nil || claimHolder(l) != name {
			t.Errorf("%s's range %s has claim %+v, want held by %s", name, p.Spec.PodCIDR, l, name)
		}
	}
}

// TestReserveServerMeshRejectsANonGatewayMeshIP: the member route's range is the
// one install.MeshNodePodCIDR derives, so a mesh IP that is not the .1 of a node
// range is an invalid claim and nothing is written.
func TestReserveServerMeshRejectsANonGatewayMeshIP(t *testing.T) {
	e, api := enrollerOverHandler(t)
	for _, ip := range []string{"100.64.1.7", "192.0.2.1", "not-an-ip"} {
		c := joinedClaim()
		c.MeshIP = ip
		if _, err := e.ReserveServerMesh(context.Background(), joinedServer, c); !errors.Is(err, bootstrap.ErrInvalidMeshClaim) {
			t.Errorf("mesh IP %q: err = %v, want bootstrap.ErrInvalidMeshClaim", ip, err)
		}
	}
	if p, l := api.peerCount(), api.leaseCount(); p != 0 || l != 0 {
		t.Errorf("an invalid claim wrote %d peers and %d claims", p, l)
	}
}

// TestServerMeshClaimCarriesOnlyThePublicKey: the joining server's member request,
// and the MeshPeer the existing server writes from it, carry the wireguard PUBLIC
// key and never the private one.
func TestServerMeshClaimCarriesOnlyThePublicKey(t *testing.T) {
	workDir := t.TempDir()
	priv, pub, err := loadOrCreateServerMeshKey(workDir)
	if err != nil {
		t.Fatalf("mint the mesh key: %v", err)
	}
	id, err := serverMemberIdentity(workDir, joinedMeshIP, "192.0.2.11")
	if err != nil {
		t.Fatalf("serverMemberIdentity: %v", err)
	}
	if id.claim == nil || id.claim.PublicKey != pub || id.claim.Endpoint != "192.0.2.11:51820" || id.claim.MeshIP != joinedMeshIP {
		t.Fatalf("claim = %+v, want the public key, the peer-host endpoint and the mesh IP", id.claim)
	}
	if id.nodePassword == "" {
		t.Error("the member identity carries no node-password")
	}
	body, _ := json.Marshal(bootstrap.EtcdMemberRequest{Name: joinedServer, PeerURL: "https://192.0.2.11:2380", NodePassword: id.nodePassword, MeshClaim: id.claim})
	if strings.Contains(string(body), priv) {
		t.Fatal("the member request carries the private key")
	}

	e, api := enrollerOverHandler(t)
	if _, err := e.ReserveServerMesh(context.Background(), joinedServer, *id.claim); err != nil {
		t.Fatalf("ReserveServerMesh: %v", err)
	}
	stored, _ := json.Marshal(api.peer(joinedServer))
	if strings.Contains(string(stored), priv) {
		t.Fatal("the written MeshPeer carries the private key")
	}

	noMesh, err := serverMemberIdentity(workDir, "", "192.0.2.11")
	if err != nil || noMesh.claim != nil {
		t.Errorf("a server with no --mesh-ip built a claim: %+v, %v", noMesh.claim, err)
	}
}

// TestBackfillClaimsCoversExistingPeers: a cluster whose MeshPeers predate claims
// gets a claim per peer on the next server start, and a /24 two peers share is left
// unclaimed for the operator rather than resolved.
func TestBackfillClaimsCoversExistingPeers(t *testing.T) {
	e, api := enrollerOverHandler(t)
	seedPeer(t, api, firstServer, "100.64.0.0/24")
	seedPeer(t, api, "worker-1", "100.64.1.0/24")
	seedPeer(t, api, "worker-2", "100.64.2.0/24")
	dup := *api.peer("worker-2")
	dup.Name, dup.Spec.NodeName = "worker-3", "worker-3"
	api.mu.Lock()
	api.peers["worker-3"] = &dup
	api.mu.Unlock()

	if err := e.BackfillClaims(context.Background()); err != nil {
		t.Fatalf("BackfillClaims: %v", err)
	}
	for idx, want := range map[int]string{0: firstServer, 1: "worker-1"} {
		if l := api.lease(meshRangeClaimName(idx)); l == nil || claimHolder(l) != want {
			t.Errorf("claim %d = %+v, want held by %s", idx, l, want)
		}
	}
	if l := api.lease(meshRangeClaimName(0)); l.Labels[meshPeerServerLabel] != "true" {
		t.Error("the first server's back-filled claim is not marked as a server's")
	}
	if api.lease(meshRangeClaimName(2)) != nil {
		t.Error("a range two peers share was claimed for one of them")
	}
	if err := e.BackfillClaims(context.Background()); err != nil {
		t.Errorf("a second back-fill is not idempotent: %v", err)
	}
}

// TestDeregisterReleasesTheRangeClaim: a deregistered worker's range is free again —
// its peer AND its claim go — so the next join is handed it.
func TestDeregisterReleasesTheRangeClaim(t *testing.T) {
	ctx := context.Background()
	e, api := enrollerOverHandler(t)
	e.nodes = fake.NewClientset().CoreV1().Nodes()
	if res, _, err := e.Enroll(ctx, "worker-1", enrollRequest("worker-1")); err != nil || res.PodCIDR != "100.64.1.0/24" {
		t.Fatalf("Enroll = (%q, %v)", res.PodCIDR, err)
	}
	if err := e.Deregister(ctx, "worker-1"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if api.lease(meshRangeClaimName(1)) != nil {
		t.Error("the deregistered worker's claim survived")
	}
	if res, _, err := e.Enroll(ctx, "worker-2", enrollRequest("worker-2")); err != nil || res.PodCIDR != "100.64.1.0/24" {
		t.Errorf("the next join got (%q, %v), want the freed 100.64.1.0/24", res.PodCIDR, err)
	}
}

// TestJoinAdvertisesEveryServerAPIEndpoint: a join is answered with this server's
// own apiserver first — the entry an agent takes, so it targets the server it joined
// through, as before — then every other server whose Node is Ready, in address
// order. A worker, and a server whose Node is not Ready, are left out; a list that
// fails answers with this server alone.
func TestJoinAdvertisesEveryServerAPIEndpoint(t *testing.T) {
	ctx := context.Background()
	e, api := enrollerOverHandler(t)
	seedPeer(t, api, firstServer, "100.64.0.0/24")
	for _, s := range []struct{ name, cidr string }{{"laptop", "100.64.1.0/24"}, {"mini", "100.64.10.0/24"}, {"parked", "100.64.2.0/24"}} {
		if _, err := e.EnrollSelf(ctx, s.name, netip.MustParsePrefix(s.cidr), enrollRequest(s.name)); err != nil {
			t.Fatalf("EnrollSelf %s: %v", s.name, err)
		}
	}
	if _, _, err := e.Enroll(ctx, "worker-1", enrollRequest("worker-1")); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	ready := func(_ context.Context, node string) bool { return node != "parked" }

	got := e.serverAPIEndpoints(ctx, firstServer, "100.64.0.1", 6443, ready)
	want := []string{"100.64.0.1:6443", "100.64.1.1:6443", "100.64.10.1:6443"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("apiServers = %v, want %v", got, want)
	}

	broken, _ := newMeshEnroller(stubServer(t, http.NotFoundHandler()), quietLogger())
	if got := broken.serverAPIEndpoints(ctx, firstServer, "100.64.0.1", 6443, ready); !reflect.DeepEqual(got, []string{"100.64.0.1:6443"}) {
		t.Errorf("a failed list answered %v, want this server alone", got)
	}
}
