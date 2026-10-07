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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// The member route's mesh half: the node-password binding of a server's name and
// the reservation of its mesh range, both decided BEFORE any membership change.

// fakeReserver is a ServerMeshReserver: it answers err, and records every call.
type fakeReserver struct {
	mu       sync.Mutex
	err      error
	fresh    bool
	reserved []string
	released []string
	claims   []bootstrap.MeshClaim
}

func (f *fakeReserver) ReserveServerMesh(_ context.Context, nodeName string, claim bootstrap.MeshClaim) (bootstrap.Allocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reserved = append(f.reserved, nodeName)
	f.claims = append(f.claims, claim)
	if f.err != nil {
		return bootstrap.Allocation{}, f.err
	}
	return bootstrap.Allocation{Fresh: f.fresh, EnrollID: "id-" + nodeName, PodCIDR: "100.64.1.0/24"}, nil
}

func (f *fakeReserver) ReleaseServerMesh(_ context.Context, nodeName string, alloc bootstrap.Allocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, nodeName+" "+alloc.EnrollID)
	return nil
}

func (f *fakeReserver) calls() (reserved, released []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reserved), slices.Clone(f.released)
}

// failingAddMembers is fakeMembers whose learner add fails.
type failingAddMembers struct{ *fakeMembers }

func (f failingAddMembers) MemberAddAsLearner(context.Context, string) (bootstrap.EtcdMember, []bootstrap.EtcdMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("add-failed")
	return bootstrap.EtcdMember{}, nil, errors.New("etcdserver: unhealthy cluster")
}

type meshMemberRig struct {
	client      *http.Client
	serverToken string
	passwords   *bootstrap.MemoryNodePasswords
}

// meshRigURL is the base URL the rig's in-process client is pointed at; no socket
// serves it (handlerTransport answers every request in-process).
const meshRigURL = "http://bootstrap.invalid"

// handlerTransport answers every request by calling h directly through a
// recorder: the client helpers run unchanged, the network never does.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

func newMeshMemberRig(t *testing.T, members bootstrap.MemberJoiner, reserver bootstrap.ServerMeshReserver) meshMemberRig {
	t.Helper()
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	passwords := bootstrap.NewMemoryNodePasswords()
	cfg := bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        bootstrap.NewTokenStore(nil),
		NodePasswords: passwords,
		Enroller:      &fakeEnroller{podCIDR: "198.51.100.0/24", meshIP: "198.51.100.11"},
		SelfNodeName:  "server-a",
		ServerAuth:    bootstrap.NewStaticServerSecret(memberTestSecret),
		Members:       members,
		Logger:        slog.New(slog.DiscardHandler),
	}
	if reserver != nil {
		cfg.ServerMesh = reserver
	}
	srv, err := bootstrap.NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return meshMemberRig{
		client:      &http.Client{Transport: handlerTransport{srv.Handler()}},
		serverToken: bootstrap.FormatServerToken(clusterCA.PinHash(), memberTestSecret),
		passwords:   passwords,
	}
}

func (r meshMemberRig) request(req bootstrap.EtcdMemberRequest) (bootstrap.EtcdMemberResponse, error) {
	return bootstrap.RequestEtcdMember(context.Background(), meshRigURL, r.serverToken, req, r.client)
}

// joinerClaim is server-b's claim: its --mesh-ip and an endpoint on its peer host.
func joinerClaim() *bootstrap.MeshClaim {
	return &bootstrap.MeshClaim{MeshIP: "100.64.1.1", PublicKey: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGVzPT0=", Endpoint: "192.0.2.11:51820"}
}

func claimedRequest() bootstrap.EtcdMemberRequest {
	return bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer, NodePassword: "server-b-password", MeshClaim: joinerClaim()}
}

// TestEtcdMemberRouteRefusesAClaimedMeshRangeBeforeMemberAdd: a range another node
// holds is answered 409 with the mesh reason, and the membership is never touched —
// no list, no remove, no learner add — so a conflict never creates a member that
// could cost the existing server its quorum.
func TestEtcdMemberRouteRefusesAClaimedMeshRangeBeforeMemberAdd(t *testing.T) {
	members := &fakeMembers{members: []bootstrap.EtcdMember{serverA}}
	reserver := &fakeReserver{err: errors.Join(bootstrap.ErrMeshRangeClaimed, errors.New("100.64.1.0/24 is held by node \"worker-1\""))}
	rig := newMeshMemberRig(t, members, reserver)

	_, err := rig.request(claimedRequest())
	re, ok := errors.AsType[*bootstrap.ServerRouteError](err)
	if !ok || re.StatusCode != http.StatusConflict || re.Reason != bootstrap.RefusalMeshRangeClaimed {
		t.Fatalf("err = %v, want a 409 with reason %q", err, bootstrap.RefusalMeshRangeClaimed)
	}
	if !bootstrap.IsPermanentServerRouteFailure(err) {
		t.Error("a held range is not classified permanent; the joiner would re-ask forever")
	}
	if calls := members.callLog(); len(calls) != 0 {
		t.Errorf("the membership was touched before the refusal: %v", calls)
	}
	if reserved, _ := reserver.calls(); !slices.Equal(reserved, []string{"server-b"}) {
		t.Errorf("reservations = %v, want one for server-b", reserved)
	}
}

// TestEtcdMemberRouteReservesThenAddsAndAcknowledges: the ordinary claimed join —
// one reservation, then one learner add, and the answer acknowledges the claim.
// The claim carries only the public key: the request body has no private-key
// field, and none is invented.
func TestEtcdMemberRouteReservesThenAddsAndAcknowledges(t *testing.T) {
	members := &fakeMembers{members: []bootstrap.EtcdMember{serverA}}
	reserver := &fakeReserver{fresh: true}
	rig := newMeshMemberRig(t, members, reserver)

	resp, err := rig.request(claimedRequest())
	if err != nil {
		t.Fatalf("RequestEtcdMember: %v", err)
	}
	if resp.MeshClaim != bootstrap.MeshClaimReserved {
		t.Errorf("meshClaim = %q, want %q: a joiner that sent a claim refuses without it", resp.MeshClaim, bootstrap.MeshClaimReserved)
	}
	if calls := members.callLog(); !slices.Equal(calls, []string{"list", "add " + joinerPeer}) {
		t.Errorf("calls = %v, want a list then one learner add", calls)
	}
	if _, released := reserver.calls(); len(released) != 0 {
		t.Errorf("a reservation was released on a successful join: %v", released)
	}
	body, _ := json.Marshal(claimedRequest())
	if strings.Contains(strings.ToLower(string(body)), "private") {
		t.Errorf("the member request carries a private-key field: %s", body)
	}
}

// TestEtcdMemberRouteReleasesTheReservationWhenTheMemberAddFails: a FRESH
// reservation is given back when the learner add after it fails, so the range of a
// server that never joined does not stay reserved.
func TestEtcdMemberRouteReleasesTheReservationWhenTheMemberAddFails(t *testing.T) {
	members := failingAddMembers{&fakeMembers{members: []bootstrap.EtcdMember{serverA}}}
	reserver := &fakeReserver{fresh: true}
	rig := newMeshMemberRig(t, members, reserver)

	_, err := rig.request(claimedRequest())
	if re, ok := errors.AsType[*bootstrap.ServerRouteError](err); !ok || re.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want the add failure's 503", err)
	}
	if _, released := reserver.calls(); !slices.Equal(released, []string{"server-b id-server-b"}) {
		t.Errorf("released = %v, want the fresh reservation given back once", released)
	}

	// A reservation that only RE-ASSERTED an existing row (not fresh) is never
	// released: that row predates this request.
	reserver2 := &fakeReserver{fresh: false}
	rig2 := newMeshMemberRig(t, failingAddMembers{&fakeMembers{members: []bootstrap.EtcdMember{serverA}}}, reserver2)
	_, _ = rig2.request(claimedRequest())
	if _, released := reserver2.calls(); len(released) != 0 {
		t.Errorf("a re-asserted reservation was released: %v", released)
	}
}

// TestEtcdMemberRouteWithoutMeshClaimIsUnchanged: a joiner that predates claims sends
// neither a claim nor a password, and is answered exactly as before — no
// reservation, no binding, no acknowledgement.
func TestEtcdMemberRouteWithoutMeshClaimIsUnchanged(t *testing.T) {
	members := &fakeMembers{members: []bootstrap.EtcdMember{serverA}}
	reserver := &fakeReserver{fresh: true}
	rig := newMeshMemberRig(t, members, reserver)

	resp, err := rig.request(bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer})
	if err != nil {
		t.Fatalf("RequestEtcdMember: %v", err)
	}
	if resp.MeshClaim != "" {
		t.Errorf("meshClaim = %q, want none for a request that made no claim", resp.MeshClaim)
	}
	if calls := members.callLog(); !slices.Equal(calls, []string{"list", "add " + joinerPeer}) {
		t.Errorf("calls = %v, want the unchanged list then learner add", calls)
	}
	if reserved, _ := reserver.calls(); len(reserved) != 0 {
		t.Errorf("a claimless request made a reservation: %v", reserved)
	}
	if err := rig.passwords.Ensure(context.Background(), "server-b", "anything"); err != nil {
		t.Errorf("a claimless request bound the name: %v", err)
	}
}

// TestEtcdMemberRouteRejectsAnInvalidMeshClaim: every claim the route cannot vouch
// for is a 400 with the invalid-claim reason, before any binding, reservation or
// membership change — a mesh IP that names no node range (the reserver's verdict),
// an endpoint off the peer URL's host, a claim with no node-password, and a claim
// sent to a server that runs no reserver.
func TestEtcdMemberRouteRejectsAnInvalidMeshClaim(t *testing.T) {
	cases := []struct {
		name     string
		reserver *fakeReserver
		noMesh   bool
		mutate   func(*bootstrap.EtcdMemberRequest)
	}{
		{name: "a non-gateway mesh IP", reserver: &fakeReserver{err: errors.Join(bootstrap.ErrInvalidMeshClaim, errors.New("100.64.1.7 is a host inside the node pod range"))},
			mutate: func(r *bootstrap.EtcdMemberRequest) { r.MeshClaim.MeshIP = "100.64.1.7" }},
		{name: "an endpoint off the peer host", reserver: &fakeReserver{},
			mutate: func(r *bootstrap.EtcdMemberRequest) { r.MeshClaim.Endpoint = "203.0.113.9:51820" }},
		{name: "no node-password", reserver: &fakeReserver{},
			mutate: func(r *bootstrap.EtcdMemberRequest) { r.NodePassword = "" }},
		{name: "a server with no reserver", noMesh: true, mutate: func(*bootstrap.EtcdMemberRequest) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			members := &fakeMembers{members: []bootstrap.EtcdMember{serverA}}
			var reserver bootstrap.ServerMeshReserver
			if !tc.noMesh {
				reserver = tc.reserver
			}
			rig := newMeshMemberRig(t, members, reserver)
			req := claimedRequest()
			tc.mutate(&req)
			_, err := rig.request(req)
			re, ok := errors.AsType[*bootstrap.ServerRouteError](err)
			if !ok || re.StatusCode != http.StatusBadRequest || re.Reason != bootstrap.RefusalMeshClaimInvalid {
				t.Fatalf("err = %v, want a 400 with reason %q", err, bootstrap.RefusalMeshClaimInvalid)
			}
			if calls := members.callLog(); len(calls) != 0 {
				t.Errorf("the membership was touched: %v", calls)
			}
		})
	}
}

// TestEtcdMemberRouteBindsTheServerName: the member name is bound to the joiner's
// node-password first-write-wins, as /join binds a worker's. A second Mac
// presenting the same server name with another password is refused 403 before the
// reservation or the membership is touched; the original holder's rejoin passes.
func TestEtcdMemberRouteBindsTheServerName(t *testing.T) {
	members := &fakeMembers{members: []bootstrap.EtcdMember{serverA}}
	reserver := &fakeReserver{fresh: true}
	rig := newMeshMemberRig(t, members, reserver)
	if _, err := rig.request(claimedRequest()); err != nil {
		t.Fatalf("first join: %v", err)
	}

	impostor := claimedRequest()
	impostor.NodePassword = "another-mac"
	before := len(members.callLog())
	_, err := rig.request(impostor)
	re, ok := errors.AsType[*bootstrap.ServerRouteError](err)
	if !ok || re.StatusCode != http.StatusForbidden || re.Reason != bootstrap.RefusalNodePassword {
		t.Fatalf("err = %v, want a 403 with reason %q", err, bootstrap.RefusalNodePassword)
	}
	if after := members.callLog(); len(after) != before {
		t.Errorf("the impostor touched the membership: %v", after[before:])
	}
	if reserved, _ := reserver.calls(); len(reserved) != 1 {
		t.Errorf("the impostor reached the reservation: %v", reserved)
	}
	if _, err := rig.request(claimedRequest()); err != nil {
		t.Errorf("the holder's own rejoin was refused: %v", err)
	}
}

// TestEtcdMemberRouteBoundsTheReservation: the reservation runs under its own
// deadline, so a reserver that never answers cannot hold the member lock past it.
func TestEtcdMemberRouteBoundsTheReservation(t *testing.T) {
	var mu sync.Mutex
	var deadline time.Time
	var hadDeadline bool
	reserver := reserverFunc(func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		deadline, hadDeadline = ctx.Deadline()
		return nil
	})
	rig := newMeshMemberRig(t, &fakeMembers{members: []bootstrap.EtcdMember{serverA}}, reserver)
	start := time.Now()
	if _, err := rig.request(claimedRequest()); err != nil {
		t.Fatalf("RequestEtcdMember: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !hadDeadline {
		t.Fatal("the reservation ran with no deadline")
	}
	if d := deadline.Sub(start); d > bootstrap.ServerMeshReserveTimeout+time.Second {
		t.Errorf("the reservation's deadline is %s away, want at most %s", d, bootstrap.ServerMeshReserveTimeout)
	}
}

// reserverFunc is a ServerMeshReserver whose reservation runs f.
type reserverFunc func(ctx context.Context) error

func (f reserverFunc) ReserveServerMesh(ctx context.Context, _ string, _ bootstrap.MeshClaim) (bootstrap.Allocation, error) {
	return bootstrap.Allocation{}, f(ctx)
}

func (f reserverFunc) ReleaseServerMesh(context.Context, string, bootstrap.Allocation) error {
	return nil
}

// TestJoinAnswersWithAPIServersFunc: a join's apiserver list is APIServersFunc's
// answer for that join when it is set, ahead of the static list.
func TestJoinAnswersWithAPIServersFunc(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:      clusterCA,
		SigningCA:      signingCA,
		Tokens:         bootstrap.NewTokenStore(nil),
		NodePasswords:  bootstrap.NewMemoryNodePasswords(),
		Enroller:       &fakeEnroller{},
		APIServers:     []string{"static:6443"},
		APIServersFunc: func(context.Context) []string { return []string{"100.64.0.1:6443", "100.64.1.1:6443"} },
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	got := bootstrap.ServerAPIServersForTest(srv, context.Background())
	if !slices.Equal(got, []string{"100.64.0.1:6443", "100.64.1.1:6443"}) {
		t.Errorf("apiServers = %v, want APIServersFunc's answer", got)
	}
}
