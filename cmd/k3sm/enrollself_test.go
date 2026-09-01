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
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/podnet"
)

// This file is M14.2 d3's unit tier: the control-plane node's own index-0 enroll,
// and the worker index assignment that had to be corrected in the same change.
//
// The two are one defect, not two. `EnrollSelf` makes index 0 an OCCUPIED slot for
// the first time; the worker allocator was a `len(existing)+1` counter, which is
// only ever right while no peer exists at index 0. With the server enrolled, that
// counter hands the first worker index 2 (skipping 1 forever) and the second
// worker index 3 — an allocator whose answers depend on how many peers exist
// rather than which indices are taken.

// testPubKey is a syntactically valid base64 wireguard public key. The enroller
// never decodes it (only the wireguard device does), so a fixed literal keeps the
// tests independent of key generation.
const testPubKey = "dGVzdC1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGVzPT0="

// seedPeer inserts a MeshPeer directly into the stub, standing in for state a
// previous enroll left behind.
func seedPeer(t *testing.T, api *meshPeerAPIStub, nodeName, podCIDR string) {
	t.Helper()
	prefix, err := netip.ParsePrefix(podCIDR)
	if err != nil {
		t.Fatalf("seed %q: %v", podCIDR, err)
	}
	meshIP, err := podnet.MeshEgressIP(prefix)
	if err != nil {
		t.Fatalf("seed %q: %v", podCIDR, err)
	}
	peer := &netv1.MeshPeer{Spec: netv1.MeshPeerSpec{
		NodeName:   nodeName,
		PublicKey:  testPubKey,
		Endpoint:   "192.0.2.1:51820",
		PodCIDR:    podCIDR,
		AllowedIPs: []string{podCIDR},
		MeshIP:     meshIP.String(),
	}.WithDefaults()}
	peer.Name = nodeName
	peer.Kind = "MeshPeer"
	peer.APIVersion = netv1.SchemeGroupVersion.String()
	api.mu.Lock()
	defer api.mu.Unlock()
	api.peers[nodeName] = peer
}

// enrollerOverStub wires a real meshEnroller to a stub apiserver.
func enrollerOverStub(t *testing.T) (*meshEnroller, *meshPeerAPIStub) {
	t.Helper()
	api := newMeshPeerAPIStub()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	e, err := newMeshEnroller(&rest.Config{Host: srv.URL}, quietLogger())
	if err != nil {
		t.Fatalf("newMeshEnroller: %v", err)
	}
	return e, api
}

func enrollRequest(node string) netv1.MeshEnrollRequest {
	return netv1.MeshEnrollRequest{NodeName: node, PublicKey: testPubKey, Endpoint: "192.0.2.9:51820"}
}

// TestNodeIndexOf pins the inverse of podnet.NodeCIDR — the derivation the
// allocator reads existing peers through. Everything it cannot vouch for (a
// malformed CIDR, a prefix that is not a /24, an address outside the cluster
// range) must report "not an index" rather than a number, because a wrong number
// silently marks the wrong slot occupied.
func TestNodeIndexOf(t *testing.T) {
	cluster := podnet.ClusterPodCIDR
	cases := []struct {
		name    string
		podCIDR string
		want    int
		wantOK  bool
	}{
		{"the control-plane carve", "100.64.0.0/24", 0, true},
		{"the first worker carve", "100.64.1.0/24", 1, true},
		{"a high carve", "100.64.9.0/24", 9, true},
		{"across the third octet", "100.65.0.0/24", 256, true},
		{"an unmasked address inside its own /24", "100.64.3.7/24", 3, true},
		{"outside the cluster CIDR", "10.0.1.0/24", 0, false},
		{"not a /24", "100.64.1.0/25", 0, false},
		{"unparsable", "not-a-cidr", 0, false},
		{"empty", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nodeIndexOf(cluster, tc.podCIDR)
			if ok != tc.wantOK {
				t.Fatalf("nodeIndexOf(%q) ok = %v, want %v", tc.podCIDR, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("nodeIndexOf(%q) = %d, want %d", tc.podCIDR, got, tc.want)
			}
		})
	}
}

// TestLowestFreeNodeIndex is the allocator table. Every case states which indices
// are OCCUPIED and what the next assignment must be — the property the replaced
// counter could not express.
func TestLowestFreeNodeIndex(t *testing.T) {
	cluster := podnet.ClusterPodCIDR
	specs := func(cidrs ...string) []netv1.MeshPeerSpec {
		out := make([]netv1.MeshPeerSpec, 0, len(cidrs))
		for i, c := range cidrs {
			out = append(out, netv1.MeshPeerSpec{NodeName: fmt.Sprintf("n%d", i), PodCIDR: c})
		}
		return out
	}
	cases := []struct {
		name     string
		existing []netv1.MeshPeerSpec
		want     int
	}{
		{"no peers at all", nil, 1},
		{"only the control-plane node", specs("100.64.0.0/24"), 1},
		{"control plane plus one worker", specs("100.64.0.0/24", "100.64.1.0/24"), 2},
		{"a worker without the control plane", specs("100.64.1.0/24"), 2},
		{"a hole left by a deleted node is reused", specs("100.64.0.0/24", "100.64.2.0/24"), 1},
		{"a hole in the middle is reused", specs("100.64.0.0/24", "100.64.1.0/24", "100.64.3.0/24"), 2},
		{"out-of-order peers", specs("100.64.3.0/24", "100.64.1.0/24", "100.64.0.0/24"), 2},
		{"an unparsable peer never shifts the numbering", specs("100.64.0.0/24", "garbage"), 1},
		{"a foreign-CIDR peer never shifts the numbering", specs("100.64.0.0/24", "10.1.2.0/24"), 1},
		{"a duplicate claim counts once", specs("100.64.0.0/24", "100.64.1.0/24", "100.64.1.0/24"), 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := lowestFreeNodeIndex(cluster, tc.existing)
			if err != nil {
				t.Fatalf("lowestFreeNodeIndex: %v", err)
			}
			if got != tc.want {
				t.Errorf("lowestFreeNodeIndex = %d, want %d", got, tc.want)
			}
			if got == serverNodeIndex {
				t.Errorf("lowestFreeNodeIndex returned the reserved control-plane index %d", serverNodeIndex)
			}
		})
	}
}

// TestLowestFreeNodeIndexExhaustsClosed pins the bound: a cluster CIDR with room
// for exactly two /24s and both taken must ERROR rather than hand out an index
// podnet.NodeCIDR would reject.
func TestLowestFreeNodeIndexExhaustsClosed(t *testing.T) {
	small := netip.MustParsePrefix("100.64.0.0/23")
	existing := []netv1.MeshPeerSpec{
		{NodeName: "cp", PodCIDR: "100.64.0.0/24"},
		{NodeName: "w1", PodCIDR: "100.64.1.0/24"},
	}
	if got, err := lowestFreeNodeIndex(small, existing); err == nil {
		t.Fatalf("lowestFreeNodeIndex returned index %d for an exhausted %s, want an error", got, small)
	}
}

// TestEnrollAssignsLowestFreeIndexAboveZero is the RED-WITHOUT-FIX leg for the
// allocator: it drives the real enroller against a stub whose state already holds
// the control-plane node's index-0 peer, exactly as it does once EnrollSelf runs.
//
// Against the replaced `len(existing)+1` counter the first worker is assigned
// 100.64.2.0/24 and the second 100.64.3.0/24 — index 1 is skipped permanently, and
// the numbering drifts further with every join.
func TestEnrollAssignsLowestFreeIndexAboveZero(t *testing.T) {
	e, api := enrollerOverStub(t)
	seedPeer(t, api, "k3sm-server", "100.64.0.0/24")

	first, err := e.Enroll(context.Background(), "worker-a", enrollRequest("worker-a"))
	if err != nil {
		t.Fatalf("first worker Enroll: %v", err)
	}
	if first.PodCIDR != "100.64.1.0/24" {
		t.Errorf("first worker podCIDR = %q, want 100.64.1.0/24 (the lowest free index above the control-plane node)", first.PodCIDR)
	}
	if first.MeshIP != "100.64.1.1" {
		t.Errorf("first worker meshIP = %q, want 100.64.1.1", first.MeshIP)
	}

	second, err := e.Enroll(context.Background(), "worker-b", enrollRequest("worker-b"))
	if err != nil {
		t.Fatalf("second worker Enroll: %v", err)
	}
	if second.PodCIDR != "100.64.2.0/24" {
		t.Errorf("second worker podCIDR = %q, want 100.64.2.0/24", second.PodCIDR)
	}

	// A worker deleted and re-joined must RECLAIM the hole, not extend the range.
	api.mu.Lock()
	delete(api.peers, "worker-a")
	api.mu.Unlock()
	third, err := e.Enroll(context.Background(), "worker-c", enrollRequest("worker-c"))
	if err != nil {
		t.Fatalf("third worker Enroll: %v", err)
	}
	if third.PodCIDR != "100.64.1.0/24" {
		t.Errorf("third worker podCIDR = %q, want the reclaimed 100.64.1.0/24", third.PodCIDR)
	}
}

// TestEnrollSelfPinsIndexZero: the control-plane node claims index 0 explicitly,
// never through the free-index scanner, and re-enrolling is an in-place update.
func TestEnrollSelfPinsIndexZero(t *testing.T) {
	e, api := enrollerOverStub(t)

	res, err := e.EnrollSelf(context.Background(), "k3sm-server", enrollRequest("k3sm-server"))
	if err != nil {
		t.Fatalf("EnrollSelf: %v", err)
	}
	if res.PodCIDR != "100.64.0.0/24" {
		t.Errorf("self podCIDR = %q, want the pinned index-0 carve 100.64.0.0/24", res.PodCIDR)
	}
	if res.MeshIP != "100.64.0.1" {
		t.Errorf("self meshIP = %q, want 100.64.0.1", res.MeshIP)
	}
	if res.PodCIDR != defaultNodePodCIDR() {
		t.Errorf("self podCIDR %q != defaultNodePodCIDR() %q — the mesh would route a different /24 than this node's pods use",
			res.PodCIDR, defaultNodePodCIDR())
	}
	if len(res.Peers) != 1 || res.Peers[0].NodeName != "k3sm-server" {
		t.Fatalf("EnrollSelf returned peers %+v, want the one just written", res.Peers)
	}
	stored := api.peer("k3sm-server")
	if stored == nil {
		t.Fatal("no MeshPeer named k3sm-server after EnrollSelf")
	}
	if stored.Spec.PublicKey == "" {
		t.Error("the written MeshPeer carries no publicKey; peers would have nothing to program")
	}
	if len(stored.Spec.AllowedIPs) != 1 || stored.Spec.AllowedIPs[0] != "100.64.0.0/24" {
		t.Errorf("written allowedIPs = %v, want the symmetric [100.64.0.0/24]", stored.Spec.AllowedIPs)
	}
	if api.creates != 1 || api.updates != 0 {
		t.Errorf("EnrollSelf issued %d creates / %d updates, want 1/0", api.creates, api.updates)
	}

	// Rejoin (a launchd kickstart): same index, an in-place update, no duplicate.
	req := enrollRequest("k3sm-server")
	req.Endpoint = "192.0.2.77:51820"
	again, err := e.EnrollSelf(context.Background(), "k3sm-server", req)
	if err != nil {
		t.Fatalf("EnrollSelf rejoin: %v", err)
	}
	if again.PodCIDR != res.PodCIDR {
		t.Errorf("rejoin podCIDR = %q, want the pinned %q", again.PodCIDR, res.PodCIDR)
	}
	if api.updates != 1 {
		t.Errorf("rejoin issued %d updates, want 1", api.updates)
	}
	if stored := api.peer("k3sm-server"); stored == nil || stored.Spec.Endpoint != "192.0.2.77:51820" {
		t.Errorf("rejoin did not update the stored endpoint: %+v", stored)
	}
}

// TestEnrollSelfFailsClosedOnAForeignIndexZeroClaim: taking the slot silently
// would rewrite a live peer's AllowedIPs out from under it, so a foreign claim on
// index 0 halts the enroll with a named error.
func TestEnrollSelfFailsClosedOnAForeignIndexZeroClaim(t *testing.T) {
	e, api := enrollerOverStub(t)
	seedPeer(t, api, "some-other-node", "100.64.0.0/24")

	_, err := e.EnrollSelf(context.Background(), "k3sm-server", enrollRequest("k3sm-server"))
	if err == nil {
		t.Fatal("EnrollSelf overwrote a foreign index-0 claim; it must fail closed")
	}
	if !errors.Is(err, ErrMeshIndexClaimed) {
		t.Errorf("EnrollSelf error = %v, want one wrapping ErrMeshIndexClaimed", err)
	}
	if api.creates != 0 || api.updates != 0 {
		t.Errorf("EnrollSelf wrote to the apiserver (%d creates / %d updates) despite the foreign claim", api.creates, api.updates)
	}
	if stored := api.peer("some-other-node"); stored == nil || stored.Spec.NodeName != "some-other-node" {
		t.Error("the foreign index-0 peer was disturbed")
	}
}

// TestEnrollSelfRequiresTheWriteToReadBack is the list-back verification, which is
// the whole basis of the happens-before the caller relies on. An apiserver that
// accepts the write and does not serve it back must NOT be reported as a durable
// index-0 claim — otherwise the caller opens the join listener over a claim that
// does not exist.
func TestEnrollSelfRequiresTheWriteToReadBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Always an EMPTY list: the write never reads back.
			writeJSON(w, http.StatusOK, netv1.MeshPeerList{
				TypeMeta: metav1.TypeMeta{APIVersion: netv1.SchemeGroupVersion.String(), Kind: "MeshPeerList"},
			})
		case http.MethodPost:
			var in netv1.MeshPeer
			_ = json.NewDecoder(r.Body).Decode(&in)
			writeJSON(w, http.StatusCreated, &in)
		default:
			writeStatus(w, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	e, err := newMeshEnroller(&rest.Config{Host: srv.URL}, quietLogger())
	if err != nil {
		t.Fatalf("newMeshEnroller: %v", err)
	}
	if _, err := e.EnrollSelf(context.Background(), "k3sm-server", enrollRequest("k3sm-server")); err == nil {
		t.Fatal("EnrollSelf reported success without reading its own write back")
	}
}

// TestSelfEnrollRacesConcurrentJoinsWithoutSharingAnIndex is the d4 race test.
//
// It runs the server's own enroll CONCURRENTLY with a burst of simulated worker
// joins through the SAME enroller instance — the two-actor race the ordering
// requirement exists to make impossible. Two properties must hold no matter how
// the goroutines interleave:
//
//   - no two nodes are assigned the same /24 (the mutex serializes assign→write);
//   - the control-plane node holds index 0 and NO worker does (EnrollSelf pins it
//     and the worker allocator starts at 1).
//
// The second is the one that fails if a future change lets the free-index scanner
// serve the server path: index 0 becomes assignable, two peers claim one
// AllowedIPs, and wireguard admits neither. Run under -race, it is also the
// detector for any unsynchronized state the two entry points come to share.
func TestSelfEnrollRacesConcurrentJoinsWithoutSharingAnIndex(t *testing.T) {
	e, api := enrollerOverStub(t)

	const workers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, workers+1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := e.EnrollSelf(context.Background(), "k3sm-server", enrollRequest("k3sm-server")); err != nil {
			errs <- fmt.Errorf("EnrollSelf: %w", err)
		}
	}()
	for i := 0; i < workers; i++ {
		name := fmt.Sprintf("worker-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := e.Enroll(context.Background(), name, enrollRequest(name)); err != nil {
				errs <- fmt.Errorf("Enroll %s: %w", name, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent enroll: %v", err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.peers) != workers+1 {
		t.Fatalf("stored %d peers, want %d (one per node)", len(api.peers), workers+1)
	}
	byCIDR := map[string]string{}
	for name, p := range api.peers {
		if other, dup := byCIDR[p.Spec.PodCIDR]; dup {
			t.Errorf("nodes %q and %q both claim %s — two peers on one AllowedIPs", other, name, p.Spec.PodCIDR)
		}
		byCIDR[p.Spec.PodCIDR] = name
		idx, ok := nodeIndexOf(podnet.ClusterPodCIDR, p.Spec.PodCIDR)
		if !ok {
			t.Errorf("node %q was assigned %q, which is not a node index of %s", name, p.Spec.PodCIDR, podnet.ClusterPodCIDR)
			continue
		}
		if idx == serverNodeIndex && name != "k3sm-server" {
			t.Errorf("worker %q was assigned the control-plane index %d (%s)", name, serverNodeIndex, p.Spec.PodCIDR)
		}
		if idx != serverNodeIndex && name == "k3sm-server" {
			t.Errorf("the control-plane node was assigned index %d (%s), not the pinned %d", idx, p.Spec.PodCIDR, serverNodeIndex)
		}
	}
}
