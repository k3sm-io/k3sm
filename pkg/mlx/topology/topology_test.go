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

package topology

import (
	"reflect"
	"testing"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// link adds a symmetric edge a<->b to g, with RDMA at both ends when rdma is set.
func link(g Graph, a, b string, rdma bool) Graph {
	if g.Edges == nil {
		g.Edges = map[string]map[string]Edge{}
	}
	dev := func(node string) string {
		if !rdma {
			return ""
		}
		return "rdma_en" + node
	}
	add := func(x, y string) {
		if g.Edges[x] == nil {
			g.Edges[x] = map[string]Edge{}
		}
		g.Edges[x][y] = Edge{
			LocalIface: "en" + x, LocalRDMA: dev(x),
			PeerIface: "en" + y, PeerRDMA: dev(y),
			SpeedGbps: 40,
		}
	}
	add(a, b)
	add(b, a)
	return g
}

// TestGraphSearches pins the clique and ring searches over hand-built graphs:
// the result lists, their canonical order, and the RDMA requirement.
func TestGraphSearches(t *testing.T) {
	two := link(Graph{}, "a", "b", true)
	threeOneTCP := link(link(link(Graph{}, "a", "b", true), "b", "c", true), "a", "c", false)
	// A 4-cycle a-b-c-d-a with no chords: a ring of 4, no clique of 3 or 4.
	fourRing := link(link(link(link(Graph{}, "a", "b", false), "b", "c", false), "c", "d", false), "d", "a", false)
	// One direction only: not an edge.
	oneWay := Graph{Edges: map[string]map[string]Edge{"a": {"b": {LocalIface: "en1"}}}}

	cases := []struct {
		name        string
		g           Graph
		n           int
		requireRDMA bool
		wantClique  [][]string
		wantRing    [][]string
	}{
		{name: "2-clique", g: two, n: 2, requireRDMA: true,
			wantClique: [][]string{{"a", "b"}}, wantRing: [][]string{{"a", "b"}}},
		{name: "2-clique_size_3_absent", g: two, n: 3, requireRDMA: false},
		{name: "3-clique_tcp", g: threeOneTCP, n: 3, requireRDMA: false,
			wantClique: [][]string{{"a", "b", "c"}}, wantRing: [][]string{{"a", "b", "c"}}},
		{name: "3-clique_one_non_rdma_edge_is_no_rdma_clique", g: threeOneTCP, n: 3, requireRDMA: true,
			wantRing: [][]string{{"a", "b", "c"}}},
		{name: "3-clique_rdma_pairs", g: threeOneTCP, n: 2, requireRDMA: true,
			wantClique: [][]string{{"a", "b"}, {"b", "c"}},
			wantRing:   [][]string{{"a", "b"}, {"a", "c"}, {"b", "c"}}},
		{name: "4-ring_without_clique_n4", g: fourRing, n: 4,
			wantRing: [][]string{{"a", "b", "c", "d"}}},
		{name: "4-ring_without_clique_n3", g: fourRing, n: 3},
		{name: "no_edges", g: Graph{}, n: 2},
		{name: "one_direction_only", g: oneWay, n: 2},
		{name: "n_below_two", g: two, n: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.Clique(tc.n, tc.requireRDMA); !reflect.DeepEqual(got, tc.wantClique) {
				t.Errorf("Clique(%d, %v) = %v, want %v", tc.n, tc.requireRDMA, got, tc.wantClique)
			}
			if got := tc.g.Ring(tc.n); !reflect.DeepEqual(got, tc.wantRing) {
				t.Errorf("Ring(%d) = %v, want %v", tc.n, got, tc.wantRing)
			}
		})
	}
}

// TestRingIsDeterministic re-runs the ring search many times: map iteration
// order must never leak into the answer.
func TestRingIsDeterministic(t *testing.T) {
	g := link(link(link(link(link(Graph{}, "n1", "n2", false), "n2", "n3", false), "n3", "n4", false), "n4", "n1", false), "n1", "n3", false)
	first := g.Ring(4)
	firstClique := g.Clique(3, false)
	for i := 0; i < 50; i++ {
		if got := g.Ring(4); !reflect.DeepEqual(got, first) {
			t.Fatalf("Ring(4) run %d = %v, want %v", i, got, first)
		}
		if got := g.Clique(3, false); !reflect.DeepEqual(got, firstClique) {
			t.Fatalf("Clique(3) run %d = %v, want %v", i, got, firstClique)
		}
	}
	if want := [][]string{{"n1", "n2", "n3", "n4"}}; !reflect.DeepEqual(first, want) {
		t.Errorf("Ring(4) = %v, want %v", first, want)
	}
	if want := [][]string{{"n1", "n2", "n3"}, {"n1", "n3", "n4"}}; !reflect.DeepEqual(firstClique, want) {
		t.Errorf("Clique(3) = %v, want %v", firstClique, want)
	}
}

// directLink builds one node's DirectLink with the given spec ports and
// resolved status ports.
func directLink(node string, spec []netv1alpha1.DirectLinkPort, status []netv1alpha1.DirectLinkPortStatus) netv1alpha1.DirectLink {
	dl := netv1alpha1.DirectLink{}
	dl.Name = node
	dl.Spec = netv1alpha1.DirectLinkSpec{SchemaVersion: 1, NodeName: node, Medium: netv1alpha1.MediumThunderbolt, Ports: spec}
	dl.Status = netv1alpha1.DirectLinkStatus{Ports: status}
	return dl
}

// TestFromDirectLinks pins the status-to-graph join: only up ports with a named
// peer become edges, the local end comes from the spec port of the same
// interface, a one-sided up is dropped, and parallel cables resolve to the
// fastest.
func TestFromDirectLinks(t *testing.T) {
	up := netv1alpha1.DirectLinkStateUp
	links := []netv1alpha1.DirectLink{
		directLink("studio",
			[]netv1alpha1.DirectLinkPort{
				{Iface: "en2", DomainUUID: "s2", PeerDomainUUID: "b1", SpeedGbps: 40, RDMADevice: "rdma_en2", LinkIP: "169.254.0.2"},
				{Iface: "en3", DomainUUID: "s3", PeerDomainUUID: "b2", SpeedGbps: 20, LinkIP: "169.254.0.3"},
				{Iface: "en4", DomainUUID: "s4", PeerDomainUUID: "x1", SpeedGbps: 40},
				{Iface: "en5", DomainUUID: "s5", PeerDomainUUID: "c1", SpeedGbps: 40},
			},
			[]netv1alpha1.DirectLinkPortStatus{
				{Iface: "en2", PeerNodeName: "book", PeerIface: "en1", PeerLinkIP: "169.254.255.1", PeerRDMADevice: "rdma_en1", State: up},
				{Iface: "en3", PeerNodeName: "book", PeerIface: "en7", PeerLinkIP: "169.254.255.7", State: up},
				{Iface: "en4", State: netv1alpha1.DirectLinkStatePeerUnknown},
				{Iface: "en5", PeerNodeName: "mini", PeerIface: "en1", State: up},
			}),
		directLink("book",
			[]netv1alpha1.DirectLinkPort{
				{Iface: "en1", DomainUUID: "b1", PeerDomainUUID: "s2", SpeedGbps: 40, RDMADevice: "rdma_en1", LinkIP: "169.254.255.1"},
				{Iface: "en7", DomainUUID: "b2", PeerDomainUUID: "s3", SpeedGbps: 20, LinkIP: "169.254.255.7"},
			},
			[]netv1alpha1.DirectLinkPortStatus{
				{Iface: "en1", PeerNodeName: "studio", PeerIface: "en2", PeerLinkIP: "169.254.0.2", PeerRDMADevice: "rdma_en2", State: up},
				{Iface: "en7", PeerNodeName: "studio", PeerIface: "en3", PeerLinkIP: "169.254.0.3", State: netv1alpha1.DirectLinkStateDown},
			}),
		// mini reports its side down, so studio->mini is one-sided and dropped.
		directLink("mini",
			[]netv1alpha1.DirectLinkPort{{Iface: "en1", DomainUUID: "c1", PeerDomainUUID: "s5"}},
			[]netv1alpha1.DirectLinkPortStatus{{Iface: "en1", PeerNodeName: "studio", State: netv1alpha1.DirectLinkStateDown}}),
	}
	g := FromDirectLinks(links)
	want := Graph{Edges: map[string]map[string]Edge{
		"studio": {"book": {LocalIface: "en2", LocalRDMA: "rdma_en2", LocalIP: "169.254.0.2", PeerIface: "en1", PeerRDMA: "rdma_en1", PeerIP: "169.254.255.1", SpeedGbps: 40}},
		"book":   {"studio": {LocalIface: "en1", LocalRDMA: "rdma_en1", LocalIP: "169.254.255.1", PeerIface: "en2", PeerRDMA: "rdma_en2", PeerIP: "169.254.0.2", SpeedGbps: 40}},
	}}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("FromDirectLinks() =\n%#v\nwant\n%#v", g, want)
	}
	if got := g.Clique(2, true); !reflect.DeepEqual(got, [][]string{{"book", "studio"}}) {
		t.Errorf("Clique(2, rdma) = %v, want [[book studio]]", got)
	}
	if got := FromDirectLinks(nil); len(got.Edges) != 0 {
		t.Errorf("FromDirectLinks(nil) has %d nodes, want 0", len(got.Edges))
	}
}
