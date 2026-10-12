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
		g.Edges[x][y] = Edge{LocalRDMA: dev(x), PeerRDMA: dev(y)}
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
	oneWay := Graph{Edges: map[string]map[string]Edge{"a": {"b": {Segment: "seg-0"}}}}

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

// member is one Interconnect status member.
func member(node string, state netv1alpha1.InterconnectMemberState, segment string) netv1alpha1.InterconnectMember {
	return netv1alpha1.InterconnectMember{Node: node, State: state, Segment: segment}
}

// TestFromInterconnect pins the status-to-graph join: members up in one
// segment form a clique, two segments never join, and a down, looped,
// unsegmented, excluded or repeated member joins nothing; a nil or disabled
// Interconnect has no links.
func TestFromInterconnect(t *testing.T) {
	up, down, loop := netv1alpha1.InterconnectMemberUp, netv1alpha1.InterconnectMemberDown, netv1alpha1.InterconnectMemberLoop
	ic := &netv1alpha1.Interconnect{
		Spec: netv1alpha1.InterconnectSpec{Medium: netv1alpha1.MediumThunderbolt, Enabled: true, ExcludedNodes: []string{"banned"}},
		Status: netv1alpha1.InterconnectStatus{Members: []netv1alpha1.InterconnectMember{
			member("a", up, "seg-0"), member("b", up, "seg-0"), member("c", up, "seg-0"),
			member("x", up, "seg-1"), member("y", up, "seg-1"),
			member("dead", down, "seg-0"), member("looped", loop, "seg-0"), member("lonely", up, ""),
			member("banned", up, "seg-0"),
			// A repeated node keeps its first entry and never bridges seg-0 to seg-1.
			member("a", up, "seg-1"),
		}},
	}
	g := FromInterconnect(ic)
	if got, want := g.Nodes(), []string{"a", "b", "c", "x", "y"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Nodes() = %v, want %v", got, want)
	}
	if got, want := g.Clique(3, false), [][]string{{"a", "b", "c"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Clique(3) = %v, want %v", got, want)
	}
	if got, want := g.Clique(2, false), [][]string{{"a", "b"}, {"a", "c"}, {"b", "c"}, {"x", "y"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Clique(2) = %v, want %v", got, want)
	}
	if got, want := g.Ring(3), [][]string{{"a", "b", "c"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Ring(3) = %v, want %v (a segment is a clique)", got, want)
	}
	if e, ok := g.Edge("a", "c"); !ok || e.Segment != "seg-0" || e.RDMA() {
		t.Errorf("edge a->c = %+v, %v; want seg-0 without rdma", e, ok)
	}
	if _, ok := g.Edge("a", "x"); ok {
		t.Error("two segments are joined")
	}
	if got := g.Clique(2, true); got != nil {
		t.Errorf("Clique(2, rdma) = %v; the interconnect carries no rdma device", got)
	}

	disabled := ic.DeepCopy()
	disabled.Spec.Enabled = false
	for name, in := range map[string]*netv1alpha1.Interconnect{"nil": nil, "disabled": disabled} {
		if got := FromInterconnect(in); len(got.Edges) != 0 {
			t.Errorf("FromInterconnect(%s) has %d nodes, want 0", name, len(got.Edges))
		}
	}
}
