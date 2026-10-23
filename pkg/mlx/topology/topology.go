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

// Package topology is the MLX operator's view of the interconnect: which
// cluster nodes can reach each other over an up interconnect segment, and the
// deterministic searches sharded placement runs over that graph.
//
// It is a CONSUMER-side value type. The server's interconnect resolver owns the
// Interconnect object and its status; this package only reads the resolved
// status (FromInterconnect) into a plain graph, so placement and its tests work
// on hand-built graphs with no API server behind them.
//
// A bridged interconnect segment is one L2 domain: every member reaches every
// other member directly. FromInterconnect therefore makes each segment a
// clique, and Ring and Clique keep working over it unchanged.
//
// The searches are brute force on purpose. A cable graph between Macs has a
// handful of nodes (n <= 5 ranks in practice), so enumerating every subset and
// every ordering is a few hundred steps, and a brute-force search is one whose
// determinism and completeness can be read off the code.
package topology

import (
	"slices"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// Edge is one direction of an up link: the local end on the node that keys it,
// and the far end on the peer it points to.
type Edge struct {
	// Segment is the interconnect segment both ends are up in, or empty for a
	// hand-built edge.
	Segment string
	// LocalRDMA is the local RDMA device on the link ("rdma_en2"), or empty.
	// The Interconnect status carries no RDMA device, so FromInterconnect
	// leaves it empty: jaccl over a bridged segment is not yet verified on
	// hardware: whether RDMA enumerates on bridged ports is unknown.
	LocalRDMA string
	// PeerRDMA is the peer's RDMA device at the far end, or empty.
	PeerRDMA string
}

// RDMA reports whether both ends of the link carry an RDMA device.
func (e Edge) RDMA() bool { return e.LocalRDMA != "" && e.PeerRDMA != "" }

// Graph is the up-link graph: Edges[node][peer] is the link node uses to reach
// peer. A graph built by FromInterconnect is symmetric; a hand-built graph is
// read as given, and the searches below treat a pair as connected only when
// BOTH directions exist.
type Graph struct {
	Edges map[string]map[string]Edge
}

// Edge returns the link from node to peer, if both directions exist.
func (g Graph) Edge(node, peer string) (Edge, bool) {
	e, ok := g.Edges[node][peer]
	if !ok {
		return Edge{}, false
	}
	if _, back := g.Edges[peer][node]; !back {
		return Edge{}, false
	}
	return e, true
}

// connected reports whether node and peer are joined in both directions, and,
// when requireRDMA is set, whether both directions carry RDMA at both ends.
func (g Graph) connected(node, peer string, requireRDMA bool) bool {
	e, ok := g.Edge(node, peer)
	if !ok {
		return false
	}
	if !requireRDMA {
		return true
	}
	back := g.Edges[peer][node]
	return e.RDMA() && back.RDMA()
}

// Nodes returns every node named in the graph, as a key or as a peer, sorted.
func (g Graph) Nodes() []string {
	set := map[string]struct{}{}
	for n, peers := range g.Edges {
		set[n] = struct{}{}
		for p := range peers {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Clique returns every set of n nodes in which every pair is joined by an up
// link (with RDMA at both ends of every link when requireRDMA is set). Each
// clique is sorted by node name and the list is in lexicographic order, so the
// first entry is the same answer on every call. n < 2 returns nil: a single
// node is not a sharded placement.
func (g Graph) Clique(n int, requireRDMA bool) [][]string {
	if n < 2 {
		return nil
	}
	var out [][]string
	nodes := g.Nodes()
	combinations(nodes, n, func(set []string) {
		for i := range set {
			for j := i + 1; j < len(set); j++ {
				if !g.connected(set[i], set[j], requireRDMA) {
					return
				}
			}
		}
		out = append(out, slices.Clone(set))
	})
	return out
}

// Ring returns every cycle through n distinct nodes in which each hop, including
// the hop from the last node back to the first, is an up link. A two-node ring
// is a single link (the cycle a-b-a).
//
// Each cycle is reported once, in canonical form: it starts at its
// lexicographically smallest node, and of its two directions the one whose
// second node is smaller is kept. The list is in lexicographic order. n < 2
// returns nil.
func (g Graph) Ring(n int) [][]string {
	if n < 2 {
		return nil
	}
	var out [][]string
	nodes := g.Nodes()
	combinations(nodes, n, func(set []string) {
		// set is sorted, so set[0] is the smallest node: fix it as the start and
		// permute the rest. That removes the rotations; the direction filter
		// below removes the reflections.
		permutations(set[1:], func(rest []string) {
			if n > 2 && rest[0] > rest[len(rest)-1] {
				return
			}
			cycle := append([]string{set[0]}, rest...)
			for i := range cycle {
				if !g.connected(cycle[i], cycle[(i+1)%len(cycle)], false) {
					return
				}
			}
			out = append(out, cycle)
		})
	})
	slices.SortFunc(out, slices.Compare)
	return out
}

// combinations calls fn with every k-subset of sorted items, in lexicographic
// order. fn must not retain its argument.
func combinations(items []string, k int, fn func([]string)) {
	if k > len(items) {
		return
	}
	set := make([]string, 0, k)
	var rec func(start int)
	rec = func(start int) {
		if len(set) == k {
			fn(set)
			return
		}
		for i := start; i <= len(items)-(k-len(set)); i++ {
			set = append(set, items[i])
			rec(i + 1)
			set = set[:len(set)-1]
		}
	}
	rec(0)
}

// permutations calls fn with every ordering of items (Heap's algorithm over a
// copy). fn receives a fresh slice it may retain.
func permutations(items []string, fn func([]string)) {
	a := slices.Clone(items)
	var rec func(k int)
	rec = func(k int) {
		if k <= 1 {
			fn(slices.Clone(a))
			return
		}
		for i := 0; i < k; i++ {
			rec(k - 1)
			if k%2 == 0 {
				a[i], a[k-1] = a[k-1], a[i]
			} else {
				a[0], a[k-1] = a[k-1], a[0]
			}
		}
	}
	rec(len(a))
}

// FromInterconnect builds the up-link graph from the resolver-written
// Interconnect status: every pair of members that are up in the same segment is
// joined in both directions, so each segment is a clique. A nil or disabled
// Interconnect has no links (nothing holds an address on an unarmed cable), and
// a member that is down, in a loop, unsegmented or excluded joins nothing. A
// node listed twice keeps its first entry, so a malformed status can never join
// two segments through one node.
func FromInterconnect(ic *netv1alpha1.Interconnect) Graph {
	g := Graph{Edges: map[string]map[string]Edge{}}
	if ic == nil || !ic.Spec.Enabled {
		return g
	}
	excluded := make(map[string]bool, len(ic.Spec.ExcludedNodes))
	for _, n := range ic.Spec.ExcludedNodes {
		excluded[n] = true
	}
	seen := map[string]bool{}
	bySegment := map[string][]string{}
	for _, m := range ic.Status.Members {
		if m.Node == "" || seen[m.Node] {
			continue
		}
		seen[m.Node] = true
		if m.State != netv1alpha1.InterconnectMemberUp || m.Segment == "" || excluded[m.Node] {
			continue
		}
		bySegment[m.Segment] = append(bySegment[m.Segment], m.Node)
	}
	for seg, nodes := range bySegment {
		for _, a := range nodes {
			for _, b := range nodes {
				if a == b {
					continue
				}
				if g.Edges[a] == nil {
					g.Edges[a] = map[string]Edge{}
				}
				g.Edges[a][b] = Edge{Segment: seg}
			}
		}
	}
	return g
}
