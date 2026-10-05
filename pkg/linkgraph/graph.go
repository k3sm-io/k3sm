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

package linkgraph

import (
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// Edge is one up cable between two nodes, seen from the first.
type Edge struct {
	LocalIface string
	LocalRDMA  string
	LocalIP    string
	PeerIface  string
	PeerRDMA   string
	PeerIP     string
	SpeedGbps  int32
}

// Graph is the cluster's cable graph: Edges[node][peer] exists iff BOTH nodes'
// statuses report a cable between them up. With several cables between one pair,
// the edge is the one on the lowest local interface name, so the choice is
// stable.
type Graph struct {
	Edges map[string]map[string]Edge
}

// BuildGraph builds the graph from DirectLink objects whose status the resolver
// has written. A port contributes only when its state is up, and an edge is kept
// only when the peer's status reports the same cable up from its side.
func BuildGraph(links []netv1alpha1.DirectLink) Graph {
	half := map[string]map[string]Edge{}
	for _, l := range links {
		node := nodeOf(l)
		spec := map[string]netv1alpha1.DirectLinkPort{}
		for _, p := range l.Spec.Ports {
			spec[p.Iface] = p
		}
		for _, ps := range l.Status.Ports {
			if ps.State != netv1alpha1.DirectLinkStateUp || ps.PeerNodeName == "" || ps.PeerNodeName == node {
				continue
			}
			local := spec[ps.Iface]
			e := Edge{
				LocalIface: ps.Iface, LocalRDMA: local.RDMADevice, LocalIP: local.LinkIP,
				PeerIface: ps.PeerIface, PeerRDMA: ps.PeerRDMADevice, PeerIP: ps.PeerLinkIP,
				SpeedGbps: local.SpeedGbps,
			}
			if half[node] == nil {
				half[node] = map[string]Edge{}
			}
			if cur, ok := half[node][ps.PeerNodeName]; ok && cur.LocalIface <= e.LocalIface {
				continue
			}
			half[node][ps.PeerNodeName] = e
		}
	}
	g := Graph{Edges: map[string]map[string]Edge{}}
	for node, peers := range half {
		for peer, e := range peers {
			back, ok := half[peer][node]
			if !ok || back.LocalIface != e.PeerIface {
				continue
			}
			if g.Edges[node] == nil {
				g.Edges[node] = map[string]Edge{}
			}
			g.Edges[node][peer] = e
		}
	}
	return g
}

// Nodes returns every node with at least one edge, sorted.
func (g Graph) Nodes() []string { return sortedNodes(g.Edges) }

// Edge returns the edge from a to b.
func (g Graph) Edge(a, b string) (Edge, bool) {
	e, ok := g.Edges[a][b]
	return e, ok
}

func (g Graph) adjacent(a, b string, requireRDMA bool) bool {
	e, ok := g.Edges[a][b]
	if !ok {
		return false
	}
	return !requireRDMA || (e.LocalRDMA != "" && e.PeerRDMA != "")
}

// Clique returns n nodes every pair of which is joined by an edge (with an RDMA
// device on both ends of every edge when requireRDMA), choosing the
// lexicographically smallest such set, or false when there is none. n < 2 has no
// clique.
func (g Graph) Clique(n int, requireRDMA bool) ([]string, bool) {
	nodes := g.Nodes()
	if n < 2 || n > len(nodes) {
		return nil, false
	}
	var pick []string
	var search func(start int) bool
	search = func(start int) bool {
		if len(pick) == n {
			return true
		}
		for i := start; i < len(nodes); i++ {
			ok := true
			for _, p := range pick {
				if !g.adjacent(p, nodes[i], requireRDMA) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			pick = append(pick, nodes[i])
			if search(i + 1) {
				return true
			}
			pick = pick[:len(pick)-1]
		}
		return false
	}
	if !search(0) {
		return nil, false
	}
	return append([]string(nil), pick...), true
}

// Ring returns n distinct nodes in an order where each is joined to the next and
// the last to the first (for n == 2, one edge), or false when there is no such
// cycle. The answer is canonical: it starts at the smallest node of the cycle,
// takes the smaller neighbour second, and of all cycles the lexicographically
// smallest such sequence wins.
func (g Graph) Ring(n int) ([]string, bool) {
	nodes := g.Nodes()
	if n < 2 || n > len(nodes) {
		return nil, false
	}
	var best []string
	path := make([]string, 0, n)
	used := map[string]bool{}
	var walk func()
	walk = func() {
		if len(path) == n {
			if !g.adjacent(path[n-1], path[0], false) {
				return
			}
			if n > 2 && path[1] > path[n-1] {
				return // the same cycle in the other direction
			}
			if best == nil || less(path, best) {
				best = append([]string(nil), path...)
			}
			return
		}
		last := path[len(path)-1]
		for _, next := range nodes {
			if used[next] || next < path[0] || !g.adjacent(last, next, false) {
				continue
			}
			used[next] = true
			path = append(path, next)
			walk()
			path = path[:len(path)-1]
			used[next] = false
		}
	}
	for _, start := range nodes {
		path = append(path[:0], start)
		used = map[string]bool{start: true}
		walk()
		if best != nil {
			break // a cycle starting at a smaller node always sorts first
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

func less(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
