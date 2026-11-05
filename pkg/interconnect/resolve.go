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

package interconnect

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// UpHold is how long a member must be continuously up before it counts as up. It is measured from the member's persisted lastTransition, never
// from an in-memory clock, so a resolver restart (or a failover to the other
// server) neither shortens nor restarts the hold.
const UpHold = 60 * time.Second

// NoIndex marks a node whose cluster index is unknown (it holds no pod /24).
const NoIndex = -1

// Report rejection reasons. They label the report-rejected counter and the
// Node Event, so they are a closed set.
const (
	RejectUnknownSchema = "UnknownSchema"
	RejectInvalid       = "Invalid"
	RejectUnknownPeer   = "UnknownPeer"
	RejectStaleNode     = "StaleNode"
)

// NodeInput is what the resolver knows about one existing Node.
type NodeInput struct {
	// Name is the Node's name.
	Name string
	// Index is the node's cluster index (its pod /24's index in the cluster pod
	// aggregate), or NoIndex.
	Index int
	// Fresh reports whether the node's coordination Lease is current. A stale
	// node's report is dropped and the node is treated as down.
	Fresh bool
	// Report is the raw k3sm.io/interconnect-report value; "" when absent.
	Report string
}

// Input is one resolution's whole input.
type Input struct {
	// Now is the reconcile time; hysteresis compares it with persisted times.
	Now time.Time
	// Spec is the Interconnect's spec as read from the apiserver.
	Spec netv1alpha1.InterconnectSpec
	// Prev is the members the Interconnect's status holds now.
	Prev []netv1alpha1.InterconnectMember
	// Nodes is every existing Node.
	Nodes []NodeInput
}

// Result is the resolved status plus the per-node desired verdict.
type Result struct {
	// Members is the new status.members, sorted by node name.
	Members []netv1alpha1.InterconnectMember
	// Segments is the new status.segments.
	Segments []netv1alpha1.InterconnectSegment
	// OutOfRange is the members whose index is beyond MaxInterconnectNodeIndex
	// (state down, reason ReasonInterconnectIndexOutOfRange), sorted.
	OutOfRange []string
	// DuplicateIndex is the nodes that share a cluster index with another Node
	// (their derived addresses would collide), sorted. Their members stay down
	// with no address and are never given the desired annotation.
	DuplicateIndex []string
	// Rejected maps a node to the reason its report was ignored.
	Rejected map[string]string
	// Desired is the set of nodes that must carry the desired annotation. Every
	// other node must not.
	Desired map[string]bool
	// HasPeer reports whether any accepted report shows a connected peer, which
	// is what triggers the Interconnect's auto-creation.
	HasPeer bool
}

// AcceptReport parses raw as an untrusted report: the apis bounds
// (size, peer count, field shapes, schema), then every reachable peer must be an
// existing Node. It returns the report, or the rejection reason and error.
func AcceptReport(raw string, nodes map[string]bool) (netv1alpha1.InterconnectReport, string, error) {
	r, err := netv1alpha1.ParseInterconnectReport(raw)
	if err != nil {
		if errors.Is(err, netv1alpha1.ErrUnknownInterconnectSchema) {
			return netv1alpha1.InterconnectReport{}, RejectUnknownSchema, err
		}
		return netv1alpha1.InterconnectReport{}, RejectInvalid, err
	}
	for _, p := range r.ReachablePeers {
		if !nodes[p] {
			return netv1alpha1.InterconnectReport{}, RejectUnknownPeer, fmt.Errorf("report names peer %q, which is not a Node", p)
		}
	}
	return r, "", nil
}

// connected reports whether a report shows a cable to a peer.
func connected(r netv1alpha1.InterconnectReport) bool {
	return len(r.PeerDomainUUIDs) > 0
}

// Resolve computes the Interconnect's members and segments and the desired
// verdict from one snapshot. It is pure: the same Input always yields the same
// Result.
//
// A member is a non-excluded node with a cluster index that holds an accepted, fresh report showing a
// connected peer, or that is already a member and still exists. A member is up
// iff its report is fresh, its index is within 0..MaxInterconnectNodeIndex (so
// its address InterconnectSlotAddress(idx, 0) exists, recomputed here and never
// taken from the node) and held by no other Node, it is not in a cable loop, and at least one peer it
// reaches also reaches it; then it must stay so for UpHold, measured from its
// persisted lastTransition.
//
// lastTransition records the last change of the member's RAW reachability (or
// of loop membership): the hold starts there, and a held member reads down with
// its mutual peers already listed in reachablePeers, so the hold survives a
// restart. Segments are connected components of mutual reachability among up
// members.
func Resolve(in Input) Result {
	res := Result{Rejected: map[string]string{}, Desired: map[string]bool{}}
	excluded := map[string]bool{}
	for _, n := range in.Spec.ExcludedNodes {
		excluded[n] = true
	}
	exists := make(map[string]bool, len(in.Nodes))
	byName := make(map[string]NodeInput, len(in.Nodes))
	for _, n := range in.Nodes {
		exists[n.Name] = true
		byName[n.Name] = n
	}
	prev := make(map[string]netv1alpha1.InterconnectMember, len(in.Prev))
	for _, m := range in.Prev {
		prev[m.Node] = m
	}

	// Accepted, fresh reports.
	reports := map[string]netv1alpha1.InterconnectReport{}
	for _, n := range in.Nodes {
		if n.Report == "" {
			continue
		}
		r, reason, err := AcceptReport(n.Report, exists)
		if err != nil {
			res.Rejected[n.Name] = reason
			continue
		}
		if !n.Fresh {
			res.Rejected[n.Name] = RejectStaleNode
			continue
		}
		reports[n.Name] = r
		if connected(r) {
			res.HasPeer = true
		}
	}

	// The member set.
	var names []string
	for _, n := range in.Nodes {
		// An excluded node never becomes a member, and a node with no cluster
		// index has no interconnect address to be a member with.
		if excluded[n.Name] || n.Index < 0 {
			continue
		}
		r, ok := reports[n.Name]
		_, was := prev[n.Name]
		if (ok && connected(r)) || was {
			names = append(names, n.Name)
		}
	}
	sort.Strings(names)
	isMember := make(map[string]bool, len(names))
	for _, n := range names {
		isMember[n] = true
	}

	// Two Nodes holding one cluster index would derive one address; neither is
	// trusted with it.
	holders := map[int][]string{}
	for _, n := range in.Nodes {
		if n.Index >= 0 {
			holders[n.Index] = append(holders[n.Index], n.Name)
		}
	}
	dupIndex := map[string]bool{}
	for _, hs := range holders {
		if len(hs) > 1 {
			for _, h := range hs {
				dupIndex[h] = true
				res.DuplicateIndex = append(res.DuplicateIndex, h)
			}
		}
	}
	sort.Strings(res.DuplicateIndex)

	inRange := func(name string) bool {
		idx := byName[name].Index
		return idx >= 0 && idx <= netv1alpha1.MaxInterconnectNodeIndex && !dupIndex[name]
	}
	loops := cableLoops(reports, isMember)

	// usable: a member whose report may count toward mutual adjacency.
	usable := func(name string) bool {
		_, ok := reports[name]
		return ok && isMember[name] && inRange(name) && !loops[name]
	}
	mutual := func(name string) []string {
		if !usable(name) {
			return nil
		}
		var out []string
		for _, p := range reports[name].ReachablePeers {
			if p == name || !usable(p) {
				continue
			}
			if slices.Contains(reports[p].ReachablePeers, name) {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out
	}

	now := metav1.NewTime(in.Now)
	for _, name := range names {
		n := byName[name]
		m := netv1alpha1.InterconnectMember{Node: name, Index: int32(n.Index), State: netv1alpha1.InterconnectMemberDown}
		if r, ok := reports[name]; ok {
			m.SpeedGbps = r.SpeedGbps
		}
		if a, err := netv1alpha1.InterconnectSlotAddress(n.Index, netv1alpha1.InterconnectSlotNode); err != nil {
			res.OutOfRange = append(res.OutOfRange, name)
		} else if !dupIndex[name] {
			m.Address = a.String()
		}

		p, had := prev[name]
		prevLoop := had && p.State == netv1alpha1.InterconnectMemberLoop
		prevRaw := had && !prevLoop && len(p.ReachablePeers) > 0
		lt := p.LastTransition
		switch {
		case loops[name]:
			m.State = netv1alpha1.InterconnectMemberLoop
			if !prevLoop {
				lt = &now
			}
		default:
			peers := mutual(name)
			m.ReachablePeers = peers
			raw := len(peers) > 0
			switch {
			case raw != prevRaw || prevLoop || !had:
				lt = &now
				// A member that just became reachable is held down; one that
				// just stopped is down at once.
			case raw && p.State == netv1alpha1.InterconnectMemberUp:
				m.State = netv1alpha1.InterconnectMemberUp
			case raw && lt != nil && !in.Now.Before(lt.Add(UpHold)):
				m.State = netv1alpha1.InterconnectMemberUp
			case raw && lt == nil:
				lt = &now
			}
		}
		if lt != nil {
			m.LastTransition = lt.DeepCopy()
		}
		res.Members = append(res.Members, m)

		if in.Spec.Enabled && m.Address != "" && m.State != netv1alpha1.InterconnectMemberLoop {
			res.Desired[name] = true
		}
	}
	sort.Strings(res.OutOfRange)
	res.Segments = segments(res.Members)
	return res
}

// segments assigns every up member to the connected component of mutual
// reachability it belongs to, and returns the components ordered by their
// smallest node name ("seg-0" first).
func segments(members []netv1alpha1.InterconnectMember) []netv1alpha1.InterconnectSegment {
	up := map[string]int{}
	for i, m := range members {
		if m.State == netv1alpha1.InterconnectMemberUp {
			up[m.Node] = i
		}
	}
	uf := newUnionFind()
	for name, i := range up {
		uf.find(name)
		for _, p := range members[i].ReachablePeers {
			if _, ok := up[p]; ok {
				uf.union(name, p)
			}
		}
	}
	groups := map[string][]string{}
	for name := range up {
		root := uf.find(name)
		groups[root] = append(groups[root], name)
	}
	comps := make([][]string, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g)
		comps = append(comps, g)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i][0] < comps[j][0] })
	out := make([]netv1alpha1.InterconnectSegment, 0, len(comps))
	for i, c := range comps {
		id := fmt.Sprintf("seg-%d", i)
		out = append(out, netv1alpha1.InterconnectSegment{ID: id, Nodes: c})
		for _, name := range c {
			members[up[name]].Segment = id
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cableLoops returns the members that sit in a bridged Thunderbolt loop,
// from the reported cable graph. Reports are untrusted, so a cable edge
// between A and B counts only when BOTH ends confirm it: A lists one of B's
// local domains as a peer AND B lists one of A's. Its multiplicity is the
// smaller of the two ends' counts. Then:
//
//   - two confirmed cables between one pair, or a cycle among confirmed edges
//     (a component with at least as many edges as nodes), marks every node of
//     that component;
//   - a node listing the same peer domain on two of its own ports marks that
//     node only.
//
// An unconfirmed claim (a peer domain the owner does not reciprocate, or that no
// member claims as local) is not an edge and marks nobody, so a lying node can
// never put honest nodes into loop. Loops through Macs that are not cluster
// nodes are invisible here, which the user page states.
func cableLoops(reports map[string]netv1alpha1.InterconnectReport, isMember map[string]bool) map[string]bool {
	owner := map[string]string{}
	ambiguous := map[string]bool{}
	for name, r := range reports {
		if !isMember[name] {
			continue
		}
		for _, u := range r.LocalDomainUUIDs {
			if o, ok := owner[u]; ok && o != name {
				ambiguous[u] = true
			}
			owner[u] = name
		}
	}
	out := map[string]bool{}
	// seen[a][b] is how many of a's peer entries name a local domain of b.
	seen := map[string]map[string]int{}
	for name, r := range reports {
		if !isMember[name] {
			continue
		}
		dup := map[string]bool{}
		for _, u := range r.PeerDomainUUIDs {
			if dup[u] {
				out[name] = true
			}
			dup[u] = true
			o, ok := owner[u]
			if !ok || ambiguous[u] || o == name {
				continue
			}
			if seen[name] == nil {
				seen[name] = map[string]int{}
			}
			seen[name][o]++
		}
	}
	type pair struct{ a, b string }
	counts := map[pair]int{}
	for a, peers := range seen {
		for b, n := range peers {
			back := seen[b][a]
			if back == 0 || b < a {
				continue // unconfirmed, or counted from the other end
			}
			counts[pair{a, b}] = min(n, back)
		}
	}
	uf := newUnionFind()
	for k := range counts {
		uf.union(k.a, k.b)
	}
	vertices := map[string]map[string]bool{}
	edges := map[string]int{}
	loopy := map[string]bool{}
	for k, c := range counts {
		root := uf.find(k.a)
		if vertices[root] == nil {
			vertices[root] = map[string]bool{}
		}
		vertices[root][k.a], vertices[root][k.b] = true, true
		edges[root]++
		if c >= 2 {
			loopy[root] = true
		}
	}
	for root, vs := range vertices {
		if edges[root] >= len(vs) {
			loopy[root] = true
		}
	}
	for root := range loopy {
		for v := range vertices[root] {
			out[v] = true
		}
	}
	return out
}

// unionFind is a string-keyed disjoint-set forest.
type unionFind struct{ parent map[string]string }

func newUnionFind() *unionFind { return &unionFind{parent: map[string]string{}} }

func (u *unionFind) find(x string) string {
	p, ok := u.parent[x]
	if !ok {
		u.parent[x] = x
		return x
	}
	if p == x {
		return x
	}
	r := u.find(p)
	u.parent[x] = r
	return r
}

func (u *unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	if rb < ra {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
}
