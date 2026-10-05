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
	"errors"
	"reflect"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

var t0 = metav1.NewTime(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))

// port is a healthy cabled port: link up, routes ready, an address.
func port(iface, uuid, peer, ip string) netv1alpha1.DirectLinkPort {
	return netv1alpha1.DirectLinkPort{Iface: iface, DomainUUID: uuid, PeerDomainUUID: peer, LinkIP: ip, LinkUp: true, RouteReady: true, SpeedGbps: 40}
}

func link(node string, ports ...netv1alpha1.DirectLinkPort) netv1alpha1.DirectLink {
	dl := netv1alpha1.DirectLink{Spec: netv1alpha1.DirectLinkSpec{
		SchemaVersion: netv1alpha1.DirectLinkSchemaVersion, NodeName: node, Medium: netv1alpha1.MediumThunderbolt, Ports: ports,
	}}
	dl.Name = node
	return dl
}

func allFresh(string) bool { return true }

// TestResolveUpRule is the up rule as a table: each row breaks exactly one of its
// conditions on a two-node cable and names the state the "a" side resolves to.
func TestResolveUpRule(t *testing.T) {
	rows := []struct {
		name  string
		a, b  netv1alpha1.DirectLinkPort
		fresh func(string) bool
		want  netv1alpha1.DirectLinkState
	}{
		{"both ends healthy", port("en2", "A", "B", "169.254.0.1"), port("en3", "B", "A", "169.254.0.10"), allFresh, netv1alpha1.DirectLinkStateUp},
		{"the peer does not list us back", port("en2", "A", "B", "169.254.0.1"), port("en3", "B", "C", "169.254.0.10"), allFresh, netv1alpha1.DirectLinkStateDown},
		{"our link is down", func() netv1alpha1.DirectLinkPort {
			p := port("en2", "A", "B", "169.254.0.1")
			p.LinkUp = false
			return p
		}(), port("en3", "B", "A", "169.254.0.10"), allFresh, netv1alpha1.DirectLinkStateDown},
		{"the peer's link is down", port("en2", "A", "B", "169.254.0.1"), func() netv1alpha1.DirectLinkPort {
			p := port("en3", "B", "A", "169.254.0.10")
			p.LinkUp = false
			return p
		}(), allFresh, netv1alpha1.DirectLinkStateDown},
		{"our routes are not ready", func() netv1alpha1.DirectLinkPort {
			p := port("en2", "A", "B", "169.254.0.1")
			p.RouteReady = false
			return p
		}(), port("en3", "B", "A", "169.254.0.10"), allFresh, netv1alpha1.DirectLinkStateDown},
		{"the peer's routes are not ready", port("en2", "A", "B", "169.254.0.1"), func() netv1alpha1.DirectLinkPort {
			p := port("en3", "B", "A", "169.254.0.10")
			p.RouteReady = false
			return p
		}(), allFresh, netv1alpha1.DirectLinkStateDown},
		{"we set tunnelOnly", func() netv1alpha1.DirectLinkPort {
			p := port("en2", "A", "B", "169.254.0.1")
			p.TunnelOnly = true
			return p
		}(), port("en3", "B", "A", "169.254.0.10"), allFresh, netv1alpha1.DirectLinkStateDown},
		{"the peer sets tunnelOnly", port("en2", "A", "B", "169.254.0.1"), func() netv1alpha1.DirectLinkPort {
			p := port("en3", "B", "A", "169.254.0.10")
			p.TunnelOnly = true
			return p
		}(), allFresh, netv1alpha1.DirectLinkStateDown},
		{"the peer's Lease is stale", port("en2", "A", "B", "169.254.0.1"), port("en3", "B", "A", "169.254.0.10"), func(n string) bool { return n != "b" }, netv1alpha1.DirectLinkStateDown},
		{"the peer has no address", port("en2", "A", "B", "169.254.0.1"), port("en3", "B", "A", ""), allFresh, netv1alpha1.DirectLinkStateDown},
		{"nothing plugged in", port("en2", "A", "", "169.254.0.1"), port("en3", "B", "", "169.254.0.10"), allFresh, netv1alpha1.DirectLinkStateDown},
		{"the far end is not a member", port("en2", "A", "Z", "169.254.0.1"), port("en3", "B", "", "169.254.0.10"), allFresh, netv1alpha1.DirectLinkStatePeerUnknown},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve([]netv1alpha1.DirectLink{link("a", tc.a), link("b", tc.b)}, tc.fresh, t0)
			ps := got["a"].Ports[0]
			if ps.State != tc.want {
				t.Fatalf("state = %s, want %s (%+v)", ps.State, tc.want, ps)
			}
			if tc.want == netv1alpha1.DirectLinkStateUp && (ps.PeerNodeName != "b" || ps.PeerIface != "en3" || ps.PeerLinkIP != "169.254.0.10") {
				t.Fatalf("up port names the wrong peer: %+v", ps)
			}
			if ps.LastTransition == nil || !ps.LastTransition.Equal(&t0) {
				t.Fatalf("a new port's lastTransition = %v, want now", ps.LastTransition)
			}
		})
	}
}

// TestResolveKeepsLastTransitionWhileTheStateHolds pins lastTransition moving on
// a change only.
func TestResolveKeepsLastTransitionWhileTheStateHolds(t *testing.T) {
	a, b := link("a", port("en2", "A", "B", "169.254.0.1")), link("b", port("en3", "B", "A", "169.254.0.10"))
	first := Resolve([]netv1alpha1.DirectLink{a, b}, allFresh, t0)
	a.Status, b.Status = first["a"], first["b"]
	later := metav1.NewTime(t0.Add(time.Minute))
	second := Resolve([]netv1alpha1.DirectLink{a, b}, allFresh, later)
	if !second["a"].Ports[0].LastTransition.Equal(&t0) {
		t.Fatalf("an unchanged state moved lastTransition to %v", second["a"].Ports[0].LastTransition)
	}
	if !StatusEqual(first["a"], second["a"]) {
		t.Fatal("an unchanged world produced a different status (the resolver would write every pass)")
	}
	third := Resolve([]netv1alpha1.DirectLink{a, b}, func(n string) bool { return n != "b" }, later)
	if third["a"].Ports[0].State != netv1alpha1.DirectLinkStateDown || !third["a"].Ports[0].LastTransition.Equal(&later) {
		t.Fatalf("a changed state = %+v, want down at the new time", third["a"].Ports[0])
	}
}

// TestDomainUUIDUniqueness pins that a collision is refused, never resolved by
// the last writer, and that colliding ports carry no direct route.
func TestDomainUUIDUniqueness(t *testing.T) {
	others := []netv1alpha1.DirectLink{link("b", port("en3", "B", "A", "169.254.0.10"))}
	spec := link("a", port("en2", "B", "", "169.254.0.1")).Spec
	if err := CheckDomainUUIDs(spec, others); !errors.Is(err, ErrDomainUUIDClaimed) {
		t.Fatalf("a UUID another node lists = %v, want ErrDomainUUIDClaimed", err)
	}
	if err := CheckDomainUUIDs(link("b", port("en3", "B", "", "")).Spec, others); err != nil {
		t.Fatalf("a node re-writing its own UUID = %v, want nil", err)
	}
	twice := link("a", port("en2", "A", "", ""), port("en3", "A", "", "")).Spec
	if err := CheckDomainUUIDs(twice, nil); !errors.Is(err, ErrDomainUUIDClaimed) {
		t.Fatalf("one node listing a UUID twice = %v, want ErrDomainUUIDClaimed", err)
	}
	// Objects written around the writer: both claimants resolve down.
	got := Resolve([]netv1alpha1.DirectLink{
		link("a", port("en2", "X", "Y", "169.254.0.1")),
		link("b", port("en2", "X", "Y", "169.254.0.9")),
		link("c", port("en2", "Y", "X", "169.254.0.17")),
	}, allFresh, t0)
	for _, n := range []string{"a", "b", "c"} {
		if got[n].Ports[0].State == netv1alpha1.DirectLinkStateUp {
			t.Fatalf("node %s resolved a collided UUID up", n)
		}
	}
}

// TestPlanWritesOnlyChangesAndLabels pins the controller's pass: a status write
// only on a change, a label only when the up count moved, and one transition per
// changed port.
func TestPlanWritesOnlyChangesAndLabels(t *testing.T) {
	a, b := link("a", port("en2", "A", "B", "169.254.0.1")), link("b", port("en3", "B", "A", "169.254.0.10"))
	p := Plan([]netv1alpha1.DirectLink{a, b}, allFresh, map[string]string{}, t0)
	if len(p.Status) != 2 || len(p.Transitions) != 2 {
		t.Fatalf("first pass: %d status writes, %d transitions, want 2 and 2", len(p.Status), len(p.Transitions))
	}
	if !reflect.DeepEqual(p.Labels, map[string]string{"a": "1", "b": "1"}) {
		t.Fatalf("labels = %v", p.Labels)
	}
	a.Status, b.Status = p.Status[0].Status, p.Status[1].Status
	q := Plan([]netv1alpha1.DirectLink{a, b}, allFresh, map[string]string{"a": "1", "b": "1"}, metav1.NewTime(t0.Add(time.Minute)))
	if len(q.Status) != 0 || len(q.Transitions) != 0 || len(q.Labels) != 0 {
		t.Fatalf("an idle pass wrote %d statuses, %d transitions, %d labels; want none (no kine churn)", len(q.Status), len(q.Transitions), len(q.Labels))
	}
}

func TestLeaseFresh(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	dur := int32(60)
	rows := []struct {
		name  string
		lease *coordinationv1.Lease
		want  bool
	}{
		{"no lease", nil, false},
		{"never renewed", &coordinationv1.Lease{}, false},
		{"renewed 10s ago", &coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{RenewTime: &metav1.MicroTime{Time: now.Add(-10 * time.Second)}}}, true},
		{"renewed 41s ago", &coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{RenewTime: &metav1.MicroTime{Time: now.Add(-41 * time.Second)}}}, false},
		{"its own longer duration", &coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{RenewTime: &metav1.MicroTime{Time: now.Add(-50 * time.Second)}, LeaseDurationSeconds: &dur}}, true},
	}
	for _, tc := range rows {
		if got := LeaseFresh(tc.lease, now); got != tc.want {
			t.Errorf("%s: LeaseFresh = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// graphOf builds a resolved graph from undirected cables "x-y" (optionally RDMA).
func graphOf(t *testing.T, cables []string, rdma bool) Graph {
	t.Helper()
	ports := map[string][]netv1alpha1.DirectLinkPort{}
	n := 0
	for _, c := range cables {
		x, y := c[:1], c[2:]
		n++
		ux, uy := c+"-x", c+"-y"
		px := port("en"+string(rune('2'+len(ports[x]))), ux, uy, "169.254.0.1")
		py := port("en"+string(rune('2'+len(ports[y]))), uy, ux, "169.254.0.2")
		if rdma {
			px.RDMADevice, py.RDMADevice = "rdma_"+px.Iface, "rdma_"+py.Iface
		}
		ports[x] = append(ports[x], px)
		ports[y] = append(ports[y], py)
	}
	var links []netv1alpha1.DirectLink
	for _, node := range sortedNodes(ports) {
		links = append(links, link(node, ports[node]...))
	}
	st := Resolve(links, allFresh, t0)
	for i := range links {
		links[i].Status = st[nodeOf(links[i])]
	}
	return BuildGraph(links)
}

func TestClique(t *testing.T) {
	rows := []struct {
		name   string
		cables []string
		rdma   bool
		n      int
		need   bool
		want   []string
		ok     bool
	}{
		{"a pair is a 2-clique", []string{"a-b"}, false, 2, false, []string{"a", "b"}, true},
		{"a triangle is a 3-clique", []string{"a-b", "b-c", "a-c"}, false, 3, false, []string{"a", "b", "c"}, true},
		{"a path is not a 3-clique", []string{"a-b", "b-c"}, false, 3, false, nil, false},
		{"the smallest set wins", []string{"c-d", "a-b"}, false, 2, false, []string{"a", "b"}, true},
		{"rdma required but absent", []string{"a-b", "b-c", "a-c"}, false, 3, true, nil, false},
		{"rdma required and present", []string{"a-b", "b-c", "a-c"}, true, 3, true, []string{"a", "b", "c"}, true},
		{"n=1 is no clique", []string{"a-b"}, false, 1, false, nil, false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := graphOf(t, tc.cables, tc.rdma).Clique(tc.n, tc.need)
			if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Clique(%d, %v) = %v %v, want %v %v", tc.n, tc.need, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestRing(t *testing.T) {
	rows := []struct {
		name   string
		cables []string
		n      int
		want   []string
		ok     bool
	}{
		{"a pair is a 2-ring", []string{"a-b"}, 2, []string{"a", "b"}, true},
		{"a square ring of four", []string{"a-b", "b-c", "c-d", "d-a"}, 4, []string{"a", "b", "c", "d"}, true},
		{"the ring direction is canonical", []string{"a-d", "d-c", "c-b", "b-a"}, 4, []string{"a", "b", "c", "d"}, true},
		{"a path of four is no 4-ring", []string{"a-b", "b-c", "c-d"}, 4, nil, false},
		{"a triangle inside a larger graph", []string{"a-b", "b-c", "c-a", "c-d"}, 3, []string{"a", "b", "c"}, true},
		{"more ranks than nodes", []string{"a-b"}, 3, nil, false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := graphOf(t, tc.cables, false).Ring(tc.n)
			if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Ring(%d) = %v %v, want %v %v", tc.n, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestBuildGraphNeedsBothSides pins that an edge exists only when both nodes'
// statuses report the cable up.
func TestBuildGraphNeedsBothSides(t *testing.T) {
	a, b := link("a", port("en2", "A", "B", "169.254.0.1")), link("b", port("en3", "B", "A", "169.254.0.10"))
	st := Resolve([]netv1alpha1.DirectLink{a, b}, allFresh, t0)
	a.Status = st["a"] // b's status not yet written
	if g := BuildGraph([]netv1alpha1.DirectLink{a, b}); len(g.Edges) != 0 {
		t.Fatalf("one side's status alone built edges %v", g.Edges)
	}
	b.Status = st["b"]
	g := BuildGraph([]netv1alpha1.DirectLink{a, b})
	e, ok := g.Edge("a", "b")
	if !ok || e.LocalIface != "en2" || e.PeerIface != "en3" || e.PeerIP != "169.254.0.10" || e.SpeedGbps != 40 {
		t.Fatalf("edge a->b = %+v %v", e, ok)
	}
}
