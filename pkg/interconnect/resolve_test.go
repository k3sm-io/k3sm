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
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	coordinationlisters "k8s.io/client-go/listers/coordination/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

var t0 = time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)

// rep builds an encoded report: local domains, peer domains (one per cabled
// port), and the reachable peer nodes.
func rep(t *testing.T, local, peerDomains, reachable []string) string {
	t.Helper()
	r := netv1alpha1.InterconnectReport{
		Schema:           netv1alpha1.InterconnectAnnotationSchema,
		LocalDomainUUIDs: local,
		PeerDomainUUIDs:  peerDomains,
		Carrier:          len(peerDomains) > 0,
		SpeedGbps:        40,
		ReachablePeers:   reachable,
	}
	v, err := r.Encode()
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	return v
}

func node(name string, idx int, report string) NodeInput {
	return NodeInput{Name: name, Index: idx, Fresh: true, Report: report}
}

// settle resolves at t0, then again UpHold later over the persisted result, so
// every member that stays reachable has served its hold.
func settle(in Input) Result {
	in.Now = t0
	first := Resolve(in)
	in.Prev = first.Members
	in.Now = t0.Add(UpHold)
	return Resolve(in)
}

func member(t *testing.T, res Result, name string) netv1alpha1.InterconnectMember {
	t.Helper()
	for _, m := range res.Members {
		if m.Node == name {
			return m
		}
	}
	t.Fatalf("%s is not a member; members = %+v", name, res.Members)
	return netv1alpha1.InterconnectMember{}
}

func isMemberOf(res Result, name string) bool {
	for _, m := range res.Members {
		if m.Node == name {
			return true
		}
	}
	return false
}

func segIDs(res Result) map[string][]string {
	out := map[string][]string{}
	for _, s := range res.Segments {
		out[s.ID] = s.Nodes
	}
	return out
}

var enabled = netv1alpha1.InterconnectSpec{Medium: netv1alpha1.MediumThunderbolt, Enabled: true}

// TestResolverSegments is the B524 resolver gate: membership needs a fresh,
// accepted report and mutual adjacency over server-recomputed addresses;
// segments are components of mutual reachability; loops and out-of-range
// indices are marked and never fail the object; the desired annotation follows
// the spec and is owned by the server; hysteresis is persisted; and missing
// information never clears anything.
func TestResolverSegments(t *testing.T) {
	t.Run("mutual adjacency makes an up segment with recomputed addresses", func(t *testing.T) {
		res := settle(Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
		}})
		for name, addr := range map[string]string{"a": "169.254.0.1", "b": "169.254.0.9"} {
			m := member(t, res, name)
			if m.State != netv1alpha1.InterconnectMemberUp || m.Segment != "seg-0" || m.Address != addr {
				t.Errorf("%s = %+v, want up in seg-0 at %s", name, m, addr)
			}
		}
		if got := segIDs(res); !reflect.DeepEqual(got, map[string][]string{"seg-0": {"a", "b"}}) {
			t.Errorf("segments = %v", got)
		}
	})

	t.Run("two cabled pairs are two segments", func(t *testing.T) {
		res := settle(Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
			node("c", 2, rep(t, []string{"C1"}, []string{"D1"}, []string{"d"})),
			node("d", 3, rep(t, []string{"D1"}, []string{"C1"}, []string{"c"})),
		}})
		want := map[string][]string{"seg-0": {"a", "b"}, "seg-1": {"c", "d"}}
		if got := segIDs(res); !reflect.DeepEqual(got, want) {
			t.Errorf("segments = %v, want %v", got, want)
		}
	})

	t.Run("a one-way report is not a member", func(t *testing.T) {
		res := settle(Input{Spec: enabled, Nodes: []NodeInput{
			// a claims b and c; b reaches nobody; c wrote no report at all.
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b", "c"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, nil)),
			node("c", 2, ""),
		}})
		for _, name := range []string{"a", "b"} {
			if m := member(t, res, name); m.State == netv1alpha1.InterconnectMemberUp || m.Segment != "" || len(m.ReachablePeers) != 0 {
				t.Errorf("%s = %+v; a one-way claim must not make it up, segmented or adjacent", name, m)
			}
		}
		if isMemberOf(res, "c") {
			t.Error("c is a member only because a peer named it; membership needs its own report")
		}
		if len(res.Segments) != 0 {
			t.Errorf("segments = %v, want none", res.Segments)
		}
	})

	t.Run("an index-31 node is down with the reason and fails nothing", func(t *testing.T) {
		res := settle(Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1", "Z1"}, []string{"b", "z"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
			node("z", 31, rep(t, []string{"Z1"}, []string{"A1"}, []string{"a"})),
		}})
		z := member(t, res, "z")
		if z.State != netv1alpha1.InterconnectMemberDown || z.Address != "" || z.Index != 31 {
			t.Errorf("z = %+v, want down at index 31 with no address", z)
		}
		if !reflect.DeepEqual(res.OutOfRange, []string{"z"}) {
			t.Errorf("OutOfRange = %v, want [z]", res.OutOfRange)
		}
		if res.Desired["z"] {
			t.Error("an out-of-range node must not be asked to configure an address")
		}
		if a := member(t, res, "a"); a.State != netv1alpha1.InterconnectMemberUp {
			t.Errorf("a = %+v; an out-of-range peer must not fail the segment", a)
		}
	})

	t.Run("loops are marked", func(t *testing.T) {
		cases := map[string][]NodeInput{
			"two cables between one pair": {
				node("a", 0, rep(t, []string{"A1", "A2"}, []string{"B1", "B2"}, []string{"b"})),
				node("b", 1, rep(t, []string{"B1", "B2"}, []string{"A1", "A2"}, []string{"a"})),
			},
			"a cycle of three": {
				node("a", 0, rep(t, []string{"A1", "A2"}, []string{"B1", "C2"}, []string{"b", "c"})),
				node("b", 1, rep(t, []string{"B1", "B2"}, []string{"A1", "C1"}, []string{"a", "c"})),
				node("c", 2, rep(t, []string{"C1", "C2"}, []string{"B2", "A2"}, []string{"a", "b"})),
			},
		}
		for name, nodes := range cases {
			t.Run(name, func(t *testing.T) {
				res := settle(Input{Spec: enabled, Nodes: nodes})
				for _, n := range nodes {
					m := member(t, res, n.Name)
					if m.State != netv1alpha1.InterconnectMemberLoop || m.Segment != "" {
						t.Errorf("%s = %+v, want loop and no segment", n.Name, m)
					}
					if res.Desired[n.Name] {
						t.Errorf("%s is in a loop and must not be given an address", n.Name)
					}
				}
			})
		}
		// The same peer domain on two of a node's own ports marks that node
		// only: the other end may be honest.
		res := settle(Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1", "A2"}, []string{"B1", "B1"}, []string{"b"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
		}}).Members
		if res[0].State != netv1alpha1.InterconnectMemberLoop || res[1].State == netv1alpha1.InterconnectMemberLoop {
			t.Errorf("repeated peer domain: members = %+v, want a loop and b not", res)
		}
		// A chain is not a loop.
		chain := settle(Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b", "c"})),
			node("b", 1, rep(t, []string{"B1", "B2"}, []string{"A1", "C1"}, []string{"a", "c"})),
			node("c", 2, rep(t, []string{"C1"}, []string{"B2"}, []string{"a", "b"})),
		}})
		for _, n := range []string{"a", "b", "c"} {
			if m := member(t, chain, n); m.State != netv1alpha1.InterconnectMemberUp {
				t.Errorf("chain member %s = %+v, want up", n, m)
			}
		}
	})

	t.Run("a lying node cannot put honest nodes into loop", func(t *testing.T) {
		// a and b are cabled to each other once. l claims to be cabled to both
		// (twice to a, and closing a triangle), but neither lists l's domains.
		res := settle(Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
			node("l", 2, rep(t, []string{"L1", "L2"}, []string{"A1", "A1", "B1"}, []string{"a", "b"})),
		}})
		for _, n := range []string{"a", "b"} {
			if m := member(t, res, n); m.State != netv1alpha1.InterconnectMemberUp || m.Segment != "seg-0" {
				t.Errorf("honest %s = %+v, want up in seg-0", n, m)
			}
		}
		if m := member(t, res, "l"); m.State == netv1alpha1.InterconnectMemberUp || m.Segment != "" {
			t.Errorf("liar l = %+v, want not up and in no segment", m)
		}
		if got := segIDs(res); !reflect.DeepEqual(got, map[string][]string{"seg-0": {"a", "b"}}) {
			t.Errorf("segments = %v", got)
		}
	})

	t.Run("duplicate cluster indices are down with no address", func(t *testing.T) {
		res := settle(Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1", "C1"}, []string{"b", "c"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
			node("c", 1, rep(t, []string{"C1"}, []string{"A1"}, []string{"a"})),
		}})
		for _, n := range []string{"b", "c"} {
			m := member(t, res, n)
			if m.State != netv1alpha1.InterconnectMemberDown || m.Address != "" || res.Desired[n] {
				t.Errorf("%s = %+v desired=%v, want down, no address, no desired", n, m, res.Desired[n])
			}
		}
		if !reflect.DeepEqual(res.DuplicateIndex, []string{"b", "c"}) {
			t.Errorf("DuplicateIndex = %v, want [b c]", res.DuplicateIndex)
		}
	})

	t.Run("desired only while enabled and not excluded", func(t *testing.T) {
		nodes := []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
		}
		off := settle(Input{Spec: netv1alpha1.InterconnectSpec{Medium: netv1alpha1.MediumThunderbolt}, Nodes: nodes})
		if len(off.Desired) != 0 {
			t.Errorf("disabled: Desired = %v, want none", off.Desired)
		}
		spec := enabled
		spec.ExcludedNodes = []string{"b"}
		on := settle(Input{Spec: spec, Nodes: nodes})
		if !on.Desired["a"] || on.Desired["b"] {
			t.Errorf("enabled, b excluded: Desired = %v, want a only", on.Desired)
		}
		if isMemberOf(on, "b") {
			t.Error("an excluded node never becomes a member")
		}
	})

	t.Run("untrusted reports are ignored", func(t *testing.T) {
		good := rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})
		cases := []struct {
			name, report string
			fresh        bool
			want         string
		}{
			{"oversize", `{"schema":1,"localDomainUUIDs":["` + strings.Repeat("x", netv1alpha1.MaxInterconnectReportBytes) + `"]}`, true, RejectInvalid},
			{"unknown schema", `{"schema":2,"carrier":true,"peerDomainUUIDs":["A1"],"reachablePeers":["a"]}`, true, RejectUnknownSchema},
			{"unknown peer", rep(t, []string{"B1"}, []string{"A1"}, []string{"a", "ghost"}), true, RejectUnknownPeer},
			{"stale node", good, false, RejectStaleNode},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				b := NodeInput{Name: "b", Index: 1, Fresh: tc.fresh, Report: tc.report}
				res := settle(Input{Spec: enabled, Nodes: []NodeInput{
					node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})),
					b,
				}})
				if res.Rejected["b"] != tc.want {
					t.Errorf("Rejected[b] = %q, want %q", res.Rejected["b"], tc.want)
				}
				if isMemberOf(res, "b") {
					t.Error("a node whose only report was ignored became a member")
				}
				if m := member(t, res, "a"); m.State == netv1alpha1.InterconnectMemberUp {
					t.Errorf("a = %+v; adjacency with an ignored report must not count", m)
				}
			})
		}
		// A member whose node goes stale stays listed, down.
		in := Input{Spec: enabled, Nodes: []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})),
			node("b", 1, good),
		}}
		up := settle(in)
		in.Prev, in.Now = up.Members, t0.Add(2*UpHold)
		in.Nodes[1].Fresh = false
		res := Resolve(in)
		if m := member(t, res, "b"); m.State != netv1alpha1.InterconnectMemberDown {
			t.Errorf("stale b = %+v, want down", m)
		}
		if m := member(t, res, "a"); m.State != netv1alpha1.InterconnectMemberDown {
			t.Errorf("a = %+v; its only peer went stale, want down", m)
		}
	})

	t.Run("hysteresis is measured from the persisted lastTransition", func(t *testing.T) {
		nodes := []NodeInput{
			node("a", 0, rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})),
			node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})),
		}
		first := Resolve(Input{Now: t0, Spec: enabled, Nodes: nodes})
		if m := member(t, first, "a"); m.State != netv1alpha1.InterconnectMemberDown || !m.LastTransition.Time.Equal(t0) {
			t.Fatalf("a newly reachable member = %+v, want held down from t0", m)
		}
		// A resolver restart has only the persisted status: 30 s in, still held.
		mid := Resolve(Input{Now: t0.Add(30 * time.Second), Spec: enabled, Nodes: nodes, Prev: first.Members})
		if m := member(t, mid, "a"); m.State != netv1alpha1.InterconnectMemberDown || !m.LastTransition.Time.Equal(t0) {
			t.Fatalf("a at +30 s = %+v, want still held, lastTransition unchanged", m)
		}
		done := Resolve(Input{Now: t0.Add(UpHold), Spec: enabled, Nodes: nodes, Prev: mid.Members})
		if m := member(t, done, "a"); m.State != netv1alpha1.InterconnectMemberUp {
			t.Fatalf("a at +60 s = %+v, want up", m)
		}
		// Losing the peer is immediate; regaining it restarts the hold.
		lost := []NodeInput{nodes[0], node("b", 1, rep(t, []string{"B1"}, []string{"A1"}, nil))}
		down := Resolve(Input{Now: t0.Add(2 * UpHold), Spec: enabled, Nodes: lost, Prev: done.Members})
		if m := member(t, down, "a"); m.State != netv1alpha1.InterconnectMemberDown {
			t.Fatalf("a after loss = %+v, want down at once", m)
		}
		back := Resolve(Input{Now: t0.Add(2*UpHold + 10*time.Second), Spec: enabled, Nodes: nodes, Prev: down.Members})
		if m := member(t, back, "a"); m.State != netv1alpha1.InterconnectMemberDown {
			t.Fatalf("a 10 s after coming back = %+v, want held again", m)
		}
	})

	t.Run("controller", testResolverController)
}

// harness is a resolver over fake clients and hand-fed listers.
type harness struct {
	cs      *fake.Clientset
	dyn     *dynamicfake.FakeDynamicClient
	nodes   cache.Indexer
	leases  cache.Indexer
	synced  bool
	indices map[string]int
	invalid map[string]string
	now     time.Time
	rec     *record.FakeRecorder
}

func newHarness(t *testing.T, nodes []*corev1.Node, ic *netv1alpha1.Interconnect) *harness {
	t.Helper()
	h := &harness{
		nodes:   cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}),
		leases:  cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}),
		synced:  true,
		indices: map[string]int{},
		now:     t0,
		rec:     record.NewFakeRecorder(100),
	}
	var objs []runtime.Object
	for i, n := range nodes {
		objs = append(objs, n)
		if err := h.nodes.Add(n); err != nil {
			t.Fatal(err)
		}
		h.indices[n.Name] = i
	}
	h.renewLeases(t, nodes, t0)
	h.cs = fake.NewClientset(objs...)
	scheme := runtime.NewScheme()
	var dynObjs []runtime.Object
	if ic != nil {
		u, err := toUnstructured(ic)
		if err != nil {
			t.Fatal(err)
		}
		dynObjs = append(dynObjs, u)
	}
	h.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{GVR: "InterconnectList"}, dynObjs...)
	return h
}

// renewLeases stamps every node's heartbeat Lease as renewed at at.
func (h *harness) renewLeases(t *testing.T, nodes []*corev1.Node, at time.Time) {
	t.Helper()
	for _, n := range nodes {
		renew := metav1.NewMicroTime(at)
		if err := h.leases.Update(&coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: n.Name, Namespace: corev1.NamespaceNodeLease},
			Spec:       coordinationv1.LeaseSpec{RenewTime: &renew},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func (h *harness) resolver() *Resolver {
	r := NewResolver(ResolverConfig{
		Client:   h.cs,
		Store:    Store{Client: h.dyn},
		Indices:  func(context.Context) (Indices, error) { return Indices{Index: h.indices, Invalid: h.invalid}, nil },
		Recorder: h.rec,
		Metrics:  NewMetrics(),
		Log:      slog.New(slog.DiscardHandler),
		Now:      func() time.Time { return h.now },
	})
	r.SetListers(corelisters.NewNodeLister(h.nodes), coordinationlisters.NewLeaseLister(h.leases), func() bool { return h.synced })
	return r
}

func (h *harness) annotation(t *testing.T, name string) (string, bool) {
	t.Helper()
	n, err := h.cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v, ok := n.Annotations[netv1alpha1.AnnotationInterconnectDesired]
	return v, ok
}

func (h *harness) object(t *testing.T) *netv1alpha1.Interconnect {
	t.Helper()
	ic, err := Store{Client: h.dyn}.Get(context.Background(), Name)
	if err != nil {
		t.Fatalf("get interconnect: %v", err)
	}
	return ic
}

func (h *harness) nodePatches() int {
	n := 0
	for _, a := range h.cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "nodes" {
			n++
		}
	}
	return n
}

func kubeNode(name string, annotations map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations}}
}

func interconnect(enabled bool, excluded ...string) *netv1alpha1.Interconnect {
	return &netv1alpha1.Interconnect{
		ObjectMeta: metav1.ObjectMeta{Name: Name},
		Spec:       netv1alpha1.InterconnectSpec{Medium: netv1alpha1.MediumThunderbolt, Enabled: enabled, ExcludedNodes: excluded},
	}
}

func cabledPair(t *testing.T) []*corev1.Node {
	return []*corev1.Node{
		kubeNode("a", map[string]string{netv1alpha1.AnnotationInterconnectReport: rep(t, []string{"A1"}, []string{"B1"}, []string{"b"})}),
		kubeNode("b", map[string]string{netv1alpha1.AnnotationInterconnectReport: rep(t, []string{"B1"}, []string{"A1"}, []string{"a"})}),
	}
}

func testResolverController(t *testing.T) {
	ctx := context.Background()
	wantDesired := `{"schema":1,"interconnect":"thunderbolt","fallback":"network"}`

	t.Run("auto-create is disabled", func(t *testing.T) {
		h := newHarness(t, cabledPair(t), nil)
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		ic := h.object(t)
		if ic.Spec.Enabled || ic.Spec.Medium != netv1alpha1.MediumThunderbolt || ic.Spec.Fallback != netv1alpha1.InterconnectFallbackNetwork {
			t.Errorf("auto-created spec = %+v, want thunderbolt, fallback network, enabled false", ic.Spec)
		}
		if h.nodePatches() != 0 {
			t.Error("the auto-create reconcile wrote node annotations")
		}
	})

	t.Run("no cabled peer creates nothing", func(t *testing.T) {
		h := newHarness(t, []*corev1.Node{kubeNode("a", map[string]string{
			netv1alpha1.AnnotationInterconnectReport: rep(t, []string{"A1"}, nil, nil),
		})}, nil)
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if _, err := (Store{Client: h.dyn}).Get(ctx, Name); !apierrors.IsNotFound(err) {
			t.Errorf("Get = %v, want NotFound", err)
		}
	})

	t.Run("desired written only when enabled and not excluded", func(t *testing.T) {
		h := newHarness(t, cabledPair(t), interconnect(true, "b"))
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if v, _ := h.annotation(t, "a"); v != wantDesired {
			t.Errorf("a desired = %q, want %q", v, wantDesired)
		}
		if v, ok := h.annotation(t, "b"); ok {
			t.Errorf("excluded b carries desired %q", v)
		}

		off := newHarness(t, cabledPair(t), interconnect(false))
		if err := off.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if off.nodePatches() != 0 {
			t.Error("a disabled interconnect wrote a desired annotation")
		}
	})

	t.Run("a node-written desired annotation is reverted", func(t *testing.T) {
		nodes := cabledPair(t)
		nodes[0].Annotations[netv1alpha1.AnnotationInterconnectDesired] = `{"schema":1,"interconnect":"thunderbolt","fallback":"none"}`
		nodes[1].Annotations[netv1alpha1.AnnotationInterconnectDesired] = wantDesired
		h := newHarness(t, nodes, interconnect(false))
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		for _, n := range []string{"a", "b"} {
			if v, ok := h.annotation(t, n); ok {
				t.Errorf("%s desired = %q survived a disabled interconnect", n, v)
			}
		}
		// Enabled: a disagreeing value is overwritten with the server's.
		nodes = cabledPair(t)
		nodes[0].Annotations[netv1alpha1.AnnotationInterconnectDesired] = `{"schema":1,"interconnect":"thunderbolt","fallback":"none"}`
		h = newHarness(t, nodes, interconnect(true))
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if v, _ := h.annotation(t, "a"); v != wantDesired {
			t.Errorf("a desired = %q, want the server's %q", v, wantDesired)
		}
	})

	t.Run("no clear on an unsynced cache or a failed read", func(t *testing.T) {
		nodes := cabledPair(t)
		nodes[0].Annotations[netv1alpha1.AnnotationInterconnectDesired] = wantDesired
		h := newHarness(t, nodes, interconnect(false))
		h.synced = false
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if h.nodePatches() != 0 {
			t.Error("an unsynced cache cleared a desired annotation")
		}

		empty := newHarness(t, nil, interconnect(false))
		if err := empty.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if len(empty.dyn.Actions()) != 0 {
			t.Error("an empty node cache read or wrote the Interconnect")
		}

		failing := newHarness(t, nodes, interconnect(false))
		failing.dyn.PrependReactor("get", "interconnects", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver unavailable")
		})
		if err := failing.resolver().Reconcile(ctx); err == nil {
			t.Error("a failed Interconnect read must be reported")
		}
		if failing.nodePatches() != 0 {
			t.Error("a failed Interconnect read cleared a desired annotation")
		}

	})

	t.Run("a missing object means disarmed", func(t *testing.T) {
		nodes := cabledPair(t)
		h := newHarness(t, nodes, interconnect(true))
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		for _, n := range []string{"a", "b"} {
			if v, _ := h.annotation(t, n); v != wantDesired {
				t.Fatalf("armed: %s desired = %q", n, v)
			}
		}
		// The object is deleted; the cache now shows the armed annotations.
		if err := h.dyn.Resource(GVR).Delete(ctx, Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"a", "b"} {
			live, err := h.cs.CoreV1().Nodes().Get(ctx, n, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := h.nodes.Update(live); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		for _, n := range []string{"a", "b"} {
			if v, ok := h.annotation(t, n); ok {
				t.Errorf("%s keeps desired %q after the Interconnect was deleted", n, v)
			}
		}
		if ic := h.object(t); ic.Spec.Enabled {
			t.Errorf("re-created object is armed: %+v", ic.Spec)
		}
	})

	t.Run("an unrecorded arming is recorded as unknown with a Warning", func(t *testing.T) {
		h := newHarness(t, cabledPair(t), interconnect(true))
		h.now = t0.Add(time.Minute)
		h.renewLeases(t, cabledPair(t), h.now)
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		st := h.object(t).Status
		if st.ArmedBy != UnknownIdentity || st.ArmedAt == nil || !st.ArmedAt.Time.Equal(h.now) {
			t.Errorf("armedBy=%q armedAt=%v, want unknown at %v", st.ArmedBy, st.ArmedAt, h.now)
		}
		if !drained(h.rec, eventUnrecordedArm) {
			t.Error("no Warning Event for an unrecorded arming")
		}
		// A recorded arming is left alone.
		ic := interconnect(true)
		ic.Status.ArmedBy = "system:admin"
		h = newHarness(t, cabledPair(t), ic)
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if got := h.object(t).Status.ArmedBy; got != "system:admin" {
			t.Errorf("armedBy = %q, want the recorded identity kept", got)
		}
		if drained(h.rec, eventUnrecordedArm) {
			t.Error("a recorded arming raised the unrecorded Warning")
		}
	})

	t.Run("duplicate indices and nodes without an index are reported", func(t *testing.T) {
		nodes := append(cabledPair(t), kubeNode("c", map[string]string{
			netv1alpha1.AnnotationInterconnectReport: rep(t, []string{"C1"}, []string{"A1"}, []string{"a"}),
		}), kubeNode("d", nil))
		h := newHarness(t, nodes, interconnect(true))
		h.indices["c"] = 1 // b's index
		delete(h.indices, "d")
		h.invalid = map[string]string{"d": `pod CIDR "garbage": not a CIDR`}
		r := h.resolver()
		for range 2 {
			if err := r.Reconcile(ctx); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
		}
		var uniq *metav1.Condition
		for i, c := range h.object(t).Status.Conditions {
			if c.Type == ConditionIndexUnique {
				uniq = &h.object(t).Status.Conditions[i]
			}
		}
		if uniq == nil || uniq.Status != metav1.ConditionFalse || uniq.Reason != ReasonDuplicateClusterIndex ||
			!strings.Contains(uniq.Message, "b, c") {
			t.Errorf("IndexUnique = %+v, want False naming b and c", uniq)
		}
		events := 0
		for len(h.rec.Events) > 0 {
			if strings.Contains(<-h.rec.Events, eventNoClusterIndex) {
				events++
			}
		}
		if events != 1 {
			t.Errorf("%d no-index Events over two reconciles, want exactly one", events)
		}
	})

	t.Run("status, conditions and hysteresis survive a resolver restart", func(t *testing.T) {
		nodes := append(cabledPair(t), kubeNode("z", map[string]string{
			netv1alpha1.AnnotationInterconnectReport: rep(t, []string{"Z1"}, []string{"A1"}, []string{"a"}),
		}))
		h := newHarness(t, nodes, interconnect(true))
		h.indices["z"] = 31
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		st := h.object(t).Status
		if len(st.Members) != 3 || st.Members[0].State != netv1alpha1.InterconnectMemberDown {
			t.Fatalf("first status = %+v, want three members, held down", st.Members)
		}
		cond := meta.FindStatusCondition(st.Conditions, ConditionIndexInRange)
		if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != netv1alpha1.ReasonInterconnectIndexOutOfRange || !strings.Contains(cond.Message, "z") {
			t.Errorf("conditions = %+v, want IndexInRange False naming z", st.Conditions)
		}
		// A new resolver (a restart or a failover) 30 s later keeps holding...
		h.now = t0.Add(30 * time.Second)
		h.renewLeases(t, nodes, h.now)
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if m := h.object(t).Status.Members[0]; m.State != netv1alpha1.InterconnectMemberDown {
			t.Fatalf("a at +30 s after a restart = %+v, want held", m)
		}
		// ...and a third one promotes at +60 s from the persisted time.
		h.now = t0.Add(UpHold)
		h.renewLeases(t, nodes, h.now)
		if err := h.resolver().Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		st = h.object(t).Status
		if st.Members[0].State != netv1alpha1.InterconnectMemberUp || st.Members[1].State != netv1alpha1.InterconnectMemberUp {
			t.Errorf("members at +60 s = %+v, want a and b up", st.Members)
		}
		if len(st.Segments) != 1 || !reflect.DeepEqual(st.Segments[0].Nodes, []string{"a", "b"}) {
			t.Errorf("segments = %+v, want one of a and b", st.Segments)
		}
	})

	t.Run("a stale node lease drops the report", func(t *testing.T) {
		h := newHarness(t, cabledPair(t), interconnect(true))
		h.now = t0.Add(2 * time.Duration(defaultNodeLeaseSeconds) * time.Second)
		r := h.resolver()
		if err := r.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if st := h.object(t).Status; len(st.Members) != 0 {
			t.Errorf("members = %+v; reports of nodes with stale leases must be dropped", st.Members)
		}
		select {
		case ev := <-h.rec.Events:
			if !strings.Contains(ev, eventReportRejected) {
				t.Errorf("event = %q, want %s", ev, eventReportRejected)
			}
		default:
			t.Error("no Event for a rejected report")
		}
	})
}

// drained reports whether any recorded Event so far carries reason, consuming
// them.
func drained(rec *record.FakeRecorder, reason string) bool {
	found := false
	for len(rec.Events) > 0 {
		if strings.Contains(<-rec.Events, reason) {
			found = true
		}
	}
	return found
}
