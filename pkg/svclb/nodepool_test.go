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

package svclb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
)

// errBusy is the fake binder's port-conflict error.
var errBusy = errors.New("address already in use")

// testNodeAddr is node-a's server-held address in the decider fixtures.
var testNodeAddr = netip.MustParseAddr("100.64.0.1")

// storeSnapshot lists the Nodes and Services currently in cs, the shape the
// decider and the hosters read from their informer caches.
func storeSnapshot(t *testing.T, cs *fake.Clientset) ([]*corev1.Node, []*corev1.Service) {
	t.Helper()
	ctx := context.Background()
	nl, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	sl, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	nodes := make([]*corev1.Node, 0, len(nl.Items))
	for i := range nl.Items {
		nodes = append(nodes, &nl.Items[i])
	}
	svcs := make([]*corev1.Service, 0, len(sl.Items))
	for i := range sl.Items {
		svcs = append(svcs, &sl.Items[i])
	}
	return nodes, svcs
}

// fakeClock is a settable clock for the decider's hold-down and distrust bound.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// poolRig is one fake store with a decider and a hoster per node, the
// multi-node shape: the decider on the server, a hoster in every node process.
type poolRig struct {
	t       *testing.T
	cs      *fake.Clientset
	d       *Decider
	rec     *record.FakeRecorder
	clock   *fakeClock
	hosters map[string]*Hoster
	binders map[string]*fakeBinder
	addrs   map[string]netip.Addr
}

// newPoolRig seeds Ready nodes (name -> labels) and the Services, gives every
// node a server-held mesh address (node-a is the server's own node), lands
// every hoster's reset, and starts the decider's clock past its hold-down.
func newPoolRig(t *testing.T, nodes map[string]map[string]string, svcs ...*corev1.Service) *poolRig {
	t.Helper()
	ctx := context.Background()
	cs := fake.NewClientset()
	r := &poolRig{
		t:       t,
		cs:      cs,
		rec:     record.NewFakeRecorder(64),
		clock:   &fakeClock{t: time.Unix(1_000_000, 0)},
		hosters: map[string]*Hoster{},
		binders: map[string]*fakeBinder{},
		addrs:   map[string]netip.Addr{},
	}
	names := make([]string, 0, len(nodes))
	for n := range nodes {
		names = append(names, n)
	}
	slices.Sort(names)
	for i, n := range names {
		if _, err := cs.CoreV1().Nodes().Create(ctx, testNodeObject(n, nodes[n]), metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed node %s: %v", n, err)
		}
		r.addrs[n] = netip.AddrFrom4([4]byte{100, 64, byte(i), 1})
	}
	for _, s := range svcs {
		if _, err := cs.CoreV1().Services(s.Namespace).Create(ctx, s, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed service %s: %v", s.Name, err)
		}
	}
	for _, n := range names {
		r.binders[n] = &fakeBinder{}
		r.hosters[n] = newTestHoster(t, cs, n, r.binders[n], map[int32]bool{}, nil)
	}
	r.d = r.newDecider()
	return r
}

// newDecider builds a decider over the rig's store whose start is a hold-down
// in the past, unless a test resets startedAt.
func (r *poolRig) newDecider() *Decider {
	peers := func(context.Context) (map[string]netip.Addr, error) {
		out := map[string]netip.Addr{}
		for n, a := range r.addrs {
			if n != testNode {
				out[n] = a
			}
		}
		return out, nil
	}
	d, err := NewDecider(DeciderConfig{
		Client:        r.cs,
		SelfNode:      testNode,
		SelfAddr:      r.addrs[testNode],
		PeerAddresses: peers,
		Recorder:      r.rec,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		r.t.Fatalf("NewDecider: %v", err)
	}
	d.now = r.clock.now
	d.startedAt = r.clock.t.Add(-2 * DefaultHoldDown)
	return d
}

// decide runs one decider pass over the store.
func (r *poolRig) decide() {
	r.t.Helper()
	nodes, svcs := storeSnapshot(r.t, r.cs)
	r.d.reconcile(context.Background(), nodes, svcs)
}

// host runs one pass of the named hoster over the store.
func (r *poolRig) host(name string) {
	r.t.Helper()
	nodes, svcs := storeSnapshot(r.t, r.cs)
	var own *corev1.Node
	for _, n := range nodes {
		if n.Name == name {
			own = n
		}
	}
	r.hosters[name].step(context.Background(), svcs, own)
}

// converge runs decide, every hoster, decide.
func (r *poolRig) converge() {
	r.t.Helper()
	r.decide()
	for _, n := range slices.Sorted(maps.Keys(r.hosters)) {
		r.host(n)
	}
	r.decide()
}

func (r *poolRig) svc(name string) *corev1.Service {
	r.t.Helper()
	s, err := r.cs.CoreV1().Services("default").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		r.t.Fatalf("get service %s: %v", name, err)
	}
	return s
}

func (r *poolRig) ingress(name string) []string {
	r.t.Helper()
	var out []string
	for _, i := range r.svc(name).Status.LoadBalancer.Ingress {
		out = append(out, i.IP)
	}
	return out
}

func (r *poolRig) stamp(name string) (string, bool) {
	r.t.Helper()
	v, ok := r.svc(name).Annotations[HostsAnnotation]
	return v, ok
}

func (r *poolRig) addr(node string) string { return r.addrs[node].String() }

// mutateNode applies f to the named Node in the store.
func (r *poolRig) mutateNode(name string, f func(*corev1.Node)) {
	r.t.Helper()
	ctx := context.Background()
	n, err := r.cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		r.t.Fatalf("get node %s: %v", name, err)
	}
	f(n)
	if _, err := r.cs.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{}); err != nil {
		r.t.Fatalf("update node %s: %v", name, err)
	}
}

func setReady(status corev1.ConditionStatus) func(*corev1.Node) {
	return func(n *corev1.Node) {
		n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}}
	}
}

// servicePatches counts the patch actions issued against Services.
func servicePatches(cs *fake.Clientset) int {
	n := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "services" {
			n++
		}
	}
	return n
}

func (r *poolRig) events() []string {
	var out []string
	for {
		select {
		case e := <-r.rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// poolService is an unstamped LoadBalancer Service with the given labels.
func poolService(name string, port int32, labels map[string]string) *corev1.Service {
	s := lbService("default", name, "10.43.1."+name[len(name)-1:], port)
	delete(s.Annotations, HostsAnnotation)
	s.Labels = labels
	return s
}

// TestNodePoolSelection is the B416 gate: multi-node ServiceLB with node pools.
//
// It covers the pure halves (selectHosts, computeIngress, the report codec) and
// a fake-clientset leg that runs the decider and one hoster per node against
// one store, which is the whole protocol: the decider stamps hosts, each hoster
// binds and reports on its own Node, and the decider writes the replaced status
// slice. The binding resolutions each have a case: P1 (server-held addresses
// only), P2 (allow-list mode on enablelb=true only), P4 (a report is trusted
// per incarnation across a Ready transition), P5 (start-up hold-down), P7
// (replace-on-reconcile) and P8/P10 (the per-node Event).
//
// The report channel's authorization (a node may patch BoundAnnotation on its
// own Node and is denied on another's, and the Virtual Kubelet status heartbeat
// leaves the annotation intact) needs a real apiserver with the Node authorizer
// and NodeRestriction. That proof is the subtest of the same name in
// e2e/b416_test.go (build tag e2e), run by hack/lab/b416.sh's integration tier;
// the "own-node report write" subtest here pins that the hoster's write is
// exactly the request that proof authorizes.
func TestNodePoolSelection(t *testing.T) {
	ctx := context.Background()

	t.Run("selectHosts", func(t *testing.T) {
		type node struct {
			name   string
			labels map[string]string
		}
		tests := []struct {
			name   string
			nodes  []node
			svc    map[string]string
			addrs  map[string]string // nil: every node gets a server-held address
			want   []string
			cordon bool
		}{
			{name: "no labels anywhere", nodes: []node{{"a", nil}, {"b", nil}}, want: []string{"a", "b"}},
			{name: "allow-list on", nodes: []node{{"a", map[string]string{EnableLBLabel: "true"}}, {"b", nil}}, want: []string{"a"}},
			{name: "allow-list on, value not true", nodes: []node{
				{"a", map[string]string{EnableLBLabel: "true"}}, {"b", map[string]string{EnableLBLabel: "false"}},
			}, want: []string{"a"}},
			// P2: only "true" turns allow-list mode on, so a node labelling itself
			// "false" cannot starve every other host.
			{name: "P2 a false value alone leaves allow-list mode off", nodes: []node{
				{"a", map[string]string{EnableLBLabel: "false"}}, {"b", nil},
			}, want: []string{"a", "b"}},
			{name: "P2 an empty value alone leaves allow-list mode off", nodes: []node{
				{"a", map[string]string{EnableLBLabel: ""}}, {"b", nil},
			}, want: []string{"a", "b"}},
			{name: "single pool", nodes: []node{
				{"a", map[string]string{LBPoolLabel: "x"}}, {"b", map[string]string{LBPoolLabel: "y"}},
			}, svc: map[string]string{LBPoolLabel: "x"}, want: []string{"a"}},
			{name: "multi-pool form", nodes: []node{
				{"a", map[string]string{LBPoolNodeLabelPrefix + "x": "true"}}, {"b", nil},
			}, svc: map[string]string{LBPoolLabel: "x"}, want: []string{"a"}},
			{name: "single OR multi", nodes: []node{
				{"a", map[string]string{LBPoolLabel: "x"}},
				{"b", map[string]string{LBPoolNodeLabelPrefix + "x": "true"}},
				{"c", map[string]string{LBPoolLabel: "y"}},
			}, svc: map[string]string{LBPoolLabel: "x"}, want: []string{"a", "b"}},
			{name: "node in two pools", nodes: []node{
				{"a", map[string]string{LBPoolNodeLabelPrefix + "x": "true", LBPoolNodeLabelPrefix + "y": "true"}},
				{"b", map[string]string{LBPoolNodeLabelPrefix + "x": "true"}},
			}, svc: map[string]string{LBPoolLabel: "y"}, want: []string{"a"}},
			{name: "multi-pool value not true", nodes: []node{
				{"a", map[string]string{LBPoolNodeLabelPrefix + "x": "false"}}, {"b", map[string]string{LBPoolLabel: "x"}},
			}, svc: map[string]string{LBPoolLabel: "x"}, want: []string{"b"}},
			{name: "pool AND allow-list", nodes: []node{
				{"a", map[string]string{EnableLBLabel: "true", LBPoolLabel: "x"}}, {"b", map[string]string{LBPoolLabel: "x"}},
			}, svc: map[string]string{LBPoolLabel: "x"}, want: []string{"a"}},
			{name: "unknown pool", nodes: []node{{"a", map[string]string{LBPoolLabel: "x"}}}, svc: map[string]string{LBPoolLabel: "z"}, want: nil},
			{name: "k3s keys ignored", nodes: []node{
				{"a", map[string]string{"svccontroller.k3s.cattle.io/enablelb": "true"}}, {"b", nil},
			}, svc: map[string]string{"svccontroller.k3s.cattle.io/lbpool": "x"}, want: []string{"a", "b"}},
			// P1: the address comes from server-held data only.
			{name: "P1 no server-held address", nodes: []node{{"a", nil}, {"b", nil}},
				addrs: map[string]string{"b": "100.64.1.1"}, want: []string{"b"}},
			{name: "P1 a loopback server-held address", nodes: []node{{"a", nil}, {"b", nil}},
				addrs: map[string]string{"a": "127.0.0.1", "b": "100.64.1.1"}, want: []string{"b"}},
			{name: "cordon does not remove a host", nodes: []node{{"a", nil}, {"b", nil}}, want: []string{"a", "b"}, cordon: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var nodes []*corev1.Node
				addrs := map[string]netip.Addr{}
				for i, n := range tt.nodes {
					obj := testNodeObject(n.name, n.labels)
					// A node-written InternalIP is present on every node and must
					// never stand in for a missing server-held address (P1).
					obj.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.1" + string(rune('0'+i))}}
					if tt.cordon {
						obj.Spec.Unschedulable = true
					}
					nodes = append(nodes, obj)
					if tt.addrs == nil {
						addrs[n.name] = netip.AddrFrom4([4]byte{100, 64, byte(i), 1})
					}
				}
				for n, a := range tt.addrs {
					addrs[n] = netip.MustParseAddr(a)
				}
				svc := poolService("svc1", 80, tt.svc)
				if got := selectHosts(nodes, svc, addrs); !slices.Equal(got, tt.want) {
					t.Errorf("selectHosts = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("computeIngress", func(t *testing.T) {
		svc := poolService("svc1", 80, nil)
		entry := reportEntry(svc)
		addrs := map[string]netip.Addr{"a": netip.MustParseAddr("100.64.0.1"), "b": netip.MustParseAddr("100.64.1.1")}
		ready := func(n string) *corev1.Node { return testNodeObject(n, nil) }
		notReady := func(n string) *corev1.Node {
			o := testNodeObject(n, nil)
			o.Status.Conditions[0].Status = corev1.ConditionFalse
			return o
		}
		rep := func(entries ...string) boundReport {
			r := boundReport{incarnation: "i", entries: map[string]bool{}}
			for _, e := range entries {
				r.entries[e] = true
			}
			return r
		}
		tests := []struct {
			name    string
			nodes   []*corev1.Node
			hosts   []string
			reports map[string]boundReport
			want    []string
		}{
			{"both report", []*corev1.Node{ready("b"), ready("a")}, []string{"a", "b"},
				map[string]boundReport{"a": rep(entry), "b": rep(entry)}, []string{"100.64.0.1", "100.64.1.1"}},
			{"one failed bind", []*corev1.Node{ready("a"), ready("b")}, []string{"a", "b"},
				map[string]boundReport{"a": rep(entry), "b": rep()}, []string{"100.64.0.1"}},
			{"stale uid", []*corev1.Node{ready("a"), ready("b")}, []string{"a", "b"},
				map[string]boundReport{"a": rep(entry), "b": rep("default/svc1:old-uid")}, []string{"100.64.0.1"}},
			{"not Ready", []*corev1.Node{ready("a"), notReady("b")}, []string{"a", "b"},
				map[string]boundReport{"a": rep(entry), "b": rep(entry)}, []string{"100.64.0.1"}},
			{"reporting but not in the stamp", []*corev1.Node{ready("a"), ready("b")}, []string{"a"},
				map[string]boundReport{"a": rep(entry), "b": rep(entry)}, []string{"100.64.0.1"}},
			{"nothing reports", []*corev1.Node{ready("a")}, []string{"a"}, nil, nil},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got []string
				for _, i := range computeIngress(tt.nodes, svc, tt.hosts, addrs, tt.reports) {
					got = append(got, i.IP)
				}
				if !slices.Equal(got, tt.want) {
					t.Errorf("computeIngress = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("bound report codec", func(t *testing.T) {
		v, truncated := formatBound("inc1", []string{"ns/b:u2", "ns/a:u1"})
		if truncated || v != "inc1;ns/a:u1,ns/b:u2" {
			t.Fatalf("formatBound = %q truncated=%v, want sorted entries after the incarnation", v, truncated)
		}
		r, ok := parseBound(v)
		if !ok || r.incarnation != "inc1" || !r.entries["ns/a:u1"] || !r.entries["ns/b:u2"] || len(r.entries) != 2 {
			t.Fatalf("parseBound(%q) = %+v, %v", v, r, ok)
		}
		if r, ok := parseBound("inc2;"); !ok || len(r.entries) != 0 {
			t.Errorf("a reset report must parse to no entries, got %+v %v", r, ok)
		}
		// The value is node-written: the reader bounds it to what a hoster writes.
		if _, ok := parseBound(strings.Repeat("i", maxIncarnationLen) + ";ns/a:u1"); !ok {
			t.Error("an incarnation at the cap must parse")
		}
		oversized := "inc;" + strings.Repeat("x", maxBoundBytes)
		longInc := strings.Repeat("i", maxIncarnationLen+1) + ";ns/a:u1"
		for _, bad := range []string{"", "no-separator", ";ns/a:u1", oversized, longInc} {
			if _, ok := parseBound(bad); ok {
				t.Errorf("parseBound(%.40q... len %d) must be no report", bad, len(bad))
			}
		}
		var many []string
		for i := 0; i < 4000; i++ {
			many = append(many, "a-long-namespace-name/a-long-service-name-"+strings.Repeat("x", 8)+":"+string(rune('a'+i%26)))
		}
		v, truncated = formatBound("inc", many)
		if !truncated || len(v) > maxBoundBytes {
			t.Errorf("an oversized report must be truncated under the cap: len=%d truncated=%v", len(v), truncated)
		}
	})

	t.Run("own-node report write", func(t *testing.T) {
		cs := fake.NewClientset(testNodeObject("node-x", nil))
		if err := PatchBoundReport(ctx, cs, "node-x", "inc;default/a:u"); err != nil {
			t.Fatal(err)
		}
		var patch k8stesting.PatchAction
		for _, a := range cs.Actions() {
			if p, ok := a.(k8stesting.PatchAction); ok {
				patch = p
			}
		}
		if patch == nil || patch.GetResource().Resource != "nodes" || patch.GetName() != "node-x" || patch.GetSubresource() != "" {
			t.Fatalf("the report must be a patch of the node's own Node object, got %#v", patch)
		}
		if patch.GetPatchType() != types.MergePatchType {
			t.Errorf("patch type = %s, want a JSON merge patch", patch.GetPatchType())
		}
		var body map[string]any
		if err := json.Unmarshal(patch.GetPatch(), &body); err != nil {
			t.Fatal(err)
		}
		meta, _ := body["metadata"].(map[string]any)
		ann, _ := meta["annotations"].(map[string]any)
		if len(body) != 1 || len(meta) != 1 || len(ann) != 1 || ann[BoundAnnotation] != "inc;default/a:u" {
			t.Errorf("patch body = %s, want ONLY metadata.annotations[%s]", patch.GetPatch(), BoundAnnotation)
		}
	})

	twoNodes := map[string]map[string]string{testNode: nil, "node-b": nil}

	t.Run("both hosts report: ingress lists both", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		if s, _ := r.stamp("lb1"); s != "node-a,node-b" {
			t.Fatalf("stamp = %q, want node-a,node-b", s)
		}
		if got, want := r.ingress("lb1"), []string{r.addr(testNode), r.addr("node-b")}; !slices.Equal(got, want) {
			t.Errorf("ingress = %v, want %v", got, want)
		}
		if !r.binders[testNode].boundPorts()[18080] || !r.binders["node-b"].boundPorts()[18080] {
			t.Error("both hosts must bind the port")
		}
	})

	t.Run("allow-list mode narrows the stamp and closes the dropped host", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		r.mutateNode(testNode, func(n *corev1.Node) { n.Labels = map[string]string{EnableLBLabel: "true"} })
		r.converge()
		if s, _ := r.stamp("lb1"); s != testNode {
			t.Errorf("stamp = %q, want only %s", s, testNode)
		}
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Errorf("ingress = %v, want only %s", got, r.addr(testNode))
		}
		if len(r.hosters["node-b"].forwarders) != 0 {
			t.Error("node-b's listener must be closed once it leaves the stamp")
		}
		// Removing the last enablelb label turns allow-list mode back off.
		r.mutateNode(testNode, func(n *corev1.Node) { n.Labels = nil })
		r.converge()
		if s, _ := r.stamp("lb1"); s != "node-a,node-b" {
			t.Errorf("after the last enablelb label is removed, stamp = %q, want node-a,node-b", s)
		}
	})

	t.Run("P2 a node labelling itself enablelb=false does not starve the others", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.mutateNode("node-b", func(n *corev1.Node) { n.Labels = map[string]string{EnableLBLabel: "false"} })
		r.converge()
		if s, _ := r.stamp("lb1"); s != "node-a,node-b" {
			t.Errorf("stamp = %q, want node-a,node-b (allow-list mode needs a true value)", s)
		}
	})

	t.Run("a node leaving a pool retracts only itself", func(t *testing.T) {
		pool := map[string]string{LBPoolLabel: "x"}
		r := newPoolRig(t, map[string]map[string]string{testNode: pool, "node-b": pool, "node-c": nil},
			poolService("lb1", 18080, pool))
		r.converge()
		if got, want := r.ingress("lb1"), []string{r.addr(testNode), r.addr("node-b")}; !slices.Equal(got, want) {
			t.Fatalf("ingress = %v, want %v", got, want)
		}
		bListener := r.hosters["node-b"].forwarders["default/lb1"][18080]
		r.mutateNode(testNode, func(n *corev1.Node) { n.Labels = nil })
		r.converge()
		if s, _ := r.stamp("lb1"); s != "node-b" {
			t.Errorf("stamp = %q, want node-b", s)
		}
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr("node-b")}) {
			t.Errorf("ingress = %v, want only node-b's %s", got, r.addr("node-b"))
		}
		if len(r.hosters[testNode].forwarders) != 0 {
			t.Error("node-a's listener must be closed once it leaves the pool")
		}
		if r.hosters["node-b"].forwarders["default/lb1"][18080] != bListener {
			t.Error("node-b's listener must be untouched (not reopened)")
		}
		if reportOf(t, r.cs, testNode).entries[reportEntry(r.svc("lb1"))] {
			t.Error("node-a must withdraw its report")
		}
	})

	t.Run("a failed bind keeps the node out and is evented after the hold-down", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.binders["node-b"].fail = map[uint16]error{18080: errBusy}
		r.converge()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Errorf("ingress = %v, want only node-a", got)
		}
		if ev := r.events(); slices.ContainsFunc(ev, func(e string) bool { return strings.Contains(e, EventReasonHostNotBound) }) {
			t.Errorf("no HostNotBound before the hold-down elapses, got %q", ev)
		}
		r.clock.advance(DefaultHoldDown)
		r.decide()
		ev := r.events()
		if len(ev) != 1 || !strings.Contains(ev[0], "Warning "+EventReasonHostNotBound) || !strings.Contains(ev[0], "node-b") {
			t.Errorf("events = %q, want one HostNotBound naming node-b", ev)
		}
		r.decide()
		if ev := r.events(); len(ev) != 0 {
			t.Errorf("the HostNotBound Event must be recorded once, got %q", ev)
		}
	})

	t.Run("P8 a host that never wrote a report is logged, not evented", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		var buf bytes.Buffer
		r.d.log = slog.New(slog.NewTextHandler(&buf, nil))
		// node-b runs an agent from before the report existed: no annotation, and
		// its hoster never runs.
		r.mutateNode("node-b", func(n *corev1.Node) { delete(n.Annotations, BoundAnnotation) })
		r.decide()
		r.host(testNode)
		r.decide()
		r.clock.advance(DefaultHoldDown)
		r.decide()
		r.decide()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Errorf("ingress = %v, want only node-a", got)
		}
		if ev := r.events(); len(ev) != 0 {
			t.Errorf("events = %q, want none for a host that has never reported", ev)
		}
		if n := strings.Count(buf.String(), "has not reported any bound services"); n != 1 || !strings.Contains(buf.String(), "node=node-b") {
			t.Errorf("want one Info line naming node-b, got %d in %q", n, buf.String())
		}
		// Once node-b's hoster runs and fails to bind, the Event fires after the
		// hold-down as usual.
		r.binders["node-b"].fail = map[uint16]error{18080: errBusy}
		if err := r.hosters["node-b"].Reset(ctx); err != nil {
			t.Fatal(err)
		}
		r.host("node-b")
		r.decide()
		r.clock.advance(DefaultHoldDown)
		r.decide()
		if ev := r.events(); len(ev) != 1 || !strings.Contains(ev[0], EventReasonHostNotBound) {
			t.Errorf("events = %q, want one HostNotBound once node-b reports", ev)
		}
	})

	t.Run("a clean hoster shutdown withdraws its report", func(t *testing.T) {
		cs := fake.NewClientset(testNodeObject(testNode, nil))
		svc := lbService("default", "lb1", "10.43.1.1", 18080)
		if _, err := cs.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		h := newTestHoster(t, cs, testNode, &fakeBinder{}, map[int32]bool{}, nil)
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- h.Run(runCtx) }()
		deadline := time.Now().Add(10 * time.Second)
		for !reportOf(t, cs, testNode).entries[reportEntry(svc)] {
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("the running hoster never reported lb1 bound")
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		if r := reportOf(t, cs, testNode); len(r.entries) != 0 {
			t.Errorf("after a clean stop the report lists %v, want no entries (the node must not stay advertised)", r.entries)
		}
	})

	t.Run("a stale uid after Service recreation is not advertised", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		if err := r.cs.CoreV1().Services("default").Delete(ctx, "lb1", metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		again := poolService("lb1", 18080, nil)
		again.UID = "uid-recreated"
		if _, err := r.cs.CoreV1().Services("default").Create(ctx, again, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		// Only node-a's hoster runs: node-b still reports the previous uid.
		r.decide()
		r.host(testNode)
		r.decide()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Errorf("ingress = %v, want only node-a (node-b's report names the previous uid)", got)
		}
	})

	t.Run("a not-Ready host leaves the status but stays in the stamp", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		r.mutateNode("node-b", setReady(corev1.ConditionFalse))
		r.decide()
		if s, _ := r.stamp("lb1"); s != "node-a,node-b" {
			t.Errorf("stamp = %q, want node-b kept in the stamp", s)
		}
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Errorf("ingress = %v, want only node-a", got)
		}
	})

	t.Run("a Service turned ClusterIP loses its stamp and status", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		s := r.svc("lb1")
		s.Spec.Type = corev1.ServiceTypeClusterIP
		if _, err := r.cs.CoreV1().Services("default").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		r.converge()
		if _, ok := r.stamp("lb1"); ok {
			t.Error("the stamp must be removed")
		}
		if got := r.ingress("lb1"); len(got) != 0 {
			t.Errorf("ingress = %v, want cleared", got)
		}
		if len(r.hosters[testNode].forwarders)+len(r.hosters["node-b"].forwarders) != 0 {
			t.Error("every listener must be closed")
		}
	})

	t.Run("an unknown pool stamps no host and records NoEligibleNodes once", func(t *testing.T) {
		r := newPoolRig(t, map[string]map[string]string{testNode: {LBPoolLabel: "x"}}, poolService("lb1", 18080, map[string]string{LBPoolLabel: "z"}))
		r.converge()
		if s, ok := r.stamp("lb1"); !ok || s != "" {
			t.Errorf("stamp = %q (present=%v), want present and empty", s, ok)
		}
		if got := r.ingress("lb1"); len(got) != 0 {
			t.Errorf("ingress = %v, want pending", got)
		}
		ev := r.events()
		if len(ev) != 1 || !strings.Contains(ev[0], "Warning "+EventReasonNoEligibleNodes) {
			t.Errorf("events = %q, want one NoEligibleNodes", ev)
		}
		r.decide()
		if ev := r.events(); len(ev) != 0 {
			t.Errorf("NoEligibleNodes must be recorded once, got %q", ev)
		}
	})

	t.Run("an unchanged host set issues no Service patch", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		r.cs.ClearActions()
		r.converge()
		if n := servicePatches(r.cs); n != 0 {
			t.Errorf("a converged pass issued %d Service patches, want 0", n)
		}
	})

	t.Run("P7 a lost status write is repaired on the next pass", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		s := r.svc("lb1")
		s.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.99"}}
		if _, err := r.cs.CoreV1().Services("default").UpdateStatus(ctx, s, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		r.decide()
		if got, want := r.ingress("lb1"), []string{r.addr(testNode), r.addr("node-b")}; !slices.Equal(got, want) {
			t.Errorf("ingress = %v, want the recomputed %v (replace, not filter)", got, want)
		}
	})

	t.Run("P4 a report left over across a Ready transition is ignored until re-issued", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		r.mutateNode("node-b", setReady(corev1.ConditionFalse))
		r.host("node-b") // node-b's hoster sees its node not Ready
		r.decide()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Fatalf("ingress = %v, want only node-a while node-b is not Ready", got)
		}
		// node-b is Ready again but still carries the report of its previous
		// Ready period: that report may predate a restart, so it is ignored.
		r.mutateNode("node-b", setReady(corev1.ConditionTrue))
		r.decide()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Errorf("ingress = %v, want only node-a: the stale report must not be trusted", got)
		}
		// node-b's live hoster sees its own Ready transition and re-issues its
		// report under a new incarnation: trusted again.
		before := reportOf(t, r.cs, "node-b").incarnation
		r.host("node-b")
		if after := reportOf(t, r.cs, "node-b").incarnation; after == before {
			t.Fatalf("the hoster must re-issue under a new incarnation on its own Ready transition (still %q)", after)
		}
		r.decide()
		if got, want := r.ingress("lb1"), []string{r.addr(testNode), r.addr("node-b")}; !slices.Equal(got, want) {
			t.Errorf("ingress = %v, want %v once node-b re-issues", got, want)
		}
	})

	t.Run("P4 a restarted hoster resets before binding and the stale report never counts", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		r.mutateNode("node-b", setReady(corev1.ConditionFalse))
		r.decide()
		r.mutateNode("node-b", setReady(corev1.ConditionTrue))
		r.decide()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Fatalf("ingress = %v, want only node-a before the restarted hoster runs", got)
		}
		// A new process: its reset lists nothing, so node-b is still out.
		r.hosters["node-b"].closeAll()
		r.binders["node-b"] = &fakeBinder{}
		r.hosters["node-b"] = newTestHoster(t, r.cs, "node-b", r.binders["node-b"], map[int32]bool{}, nil)
		r.hosters["node-b"].incarnation = "node-b-restarted"
		if err := r.hosters["node-b"].Reset(ctx); err != nil {
			t.Fatal(err)
		}
		r.decide()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr(testNode)}) {
			t.Errorf("ingress = %v, want only node-a after the reset", got)
		}
		r.host("node-b")
		r.decide()
		if got, want := r.ingress("lb1"), []string{r.addr(testNode), r.addr("node-b")}; !slices.Equal(got, want) {
			t.Errorf("ingress = %v, want %v once the new process binds", got, want)
		}
	})

	t.Run("P4 the distrust is bounded by the hold-down", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		r.mutateNode("node-b", setReady(corev1.ConditionFalse))
		r.decide()
		r.mutateNode("node-b", setReady(corev1.ConditionTrue))
		r.decide()
		r.clock.advance(DefaultHoldDown)
		r.decide()
		if got, want := r.ingress("lb1"), []string{r.addr(testNode), r.addr("node-b")}; !slices.Equal(got, want) {
			t.Errorf("ingress = %v, want %v once the distrust bound passes", got, want)
		}
	})

	t.Run("P5 a restarted decider holds status changes down", func(t *testing.T) {
		r := newPoolRig(t, twoNodes, poolService("lb1", 18080, nil))
		r.converge()
		// The server restarts: a new decider, and the server's own node's hoster
		// restarts with it and resets its report.
		r.d = r.newDecider()
		r.d.startedAt = r.clock.t
		r.hosters[testNode].closeAll()
		r.binders[testNode] = &fakeBinder{}
		r.hosters[testNode] = newTestHoster(t, r.cs, testNode, r.binders[testNode], map[int32]bool{}, nil)
		r.hosters[testNode].incarnation = "node-a-restarted"
		if err := r.hosters[testNode].Reset(ctx); err != nil {
			t.Fatal(err)
		}
		// The restarted node-a cannot re-bind lb1's port (a pod took it).
		r.binders[testNode].fail = map[uint16]error{18080: errBusy}
		r.decide()
		if got, want := r.ingress("lb1"), []string{r.addr(testNode), r.addr("node-b")}; !slices.Equal(got, want) {
			t.Errorf("ingress = %v, want %v held during the hold-down (no cluster-wide retraction on a server restart)", got, want)
		}
		// A Service every stamped host reports is written at once, hold-down or not.
		if _, err := r.cs.CoreV1().Services("default").Create(ctx, poolService("lb2", 18081, nil), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		r.converge()
		if got := r.ingress("lb2"); len(got) != 2 {
			t.Errorf("lb2 ingress = %v, want both hosts: every stamped host reports it", got)
		}
		// Once the hold-down passes, an unreported host is dropped.
		r.clock.advance(DefaultHoldDown)
		r.converge()
		if got := r.ingress("lb1"); !slices.Equal(got, []string{r.addr("node-b")}) {
			t.Errorf("ingress = %v, want only node-b after the hold-down (node-a never re-bound)", got)
		}
	})
}
