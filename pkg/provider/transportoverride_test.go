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

package provider

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/darwin-net/pkg/proxy"
)

// The lease addresses this file feeds through the status stream. They sit in a
// vmnet-shaped NAT segment that is deliberately disjoint from the node podCIDR
// (guestPodCIDR) and from the node IP (guestNodeIP), so an override keyed or
// valued on the wrong address cannot look right by coincidence.
const (
	leaseFirst  = "192.168.64.7"
	leaseSecond = "192.168.64.9"
)

// leaseRuntimeServer is an in-memory runtimev1.RuntimeServer whose status stream
// the TEST drives: push delivers one PodStatus to whatever WatchPodStatus stream
// is live, which is the path the provider consumes in production.
//
// CreatePod deliberately answers with NO status. The provider dispatches a
// synchronous status callback for a mutating RPC in a goroutine, and a
// lease-free create snapshot landing after a pushed lease would drop the very
// override the case just installed — a race in the TEST, not in the provider,
// whose real runtime emits a fresh status per observation. Returning no status
// routes every observation in this file through the watch stream, in order.
type leaseRuntimeServer struct {
	runtimev1.UnimplementedRuntimeServer

	events chan *runtimev1.PodStatusEvent
	// echoPodIP makes every status this server emits carry back the PodBox.pod_ip
	// the provider sent at CreatePod — what a real runtimed does, since a pod's
	// reported pod_ip IS the address the box was created with. It is OFF by
	// default so this file's own cases keep an EMPTY pod_ip: the override key must
	// come from the node's guest record, never from a status the test could shape.
	echoPodIP bool

	mu     sync.Mutex
	live   map[string]struct{}
	boxIPs map[string]string // pod id -> the PodBox.pod_ip the provider sent
}

func newLeaseRuntimeServer(echoPodIP bool) *leaseRuntimeServer {
	return &leaseRuntimeServer{
		events:    make(chan *runtimev1.PodStatusEvent, 16),
		echoPodIP: echoPodIP,
		live:      map[string]struct{}{},
		boxIPs:    map[string]string{},
	}
}

func (s *leaseRuntimeServer) CreatePod(_ context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	s.mu.Lock()
	s.live[req.GetPod().GetPodId()] = struct{}{}
	s.boxIPs[req.GetPod().GetPodId()] = req.GetPod().GetPodIp()
	s.mu.Unlock()
	return &runtimev1.CreatePodResponse{}, nil
}

// boxPodIP returns the PodBox.pod_ip the provider sent for podID — the value
// podIP resolved, crossing the RPC boundary. It is what a status echoes back when
// echoPodIP is set, and "" otherwise.
func (s *leaseRuntimeServer) boxPodIP(podID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boxIPs[podID]
}

// reportedPodIP is boxPodIP gated on echoPodIP.
func (s *leaseRuntimeServer) reportedPodIP(podID string) string {
	if !s.echoPodIP {
		return ""
	}
	return s.boxPodIP(podID)
}

func (s *leaseRuntimeServer) DeletePod(_ context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	s.mu.Lock()
	delete(s.live, req.GetPodId())
	s.mu.Unlock()
	return &runtimev1.DeletePodResponse{}, nil
}

func (s *leaseRuntimeServer) GetPodStatus(_ context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	return &runtimev1.GetPodStatusResponse{Status: leaseStatus(req.GetPodId(), s.reportedPodIP(req.GetPodId()), "")}, nil
}

// WatchPodStatus forwards pushed events until the stream ends.
func (s *leaseRuntimeServer) WatchPodStatus(_ *runtimev1.WatchPodStatusRequest, stream grpc.ServerStreamingServer[runtimev1.PodStatusEvent]) error {
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case ev := <-s.events:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// push delivers one status observation for podID carrying the given guest
// transport address ("" = the guest holds no lease).
func (s *leaseRuntimeServer) push(t *testing.T, podID, transport string) {
	t.Helper()
	select {
	case s.events <- &runtimev1.PodStatusEvent{
		Type:   runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED,
		Status: leaseStatus(podID, s.reportedPodIP(podID), transport),
	}:
	case <-time.After(2 * time.Second):
		t.Fatalf("push status for %s: the provider is not consuming the stream", podID)
	}
}

// leaseStatus is a minimal Running PodStatus carrying the vm-pod live transport
// address under test. podIP is the reported pod_ip: EMPTY for this file's own
// cases, so the published identity the override is keyed on must come from the
// node's own guest record and not from a status the same test wrote; echoed back
// from the created PodBox for the chain gate, which is what a real runtimed does.
func leaseStatus(podID, podIP, transport string) *runtimev1.PodStatus {
	return &runtimev1.PodStatus{
		PodId:                 podID,
		PodIp:                 podIP,
		Phase:                 runtimev1.PodPhase_POD_PHASE_RUNNING,
		GuestTransportAddress: transport,
		ContainerStatuses: []*runtimev1.ContainerStatus{{
			Name:  "c0",
			Image: "registry/app:latest",
			Ready: true,
			State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{}},
		}},
	}
}

// recordingSink is the TransportOverrideSink under assertion: it records every
// map generation the feed publishes (copied on arrival, since the feed hands
// ownership over and the test must not observe a later mutation) and FORWARDS it
// to the real darwin-net routing table.
//
// The forward is what keeps the recording honest: the production consumer takes
// every generation this file asserts on, so a map the real table would reject
// (an invalid key, a shape it does not accept) cannot pass here.
type recordingSink struct {
	table *proxy.RoutingTable

	mu   sync.Mutex
	sets int
	last map[netip.Addr]netip.Addr
}

func (s *recordingSink) SetTransportOverrides(overrides map[netip.Addr]netip.Addr) {
	s.mu.Lock()
	s.sets++
	s.last = maps.Clone(overrides)
	if s.last == nil {
		s.last = map[netip.Addr]netip.Addr{}
	}
	s.mu.Unlock()
	if s.table != nil {
		s.table.SetTransportOverrides(overrides)
	}
}

func (s *recordingSink) snapshot() (int, map[netip.Addr]netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sets, maps.Clone(s.last)
}

// Compile-time proof the seam binds to the REAL consumer: darwin-net's routing
// table is what production feeds, so a signature drift on either side is a build
// failure here rather than an override map nobody installs.
var _ TransportOverrideSink = (*proxy.RoutingTable)(nil)

// leaseNode is the provider assembled the way a vm-capable node assembles it:
// the REAL PodNetAdapter over a real podnet.Allocator (so a pod's published /32
// is drawn from the node's own pool, not handed in by the test), the real
// provider translate/watch path, and the recording sink standing in for the
// Service proxy's routing table.
type leaseNode struct {
	r      *runtimedRuntime
	adapt  *PodNetAdapter
	ipam   *fakeIPAM
	rt     *leaseRuntimeServer
	sink   *recordingSink
	table  *proxy.RoutingTable
	mu     sync.Mutex
	seen   map[string]int    // pod id -> status callbacks delivered
	podIPs map[string]string // pod id -> the LAST status.podIP VK was told
	notify chan struct{}
}

// newLeaseNode builds the node with statuses that report NO pod_ip (this file's
// posture — see leaseStatus).
func newLeaseNode(t *testing.T) *leaseNode { return newLeaseNodeWith(t, false) }

// newLeaseNodeWith builds the node with a runtimed fake that echoes the created
// PodBox.pod_ip back on every status when echoPodIP is set, the way a real
// runtimed does.
func newLeaseNodeWith(t *testing.T, echoPodIP bool) *leaseNode {
	t.Helper()
	ipam := newFakeIPAM(t, guestPodCIDR)
	ipam.vm = podnet.VMNetworkConfig{
		NATSubnet: netip.MustParsePrefix("192.168.64.0/24"),
		Gateway:   netip.MustParseAddr("192.168.64.1"),
		DNSVIP:    netip.MustParseAddr(guestDNSVIP),
	}
	adapt := NewPodNetAdapter(ipam, guestNodeIP, nil)
	rt := newLeaseRuntimeServer(echoPodIP)
	// The REAL routing table the node's Service proxy would route on, behind the
	// recorder — so every override generation this fixture asserts on is one the
	// production consumer actually took.
	table := proxy.NewRoutingTable(netip.MustParsePrefix(guestPodCIDR))
	sink := &recordingSink{table: table}
	n := &leaseNode{
		ipam: ipam, adapt: adapt, rt: rt, sink: sink, table: table,
		seen: map[string]int{}, podIPs: map[string]string{}, notify: make(chan struct{}, 64),
	}
	n.r = newRuntimedWith(rt, RuntimedConfig{
		NodeName:           guestNodeName,
		NodeIP:             guestNodeIP,
		Root:               t.TempDir(),
		ResolverVIP:        guestDNSVIP,
		ClusterDomain:      "cluster.local",
		Network:            adapt,
		TransportOverrides: sink,
	}, nil, nil)
	return n
}

// watch starts the provider's status watch, bounded by the test's lifetime.
func (n *leaseNode) watch(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	n.r.Watch(ctx, func(pod *corev1.Pod) {
		n.mu.Lock()
		n.seen[string(pod.UID)]++
		n.podIPs[string(pod.UID)] = pod.Status.PodIP
		n.mu.Unlock()
		select {
		case n.notify <- struct{}{}:
		default:
		}
	})
}

// awaitStatus blocks until the VK callback has reported podID at least want
// times. It is what makes an "override was NOT installed" assertion non-vacuous:
// the status carrying the field provably reached the provider's status path.
func (n *leaseNode) awaitStatus(t *testing.T, podID string, want int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		n.mu.Lock()
		got := n.seen[podID]
		n.mu.Unlock()
		if got >= want {
			return
		}
		select {
		case <-n.notify:
		case <-deadline:
			t.Fatalf("status callback for %s fired %d times, want >= %d", podID, got, want)
		}
	}
}

// awaitStatusPodIP blocks until the VK callback has reported podID with the given
// status.podIP. It is how the PUBLISHED identity is observed where a Service
// controller would observe it, rather than where the provider computed it.
func (n *leaseNode) awaitStatusPodIP(t *testing.T, podID, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		n.mu.Lock()
		got, seen := n.podIPs[podID], n.seen[podID]
		n.mu.Unlock()
		if got == want {
			return
		}
		select {
		case <-n.notify:
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			t.Fatalf("status.podIP for %s = %q after %d callbacks, want %q", podID, got, seen, want)
		}
	}
}

// awaitOverrides blocks until the sink's latest generation equals want (keys and
// values as strings, for a legible failure), or fails.
func (n *leaseNode) awaitOverrides(t *testing.T, want map[string]string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	var got map[string]string
	for {
		_, live := n.sink.snapshot()
		got = renderOverrides(live)
		if maps.Equal(got, want) {
			return
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			t.Fatalf("transport overrides = %v, want %v", got, want)
		}
	}
}

func renderOverrides(m map[netip.Addr]netip.Addr) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k.String()] = v.String()
	}
	return out
}

// published returns the /32 the node's IPAM carved for podID — the pod's cluster
// identity and the key every override must be under. It reads the adapter's own
// record, which is the value the feed is required to have used.
func (n *leaseNode) published(t *testing.T, podID string) string {
	t.Helper()
	cfg, ok := n.adapt.GuestNetwork(podID)
	if !ok || !cfg.PodIP.IsValid() {
		t.Fatalf("no guest network recorded for %s; the node never provisioned a guest", podID)
	}
	return cfg.PodIP.String()
}

// TestGuestLeaseFeedsTransportOverride is the B237 named gate for the consumer
// half of the guest-lease chain: the provider reads a vm pod's
// PodStatus.guest_transport_address off runtimed's status stream and maintains
// the Service proxy's published-/32 -> live-lease override map across the whole
// lease lifecycle.
//
// WHY IT IS NOT VACUOUS. The KEY of every asserted override is the /32 the
// node's own podnet allocator drew for the pod (read back from the adapter, not
// supplied by the test at both ends), and the pushed statuses deliberately carry
// an EMPTY pod_ip — so an implementation that keyed the override on the reported
// status, on the node IP, or on anything else the test handed in would fail. The
// negative leg proves the vm gate is a routing fact rather than a pod that
// reported nothing: the host-process pod's status carries the field and is
// proven to have reached the provider's status path.
func TestGuestLeaseFeedsTransportOverride(t *testing.T) {
	t.Parallel()

	t.Run("a reported lease installs published -> live for a vm pod", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := vmPod("team-a", "guest")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)

		pub := n.published(t, id)
		if pub == guestNodeIP {
			t.Fatalf("the pod's published address is the node IP (%s); the override key would not be a pod identity", pub)
		}
		if !netip.MustParsePrefix(guestPodCIDR).Contains(netip.MustParseAddr(pub)) {
			t.Fatalf("published %s is outside the node podCIDR %s; it did not come from the node pool", pub, guestPodCIDR)
		}

		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})
	})

	t.Run("a lease CHANGE replaces the override wholesale", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := vmPod("team-a", "churn")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)
		pub := n.published(t, id)

		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})

		// The guest rebooted and DHCP handed it a different address. The old one
		// may already belong to another guest, so it must not survive.
		n.rt.push(t, id, leaseSecond)
		n.awaitOverrides(t, map[string]string{pub: leaseSecond})
	})

	t.Run("an emptied field drops the override", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := vmPod("team-a", "leaseless")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)
		pub := n.published(t, id)

		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})

		n.rt.push(t, id, "")
		n.awaitOverrides(t, map[string]string{})
	})

	t.Run("pod deletion drops the override", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := vmPod("team-a", "doomed")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)
		pub := n.published(t, id)

		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})

		// No further status can ever arrive for a deleted pod, so the delete path
		// itself has to retract the override.
		if err := n.r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		n.awaitOverrides(t, map[string]string{})
	})

	t.Run("a host-process pod's set field never creates an override", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := hostPod("team-a", "native")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)

		// The pod DID provision through the host-process seam — so the absence
		// below is the vm gate, not a pod that allocated nothing.
		if !slices.Contains(n.ipam.setupCalls(), id) {
			t.Fatalf("host-process Setup calls = %v, want it to contain %s", n.ipam.setupCalls(), id)
		}
		if _, ok := n.adapt.GuestNetwork(id); ok {
			t.Fatal("the adapter recorded a guest network for a host-process pod")
		}

		// An erroneous (or hostile) report of a transport address for a pod whose
		// published /32 IS live on lo0 must install nothing: overriding it would
		// redirect that pod's Service traffic to a guest.
		n.rt.push(t, id, leaseFirst)
		n.awaitStatus(t, id, 1)

		if sets, live := n.sink.snapshot(); sets != 0 {
			t.Errorf("the sink was called %d times for a host-process pod (last=%v), want 0", sets, renderOverrides(live))
		}
	})

	t.Run("the real routing table is the sink", func(t *testing.T) {
		t.Parallel()
		// darwin-net's table exposes no reader for its override map, so the
		// assertion available from outside that package is the BINDING: the real
		// type is accepted as the sink and takes the feed's whole lifecycle. The
		// override's effect on the dial is proven inside darwin-net
		// (TestTransportOverrideDialTarget), against the same setter.
		table := proxy.NewRoutingTable(netip.MustParsePrefix(guestPodCIDR))
		feed := newTransportFeed(table, nil)
		if feed == nil {
			t.Fatal("newTransportFeed returned the inert feed for a real routing table")
		}
		pub, live := netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr(leaseFirst)
		feed.observe("pod-1", pub, live)
		feed.observe("pod-1", pub, netip.MustParseAddr(leaseSecond))
		feed.drop("pod-1")
	})
}

// TestTransportFeedInertWithoutSink pins the no-datapath posture: with no sink
// configured the feed is nil and every call site tolerates it, so a node running
// `--network none` neither panics nor holds lease state.
func TestTransportFeedInertWithoutSink(t *testing.T) {
	t.Parallel()
	if f := newTransportFeed(nil, nil); f != nil {
		t.Fatalf("newTransportFeed(nil) = %v, want the inert nil feed", f)
	}
	var f *transportFeed
	f.observe("pod-1", netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr(leaseFirst))
	f.drop("pod-1")
}
