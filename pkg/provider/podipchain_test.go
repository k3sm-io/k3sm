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
	"net/netip"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/proxy"
)

// TestVMPodPublishedIPKeysItsTransportOverride is the B237 closing gate: it joins
// the two halves of a vm pod's two-address identity into ONE assertion chain, from
// the node's IPAM to the Service proxy's routing table.
//
// THE CHAIN, and what produces each link:
//
//	podnet allocator  -> SetupGuest allocates the pod's /32
//	podIP             -> publishes that /32 (B237: it used to publish the node IP)
//	toPodBox          -> carries it to runtimed as PodBox.pod_ip, over the RPC
//	runtimed          -> echoes it back as PodStatus.pod_ip (the fake does what the
//	                     real daemon does: a pod's reported ip IS the box's)
//	buildStatus       -> corev1 status.podIP, delivered to the VK callback
//	observeTransport  -> keys the proxy override map on the node's guest record
//	proxy.RoutingTable-> takes that map, and routes/picks on the PUBLISHED address
//
// WHY IT IS NOT VACUOUS. Every value asserted is one the test could not have
// supplied: the /32 is drawn from the node's real 253-address pool by the real
// allocator, and the test reads it back from FOUR independent places that must
// agree — the adapter's guest record, the PodBox the provider sent over the RPC,
// the corev1 status.podIP the VK callback delivered, and the key of the override
// map the real routing table took. The lease value arrives only through the gRPC
// status stream. Before B237 this test cannot pass at all: podIP returned the node
// IP, so the PodBox and status.podIP links carried an address the override map is
// not keyed on, and every guest on the node shared it.
//
// THE ONE LINK PROVEN NEXT DOOR. darwin-net's RoutingTable applies an override at
// the DIAL site only (RoutingTable.transportAddr, unexported), which is why Pick
// below still answers with the published address — the NetworkPolicy verdict, the
// affinity binding and the endpoint-set membership all key on the identity, and
// only the packet takes the lease. That last translation is proven inside
// darwin-net (TestTransportOverrideDialTarget) against the very setter this chain
// feeds.
func TestVMPodPublishedIPKeysItsTransportOverride(t *testing.T) {
	t.Parallel()

	n := newLeaseNodeWith(t, true)
	pod := vmPod("team-a", "chain")
	id := string(pod.UID)
	if err := n.r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	n.watch(t)

	// Link 1: the node's IPAM drew the guest's /32 and the adapter recorded it.
	published := n.published(t, id)
	if published == guestNodeIP {
		t.Fatalf("the pod's published address is the node IP (%s); it is no pod identity and no override key", published)
	}
	if !netip.MustParsePrefix(guestPodCIDR).Contains(netip.MustParseAddr(published)) {
		t.Fatalf("published %s is outside the node podCIDR %s; it did not come from the node pool", published, guestPodCIDR)
	}

	// Link 2: podIP published exactly that address into the PodBox — this is the
	// B237 flip, observed at the far side of the RPC rather than at its source.
	if box := n.rt.boxPodIP(id); box != published {
		t.Fatalf("PodBox.pod_ip = %q, want the allocated guest /32 %q — podIP must publish what SetupGuest drew", box, published)
	}

	// Link 3: the guest reports its DHCP lease, and the feed installs the override
	// keyed on the published identity.
	n.rt.push(t, id, leaseFirst)
	n.awaitOverrides(t, map[string]string{published: leaseFirst})

	// Link 4: the SAME address is what a Service controller sees as status.podIP,
	// so the EndpointSlice a vm pod lands in carries the very key the override map
	// is under. This is the join: identity out, override keyed on it.
	n.awaitStatusPodIP(t, id, published)

	// Link 5: the real routing table took that override generation (the fixture's
	// sink forwards to it) and still PICKS the published address for a Service
	// backed by this pod — the identity is what routing, policy and affinity see.
	key := proxy.PortKey{ClusterIP: "10.43.0.99", Port: 80, Protocol: netv1.ProtocolTCP}
	if got := n.table.SetEndpoints(key, []netv1.Endpoint{{IP: published, Port: 8080, Ready: true}}); got != 1 {
		t.Fatalf("SetEndpoints installed %d ready backends, want 1", got)
	}
	picked, err := n.table.Pick(key)
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if got, want := picked.Addr().Addr().String(), published; got != want {
		t.Errorf("picked backend = %s, want the published identity %s (only the dial takes the lease)", got, want)
	}
	if got := picked.Addr().Port(); got != 8080 {
		t.Errorf("picked backend port = %d, want 8080 — an override never moves the port", got)
	}

	// And the liveness half still holds through the whole chain: the guest reboots
	// onto a different lease, and the identity is unchanged while the override
	// follows.
	n.rt.push(t, id, leaseSecond)
	n.awaitOverrides(t, map[string]string{published: leaseSecond})
	n.awaitStatusPodIP(t, id, published)
}
