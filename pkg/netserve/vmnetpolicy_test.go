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

package netserve

import (
	"net/netip"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/darwin-net/pkg/proxy"
)

// TestVMNetPolicyPrefixSelection is the pure table over the ONE decision: which
// NAT segment (if any) the NetworkPolicy table's fail-closed unknown-vm-source
// branch is scoped to. Both inputs must hold — a node with no vm backend hosts no
// guest, and an unparsable subnet gives nothing to scope to — and either miss
// yields the zero Prefix, which proxy.NewPolicyTableVMNet defines to be exactly
// the plain table.
func TestVMNetPolicyPrefixSelection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		vmBackend bool
		subnet    string
		want      netip.Prefix
	}{
		{"vm-capable node with its NAT segment", true, "192.168.64.0/24", netip.MustParsePrefix("192.168.64.0/24")},
		{"a host address with a prefix length still scopes the segment", true, "192.168.64.1/24", netip.MustParsePrefix("192.168.64.0/24")},
		{"no vm backend ignores a configured segment", false, "192.168.64.0/24", netip.Prefix{}},
		{"vm-capable node with an unknown segment", true, "", netip.Prefix{}},
		{"vm-capable node with an unparsable segment", true, "192.168.64.0", netip.Prefix{}},
		{"neither", false, "", netip.Prefix{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := vmnetPolicyPrefix(tc.vmBackend, tc.subnet); got != tc.want {
				t.Errorf("vmnetPolicyPrefix(%v, %q) = %v, want %v", tc.vmBackend, tc.subnet, got, tc.want)
			}
		})
	}
}

// TestVMNetPolicyTableConstruction proves the selection above reaches the table
// netserve CONSTRUCTS, through darwin-net's exported verdict rather than through
// a field read: on a vm-capable node an unattributable source INSIDE the node's
// NAT segment is DENIED (the M11.3-d3a fail-closed branch — a guest's packets
// carry its DHCP lease, and nothing maps a lease back to a pod yet), while the
// same source on a node with no vm backend is ALLOWED, exactly as before.
//
// The third leg is what keeps the deny narrow: an unknown source OUTSIDE the
// segment still fails open on the very same vm-capable node, so this is a scoped
// branch and not a deny-unknown-sources cutover.
func TestVMNetPolicyTableConstruction(t *testing.T) {
	t.Parallel()

	const natSubnet = "192.168.64.0/24"
	backend := netip.MustParseAddr("100.64.0.5")    // a policy-selected pod
	guestSrc := netip.MustParseAddr("192.168.64.7") // a guest's vmnet lease
	offSegment := netip.MustParseAddr("10.7.7.7")   // any other unknown source

	// A selected backend with NO matching rule: the verdict then turns entirely on
	// source attribution, which is the branch under test.
	arm := func(s *Server) {
		s.policy.Update(map[netip.Addr][]proxy.PolicyRule{backend: {}}, nil)
	}

	vmNode := New(Config{
		Client:      fake.NewClientset(),
		WorkDir:     t.TempDir(),
		DNSVIP:      "10.43.0.10",
		PodCIDR:     "100.64.0.0/24",
		NodeIP:      "192.168.1.10",
		VMBackend:   true,
		VMNetSubnet: natSubnet,
	})
	arm(vmNode)

	plainNode := New(Config{
		Client:      fake.NewClientset(),
		WorkDir:     t.TempDir(),
		DNSVIP:      "10.43.0.10",
		PodCIDR:     "100.64.0.0/24",
		NodeIP:      "192.168.1.10",
		VMNetSubnet: natSubnet, // configured, but the node advertises no vm backend
	})
	arm(plainNode)

	if vmNode.policy.Allow(guestSrc, backend, 80) {
		t.Errorf("vm-capable node ALLOWED an unattributable source %v inside its NAT segment %s; it must fail closed", guestSrc, natSubnet)
	}
	if !vmNode.policy.Allow(offSegment, backend, 80) {
		t.Errorf("vm-capable node DENIED an unattributable source %v outside its NAT segment; the fail-closed branch must stay scoped", offSegment)
	}
	if !plainNode.policy.Allow(guestSrc, backend, 80) {
		t.Errorf("node without the vm backend denied %v; it must be byte-identical to the plain table (fail open)", guestSrc)
	}
}

// TestTransportOverrideSinkReachesTheProxyTable pins the other half of the M11.3
// wiring: the Server exposes the routing table's transport-override setter, and
// it is the SAME table the proxy routes on — not a second one. darwin-net exposes
// no reader for the override map, so the assertion available here is that the
// setter is wired to a constructed table and takes the assembler's map; the
// override's effect on the dial is proven inside darwin-net against that setter.
func TestTransportOverrideSinkReachesTheProxyTable(t *testing.T) {
	t.Parallel()
	s := New(Config{
		Client:  fake.NewClientset(),
		WorkDir: t.TempDir(),
		DNSVIP:  "10.43.0.10",
		PodCIDR: "100.64.0.0/24",
	})
	if s.table == nil {
		t.Fatal("the Server retains no routing table; the transport-override seam has nothing to write to")
	}
	s.SetTransportOverrides(map[netip.Addr]netip.Addr{
		netip.MustParseAddr("100.64.0.9"): netip.MustParseAddr("192.168.64.7"),
	})
	s.SetTransportOverrides(nil)
}

// TestDefaultVMNetSubnetScopesTheConstructedTable is the B237 wiring gate for the
// CONSTANT rather than for the selection: DefaultVMNetSubnet — the one home for
// the vmnet segment both node bring-ups pass — must be a value that actually
// scopes a constructed table, and must scope it only when the node advertises the
// vm backend.
//
// It is separate from the table above on purpose. That one pins the DECISION
// against literals; this one pins the SHIPPED VALUE, so a constant edited to
// something unparsable (or to a prefix that excludes the address macOS was
// observed to hand a guest) goes red here rather than silently degrading every vm
// node's policy table to fail-open.
func TestDefaultVMNetSubnetScopesTheConstructedTable(t *testing.T) {
	t.Parallel()

	segment, err := netip.ParsePrefix(DefaultVMNetSubnet)
	if err != nil {
		t.Fatalf("DefaultVMNetSubnet %q does not parse: %v — an unparsable constant leaves every vm node fail-open", DefaultVMNetSubnet, err)
	}
	if segment != segment.Masked() {
		t.Errorf("DefaultVMNetSubnet = %q, want a masked segment (a host address would still scope, but the constant should read as the segment it is)", DefaultVMNetSubnet)
	}
	// The address the reference rig observed a guest lease. It is the value this
	// constant exists to cover, so a prefix that excludes it is the wrong prefix.
	observed := netip.MustParseAddr("192.168.64.7")
	if !segment.Contains(observed) {
		t.Fatalf("DefaultVMNetSubnet %q does not contain the observed guest lease %v", DefaultVMNetSubnet, observed)
	}

	backend := netip.MustParseAddr("100.64.0.5") // a policy-selected pod
	arm := func(s *Server) {
		s.policy.Update(map[netip.Addr][]proxy.PolicyRule{backend: {}}, nil)
	}
	newNode := func(t *testing.T, vmCapable bool) *Server {
		t.Helper()
		s := New(Config{
			Client:      fake.NewClientset(),
			WorkDir:     t.TempDir(),
			DNSVIP:      "10.43.0.10",
			PodCIDR:     "100.64.0.0/24",
			NodeIP:      "192.168.1.10",
			VMBackend:   vmCapable,
			VMNetSubnet: DefaultVMNetSubnet, // exactly what both bring-ups pass
		})
		arm(s)
		return s
	}

	if newNode(t, true).policy.Allow(observed, backend, 80) {
		t.Errorf("a vm-capable node ALLOWED the unattributable source %v inside DefaultVMNetSubnet %s; the constant did not reach the table",
			observed, DefaultVMNetSubnet)
	}
	if !newNode(t, false).policy.Allow(observed, backend, 80) {
		t.Errorf("a node with no vm backend DENIED %v; passing the constant unconditionally must leave the plain table byte-identical", observed)
	}
}
