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

package netdsvc

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPortAuthorizer proves the Service-CIDR-VIP branch of the privileged-port
// policy: a VIP port a Service declares is allowed; an undeclared <1024 VIP
// port is denied; and a nil declares (no Service set available) denies every
// bind — fail safe, the daemon never trusts the client's self-assertion.
func TestPortAuthorizer(t *testing.T) {
	svcCIDR := netip.MustParsePrefix("10.43.0.0/16")
	declares := func(port int) bool { return port == 53 } // kube-dns declares :53
	a := PortAuthorizer(PortPolicy{ServiceCIDR: svcCIDR, Declares: declares})

	if err := a.Authorize(context.Background(), 53, "10.43.0.10"); err != nil {
		t.Errorf("declared VIP port 53 must be authorized, got %v", err)
	}
	if err := a.Authorize(context.Background(), 80, "10.43.0.20"); err == nil {
		t.Error("undeclared privileged VIP port 80 must be denied")
	}

	deny := PortAuthorizer(PortPolicy{ServiceCIDR: svcCIDR})
	if err := deny.Authorize(context.Background(), 53, "10.43.0.10"); err == nil {
		t.Error("a nil declares (no service set) must deny every VIP bind, fail-safe")
	}
}

// canonicalIngress is the one Service the node-address bind class is
// allowlisted for in these tests — the same namespace+name pkg/ingresshost
// provisions and the `k3sm netd` assembler binds.
var canonicalIngress = ServiceRef{Namespace: "kube-system", Name: "k3sm-ingress"}

// TestNetdAuthorizerNodeAddrLB is the M10.3 deny-by-default table for the
// node-own-address extension: a <1024 bind on the node's OWN InternalIP is
// authorized ONLY when the canonical ingress LoadBalancer declares the port.
// Everything else — wrong address, wrong port, only a non-LB Service declaring,
// a nil predicate, no configured node IP, an unparseable address — is denied.
func TestNetdAuthorizerNodeAddrLB(t *testing.T) {
	svcCIDR := netip.MustParsePrefix("10.43.0.0/16")
	nodeIP := netip.MustParseAddr("192.168.7.20")
	// The authoritative Service set: kube-dns (ClusterIP) declares 53; the
	// canonical k3sm-ingress LoadBalancer declares 80+443.
	declares := func(port int) bool { return port == 53 || port == 80 || port == 443 }
	lbDeclarers := func(port int) []ServiceRef {
		if port == 80 || port == 443 {
			return []ServiceRef{canonicalIngress}
		}
		return nil
	}

	full := PortPolicy{
		ServiceCIDR:        svcCIDR,
		Declares:           declares,
		NodeIP:             nodeIP,
		LBDeclarers:        lbDeclarers,
		NodeAddressService: canonicalIngress,
	}

	tests := []struct {
		name   string
		policy PortPolicy
		port   int
		addr   string
		allow  bool
	}{
		{"node addr + LB-declared 80 allowed", full, 80, "192.168.7.20", true},
		{"node addr + LB-declared 443 allowed", full, 443, "192.168.7.20", true},
		{"node addr + port no LB service declares denied (53 is ClusterIP-only)", full, 53, "192.168.7.20", false},
		{"node addr + wholly undeclared port denied", full, 22, "192.168.7.20", false},
		{"wrong addr (neither VIP nor node) denied even for an LB-declared port", full, 80, "192.168.7.99", false},
		{"service VIP + declared port still allowed (existing rule intact)", full, 53, "10.43.0.10", true},
		{"service VIP + only-LB semantics do not leak: undeclared VIP port denied", full, 22, "10.43.0.10", false},
		{"nil LBDeclarers denies the node-address class, fail-safe",
			PortPolicy{ServiceCIDR: svcCIDR, Declares: declares, NodeIP: nodeIP, NodeAddressService: canonicalIngress}, 80, "192.168.7.20", false},
		{"zero NodeAddressService denies the node-address class, fail-safe",
			PortPolicy{ServiceCIDR: svcCIDR, Declares: declares, NodeIP: nodeIP, LBDeclarers: lbDeclarers}, 80, "192.168.7.20", false},
		{"zero NodeIP disables the node-address class entirely",
			PortPolicy{ServiceCIDR: svcCIDR, Declares: declares, LBDeclarers: lbDeclarers, NodeAddressService: canonicalIngress}, 80, "192.168.7.20", false},
		{"zero policy denies everything", PortPolicy{}, 80, "192.168.7.20", false},
		{"unparseable address denied", full, 80, "not-an-ip", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := PortAuthorizer(tc.policy).Authorize(context.Background(), tc.port, tc.addr)
			if tc.allow && err != nil {
				t.Errorf("Authorize(%d, %s) = %v, want allow", tc.port, tc.addr, err)
			}
			if !tc.allow && err == nil {
				t.Errorf("Authorize(%d, %s) = nil, want deny", tc.port, tc.addr)
			}
		})
	}
}

// TestMeshKeyResolver proves the resolver reads a key from the root-only dir,
// errors on a missing key (no embedded default), and rejects a traversing ref.
func TestMeshKeyResolver(t *testing.T) {
	dir := t.TempDir()
	const key = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3OD0="
	if err := os.WriteFile(filepath.Join(dir, "node.key"), []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := MeshKeyResolver(dir)

	t.Run("reads the key (trimmed)", func(t *testing.T) {
		got, err := r.Resolve(context.Background(), "node.key")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != key {
			t.Errorf("Resolve = %q, want %q", got, key)
		}
	})
	t.Run("missing key errors (no embedded default)", func(t *testing.T) {
		_, err := r.Resolve(context.Background(), "absent.key")
		if err == nil {
			t.Fatal("a missing key must error, never return an embedded default")
		}
		// The node daemon reports this text as its mesh bring-up failure, so it
		// must name the remedy.
		if !strings.Contains(err.Error(), "sudo k3sm install") {
			t.Errorf("the missing-key error does not name the remedy: %v", err)
		}
	})
	t.Run("path traversal rejected", func(t *testing.T) {
		for _, ref := range []string{"../node.key", "sub/node.key", ".."} {
			if _, err := r.Resolve(context.Background(), ref); err == nil {
				t.Errorf("traversing ref %q must be rejected", ref)
			}
		}
	})
}

// TestBuildConfig proves the daemon Config assembly: the Service CIDR is pinned
// (without it the proxy's ClusterIP VIP aliases are denied, so it is required),
// the node pod CIDR and uid flow through, and the authorizer + key resolver are
// wired.
func TestBuildConfig(t *testing.T) {
	nodeCIDR := netip.MustParsePrefix("100.64.1.0/24")
	svcCIDR := netip.MustParsePrefix("10.43.0.0/16")

	t.Run("assembles a valid config", func(t *testing.T) {
		cfg, err := BuildConfig(Options{
			NodePodCIDR: nodeCIDR,
			ServiceCIDR: svcCIDR,
			ServiceUID:  502,
			Declares:    func(int) bool { return true },
			LBDeclarers: func(port int) []ServiceRef {
				if port == 80 {
					return []ServiceRef{canonicalIngress}
				}
				return nil
			},
			NodeAddressService: canonicalIngress,
			NodeIP:             netip.MustParseAddr("192.168.7.20"),
			MeshKeyDir:         t.TempDir(),
			ClusterCAPath:      "/var/lib/k3sm/server/tls/cluster-ca.crt",
		})
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if cfg.ClusterCAPath != "/var/lib/k3sm/server/tls/cluster-ca.crt" {
			t.Errorf("ClusterCAPath = %q, want the --cluster-ca the managed update's signer chains to", cfg.ClusterCAPath)
		}
		if cfg.ServiceCIDR != svcCIDR {
			t.Errorf("ServiceCIDR = %v, want %v (proxy VIP aliases depend on it)", cfg.ServiceCIDR, svcCIDR)
		}
		if cfg.NodePodCIDR != nodeCIDR {
			t.Errorf("NodePodCIDR = %v, want %v", cfg.NodePodCIDR, nodeCIDR)
		}
		if cfg.ServiceUID != 502 {
			t.Errorf("ServiceUID = %d, want 502", cfg.ServiceUID)
		}
		if cfg.PortAuthorizer == nil {
			t.Error("PortAuthorizer must be wired")
		}
		// The Options plumb through to the authorizer's two address classes.
		if err := cfg.PortAuthorizer.Authorize(context.Background(), 53, "10.43.0.10"); err != nil {
			t.Errorf("VIP branch must flow through BuildConfig, got %v", err)
		}
		if err := cfg.PortAuthorizer.Authorize(context.Background(), 80, "192.168.7.20"); err != nil {
			t.Errorf("node-address LB branch must flow through BuildConfig, got %v", err)
		}
		if err := cfg.PortAuthorizer.Authorize(context.Background(), 443, "192.168.7.20"); err == nil {
			t.Error("node-address port no LB service declares must be denied")
		}
		if cfg.MeshKeyResolver == nil {
			t.Error("MeshKeyResolver must be wired when MeshKeyDir is set")
		}
	})

	t.Run("the adopted-identity file is threaded into the mesh key dir", func(t *testing.T) {
		dir := t.TempDir()
		cfg, err := BuildConfig(Options{NodePodCIDR: nodeCIDR, ServiceCIDR: svcCIDR, MeshKeyDir: dir})
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		want := filepath.Join(dir, NodeIdentityFileName)
		if cfg.IdentityPath != want {
			t.Errorf("IdentityPath = %q, want %q — netd persists the /24 it adopted there and re-reads it at start, so a restart the agent did not drive does not revert the node's identity", cfg.IdentityPath, want)
		}
		if filepath.Dir(cfg.IdentityPath) != dir {
			t.Errorf("IdentityPath must live INSIDE the root-only mesh key dir %q, got %q — a directory an unprivileged writer can reach would let it dictate the pod-alias policy boundary at the next start", dir, cfg.IdentityPath)
		}
		wantIC := filepath.Join(dir, InterconnectStateFileName)
		if cfg.InterconnectStatePath != wantIC {
			t.Errorf("InterconnectStatePath = %q, want %q — netd records the bridge0 aliases it owns there, so a restart removes only aliases it did not create", cfg.InterconnectStatePath, wantIC)
		}
		if filepath.Dir(cfg.InterconnectStatePath) != filepath.Dir(cfg.IdentityPath) {
			t.Errorf("InterconnectStatePath %q must sit beside IdentityPath %q in the root-only mesh key dir", cfg.InterconnectStatePath, cfg.IdentityPath)
		}
	})

	t.Run("missing service CIDR errors", func(t *testing.T) {
		if _, err := BuildConfig(Options{NodePodCIDR: nodeCIDR}); err == nil {
			t.Error("BuildConfig must require a Service CIDR (else proxy VIPs are denied)")
		}
	})
	t.Run("missing node pod CIDR errors", func(t *testing.T) {
		if _, err := BuildConfig(Options{ServiceCIDR: svcCIDR}); err == nil {
			t.Error("BuildConfig must require a node pod CIDR")
		}
	})
	t.Run("no mesh key dir leaves resolver nil (ConfigureMesh fails fast)", func(t *testing.T) {
		cfg, err := BuildConfig(Options{NodePodCIDR: nodeCIDR, ServiceCIDR: svcCIDR})
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if cfg.MeshKeyResolver != nil {
			t.Error("an unset MeshKeyDir must leave MeshKeyResolver nil so ConfigureMesh fails fast")
		}
		// No root-only directory means no place to persist the identity. Empty is
		// the honest answer (netd then persists nothing); a path derived from
		// somewhere else would put the node's policy boundary in a directory the
		// installer never made 0700.
		if cfg.IdentityPath != "" {
			t.Errorf("an unset MeshKeyDir must leave IdentityPath empty, got %q", cfg.IdentityPath)
		}
		if got := NodeIdentityPath(""); got != "" {
			t.Errorf("NodeIdentityPath(\"\") = %q, want \"\"", got)
		}
		if cfg.InterconnectStatePath != "" || InterconnectStatePath("") != "" {
			t.Errorf("an unset MeshKeyDir must leave InterconnectStatePath empty, got %q", cfg.InterconnectStatePath)
		}
	})
}

// TestNodeAddressAuthorizerAllowlist is the B133 gate: the node-own-address
// bind class is an ALLOWLIST keyed on namespace+name, not a test on the
// requester's shape. Before B133 the branch authorized a privileged bind on the
// node's real address for ANY Service of type LoadBalancer, in ANY namespace,
// that declared the port — so the requesting object was its own authorization
// predicate. Now only the canonical ingress Service (kube-system/k3sm-ingress)
// authorizes it; a same-port, same-name-other-namespace, or
// same-namespace-other-name Service is refused, and the refusal NAMES the
// Service that declared the port so the root daemon's log shows who was denied.
func TestNodeAddressAuthorizerAllowlist(t *testing.T) {
	const nodeAddr = "192.168.7.20"
	svcCIDR := netip.MustParsePrefix("10.43.0.0/16")
	nodeIP := netip.MustParseAddr(nodeAddr)

	// policy returns the production-shaped policy whose LoadBalancer Service set
	// (for port 80) is exactly declarers.
	policy := func(declarers ...ServiceRef) PortPolicy {
		return PortPolicy{
			ServiceCIDR: svcCIDR,
			Declares:    func(int) bool { return true },
			NodeIP:      nodeIP,
			LBDeclarers: func(port int) []ServiceRef {
				if port != 80 {
					return nil
				}
				return declarers
			},
			NodeAddressService: canonicalIngress,
		}
	}

	tests := []struct {
		name string
		// declarers is the LoadBalancer Service set declaring port 80.
		declarers []ServiceRef
		allow     bool
		// wantNamed, when set, must appear in the refusal so the operator can
		// see WHICH Service was denied the node's address.
		wantNamed string
	}{
		{
			name:      "the canonical ingress Service is authorized",
			declarers: []ServiceRef{canonicalIngress},
			allow:     true,
		},
		{
			name:      "same port, another namespace: refused and named",
			declarers: []ServiceRef{{Namespace: "tenant-a", Name: "public-web"}},
			wantNamed: "tenant-a/public-web",
		},
		{
			name:      "same NAME, another namespace: refused and named",
			declarers: []ServiceRef{{Namespace: "tenant-a", Name: "k3sm-ingress"}},
			wantNamed: "tenant-a/k3sm-ingress",
		},
		{
			name:      "another name in the canonical namespace: refused and named",
			declarers: []ServiceRef{{Namespace: "kube-system", Name: "traefik"}},
			wantNamed: "kube-system/traefik",
		},
		{
			name:      "an impostor does not block the canonical Service",
			declarers: []ServiceRef{{Namespace: "tenant-a", Name: "public-web"}, canonicalIngress},
			allow:     true,
		},
		{
			name:      "no LoadBalancer Service declares the port: refused",
			declarers: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := PortAuthorizer(policy(tc.declarers...)).Authorize(context.Background(), 80, nodeAddr)
			if tc.allow {
				if err != nil {
					t.Fatalf("Authorize(80, %s) = %v, want allow", nodeAddr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Authorize(80, %s) = nil, want deny: only %s may authorize a node-address bind", nodeAddr, canonicalIngress)
			}
			if !strings.Contains(err.Error(), canonicalIngress.String()) {
				t.Errorf("refusal %q must name the canonical service %s", err, canonicalIngress)
			}
			if tc.wantNamed != "" && !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("refusal %q must NAME the declaring service %q; a silent refusal is invisible to the operator", err, tc.wantNamed)
			}
		})
	}

	t.Run("the refusal caps the named declarers", func(t *testing.T) {
		var many []ServiceRef
		for _, ns := range []string{"t1", "t2", "t3", "t4", "t5", "t6"} {
			many = append(many, ServiceRef{Namespace: ns, Name: "web"})
		}
		err := PortAuthorizer(policy(many...)).Authorize(context.Background(), 80, nodeAddr)
		if err == nil {
			t.Fatal("six foreign LoadBalancer Services must not authorize a node-address bind")
		}
		if !strings.Contains(err.Error(), "t1/web") || !strings.Contains(err.Error(), "(+2 more)") {
			t.Errorf("refusal %q must name the first declarers in sorted order and cap the rest", err)
		}
		if strings.Contains(err.Error(), "t6/web") {
			t.Errorf("refusal %q must cap the list so a many-Service cluster cannot flood the root daemon log", err)
		}
	})
}

// TestWildcardAuthorizerAllowlist is the B403 gate, the wildcard twin of
// TestNodeAddressAuthorizerAllowlist: the ingress host asks the root helper for
// 0.0.0.0:80/443 (the k3s ServiceLB shape), and the helper grants that
// privileged wildcard bind ONLY when the canonical kube-system/k3sm-ingress
// Service declares the port. A same-named Service in another namespace, a
// tenant LoadBalancer on the same port, an undeclared port, the IPv6 wildcard
// and a non-privileged port are all refused. The arm does not depend on
// PortPolicy.NodeIP (the installed plist renders none), and a specific-address
// request keeps the pre-existing classes' verdicts.
func TestWildcardAuthorizerAllowlist(t *testing.T) {
	svcCIDR := netip.MustParsePrefix("10.43.0.0/16")
	nodeIP := netip.MustParseAddr("192.168.7.20")
	tenantWeb := ServiceRef{Namespace: "tenant-a", Name: "public-web"}
	otherNSIngress := ServiceRef{Namespace: "tenant-a", Name: "k3sm-ingress"}

	// policy is the production-shaped policy whose LoadBalancer Service set on
	// every port is byPort[port]; NodeIP is ZERO, as the shipped plist leaves it.
	policy := func(byPort map[int][]ServiceRef) PortPolicy {
		return PortPolicy{
			ServiceCIDR: svcCIDR,
			Declares:    func(port int) bool { return port == 53 || len(byPort[port]) > 0 },
			LBDeclarers: func(port int) []ServiceRef {
				return byPort[port]
			},
			NodeAddressService: canonicalIngress,
		}
	}
	production := map[int][]ServiceRef{80: {canonicalIngress}, 443: {canonicalIngress}}

	tests := []struct {
		name   string
		policy PortPolicy
		port   int
		addr   string
		allow  bool
		// wantNamed, when set, must appear in the refusal.
		wantNamed string
	}{
		{name: "wildcard :80 declared by the canonical ingress is allowed", policy: policy(production), port: 80, addr: "0.0.0.0", allow: true},
		{name: "wildcard :443 declared by the canonical ingress is allowed", policy: policy(production), port: 443, addr: "0.0.0.0", allow: true},
		{name: "an impostor does not block the canonical Service",
			policy: policy(map[int][]ServiceRef{80: {tenantWeb, canonicalIngress}}), port: 80, addr: "0.0.0.0", allow: true},
		{name: "wildcard :80 declared only by a tenant LoadBalancer is refused and named",
			policy: policy(map[int][]ServiceRef{80: {tenantWeb}}), port: 80, addr: "0.0.0.0", wantNamed: "tenant-a/public-web"},
		{name: "wildcard :80 declared only by a same-named Service in another namespace is refused and named",
			policy: policy(map[int][]ServiceRef{80: {otherNSIngress}}), port: 80, addr: "0.0.0.0", wantNamed: "tenant-a/k3sm-ingress"},
		{name: "wildcard on a port no LoadBalancer declares is refused", policy: policy(production), port: 22, addr: "0.0.0.0"},
		{name: "wildcard on 53 (declared by a ClusterIP only) is refused", policy: policy(production), port: 53, addr: "0.0.0.0"},
		{name: "the IPv6 wildcard is refused even for the canonical port", policy: policy(production), port: 80, addr: "::"},
		{name: "a non-privileged wildcard is refused", policy: policy(map[int][]ServiceRef{8080: {canonicalIngress}}), port: 8080, addr: "0.0.0.0"},
		{name: "nil LBDeclarers refuses the wildcard, fail-safe",
			policy: PortPolicy{ServiceCIDR: svcCIDR, NodeAddressService: canonicalIngress}, port: 80, addr: "0.0.0.0"},
		{name: "zero NodeAddressService refuses the wildcard, fail-safe",
			policy: PortPolicy{ServiceCIDR: svcCIDR, LBDeclarers: func(int) []ServiceRef { return []ServiceRef{canonicalIngress} }}, port: 80, addr: "0.0.0.0"},
		{name: "zero policy refuses the wildcard", policy: PortPolicy{}, port: 80, addr: "0.0.0.0"},
		// A specific-address request keeps today's behavior.
		{name: "service VIP + declared port still allowed", policy: policy(production), port: 53, addr: "10.43.0.10", allow: true},
		{name: "service VIP + undeclared port still refused", policy: policy(production), port: 22, addr: "10.43.0.10"},
		{name: "node address with no configured NodeIP is still refused", policy: policy(production), port: 80, addr: "192.168.7.20"},
		{name: "node address with a configured NodeIP keeps the allowlist", policy: func() PortPolicy {
			p := policy(production)
			p.NodeIP = nodeIP
			return p
		}(), port: 80, addr: "192.168.7.20", allow: true},
		{name: "an unrelated address is still refused", policy: policy(production), port: 80, addr: "192.168.7.99"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := PortAuthorizer(tc.policy).Authorize(context.Background(), tc.port, tc.addr)
			if tc.allow {
				if err != nil {
					t.Fatalf("Authorize(%d, %s) = %v, want allow", tc.port, tc.addr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Authorize(%d, %s) = nil, want deny", tc.port, tc.addr)
			}
			if tc.wantNamed != "" && !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("refusal %q must NAME the declaring service %q", err, tc.wantNamed)
			}
			if tc.wantNamed != "" && !strings.Contains(err.Error(), canonicalIngress.String()) {
				t.Errorf("refusal %q must name the canonical service %s", err, canonicalIngress)
			}
		})
	}
}

// TestPortAuthorizerAdmitsPublishedVMPodPorts is the B440 named gate for the
// published-vm-pod bind class: a privileged bind on a vm pod's published address
// is authorized only on a port the vm pod set lists for THAT address. It refuses
// an address the set does not list (an unpublished pod address, a native pod's),
// an undeclared port, a port the set lists only for a different pod, an address
// outside this node's pod /24 even when the set would list it, a nil set, and a
// missing node pod CIDR. The address and port set come from the policy's
// predicate; nothing in the request widens them.
func TestPortAuthorizerAdmitsPublishedVMPodPorts(t *testing.T) {
	t.Parallel()
	node := netip.MustParsePrefix("100.64.3.0/24")
	webhook := netip.MustParseAddr("100.64.3.7") // vm pod: declares 443, a Service targets 80
	other := netip.MustParseAddr("100.64.3.8")   // vm pod: declares 53
	remote := netip.MustParseAddr("100.64.4.7")  // a vm pod on ANOTHER node
	set := map[netip.Addr][]uint16{
		webhook: {443, 80},
		other:   {53},
		remote:  {443},
	}
	vmPodPorts := func(addr netip.Addr) []uint16 { return set[addr] }
	full := PortPolicy{
		ServiceCIDR: netip.MustParsePrefix("10.43.0.0/16"),
		Declares:    func(int) bool { return false },
		NodePodCIDR: func() netip.Prefix { return node },
		VMPodPorts:  vmPodPorts,
	}

	cases := []struct {
		name   string
		policy PortPolicy
		port   int
		addr   string
		allow  bool
	}{
		{name: "declared port on a published vm pod address", policy: full, port: 443, addr: "100.64.3.7", allow: true},
		{name: "Service-targeted port on a published vm pod address", policy: full, port: 80, addr: "100.64.3.7", allow: true},
		{name: "IPv4-mapped spelling of the same address", policy: full, port: 443, addr: "::ffff:100.64.3.7", allow: true},
		{name: "unpublished pod address", policy: full, port: 443, addr: "100.64.3.9"},
		{name: "undeclared port", policy: full, port: 22, addr: "100.64.3.7"},
		{name: "a port only another vm pod declares", policy: full, port: 53, addr: "100.64.3.7"},
		{name: "a vm pod address outside this node's pod CIDR", policy: full, port: 443, addr: "100.64.4.7"},
		{name: "nil vm pod set", policy: PortPolicy{NodePodCIDR: full.NodePodCIDR}, port: 443, addr: "100.64.3.7"},
		{name: "no node pod CIDR", policy: PortPolicy{VMPodPorts: vmPodPorts}, port: 443, addr: "100.64.3.7"},
		{name: "invalid node pod CIDR", policy: PortPolicy{VMPodPorts: vmPodPorts, NodePodCIDR: func() netip.Prefix { return netip.Prefix{} }}, port: 443, addr: "100.64.3.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := PortAuthorizer(tc.policy).Authorize(context.Background(), tc.port, tc.addr)
			if tc.allow && err != nil {
				t.Errorf("Authorize(%d, %s) = %v, want authorized", tc.port, tc.addr, err)
			}
			if !tc.allow && err == nil {
				t.Errorf("Authorize(%d, %s) authorized, want refused", tc.port, tc.addr)
			}
		})
	}

	t.Run("a refusal names the relayed ports", func(t *testing.T) {
		t.Parallel()
		err := PortAuthorizer(full).Authorize(context.Background(), 22, "100.64.3.7")
		if err == nil || !strings.Contains(err.Error(), "80, 443") {
			t.Errorf("refusal = %v, want it to name the relayed ports 80, 443", err)
		}
	})

	t.Run("BuildConfig wires the class", func(t *testing.T) {
		t.Parallel()
		cfg, err := BuildConfig(Options{
			NodePodCIDR: node,
			ServiceCIDR: netip.MustParsePrefix("10.43.0.0/16"),
			VMPodPorts:  vmPodPorts,
		})
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if err := cfg.PortAuthorizer.Authorize(context.Background(), 443, "100.64.3.7"); err != nil {
			t.Errorf("assembled authorizer refused a published vm pod's declared port: %v", err)
		}
		if err := cfg.PortAuthorizer.Authorize(context.Background(), 443, "100.64.3.9"); err == nil {
			t.Error("assembled authorizer admitted an unpublished pod address")
		}
	})
}

// TestNodePodCIDRInForce pins the bound the published-vm-pod class reads: the
// identity netd persisted once a join adopted one, re-read on every call, and
// the configured pre-adoption value otherwise (no file, a malformed file, a
// prefix outside the cluster aggregate, persistence off).
func TestNodePodCIDRInForce(t *testing.T) {
	t.Parallel()
	configured := netip.MustParsePrefix("100.64.0.0/24")
	dir := t.TempDir()
	path := filepath.Join(dir, NodeIdentityFileName)
	inForce := NodePodCIDRInForce(path, configured)

	if got := inForce(); got != configured {
		t.Errorf("no identity file: %s, want %s", got, configured)
	}
	write := func(v string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("100.64.5.0/24\n")
	if got, want := inForce(), netip.MustParsePrefix("100.64.5.0/24"); got != want {
		t.Errorf("adopted identity: %s, want %s", got, want)
	}
	write("not a prefix")
	if got := inForce(); got != configured {
		t.Errorf("malformed identity: %s, want %s", got, configured)
	}
	write("10.0.0.0/24")
	if got := inForce(); got != configured {
		t.Errorf("identity outside the cluster aggregate: %s, want %s", got, configured)
	}
	if got := NodePodCIDRInForce("", configured)(); got != configured {
		t.Errorf("persistence off: %s, want %s", got, configured)
	}
}

// TestPortAuthorizerSyncedWording pins the refusal text for an unsynced
// Service set versus a synced one that declares nothing on the port.
func TestPortAuthorizerSyncedWording(t *testing.T) {
	svcCIDR := netip.MustParsePrefix("10.43.0.0/16")
	canonical := ServiceRef{Namespace: "kube-system", Name: "k3sm-ingress"}
	synced := false
	a := PortAuthorizer(PortPolicy{
		ServiceCIDR:        svcCIDR,
		NodeIP:             netip.MustParseAddr("192.168.7.20"),
		NodeAddressService: canonical,
		Declares:           func(int) bool { return false },
		LBDeclarers:        func(int) []ServiceRef { return nil },
		Synced:             func() bool { return synced },
	})
	cases := []struct {
		name, addr, want string
		synced           bool
	}{
		{"vip unsynced", "10.43.0.10", "service set not yet synced; port 53 cannot be authorized yet on 10.43.0.10", false},
		{"vip synced", "10.43.0.10", "no service declares port 53 (requested on 10.43.0.10)", true},
		{"node address unsynced", "192.168.7.20", "service set not yet synced; port 53 cannot be authorized yet on node address 192.168.7.20", false},
		{"node address synced", "192.168.7.20", "does not declare port 53", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synced = tc.synced
			err := a.Authorize(context.Background(), 53, tc.addr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Authorize error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestPortAuthorizerAdmitsListedLBPortOnHostAddress is the host-address class
// table: with LAN access off the svclb hoster asks netd for a LoadBalancer
// port below 1024 on one of this Mac's own addresses. It is admitted only for
// a port the operator listed, on an address assigned to an interface now, that
// is not loopback, a Service-CIDR VIP or a pod address (inside the cluster pod
// range only this node's mesh-egress address is its own), and only while some
// LoadBalancer Service declares the port. 127.0.0.1 is admitted on the same
// terms (no other loopback address is), and so is the wildcard, so the
// hoster's LAN-on and LAN-off listeners of a listed port share one owner. The
// address shapes are only the hoster's: 127.0.0.1, this node's .1 (even beside
// a vm pod in the same /24), and en* addresses; a utun, bridge, awdl or other
// lo0 address is refused. A port the canonical ingress Service declares is
// refused on every shape but the ingress host's own wildcard.
func TestPortAuthorizerAdmitsListedLBPortOnHostAddress(t *testing.T) {
	t.Parallel()
	nodeCIDR := netip.MustParsePrefix("100.64.3.0/24")
	lan := netip.MustParseAddr("192.168.7.20")
	egress := netip.MustParseAddr("100.64.3.1")
	tenant := ServiceRef{Namespace: "default", Name: "www"}
	host := map[netip.Addr]string{
		netip.MustParseAddr("127.0.0.1"):    "lo0",
		egress:                              "lo0",
		lan:                                 "en0",
		netip.MustParseAddr("192.168.8.4"):  "en7",
		netip.MustParseAddr("100.64.3.7"):   "lo0",
		netip.MustParseAddr("10.43.0.20"):   "lo0",
		netip.MustParseAddr("100.64.9.1"):   "lo0",
		netip.MustParseAddr("100.64.3.255"): "utun4",
		netip.MustParseAddr("172.20.0.9"):   "utun5",
		netip.MustParseAddr("192.168.64.1"): "bridge100",
		netip.MustParseAddr("169.254.3.3"):  "awdl0",
		netip.MustParseAddr("192.0.2.77"):   "lo0",
	}
	// 80 and 443 are tenant ports; 8 is listed and also the canonical ingress
	// Service's; 22 is declared but not listed.
	lbDeclarers := func(port int) []ServiceRef {
		switch port {
		case 80, 443, 22:
			return []ServiceRef{tenant}
		case 8:
			return []ServiceRef{tenant, canonicalIngress}
		}
		return nil
	}
	full := PortPolicy{
		ServiceCIDR:        netip.MustParsePrefix("10.43.0.0/16"),
		Declares:           func(int) bool { return false },
		LBDeclarers:        lbDeclarers,
		NodeAddressService: canonicalIngress,
		NodePodCIDR:        func() netip.Prefix { return nodeCIDR },
		VMPodPorts: func(a netip.Addr) []uint16 {
			if a == netip.MustParseAddr("100.64.3.7") {
				return []uint16{443}
			}
			return nil
		},
		LBPrivilegedPorts: []uint16{8, 80, 443},
		InterfaceAddrs:    func() (map[netip.Addr]string, error) { return host, nil },
	}
	with := func(edit func(*PortPolicy)) PortPolicy {
		p := full
		edit(&p)
		return p
	}

	cases := []struct {
		name    string
		policy  PortPolicy
		port    int
		addr    string
		allow   bool
		mention string
	}{
		{name: "listed port on the node's mesh-egress address", policy: full, port: 80, addr: "100.64.3.1", allow: true},
		{name: "listed port on a live en0 address", policy: full, port: 443, addr: "192.168.7.20", allow: true},
		{name: "listed port on another en* interface", policy: full, port: 80, addr: "192.168.8.4", allow: true},
		{name: "the node's .1 with a vm pod in the same /24", policy: full, port: 443, addr: "100.64.3.1", allow: true},
		{name: "a vm pod's own address keeps its own class", policy: full, port: 443, addr: "100.64.3.7", allow: true},
		{name: "a utun address", policy: full, port: 80, addr: "172.20.0.9", mention: "on utun5"},
		{name: "the mesh utun link address", policy: full, port: 80, addr: "100.64.3.255"},
		{name: "a vm bridge address", policy: full, port: 80, addr: "192.168.64.1", mention: "on bridge100"},
		{name: "an awdl address", policy: full, port: 80, addr: "169.254.3.3"},
		{name: "another lo0 alias", policy: full, port: 80, addr: "192.0.2.77", mention: "on lo0"},
		{name: "an ingress-owned listed port on the node address is the ingress host's bind", policy: full, port: 8, addr: "100.64.3.1", allow: true},
		{name: "an ingress-owned listed port on 127.0.0.1", policy: full, port: 8, addr: "127.0.0.1", mention: "belongs to the ingress host"},
		{name: "an ingress-owned listed port on an en* address is the ingress host's bind", policy: full, port: 8, addr: "192.168.7.20", allow: true},
		{name: "IPv4-mapped spelling of a live address", policy: full, port: 80, addr: "::ffff:100.64.3.1", allow: true},
		{name: "a port not in the list", policy: full, port: 22, addr: "100.64.3.1", mention: "port 22 on 100.64.3.1 is not in the allowed LoadBalancer port list (8, 80, 443)"},
		{name: "an empty list allows nothing", policy: with(func(p *PortPolicy) { p.LBPrivilegedPorts = nil }), port: 80, addr: "100.64.3.1", mention: "not in the allowed LoadBalancer port list (empty)"},
		{name: "127.0.0.1 on a listed port", policy: full, port: 80, addr: "127.0.0.1", allow: true},
		{name: "127.0.0.1 on a port not in the list", policy: full, port: 22, addr: "127.0.0.1", mention: "not in the allowed LoadBalancer port list"},
		{name: "127.0.0.1 with no declaring LoadBalancer service", policy: with(func(p *PortPolicy) { p.LBDeclarers = func(int) []ServiceRef { return nil } }), port: 80, addr: "127.0.0.1", mention: "no LoadBalancer service declares port 80"},
		{name: "another 127/8 address", policy: full, port: 80, addr: "127.0.0.2", mention: "only loopback address authorized"},
		{name: "IPv6 loopback", policy: full, port: 80, addr: "::1", mention: "only loopback address authorized"},
		{name: "the wildcard on a listed port a tenant declares", policy: full, port: 80, addr: "0.0.0.0", allow: true},
		{name: "the wildcard on a port not in the list", policy: full, port: 22, addr: "0.0.0.0"},
		{name: "the wildcard on a listed port nobody declares", policy: with(func(p *PortPolicy) { p.LBDeclarers = func(int) []ServiceRef { return nil } }), port: 80, addr: "0.0.0.0"},
		{name: "the ingress keeps its own wildcard on a listed port it declares", policy: full, port: 8, addr: "0.0.0.0", allow: true},
		{name: "a service-CIDR address", policy: full, port: 80, addr: "10.43.0.20"},
		{name: "a pod address of this node", policy: full, port: 80, addr: "100.64.3.7"},
		{name: "another node's mesh-egress address", policy: full, port: 80, addr: "100.64.9.1", mention: "cluster pod range"},
		{name: "an address not assigned to this Mac", policy: full, port: 80, addr: "192.168.7.99", mention: "not assigned to this Mac"},
		{name: "no LoadBalancer service declares the port", policy: with(func(p *PortPolicy) { p.LBDeclarers = func(int) []ServiceRef { return nil } }), port: 80, addr: "100.64.3.1", mention: "no LoadBalancer service declares port 80"},
		{name: "nil LoadBalancer service set", policy: with(func(p *PortPolicy) { p.LBDeclarers = nil }), port: 80, addr: "100.64.3.1"},
		{name: "unsynced service set", policy: with(func(p *PortPolicy) { p.Synced = func() bool { return false } }), port: 80, addr: "100.64.3.1", mention: "not yet synced"},
		{name: "nil host address set", policy: with(func(p *PortPolicy) { p.InterfaceAddrs = nil }), port: 80, addr: "100.64.3.1"},
		{name: "an unreadable host address set", policy: with(func(p *PortPolicy) {
			p.InterfaceAddrs = func() (map[netip.Addr]string, error) { return nil, errors.New("no interfaces") }
		}), port: 80, addr: "100.64.3.1"},
		{name: "the IPv6 unspecified address stays refused", policy: full, port: 80, addr: "::"},
		{name: "an IPv6 address", policy: with(func(p *PortPolicy) {
			p.InterfaceAddrs = func() (map[netip.Addr]string, error) {
				return map[netip.Addr]string{netip.MustParseAddr("2001:db8::1"): "en0"}, nil
			}
		}), port: 80, addr: "2001:db8::1"},
		{name: "the zero policy", policy: PortPolicy{}, port: 80, addr: "192.168.7.20"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := PortAuthorizer(tc.policy).Authorize(context.Background(), tc.port, tc.addr)
			if tc.allow && err != nil {
				t.Errorf("Authorize(%d, %s) = %v, want authorized", tc.port, tc.addr, err)
			}
			if !tc.allow && err == nil {
				t.Errorf("Authorize(%d, %s) authorized, want refused", tc.port, tc.addr)
			}
			if tc.mention != "" && (err == nil || !strings.Contains(err.Error(), tc.mention)) {
				t.Errorf("refusal = %v, want it to say %q", err, tc.mention)
			}
		})
	}

	t.Run("an unlisted wildcard is still the canonical ingress Service's alone", func(t *testing.T) {
		t.Parallel()
		p := with(func(p *PortPolicy) { p.NodeAddressService = canonicalIngress })
		if err := PortAuthorizer(p).Authorize(context.Background(), 22, "0.0.0.0"); err == nil {
			t.Error("an unlisted port declared only by a tenant Service authorized the wildcard")
		}
		canon := with(func(p *PortPolicy) {
			p.NodeAddressService = canonicalIngress
			p.LBPrivilegedPorts = nil
			p.LBDeclarers = func(int) []ServiceRef { return []ServiceRef{canonicalIngress} }
		})
		if err := PortAuthorizer(canon).Authorize(context.Background(), 8, "0.0.0.0"); err != nil {
			t.Errorf("the canonical ingress Service no longer authorizes its own wildcard: %v", err)
		}
	})

	t.Run("the host address set is read on every request", func(t *testing.T) {
		t.Parallel()
		cur := map[netip.Addr]string{lan: "en0"}
		p := with(func(p *PortPolicy) { p.InterfaceAddrs = func() (map[netip.Addr]string, error) { return cur, nil } })
		a := PortAuthorizer(p)
		if err := a.Authorize(context.Background(), 80, "192.168.7.20"); err != nil {
			t.Fatalf("live address refused: %v", err)
		}
		cur = map[netip.Addr]string{netip.MustParseAddr("192.168.7.21"): "en0"}
		if err := a.Authorize(context.Background(), 80, "192.168.7.20"); err == nil {
			t.Error("an address the Mac no longer holds was still authorized")
		}
	})

	t.Run("BuildConfig wires the class", func(t *testing.T) {
		t.Parallel()
		cfg, err := BuildConfig(Options{
			NodePodCIDR:       nodeCIDR,
			ServiceCIDR:       netip.MustParsePrefix("10.43.0.0/16"),
			LBDeclarers:       lbDeclarers,
			LBPrivilegedPorts: []uint16{80},
			InterfaceAddrs:    func() (map[netip.Addr]string, error) { return host, nil },
		})
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if err := cfg.PortAuthorizer.Authorize(context.Background(), 80, "100.64.3.1"); err != nil {
			t.Errorf("assembled authorizer refused a listed port on the node address: %v", err)
		}
		if err := cfg.PortAuthorizer.Authorize(context.Background(), 443, "100.64.3.1"); err == nil {
			t.Error("assembled authorizer admitted a port the list does not name")
		}
	})
}

// TestAuthorizeLBDeclaredRefusesAnIngressOwnedPort pins the ownership rule on
// the declarer set itself: when the canonical ingress Service is among a
// port's LoadBalancer declarers the listed-port classes refuse, whoever else
// declares it, and a port only tenants declare is admitted.
func TestAuthorizeLBDeclaredRefusesAnIngressOwnedPort(t *testing.T) {
	t.Parallel()
	tenant := ServiceRef{Namespace: "default", Name: "www"}
	a := servicePortAuthorizer{policy: PortPolicy{
		NodeAddressService: canonicalIngress,
		LBDeclarers: func(port int) []ServiceRef {
			if port == 80 {
				return []ServiceRef{tenant, canonicalIngress}
			}
			return []ServiceRef{tenant}
		},
	}}
	err := a.authorizeLBDeclared(80, "100.64.3.1")
	if err == nil || !strings.Contains(err.Error(), "belongs to the ingress host") || !strings.Contains(err.Error(), canonicalIngress.String()) {
		t.Errorf("authorizeLBDeclared(80) = %v, want the ingress-ownership refusal naming %s", err, canonicalIngress)
	}
	if err := a.authorizeLBDeclared(443, "100.64.3.1"); err != nil {
		t.Errorf("authorizeLBDeclared(443) = %v, want admitted: only a tenant declares it", err)
	}
}

// TestIngressHostNodeAddressBindAdmitted is the B709 gate. With LAN access off
// the ingress host binds 80 and 443 on the node's own address through netd,
// which reaches the host-address class. A port the canonical ingress Service
// declares is admitted there for the ingress host on the node's mesh-egress
// .1 and on an en* address whether or not the operator listed it, never on
// 127.0.0.1, and a port only tenants declare keeps the listed-port rule.
func TestIngressHostNodeAddressBindAdmitted(t *testing.T) {
	t.Parallel()
	tenant := ServiceRef{Namespace: "default", Name: "www"}
	host := map[netip.Addr]string{
		netip.MustParseAddr("127.0.0.1"):    "lo0",
		netip.MustParseAddr("100.64.0.1"):   "lo0",
		netip.MustParseAddr("192.168.7.20"): "en0",
	}
	// 80 and 443 are the ingress's (443 with a tenant beside it); 8080 is a
	// tenant's listed port; 22 a tenant's unlisted one.
	declarers := func(port int) []ServiceRef {
		switch port {
		case 80:
			return []ServiceRef{canonicalIngress}
		case 443:
			return []ServiceRef{tenant, canonicalIngress}
		case 8080, 22:
			return []ServiceRef{tenant}
		}
		return nil
	}
	// The server's netd: no --node-ip, an operator port list of 8080 only, and
	// the mesh /24 in force.
	server := PortPolicy{
		ServiceCIDR:        netip.MustParsePrefix("10.43.0.0/16"),
		Declares:           func(int) bool { return false },
		LBDeclarers:        declarers,
		NodeAddressService: canonicalIngress,
		NodePodCIDR:        func() netip.Prefix { return netip.MustParsePrefix("100.64.0.0/24") },
		LBPrivilegedPorts:  []uint16{8080},
		InterfaceAddrs:     func() (map[netip.Addr]string, error) { return host, nil },
	}
	nobody := server
	nobody.LBDeclarers = func(int) []ServiceRef { return nil }
	listed := server
	listed.LBPrivilegedPorts = []uint16{80, 443}

	for _, tc := range []struct {
		name    string
		policy  PortPolicy
		port    int
		addr    string
		allow   bool
		mention string
	}{
		{name: "ingress-declared 80 on the mesh .1", policy: server, port: 80, addr: "100.64.0.1", allow: true},
		{name: "ingress-declared 80 on an en* address", policy: server, port: 80, addr: "192.168.7.20", allow: true},
		{name: "ingress-declared 443 a tenant also declares, on the mesh .1", policy: server, port: 443, addr: "100.64.0.1", allow: true},
		{name: "ingress-declared 80 listed too, on the mesh .1", policy: listed, port: 80, addr: "100.64.0.1", allow: true},
		{name: "ingress-declared 80 on 127.0.0.1", policy: listed, port: 80, addr: "127.0.0.1", mention: "belongs to the ingress host"},
		{name: "ingress-declared 80 unlisted on 127.0.0.1", policy: server, port: 80, addr: "127.0.0.1"},
		{name: "no LoadBalancer declares 80", policy: nobody, port: 80, addr: "100.64.0.1", mention: "not in the allowed LoadBalancer port list"},
		{name: "no LoadBalancer declares a listed 80", policy: func() PortPolicy { p := nobody; p.LBPrivilegedPorts = []uint16{80}; return p }(), port: 80, addr: "100.64.0.1", mention: "no LoadBalancer service declares port 80"},
		{name: "a tenant-only listed port keeps the listed rule", policy: server, port: 8080, addr: "100.64.0.1", allow: true},
		{name: "a tenant-only unlisted port", policy: server, port: 22, addr: "100.64.0.1", mention: "not in the allowed LoadBalancer port list"},
		{name: "ingress-declared 80 on a non-en interface", policy: func() PortPolicy {
			p := server
			p.InterfaceAddrs = func() (map[netip.Addr]string, error) {
				return map[netip.Addr]string{netip.MustParseAddr("192.168.64.1"): "bridge100"}, nil
			}
			return p
		}(), port: 80, addr: "192.168.64.1", mention: "on bridge100"},
		{name: "ingress-declared 80 before the first sync", policy: func() PortPolicy { p := listed; p.Synced = func() bool { return false }; return p }(), port: 80, addr: "100.64.0.1", mention: "not yet synced"},
		{name: "the ingress's wildcard is unchanged", policy: server, port: 80, addr: "0.0.0.0", allow: true},
		{name: "a tenant's wildcard on an unlisted ingress port is unchanged", policy: server, port: 22, addr: "0.0.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := PortAuthorizer(tc.policy).Authorize(context.Background(), tc.port, tc.addr)
			if tc.allow && err != nil {
				t.Errorf("Authorize(%d, %s) = %v, want authorized", tc.port, tc.addr, err)
			}
			if !tc.allow && err == nil {
				t.Errorf("Authorize(%d, %s) authorized, want refused", tc.port, tc.addr)
			}
			if tc.mention != "" && (err == nil || !strings.Contains(err.Error(), tc.mention)) {
				t.Errorf("refusal = %v, want it to say %q", err, tc.mention)
			}
		})
	}
}
