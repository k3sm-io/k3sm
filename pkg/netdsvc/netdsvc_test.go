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
		if _, err := r.Resolve(context.Background(), "absent.key"); err == nil {
			t.Error("a missing key must error, never return an embedded default")
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
		})
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
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
