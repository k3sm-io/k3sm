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

// TestNetdAuthorizerNodeAddrLB is the M10.3 deny-by-default table for the
// node-own-address extension: a <1024 bind on the node's OWN InternalIP is
// authorized ONLY when a Service of type LoadBalancer declares the port (the
// ingress/svclb listener, declared by kube-system/k3sm-ingress). Everything
// else — wrong address, wrong port, only a non-LB Service declaring, a nil
// predicate, no configured node IP, an unparseable address — is denied.
func TestNetdAuthorizerNodeAddrLB(t *testing.T) {
	svcCIDR := netip.MustParsePrefix("10.43.0.0/16")
	nodeIP := netip.MustParseAddr("192.168.7.20")
	// The authoritative Service set: kube-dns (ClusterIP) declares 53; the
	// canonical k3sm-ingress LoadBalancer declares 80+443.
	declares := func(port int) bool { return port == 53 || port == 80 || port == 443 }
	declaresLB := func(port int) bool { return port == 80 || port == 443 }

	full := PortPolicy{ServiceCIDR: svcCIDR, Declares: declares, NodeIP: nodeIP, DeclaresLB: declaresLB}

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
		{"nil DeclaresLB denies the node-address class, fail-safe",
			PortPolicy{ServiceCIDR: svcCIDR, Declares: declares, NodeIP: nodeIP}, 80, "192.168.7.20", false},
		{"zero NodeIP disables the node-address class entirely",
			PortPolicy{ServiceCIDR: svcCIDR, Declares: declares, DeclaresLB: declaresLB}, 80, "192.168.7.20", false},
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
			DeclaresLB:  func(port int) bool { return port == 80 },
			NodeIP:      netip.MustParseAddr("192.168.7.20"),
			MeshKeyDir:  t.TempDir(),
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
