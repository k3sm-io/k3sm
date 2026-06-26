package netdsvc

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// TestPortAuthorizer proves the privileged-port policy: a port a Service
// declares is allowed; an undeclared <1024 port is denied; and a nil declares
// (no Service set available) denies every bind — fail safe, the daemon never
// trusts the client's self-assertion.
func TestPortAuthorizer(t *testing.T) {
	declares := func(port int) bool { return port == 53 } // kube-dns declares :53
	a := PortAuthorizer(declares)

	if err := a.Authorize(context.Background(), 53, "10.43.0.10"); err != nil {
		t.Errorf("declared port 53 must be authorized, got %v", err)
	}
	if err := a.Authorize(context.Background(), 80, "10.43.0.20"); err == nil {
		t.Error("undeclared privileged port 80 must be denied")
	}

	deny := PortAuthorizer(nil)
	if err := deny.Authorize(context.Background(), 53, "10.43.0.10"); err == nil {
		t.Error("a nil declares (no service set) must deny every bind, fail-safe")
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
