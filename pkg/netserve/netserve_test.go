package netserve

import (
	"os"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// TestPodDNSConfigUsesDarwinNetSeam verifies netserve hands pods darwin-net's
// PodDNSConfig (cluster DNS VIP + domain + search list) rather than
// reimplementing ndots/search.
func TestPodDNSConfigUsesDarwinNetSeam(t *testing.T) {
	s := New(Config{
		Client:        fake.NewClientset(),
		WorkDir:       t.TempDir(),
		DNSVIP:        "10.43.0.10",
		ClusterDomain: "cluster.local",
	})
	cfg := s.PodDNSConfig("default")
	if cfg.ClusterDNSIP != "10.43.0.10" {
		t.Errorf("ClusterDNSIP = %q, want 10.43.0.10", cfg.ClusterDNSIP)
	}
	if cfg.ClusterDomain != "cluster.local" {
		t.Errorf("ClusterDomain = %q, want cluster.local", cfg.ClusterDomain)
	}
	wantSearch := "default.svc.cluster.local"
	found := false
	for _, d := range cfg.SearchDomains {
		if d == wantSearch {
			found = true
		}
	}
	if !found {
		t.Errorf("search domains %v missing %q", cfg.SearchDomains, wantSearch)
	}
}

// TestNetdSocketConstructs proves the unprivileged posture (a non-empty
// NetdSocket) constructs the proxy with the netd-helper backend without panic —
// the construction-time selection of the helper alias/binder over the direct
// root path. The helper-vs-direct decision itself is table-tested in pkg/hostnet.
func TestNetdSocketConstructs(t *testing.T) {
	s := New(Config{
		Client:        fake.NewClientset(),
		WorkDir:       t.TempDir(),
		DNSVIP:        "10.43.0.10",
		ClusterDomain: "cluster.local",
		NetdSocket:    "/var/lib/k3sm/run/netd.sock",
	})
	if s == nil || s.proxy == nil {
		t.Fatal("New with a NetdSocket must build a proxy routed through the helper")
	}
}

// TestWriteCorefile checks the rendered CoreDNS config binds the DNS VIP and
// serves the cluster domain via the kubernetes plugin.
func TestWriteCorefile(t *testing.T) {
	dir := t.TempDir()
	s := New(Config{
		Client:        fake.NewClientset(),
		WorkDir:       dir,
		DNSVIP:        "10.43.0.10",
		ClusterDomain: "cluster.local",
	})
	if err := s.writeCorefile(); err != nil {
		t.Fatalf("writeCorefile: %v", err)
	}
	b, err := os.ReadFile(s.CorefilePath())
	if err != nil {
		t.Fatalf("read corefile: %v", err)
	}
	cf := string(b)
	if !strings.Contains(cf, "bind 10.43.0.10") {
		t.Errorf("corefile does not bind the DNS VIP:\n%s", cf)
	}
	if !strings.Contains(cf, "kubernetes cluster.local") {
		t.Errorf("corefile does not serve the cluster domain:\n%s", cf)
	}
}
