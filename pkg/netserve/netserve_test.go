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
	"os"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// TestM3_3_InfraVIPExemptionAndMeshEgressPassed proves netserve.New passes the
// right node-local-datapath config to the Service proxy for M3.3: the DNS VIP is
// recorded as the infra-VIP exemption (the proxy steps aside so the per-node
// resolver owns 10.43.0.10:53 — no EADDRINUSE) and the node's mesh-egress /32 is
// recorded as the proxy's backend-dial source (so cross-node dials are not
// blackholed by wireguard). darwin-net's proxy exempt_test.go / meshegress_test.go
// prove the proxy HONORS these; this proves k3sm SUPPLIES the right values, and
// selects the netd-helper binder when unprivileged. Maps to M3.3-a1.
func TestM3_3_InfraVIPExemptionAndMeshEgressPassed(t *testing.T) {
	t.Parallel()

	s := New(Config{
		Client:        fake.NewClientset(),
		WorkDir:       t.TempDir(),
		DNSVIP:        "10.43.0.10",
		ClusterDomain: "cluster.local",
		PodCIDR:       "100.64.1.0/24",
		MeshEgressIP:  "100.64.1.1",
		NetdSocket:    "/var/lib/k3sm/run/netd.sock",
	})
	if s.dnsVIP != netip.MustParseAddr("10.43.0.10") {
		t.Errorf("exempted DNS VIP = %v, want 10.43.0.10 (only the DNS VIP is exempted; the API VIP stays proxy-owned)", s.dnsVIP)
	}
	if s.meshEgress != netip.MustParseAddr("100.64.1.1") {
		t.Errorf("proxy mesh-egress source = %v, want 100.64.1.1 (the node's reserved /32)", s.meshEgress)
	}
	if _, ok := s.binder.(*helperDNSBinder); !ok {
		t.Errorf("resolver binder = %T, want *helperDNSBinder (NetdSocket set ⇒ unprivileged posture)", s.binder)
	}
}

// TestMeshEgressEmptyKeepsDefaultSource proves a single node (no mesh-egress IP)
// leaves the proxy's dialer on the kernel's default source selection — setting a
// non-local source would break every backend dial (the dialer binds it
// unconditionally), so an empty value must stay zero.
func TestMeshEgressEmptyKeepsDefaultSource(t *testing.T) {
	t.Parallel()
	s := New(Config{
		Client:        fake.NewClientset(),
		WorkDir:       t.TempDir(),
		DNSVIP:        "10.43.0.10",
		ClusterDomain: "cluster.local",
	})
	if s.meshEgress.IsValid() {
		t.Errorf("mesh-egress source = %v, want invalid/zero on a single node", s.meshEgress)
	}
}

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
