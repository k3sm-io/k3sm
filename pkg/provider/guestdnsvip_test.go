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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/podnet"
)

// TestGuestNetworkCarriesTheDNSVIP is the B612 gate: a vm pod's guest network
// carries the cluster DNS VIP its resolv.conf names, on a server and on a worker,
// and the provisioning log line prints that address.
//
// WHY THE IPAM CARRIES NO DNS VIP. Production never hands podnet a VM network
// config (cmd/k3sm builds the node's podnet.Network without WithVMNetwork, on
// either role), so the GuestNetwork it returns has a zero DNSVIP. Each leg below
// uses that production shape. The VIP the guest must carry is the one the
// provider's own per-pod DNS config names, which on both roles comes from the
// node's --dns-vip (RuntimedConfig.ResolverVIP), the address the node's resolver
// binds. The worker leg uses a non-default VIP, so a value that merely matches
// the default cannot pass it.
func TestGuestNetworkCarriesTheDNSVIP(t *testing.T) {
	t.Parallel()

	roles := []struct {
		name string
		vip  string
	}{
		{name: "server", vip: dns.DefaultDNSVIP},
		{name: "worker", vip: "10.96.0.10"},
	}
	for _, role := range roles {
		t.Run(role.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			ipam := newFakeIPAM(t, guestPodCIDR) // ipam.vm is zero: the production shape
			adapter := NewPodNetAdapter(ipam, guestNodeIP, slog.New(slog.NewTextHandler(&logs, nil)))
			r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
				NodeName: guestNodeName,
				NodeIP:   guestNodeIP,
				Root:     t.TempDir(), PodLogsDir: t.TempDir(),
				ResolverVIP:   role.vip,
				ClusterDomain: "cluster.local",
				Network:       adapter,
			}, nil, nil)

			pod := vmPod("team-a", "guest-"+role.name)
			dnsCfg, _ := r.podDNSConfig(pod)
			cfg, err := r.setupGuestNetwork(context.Background(), pod, dnsCfg)
			if err != nil {
				t.Fatalf("setupGuestNetwork: %v", err)
			}
			want := netip.MustParseAddr(role.vip)
			if cfg.DNSVIP != want {
				t.Errorf("guest DNSVIP = %v, want the node's cluster DNS VIP %v", cfg.DNSVIP, want)
			}
			if len(cfg.Nameservers) != 1 || cfg.Nameservers[0] != role.vip {
				t.Errorf("guest nameservers = %v, want [%s]: DNSVIP must name the resolver the guest's resolv.conf uses", cfg.Nameservers, role.vip)
			}
			recorded, ok := adapter.GuestNetwork(string(pod.UID))
			if !ok || recorded.DNSVIP != want {
				t.Errorf("recorded guest config DNSVIP = %v (ok=%v), want %v: runtimed reads the recorded value", recorded.DNSVIP, ok, want)
			}
			line := logs.String()
			if !strings.Contains(line, "guest network provisioned for vm pod") {
				t.Fatalf("no provisioning log line; log = %q", line)
			}
			if !strings.Contains(line, "dns_vip="+role.vip) {
				t.Errorf("provisioning log line does not carry dns_vip=%s; log = %q", role.vip, line)
			}
			if strings.Contains(line, "invalid IP") {
				t.Errorf("provisioning log line prints a zero address; log = %q", line)
			}
		})
	}

	// The unresolved case: a ClusterFirst config whose VIP is absent or does not
	// parse fails the provisioning with the named error, records nothing, and logs
	// no provisioning line. A guest booted from it would have no cluster resolver.
	unresolved := []struct {
		name string
		vip  string
	}{
		{name: "empty", vip: ""},
		{name: "unparseable", vip: "kube-dns"},
	}
	for _, tc := range unresolved {
		t.Run("unresolved/"+tc.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			adapter := NewPodNetAdapter(newFakeIPAM(t, guestPodCIDR), guestNodeIP, slog.New(slog.NewTextHandler(&logs, nil)))
			dnsCfg := netv1.DNSConfig{Policy: netv1.DNSPolicyClusterFirst, ClusterDNSIP: tc.vip, ClusterDomain: "cluster.local"}
			_, err := adapter.SetupGuest(context.Background(), "p-"+tc.name, dnsCfg)
			if !errors.Is(err, ErrGuestDNSVIPUnresolved) {
				t.Fatalf("SetupGuest error = %v, want ErrGuestDNSVIPUnresolved", err)
			}
			if _, ok := adapter.GuestNetwork("p-" + tc.name); ok {
				t.Error("a guest config was recorded for a guest with no cluster DNS VIP")
			}
			if strings.Contains(logs.String(), "guest network provisioned") {
				t.Errorf("provisioning was logged for a failed guest; log = %q", logs.String())
			}
		})
	}

	// Two authorities disagreeing is also unresolved: a podnet config that names
	// one VIP while the pod's resolv.conf names another would hand the guest a
	// diagnostic value that is not its resolver.
	t.Run("unresolved/disagreement", func(t *testing.T) {
		t.Parallel()
		ipam := newFakeIPAM(t, guestPodCIDR)
		ipam.vm = podnet.VMNetworkConfig{DNSVIP: netip.MustParseAddr("10.43.0.53")}
		adapter := NewPodNetAdapter(ipam, guestNodeIP, nil)
		_, err := adapter.SetupGuest(context.Background(), "p-disagree", dns.PodDNSConfig(guestDNSVIP, "cluster.local", "team-a"))
		if !errors.Is(err, ErrGuestDNSVIPUnresolved) {
			t.Fatalf("SetupGuest error = %v, want ErrGuestDNSVIPUnresolved", err)
		}
	})
}
