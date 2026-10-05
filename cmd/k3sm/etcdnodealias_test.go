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

package main

import (
	"context"
	"errors"
	"flag"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
)

// aliasRecordingIPAM is a provider.PodIPAM that records the node lo0 aliases the
// adapter's startup reconcile requests and touches no interface.
type aliasRecordingIPAM struct{ aliases []string }

func (r *aliasRecordingIPAM) Setup(context.Context, string) (netip.Addr, error) {
	return netip.Addr{}, errors.New("unused")
}

func (r *aliasRecordingIPAM) SetupGuest(context.Context, string) (podnet.GuestNetwork, error) {
	return podnet.GuestNetwork{}, errors.New("unused")
}
func (r *aliasRecordingIPAM) Teardown(context.Context, string) error { return nil }
func (r *aliasRecordingIPAM) ReattachPod(context.Context, string, netip.Addr) error {
	return nil
}
func (r *aliasRecordingIPAM) SweepStale(context.Context, map[string]netip.Addr) error { return nil }
func (r *aliasRecordingIPAM) EnsureNodeAlias(_ context.Context, ip netip.Addr) error {
	r.aliases = append(r.aliases, ip.String())
	return nil
}

// TestEtcdServerDoesNotAliasItsLANNodeIP pins that an embedded-etcd server's LAN
// address is its etcd PEER address only and never reaches the node's addressing.
//
// The defect it guards: `k3sm server --cluster-init --node-ip <LAN> --mesh-ip <mesh>`
// formed its etcd member and then exited 1 at every start, because --node-ip was
// also the node's advertised address and the pod-network startup reconcile asked
// netd to alias the LAN address on lo0. netd refuses any alias outside the node
// pod CIDR and the Service CIDR, so launchd restarted the daemon forever and every
// restart reaped the node's pods.
//
// Each row runs the server's own argv through the real flag set and validation,
// then the mesh rewrite (meshNodeIP), the advertise derivation (advertisedNodeIP),
// and the podnet adapter seam (newNodePodNetAdapter + ReconcileStartup) over a
// recording IPAM: exactly the chain startNode drives, without a real lo0.
func TestEtcdServerDoesNotAliasItsLANNodeIP(t *testing.T) {
	const (
		lan     = "192.0.2.50"
		lanB    = "192.0.2.51"
		meshIP  = "100.64.0.1"
		podCIDR = "100.64.0.0/24" // the server's index-0 /24, whose mesh-egress .1 is meshIP
	)
	cases := []struct {
		name          string
		argv          []string
		wantValidate  string // non-empty: validateEtcdFlags must refuse, naming this
		wantAdvertise string
		wantAliases   []string
		wantPeerIP    string // "" = the kine posture, no etcd block
		wantAliasErr  string // non-empty: the adapter seam refuses, naming this address
	}{
		{
			name:          "cluster-init: LAN peer address, mesh .1 advertised and aliased",
			argv:          []string{"--cluster-init", "--etcd-peer-ip", lan, "--mesh-ip", meshIP},
			wantAdvertise: meshIP,
			wantAliases:   []string{meshIP},
			wantPeerIP:    lan,
		},
		{
			name:          "server-join: LAN peer address, mesh .1 advertised and aliased",
			argv:          []string{"--server-join", "--server", lan, "--etcd-peer-ip", lanB, "--mesh-ip", meshIP},
			wantAdvertise: meshIP,
			wantAliases:   []string{meshIP},
			wantPeerIP:    lanB,
		},
		{
			name:          "single-server mesh node is unchanged",
			argv:          []string{"--mesh-ip", meshIP},
			wantAdvertise: meshIP,
			wantAliases:   []string{meshIP},
		},
		{
			name:          "single-node loopback server is unchanged: the derived .1",
			argv:          nil,
			wantAdvertise: meshIP,
			wantAliases:   []string{meshIP},
		},
		{
			name:         "the pre-split grammar (LAN on --node-ip) is refused before anything starts",
			argv:         []string{"--cluster-init", "--node-ip", lan, "--mesh-ip", meshIP},
			wantValidate: "--etcd-peer-ip",
		},
		{
			name:         "--node-ip equal to the peer address is refused",
			argv:         []string{"--cluster-init", "--etcd-peer-ip", lan, "--node-ip", lan, "--mesh-ip", meshIP},
			wantValidate: "--node-ip " + lan,
		},
		{
			name:          "a LAN --node-ip beside the peer address fails naming it, and is never aliased",
			argv:          []string{"--cluster-init", "--etcd-peer-ip", lan, "--node-ip", "192.0.2.60", "--mesh-ip", meshIP},
			wantAdvertise: "192.0.2.60",
			wantPeerIP:    lan,
			wantAliasErr:  "192.0.2.60",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("server", flag.ContinueOnError)
			opts := serverOptions{}
			_ = registerServerFlags(fs, &opts)
			if err := fs.Parse(tc.argv); err != nil {
				t.Fatalf("parse %q: %v", tc.argv, err)
			}
			err := opts.validateEtcdFlags()
			if tc.wantValidate != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantValidate) {
					t.Fatalf("validateEtcdFlags = %v, want a refusal naming %q", err, tc.wantValidate)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateEtcdFlags: %v", err)
			}

			// The etcd member peers on the LAN address, and only there.
			var gotPeer string
			if e := opts.etcdConfig(); e != nil {
				gotPeer = e.PeerIP
			}
			if gotPeer != tc.wantPeerIP {
				t.Errorf("etcd PeerIP = %q, want %q", gotPeer, tc.wantPeerIP)
			}

			// The mesh rewrite provisionMeshPKI applies, then the node addressing
			// startServerDatapath builds and startNode advertises.
			if opts.meshIP != "" {
				opts.nodeIP = meshNodeIP(opts)
			}
			node := nodeOptions{
				nodeIP:      opts.nodeIP,
				podCIDR:     podCIDR,
				serviceCIDR: install.DefaultServiceCIDR,
				netMode:     hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/var/run/k3sm-netd.sock"},
			}
			advertised := advertisedNodeIP(node)
			if advertised != tc.wantAdvertise {
				t.Errorf("advertised node address = %q, want %q", advertised, tc.wantAdvertise)
			}
			if tc.wantPeerIP != "" && advertised == tc.wantPeerIP {
				t.Errorf("the node advertises its etcd peer address %s", advertised)
			}
			node.nodeIP = advertised

			ipam := &aliasRecordingIPAM{}
			adapter, err := newNodePodNetAdapter(ipam, node)
			if tc.wantAliasErr != "" {
				if !errors.Is(err, errNodeAliasOutsidePodNetwork) || !strings.Contains(err.Error(), tc.wantAliasErr) {
					t.Fatalf("newNodePodNetAdapter = %v, want errNodeAliasOutsidePodNetwork naming %s", err, tc.wantAliasErr)
				}
				if len(ipam.aliases) != 0 {
					t.Errorf("aliases requested before the refusal: %q", ipam.aliases)
				}
				return
			}
			if err != nil {
				t.Fatalf("newNodePodNetAdapter: %v", err)
			}
			if err := adapter.ReconcileStartup(t.Context()); err != nil {
				t.Fatalf("ReconcileStartup: %v", err)
			}
			if !slices.Equal(ipam.aliases, tc.wantAliases) {
				t.Errorf("lo0 aliases requested = %q, want exactly %q", ipam.aliases, tc.wantAliases)
			}
			for _, a := range ipam.aliases {
				if a == lan || a == lanB {
					t.Errorf("the LAN address %s was requested as an lo0 alias", a)
				}
			}
		})
	}
}

// TestCheckNodeAliasAddr pins the pre-start refusal to netd's alias policy
// (darwin-net pkg/netd validateAliasIP), whose rows it carries: the node's own
// pod IPs (pkg/netd server_test: 100.64.0.2/.3/.7 on a 100.64.0.0/24 node) and the
// Service VIP (adopt_test: 10.43.0.10) pass; a LAN address (server_test:
// 192.168.1.5) and another node's /24 (adopt_test: 100.64.7.5 on a 100.64.0.0/24
// node, and 100.64.0.5 on a 100.64.7.0/24 node) are refused; and the
// IPv4-unicast shape rules (not IPv6, not multicast, not unspecified) hold. A
// custom Service CIDR replaces the default one rather than adding to it, and with
// none configured only the pod CIDR admits. Loopback and an unparseable value are
// the reconcile's own skip.
func TestCheckNodeAliasAddr(t *testing.T) {
	const svc = install.DefaultServiceCIDR // 10.43.0.0/16
	for _, tc := range []struct {
		name         string
		ip, pod, svc string
		ok           bool
	}{
		{"own pod IP .2", "100.64.0.2", "100.64.0.0/24", svc, true},
		{"own pod IP .3", "100.64.0.3", "100.64.0.0/24", svc, true},
		{"own pod IP .7", "100.64.0.7", "100.64.0.0/24", svc, true},
		{"own mesh-egress .1", "100.64.0.1", "100.64.0.0/24", svc, true},
		{"adopted /24's pod IP", "100.64.7.5", "100.64.7.0/24", svc, true},
		{"the Service DNS VIP", "10.43.0.10", "100.64.0.0/24", svc, true},
		{"a LAN address", "192.168.1.5", "100.64.0.0/24", svc, false},
		{"the HA server's LAN peer address", "192.0.2.50", "100.64.0.0/24", svc, false},
		{"another node's /24", "100.64.7.5", "100.64.0.0/24", svc, false},
		{"the previous /24 after adoption", "100.64.0.5", "100.64.7.0/24", svc, false},
		{"a pod CIDR outside the cluster aggregate", "10.200.0.1", "10.200.0.0/24", svc, false},
		{"IPv6", "fd00::1", "100.64.0.0/24", svc, false},
		{"multicast", "224.0.0.1", "100.64.0.0/24", "224.0.0.0/4", false},
		{"unspecified", "0.0.0.0", "100.64.0.0/24", "0.0.0.0/0", false},
		{"inside a custom Service CIDR", "10.96.0.10", "100.64.0.0/24", "10.96.0.0/12", true},
		{"the default range under a custom Service CIDR", "10.43.0.10", "100.64.0.0/24", "10.96.0.0/12", false},
		{"no Service CIDR configured: a VIP is refused", "10.43.0.10", "100.64.0.0/24", "", false},
		{"no Service CIDR configured: the pod CIDR still admits", "100.64.0.1", "100.64.0.0/24", "", true},
		{"loopback is the reconcile's skip", "127.0.0.1", "100.64.0.0/24", svc, true},
		{"empty is the reconcile's skip", "", "100.64.0.0/24", svc, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNodeAliasAddr(tc.ip, tc.pod, tc.svc)
			if tc.ok != (err == nil) {
				t.Fatalf("checkNodeAliasAddr(%q, %q, %q) = %v, want ok=%v", tc.ip, tc.pod, tc.svc, err, tc.ok)
			}
			if err != nil && (!errors.Is(err, errNodeAliasOutsidePodNetwork) || !strings.Contains(err.Error(), tc.ip)) {
				t.Errorf("the refusal is not errNodeAliasOutsidePodNetwork naming %s: %v", tc.ip, err)
			}
		})
	}
}

// TestMeshServerAliasAgreesWithSeededNetdRange pins that the node-address check
// and the install's netd seed agree on a mesh server's own address: for every
// --mesh-ip the install accepts, checkNodeAliasAddr admits that address against
// the node range install.MeshNodePodCIDR seeds netd with, so the check refuses
// nothing netd would admit at the server's first start.
func TestMeshServerAliasAgreesWithSeededNetdRange(t *testing.T) {
	for _, mesh := range []string{"100.64.0.1", "100.64.1.1", "100.64.7.1", "100.127.255.1"} {
		t.Run(mesh, func(t *testing.T) {
			if err := validateMeshIP(mesh); err != nil {
				t.Fatalf("validateMeshIP(%s) = %v, want accepted", mesh, err)
			}
			cidr, err := install.MeshNodePodCIDR(mesh)
			if err != nil {
				t.Fatalf("MeshNodePodCIDR(%s): %v", mesh, err)
			}
			if err := checkNodeAliasAddr(mesh, cidr.String(), install.DefaultServiceCIDR); err != nil {
				t.Errorf("checkNodeAliasAddr(%s, %s) = %v; the node check refuses the address netd is seeded to admit", mesh, cidr, err)
			}
			if gw, err := podnet.MeshEgressIP(cidr); err != nil || gw.String() != mesh {
				t.Errorf("the seeded range %s has mesh-egress %v (err %v), want %s", cidr, gw, err, mesh)
			}
		})
	}
}
