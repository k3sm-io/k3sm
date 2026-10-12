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
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
)

// icIfconfig is `ifconfig bridge0` on a healthy cabled node with cluster index
// 1: both Thunderbolt ports are members, the self-assigned address is there,
// the node's slot-0 address 169.254.0.9 carries the /24, and one pod's slot-1
// address 169.254.0.10 rides it.
const icIfconfig = `bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 169.254.9.209 netmask 0xffff0000 broadcast 169.254.255.255
	inet 169.254.0.9 netmask 0xffffff00 broadcast 169.254.0.255
	inet 169.254.0.10 netmask 0xffffffff
	member: en1 flags=3<LEARNING,DISCOVER>
	member: en2 flags=3<LEARNING,DISCOVER>
	status: active
`

// icNetstat is the 169.254 part of `netstat -rn -f inet` on that node: the
// self-assigned /16, the connected /24, and an ARP entry for the peer.
const icNetstat = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.0.1        UGScg                 en0
169.254            link#30            UCS               bridge0      !
169.254.0/24       link#30            UCS               bridge0      !
169.254.0.1        36:a1:2b:0:0:2     UHLWIi            bridge0   1190
`

// icNodeCIDR is the pod /24 with cluster index 1, the identity netd adopted.
func icNodeCIDR(t *testing.T) netip.Prefix {
	t.Helper()
	p, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 1)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// healthyIC is a cabled worker-to-studio node, armed, with one MLX rank pod
// attached: every row passes. Each case overrides the one seam under test.
func healthyIC(t *testing.T) *interconnectEnv {
	t.Helper()
	cidr := icNodeCIDR(t)
	return &interconnectEnv{
		ports: func() ([]linkenum.Port, error) {
			return []linkenum.Port{
				{Iface: "en1", PortOrdinal: 0, DomainUUID: "local-1", PeerDomainUUID: "studio-3", SpeedGbps: 40},
				{Iface: "en2", PortOrdinal: 1, DomainUUID: "local-2"},
			}, nil
		},
		bridge: func() (install.BridgeState, error) { return install.ParseBridgeIfconfig([]byte(icIfconfig)), nil },
		routes: func() ([]icRoute, error) { return parseNetstatRoutes(icNetstat), nil },
		neighbors: func() ([]netip.Addr, error) {
			return parseARPNeighbors("? (169.254.0.1) at 36:a1:2b:0:0:2 on bridge0 [bridge]\n? (169.254.0.2) at 36:a1:2b:0:0:2 on bridge0 [bridge]\n? (169.254.0.17) at (incomplete) on bridge0 [bridge]\n"), nil
		},
		rtt: func(addrs []netip.Addr) map[netip.Addr]time.Duration {
			out := map[netip.Addr]time.Duration{}
			for _, a := range addrs {
				out[a] = 660 * time.Microsecond
			}
			return out
		},
		helper: func() error { return nil },
		ledger: func() ([]install.InterconnectAlias, error) {
			return install.ParseInterconnectLedger([]byte(`{"aliases":[{"slot":0,"address":"169.254.0.9"},{"slot":1,"address":"169.254.0.10"}]}`))
		},
		identity: func() (netip.Prefix, error) { return cidr, nil },
		cluster: func() (icCluster, error) {
			return icCluster{Node: "mikobook", Desired: true, MemberState: netv1alpha1.InterconnectMemberUp,
				Pods: []status.InterconnectPod{{Namespace: "mlx", Pod: "llama-1", Node: "mikobook", Address: "169.254.0.10"}}}, nil
		},
		power: func() (powerSettings, error) {
			return parsePmset(" sleep                0\n displaysleep         10\n autorestart          1\n"), nil
		},
		autoLogin: func() (string, error) { return "miko", nil },
	}
}

// icRows runs the section and indexes its rows by name.
func icRows(t *testing.T, ic *interconnectEnv, role install.Role) ([]checkResult, map[string]checkResult) {
	t.Helper()
	rows := interconnectChecks(ic, role)
	by := map[string]checkResult{}
	for _, r := range rows {
		if _, dup := by[r.name]; dup {
			t.Fatalf("row %q appears twice", r.name)
		}
		by[r.name] = r
	}
	return rows, by
}

// mustRow returns the named row and fails when it is absent.
func mustRow(t *testing.T, by map[string]checkResult, name string) checkResult {
	t.Helper()
	r, ok := by[name]
	if !ok {
		t.Fatalf("no %s row", name)
	}
	return r
}

// TestDoctorInterconnectSection is the doctor gate of the interconnect. On a
// cabled Mac `k3sm doctor` checks bridge0 and its Thunderbolt members, netd's
// socket, this node's slot-0 address and its /24, the peers and their round
// trip, the pods holding an interconnect address, cable loops, stray
// reserved-range state, the undeletable cloned-route residue (reported as
// harmless), and the three TN3205 settings; each row is OK, WARN or FAIL with
// a one-line remedy.
func TestDoctorInterconnectSection(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		rows, by := icRows(t, healthyIC(t), install.RoleAgent)
		want := []string{icBridge, icNetd, icAddress, icPeers, icPods, icLoop, icStray, icSleep, icAutoLogin, icPower}
		if len(rows) != len(want) {
			t.Fatalf("rows = %v, want %v", rows, want)
		}
		for i, name := range want {
			r := rows[i]
			if r.name != name {
				t.Errorf("row %d = %q, want %q", i, r.name, name)
			}
			if r.status != statusPass {
				t.Errorf("%s = %v (%q), want PASS", r.name, r.status, r.detail)
			}
			if r.detail == "" {
				t.Errorf("%s has no detail", r.name)
			}
		}
		for name, want := range map[string]string{
			icBridge:  "en1 (Thunderbolt 1), en2 (Thunderbolt 2)",
			icAddress: "169.254.0.9/24 on bridge0",
			icPeers:   "169.254.0.1 0.66 ms",
			icPods:    "mlx/llama-1 169.254.0.10",
		} {
			if d := mustRow(t, by, name).detail; !strings.Contains(d, want) {
				t.Errorf("%s detail %q does not say %q", name, d, want)
			}
		}
		if d := mustRow(t, by, icPeers).detail; strings.Contains(d, "169.254.0.2 ") || strings.Contains(d, "169.254.0.17") {
			t.Errorf("peers %q include a pod address or an incomplete ARP entry", d)
		}

		// The section rides the doctor report: a healthy run still exits 0.
		env := healthyDoctorEnv()
		env.interconnect = healthyIC(t)
		rep, screen, code := reportFor(t, env)
		if code != 0 {
			t.Errorf("exit = %d, want 0:\n%s", code, screen)
		}
		if _, ok := rep.Row(icAddress); !ok {
			t.Errorf("the doctor report does not carry the interconnect rows:\n%s", screen)
		}
	})

	t.Run("address missing", func(t *testing.T) {
		ic := healthyIC(t)
		ic.bridge = func() (install.BridgeState, error) {
			st := install.ParseBridgeIfconfig([]byte(icIfconfig))
			delete(st.Addrs, netip.MustParseAddr("169.254.0.9"))
			return st, nil
		}
		_, by := icRows(t, ic, install.RoleAgent)
		r := mustRow(t, by, icAddress)
		if r.status != statusFail || !strings.Contains(r.detail, "169.254.0.9 is not on bridge0") {
			t.Fatalf("address = %v %q, want FAIL naming 169.254.0.9", r.status, r.detail)
		}
		if !strings.Contains(r.remedy, "kickstart -k system/"+install.AgentLabel) {
			t.Errorf("remedy %q does not restart this worker's node daemon", r.remedy)
		}
		if p := mustRow(t, by, icPeers); p.status != statusSkip {
			t.Errorf("peers = %v with no address to reach from, want SKIP", p.status)
		}

		// The same absence on a node that is not an armed member is the
		// default, not a fault.
		ic.ledger = func() ([]install.InterconnectAlias, error) { return nil, nil }
		ic.cluster = func() (icCluster, error) { return icCluster{Node: "mikobook"}, nil }
		_, by = icRows(t, ic, install.RoleAgent)
		if r := mustRow(t, by, icAddress); r.status != statusSkip {
			t.Errorf("an unarmed node's address row = %v %q, want SKIP", r.status, r.detail)
		}

		// A /32 where the /24 belongs is repaired by the node, not a pass.
		ic = healthyIC(t)
		ic.bridge = func() (install.BridgeState, error) {
			st := install.ParseBridgeIfconfig([]byte(icIfconfig))
			st.Addrs[netip.MustParseAddr("169.254.0.9")] = 32
			return st, nil
		}
		_, by = icRows(t, ic, install.RoleServer)
		if r := mustRow(t, by, icAddress); r.status != statusWarn || !strings.Contains(r.remedy, install.ServerLabel) {
			t.Errorf("a /32 slot-0 alias = %v %q (remedy %q), want WARN restarting the server daemon", r.status, r.detail, r.remedy)
		}
	})

	t.Run("an index beyond the ceiling", func(t *testing.T) {
		ic := healthyIC(t)
		ic.identity = func() (netip.Prefix, error) { return podnet.NodeCIDR(podnet.ClusterPodCIDR, 31) }
		_, by := icRows(t, ic, install.RoleAgent)
		r := mustRow(t, by, icAddress)
		if r.status != statusWarn || !strings.Contains(r.detail, "cluster index is 31, above 30") || !strings.Contains(r.remedy, `"excludedNodes":["mikobook"]`) {
			t.Errorf("address = %v %q (remedy %q), want WARN naming index 31 and excluding mikobook", r.status, r.detail, r.remedy)
		}
	})

	t.Run("old-half stray state", func(t *testing.T) {
		ic := healthyIC(t)
		ic.bridge = func() (install.BridgeState, error) {
			return install.ParseBridgeIfconfig([]byte(icIfconfig + "\tinet 169.254.255.1 netmask 0xffffff00\n\tinet 169.254.0.42 netmask 0xffffffff\n")), nil
		}
		ic.routes = func() ([]icRoute, error) {
			return parseNetstatRoutes(icNetstat + "169.254.255/24     link#30            UCS               bridge0      !\n"), nil
		}
		_, by := icRows(t, ic, install.RoleAgent)
		r := mustRow(t, by, icStray)
		if r.status != statusWarn {
			t.Fatalf("stray = %v %q, want WARN", r.status, r.detail)
		}
		for _, want := range []string{"alias 169.254.255.1", "alias 169.254.0.42 in 169.254.0.0/24 that netd does not own", "route 169.254.255.0/24"} {
			if !strings.Contains(r.detail, want) {
				t.Errorf("stray detail %q does not say %q", r.detail, want)
			}
		}
		for _, want := range []string{"sudo ifconfig bridge0 -alias 169.254.255.1", "sudo ifconfig bridge0 -alias 169.254.0.42", "sudo route -n delete -net 169.254.255.0/24 -interface bridge0"} {
			if !strings.Contains(r.remedy, want) {
				t.Errorf("stray remedy %q does not say %q", r.remedy, want)
			}
		}
		if strings.Contains(r.detail, "169.254.0.9") || strings.Contains(r.detail, "169.254.0.10") || strings.Contains(r.detail, "169.254.9.209") {
			t.Errorf("stray names netd's own aliases or the self-assigned address: %q", r.detail)
		}

		// Unprivileged, the ownership half cannot be judged and says so.
		ic = healthyIC(t)
		ic.ledger = func() ([]install.InterconnectAlias, error) {
			return nil, &fs.PathError{Op: "open", Err: fs.ErrPermission}
		}
		_, by = icRows(t, ic, install.RoleAgent)
		if r := mustRow(t, by, icStray); r.status != statusSkip || r.remedy != "sudo k3sm doctor" {
			t.Errorf("unprivileged stray = %v %q, want SKIP with sudo", r.status, r.detail)
		}
		if r := mustRow(t, by, icAddress); r.status != statusSkip || r.remedy != "sudo k3sm doctor" {
			t.Errorf("unprivileged address = %v %q, want SKIP with sudo", r.status, r.detail)
		}
	})

	t.Run("residue is reported as harmless", func(t *testing.T) {
		ic := healthyIC(t)
		ic.routes = func() ([]icRoute, error) {
			return parseNetstatRoutes(icNetstat +
				"169.254.0.10/32    link#30            UC                bridge0      !\n" +
				"169.254.0.11/32    link#30            UC                bridge0      !\n" +
				"169.254.255.2/32   link#30            UC                bridge0      !\n"), nil
		}
		rows, by := icRows(t, ic, install.RoleAgent)
		r := mustRow(t, by, icResidue)
		if r.status != statusPass || r.remedy != "" {
			t.Fatalf("residue = %v %q (remedy %q), want PASS with no remedy", r.status, r.detail, r.remedy)
		}
		if !strings.Contains(r.detail, "harmless pre-existing state") || !strings.Contains(r.detail, "169.254.0.11/32") || !strings.Contains(r.detail, "169.254.255.2/32") {
			t.Errorf("residue detail %q", r.detail)
		}
		// 169.254.0.10 is still an alias, so its /32 is not residue.
		if strings.Contains(r.detail, "169.254.0.10/32") {
			t.Errorf("a live alias's route is called residue: %q", r.detail)
		}
		if s := mustRow(t, by, icStray); s.status != statusPass {
			t.Errorf("residue in the old half made stray %v %q; it is reported once, as harmless", s.status, s.detail)
		}
		for _, row := range rows {
			if row.status == statusWarn || row.status == statusFail {
				t.Errorf("%s = %v: residue alone must not warn", row.name, row.status)
			}
		}
	})

	t.Run("loop", func(t *testing.T) {
		ic := healthyIC(t)
		ic.ports = func() ([]linkenum.Port, error) {
			return []linkenum.Port{
				{Iface: "en1", PortOrdinal: 0, DomainUUID: "local-1", PeerDomainUUID: "studio-3"},
				{Iface: "en2", PortOrdinal: 1, DomainUUID: "local-2", PeerDomainUUID: "studio-3"},
			}, nil
		}
		_, by := icRows(t, ic, install.RoleAgent)
		r := mustRow(t, by, icLoop)
		if r.status != statusWarn || !strings.Contains(r.detail, "en1 and en2 reach the same Mac") || !strings.Contains(r.remedy, "remove one cable") {
			t.Errorf("loop = %v %q (remedy %q)", r.status, r.detail, r.remedy)
		}

		ic = healthyIC(t)
		ic.cluster = func() (icCluster, error) {
			return icCluster{Node: "mikobook", Desired: true, MemberState: netv1alpha1.InterconnectMemberLoop}, nil
		}
		_, by = icRows(t, ic, install.RoleAgent)
		if r := mustRow(t, by, icLoop); r.status != statusWarn || !strings.Contains(r.detail, "server marked this node a loop member") {
			t.Errorf("server-detected loop = %v %q", r.status, r.detail)
		}
	})

	t.Run("each advisory", func(t *testing.T) {
		for _, tc := range []struct {
			name, row, pmset, user, remedy string
		}{
			{"idle sleep", icSleep, " sleep                10\n autorestart          1\n", "miko", "sudo pmset -a sleep 0"},
			{"auto-login", icAutoLogin, " sleep                0\n autorestart          1\n", "", "Automatically log in as"},
			{"start after power failure", icPower, " sleep                0\n autorestart          0\n", "miko", "sudo pmset -a autorestart 1"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ic := healthyIC(t)
				ic.power = func() (powerSettings, error) { return parsePmset(tc.pmset), nil }
				ic.autoLogin = func() (string, error) { return tc.user, nil }
				rows, by := icRows(t, ic, install.RoleAgent)
				r := mustRow(t, by, tc.row)
				if r.status != statusWarn || !strings.Contains(r.remedy, tc.remedy) {
					t.Errorf("%s = %v %q (remedy %q), want WARN with %q", tc.row, r.status, r.detail, r.remedy, tc.remedy)
				}
				for _, other := range rows {
					if other.name != tc.row && other.status != statusPass {
						t.Errorf("%s = %v; only %s should move", other.name, other.status, tc.row)
					}
				}
			})
		}
		if r := checkICSleep(parsePmset(" displaysleep 10\n disksleep 10\n"), nil); r.status != statusWarn {
			t.Errorf("displaysleep and disksleep were read as system sleep: %v %q", r.status, r.detail)
		}
		if r := checkICPower(parsePmset(" sleep 0\n"), nil); r.status != statusSkip {
			t.Errorf("a Mac with no autorestart setting = %v, want SKIP", r.status)
		}
	})

	t.Run("netd unreachable", func(t *testing.T) {
		ic := healthyIC(t)
		ic.helper = func() error { return fmt.Errorf("dial unix /var/lib/k3sm/run/netd.sock: %w", syscall.ECONNREFUSED) }
		_, by := icRows(t, ic, install.RoleAgent)
		r := mustRow(t, by, icNetd)
		if r.status != statusWarn || r.remedy != "sudo launchctl kickstart -k system/"+install.NetdLabel {
			t.Errorf("netd = %v %q (remedy %q), want WARN kickstarting netd", r.status, r.detail, r.remedy)
		}
		ic.helper = func() error { return fmt.Errorf("dial: %w", syscall.EACCES) }
		_, by = icRows(t, ic, install.RoleAgent)
		if r := mustRow(t, by, icNetd); r.status != statusSkip || r.remedy != "sudo k3sm doctor" {
			t.Errorf("an unreadable socket = %v %q, want SKIP with sudo", r.status, r.detail)
		}
	})

	t.Run("no Thunderbolt port, and no cable", func(t *testing.T) {
		ic := healthyIC(t)
		ic.ports = func() ([]linkenum.Port, error) { return nil, linkenum.ErrNoThunderboltService }
		rows, _ := icRows(t, ic, install.RoleServer)
		if len(rows) != 1 || rows[0].name != icBridge || rows[0].status != statusSkip {
			t.Errorf("no Thunderbolt port = %+v, want one ic-bridge SKIP", rows)
		}

		// Ports but no cable and no interconnect state: no advisory nags a
		// Mac that is not using the cable; stray state is still checked.
		ic = healthyIC(t)
		ic.ports = func() ([]linkenum.Port, error) {
			return []linkenum.Port{{Iface: "en1", DomainUUID: "local-1"}, {Iface: "en2", PortOrdinal: 1, DomainUUID: "local-2"}}, nil
		}
		ic.bridge = func() (install.BridgeState, error) {
			return install.ParseBridgeIfconfig([]byte("bridge0: flags=8863<UP>\n\tinet 169.254.9.209 netmask 0xffff0000\n\tmember: en1 flags=3<>\n")), nil
		}
		ic.ledger = func() ([]install.InterconnectAlias, error) { return nil, nil }
		ic.cluster = func() (icCluster, error) { return icCluster{}, errors.New("no kubeconfig") }
		rows, by := icRows(t, ic, install.RoleServer)
		if len(rows) != 2 || mustRow(t, by, icBridge).status != statusSkip || mustRow(t, by, icStray).status != statusPass {
			t.Errorf("an uncabled Mac = %+v, want the ic-bridge SKIP and a passing stray check", rows)
		}
	})

	t.Run("bridge0 without a Thunderbolt member", func(t *testing.T) {
		ic := healthyIC(t)
		ic.bridge = func() (install.BridgeState, error) {
			return install.ParseBridgeIfconfig([]byte(strings.ReplaceAll(icIfconfig, "member: en", "member: vmenet"))), nil
		}
		_, by := icRows(t, ic, install.RoleAgent)
		if r := mustRow(t, by, icBridge); r.status != statusWarn || !strings.Contains(r.remedy, "restart this Mac") {
			t.Errorf("bridge = %v %q (remedy %q)", r.status, r.detail, r.remedy)
		}
	})

	// Every non-pass row carries a remedy the Next: block shows, except a
	// SKIP the operator cannot act on.
	t.Run("every warning and failure carries a remedy", func(t *testing.T) {
		ic := healthyIC(t)
		ic.bridge = func() (install.BridgeState, error) { return install.BridgeState{}, errNoBridge }
		ic.routes = func() ([]icRoute, error) { return nil, errors.New("netstat: exit status 1") }
		ic.helper = func() error { return errors.New("refused") }
		ic.neighbors = func() ([]netip.Addr, error) { return nil, errors.New("arp failed") }
		ic.power = func() (powerSettings, error) { return powerSettings{}, errors.New("pmset failed") }
		ic.autoLogin = func() (string, error) { return "", nil }
		rows, _ := icRows(t, ic, install.RoleAgent)
		for _, r := range rows {
			if (r.status == statusWarn || r.status == statusFail) && r.remedy == "" {
				t.Errorf("%s is %v with no remedy (%q)", r.name, r.status, r.detail)
			}
		}
	})
}

func TestDoctorInterconnectParsers(t *testing.T) {
	routes := parseNetstatRoutes(icNetstat + "169.254.0.10/32    link#30            UC                bridge0      !\n")
	want := []string{"169.254.0.0/16 UCS", "169.254.0.0/24 UCS", "169.254.0.1/32 UHLWIi", "169.254.0.10/32 UC"}
	if len(routes) != len(want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	for i, r := range routes {
		if got := r.Dest.String() + " " + r.Flags; got != want[i] || r.Iface != "bridge0" {
			t.Errorf("route %d = %q on %s, want %q on bridge0", i, got, r.Iface, want[i])
		}
	}
	if d, ok := parsePingRTT("1 packets transmitted, 1 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 0.612/0.660/0.700/0.000 ms\n"); !ok || d != 660*time.Microsecond {
		t.Errorf("ping rtt = %v %v, want 660µs", d, ok)
	}
	if _, ok := parsePingRTT("1 packets transmitted, 0 packets received, 100.0% packet loss\n"); ok {
		t.Error("a ping with no answer parsed a round trip")
	}
	for _, avg := range []string{"NaN", "nan", "Inf", "+Inf", "-Inf", "-0.5"} {
		if d, ok := parsePingRTT("round-trip min/avg/max/stddev = 0.1/" + avg + "/0.2/0.0 ms\n"); ok {
			t.Errorf("an average of %q parsed as %v", avg, d)
		}
	}
	// Only complete entries inside the interconnect subnet count: an option
	// echoed in parentheses, an address outside the subnet, and an incomplete
	// entry are dropped.
	got := parseARPNeighbors("? (-f) at 36:a1:2b:0:0:2 on bridge0 [bridge]\n" +
		"? (8.8.8.8) at 36:a1:2b:0:0:3 on bridge0 [bridge]\n" +
		"? (169.254.9.209) at 36:a1:2b:0:0:4 on bridge0 [bridge]\n" +
		"? (169.254.0.17) at (incomplete) on bridge0 [bridge]\n" +
		"? (169.254.0.1) at 36:a1:2b:0:0:5 on bridge0 [bridge]\n")
	if want := []netip.Addr{netip.MustParseAddr("169.254.0.1")}; !slices.Equal(got, want) {
		t.Errorf("ARP neighbors = %v, want %v", got, want)
	}
}
