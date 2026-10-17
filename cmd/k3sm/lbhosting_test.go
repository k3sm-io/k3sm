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
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/netbind"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/ports"
)

// helperMode is the fixture posture for the gate: the UNPRIVILEGED production
// posture, where mode.UsesHelper() is TRUE.
//
// It is load-bearing. Under a root/direct fixture the privileged binder used to
// resolve to netbind.Direct anyway, so a "no netd binder is wired" assertion
// would be vacuous against exactly the wrong diff it exists to catch: a one-line
// change of the ADDRESS that leaves the port-keyed privileged-binder selection
// live, whereupon every <1024 tenant LoadBalancer port would route into netd,
// which grants a privileged wildcard only to the canonical ingress Service, and
// fail to bind.
var helperMode = hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/var/run/k3sm/netd.sock"}

// gateNodeOptions is the single-node server fixture: the shipped --node-ip
// default on the datapath, with the reserved index-0 pod /24.
func gateNodeOptions() nodeOptions {
	return nodeOptions{
		nodeName: "k3sm-gate",
		nodeIP:   loopbackNodeIP,
		podCIDR:  "100.64.0.0/24",
		netMode:  helperMode,
	}
}

// TestLBListenersBindWildcardAdvertiseDerived is the B116 gate.
//
// It owns the WIRING and the DERIVATION at the call site — the decision
// lbHostingConfigs makes — and nothing else. The behavioural halves are
// partitioned to the packages that can reach their unexported reconcile/status
// writers: pkg/svclb (TestSvclbBindHonesty's inverted single-binder and
// reserved-port subtests, TestSvclbNewHosterValidation, TestRetractable, and
// TestNodePoolSelection's server-held address cases),
// pkg/ingresshost (TestIngressHostNewValidationAsymmetry,
// TestIngressHostDerivationFailureServesButNeverAdvertises,
// TestIngressHostRetractsWhenNotServing), pkg/policy
// (TestReservedLoadBalancerPortCELSemantics and siblings) and pkg/install
// (TestNetdPlistXML's --node-ip pin).
func TestLBListenersBindWildcardAdvertiseDerived(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	// (a) THE BIND ADDRESS is the IPv4 wildcard literal.
	t.Run("both listeners bind the IPv4 wildcard 0.0.0.0", func(t *testing.T) {
		_, ih, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), "", 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		lb := lbHosterConfig(fake.NewClientset(), gateNodeOptions(), log)
		for _, tc := range []struct {
			what string
			got  netip.Addr
		}{{"svclb hoster", lb.BindAddr}, {"ingresshost", ih.BindAddr}} {
			// String()=="0.0.0.0" AND Is4(), deliberately NOT IsUnspecified():
			// IsUnspecified() is also true for "::", which is exactly the
			// dual-stack [::] socket (IPV6_V6ONLY=0) the ":port" form would
			// produce and which this change forbids.
			if tc.got.String() != "0.0.0.0" || !tc.got.Is4() {
				t.Errorf("%s BindAddr = %q (Is4=%v), want the IPv4 literal 0.0.0.0", tc.what, tc.got, tc.got.Is4())
			}
		}
	})

	// (a, second half) THE SVCLB BINDER SELECTION. The address and the binder are
	// INDEPENDENT: a one-line address change satisfies the assert above while
	// leaving the binder wrong. With the helper present every bind of a LISTED
	// port, the wildcard included, goes to netd, so both shapes of the port have
	// one owner and a LAN access swap cannot meet Darwin's cross-owner
	// EADDRINUSE; every other port, an unlisted one below 1024 included, binds
	// in-process and never asks netd. The ingress host's own binder is
	// TestIngressHostBindsThroughNetdWhenPresent's.
	t.Run("svclb sends exactly the listed ports to netd", func(t *testing.T) {
		opts := gateNodeOptions()
		if !opts.netMode.UsesHelper() {
			t.Fatal("fixture must be in the helper posture or the assertion below is vacuous")
		}
		opts.lbPrivilegedPorts = []uint16{80, 443}
		lb := lbHosterConfig(fake.NewClientset(), opts, log)
		hb, ok := lb.Binder.(hosterBinder)
		if !ok {
			t.Fatalf("svclb Binder = %T, want hosterBinder in the helper posture", lb.Binder)
		}
		if !slices.Equal(lb.PrivilegedPorts, []uint16{80, 443}) || !slices.Equal(hb.listed, []uint16{80, 443}) {
			t.Errorf("PrivilegedPorts = %v, binder list = %v, want the node's list [80 443] for both", lb.PrivilegedPorts, hb.listed)
		}
		n, ok := hb.privileged.(netdBinder)
		if raw, isNetd := n.netd.(*netbind.Netd); !ok || !isNetd || raw.Client == nil {
			t.Fatalf("hosterBinder privileged leg = %T, want the netdBinder adapter over a wire client (a raw *netbind.Netd sends \"tcp4\", which netd refuses)", hb.privileged)
		}
		if _, ok := hb.direct.(netbind.Direct); !ok {
			t.Fatalf("hosterBinder direct leg = %T, want netbind.Direct", hb.direct)
		}
		node := netip.MustParseAddr("100.64.0.1")
		priv, direct := &recordingBinder{}, &recordingBinder{}
		b := hosterBinder{listed: hb.listed, privileged: priv, direct: direct}
		for _, ap := range []netip.AddrPort{
			netip.AddrPortFrom(node, 80),
			netip.AddrPortFrom(wildcardBindAddr, 80),
			netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 443),
			netip.AddrPortFrom(wildcardBindAddr, 81),
			netip.AddrPortFrom(node, 81),
			netip.AddrPortFrom(wildcardBindAddr, 8080),
		} {
			_, _ = b.Listen(context.Background(), "tcp", ap)
		}
		wantPriv := []netip.AddrPort{netip.AddrPortFrom(node, 80), netip.AddrPortFrom(wildcardBindAddr, 80), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 443)}
		if !slices.Equal(priv.got, wantPriv) {
			t.Errorf("netd leg got %v, want only the listed ports %v", priv.got, wantPriv)
		}
		wantDirect := []netip.AddrPort{netip.AddrPortFrom(wildcardBindAddr, 81), netip.AddrPortFrom(node, 81), netip.AddrPortFrom(wildcardBindAddr, 8080)}
		if !slices.Equal(direct.got, wantDirect) {
			t.Errorf("in-process leg got %v, want the unlisted and unprivileged ports %v", direct.got, wantDirect)
		}
	})

	t.Run("the ingress host's ports are reserved on a server only", func(t *testing.T) {
		opts := gateNodeOptions()
		opts.ingressPorts = ingressListenerPorts(80, 0)
		lb := lbHosterConfig(fake.NewClientset(), opts, log)
		if !lb.ReservedPorts[80] || lb.ReservedPorts[443] {
			t.Errorf("reserved 80=%v 443=%v, want the enabled ingress port 80 only", lb.ReservedPorts[80], lb.ReservedPorts[443])
		}
		if !lb.ReservedPorts[int32(ports.KubeletAPIPort)] {
			t.Error("the ingress ports replaced the base reserved set instead of joining it")
		}
		worker := lbHosterConfig(fake.NewClientset(), gateNodeOptions(), log)
		if worker.ReservedPorts[80] {
			t.Error("a node with no ingress host reserves port 80 from flags it does not have")
		}
		// Every node, a worker included, reserves what the canonical ingress
		// Service declares, by its namespace and name.
		if worker.IngressService.Namespace != ingresshost.ServiceNamespace || worker.IngressService.Name != ingresshost.ServiceName {
			t.Errorf("IngressService = %v, want %s/%s", worker.IngressService, ingresshost.ServiceNamespace, ingresshost.ServiceName)
		}
	})

	t.Run("svclb brokers nothing with an empty list", func(t *testing.T) {
		if lb := lbHosterConfig(fake.NewClientset(), gateNodeOptions(), log); lb.Binder != nil || lb.PrivilegedPorts != nil {
			t.Errorf("svclb Binder = %T, PrivilegedPorts = %v, want nil and nil with no listed port", lb.Binder, lb.PrivilegedPorts)
		}
	})

	t.Run("svclb keeps the in-process binder with no helper", func(t *testing.T) {
		opts := gateNodeOptions()
		opts.netMode = hostnet.Mode{Backend: hostnet.BackendDirect}
		opts.lbPrivilegedPorts = []uint16{80, 443}
		if lb := lbHosterConfig(fake.NewClientset(), opts, log); lb.Binder != nil || lb.PrivilegedPorts != nil {
			t.Errorf("svclb Binder = %T, PrivilegedPorts = %v, want nil (netbind.Direct) and nil on a node without the helper", lb.Binder, lb.PrivilegedPorts)
		}
	})

	// THE DERIVATION: the advertised address is the node's derived
	// globally-unicast .1, not the raw loopback --node-ip default.
	t.Run("the advertised address is the derived non-loopback node address", func(t *testing.T) {
		opts := gateNodeOptions()
		lb, ih, err := lbHostingConfigs(fake.NewClientset(), opts, "", 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		const want = "100.64.0.1"
		if lb.SelfAddr.String() != want {
			t.Errorf("svclb decider SelfAddr = %q, want the derived %q", lb.SelfAddr, want)
		}
		if lb.SelfNode != opts.nodeName {
			t.Errorf("svclb decider SelfNode = %q, want the node's own name %q", lb.SelfNode, opts.nodeName)
		}
		if ih.AdvertiseAddr.String() != want {
			t.Errorf("ingresshost AdvertiseAddr = %q, want the derived %q", ih.AdvertiseAddr, want)
		}
		if lb.SelfAddr.IsLoopback() {
			t.Error("a loopback EXTERNAL-IP is unreachable from anywhere but this Mac and must never be advertised")
		}
		// The two controllers cannot disagree, and neither can disagree with the
		// address startNode stamps on the Node object.
		if got := advertisedNodeIP(opts); got != want {
			t.Errorf("advertisedNodeIP (what startNode advertises) = %q, want %q — the Node object and the EXTERNAL-IP must match", got, want)
		}
		// And the source options are NEVER mutated: opts.nodeIP feeds the
		// apiserver's --advertise-address/--bind-address in runServer.
		if opts.nodeIP != loopbackNodeIP {
			t.Errorf("opts.nodeIP = %q, want it UNCHANGED at %q: writing the derived address back invalidates the loopback admin kubeconfig, empties the kubernetes VIP's only static backend and changes the NetworkPolicy seed", opts.nodeIP, loopbackNodeIP)
		}
	})

	// THE MESH ARM. Every HA server computes the SAME index-0 podCIDR, so a
	// dropped conjunct here makes two Macs publish one EXTERNAL-IP.
	t.Run("a mesh server advertises its mesh IP, never the pod-CIDR .1", func(t *testing.T) {
		const meshIP = "100.100.0.7"
		opts := gateNodeOptions()
		opts.nodeIP = meshIP // runServer's mesh rewrite already ran
		lb, ih, err := lbHostingConfigs(fake.NewClientset(), opts, "", 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		for _, tc := range []struct {
			what string
			got  netip.Addr
		}{{"svclb decider", lb.SelfAddr}, {"ingresshost", ih.AdvertiseAddr}} {
			if tc.got.String() != meshIP {
				t.Errorf("%s AdvertiseAddr = %q, want the mesh IP %q", tc.what, tc.got, meshIP)
			}
			if tc.got.String() == "100.64.0.1" {
				t.Errorf("%s advertised the pod-CIDR .1 on a mesh server: every HA server derives the SAME index-0 podCIDR, so two Macs would publish one EXTERNAL-IP", tc.what)
			}
		}
		// A mesh IP is the mesh device's address, not an lo0 alias this host may
		// claim — so the pre-start alias plumbing must not fire for it.
		if got := derivedNodeAdvertiseIP(opts); got != "" {
			t.Errorf("derivedNodeAdvertiseIP = %q on a mesh server, want \"\": aliasing the mesh IP on lo0 would make this host answer for an address it must not own", got)
		}
	})

	// DERIVATION FAILURE: listeners still bind (the Service is <pending>, not
	// disabled) and nothing advertisable is produced.
	t.Run("derivation failure yields no advertise address but still binds", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			opts func() nodeOptions
		}{
			{"malformed podCIDR", func() nodeOptions {
				o := gateNodeOptions()
				o.podCIDR = "not-a-cidr"
				return o
			}},
			{"no podCIDR", func() nodeOptions {
				o := gateNodeOptions()
				o.podCIDR = ""
				return o
			}},
			{"no datapath (--network none) on the loopback default", func() nodeOptions {
				o := gateNodeOptions()
				o.netMode = hostnet.Mode{Backend: hostnet.BackendNone}
				return o
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				lb, ih, err := lbHostingConfigs(fake.NewClientset(), tc.opts(), "", 80, 443, log)
				if err != nil {
					t.Fatalf("lbHostingConfigs: %v", err)
				}
				if lb.SelfAddr.IsValid() || ih.AdvertiseAddr.IsValid() {
					t.Errorf("the advertise address must be the ZERO Addr on a derivation failure, got svclb=%q ingress=%q", lb.SelfAddr, ih.AdvertiseAddr)
				}
				if lbHosterConfig(fake.NewClientset(), tc.opts(), log).BindAddr.String() != "0.0.0.0" || ih.BindAddr.String() != "0.0.0.0" {
					t.Error("listeners must STILL bind the wildcard on a derivation failure (the Service is <pending>, not disabled)")
				}
			})
		}
	})

	// The reserved-port set the datapath refusal uses is the SAME single source
	// the admission CEL and the apiserver argv derive from.
	t.Run("the reserved-port set is single-sourced from pkg/ports", func(t *testing.T) {
		lb := lbHosterConfig(fake.NewClientset(), gateNodeOptions(), log)
		for _, p := range []int32{ports.NodePortRangeMin, ports.NodePortRangeMax, ports.KubeletAPIPort} {
			if !lb.ReservedPorts[p] {
				t.Errorf("ReservedPorts is missing %d", p)
			}
		}
		for _, p := range []int32{80, 443, 8080} {
			if lb.ReservedPorts[p] {
				t.Errorf("port %d must NOT be reserved (D1: the ingress ports stay legitimate LoadBalancer ports; the ingress host wins them by starting first)", p)
			}
		}
	})

	// The ingress host's retraction scope is the CLUSTER pod aggregate, so a node
	// that re-enrolls into a different /24 still retracts what its previous life
	// advertised. (svclb's decider replaces its whole status slice instead.)
	t.Run("the retraction scope covers a previous enrollment's /24", func(t *testing.T) {
		_, ih, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), "", 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		if !ih.PodCIDR.Contains(netip.MustParseAddr("100.64.0.1")) || !ih.PodCIDR.Contains(netip.MustParseAddr("100.64.2.1")) {
			t.Errorf("ingresshost PodCIDR = %s, want the cluster aggregate containing both this node's /24 and a re-enrolled one", ih.PodCIDR)
		}
	})

	// The seam is TOTAL: an out-of-range port errors rather than silently
	// truncating through the uint16 conversion (70000 -> 4464).
	t.Run("an out-of-range ingress port is an error, never a truncation", func(t *testing.T) {
		if _, _, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), "", 70000, 443, log); err == nil {
			t.Error("--ingress-http-port 70000 must error")
		}
		if _, _, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), "", 80, -1, log); err == nil {
			t.Error("--ingress-https-port -1 must error")
		}
	})
}

// TestServerKubeletPortRenumbersOnlyThePort pins the ONE property that makes
// `k3sm server --kubelet-port` a port change and not an exposure change: the
// derived listen address keeps the node's own address as its host and changes
// only the port. The address is resolveKubeletEndpoint's to decide, never the
// port flag's.
func TestServerKubeletPortRenumbersOnlyThePort(t *testing.T) {
	stubLocalAddrs(t, "127.0.0.1", "100.64.0.1")
	for _, port := range []int{ports.KubeletAPIPort, 10450, 10961} {
		ep, err := resolveKubeletEndpoint(nodeOptions{
			nodeIP:      loopbackNodeIP,
			kubeletPort: port,
			podCIDR:     "100.64.0.0/24",
			netMode:     hostnet.Mode{Backend: hostnet.BackendDirect},
		})
		if err != nil {
			t.Fatalf("resolveKubeletEndpoint(port %d): %v", port, err)
		}
		if want := net.JoinHostPort("100.64.0.1", strconv.Itoa(port)); ep.listen != want {
			t.Errorf("--kubelet-port %d listens on %q, want %q: renumbering must move the port and nothing else", port, ep.listen, want)
		}
	}
}

// TestKubeletListenAddressesUsePortsConstant pins that the kubelet API listen
// addresses are BUILT from ports.KubeletAPIPort, so the port the reserved-set
// guard protects and the port the node actually listens on cannot desync. Before
// B116 that port had no constant at all — just bare literals inside address
// strings.
func TestKubeletListenAddressesUsePortsConstant(t *testing.T) {
	suffix := ":" + strconv.Itoa(ports.KubeletAPIPort)
	if !strings.HasSuffix(nodeKubeletListen, suffix) {
		t.Errorf("standalone `k3sm node` listen = %q, want the %q suffix from ports.KubeletAPIPort", nodeKubeletListen, suffix)
	}
	agent := agentNodeOptions(agentOptions{}, &bootstrap.JoinResult{MeshIP: "100.64.1.1"}, "", hostnet.Mode{Backend: hostnet.BackendDirect}, nil)
	if agent.kubeletPort != ports.KubeletAPIPort {
		t.Errorf("agent kubelet port = %d, want ports.KubeletAPIPort %d", agent.kubeletPort, ports.KubeletAPIPort)
	}
	var opts serverOptions
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	if err := registerServerFlags(fs, &opts); err != nil {
		t.Fatalf("registerServerFlags: %v", err)
	}
	if opts.kubeletPort != ports.KubeletAPIPort {
		t.Errorf("server --kubelet-port default = %d, want ports.KubeletAPIPort %d", opts.kubeletPort, ports.KubeletAPIPort)
	}
	if !ports.Reserved(ports.KubeletAPIPort) {
		t.Error("the kubelet API port must be in the reserved set: losing it to a LoadBalancer Service kills logs/exec/top on this node")
	}
}

// TestIngressHostBindsThroughNetdWhenPresent is the B403 gate for the binder
// decision lbHostingConfigs owns. An unprivileged 0.0.0.0:80 loses to netd's
// root-owned Service-VIP:80 socket (a different-uid wildcard fails with
// EADDRINUSE on Darwin), so when the node has a netd helper the ingress host's
// privileged listeners bind through it; the high-port integration pair, and a
// node with no helper, keep the in-process netbind.Direct.
func TestIngressHostBindsThroughNetdWhenPresent(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	socket := helperMode.Socket

	for _, tc := range []struct {
		name            string
		netdSocket      string
		http, https     int
		wantNetd        bool
		wantDirect      bool
		wantSplitByPort bool
	}{
		{name: "netd configured + 80/443 binds through netd", netdSocket: socket, http: 80, https: 443, wantNetd: true},
		{name: "netd configured + 80 only binds through netd", netdSocket: socket, http: 80, https: 0, wantNetd: true},
		{name: "netd configured + 8080/8443 binds in-process", netdSocket: socket, http: 8080, https: 8443, wantDirect: true},
		{name: "no netd + 80/443 binds in-process", netdSocket: "", http: 80, https: 443, wantDirect: true},
		{name: "no netd + 8080/8443 binds in-process", netdSocket: "", http: 8080, https: 8443, wantDirect: true},
		{name: "netd configured + a mixed 80/8443 pair splits by port", netdSocket: socket, http: 80, https: 8443, wantSplitByPort: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ih, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), tc.netdSocket, tc.http, tc.https, log)
			if err != nil {
				t.Fatalf("lbHostingConfigs: %v", err)
			}
			lbOpts := gateNodeOptions()
			lbOpts.lbPrivilegedPorts = []uint16{80, 443}
			if _, ok := lbHosterConfig(fake.NewClientset(), lbOpts, log).Binder.(hosterBinder); !ok {
				t.Errorf("svclb Binder is not the hosterBinder: with the helper every svclb bind of a listed port goes to netd")
			}
			if ih.NodeName != gateNodeOptions().nodeName {
				t.Errorf("ingress NodeName = %q, want the node's own name %q (it names the node's EndpointSlice shard)", ih.NodeName, gateNodeOptions().nodeName)
			}
			switch b := ih.Binder.(type) {
			case netdBinder:
				if !tc.wantNetd {
					t.Fatalf("ingress Binder = netdBinder, want in-process (netd grants a wildcard only below 1024)")
				}
				if n, ok := b.netd.(*netbind.Netd); !ok || n.Client == nil {
					t.Fatal("the netd binder must carry a wire client for the configured socket")
				}
			case netbind.Direct:
				if !tc.wantDirect {
					t.Fatalf("ingress Binder = netbind.Direct, want the netd helper: an unprivileged 0.0.0.0:80 loses to netd's root-owned VIP:80 socket")
				}
			case portSplitBinder:
				if !tc.wantSplitByPort {
					t.Fatalf("ingress Binder = portSplitBinder, want a single binder")
				}
				if _, ok := b.privileged.(netdBinder); !ok {
					t.Errorf("split binder privileged leg = %T, want netdBinder", b.privileged)
				}
				if _, ok := b.unprivileged.(netbind.Direct); !ok {
					t.Errorf("split binder unprivileged leg = %T, want netbind.Direct", b.unprivileged)
				}
			default:
				t.Fatalf("ingress Binder = %T, want an explicit selection", ih.Binder)
			}
		})
	}

	t.Run("the socket follows the resolved --network posture", func(t *testing.T) {
		if got := netdSocketFor(helperMode); got != helperMode.Socket {
			t.Errorf("netdSocketFor(helper) = %q, want %q", got, helperMode.Socket)
		}
		for _, m := range []hostnet.Mode{{Backend: hostnet.BackendDirect}, {Backend: hostnet.BackendNone}} {
			if got := netdSocketFor(m); got != "" {
				t.Errorf("netdSocketFor(%s) = %q, want \"\" (no helper: root binds 80/443 itself)", m.Backend, got)
			}
		}
	})
}

// TestLBPeerAddressesFromMeshPeers pins the svclb decider's address source: a
// node's LoadBalancer address is the mesh address in its MeshPeer record (which
// only the server's guarded enroll path writes), never anything the node
// reports about itself, and a record without a usable MeshIP contributes
// nothing.
func TestLBPeerAddressesFromMeshPeers(t *testing.T) {
	list := func(context.Context) ([]netv1.MeshPeerSpec, error) {
		return []netv1.MeshPeerSpec{
			{NodeName: "node-a", MeshIP: "100.64.0.1"},
			{NodeName: "node-b", MeshIP: "100.64.1.1"},
			{NodeName: "node-c"},                              // no MeshIP: never advertised
			{NodeName: "node-d", MeshIP: "127.0.0.1"},         // loopback: never advertised
			{NodeName: "node-e", MeshIP: "not-an-ip"},         // unparsable: never advertised
			{NodeName: "", MeshIP: "100.64.9.1"},              // no node: dropped
			{NodeName: "node-f", MeshIP: "::ffff:100.64.5.1"}, // v4-mapped: unmapped
		}, nil
	}
	got, err := lbPeerAddresses(list)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"node-a": "100.64.0.1", "node-b": "100.64.1.1", "node-f": "100.64.5.1"}
	if len(got) != len(want) {
		t.Errorf("addresses = %v, want exactly %v", got, want)
	}
	for n, a := range want {
		if got[n].String() != a {
			t.Errorf("address of %s = %q, want %q", n, got[n], a)
		}
	}
	if _, err := lbPeerAddresses(func(context.Context) ([]netv1.MeshPeerSpec, error) {
		return nil, errors.New("apiserver unavailable")
	})(context.Background()); err == nil {
		t.Error("a failed MeshPeer list must surface as an error (the decider keeps its last good set)")
	}
}

// TestLBPeerAddressCache pins that the decider's MeshPeer addresses come from a
// watch-backed cache: many reconciles cost one LIST, a MeshPeer change arrives
// through the watch, and before the first LIST lands the source reports an
// error (the decider keeps its last good set) instead of an empty set.
func TestLBPeerAddressCache(t *testing.T) {
	var lists atomic.Int32
	w := watch.NewFake()
	lw := listOnlyLW{&cache.ListWatch{
		ListFunc: func(metav1.ListOptions) (runtime.Object, error) {
			lists.Add(1)
			return &netv1.MeshPeerList{
				ListMeta: metav1.ListMeta{ResourceVersion: "1"},
				Items: []netv1.MeshPeer{
					{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: netv1.MeshPeerSpec{NodeName: "node-a", MeshIP: "100.64.0.1"}},
				},
			}, nil
		},
		WatchFunc: func(metav1.ListOptions) (watch.Interface, error) { return w, nil },
	}}
	inf, list := meshPeerCache(lw)
	addrs := lbPeerAddresses(list)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := addrs(ctx); !errors.Is(err, errMeshPeerCacheNotSynced) {
		t.Fatalf("before the first LIST, err = %v, want errMeshPeerCacheNotSynced", err)
	}
	go inf.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		t.Fatal("the MeshPeer cache never synced")
	}
	for range 5 {
		got, err := addrs(ctx)
		if err != nil || got["node-a"].String() != "100.64.0.1" {
			t.Fatalf("addresses = %v, %v, want node-a at 100.64.0.1", got, err)
		}
	}
	w.Add(&netv1.MeshPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "node-b", ResourceVersion: "2"},
		Spec:       netv1.MeshPeerSpec{NodeName: "node-b", MeshIP: "100.64.1.1"},
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := addrs(ctx)
		if err == nil && got["node-b"].String() == "100.64.1.1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a watched MeshPeer add never reached the addresses: %v, %v", got, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := lists.Load(); n != 1 {
		t.Errorf("the address source issued %d MeshPeer LISTs across 6+ reads, want 1 (served from the watch cache)", n)
	}
}

// listOnlyLW is a fake list-watch that declines watch-list semantics, so the
// reflector LISTs then WATCHes instead of waiting for a streamed initial-events
// bookmark the fake never sends.
type listOnlyLW struct{ *cache.ListWatch }

func (listOnlyLW) IsWatchListSemanticsUnSupported() bool { return true }

// TestLBHosterNeedsTheDatapath pins that a node with no datapath runs no svclb
// hoster: the splice needs the node's Service proxy behind the ClusterIP VIP.
func TestLBHosterNeedsTheDatapath(t *testing.T) {
	opts := gateNodeOptions()
	opts.netMode = hostnet.Mode{Backend: hostnet.BackendNone}
	cs := fake.NewClientset()
	stop := startLBHoster(context.Background(), opts, cs, slog.New(slog.DiscardHandler))
	stop()
	if n := len(cs.Actions()); n != 0 {
		t.Errorf("a no-datapath node issued %d API actions for svclb, want none", n)
	}
}

// TestNetdProtocolKeepsTheWireNames pins the netd adapter's mapping: the
// ingress host binds IPv4 addresses with the family-pinned "tcp4", and netd's
// wire accepts only "tcp" and "udp", so a family name must never reach it.
func TestNetdProtocolKeepsTheWireNames(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"tcp4", "tcp"},
		{"tcp6", "tcp"},
		{"tcp", "tcp"},
		{"udp4", "udp"},
		{"udp6", "udp"},
		{"udp", "udp"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := netdProtocol(tc.in); got != tc.want {
				t.Errorf("netdProtocol(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// recordingBinder records every address it is asked to bind and binds nothing.
type recordingBinder struct{ got []netip.AddrPort }

func (r *recordingBinder) Listen(_ context.Context, _ string, ap netip.AddrPort) (net.Listener, error) {
	r.got = append(r.got, ap)
	return nil, errors.New("recordingBinder binds nothing")
}
