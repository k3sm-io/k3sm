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
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/ports"
)

// helperMode is the fixture posture for the gate: the UNPRIVILEGED production
// posture, where mode.UsesHelper() is TRUE.
//
// It is load-bearing. Under a root/direct fixture the privileged binder used to
// resolve to netbind.Direct anyway, so a "no netd binder is wired" assertion
// would be vacuous against exactly the wrong diff it exists to catch: a one-line
// change of the ADDRESS that leaves the port-keyed privileged-binder selection
// live, whereupon every <1024 LoadBalancer port and both ingress listeners would
// route into netd — which refuses the wildcard — and fail to bind.
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
// writers: pkg/svclb (TestSvclbStatusHonesty's inverted single-binder and
// reserved-port subtests, TestSvclbNewValidationAsymmetry,
// TestSvclbDerivationFailureBindsButNeverAdvertises, TestRetractable),
// pkg/ingresshost (TestIngressHostNewValidationAsymmetry,
// TestIngressHostDerivationFailureServesButNeverAdvertises,
// TestIngressHostRetractsWhenNotServing), pkg/policy
// (TestReservedLoadBalancerPortCELSemantics and siblings) and pkg/install
// (TestNetdPlistXML's --node-ip pin).
func TestLBListenersBindWildcardAdvertiseDerived(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	// (a) THE BIND ADDRESS is the IPv4 wildcard literal.
	t.Run("both listeners bind the IPv4 wildcard 0.0.0.0", func(t *testing.T) {
		lb, ih, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		for _, tc := range []struct {
			what string
			got  netip.Addr
		}{{"svclb", lb.BindAddr}, {"ingresshost", ih.BindAddr}} {
			// String()=="0.0.0.0" AND Is4(), deliberately NOT IsUnspecified():
			// IsUnspecified() is also true for "::", which is exactly the
			// dual-stack [::] socket (IPV6_V6ONLY=0) the ":port" form would
			// produce and which this change forbids.
			if tc.got.String() != "0.0.0.0" || !tc.got.Is4() {
				t.Errorf("%s BindAddr = %q (Is4=%v), want the IPv4 literal 0.0.0.0", tc.what, tc.got, tc.got.Is4())
			}
		}
	})

	// (a, second half) THE BINDER SELECTION. The address and the binder are
	// INDEPENDENT: a one-line address change satisfies the assert above while
	// leaving every privileged port routed into netd.
	t.Run("no privileged binder is wired even in the helper posture", func(t *testing.T) {
		opts := gateNodeOptions()
		if !opts.netMode.UsesHelper() {
			t.Fatal("fixture must be in the helper posture or the assertion below is vacuous")
		}
		lb, ih, err := lbHostingConfigs(fake.NewClientset(), opts, 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		// Nil means the packages' in-process netbind.Direct default: ONE binder,
		// taking every port including <1024. (The per-port behavioural proof lives
		// in pkg/svclb's inverted "single in-process binder takes every port"
		// subtest — the config-level assert here is what keeps the helper posture
		// from re-acquiring a netd binder.)
		if lb.Binder != nil {
			t.Errorf("svclb Binder = %T, want nil (the single in-process binder); netd refuses the wildcard, so a helper binder fails every listener", lb.Binder)
		}
		if ih.Binder != nil {
			t.Errorf("ingresshost Binder = %T, want nil (the single in-process binder)", ih.Binder)
		}
	})

	// THE DERIVATION: the advertised address is the node's derived
	// globally-unicast .1, not the raw loopback --node-ip default.
	t.Run("the advertised address is the derived non-loopback node address", func(t *testing.T) {
		opts := gateNodeOptions()
		lb, ih, err := lbHostingConfigs(fake.NewClientset(), opts, 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		const want = "100.64.0.1"
		if lb.AdvertiseAddr.String() != want {
			t.Errorf("svclb AdvertiseAddr = %q, want the derived %q", lb.AdvertiseAddr, want)
		}
		if ih.AdvertiseAddr.String() != want {
			t.Errorf("ingresshost AdvertiseAddr = %q, want the derived %q", ih.AdvertiseAddr, want)
		}
		if lb.AdvertiseAddr.IsLoopback() {
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
		lb, ih, err := lbHostingConfigs(fake.NewClientset(), opts, 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		for _, tc := range []struct {
			what string
			got  netip.Addr
		}{{"svclb", lb.AdvertiseAddr}, {"ingresshost", ih.AdvertiseAddr}} {
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
				lb, ih, err := lbHostingConfigs(fake.NewClientset(), tc.opts(), 80, 443, log)
				if err != nil {
					t.Fatalf("lbHostingConfigs: %v", err)
				}
				if lb.AdvertiseAddr.IsValid() || ih.AdvertiseAddr.IsValid() {
					t.Errorf("AdvertiseAddr must be the ZERO Addr on a derivation failure, got svclb=%q ingress=%q", lb.AdvertiseAddr, ih.AdvertiseAddr)
				}
				if lb.BindAddr.String() != "0.0.0.0" || ih.BindAddr.String() != "0.0.0.0" {
					t.Error("listeners must STILL bind the wildcard on a derivation failure (the Service is <pending>, not disabled)")
				}
			})
		}
	})

	// The reserved-port set the datapath refusal uses is the SAME single source
	// the admission CEL and the apiserver argv derive from.
	t.Run("the reserved-port set is single-sourced from pkg/ports", func(t *testing.T) {
		lb, _, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
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

	// The retraction scope is the CLUSTER pod aggregate, so a node that re-enrolls
	// into a different /24 still retracts what its previous life advertised.
	t.Run("the retraction scope covers a previous enrollment's /24", func(t *testing.T) {
		lb, ih, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), 80, 443, log)
		if err != nil {
			t.Fatalf("lbHostingConfigs: %v", err)
		}
		for _, tc := range []struct {
			what string
			got  netip.Prefix
		}{{"svclb", lb.PodCIDR}, {"ingresshost", ih.PodCIDR}} {
			if !tc.got.Contains(netip.MustParseAddr("100.64.0.1")) || !tc.got.Contains(netip.MustParseAddr("100.64.2.1")) {
				t.Errorf("%s PodCIDR = %s, want the cluster aggregate containing both this node's /24 and a re-enrolled one", tc.what, tc.got)
			}
		}
	})

	// The seam is TOTAL: an out-of-range port errors rather than silently
	// truncating through the uint16 conversion (70000 -> 4464).
	t.Run("an out-of-range ingress port is an error, never a truncation", func(t *testing.T) {
		if _, _, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), 70000, 443, log); err == nil {
			t.Error("--ingress-http-port 70000 must error")
		}
		if _, _, err := lbHostingConfigs(fake.NewClientset(), gateNodeOptions(), 80, -1, log); err == nil {
			t.Error("--ingress-https-port -1 must error")
		}
	})
}

// TestKubeletListenAddressesUsePortsConstant pins that the kubelet API listen
// addresses are BUILT from ports.KubeletAPIPort, so the port the reserved-set
// guard protects and the port the node actually listens on cannot desync. Before
// B116 that port had no constant at all — just bare literals inside address
// strings.
func TestKubeletListenAddressesUsePortsConstant(t *testing.T) {
	suffix := ":" + strconv.Itoa(ports.KubeletAPIPort)
	for _, tc := range []struct{ name, addr string }{
		{"server/agent in-process node", serverKubeletListen},
		{"standalone `k3sm node` default", nodeKubeletListen},
	} {
		if !strings.HasSuffix(tc.addr, suffix) {
			t.Errorf("%s listen = %q, want the %q suffix from ports.KubeletAPIPort", tc.name, tc.addr, suffix)
		}
	}
	// The server/agent node listens on the WILDCARD so the apiserver node-proxy
	// reaches it at the address the node advertises.
	if serverKubeletListen != suffix {
		t.Errorf("serverKubeletListen = %q, want the wildcard form %q", serverKubeletListen, suffix)
	}
	if !ports.Reserved(ports.KubeletAPIPort) {
		t.Error("the kubelet API port must be in the reserved set: losing it to a LoadBalancer Service kills logs/exec/top on this node")
	}
}
