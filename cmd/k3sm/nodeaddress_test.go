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
	"crypto/x509"
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/provider"
)

// upstreamProxyable is the apiserver node-proxy predicate, restated from
// kubernetes v1.36.2 pkg/registry/core/node/strategy.go:275-291
// (isProxyableHostname, reached from ResourceLocation at :256):
//
//	resp, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
//	...
//	for _, host := range resp {
//	    if !host.IP.IsGlobalUnicast() {
//	        return fmt.Errorf("address not allowed")
//	    }
//	}
//
// The address it is handed is GetPreferredNodeAddress(node, preferredAddressTypes)
// — and k3sm's executor starts the apiserver with
// --kubelet-preferred-address-types=InternalIP (pkg/executor/supervised.go), so
// the address under test is exactly Node.Status.Addresses' InternalIP entry.
//
// Resolution is elided deliberately: a unit test does no DNS, and LookupIPAddr on
// an IP LITERAL returns that literal, so for the values k3sm registers the whole
// predicate reduces to the stdlib net.IP.IsGlobalUnicast() call below — the SAME
// function upstream calls, not a paraphrase of it.
func upstreamProxyable(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.IsGlobalUnicast()
}

// registeredInternalIP runs the real registration path for opts and returns the
// InternalIP the Node object carries.
func registeredInternalIP(t *testing.T, opts nodeOptions) string {
	t.Helper()
	// startNode's own two-tier sequence: the datapath derivation first, then the
	// proxyable substitution. Keep them in this order — see advertisedNodeIP.
	opts.nodeIP = advertisedNodeIP(opts)
	n := &corev1.Node{}
	configureNode(n, opts.nodeName, proxyableNodeIP(opts), provider.NodeCapabilities{})
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	t.Fatalf("node registered no InternalIP: %+v", n.Status.Addresses)
	return ""
}

// stubHostIPs replaces the host-interface seam for one test.
func stubHostIPs(t *testing.T, addrs ...string) {
	t.Helper()
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("stubHostIPs: %q is not an IP", a)
		}
		ips = append(ips, ip)
	}
	saved := hostInterfaceIPs
	hostInterfaceIPs = func() []net.IP { return ips }
	t.Cleanup(func() { hostInterfaceIPs = saved })
}

// TestNodeAddressProxyable is B174's gate: the address the VK node registers as
// its NodeInternalIP must satisfy the upstream apiserver node-proxy predicate, in
// every posture where the node's kubelet API listener can actually answer at it.
// A loopback InternalIP — what `k3sm dev` (--network none) registered — makes
// every GET /api/v1/nodes/<n>/proxy/... fail with HTTP 400 "address not allowed",
// which is `kubectl top node`, `kubectl top pod`, and metrics-server.
func TestNodeAddressProxyable(t *testing.T) {
	const (
		devPodCIDR = "100.64.0.0/24"
		hostLAN    = "192.168.1.42"
	)
	noDatapath := hostnet.Mode{Backend: hostnet.BackendNone}
	datapath := hostnet.Mode{Backend: hostnet.BackendDirect}

	t.Run("dev rootless registers a proxyable address", func(t *testing.T) {
		stubHostIPs(t, "169.254.10.1", hostLAN)
		got := registeredInternalIP(t, nodeOptions{
			nodeName: "k3sm-dev",
			nodeIP:   loopbackNodeIP,
			listen:   serverKubeletListen,
			podCIDR:  devPodCIDR,
			netMode:  noDatapath,
		})
		if !upstreamProxyable(got) {
			t.Fatalf("InternalIP %q fails the apiserver node-proxy predicate; the proxy answers 400 %q and kubectl top is dead", got, "address not allowed")
		}
		if got != hostLAN {
			t.Errorf("InternalIP = %q, want the host's globally-unicast interface address %q", got, hostLAN)
		}
	})

	t.Run("datapath derivation still wins", func(t *testing.T) {
		stubHostIPs(t, hostLAN)
		got := registeredInternalIP(t, nodeOptions{
			nodeName: "k3sm-node",
			nodeIP:   loopbackNodeIP,
			listen:   serverKubeletListen,
			podCIDR:  devPodCIDR,
			netMode:  datapath,
		})
		if !upstreamProxyable(got) {
			t.Fatalf("InternalIP %q fails the apiserver node-proxy predicate", got)
		}
		// The mesh-egress .1 the podnet adapter aliases on lo0 — NOT the host LAN
		// address, which nothing on the datapath answers for.
		if want := nodeInternalIP(devPodCIDR); got != want {
			t.Errorf("InternalIP = %q, want the derived mesh-egress address %q", got, want)
		}
	})

	t.Run("explicit node-ip is honored", func(t *testing.T) {
		stubHostIPs(t, hostLAN)
		got := registeredInternalIP(t, nodeOptions{
			nodeName: "k3sm-node",
			nodeIP:   "10.9.8.7",
			listen:   serverKubeletListen,
			podCIDR:  devPodCIDR,
			netMode:  noDatapath,
		})
		if got != "10.9.8.7" {
			t.Errorf("InternalIP = %q, want the operator's --node-ip %q", got, "10.9.8.7")
		}
	})

	t.Run("loopback-scoped listener is not readvertised", func(t *testing.T) {
		// Standalone `k3sm node` binds 127.0.0.1:10250. Advertising a host address
		// there would trade HTTP 400 for a refused connection — bind before you
		// advertise.
		stubHostIPs(t, hostLAN)
		got := registeredInternalIP(t, nodeOptions{
			nodeName: "k3sm-node",
			nodeIP:   loopbackNodeIP,
			listen:   nodeKubeletListen,
			podCIDR:  devPodCIDR,
			netMode:  noDatapath,
		})
		if got != loopbackNodeIP {
			t.Errorf("InternalIP = %q, want %q: the listener serves only loopback", got, loopbackNodeIP)
		}
	})

	t.Run("no proxyable host address keeps the loopback default", func(t *testing.T) {
		// Fail-soft: an offline Mac with nothing but link-local still registers.
		stubHostIPs(t, "169.254.10.1", "fe80::1")
		got := registeredInternalIP(t, nodeOptions{
			nodeName: "k3sm-node",
			nodeIP:   loopbackNodeIP,
			listen:   serverKubeletListen,
			podCIDR:  devPodCIDR,
			netMode:  noDatapath,
		})
		if got != loopbackNodeIP {
			t.Errorf("InternalIP = %q, want the %q fail-soft default", got, loopbackNodeIP)
		}
	})

	t.Run("serving cert SANs cover the registered address", func(t *testing.T) {
		// The apiserver dials the InternalIP by IP; the cert must verify at it.
		stubHostIPs(t, hostLAN)
		opts := nodeOptions{
			nodeName: "k3sm-dev",
			nodeIP:   loopbackNodeIP,
			listen:   serverKubeletListen,
			podCIDR:  devPodCIDR,
			netMode:  noDatapath,
		}
		opts.nodeIP = advertisedNodeIP(opts)
		internalIP := proxyableNodeIP(opts)
		cfg, err := kubeletServingTLS(opts.nodeName, opts.nodeIP, internalIP)
		if err != nil {
			t.Fatalf("kubeletServingTLS: %v", err)
		}
		if len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
			t.Fatalf("kubeletServingTLS returned no certificate")
		}
		leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		want := net.ParseIP(internalIP)
		found := false
		for _, ip := range leaf.IPAddresses {
			if ip.Equal(want) {
				found = true
			}
		}
		if !found {
			t.Errorf("kubelet serving cert IP SANs %v do not cover the registered InternalIP %s", leaf.IPAddresses, internalIP)
		}
	})

	t.Run("firstProxyableIP applies the upstream address classes", func(t *testing.T) {
		cases := []struct {
			name string
			in   []string
			want string
		}{
			{"unspecified is refused", []string{"0.0.0.0"}, ""},
			{"loopback is refused", []string{"127.0.0.1"}, ""},
			{"ipv6 loopback is refused", []string{"::1"}, ""},
			{"link-local is refused", []string{"169.254.1.1"}, ""},
			{"ipv6 link-local is refused", []string{"fe80::1"}, ""},
			{"multicast is refused", []string{"224.0.0.1"}, ""},
			{"rfc1918 is allowed", []string{"10.1.2.3"}, "10.1.2.3"},
			{"cgnat is allowed", []string{"100.64.0.1"}, "100.64.0.1"},
			{"public is allowed", []string{"93.184.216.34"}, "93.184.216.34"},
			{"ipv4 wins over ipv6", []string{"2001:db8::1", "192.168.5.5"}, "192.168.5.5"},
			{"ipv6 only", []string{"fe80::1", "2001:db8::1"}, "2001:db8::1"},
			{"first allowed wins", []string{"127.0.0.1", "172.16.0.9", "10.0.0.1"}, "172.16.0.9"},
			{"none", nil, ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ips := make([]net.IP, 0, len(tc.in))
				for _, a := range tc.in {
					ip := net.ParseIP(a)
					if ip == nil {
						t.Fatalf("bad fixture %q", a)
					}
					ips = append(ips, ip)
				}
				if got := firstProxyableIP(ips); got != tc.want {
					t.Errorf("firstProxyableIP(%v) = %q, want %q", tc.in, got, tc.want)
				}
				if tc.want != "" && !upstreamProxyable(tc.want) {
					t.Errorf("fixture %q does not satisfy the upstream predicate", tc.want)
				}
			})
		}
	})

	t.Run("wildcardListen", func(t *testing.T) {
		cases := map[string]bool{
			":10250":            true,
			"0.0.0.0:10250":     true,
			"[::]:10250":        true,
			"127.0.0.1:10250":   false,
			"192.168.1.42:1025": false,
			"localhost:10250":   false,
			"nonsense":          false,
			"":                  false,
		}
		for listen, want := range cases {
			if got := wildcardListen(listen); got != want {
				t.Errorf("wildcardListen(%q) = %v, want %v", listen, got, want)
			}
		}
		if !wildcardListen(serverKubeletListen) {
			t.Errorf("serverKubeletListen %q must be wildcard", serverKubeletListen)
		}
		if wildcardListen(nodeKubeletListen) {
			t.Errorf("nodeKubeletListen %q must be scoped", nodeKubeletListen)
		}
	})
}
