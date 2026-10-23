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
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/ports"
	"k3sm.io/k3sm/pkg/provider"
)

// testKubeletAuth builds the kubelet endpoint's auth posture from a throwaway CA,
// so the address/SAN assertions here exercise the REAL kubeletServingTLS signature
// (which has no shape that omits client authentication) without needing a
// provisioned work dir.
func testKubeletAuth(t *testing.T) *provider.KubeletEndpointAuth {
	t.Helper()
	ca, err := certs.NewCA("k3sm-test-signing-ca")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	auth, err := provider.NewKubeletEndpointAuth(ca.CertPEM, nil)
	if err != nil {
		t.Fatalf("NewKubeletEndpointAuth: %v", err)
	}
	return auth
}

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
	// startNode's own sequence: the advertise derivation, then the registered
	// address, which is the same value (proxyableNodeIP).
	opts.nodeIP = advertisedNodeIP(opts)
	n := &corev1.Node{}
	configureNode(n, opts.nodeName, proxyableNodeIP(opts), opts.listen, provider.NodeCapabilities{})
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	t.Fatalf("node registered no InternalIP: %+v", n.Status.Addresses)
	return ""
}

// stubLocalAddrs replaces the interface-address seam the kubelet endpoint's
// presence check reads, for one test.
func stubLocalAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	saved := localInterfaceAddrs
	localInterfaceAddrs = func() ([]netip.Addr, error) { return out, nil }
	t.Cleanup(func() { localInterfaceAddrs = saved })
}

// TestNodeAddressProxyable is the gate for this behaviour, narrowed by the kubelet listener
// derivation: the address the VK node registers as its NodeInternalIP is the
// address its kubelet API binds, so on the pod network it satisfies the
// upstream apiserver node-proxy predicate, and with no pod network it is
// loopback. It is never a host LAN address the operator did not name: serving
// the kubelet API there is what put it on untrusted networks. The cost is
// stated: a `--network none` node (the rootless `k3sm dev` tier) answers GET
// /api/v1/nodes/<n>/proxy/... with HTTP 400 "address not allowed" again.
func TestNodeAddressProxyable(t *testing.T) {
	const devPodCIDR = "100.64.0.0/24"
	noDatapath := hostnet.Mode{Backend: hostnet.BackendNone}
	datapath := hostnet.Mode{Backend: hostnet.BackendDirect}

	t.Run("dev rootless registers loopback, never a host address", func(t *testing.T) {
		got := registeredInternalIP(t, nodeOptions{
			nodeName:    "k3sm-dev",
			nodeIP:      loopbackNodeIP,
			kubeletPort: ports.KubeletAPIPort,
			podCIDR:     devPodCIDR,
			netMode:     noDatapath,
		})
		if got != loopbackNodeIP {
			t.Errorf("InternalIP = %q, want %q: with no pod network nothing else is the node's own", got, loopbackNodeIP)
		}
	})

	t.Run("datapath derivation is proxyable", func(t *testing.T) {
		got := registeredInternalIP(t, nodeOptions{
			nodeName:    "k3sm-node",
			nodeIP:      loopbackNodeIP,
			kubeletPort: ports.KubeletAPIPort,
			podCIDR:     devPodCIDR,
			netMode:     datapath,
		})
		if !upstreamProxyable(got) {
			t.Fatalf("InternalIP %q fails the apiserver node-proxy predicate", got)
		}
		// The mesh-egress .1 the podnet adapter aliases on lo0 — NOT a host LAN
		// address, which nothing on the datapath answers for.
		if want := nodeInternalIP(devPodCIDR); got != want {
			t.Errorf("InternalIP = %q, want the derived mesh-egress address %q", got, want)
		}
	})

	t.Run("explicit node-ip is honored", func(t *testing.T) {
		got := registeredInternalIP(t, nodeOptions{
			nodeName:    "k3sm-node",
			nodeIP:      "10.9.8.7",
			kubeletPort: ports.KubeletAPIPort,
			podCIDR:     devPodCIDR,
			netMode:     noDatapath,
		})
		if got != "10.9.8.7" {
			t.Errorf("InternalIP = %q, want the operator's --node-ip %q", got, "10.9.8.7")
		}
	})

	t.Run("standalone loopback listener registers loopback", func(t *testing.T) {
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

	t.Run("serving cert SANs cover the registered address", func(t *testing.T) {
		// The apiserver dials the InternalIP by IP; the cert must verify at it.
		opts := nodeOptions{
			nodeName:    "k3sm-dev",
			nodeIP:      loopbackNodeIP,
			kubeletPort: ports.KubeletAPIPort,
			podCIDR:     devPodCIDR,
			netMode:     datapath,
		}
		opts.nodeIP = advertisedNodeIP(opts)
		internalIP := proxyableNodeIP(opts)
		// nil/nil: the self-signed dev posture this case is about (a mesh node
		// carries an issued pair — TestKubeletServingTLSUsesIssuedPair).
		cfg, err := kubeletServingTLS(testKubeletAuth(t), nil, nil, opts.nodeName, opts.nodeIP, internalIP)
		if err != nil {
			t.Fatalf("kubeletServingTLS: %v", err)
		}
		// The serving half never ships without the client half.
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("kubeletServingTLS ClientAuth = %v, want tls.RequireAndVerifyClientCert", cfg.ClientAuth)
		}
		if cfg.ClientCAs == nil {
			t.Error("kubeletServingTLS returned a nil ClientCAs pool: no client certificate could verify")
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
}
