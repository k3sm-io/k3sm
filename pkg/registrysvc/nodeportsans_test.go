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

package registrysvc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
)

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// TestRelayServingSANsWithoutNodePort pins the flag-off certificate: with no
// NodePort SANs the set is exactly the in-cluster one, name for name and
// address for address, whatever the host is called.
func TestRelayServingSANsWithoutNodePort(t *testing.T) {
	dnsNames, ips := RelayServingSANs("", "10.43.0.20", "100.64.0.1", "192.168.64.0/24", NodePortSANs{})
	wantDNS := []string{"registry-k3sm", "registry-k3sm.k3sm-registry", "registry-k3sm.k3sm-registry.svc", "registry-k3sm.k3sm-registry.svc.cluster.local"}
	if !slices.Equal(dnsNames, wantDNS) {
		t.Errorf("DNS SANs = %v, want exactly %v", dnsNames, wantDNS)
	}
	if got, want := ipStrings(ips), []string{"10.43.0.20", "100.64.0.1", "192.168.64.1"}; !slices.Equal(got, want) {
		t.Errorf("IP SANs = %v, want exactly %v", got, want)
	}
	if !slices.Equal(dnsNames, FlatServiceDNSNames("")) || !slices.Equal(ipStrings(ips), ipStrings(FlatServingIPs("10.43.0.20", "100.64.0.1", "192.168.64.0/24"))) {
		t.Error("the flag-off set differs from FlatServiceDNSNames + FlatServingIPs")
	}
}

// TestNodePortServingSANs pins what the NodePort adds: the Node's usable
// InternalIP addresses, the hostname, and a .local name with its bare label.
func TestNodePortServingSANs(t *testing.T) {
	node := func(addrs ...corev1.NodeAddress) *corev1.Node {
		return &corev1.Node{Status: corev1.NodeStatus{Addresses: addrs}}
	}
	for _, tc := range []struct {
		name     string
		node     *corev1.Node
		hostname string
		wantDNS  []string
		wantIPs  []string
	}{
		{name: "nothing known", wantDNS: nil, wantIPs: nil},
		{
			name: "a .local hostname and a mesh InternalIP", hostname: "Studio-Mac.local.",
			node:    node(corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "100.64.0.1"}, corev1.NodeAddress{Type: corev1.NodeHostName, Address: "k3sm-studio-mac"}),
			wantDNS: []string{"studio-mac.local", "studio-mac"}, wantIPs: []string{"100.64.0.1"},
		},
		{
			name: "a plain hostname adds no .local name", hostname: "build-host",
			wantDNS: []string{"build-host"},
		},
		{
			name: "a .local Hostname address on the Node", hostname: "build-host",
			node:    node(corev1.NodeAddress{Type: corev1.NodeHostName, Address: "box.local"}),
			wantDNS: []string{"build-host", "box", "box.local"},
		},
		{
			name: "only usable InternalIPs, each once", hostname: "Alex's Mac",
			node: node(
				corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "127.0.0.1"},
				corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "0.0.0.0"},
				corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "::ffff:10.0.0.7"},
				corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "10.0.0.7"},
				corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "not-an-ip"},
				corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: "203.0.113.9"},
				corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "fd00::7"},
			),
			wantIPs: []string{"10.0.0.7", "fd00::7"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NodePortServingSANs(tc.node, tc.hostname)
			if !slices.Equal(got.DNS, tc.wantDNS) {
				t.Errorf("DNS = %v, want %v", got.DNS, tc.wantDNS)
			}
			var ips []string
			for _, a := range got.IPs {
				ips = append(ips, a.String())
			}
			if !slices.Equal(ips, tc.wantIPs) {
				t.Errorf("IPs = %v, want %v", ips, tc.wantIPs)
			}
		})
	}

	t.Run("composed after the in-cluster set, each once", func(t *testing.T) {
		ext := NodePortSANs{DNS: []string{"studio-mac", "registry-k3sm"}, IPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("172.16.5.10")}}
		dnsNames, ips := RelayServingSANs("", "10.43.0.20", "100.64.0.1", "", ext)
		if want := append(FlatServiceDNSNames(""), "studio-mac"); !slices.Equal(dnsNames, want) {
			t.Errorf("DNS SANs = %v, want %v", dnsNames, want)
		}
		if got, want := ipStrings(ips), []string{"10.43.0.20", "100.64.0.1", "172.16.5.10"}; !slices.Equal(got, want) {
			t.Errorf("IP SANs = %v, want %v", got, want)
		}
		if !ext.Equal(NodePortSANs{DNS: []string{"studio-mac", "registry-k3sm"}, IPs: ext.IPs}) || ext.Equal(NodePortSANs{}) {
			t.Error("NodePortSANs.Equal does not compare the sets")
		}
	})
}

// TestRelayVerifiesAtTheNodePortAddress dials the shipped relay the way a tool
// on another Mac dials the NodePort: at the server Node's InternalIP and the
// NodePort, and by the host's .local name, trusting only the cluster CA. With
// the NodePort SANs the handshake verifies; with the flag-off set the same dial
// is refused by verification, which is the failure the SANs exist to remove.
func TestRelayVerifiesAtTheNodePortAddress(t *testing.T) {
	const (
		meshIP     = "100.64.0.1"
		internalIP = "172.16.5.10"
		nodePort   = "30650"
	)
	ca, err := testCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	node := &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: internalIP},
		{Type: corev1.NodeHostName, Address: "k3sm-studio"},
	}}}

	start := func(t *testing.T, ext NodePortSANs) *memListener {
		t.Helper()
		_, zaddr := socketZot(t)
		registryPort := portOf(t, zaddr)
		serving, err := NewServingIdentity(ServingConfig{
			Mint: func() (tls.Certificate, error) {
				dnsNames, ips := RelayServingSANs("", "10.43.0.20", meshIP, "", ext)
				return ca.IssueRegistryServing(FlatServiceName, dnsNames, ips, time.Hour)
			},
			Margin: time.Minute,
			Logger: quietLogger(),
		})
		if err != nil {
			t.Fatalf("NewServingIdentity: %v", err)
		}
		front := newMemListener()
		r, err := NewRelay(RelayConfig{
			Port:           registryPort,
			MeshIP:         meshIP,
			Auth:           GateAuth{Tokens: &fakeTokens{}, Access: &fakeAccess{allow: func(*authzv1.SubjectAccessReview) bool { return false }}, Namespaces: &fakeNamespaces{}},
			Serving:        serving,
			Listen:         func(string) (net.Listener, error) { return front, nil },
			GateCredential: gateCred,
			Logger:         quietLogger(),
		})
		if err != nil {
			t.Fatalf("NewRelay: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); r.Run(ctx) }()
		t.Cleanup(func() { cancel(); <-done })
		return front
	}

	// get dials host:nodePort, as the URL names it, with the system roots
	// replaced by the cluster CA alone.
	get := func(t *testing.T, front *memListener, host string) error {
		t.Helper()
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext:     func(context.Context, string, string) (net.Conn, error) { return front.dial() },
		}
		t.Cleanup(tr.CloseIdleConnections)
		client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
		resp, err := client.Get("https://" + net.JoinHostPort(host, nodePort) + "/v2/app/manifests/v1")
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET via %s = %d, want 200", host, resp.StatusCode)
		}
		return nil
	}

	t.Run("with the NodePort SANs", func(t *testing.T) {
		front := start(t, NodePortServingSANs(node, "studio.local"))
		for _, host := range []string{internalIP, "studio.local", "studio"} {
			if err := get(t, front, host); err != nil {
				t.Errorf("GET via %s:%s trusting only the cluster CA: %v", host, nodePort, err)
			}
		}
	})

	t.Run("the flag-off set does not verify there", func(t *testing.T) {
		front := start(t, NodePortSANs{})
		for _, host := range []string{internalIP, "studio.local"} {
			err := get(t, front, host)
			var hostErr x509.HostnameError
			if !errors.As(err, &hostErr) {
				t.Errorf("GET via %s:%s with the in-cluster certificate: err = %v, want a hostname verification failure", host, nodePort, err)
			}
		}
	})
}
