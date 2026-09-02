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
	"net"
	"net/http"
	"testing"
	"time"
)

// stubUnderlayIPs replaces the host-interface scan for the duration of a test: a
// test cannot add or remove an address on the machine running it, and the whole
// point of the fallback is WHICH address it picks.
func stubUnderlayIPs(t *testing.T, ips []net.IP) {
	t.Helper()
	orig := underlayInterfaceIPs
	t.Cleanup(func() { underlayInterfaceIPs = orig })
	underlayInterfaceIPs = func() []net.IP { return ips }
}

// TestWorkerMeshEndpointIsAnUnderlayAddress is M14.2 defect-A's unit tier.
//
// The property is REACHABILITY BEFORE THE MESH EXISTS. A MeshPeer endpoint is what
// every other node dials to open the wireguard handshake, and a peer that has not
// yet completed that handshake has no route into the mesh — so an endpoint inside
// the mesh is unreachable by definition. The live lab showed exactly that:
// `k3sm-worker-b` enrolled `100.64.1.1:51820`, its own mesh IP, and the server then
// initiated handshakes into its own tunnel.
//
// The captured address is preferred because it is the source address the kernel's
// route lookup picked for THIS server — the interface that provably reaches the
// control plane is exactly the one a peer should dial back on.
func TestWorkerMeshEndpointIsAnUnderlayAddress(t *testing.T) {
	stubUnderlayIPs(t, []net.IP{net.ParseIP("192.168.1.42")})

	for _, tc := range []struct {
		name   string
		local  net.IP
		meshIP string
		want   string
	}{
		{"the captured join source address is advertised", net.ParseIP("192.168.1.77"), "100.64.1.1", "192.168.1.77:51820"},
		{"this node's own mesh IP is rejected", net.ParseIP("100.64.1.1"), "100.64.1.1", "192.168.1.42:51820"},
		{"any address inside the mesh CIDR is rejected", net.ParseIP("100.64.2.1"), "100.64.1.1", "192.168.1.42:51820"},
		{"loopback is rejected", net.ParseIP("127.0.0.1"), "100.64.1.1", "192.168.1.42:51820"},
		{"an unspecified address is rejected", net.IPv4zero, "100.64.1.1", "192.168.1.42:51820"},
		{"a link-local address is rejected", net.ParseIP("169.254.7.7"), "100.64.1.1", "192.168.1.42:51820"},
		{"a failed capture falls back to the host scan", nil, "100.64.1.1", "192.168.1.42:51820"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := underlayMeshEndpoint(tc.local, tc.meshIP, 51820)
			if err != nil {
				t.Fatalf("underlayMeshEndpoint: %v", err)
			}
			if got != tc.want {
				t.Errorf("underlayMeshEndpoint(%v, %q) = %q, want %q", tc.local, tc.meshIP, got, tc.want)
			}
			if host, _, err := net.SplitHostPort(got); err != nil {
				t.Errorf("unparsable endpoint %q: %v", got, err)
			} else if host == tc.meshIP {
				t.Errorf("advertised this node's mesh IP %q as its wireguard endpoint — no peer can dial it", host)
			}
		})
	}
}

// TestWorkerMeshEndpointRefusesRatherThanAdvertiseTheMeshIP: when the capture fails
// AND the host offers no underlay address, there is no honest endpoint to publish.
// Failing the join is correct; publishing the mesh IP would enroll a peer entry that
// can never complete a handshake and would be indistinguishable, from the server's
// side, from a working one.
func TestWorkerMeshEndpointRefusesRatherThanAdvertiseTheMeshIP(t *testing.T) {
	stubUnderlayIPs(t, []net.IP{net.ParseIP("100.64.1.1"), net.ParseIP("127.0.0.1")})

	got, err := underlayMeshEndpoint(net.ParseIP("100.64.1.1"), "100.64.1.1", 51820)
	if err == nil {
		t.Fatalf("underlayMeshEndpoint returned %q with only mesh/loopback addresses available; want an error", got)
	}
}

// TestUnderlayInterfaceScanExcludesTunnels: the mesh's own utun carries the very
// address this derivation exists to reject, so the fallback scan must not offer it.
func TestUnderlayInterfaceScanExcludesTunnels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tunnel bool
	}{
		{"utun0", true},
		{"utun7", true},
		{"ipsec0", true},
		{"gif0", true},
		{"stf0", true},
		{"en0", false},
		{"en1", false},
		{"bridge100", false},
	} {
		if got := isTunnelInterface(tc.name); got != tc.tunnel {
			t.Errorf("isTunnelInterface(%q) = %v, want %v", tc.name, got, tc.tunnel)
		}
	}
}

// TestJoinDialerCapturesTheJoinSourceAddress pins the seam the derivation reads:
// the join client's dialer must record the LOCAL address of the connection it
// opened, or every join falls back to the host scan and the capture is decorative.
func TestJoinDialerCapturesTheJoinSourceAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()

	d := &localAddrDialer{}
	if ip := d.localIP(); ip != nil {
		t.Errorf("a dialer that has not dialed reports %v, want nil", ip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	got := d.localIP()
	if got == nil {
		t.Fatal("the dialer recorded no local address")
	}
	if !got.IsLoopback() {
		t.Errorf("recorded local address %v for a loopback destination, want a loopback address", got)
	}
}

// TestPinnedJoinClientKeepsTheCAPin: installing the capturing dialer must not
// disturb the token's CA-hash pin — that pin is the join's ONLY trust anchor before
// the node possesses any CA, and a transport rebuilt without it would silently
// downgrade to insecure-skip-verify.
func TestPinnedJoinClientKeepsTheCAPin(t *testing.T) {
	client, dialer, err := pinnedJoinClient("abc123")
	if err != nil {
		t.Fatalf("pinnedJoinClient: %v", err)
	}
	if dialer == nil {
		t.Fatal("pinnedJoinClient returned no dialer to read the join source address from")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("join client transport is %T, want *http.Transport", client.Transport)
	}
	if tr.DialContext == nil {
		t.Error("the join client does not dial through the capturing dialer")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("the join client lost its pinned-CA VerifyConnection — the join would trust any chain")
	}
	if tr.TLSClientConfig.MinVersion != 0x0303 {
		t.Errorf("join client MinVersion = %#x, want TLS 1.2", tr.TLSClientConfig.MinVersion)
	}
}
