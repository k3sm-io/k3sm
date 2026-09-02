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
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestNewRelayBindDiscipline is the relay's half of the security posture the
// loopback-only registry rests on. The registry refuses every non-loopback bind,
// so the ONLY off-loopback exposure in this package is this relay — which means
// the set of addresses it will bind IS the exposure, and it has to be a closed
// set rather than a configurable one.
//
// The rows that carry the most weight are the refusals. The wildcard would serve
// every network this Mac is on; a LAN address would serve the coffee shop; and
// the vm gateway offered as a MESH address must still be refused, because the
// two addresses are admitted by different evidence and conflating them would let
// a bad --mesh-ip open a bind the mesh check was supposed to gate.
func TestNewRelayBindDiscipline(t *testing.T) {
	tests := []struct {
		name        string
		meshIP      string
		vmNetSubnet string
		port        int
		want        []string
		wantErr     error // nil => expect want
	}{
		{
			name: "a mesh address alone", meshIP: "100.64.1.1", port: 6450,
			want: []string{"100.64.1.1:6450"},
		},
		{
			name: "a vm NAT segment alone binds its gateway", vmNetSubnet: "192.168.64.0/24", port: 6450,
			want: []string{"192.168.64.1:6450"},
		},
		{
			name: "both, mesh first", meshIP: "100.64.2.1", vmNetSubnet: "192.168.64.0/24", port: 6450,
			want: []string{"100.64.2.1:6450", "192.168.64.1:6450"},
		},
		{
			name: "neither: there is no relay to start", port: 6450,
			wantErr: ErrNoRelayAddress,
		},
		{
			name: "loopback is refused: the registry already binds it", meshIP: "127.0.0.1", port: 6450,
			wantErr: ErrNonRelayableBind,
		},
		{
			name: "the wildcard is refused: it is the widening this design avoids", meshIP: "0.0.0.0", port: 6450,
			wantErr: ErrNonRelayableBind,
		},
		{
			name: "a LAN address is refused: it is not this cluster's mesh", meshIP: "192.168.1.10", port: 6450,
			wantErr: ErrNonRelayableBind,
		},
		{
			name: "a public address is refused", meshIP: "8.8.8.8", port: 6450,
			wantErr: ErrNonRelayableBind,
		},
		{
			name: "the vm gateway is refused AS a mesh address", meshIP: "192.168.64.1", port: 6450,
			wantErr: ErrNonRelayableBind,
		},
		{
			name: "a mesh address that is not an address", meshIP: "mac-a.local", port: 6450,
			wantErr: ErrNonRelayableBind,
		},
		{
			name: "a vm segment that is not a CIDR", vmNetSubnet: "192.168.64.1", port: 6450,
			wantErr: ErrNonRelayableBind,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRelay(RelayConfig{
				Port:        tc.port,
				MeshIP:      tc.meshIP,
				VMNetSubnet: tc.vmNetSubnet,
				Logger:      quietLogger(),
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("NewRelay err = %v, want %v", err, tc.wantErr)
				}
				if r != nil {
					t.Errorf("NewRelay returned a relay alongside %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRelay: %v", err)
			}
			if got := r.Addresses(); !slices.Equal(got, tc.want) {
				t.Errorf("Addresses() = %v, want %v", got, tc.want)
			}
			// Whatever it binds, it forwards to loopback and nowhere else.
			if want := "127.0.0.1:" + strconv.Itoa(tc.port); r.target() != want {
				t.Errorf("target = %q, want %q — the relay must never forward off-host", r.target(), want)
			}
		})
	}
}

// TestNewRelayPortDiscipline pins the port range. A relay on port 0 would bind an
// ephemeral port no advertisement names.
func TestNewRelayPortDiscipline(t *testing.T) {
	for _, port := range []int{0, -1, 65536, 70000} {
		t.Run("port "+strconv.Itoa(port)+" is refused", func(t *testing.T) {
			if _, err := NewRelay(RelayConfig{Port: port, MeshIP: "100.64.1.1", Logger: quietLogger()}); err == nil {
				t.Fatalf("NewRelay(port %d) = nil error", port)
			}
		})
	}
}

// TestVMNetGateway pins the derivation. The gateway is DERIVED from the segment
// rather than written down, so moving the segment moves the bind — two constants
// that must agree are one constant and one bug.
func TestVMNetGateway(t *testing.T) {
	tests := []struct {
		subnet string
		want   string
	}{
		{subnet: "192.168.64.0/24", want: "192.168.64.1"},
		{subnet: "192.168.65.0/24", want: "192.168.65.1"},
		{subnet: "10.37.129.0/24", want: "10.37.129.1"},
	}
	for _, tc := range tests {
		t.Run(tc.subnet, func(t *testing.T) {
			gw, err := VMNetGateway(tc.subnet)
			if err != nil {
				t.Fatalf("VMNetGateway(%q): %v", tc.subnet, err)
			}
			if gw.String() != tc.want {
				t.Errorf("VMNetGateway(%q) = %s, want %s", tc.subnet, gw, tc.want)
			}
		})
	}
	t.Run("a non-CIDR is refused", func(t *testing.T) {
		if _, err := VMNetGateway("192.168.64.1"); !errors.Is(err, ErrNonRelayableBind) {
			t.Errorf("err = %v, want ErrNonRelayableBind", err)
		}
	})
}

// TestRelayForwards drives the accept+forward mechanics over a loopback pair: the
// relay's own production listener and dialer, an echo server standing in for the
// registry, and a client standing in for a peer.
//
// The half-close row is the one worth having. A registry push writes a large body
// and then reads the response, and a pull streams a blob long after the request
// ended; a forwarder that tore the pair down when EITHER direction finished would
// truncate both, and would still pass a naive round-trip test.
func TestRelayForwards(t *testing.T) {
	t.Run("bytes reach the registry and the answer comes back", func(t *testing.T) {
		port := startEchoRegistry(t)
		client := dialThroughRelay(t, port)
		if _, err := client.Write([]byte("ping\n")); err != nil {
			t.Fatalf("write through the relay: %v", err)
		}
		got := readLine(t, client)
		if got != "ping" {
			t.Errorf("read %q through the relay, want %q", got, "ping")
		}
	})

	t.Run("a client half-close does not truncate the response", func(t *testing.T) {
		port := startEchoRegistry(t)
		client := dialThroughRelay(t, port)
		if _, err := client.Write([]byte("last\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		// The client is done writing. The registry must still be able to answer,
		// which is exactly the shape of a completed push awaiting its response.
		if tc, ok := client.(*net.TCPConn); ok {
			if err := tc.CloseWrite(); err != nil {
				t.Fatalf("half-close: %v", err)
			}
		}
		if got := readLine(t, client); got != "last" {
			t.Errorf("read %q after a half-close, want %q — the response was truncated", got, "last")
		}
	})

	t.Run("a dead registry closes the connection rather than hanging", func(t *testing.T) {
		// No echo server: the loopback dial is refused, which is precisely what a
		// peer's puller reads as "this mirror does not have it".
		port := freePort(t)
		client := dialThroughRelay(t, port)
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(client); err != nil {
			t.Fatalf("read from a relay with no registry behind it: %v", err)
		}
	})
}

// TestRelaySkipsAnAbsentAddress pins the graceful skip. A Mac that has never
// started a vm guest has no bridge interface, so the gateway address is not
// configured and the bind returns EADDRNOTAVAIL. That is a STATE, not a fault:
// the listener stops immediately, without spending the retry budget on a
// condition nothing here can change, and without touching the other address.
func TestRelaySkipsAnAbsentAddress(t *testing.T) {
	r := newRelay(6450, []netip.Addr{netip.MustParseAddr("192.168.64.1")}, quietLogger())
	attempts := 0
	r.listen = func(string) (net.Listener, error) {
		attempts++
		return nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRNOTAVAIL}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(t.Context())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on an unconfigured address; it is retrying a condition it cannot change")
	}
	if attempts != 1 {
		t.Errorf("bind attempts = %d, want 1 — an absent address must not consume the retry budget", attempts)
	}
}

// TestRelayStopsOnContextCancel pins the lifecycle: the relay comes down with the
// registry it fronts, and Run returns rather than leaking its listeners.
func TestRelayStopsOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := newRelay(portOf(t, ln.Addr()), nil, quietLogger())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.accept(ctx, ln)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("accept did not return on cancellation")
	}
	// The listener is closed by the accept loop's watcher, so a second bind of
	// the same address succeeds.
	_ = ln.Close()
}

// --- helpers ---------------------------------------------------------------

// quietLogger discards: these tests assert behavior, not log lines.
func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// startEchoRegistry stands in for the loopback ingest registry: it echoes each
// line back. It returns the port, which is BOTH the relay's forward target and
// the port the relay would bind on a real address.
func startEchoRegistry(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return portOf(t, ln.Addr())
}

// dialThroughRelay starts a relay whose forward target is 127.0.0.1:<port>,
// fronted by a loopback listener the test dials — the same accept+forward path a
// mesh peer or a vm guest takes, with no mesh and no guest.
func dialThroughRelay(t *testing.T, port int) net.Conn {
	t.Helper()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := newRelay(port, nil, quietLogger())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.accept(ctx, front)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = front.Close()
	})
	c, err := net.DialTimeout("tcp", front.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the relay: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// portOf extracts the port from a listener address.
func portOf(t *testing.T, a net.Addr) int {
	t.Helper()
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatalf("split %s: %v", a, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port %q: %v", p, err)
	}
	return n
}

// readLine reads one newline-terminated line.
func readLine(t *testing.T, c net.Conn) string {
	t.Helper()
	buf := make([]byte, 0, 64)
	one := make([]byte, 1)
	for {
		n, err := c.Read(one)
		if err != nil {
			t.Fatalf("read: %v (got %q so far)", err, buf)
		}
		if n == 0 {
			continue
		}
		if one[0] == '\n' {
			return strings.TrimRight(string(buf), "\r")
		}
		buf = append(buf, one[0])
	}
}
