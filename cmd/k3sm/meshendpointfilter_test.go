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
	"net"
	"strings"
	"testing"
)

// stubControlPlaneSourceIP replaces the worker's probe of the control plane: each
// call returns the next entry, where a nil address means the server is unreachable.
func stubControlPlaneSourceIP(t *testing.T, seq []net.IP) {
	t.Helper()
	orig := controlPlaneSourceIP
	t.Cleanup(func() { controlPlaneSourceIP = orig })
	i := 0
	controlPlaneSourceIP = func(context.Context, string) (net.IP, error) {
		ip := seq[i]
		i++
		if ip == nil {
			return nil, errors.New("connect: host is down")
		}
		return ip, nil
	}
}

// TestMeshEndpointNeverAdvertisesSpecialPurpose pins which addresses may be
// published as a wireguard endpoint.
//
// A worker on a network that hands it a CLAT address (192.0.0.2, from the RFC 6890
// IETF protocol-assignments block) advertised it, and no peer can reach it. The
// same holds for the other special-purpose blocks a Mac can hold on an interface:
// carrier-grade NAT space, benchmarking space that VPN clients use for fake
// addresses, the reserved class-E block and the NAT64 and Teredo prefixes. Each
// must be refused both as the route-proven source address and in the interface
// scan, while ordinary private and global addresses stay advertisable.
func TestMeshEndpointNeverAdvertisesSpecialPurpose(t *testing.T) {
	const meshIP = "100.64.1.1"

	t.Run("special-purpose addresses are never usable", func(t *testing.T) {
		for _, addr := range []string{
			"192.0.0.2",         // CLAT (192.0.0.0/24, IETF protocol assignments)
			"192.0.0.170",       // NAT64 discovery, same block
			"100.100.5.5",       // carrier-grade NAT (100.64.0.0/10)
			"100.127.255.254",   // top of the CGNAT block
			"198.18.0.1",        // benchmarking (198.18.0.0/15)
			"198.19.255.1",      // benchmarking, upper half
			"240.0.0.1",         // reserved (240.0.0.0/4)
			"0.1.2.3",           // "this network" (0.0.0.0/8)
			"169.254.10.10",     // link-local
			"fe80::1",           // IPv6 link-local
			"64:ff9b::c000:202", // NAT64 well-known prefix
			"64:ff9b:1::1",      // NAT64 local-use prefix
			"2001::1",           // Teredo (2001::/32)
			"100::1",            // discard-only (100::/64)
		} {
			if got := usableUnderlayIP(net.ParseIP(addr), meshIP); got != "" {
				t.Errorf("usableUnderlayIP(%s) = %q, want it refused", addr, got)
			}
		}
	})

	t.Run("ordinary private and global addresses stay usable", func(t *testing.T) {
		for _, addr := range []string{"192.168.7.20", "10.1.2.3", "172.16.5.5", "17.1.2.3", "fd00::5", "2a01:4f8::1"} {
			if got := usableUnderlayIP(net.ParseIP(addr), meshIP); got == "" {
				t.Errorf("usableUnderlayIP(%s) refused an ordinary address", addr)
			}
		}
	})

	t.Run("a special-purpose join source falls back to the scan", func(t *testing.T) {
		stubUnderlayIPs(t, []net.IP{net.ParseIP("192.168.1.42")})
		got, err := underlayMeshEndpoint(net.ParseIP("192.0.0.2"), meshIP, 51820)
		if err != nil {
			t.Fatalf("underlayMeshEndpoint: %v", err)
		}
		if got != "192.168.1.42:51820" {
			t.Errorf("underlayMeshEndpoint = %q, want the scanned LAN address", got)
		}
	})

	t.Run("the scan skips special-purpose addresses", func(t *testing.T) {
		stubUnderlayIPs(t, []net.IP{net.ParseIP("192.0.0.2"), net.ParseIP("100.80.1.1"), net.ParseIP("198.18.0.9"), net.ParseIP("10.0.0.7")})
		got, err := underlayMeshEndpoint(nil, meshIP, 51820)
		if err != nil {
			t.Fatalf("underlayMeshEndpoint: %v", err)
		}
		if got != "10.0.0.7:51820" {
			t.Errorf("underlayMeshEndpoint = %q, want 10.0.0.7:51820", got)
		}
	})

	t.Run("only special-purpose addresses is an error, not a guess", func(t *testing.T) {
		stubUnderlayIPs(t, []net.IP{net.ParseIP("192.0.0.2"), net.ParseIP("fe80::1")})
		if got, err := underlayMeshEndpoint(net.ParseIP("192.0.0.2"), meshIP, 51820); err == nil {
			t.Fatalf("underlayMeshEndpoint = %q with only special-purpose addresses, want an error", got)
		}
	})

	t.Run("the server derivation skips special-purpose addresses", func(t *testing.T) {
		stubUnderlayIPs(t, []net.IP{net.ParseIP("192.0.0.2"), net.ParseIP("192.168.7.10")})
		got, err := serverMeshEndpoint("100.64.0.1", "100.64.0.1", serverMeshListenPort)
		if err != nil {
			t.Fatalf("serverMeshEndpoint: %v", err)
		}
		if host, _, _ := net.SplitHostPort(got); host != "192.168.7.10" {
			t.Errorf("serverMeshEndpoint = %q, want the LAN address", got)
		}
	})

	t.Run("an unreachable control plane derives nothing, even with addresses to scan", func(t *testing.T) {
		stubUnderlayIPs(t, []net.IP{net.ParseIP("10.20.30.40")})
		stubControlPlaneSourceIP(t, []net.IP{nil})
		if s, err := workerRefreshEndpoint(context.Background(), "192.168.7.10:9345", meshIP, 51820); err == nil {
			t.Fatalf("workerRefreshEndpoint = %+v with the server unreachable, want an error", s)
		}
	})

	t.Run("the route source to the server is preferred and proven", func(t *testing.T) {
		stubUnderlayIPs(t, []net.IP{net.ParseIP("10.20.30.40")})
		stubControlPlaneSourceIP(t, []net.IP{net.ParseIP("192.168.7.20")})
		s, err := workerRefreshEndpoint(context.Background(), "192.168.7.10:9345", meshIP, 51820)
		if err != nil {
			t.Fatalf("workerRefreshEndpoint: %v", err)
		}
		if s.endpoint != "192.168.7.20:51820" || !s.routeProven {
			t.Errorf("workerRefreshEndpoint = %+v, want 192.168.7.20:51820 route-proven", s)
		}
	})

	t.Run("a special-purpose route source falls back to the scan, unproven", func(t *testing.T) {
		stubUnderlayIPs(t, []net.IP{net.ParseIP("192.0.0.2"), net.ParseIP("10.20.30.40")})
		stubControlPlaneSourceIP(t, []net.IP{net.ParseIP("192.0.0.2")})
		s, err := workerRefreshEndpoint(context.Background(), "192.168.7.10:9345", meshIP, 51820)
		if err != nil {
			t.Fatalf("workerRefreshEndpoint: %v", err)
		}
		if s.endpoint != "10.20.30.40:51820" || s.routeProven {
			t.Errorf("workerRefreshEndpoint = %+v, want 10.20.30.40:51820 unproven", s)
		}
	})

	t.Run("the refresher publishes promptly when the route returns", func(t *testing.T) {
		// The worker joined on one lease, left the LAN (the server unreachable for
		// several ticks), and came back on a new lease. Nothing may be published
		// while it was away, and the new address must go out on the first tick
		// the server answers from it.
		stubUnderlayIPs(t, []net.IP{net.ParseIP("192.0.0.2"), net.ParseIP("100.90.1.1"), net.ParseIP("10.20.30.40")})
		stubControlPlaneSourceIP(t, []net.IP{nil, nil, nil, net.ParseIP("192.168.7.33"), net.ParseIP("192.168.7.33")})
		var published []string
		r := &meshEndpointRefresher{
			derive: func(ctx context.Context) (meshEndpointSighting, error) {
				return workerRefreshEndpoint(ctx, "192.168.7.10:9345", meshIP, 51820)
			},
			publish: func(_ context.Context, endpoint string) error {
				published = append(published, endpoint)
				return nil
			},
			log:       quietLogger(),
			published: "192.168.7.20:51820",
			announced: "192.168.7.20:51820",
		}
		for i := 0; i < 3; i++ {
			r.tickOnce(context.Background())
		}
		if len(published) != 0 {
			t.Fatalf("published %v while the control plane was unreachable, want nothing", published)
		}
		r.tickOnce(context.Background())
		if strings.Join(published, ",") != "192.168.7.33:51820" {
			t.Fatalf("published %v on the first reachable tick, want [192.168.7.33:51820]", published)
		}
		r.tickOnce(context.Background())
		if len(published) != 1 {
			t.Errorf("published %v, want no repeat of an unchanged endpoint", published)
		}
	})

	t.Run("an unproven change is still debounced", func(t *testing.T) {
		var published []string
		r := &meshEndpointRefresher{
			derive: func(context.Context) (meshEndpointSighting, error) {
				return meshEndpointSighting{endpoint: "10.20.30.40:51820"}, nil
			},
			publish: func(_ context.Context, endpoint string) error {
				published = append(published, endpoint)
				return nil
			},
			log:       quietLogger(),
			published: "192.168.7.20:51820",
		}
		r.tickOnce(context.Background())
		if len(published) != 0 {
			t.Fatalf("published %v on a single unproven sighting", published)
		}
		r.tickOnce(context.Background())
		if len(published) != 1 {
			t.Errorf("published %v after two sightings, want one publish", published)
		}
	})
}
