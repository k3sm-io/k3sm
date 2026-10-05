//go:build integration

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

package pairing

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestRealSocketReportsTheInterfaceAsTheZone is the premise TestPairTrustDecision
// fakes: on Darwin, the LOCAL address net/http reports for an accepted link-local
// TCP connection carries the receiving interface's NAME as its zone. It opens a
// listener on the link-local address of the first up, non-loopback interface that
// has one, dials it, and records the zone the server saw. The S3 spike rung
// records the same value for a Thunderbolt port (the golden); the M17-lab ladder
// re-asserts it on the cable by naming the Thunderbolt interface in
// K3SM_ZONE_IFACE. It skips when this Mac has no such interface.
func TestRealSocketReportsTheInterfaceAsTheZone(t *testing.T) {
	iface, addr, ok := firstLinkLocal(t, os.Getenv("K3SM_ZONE_IFACE"))
	if !ok {
		t.Skip("no up, non-loopback interface with a link-local IPv6 address on this Mac")
	}
	ln, err := net.Listen("tcp6", net.JoinHostPort(addr.WithZone(iface).String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on %s%%%s: %v", addr, iface, err)
	}
	seen := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		local := ""
		if la != nil {
			local = la.String()
		}
		seen <- local
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The URL names no address: a zoned literal in a URL needs %25-escaping, and
	// the dial target is the listener's own address either way.
	target := ln.Addr().String()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp6", target)
	}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://link-local/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("dial the link-local listener: %v", err)
	}
	_ = resp.Body.Close()
	local := <-seen
	host, _, err := net.SplitHostPort(local)
	if err != nil {
		t.Fatalf("local address %q: %v", local, err)
	}
	got, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("local address %q: %v", local, err)
	}
	t.Logf("the zone net/http reported for an accepted link-local connection on %s: %q (local %s)", iface, got.Zone(), local)
	if got.Zone() != iface {
		t.Fatalf("zone = %q, want the interface name %q — the pairing trust decision reads the interface from this zone", got.Zone(), iface)
	}
	d := Decide(got, got, map[string]int{iface: 1})
	if d.Refused != "" || d.Iface != iface {
		t.Fatalf("Decide over the real zone = %+v, want trusted on %s", d, iface)
	}
}

// firstLinkLocal returns the first up, non-loopback interface with a link-local
// IPv6 address, or the named one when want is set.
func firstLinkLocal(t *testing.T, want string) (string, netip.Addr, bool) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("list interfaces: %v", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if want != "" && ifi.Name != want {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if ok && ip.Is6() && ip.IsLinkLocalUnicast() {
				return ifi.Name, ip, true
			}
		}
	}
	return "", netip.Addr{}, false
}
