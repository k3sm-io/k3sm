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

package netserve

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

// flakyBinder fails the first failUntil bind attempts (as the netd helper does
// before its Service authorizer syncs), then succeeds — the boot race the DNS-VIP
// bind retry exists to survive.
type flakyBinder struct {
	attempts  int
	failUntil int
}

func (b *flakyBinder) ensureAlias(context.Context, netip.Addr) error { return nil }

func (b *flakyBinder) listenUDP(context.Context, netip.AddrPort) (net.PacketConn, error) {
	b.attempts++
	if b.attempts <= b.failUntil {
		return nil, errors.New("netd BindPort rejected: no service set available to authorize port 53")
	}
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func (b *flakyBinder) listenTCP(context.Context, netip.AddrPort) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func testServer(binder dnsBinder) *Server {
	return &Server{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		dnsVIP: netip.MustParseAddr("10.43.0.10"),
		binder: binder,
	}
}

// TestBindDNSVIPRetriesUntilAuthorized proves the resolver's DNS-VIP bind survives
// the transient netd-authorizer denial at boot instead of one-shot-disabling — the
// regression that left cluster DNS dark for the daemon's whole life.
func TestBindDNSVIPRetriesUntilAuthorized(t *testing.T) {
	// Shrink the schedule so the test doesn't wait real backoff seconds.
	orig := dnsBindRetrySchedule
	dnsBindRetrySchedule = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { dnsBindRetrySchedule = orig })

	b := &flakyBinder{failUntil: 2} // denied twice, authorized on the 3rd attempt
	s := testServer(b)
	ap := netip.AddrPortFrom(s.dnsVIP, 53)

	udp, tcp, err := s.bindDNSVIP(context.Background(), ap)
	if err != nil {
		t.Fatalf("bindDNSVIP after retries: %v", err)
	}
	defer udp.Close()
	defer tcp.Close()
	if b.attempts != 3 {
		t.Fatalf("expected 3 bind attempts (2 denied + 1 authorized), got %d", b.attempts)
	}
}

// TestBindDNSVIPExhaustsRetries proves a persistently-denied bind eventually gives
// up with the last error rather than looping forever.
func TestBindDNSVIPExhaustsRetries(t *testing.T) {
	orig := dnsBindRetrySchedule
	dnsBindRetrySchedule = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { dnsBindRetrySchedule = orig })

	b := &flakyBinder{failUntil: 1000} // never authorized
	s := testServer(b)
	ap := netip.AddrPortFrom(s.dnsVIP, 53)

	if _, _, err := s.bindDNSVIP(context.Background(), ap); err == nil {
		t.Fatal("expected bindDNSVIP to fail after exhausting retries")
	}
	// len(schedule)+1 attempts: the initial try plus one per scheduled backoff.
	if b.attempts != len(dnsBindRetrySchedule)+1 {
		t.Fatalf("expected %d attempts, got %d", len(dnsBindRetrySchedule)+1, b.attempts)
	}
}

// TestBindDNSVIPHonorsCancellation proves a cancelled ctx aborts the retry loop
// promptly (the daemon is shutting down; don't keep retrying a doomed bind).
func TestBindDNSVIPHonorsCancellation(t *testing.T) {
	orig := dnsBindRetrySchedule
	dnsBindRetrySchedule = []time.Duration{time.Hour} // long backoff we must not wait out
	t.Cleanup(func() { dnsBindRetrySchedule = orig })

	b := &flakyBinder{failUntil: 1000}
	s := testServer(b)
	ap := netip.AddrPortFrom(s.dnsVIP, 53)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	done := make(chan struct{})
	go func() {
		_, _, _ = s.bindDNSVIP(ctx, ap)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("bindDNSVIP did not honor ctx cancellation")
	}
}
