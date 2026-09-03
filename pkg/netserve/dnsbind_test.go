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

// fakeBindClock replaces the retry sleep so the loop can be driven through hundreds
// of attempts instantly, and records every backoff it was asked to wait — the only
// place the schedule's shape is observable.
type fakeBindClock struct {
	waits []time.Duration
}

func (c *fakeBindClock) wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.waits = append(c.waits, d)
	return nil
}

// useFakeBindClock installs the fake for the duration of a test. No unit test here
// spends real time on a backoff.
func useFakeBindClock(t *testing.T) *fakeBindClock {
	t.Helper()
	c := &fakeBindClock{}
	orig := dnsBindWait
	dnsBindWait = c.wait
	t.Cleanup(func() { dnsBindWait = orig })
	return c
}

// TestBindDNSVIPRetriesUntilAuthorized proves the resolver's DNS-VIP bind survives
// the transient netd-authorizer denial at boot instead of one-shot-disabling — the
// regression that left cluster DNS dark for the daemon's whole life.
func TestBindDNSVIPRetriesUntilAuthorized(t *testing.T) {
	useFakeBindClock(t)

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

// TestBindDNSVIPRetriesIndefinitely is the regression for the permanent give-up.
// The old schedule stopped after ~2.5 minutes on the assumption that the only thing
// being waited for was netd's authorizer syncing at boot — so a netd outage longer
// than that (a reinstall that left the helper down; a helper restart coinciding with
// the server's) killed this node's cluster DNS for the process's whole life. The
// bind must keep trying, at a capped interval, for as long as the daemon runs.
func TestBindDNSVIPRetriesIndefinitely(t *testing.T) {
	c := useFakeBindClock(t)

	// Far more failures than any bounded schedule would have tolerated.
	const denials = 500
	b := &flakyBinder{failUntil: denials}
	s := testServer(b)
	ap := netip.AddrPortFrom(s.dnsVIP, 53)

	udp, tcp, err := s.bindDNSVIP(context.Background(), ap)
	if err != nil {
		t.Fatalf("bindDNSVIP must not give up: %v", err)
	}
	defer udp.Close()
	defer tcp.Close()
	if b.attempts != denials+1 {
		t.Fatalf("bind attempts = %d, want %d (every denial retried, then the success)", b.attempts, denials+1)
	}
	if len(c.waits) != denials {
		t.Fatalf("backoff waits = %d, want %d (one per denial)", len(c.waits), denials)
	}
	// The backoff grows and then holds at the ceiling — it never runs away, and it
	// never collapses to a hot loop.
	if c.waits[0] != dnsBindRetryInitial {
		t.Errorf("first backoff = %s, want %s", c.waits[0], dnsBindRetryInitial)
	}
	for i, d := range c.waits {
		if d > dnsBindRetryMax {
			t.Fatalf("backoff %d = %s, above the %s ceiling", i, d, dnsBindRetryMax)
		}
		if i > 0 && d < c.waits[i-1] {
			t.Fatalf("backoff %d = %s went backwards from %s", i, d, c.waits[i-1])
		}
	}
	if last := c.waits[len(c.waits)-1]; last != dnsBindRetryMax {
		t.Errorf("steady-state backoff = %s, want the %s ceiling", last, dnsBindRetryMax)
	}
}

// TestBindDNSVIPHonorsCancellation proves a cancelled ctx aborts the retry loop
// promptly (the daemon is shutting down; don't keep retrying a doomed bind).
func TestBindDNSVIPHonorsCancellation(t *testing.T) {
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
