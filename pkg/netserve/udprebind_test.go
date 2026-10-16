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
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var fakeClientAddr = &net.UDPAddr{IP: net.IPv4(100, 64, 0, 7), Port: 40000}

// deadConn is a UDP socket that has stopped receiving. With readErr nil it is the
// macOS SS_CANTRCVMORE socket: every read returns 0 bytes and no error, at once.
// With readErr set every read fails with it. Reads after Close fail with
// net.ErrClosed, as a real socket's do.
type deadConn struct {
	readErr error
	reads   atomic.Int64
	closed  atomic.Bool
}

func (c *deadConn) ReadFrom([]byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	c.reads.Add(1)
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	return 0, fakeClientAddr, nil
}

func (c *deadConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *deadConn) Close() error                              { c.closed.Store(true); return nil }
func (c *deadConn) LocalAddr() net.Addr                       { return &net.UDPAddr{IP: net.IPv4(10, 43, 0, 10), Port: 53} }
func (c *deadConn) SetDeadline(time.Time) error               { return nil }
func (c *deadConn) SetReadDeadline(time.Time) error           { return nil }
func (c *deadConn) SetWriteDeadline(time.Time) error          { return nil }

// queueConn is a healthy UDP socket: datagrams pushed on in are read from it, and
// every reply written to it lands on out.
type queueConn struct {
	in     chan []byte
	out    chan []byte
	done   chan struct{}
	closer sync.Once
}

func newQueueConn(depth int) *queueConn {
	return &queueConn{in: make(chan []byte, depth), out: make(chan []byte, depth), done: make(chan struct{})}
}

func (c *queueConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case q := <-c.in:
		return copy(b, q), fakeClientAddr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *queueConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case c.out <- append([]byte(nil), b...):
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *queueConn) Close() error                     { c.closer.Do(func() { close(c.done) }); return nil }
func (c *queueConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(10, 43, 0, 10), Port: 53} }
func (c *queueConn) SetDeadline(time.Time) error      { return nil }
func (c *queueConn) SetReadDeadline(time.Time) error  { return nil }
func (c *queueConn) SetWriteDeadline(time.Time) error { return nil }

// rebindBinder hands out a fixed UDP socket on every listenUDP and signals each
// bind on bound.
type rebindBinder struct {
	conn  net.PacketConn
	binds atomic.Int64
	bound chan struct{}
}

func (b *rebindBinder) ensureAlias(context.Context, netip.Addr) error { return nil }

func (b *rebindBinder) listenUDP(context.Context, netip.AddrPort) (net.PacketConn, error) {
	b.binds.Add(1)
	select {
	case b.bound <- struct{}{}:
	default:
	}
	return b.conn, nil
}

func (b *rebindBinder) listenTCP(context.Context, netip.AddrPort) (net.Listener, error) {
	return nil, errors.New("rebindBinder binds UDP only")
}

// goroutinePeak samples runtime.NumGoroutine until stop is closed and returns the
// highest count seen.
func goroutinePeak(stop <-chan struct{}) <-chan int {
	peak := make(chan int, 1)
	go func() {
		highest := runtime.NumGoroutine()
		for {
			select {
			case <-stop:
				peak <- highest
				return
			case <-time.After(200 * time.Microsecond):
				highest = max(highest, runtime.NumGoroutine())
			}
		}
	}()
	return peak
}

// TestResolverRebindsWhenTheUDPSocketStopsReceiving is the regression for the
// kube-dns VIP socket that came out of the netd fd handover unable to receive: its
// reads returned 0 bytes with no error, and the resolver treated each one as a
// query, a goroutine per read, at 800 to 1100 percent CPU and 15.9 GB of memory,
// with no UDP answer until the server was restarted. A socket that stops receiving,
// by empty reads or by a read error, must be closed and replaced through the bind
// retry within one retry interval, with the goroutine count bounded throughout, and
// the replacement must answer a cluster-local query.
func TestResolverRebindsWhenTheUDPSocketStopsReceiving(t *testing.T) {
	cases := []struct {
		name    string
		readErr error
	}{
		{"zero-byte reads with no error", nil},
		{"read error", syscall.ECONNRESET},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := runtime.NumGoroutine()
			zone := mapZone{"default/kubernetes": {IP: netip.MustParseAddr("10.43.0.1")}}
			r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, mapForwarder{}, testLogger())

			dead := &deadConn{readErr: tc.readErr}
			healthy := newQueueConn(4)
			b := &rebindBinder{conn: healthy, bound: make(chan struct{}, 1)}
			s := testServer(b)
			ap := netip.AddrPortFrom(s.dnsVIP, 53)
			rebind := func(ctx context.Context) (net.PacketConn, error) { return s.rebindDNSUDP(ctx, ap) }

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopSampling := make(chan struct{})
			peak := goroutinePeak(stopSampling)
			done := make(chan error, 1)
			go func() { done <- r.serveUDP(ctx, dead, rebind) }()

			select {
			case <-b.bound:
			case <-time.After(dnsBindRetryInitial):
				close(stopSampling)
				t.Fatalf("no re-bind within one retry interval (%s); %d reads on the dead socket", dnsBindRetryInitial, dead.reads.Load())
			}
			if !dead.closed.Load() {
				t.Errorf("the dead socket was not closed before the re-bind")
			}

			healthy.in <- buildAQuery(t, "kubernetes.default.svc.cluster.local")
			select {
			case resp := <-healthy.out:
				rcode, addrs := parseResponse(t, resp)
				if rcode != dnsmessage.RCodeSuccess || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("10.43.0.1") {
					t.Errorf("answer on the re-bound socket = %v %v, want NOERROR 10.43.0.1", rcode, addrs)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("no answer on the re-bound socket")
			}
			close(stopSampling)
			if extra := <-peak - base; extra > 32 {
				t.Errorf("goroutines peaked %d above the %d before serving; want at most 32 (one per read is the regression)", extra, base)
			}
			if n := b.binds.Load(); n != 1 {
				t.Errorf("binds = %d, want exactly 1 re-bind", n)
			}

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("serveUDP returned %v, want nil on shutdown", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("serveUDP did not return after cancellation")
			}
		})
	}
}

// TestResolverToleratesStrayEmptyDatagrams proves the dead-socket detector is a
// burst detector: a few zero-byte datagrams, which are legal on the wire, are
// skipped, the socket is kept, and the next query is answered on it.
func TestResolverToleratesStrayEmptyDatagrams(t *testing.T) {
	zone := mapZone{"default/kubernetes": {IP: netip.MustParseAddr("10.43.0.1")}}
	r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, mapForwarder{}, testLogger())
	pc := newQueueConn(udpDeadBurst + 1)
	for range udpDeadBurst - 1 {
		pc.in <- []byte{}
	}
	pc.in <- buildAQuery(t, "kubernetes.default.svc.cluster.local")

	rebound := make(chan struct{}, 1)
	rebind := func(context.Context) (net.PacketConn, error) {
		rebound <- struct{}{}
		return nil, errors.New("must not re-bind")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.serveUDP(ctx, pc, rebind) }()

	select {
	case resp := <-pc.out:
		if rcode, addrs := parseResponse(t, resp); rcode != dnsmessage.RCodeSuccess || len(addrs) != 1 {
			t.Errorf("answer = %v %v, want NOERROR with one address", rcode, addrs)
		}
	case <-rebound:
		t.Error("re-bound after fewer than udpDeadBurst empty datagrams")
	case <-time.After(5 * time.Second):
		t.Error("no answer after the empty datagrams")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serveUDP returned %v, want nil on shutdown", err)
	}
}

// blockingForwarder holds every lookup until release is closed or the query
// context ends, counting the lookups in flight.
type blockingForwarder struct {
	release  chan struct{}
	inFlight atomic.Int64
}

func (f *blockingForwarder) LookupIP4(ctx context.Context, host string) ([]netip.Addr, error) {
	f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	select {
	case <-f.release:
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestUDPQueriesBeyondTheHandlerBudgetAreDropped proves the in-flight bound: with
// udpInFlightMax handlers blocked on the upstream forwarder, further datagrams are
// dropped and counted instead of each getting a goroutine.
func TestUDPQueriesBeyondTheHandlerBudgetAreDropped(t *testing.T) {
	const extra = 10
	fwd := &blockingForwarder{release: make(chan struct{})}
	r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", mapZone{}, fwd, testLogger())
	pc := newQueueConn(udpInFlightMax + extra)
	q := buildAQuery(t, "example.com")
	for range udpInFlightMax + extra {
		pc.in <- q
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.serveUDP(ctx, pc, nil) }()

	deadline := time.Now().Add(5 * time.Second)
	for r.udpDropped.Load() < extra && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := r.udpDropped.Load(); got != extra {
		t.Errorf("dropped = %d, want %d", got, extra)
	}
	if got := fwd.inFlight.Load(); got > udpInFlightMax {
		t.Errorf("lookups in flight = %d, above the %d budget", got, udpInFlightMax)
	}
	close(fwd.release)
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serveUDP returned %v, want nil on shutdown", err)
	}
}

// fakeSyscallConn is a socket stand-in whose descriptor is never touched: rcvBufOf
// is replaced for the test.
type fakeSyscallConn struct{}

func (fakeSyscallConn) SyscallConn() (syscall.RawConn, error) { return fakeRawConn{}, nil }

type fakeRawConn struct{}

func (fakeRawConn) Control(f func(fd uintptr)) error         { f(3); return nil }
func (fakeRawConn) Read(func(fd uintptr) (done bool)) error  { return nil }
func (fakeRawConn) Write(func(fd uintptr) (done bool)) error { return nil }

// TestAdoptedSocketWithAFlushedReceiveBufferIsRefused pins the handover check: a
// socket delivered with SO_RCVBUF 0 (flushed by the kernel's unix-socket garbage
// collector while in flight) is refused so the bind retry fetches another; a
// healthy one, a non-socket, and an unreadable buffer size all pass.
func TestAdoptedSocketWithAFlushedReceiveBufferIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		conn    any
		rcvbuf  int
		readErr error
		want    error
	}{
		{"flushed receive buffer", fakeSyscallConn{}, 0, nil, errSocketCannotReceive},
		{"healthy receive buffer", fakeSyscallConn{}, 786896, nil, nil},
		{"unreadable buffer size", fakeSyscallConn{}, 0, syscall.EBADF, nil},
		{"not a socket", &deadConn{}, 0, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := rcvBufOf
			rcvBufOf = func(uintptr) (int, error) { return tc.rcvbuf, tc.readErr }
			t.Cleanup(func() { rcvBufOf = orig })
			if err := checkReceiving(tc.conn); !errors.Is(err, tc.want) {
				t.Fatalf("checkReceiving = %v, want %v", err, tc.want)
			}
		})
	}
}
