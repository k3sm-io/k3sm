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
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// stallWindow is the progress window the stall tests shrink the relay to.
const stallWindow = 300 * time.Millisecond

var (
	bigBlob  = "/v2/team/app/blobs/sha256:" + strings.Repeat("a", 64)
	dripBlob = "/v2/team/app/blobs/sha256:" + strings.Repeat("b", 64)
	tailBlob = "/v2/team/app/blobs/sha256:" + strings.Repeat("c", 64)
)

// dripLen is the length of the blob the registry sends one byte at a time.
const dripLen = 20

// dripGap is how long the test holds each dripped byte before reading it.
const dripGap = 100 * time.Millisecond

// bigLen is the length of bigBlob: far more than every buffer between the
// registry and the peer holds, so a peer that stops reading stalls a write.
const bigLen = 1 << 20

// stallRegistry serves bigBlob and dripBlob. Each sends its headers at once
// and then waits on drip before any body: one value releases all of bigBlob,
// and each value releases one byte of dripBlob. Sending the headers first lets
// the proxy's header flush, which shares a lock with its body writes, finish
// before the first body write can block on a peer that is not reading; a
// goroutine waiting on that lock would stop the bubble's clock.
func stallRegistry(drip <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		next := func() bool {
			select {
			case <-drip:
				return true
			case <-r.Context().Done():
				return false
			}
		}
		switch r.URL.Path {
		case bigBlob:
			w.Header().Set("Content-Length", strconv.Itoa(bigLen))
			w.WriteHeader(http.StatusOK)
			_ = rc.Flush()
			if !next() {
				return
			}
			chunk := make([]byte, 32<<10)
			for range bigLen / len(chunk) {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		case dripBlob:
			w.Header().Set("Content-Length", strconv.Itoa(dripLen))
			w.WriteHeader(http.StatusOK)
			_ = rc.Flush()
			for range dripLen {
				if !next() {
					return
				}
				if _, err := w.Write([]byte{'x'}); err != nil {
					return
				}
				_ = rc.Flush()
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
}

// dial opens an in-memory connection and hands its server end to the relay as
// a connection from src. A net.Pipe buffers nothing, so a peer that stops
// reading blocks the relay's next write at once, and inside a synctest bubble
// only the relay's own deadline, on the bubble's clock, can end that write.
func (f *relayLimitFixture) dial(t *testing.T, src string) net.Conn {
	t.Helper()
	return f.dialWith(t, src, func(c net.Conn) net.Conn { return c })
}

// dialWith is dial with the relay's end of the connection passed through wrap
// first, so the test owns the exact conn the relay sees.
func (f *relayLimitFixture) dialWith(t *testing.T, src string, wrap func(net.Conn) net.Conn) net.Conn {
	t.Helper()
	c, s := net.Pipe()
	remote := net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(src), uint16(40000+srcPort.Add(1)%20000)))
	bound := time.NewTimer(stallWindow)
	defer bound.Stop()
	select {
	case f.front.conns <- srcConn{Conn: wrap(s), remote: remote}:
	case <-bound.C:
		t.Fatal("the relay did not accept the connection")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// tryGet sends one GET from src on a fresh connection and reports its status,
// or the error that ended it. A connection past the source's share is closed
// by the relay on accept, which fails the write or the read. A served probe
// closes its own end and waits for the bubble to settle, so the relay has
// closed the probe's connection, and freed its slot, when tryGet returns. It
// must run in a synctest bubble.
func (f *relayLimitFixture) tryGet(t *testing.T, src, target string) (int, error) {
	t.Helper()
	c := f.dial(t, src)
	defer synctest.Wait()
	defer c.Close()
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\n\r\n", target); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// slotStep is how far awaitSlot moves the bubble's clock between attempts.
const slotStep = stallWindow / 10

// awaitSlot tries a fresh GET from src, moving the bubble's clock a tenth of
// a window between attempts, until one is served, and returns how long that
// took on the bubble's clock. It fails the test once within has passed with
// none served: the stalled connection still holds the source's only slot.
func (f *relayLimitFixture) awaitSlot(t *testing.T, src string, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	var last error
	for {
		code, err := f.tryGet(t, src, "/v2/team/app/manifests/v1")
		if err == nil && code == http.StatusOK {
			return time.Since(start)
		}
		last = fmt.Errorf("status %d, err %v", code, err)
		if time.Since(start) >= within {
			t.Fatalf("no second connection from %s served within %v of the stall (last: %v): the stalled connection still holds the source's only slot", src, within, last)
		}
		advance(t, slotStep)
	}
}

// assertSlotHeld fails the test when a second connection from src is served
// while the first is stalled, which would leave the slot tests proving
// nothing.
func (f *relayLimitFixture) assertSlotHeld(t *testing.T, src string) {
	t.Helper()
	if code, err := f.tryGet(t, src, "/v2/team/app/manifests/v1"); err == nil && code == http.StatusOK {
		t.Fatalf("a second connection from %s was served while the first is stalled: the source's share is not one connection", src)
	}
}

// drainPeer reads c until it ends, in the background, as a peer that has stopped
// sending but still reads would.
func drainPeer(c net.Conn) { go func() { _, _ = io.Copy(io.Discard, c) }() }

// stallGet sends a GET for bigBlob from src, reads its headers, releases the
// body on drip, reads its first bytes, and then stops reading without
// closing. It returns the connection and the reader holding what the peer has
// buffered.
func (f *relayLimitFixture) stallGet(t *testing.T, src string, drip chan<- struct{}) (net.Conn, *bufio.Reader) {
	t.Helper()
	c := f.dial(t, src)
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\n\r\n", bigBlob); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReaderSize(c, 64)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("stalled GET headers: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stalled GET = %d, want 200", resp.StatusCode)
	}
	synctest.Wait()
	drip <- struct{}{}
	if _, err := io.ReadFull(resp.Body, make([]byte, 16)); err != nil {
		t.Fatalf("stalled GET first bytes: %v", err)
	}
	return c, br
}

// dripGet sends a GET for dripBlob from src, reads its headers, and reads the
// body a byte at a time: the test releases each byte on drip, holds it
// dripGap unread with the relay's write of it in progress, then reads it. It
// returns the bytes read and how long that took on the bubble's clock.
func (f *relayLimitFixture) dripGet(t *testing.T, src string, drip chan<- struct{}) (int, time.Duration) {
	t.Helper()
	c := f.dial(t, src)
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\n\r\n", dripBlob); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("slow GET headers: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("slow GET = %d, want 200", resp.StatusCode)
	}
	synctest.Wait()
	got := 0
	one := make([]byte, 1)
	for range dripLen {
		drip <- struct{}{}
		advance(t, dripGap)
		n, err := io.ReadFull(resp.Body, one)
		got += n
		if err != nil {
			t.Fatalf("slow GET body after %d bytes: %v", got, err)
		}
	}
	if n, err := resp.Body.Read(one); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("slow GET after %d bytes = %d more, %v; want the end of the body", got, n, err)
	}
	return got, time.Since(start)
}

// relayBubble runs f in a synctest bubble. Its last cleanup, after every
// fixture's, moves the bubble's clock past the pause net/http takes before it
// closes a connection it answered with Connection: close, so that goroutine
// ends inside the bubble rather than outliving the test.
func relayBubble(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		t.Cleanup(func() { advance(t, time.Second) })
		f(t)
	})
}

func stallLimits() relayLimits {
	lim := defaultRelayLimits
	lim.maxConns = 4
	lim.maxConnsPerSource = 1
	lim.writeProgress = stallWindow
	lim.readProgress = stallWindow
	return lim
}

// TestRelayStalledReaderFreesItsSlot is the gate for a stalled relay
// connection: a peer that opens a blob GET and stops reading loses its
// connection, and its per-source slot, within a few progress windows, while a
// peer that is slow but keeps reading is served in full however long that
// takes. Every case runs in a synctest bubble over in-memory connections, so
// the windows pass on the bubble's clock.
func TestRelayStalledReaderFreesItsSlot(t *testing.T) {
	const peerA = "100.64.1.1"
	within := 3 * stallWindow

	t.Run("a stalled reader is cut and its slot freed", func(t *testing.T) {
		relayBubble(t, func(t *testing.T) {
			drip := make(chan struct{})
			f := newRelayLimitFixtureWith(t, stallLimits(), stallRegistry(drip))
			c, br := f.stallGet(t, peerA, drip)
			// Stop reading, without closing.
			f.assertSlotHeld(t, peerA)
			f.awaitSlot(t, peerA, within)
			// The stalled connection was closed by the relay: what the
			// peer buffered drains, then the stream ends.
			_, err := io.Copy(io.Discard, br)
			if err != nil {
				t.Errorf("stalled connection: drain = %v, want it closed by the relay", err)
			}
			_ = c.Close()
		})
	})

	t.Run("slow but moving reader is not cut", func(t *testing.T) {
		relayBubble(t, func(t *testing.T) {
			drip := make(chan struct{})
			f := newRelayLimitFixtureWith(t, stallLimits(), stallRegistry(drip))
			got, el := f.dripGet(t, peerA, drip)
			if got != dripLen {
				t.Errorf("slow GET body = %d bytes, want %d", got, dripLen)
			}
			if el < 3*stallWindow {
				t.Errorf("slow GET took %v, want longer than three windows for the test to mean anything", el)
			}
		})
	})

	t.Run("a request body that never arrives is cut and its slot freed", func(t *testing.T) {
		relayBubble(t, func(t *testing.T) {
			f := newRelayLimitFixtureWith(t, stallLimits(), stallRegistry(nil))
			c := f.dial(t, peerA)
			if _, err := fmt.Fprintf(c, "POST /v2/team/app/blobs/uploads/ HTTP/1.1\r\nHost: registry.test\r\nContent-Length: 10\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			// Send no body and never close; read whatever comes back.
			drainPeer(c)
			f.assertSlotHeld(t, peerA)
			f.awaitSlot(t, peerA, within)
		})
	})

	// The response is chunked because the gate's proxy flushes each body
	// write inside the handler (gate.go, FlushInterval -1): a Content-Length
	// body is all out before done runs, and only the chunk terminator is left
	// for the server's own final flush.
	t.Run("the final flush is cut when the reader has stopped", func(t *testing.T) {
		relayBubble(t, func(t *testing.T) {
			var g *gateConn
			var returned atomic.Bool
			var returnedAt time.Time
			release := make(chan struct{})
			registry := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tailBlob {
					w.WriteHeader(http.StatusOK)
					return
				}
				defer func() {
					returnedAt = time.Now()
					returned.Store(true)
				}()
				g.engage()
				_, _ = w.Write(make([]byte, 1000))
				_ = http.NewResponseController(w).Flush()
				<-release
			})
			f := newRelayLimitFixtureWith(t, stallLimits(), registry)
			c := f.dialWith(t, peerA, func(c net.Conn) net.Conn {
				g = newGateConn(c)
				return g
			})
			if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\n\r\n", tailBlob); err != nil {
				t.Fatal(err)
			}
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
			if err != nil {
				t.Fatalf("tail GET headers: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("tail GET = %d, want 200", resp.StatusCode)
			}
			if _, err := io.ReadFull(resp.Body, make([]byte, 1000)); err != nil {
				t.Fatalf("tail GET body: %v", err)
			}
			// The registry holds the response open half a window after its
			// last write, then returns; the peer reads no more.
			advance(t, stallWindow/2)
			close(release)
			var h gateHold
			bound := time.NewTimer(within)
			select {
			case h = <-g.held:
				bound.Stop()
			case <-bound.C:
				t.Fatal("the relay never wrote the chunk terminator")
			}
			if !returned.Load() {
				t.Fatal("the relay wrote the chunk terminator before the registry's handler returned")
			}
			if h.deadline.IsZero() {
				t.Fatal("the final flush ran with no write deadline: a peer that stops reading there holds its slot for good")
			}
			const eps = 50 * time.Millisecond
			if want := returnedAt.Add(stallWindow - eps); h.deadline.Before(want) {
				t.Errorf("the final flush's write deadline is %v, want no earlier than %v (handler return plus a window)", h.deadline, want)
			}
			f.awaitSlot(t, peerA, within)
			if n, err := resp.Body.Read(make([]byte, 1)); n != 0 || errors.Is(err, io.EOF) || err == nil {
				t.Errorf("tail GET after the body = %d bytes, %v; want the stream cut before the chunk terminator", n, err)
			}
		})
	})

	// The server flushes the response's buffered tail after the handler
	// returns, so a peer that stops reading there is bounded only if done
	// leaves the write deadline armed. The next request clears it before its
	// handler runs.
	t.Run("a reader that stops at the tail is cut", func(t *testing.T) {
		s := newSourceLimiter(http.NotFoundHandler(), stallLimits(), nil)
		dw := &deadlineRecorder{header: http.Header{}}
		r := httptest.NewRequest(http.MethodGet, bigBlob, nil)
		w, _, done := s.bindProgress(dw, r)
		_, _ = w.Write([]byte("tail"))
		before := time.Now()
		done()
		if len(dw.write) == 0 {
			t.Fatal("done set no write deadline")
		}
		last := dw.write[len(dw.write)-1]
		if last.IsZero() {
			t.Fatal("done cleared the write deadline: the server's final flush is unbounded")
		}
		if last.Before(before) || last.After(before.Add(stallWindow+time.Second)) {
			t.Errorf("done armed the write deadline at %v, want about one window after %v", last, before)
		}
		dw.write = nil
		_, _, done = s.bindProgress(dw, httptest.NewRequest(http.MethodGet, bigBlob, nil))
		defer done()
		if len(dw.write) == 0 || !dw.write[0].IsZero() {
			t.Fatalf("the next request's bind set write deadlines %v, want it to clear the stale one first", dw.write)
		}
	})
}

// gateConn is the relay's end of a connection that, once engaged, records the
// write deadline in force when the chunk terminator is written and reports it
// on held. The write itself goes through to the pipe, which blocks while the
// peer is not reading, so only that deadline ends it.
type gateConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	engaged  bool
	held     chan gateHold
}

// gateHold is what gateConn saw at the chunk terminator's Write.
type gateHold struct {
	deadline time.Time
}

func newGateConn(c net.Conn) *gateConn { return &gateConn{Conn: c, held: make(chan gateHold, 1)} }

func (g *gateConn) engage() {
	g.mu.Lock()
	g.engaged = true
	g.mu.Unlock()
}

func (g *gateConn) SetWriteDeadline(t time.Time) error {
	g.mu.Lock()
	g.deadline = t
	g.mu.Unlock()
	return g.Conn.SetWriteDeadline(t)
}

func (g *gateConn) Write(b []byte) (int, error) {
	g.mu.Lock()
	if g.engaged && string(b) == "0\r\n\r\n" {
		select {
		case g.held <- gateHold{deadline: g.deadline}:
		default:
		}
	}
	g.mu.Unlock()
	return g.Conn.Write(b)
}

// deadlineRecorder is a ResponseWriter that records the write deadlines set on
// it through http.ResponseController.
type deadlineRecorder struct {
	header http.Header
	write  []time.Time
}

func (d *deadlineRecorder) Header() http.Header         { return d.header }
func (d *deadlineRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (d *deadlineRecorder) WriteHeader(int)             {}
func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.write = append(d.write, t)
	return nil
}
func (d *deadlineRecorder) SetReadDeadline(time.Time) error { return nil }
