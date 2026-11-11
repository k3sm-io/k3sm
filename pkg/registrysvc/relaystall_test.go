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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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

// stallRegistry serves bigBlob as far more bytes than any socket buffers, and
// dripBlob one byte per 100 ms.
func stallRegistry() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case bigBlob:
			w.Header().Set("Content-Length", strconv.Itoa(256<<20))
			w.WriteHeader(http.StatusOK)
			chunk := make([]byte, 32<<10)
			for range (256 << 20) / len(chunk) {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		case dripBlob:
			w.Header().Set("Content-Length", strconv.Itoa(dripLen))
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			for range dripLen {
				if _, err := w.Write([]byte{'x'}); err != nil {
					return
				}
				_ = rc.Flush()
				time.Sleep(100 * time.Millisecond)
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
}

// dialTCP opens a real loopback TCP connection and hands its server end to the
// relay as a connection from src, so the kernel's socket buffers sit between
// the relay and the peer as they do in production.
func (f *relayLimitFixture) dialTCP(t *testing.T, src string) net.Conn {
	t.Helper()
	return f.dialTCPWith(t, src, func(c net.Conn) net.Conn { return c })
}

// dialTCPWith is dialTCP with the relay's end of the connection passed through
// wrap first, so the test owns the exact conn the relay sees.
func (f *relayLimitFixture) dialTCPWith(t *testing.T, src string, wrap func(net.Conn) net.Conn) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	remote := net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(src), uint16(40000+srcPort.Add(1)%20000)))
	select {
	case f.front.conns <- srcConn{Conn: wrap(s), remote: remote}:
	case <-time.After(3 * time.Second):
		t.Fatal("the relay did not accept the connection")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// tryGet sends one GET from src on a fresh connection and reports its status,
// or the error that ended it.
func (f *relayLimitFixture) tryGet(t *testing.T, src, target string) (int, error) {
	t.Helper()
	c := f.dialTCP(t, src)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\n\r\n", target); err != nil {
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

// awaitSlot polls a fresh GET from src until one is served, and fails the test
// when none is within budget.
func (f *relayLimitFixture) awaitSlot(t *testing.T, src string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		code, err := f.tryGet(t, src, "/v2/team/app/manifests/v1")
		if err == nil && code == http.StatusOK {
			return
		}
		last = fmt.Errorf("status %d, err %v", code, err)
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no second connection from %s served within %v of the stall (last: %v): the stalled connection still holds the source's only slot", src, budget, last)
}

func stallLimits() relayLimits {
	lim := defaultRelayLimits
	lim.maxConns = 4
	lim.maxConnsPerSource = 1
	lim.writeProgress = stallWindow
	lim.readProgress = stallWindow
	return lim
}

// TestRelayStalledReaderFreesItsSlot is the gate for B1564: a peer that opens a
// blob GET and stops reading loses its connection, and its per-source slot,
// within a few progress windows, while a peer that is slow but keeps reading
// is served in full however long that takes.
func TestRelayStalledReaderFreesItsSlot(t *testing.T) {
	const peerA = "100.64.1.1"
	budget := 3*stallWindow + 500*time.Millisecond

	t.Run("a stalled reader is cut and its slot freed", func(t *testing.T) {
		f := newRelayLimitFixtureWith(t, stallLimits(), stallRegistry())
		c := f.dialTCP(t, peerA)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
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
		if _, err := io.ReadFull(resp.Body, make([]byte, 16)); err != nil {
			t.Fatalf("stalled GET first bytes: %v", err)
		}
		// Stop reading, without closing.
		f.awaitSlot(t, peerA, budget)
		// The stalled connection was closed by the relay: what the kernel
		// buffered drains, then the stream ends rather than timing out.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.Copy(io.Discard, br)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("stalled connection: drain timed out, want it closed by the relay")
		}
	})

	t.Run("slow but moving reader is not cut", func(t *testing.T) {
		f := newRelayLimitFixtureWith(t, stallLimits(), stallRegistry())
		c := f.dialTCP(t, peerA)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\n\r\n", dripBlob); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
		if err != nil {
			t.Fatalf("slow GET headers: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("slow GET = %d, want 200", resp.StatusCode)
		}
		start := time.Now()
		got := 0
		one := make([]byte, 1)
		for {
			n, err := resp.Body.Read(one)
			got += n
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("slow GET body after %d bytes: %v", got, err)
				}
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if got != dripLen {
			t.Errorf("slow GET body = %d bytes, want %d", got, dripLen)
		}
		if el := time.Since(start); el < 3*stallWindow {
			t.Errorf("slow GET took %v, want longer than three windows for the test to mean anything", el)
		}
	})

	t.Run("a request body that never arrives is cut and its slot freed", func(t *testing.T) {
		f := newRelayLimitFixtureWith(t, stallLimits(), stallRegistry())
		c := f.dialTCP(t, peerA)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(c, "POST /v2/team/app/blobs/uploads/ HTTP/1.1\r\nHost: registry.test\r\nContent-Length: 10\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		// Send no body and never close.
		f.awaitSlot(t, peerA, budget)
	})

	// The response is chunked because the gate's proxy flushes each body
	// write inside the handler (gate.go, FlushInterval -1): a Content-Length
	// body is all out before done runs, and only the chunk terminator is left
	// for the server's own final flush.
	t.Run("the final flush is cut when the reader has stopped", func(t *testing.T) {
		var g *gateConn
		var returned atomic.Bool
		var returnedAt time.Time
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
			time.Sleep(stallWindow / 2)
		})
		f := newRelayLimitFixtureWith(t, stallLimits(), registry)
		c := f.dialTCPWith(t, peerA, func(c net.Conn) net.Conn {
			g = newGateConn(c)
			return g
		})
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\n\r\n", tailBlob); err != nil {
			t.Fatal(err)
		}
		var h gateHold
		select {
		case h = <-g.held:
		case <-time.After(5 * time.Second):
			t.Fatal("the relay never wrote the response")
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
		f.awaitSlot(t, peerA, budget)
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
		if err != nil {
			t.Fatalf("tail GET headers: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tail GET = %d, want 200", resp.StatusCode)
		}
		if _, err := io.ReadFull(resp.Body, make([]byte, 1000)); err != nil {
			t.Fatalf("tail GET body: %v", err)
		}
		if n, err := resp.Body.Read(make([]byte, 1)); n != 0 || errors.Is(err, io.EOF) || err == nil {
			t.Errorf("tail GET after the body = %d bytes, %v; want the stream cut before the chunk terminator", n, err)
		}
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

// gateConn is the relay's end of a connection that, once engaged, holds the
// chunk terminator's Write until the write deadline in force passes, as a peer
// that has stopped reading would, and records what it saw. Every other Write
// goes through. A 3 s safety release bounds
// the hold when no deadline is set, so a regression fails instead of hanging.
type gateConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	engaged  bool
	held     chan gateHold
}

// gateHold is what gateConn saw at the Write it held.
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
	if !g.engaged || string(b) != "0\r\n\r\n" {
		g.mu.Unlock()
		return g.Conn.Write(b)
	}
	h := gateHold{deadline: g.deadline}
	g.mu.Unlock()
	select {
	case g.held <- h:
	default:
	}
	wait := 3 * time.Second
	if !h.deadline.IsZero() {
		wait = min(wait, time.Until(h.deadline))
	}
	time.Sleep(wait)
	return 0, os.ErrDeadlineExceeded
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
