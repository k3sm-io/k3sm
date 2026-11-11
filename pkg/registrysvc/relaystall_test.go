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
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stallWindow is the progress window the stall tests shrink the relay to.
const stallWindow = 300 * time.Millisecond

var (
	bigBlob  = "/v2/team/app/blobs/sha256:" + strings.Repeat("a", 64)
	dripBlob = "/v2/team/app/blobs/sha256:" + strings.Repeat("b", 64)
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
	case f.front.conns <- srcConn{Conn: s, remote: remote}:
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
}
