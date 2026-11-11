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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRelayEarlyAnswerWhileBodyIsSent: the registry answers an upload before
// its body is fully sent, so the proxy's transport is still reading the body on
// its own goroutine when the relay's handler returns and decides the read
// deadline. Under -race, that decision and the transport's reads must not
// race, and the connection must still serve the client's whole exchange.
func TestRelayEarlyAnswerWhileBodyIsSent(t *testing.T) {
	const peerA = "100.64.1.3"
	registry := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Answer at once, before reading the body: full duplex keeps the
		// server from draining the body before the answer goes out.
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex()
		w.WriteHeader(http.StatusAccepted)
		_ = rc.Flush()
	})
	f := newRelayLimitFixtureWith(t, stallLimits(), registry)
	f.tokens.statuses[tokTeam] = saStatus("team", "builder")
	for i := range 20 {
		if i > 0 {
			// The server frees the per-source slot only when it closes its
			// side of the previous round's connection.
			f.awaitSlot(t, peerA, 3*stallWindow+500*time.Millisecond)
		}
		c := f.dialTCP(t, peerA)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		const total = 4 << 10
		if _, err := fmt.Fprintf(c, "POST /v2/team/app/blobs/uploads/ HTTP/1.1\r\nHost: registry.test\r\nAuthorization: %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", basic(tokTeam), total); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(make([]byte, total/2)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("round %d: early answer: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("round %d: status = %d, want %d", i, resp.StatusCode, http.StatusAccepted)
		}
		// The rest of the body arrives after the answer, while the
		// transport may still be reading it.
		_, _ = c.Write(make([]byte, total-total/2))
		_ = c.Close()
	}
	f.awaitSlot(t, peerA, 3*stallWindow+500*time.Millisecond)
}

// readDeadlineRecorder is a ResponseWriter that records every read deadline
// set on it through http.ResponseController, and forwards write deadlines to
// conn when it is set.
type readDeadlineRecorder struct {
	header http.Header
	mu     sync.Mutex
	read   []time.Time
	conn   net.Conn
}

func (d *readDeadlineRecorder) Header() http.Header         { return d.header }
func (d *readDeadlineRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (d *readDeadlineRecorder) WriteHeader(int)             {}
func (d *readDeadlineRecorder) SetWriteDeadline(t time.Time) error {
	if d.conn != nil {
		return d.conn.SetWriteDeadline(t)
	}
	return nil
}
func (d *readDeadlineRecorder) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.read = append(d.read, t)
	return nil
}

func (d *readDeadlineRecorder) reads() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.read)
}

// closingBody is a request body that, like the server's, refuses a read after
// Close.
type closingBody struct {
	mu     sync.Mutex
	r      io.Reader
	closed bool
}

func (b *closingBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, http.ErrBodyReadAfterClose
	}
	return b.r.Read(p)
}

func (b *closingBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

// TestRelayReadAfterCloseArmsNoDeadline: a read of the request body that
// starts once the body is closed, or once the handler has returned, sets no
// read deadline. One set then would land on the connection while it serves
// its next request.
func TestRelayReadAfterCloseArmsNoDeadline(t *testing.T) {
	newReq := func() (*sourceLimiter, *readDeadlineRecorder, *http.Request) {
		s := newSourceLimiter(http.NotFoundHandler(), stallLimits(), nil)
		dw := &readDeadlineRecorder{header: http.Header{}}
		r := httptest.NewRequest(http.MethodPost, "/v2/team/app/blobs/uploads/", nil)
		r.Body = &closingBody{r: strings.NewReader(strings.Repeat("x", 100))}
		r.ContentLength = 100
		return s, dw, r
	}

	t.Run("after the body is closed", func(t *testing.T) {
		s, dw, r := newReq()
		_, r, done := s.bindProgress(dw, r)
		defer done()
		if _, err := r.Body.Read(make([]byte, 10)); err != nil {
			t.Fatalf("first read: %v", err)
		}
		if err := r.Body.Close(); err != nil {
			t.Fatal(err)
		}
		before := len(dw.reads())
		if _, err := r.Body.Read(make([]byte, 10)); !errors.Is(err, http.ErrBodyReadAfterClose) {
			t.Fatalf("read after close = %v, want %v", err, http.ErrBodyReadAfterClose)
		}
		if got := dw.reads()[before:]; len(got) != 0 {
			t.Errorf("the read after close set read deadlines %v, want none", got)
		}
	})

	t.Run("after the handler returns", func(t *testing.T) {
		s, dw, r := newReq()
		_, r, done := s.bindProgress(dw, r)
		body := r.Body
		if _, err := body.Read(make([]byte, 10)); err != nil {
			t.Fatalf("first read: %v", err)
		}
		done()
		before := len(dw.reads())
		// The server closes the body after the handler; a transport still
		// sending it upstream reads on.
		_ = r.Body.Close()
		if _, err := body.Read(make([]byte, 10)); !errors.Is(err, http.ErrBodyReadAfterClose) {
			t.Fatalf("read after close = %v, want %v", err, http.ErrBodyReadAfterClose)
		}
		if got := dw.reads()[before:]; len(got) != 0 {
			t.Errorf("the read after the handler returned set read deadlines %v, want none", got)
		}
	})
}

// failingConn is a connection whose writes, once fail is set, time out at
// once, as a write under an expired deadline does.
type failingConn struct {
	net.Conn
	fail atomic.Bool
}

func (c *failingConn) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	return c.Conn.Write(b)
}

func (c *failingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *failingConn) SetDeadline(time.Time) error      { return nil }

// TestRelayCutLogEndsWithTheResponse: the relay's write deadline stands for
// a response in progress. Once that response has ended, a write that times
// out for another cause is not logged as a stalled-connection cut, and a write
// deadline the relay did not set is not the relay's.
func TestRelayCutLogEndsWithTheResponse(t *testing.T) {
	const peerA = "100.64.1.4"

	t.Run("a refusal after the response ended logs no cut", func(t *testing.T) {
		f, rec := newCutLogFixture(t)
		var fc *failingConn
		c := f.dialTCPWith(t, peerA, func(c net.Conn) net.Conn {
			fc = &failingConn{Conn: c}
			return fc
		})
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		if _, err := fmt.Fprintf(c, "GET /v2/team/app/manifests/v1 HTTP/1.1\r\nHost: registry.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		// The response has ended. The server's refusal of the malformed
		// next request is written outside any response the relay serves,
		// and here it times out.
		// net/http sets StateIdle on the serve goroutine before it reads
		// the next request, so the refusal below always follows it.
		fc.fail.Store(true)
		if _, err := fmt.Fprintf(c, "NOT A REQUEST\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, br)
		if cuts := rec.cuts(); len(cuts) != 0 {
			t.Errorf("cut lines = %v, want none once the response has ended", cuts)
		}
	})

	// bound wires a cut watch, a limitConn over a conn whose writes time
	// out, and a request bound by the limiter, the way the relay's server
	// does, without a server.
	bound := func(t *testing.T) (*recordedLog, *limitConn, http.ResponseWriter) {
		t.Helper()
		rec := &recordedLog{}
		cw := &cutWatch{log: slog.New(rec), remote: peerA + ":1", writeProgress: stallWindow, readProgress: stallWindow}
		fc := &failingConn{}
		fc.fail.Store(true)
		lc := &limitConn{Conn: fc, release: func() {}, cut: cw}
		s := newSourceLimiter(http.NotFoundHandler(), stallLimits(), nil)
		dw := &readDeadlineRecorder{header: http.Header{}, conn: lc}
		r := httptest.NewRequest(http.MethodGet, bigBlob, nil)
		r = r.WithContext(context.WithValue(r.Context(), relayConnKey{}, &relayConn{cut: cw}))
		w, _, done := s.bindProgress(dw, r)
		t.Cleanup(done)
		return rec, lc, w
	}

	t.Run("a write under a deadline the relay did not set logs no cut", func(t *testing.T) {
		rec, lc, w := bound(t)
		_, _ = w.Write([]byte("part"))
		// The TLS close alert sets its own write deadline.
		_ = lc.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = lc.Write([]byte("alert"))
		if cuts := rec.cuts(); len(cuts) != 0 {
			t.Errorf("cut lines = %v, want none for a write under another deadline", cuts)
		}
	})

	t.Run("a write under the relay's deadline still logs its cut", func(t *testing.T) {
		rec, lc, w := bound(t)
		_, _ = w.Write([]byte("part"))
		_, _ = lc.Write([]byte("part"))
		cuts := rec.cuts()
		if len(cuts) != 1 || cuts[0]["direction"] != cutWrite {
			t.Fatalf("cut lines = %v, want exactly one with direction %q", cuts, cutWrite)
		}
	})
}
