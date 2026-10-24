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
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
)

// srcListener is an in-memory listener whose connections come from a chosen
// remote address, so per-source limits are testable without configuring a
// second loopback address on the host.
type srcListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newSrcListener() *srcListener {
	return &srcListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *srcListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *srcListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *srcListener) Addr() net.Addr { return memAddr{} }

// srcConn is the server end of a pipe, reporting remote as its peer.
type srcConn struct {
	net.Conn
	remote net.Addr
}

func (c srcConn) RemoteAddr() net.Addr { return c.remote }

var srcPort atomic.Int32

// dial opens a connection from src, or fails when the relay does not accept it
// within wait.
func (l *srcListener) dial(src string, wait time.Duration) (net.Conn, error) {
	c, s := net.Pipe()
	remote := net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(src), uint16(40000+srcPort.Add(1)%20000)))
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case l.conns <- srcConn{Conn: s, remote: remote}:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-t.C:
		_ = c.Close()
		_ = s.Close()
		return nil, errors.New("the relay did not accept the connection")
	}
}

// relayLimitFixture is a relay built by newRelay, served by its own accept on a
// srcListener, in front of a socket fake registry and fake apiserver clients.
type relayLimitFixture struct {
	zot    *fakeZot
	tokens *fakeTokens
	front  *srcListener
}

func newRelayLimitFixture(t *testing.T) *relayLimitFixture {
	t.Helper()
	z, zaddr := socketZot(t)
	f := &relayLimitFixture{
		zot:    z,
		tokens: &fakeTokens{statuses: map[string]authnv1.TokenReviewStatus{}},
		front:  newSrcListener(),
	}
	auth := GateAuth{
		Tokens: f.tokens,
		Access: &fakeAccess{allow: func(sar *authzv1.SubjectAccessReview) bool {
			return sar.Spec.User == "system:serviceaccount:team:builder"
		}},
		Namespaces: &fakeNamespaces{labels: map[string]map[string]string{"team": {PushLabel: "team"}}},
	}
	r := newRelay(portOf(t, zaddr), nil, quietLogger(), auth, gateCred)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.accept(ctx, f.front)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = f.front.Close()
	})
	return f
}

// do sends one request from src on a fresh connection.
func (f *relayLimitFixture) do(t *testing.T, src, method, target string, headers map[string]string, body string) rawResponse {
	t.Helper()
	c, err := f.front.dial(src, 3*time.Second)
	if err != nil {
		t.Fatalf("%s from %s: %v", method, src, err)
	}
	return rawOn(t, c, method, target, headers, body)
}

// TestRelayLimitsArePerSource is B920's gate: one remote address at any of the
// relay's limits leaves another address's read and push served. The shared
// connection cap cannot be filled by one address, the shared TokenReview budget
// cannot be drained by one address's garbage tokens, and a keep-alive
// connection is turned over rather than held for good.
func TestRelayLimitsArePerSource(t *testing.T) {
	const peerA, peerB = "100.64.1.1", "100.64.2.1"

	t.Run("one source holding every connection leaves another source served", func(t *testing.T) {
		f := newRelayLimitFixture(t)
		f.tokens.statuses[tokTeam] = saStatus("team", "builder")
		var held []net.Conn
		t.Cleanup(func() {
			for _, c := range held {
				_ = c.Close()
			}
		})
		// As many idle connections as the whole relay allows, from one peer.
		for i := 0; i < relayMaxConns; i++ {
			c, err := f.front.dial(peerA, 3*time.Second)
			if err != nil {
				t.Fatalf("peer A connection %d: %v", i, err)
			}
			held = append(held, c)
		}
		// The last of them is past the peer's share, so the relay closed it.
		last := held[len(held)-1]
		_ = last.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := last.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Errorf("a connection past one source's share: read err = %v, want it closed (EOF)", err)
		}
		if r := f.do(t, peerB, "GET", "/v2/team/app/manifests/v1", nil, ""); r.status != 200 {
			t.Errorf("peer B read = %d, want 200", r.status)
		}
		if r := f.do(t, peerB, "POST", "/v2/team/app/blobs/uploads/", map[string]string{"Authorization": basic(tokTeam)}, ""); r.status != 202 {
			t.Errorf("peer B push = %d, want 202", r.status)
		}
	})

	t.Run("one source flooding garbage tokens leaves another source's push served", func(t *testing.T) {
		f := newRelayLimitFixture(t)
		var good []string
		for i := range 3 {
			tok := mkToken(fmt.Sprintf("builder-%d", i), testEpoch.Add(time.Hour))
			f.tokens.statuses[tok] = saStatus("team", "builder")
			good = append(good, tok)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var n atomic.Int64
		for range 8 {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					c, err := f.front.dial(peerA, time.Second)
					if err != nil {
						continue
					}
					// Well-shaped, never seen before, so never cached: every
					// one the gate takes costs a TokenReview.
					tok := mkToken(fmt.Sprintf("garbage-%d", n.Add(1)), testEpoch.Add(time.Hour))
					floodOn(c, "POST /v2/team/app/blobs/uploads/ HTTP/1.1\r\nHost: r\r\nConnection: close\r\nContent-Length: 0\r\nAuthorization: "+basic(tok)+"\r\n\r\n")
				}
			})
		}
		defer func() { close(stop); wg.Wait() }()
		deadline := time.Now().Add(10 * time.Second)
		for f.tokens.count() < int(tokenReviewBurst/2) {
			if time.Now().After(deadline) {
				t.Fatalf("the flood reached only %d token reviews", f.tokens.count())
			}
			time.Sleep(5 * time.Millisecond)
		}
		for i, tok := range good {
			r := f.do(t, peerB, "POST", "/v2/team/app/blobs/uploads/", map[string]string{"Authorization": basic(tok)}, "")
			if r.status != 202 {
				t.Errorf("peer B push %d during peer A's flood = %d %s, want 202", i, r.status, r.body)
			}
		}
	})

	t.Run("a keep-alive connection is turned over", func(t *testing.T) {
		f := newRelayLimitFixture(t)
		c, err := f.front.dial(peerA, 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for i := 1; i <= 1000; i++ {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(c, "GET /v2/team/app/manifests/v1 HTTP/1.1\r\nHost: r\r\n\r\n"); err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
			if err != nil {
				t.Fatalf("response %d: %v", i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("response %d = %d, want 200", i, resp.StatusCode)
			}
			if resp.Close {
				return
			}
		}
		t.Error("the relay kept one connection open for 1000 requests")
	})
}

// floodOn writes req on c, reads whatever comes back, and closes c.
func floodOn(c net.Conn, req string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, c)
}

// TestSourceLimiter pins the limiter's arithmetic on a fake clock: the
// connection age bound, a refusal with the wait it would have needed, the
// independence of two sources, and the bounded table.
func TestSourceLimiter(t *testing.T) {
	lim := relayLimits{
		requestRate: 10, requestBurst: 2, requestWait: 100 * time.Millisecond,
		writeRate: 1, writeBurst: 1, writeWait: 0,
		maxRequestsPerConn: 3, maxConnAge: time.Minute, tableMax: 2,
	}
	clock := &fakeClock{t: testEpoch}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s := newSourceLimiter(ok, lim, clock.now)
	serve := func(ctx context.Context, src, method string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(ctx, method, "/v2/", nil)
		req.RemoteAddr = src + ":1234"
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	t.Run("a write over its bucket is refused with the wait it needed", func(t *testing.T) {
		if rec := serve(t.Context(), "10.0.0.1", "POST"); rec.Code != http.StatusNoContent {
			t.Fatalf("first write = %d, want 204", rec.Code)
		}
		rec := serve(t.Context(), "10.0.0.1", "POST")
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
			t.Errorf("second write = %d Retry-After %q, want 429 and 1", rec.Code, rec.Header().Get("Retry-After"))
		}
		if rec := serve(t.Context(), "10.0.0.2", "POST"); rec.Code != http.StatusNoContent {
			t.Errorf("another source's write = %d, want 204", rec.Code)
		}
		clock.advance(time.Second)
		if rec := serve(t.Context(), "10.0.0.1", "POST"); rec.Code != http.StatusNoContent {
			t.Errorf("write after a refill = %d, want 204", rec.Code)
		}
	})

	t.Run("an old connection is closed after its next response", func(t *testing.T) {
		ctx := s.ConnContext(t.Context(), nil)
		clock.advance(time.Second)
		if rec := serve(ctx, "10.0.0.3", "GET"); rec.Header().Get("Connection") == "close" {
			t.Error("a new connection was told to close")
		}
		clock.advance(lim.maxConnAge)
		if rec := serve(ctx, "10.0.0.3", "GET"); rec.Header().Get("Connection") != "close" {
			t.Error("a connection past its age was not told to close")
		}
	})

	t.Run("a connection is closed after its request bound", func(t *testing.T) {
		clock.advance(time.Second)
		ctx := s.ConnContext(t.Context(), nil)
		for i := 1; i <= lim.maxRequestsPerConn; i++ {
			clock.advance(time.Second)
			rec := serve(ctx, "10.0.0.4", "GET")
			if got, want := rec.Header().Get("Connection") == "close", i == lim.maxRequestsPerConn; got != want {
				t.Errorf("request %d told to close = %v, want %v", i, got, want)
			}
		}
	})

	t.Run("the table stays bounded", func(t *testing.T) {
		clock.advance(time.Hour)
		for i := range 10 {
			serve(t.Context(), fmt.Sprintf("10.1.0.%d", i), "GET")
		}
		s.mu.Lock()
		n := len(s.sources)
		s.mu.Unlock()
		if n > lim.tableMax {
			t.Errorf("table holds %d sources, want at most %d", n, lim.tableMax)
		}
	})

	t.Run("a waiting request ends with its context", func(t *testing.T) {
		clock.advance(time.Hour)
		for range 2 {
			serve(t.Context(), "10.0.0.9", "GET")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if rec := serve(ctx, "10.0.0.9", "GET"); rec.Code == http.StatusNoContent {
			t.Error("a request whose context ended was served after waiting")
		}
	})
}
