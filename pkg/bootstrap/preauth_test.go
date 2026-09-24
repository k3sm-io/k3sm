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

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// countingVerifier is a TokenVerifier that counts its invocations and refuses
// every token. The count is the whole point: each invocation stands for one
// bcrypt compare the real TokenStore would pay, so it is what the pre-auth
// bound must keep finite.
type countingVerifier struct{ calls atomic.Int64 }

func (v *countingVerifier) VerifyToken(context.Context, string) error {
	v.calls.Add(1)
	return errors.New("not a minted token")
}

// unreachedPasswords and unreachedEnroller satisfy NewServer. Every request in
// this file is refused at step 0 or step 1, so neither is ever called; a nil
// embedded interface panics if that ever stops being true.
type unreachedPasswords struct{ NodePasswordStore }

type unreachedEnroller struct{ Enroller }

// preAuthClock is the injected clock. Locking discipline: mu guards at.
type preAuthClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *preAuthClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *preAuthClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type preAuthRig struct {
	srv      *Server
	handler  http.Handler
	verifier *countingVerifier
	clock    *preAuthClock
}

func newPreAuthRig(t *testing.T) *preAuthRig {
	t.Helper()
	cluster, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	signing, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatal(err)
	}
	clock := &preAuthClock{at: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	verifier := &countingVerifier{}
	srv, err := NewServer(ServerConfig{
		ClusterCA:     cluster,
		SigningCA:     signing,
		Tokens:        verifier,
		NodePasswords: unreachedPasswords{},
		Enroller:      unreachedEnroller{},
		SelfNodeName:  "server",
		Now:           clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &preAuthRig{srv: srv, handler: srv.Handler(), verifier: verifier, clock: clock}
}

// post sends one join from remoteAddr with body and returns the recorder.
func (r *preAuthRig) post(remoteAddr, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, JoinPath, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

// wellFormedJoin decodes cleanly, so an admitted request reaches VerifyToken.
const wellFormedJoin = `{"token":"K10abc::id.secret","nodeName":"worker"}`

// TestJoinPreAuthBoundRefusesFloods is the B372 gate: anonymous join volume is
// bounded BEFORE the bcrypt compare in VerifyToken and before the body is
// decoded, per source address and in total.
//
// The VerifyToken invocation counts are the non-vacuity argument: with the
// bound absent, or placed after VerifyToken, every request reaches the verifier
// and the counts equal the sends; with it placed after the decode, the
// garbage-body row answers 400 instead of 429.
// trackedSources reports how many per-source buckets are held; the tests
// assert the hard cap with it (test-only so the shipped type carries no
// unused surface).
func (l *preAuthLimiter) trackedSources() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources)
}

func TestJoinPreAuthBoundRefusesFloods(t *testing.T) {
	t.Parallel()

	t.Run("a single-source flood reaches the verifier only within its budget", func(t *testing.T) {
		t.Parallel()
		rig := newPreAuthRig(t)
		const sends = 10 * PreAuthSourceBurst
		refused := 0
		for i := range sends {
			rec := rig.post(fmt.Sprintf("198.51.100.7:%d", 40000+i), wellFormedJoin)
			switch rec.Code {
			case http.StatusUnauthorized:
			case http.StatusTooManyRequests:
				refused++
				secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
				if err != nil || secs < 1 {
					t.Fatalf("Retry-After = %q, want whole seconds >= 1", rec.Header().Get("Retry-After"))
				}
			default:
				t.Fatalf("send %d: status = %d, want 401 (admitted) or 429 (refused)", i, rec.Code)
			}
		}
		if got := rig.verifier.calls.Load(); got > PreAuthSourceBurst {
			t.Errorf("VerifyToken ran %d times for %d sends from one source, want <= the %d burst", got, sends, PreAuthSourceBurst)
		}
		if want := sends - PreAuthSourceBurst; refused != want {
			t.Errorf("refused = %d, want %d (every send past the burst, the port rotated each time)", refused, want)
		}
	})

	t.Run("an over-budget garbage body is refused before it is decoded", func(t *testing.T) {
		t.Parallel()
		rig := newPreAuthRig(t)
		for range PreAuthSourceBurst {
			rig.post("198.51.100.8:1", wellFormedJoin)
		}
		rec := rig.post("198.51.100.8:1", "{this is not json")
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429: a 400 means the body was decoded before the bound ran", rec.Code)
		}
		// And the same garbage within budget is a 400, so the row above is
		// telling the two placements apart.
		if rec := rig.post("198.51.100.9:1", "{this is not json"); rec.Code != http.StatusBadRequest {
			t.Fatalf("within budget: status = %d, want 400 from the decode", rec.Code)
		}
	})

	t.Run("a many-source flood is held by the global ceiling", func(t *testing.T) {
		t.Parallel()
		rig := newPreAuthRig(t)
		const sends = preAuthMaxSources + 500
		for i := range sends {
			rig.post(fmt.Sprintf("10.%d.%d.1:5000", i/256, i%256), wellFormedJoin)
		}
		if got := rig.verifier.calls.Load(); got != PreAuthGlobalBurst {
			t.Errorf("VerifyToken ran %d times for %d distinct sources at one instant, want exactly the %d global burst", got, sends, PreAuthGlobalBurst)
		}
		if n := rig.srv.preauth.trackedSources(); n > preAuthMaxSources {
			t.Errorf("tracked sources = %d, want <= the %d cap", n, preAuthMaxSources)
		}
	})

	t.Run("sources past the map cap share one overflow bucket", func(t *testing.T) {
		t.Parallel()
		rig := newPreAuthRig(t)
		// Lift the global ceiling so the per-source map is the only bound in
		// play; this row isolates the hard cap and the overflow routing.
		rig.srv.preauth.globalBurst = 1 << 30
		const sends = preAuthMaxSources + 500
		for i := range sends {
			rig.post(fmt.Sprintf("10.%d.%d.1:5000", i/256, i%256), wellFormedJoin)
		}
		if n := rig.srv.preauth.trackedSources(); n != preAuthMaxSources {
			t.Errorf("tracked sources = %d, want exactly the %d cap: past it the map must not grow", n, preAuthMaxSources)
		}
		// The first cap sources each got their own bucket; the 500 past the
		// cap shared one, which admits only its burst.
		if got, want := rig.verifier.calls.Load(), int64(preAuthMaxSources+PreAuthSourceBurst); got != want {
			t.Errorf("VerifyToken ran %d times, want %d (cap + one shared overflow burst)", got, want)
		}
	})

	t.Run("a throttled source is admitted again after the refill", func(t *testing.T) {
		t.Parallel()
		rig := newPreAuthRig(t)
		for range PreAuthSourceBurst {
			rig.post("198.51.100.10:1", wellFormedJoin)
		}
		if rec := rig.post("198.51.100.10:1", wellFormedJoin); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 with the burst spent", rec.Code)
		}
		before := rig.verifier.calls.Load()
		rig.clock.advance(PreAuthSourceRefill)
		if rec := rig.post("198.51.100.10:1", wellFormedJoin); rec.Code != http.StatusUnauthorized {
			t.Fatalf("after one refill: status = %d, want 401 (admitted to verification)", rec.Code)
		}
		if got := rig.verifier.calls.Load(); got != before+1 {
			t.Errorf("VerifyToken calls = %d, want %d: the refilled unit must reach verification", got, before+1)
		}
		if rec := rig.post("198.51.100.10:1", wellFormedJoin); rec.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429: one refill buys one request, not a fresh burst", rec.Code)
		}
	})

	t.Run("a lab batch behind one NAT all reaches verification", func(t *testing.T) {
		t.Parallel()
		rig := newPreAuthRig(t)
		for i := range PreAuthSourceBurst {
			if rec := rig.post(fmt.Sprintf("203.0.113.1:%d", 50000+i), wellFormedJoin); rec.Code != http.StatusUnauthorized {
				t.Fatalf("batch join %d: status = %d, want 401 (reached verification)", i+1, rec.Code)
			}
		}
		if got := rig.verifier.calls.Load(); got != PreAuthSourceBurst {
			t.Errorf("VerifyToken ran %d times, want %d: every join in the batch must reach it", got, PreAuthSourceBurst)
		}
	})
}

// TestPreAuthSweepDrainsAfterFlood pins the eviction: once a flood stops and a
// sweep interval passes, full buckets are dropped and new sources get buckets
// of their own again instead of sharing the overflow bucket.
func TestPreAuthSweepDrainsAfterFlood(t *testing.T) {
	t.Parallel()
	clock := &preAuthClock{at: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	l := newPreAuthLimiter(clock.now)
	l.globalBurst = 1 << 30
	for i := range preAuthMaxSources {
		if ok, _ := l.allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256)); !ok {
			t.Fatalf("source %d refused below the cap", i)
		}
	}
	if n := l.trackedSources(); n != preAuthMaxSources {
		t.Fatalf("tracked = %d, want %d", n, preAuthMaxSources)
	}
	clock.advance(preAuthSweepInterval)
	if ok, _ := l.allow("192.0.2.200"); !ok {
		t.Fatal("a new source after the flood was refused")
	}
	if n := l.trackedSources(); n != 1 {
		t.Errorf("tracked = %d after the sweep, want 1 (only the new source)", n)
	}
}

// TestPreAuthSourceKey pins the key: RemoteAddr's host, the raw string when it
// does not split, and never anything else.
func TestPreAuthSourceKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"198.51.100.7:40000", "198.51.100.7"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"not-an-addr", "not-an-addr"},
		{"", ""},
	} {
		if got := preAuthSourceKey(tc.in); got != tc.want {
			t.Errorf("preAuthSourceKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPreAuthIgnoresForwardedFor pins that a client-set X-Forwarded-For buys no
// fresh bucket: the flood is still keyed by the connection's address.
func TestPreAuthIgnoresForwardedFor(t *testing.T) {
	t.Parallel()
	rig := newPreAuthRig(t)
	for i := range 4 * PreAuthSourceBurst {
		req := httptest.NewRequest(http.MethodPost, JoinPath, strings.NewReader(wellFormedJoin))
		req.RemoteAddr = "198.51.100.11:1"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.1.%d.%d", i/256, i%256))
		rig.handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := rig.verifier.calls.Load(); got > PreAuthSourceBurst {
		t.Errorf("VerifyToken ran %d times, want <= %d: X-Forwarded-For must not select the bucket", got, PreAuthSourceBurst)
	}
}
