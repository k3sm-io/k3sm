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

package bootstrap_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// rateLimitClock is the injected clock the join limiter refills against. Every
// row advances it explicitly; nothing in this file sleeps.
//
// Locking discipline: mu guards at; httptest serves each request on its own
// goroutine, so the handler reads the clock concurrently with the test
// advancing it between requests.
type rateLimitClock struct {
	mu sync.Mutex
	at time.Time
}

func newRateLimitClock() *rateLimitClock {
	return &rateLimitClock{at: time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)}
}

func (c *rateLimitClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *rateLimitClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// rateLimitJoin is a join request that WOULD be served: a well-formed CSR for
// its own name, no asserted address, and a mesh enroll naming the same node. So
// the only thing that can refuse it is the rate limit.
func rateLimitJoin(t *testing.T, token, nodeName string) bootstrap.JoinRequest {
	t.Helper()
	return bootstrap.JoinRequest{
		SchemaVersion: bootstrap.JoinSchemaVersion,
		Token:         token,
		NodeName:      nodeName,
		NodePassword:  nodeName + "-node-password",
		ClientCSRPEM:  nodeCSRPEM(t, nodeName, []string{nodeName}, nil),
		Mesh: netv1.MeshEnrollRequest{
			NodeName:  nodeName,
			PublicKey: "d29ya2VyLXB1YmxpYy1rZXktYmFzZTY0LTMyYnl0ZXM9",
			Endpoint:  "192.0.2.50:51820",
		}.WithDefaults(),
	}
}

// TestJoinIsRateLimitedPerToken is the B346 gate: one valid worker token may
// drive only a bounded number of joins, because a join is expensive on the
// server's side and every one of those requests is authenticated.
//
// What it costs per round trip: a bcrypt compare, a first-write-wins
// node-password bind, a CSR parse and its policy checks, a mesh enroll that
// carves an index plus the release that gives it back, and two signatures. A
// holder of ONE token could drive that as fast as the network allows, and
// nothing upstream of the limiter would refuse it.
//
// The keying is the load-bearing half. The bucket is keyed by the token's id
// ALONE; the node name is the caller's to pick and to rotate, so a composite
// key would hand out a fresh bucket per request and limit nothing. The
// rotated-name row below is that bypass, asserted closed.
//
// Fails before the fix: handleJoin admitted every authenticated request, so the
// burst+1st join was served 200 with a certificate, and the rotated-name row
// was served too.
func TestJoinIsRateLimitedPerToken(t *testing.T) {
	t.Parallel()

	t.Run("a burst is served and the next is refused with a Retry-After", func(t *testing.T) {
		t.Parallel()
		clock := newRateLimitClock()
		enroller := newPeerStoreEnroller("100.64.1.0/24", "100.64.1.2")
		rig := newClockedJoinServerRig(t, enroller, "", clock.now)

		for i := range bootstrap.JoinRateBurst {
			node := fmt.Sprintf("worker-%d", i)
			if status, body := rig.post(t, rateLimitJoin(t, rig.token, node)); status != http.StatusOK {
				t.Fatalf("join %d of the burst: status = %d (%s), want 200", i+1, status, body)
			}
		}

		status, body, header := rig.postWithHeaders(t, rateLimitJoin(t, rig.token, "worker-over"))
		if status != http.StatusTooManyRequests {
			t.Fatalf("join %d: status = %d (%s), want 429 once the burst is spent", bootstrap.JoinRateBurst+1, status, body)
		}
		secs, err := strconv.Atoi(header.Get("Retry-After"))
		if err != nil {
			t.Fatalf("Retry-After = %q, want whole seconds: %v", header.Get("Retry-After"), err)
		}
		// The wait must be usable: positive, and no longer than one refill —
		// the budget the request was refused for is one unit, not the burst.
		if secs < 1 || time.Duration(secs)*time.Second > bootstrap.JoinRateRefill {
			t.Errorf("Retry-After = %ds, want between 1s and the %s refill", secs, bootstrap.JoinRateRefill)
		}
		if body == "" {
			t.Error("a refused join must say why; an empty 429 body tells the operator nothing")
		}
	})

	t.Run("the budget recovers after the refill window", func(t *testing.T) {
		t.Parallel()
		clock := newRateLimitClock()
		enroller := newPeerStoreEnroller("100.64.1.0/24", "100.64.1.2")
		rig := newClockedJoinServerRig(t, enroller, "", clock.now)

		for i := range bootstrap.JoinRateBurst {
			if status, body := rig.post(t, rateLimitJoin(t, rig.token, fmt.Sprintf("worker-%d", i))); status != http.StatusOK {
				t.Fatalf("join %d of the burst: status = %d (%s), want 200", i+1, status, body)
			}
		}
		if status, _ := rig.post(t, rateLimitJoin(t, rig.token, "worker-over")); status != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 with the burst spent", status)
		}

		// One refill buys exactly one join back, and no more.
		clock.advance(bootstrap.JoinRateRefill)
		if status, body := rig.post(t, rateLimitJoin(t, rig.token, "worker-again")); status != http.StatusOK {
			t.Fatalf("after one %s refill: status = %d (%s), want 200", bootstrap.JoinRateRefill, status, body)
		}
		if status, _ := rig.post(t, rateLimitJoin(t, rig.token, "worker-again-2")); status != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429: one refill window buys ONE join, not a fresh burst", status)
		}

		// A long enough idle restores the whole burst, and caps there.
		clock.advance(bootstrap.JoinRateRefill * time.Duration(bootstrap.JoinRateBurst+10))
		for i := range bootstrap.JoinRateBurst {
			if status, body := rig.post(t, rateLimitJoin(t, rig.token, fmt.Sprintf("worker-later-%d", i))); status != http.StatusOK {
				t.Fatalf("join %d after a long idle: status = %d (%s), want 200", i+1, status, body)
			}
		}
		if status, _ := rig.post(t, rateLimitJoin(t, rig.token, "worker-later-over")); status != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429: the bucket must cap at the burst however long it idled", status)
		}
	})

	t.Run("two different tokens do not share a bucket", func(t *testing.T) {
		t.Parallel()
		clock := newRateLimitClock()
		enroller := newPeerStoreEnroller("100.64.1.0/24", "100.64.1.2")
		rig := newClockedJoinServerRig(t, enroller, "", clock.now)
		second := rig.mintToken(t)

		for i := range bootstrap.JoinRateBurst {
			if status, body := rig.post(t, rateLimitJoin(t, rig.token, fmt.Sprintf("worker-%d", i))); status != http.StatusOK {
				t.Fatalf("join %d of the burst: status = %d (%s), want 200", i+1, status, body)
			}
		}
		if status, _ := rig.post(t, rateLimitJoin(t, rig.token, "worker-over")); status != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 with the first token's burst spent", status)
		}

		// The second token is a separate operator decision with its own budget:
		// this is what makes "mint a token per batch" the real mitigation for
		// onboarding several Macs at once.
		for i := range bootstrap.JoinRateBurst {
			if status, body := rig.post(t, rateLimitJoin(t, second, fmt.Sprintf("other-%d", i))); status != http.StatusOK {
				t.Fatalf("second token, join %d: status = %d (%s), want 200 — buckets are per token", i+1, status, body)
			}
		}
	})

	t.Run("the same token with a rotated node name shares one bucket", func(t *testing.T) {
		t.Parallel()
		clock := newRateLimitClock()
		enroller := newPeerStoreEnroller("100.64.1.0/24", "100.64.1.2")
		rig := newClockedJoinServerRig(t, enroller, "", clock.now)

		// Every request names a node nobody has bound, which is free to a token
		// holder: NodePasswordStore.Ensure binds any unseen name on sight. If the
		// key were the node name, or anything composed with it, each of these
		// would land in its own bucket and the limiter would measure nothing.
		for i := range bootstrap.JoinRateBurst {
			if status, body := rig.post(t, rateLimitJoin(t, rig.token, fmt.Sprintf("rotated-%d", i))); status != http.StatusOK {
				t.Fatalf("join %d: status = %d (%s), want 200", i+1, status, body)
			}
		}
		status, body := rig.post(t, rateLimitJoin(t, rig.token, "rotated-fresh-name"))
		if status != http.StatusTooManyRequests {
			t.Fatalf("a brand-new node name on a spent token: status = %d (%s), want 429 — rotating the name must not buy a fresh bucket", status, body)
		}
	})

	t.Run("a refused join binds no node-password and runs no enroll", func(t *testing.T) {
		t.Parallel()
		clock := newRateLimitClock()
		enroller := newPeerStoreEnroller("100.64.1.0/24", "100.64.1.2")
		rig := newClockedJoinServerRig(t, enroller, "", clock.now)

		for i := range bootstrap.JoinRateBurst {
			if status, body := rig.post(t, rateLimitJoin(t, rig.token, fmt.Sprintf("worker-%d", i))); status != http.StatusOK {
				t.Fatalf("join %d of the burst: status = %d (%s), want 200", i+1, status, body)
			}
		}
		enrollsBefore := enroller.calls()

		const refused = "worker-refused"
		if status, body := rig.post(t, rateLimitJoin(t, rig.token, refused)); status != http.StatusTooManyRequests {
			t.Fatalf("status = %d (%s), want 429", status, body)
		}

		// The binding is the durable half: a name bound by a refused request
		// belongs to whoever sent it on every later join. The limit sits ahead of
		// Ensure precisely so a refusal cannot take one.
		if _, bound := rig.passwords.StoredHash(refused); bound {
			t.Error("a rate-limited join bound a node-password; the refusal must precede the first-write-wins binding")
		}
		if got := enroller.calls(); got != enrollsBefore {
			t.Errorf("the enroll ran %d more times on a refused join, want 0: the enroll allocates, and every certificate is signed after it", got-enrollsBefore)
		}
		if _, ok := enroller.peer(refused); ok {
			t.Error("a rate-limited join wrote a MeshPeer")
		}
	})
}

// TestJoinClientSurfacesARateLimitedRefusal is the client half of B346, and it
// ships in the same change for a reason the server half cannot fix: postJSON
// collapsed every non-2xx into one "join rejected" error, an agent calls Join
// once per process start, and `k3sm install` waits one bounded budget for the
// credential that join writes. A rate-limited join read as a rejected token
// therefore FAILS THE INSTALL — on exactly the multi-worker onboarding the
// server-side limit exists to protect.
//
// Fails before the fix: the 429 came back as a generic rejection, indis-
// tinguishable by errors.Is from a refused token.
func TestJoinClientSurfacesARateLimitedRefusal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	join := func(t *testing.T, h http.HandlerFunc) error {
		t.Helper()
		ts := httptest.NewServer(h)
		t.Cleanup(ts.Close)
		_, err := bootstrap.Join(ctx, bootstrap.JoinOptions{
			Server:     ts.URL,
			Token:      bootstrap.FormatToken("cafe", "boot-abc", "secret"),
			NodeName:   "worker-1",
			HTTPClient: ts.Client(),
		})
		if err == nil {
			t.Fatal("want an error from a refused join")
		}
		return err
	}

	t.Run("a 429 is a retry-later condition carrying the wait", func(t *testing.T) {
		t.Parallel()
		err := join(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "12")
			http.Error(w, "join refused: too many join attempts for this token; retry in 12s", http.StatusTooManyRequests)
		})
		if !errors.Is(err, bootstrap.ErrJoinRateLimited) {
			t.Fatalf("err = %v, want it to be ErrJoinRateLimited: an agent that cannot tell this from a rejected token fails its install on a wait", err)
		}
		var limited *bootstrap.JoinRateLimitedError
		if !errors.As(err, &limited) {
			t.Fatalf("err = %v, want a *JoinRateLimitedError carrying the server's wait", err)
		}
		if limited.RetryAfter != 12*time.Second {
			t.Errorf("RetryAfter = %s, want 12s — the wait the server named", limited.RetryAfter)
		}
	})

	t.Run("a 429 without a readable Retry-After leaves the wait to the caller", func(t *testing.T) {
		t.Parallel()
		err := join(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "slow down", http.StatusTooManyRequests)
		})
		var limited *bootstrap.JoinRateLimitedError
		if !errors.As(err, &limited) {
			t.Fatalf("err = %v, want a *JoinRateLimitedError", err)
		}
		if limited.RetryAfter != 0 {
			t.Errorf("RetryAfter = %s, want 0 when the server named no wait this client can read", limited.RetryAfter)
		}
	})

	t.Run("a terminal rejection is NOT retry-later", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name   string
			status int
			body   string
		}{
			{"rejected token", http.StatusUnauthorized, "invalid join token"},
			{"refused name", http.StatusForbidden, "join refused: that node name is not available"},
			{"refused CSR", http.StatusForbidden, "client CSR denied"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := join(t, func(w http.ResponseWriter, _ *http.Request) {
					// A Retry-After on a non-429 must not make it one either:
					// the status is what decides, not a stray header.
					w.Header().Set("Retry-After", "12")
					http.Error(w, tc.body, tc.status)
				})
				if errors.Is(err, bootstrap.ErrJoinRateLimited) {
					t.Errorf("err = %v, want a TERMINAL error: waiting changes nothing about a %d, and an agent that retries it burns its install budget", err, tc.status)
				}
			})
		}
	})
}
