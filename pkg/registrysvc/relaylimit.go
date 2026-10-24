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
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// PER-SOURCE LIMITS. The relay's connection cap and the gate's TokenReview
// budget are shared by every caller, so without a per-source share one peer can
// spend either for all of them: hold every connection slot with keep-alives, or
// drain the review budget with well-shaped garbage tokens so every other
// uncached push gets 429. The limits here give each remote address its own
// share of both, in front of the gate:
//
//   - a CONNECTION share: one address holds at most relayMaxConnsPerSource of
//     the relay's relayMaxConns slots at once, and a connection past its share
//     is closed on accept rather than queued, so it never waits in front of
//     another source's connection;
//   - a REQUEST bucket per address, for every request;
//   - a WRITE bucket per address, refilling at half the gate's TokenReview
//     rate. Every write is metered, cached token or not, so one address can
//     never take more than half of the review budget, and what it leaves
//     refills for everyone else. The SubjectAccessReviews and namespace lookups
//     a write can cost sit behind the same bucket;
//   - a connection is closed after relayMaxRequestsPerConn requests or once it
//     is older than relayMaxConnAge, so a keep-alive held open with a cheap
//     request now and then is turned over rather than held for good.
//
// A request over its bucket first WAITS, up to the bucket's bound, and only
// then is refused with 429 and Retry-After, so a busy but honest pusher slows
// down instead of failing. The source is the remote IP address the relay sees.
// Traffic that reaches the relay through the Service VIP arrives from the
// Service proxy of the node it came from, so on that path a source is a node,
// not a Pod: the shares are sized for a whole node's pulls and pushes.
const (
	// relayMaxConnsPerSource is one address's share of relayMaxConns.
	relayMaxConnsPerSource = relayMaxConns / 4
	// relayRequestRate, relayRequestBurst and relayRequestWait bound the
	// requests of one address.
	relayRequestRate  = 100.0
	relayRequestBurst = 200.0
	relayRequestWait  = 1 * time.Second
	// relayWriteRate, relayWriteBurst and relayWriteWait bound the writes of
	// one address: half the gate's TokenReview budget, so one address cannot
	// take the rest.
	relayWriteRate  = tokenReviewRate / 2
	relayWriteBurst = tokenReviewBurst / 2
	relayWriteWait  = 5 * time.Second
	// relayMaxRequestsPerConn and relayMaxConnAge bound how long one
	// connection is reused. Neither interrupts a response: the connection is
	// closed after the response that crosses the bound.
	relayMaxRequestsPerConn = 100
	relayMaxConnAge         = 10 * time.Minute
	// relaySourceTableMax bounds the per-address bucket table. A full table
	// drops its idle entries and, if still full, starts over: the cost is a
	// fresh bucket for every address, never a refusal.
	relaySourceTableMax = 4096
)

// relayLimits are the per-source limits a relay applies. Production uses
// defaultRelayLimits; a test may shrink them.
type relayLimits struct {
	maxConns, maxConnsPerSource int
	requestRate, requestBurst   float64
	requestWait                 time.Duration
	writeRate, writeBurst       float64
	writeWait                   time.Duration
	maxRequestsPerConn          int
	maxConnAge                  time.Duration
	tableMax                    int
}

// defaultRelayLimits are the limits every shipped relay applies.
var defaultRelayLimits = relayLimits{
	maxConns:           relayMaxConns,
	maxConnsPerSource:  relayMaxConnsPerSource,
	requestRate:        relayRequestRate,
	requestBurst:       relayRequestBurst,
	requestWait:        relayRequestWait,
	writeRate:          relayWriteRate,
	writeBurst:         relayWriteBurst,
	writeWait:          relayWriteWait,
	maxRequestsPerConn: relayMaxRequestsPerConn,
	maxConnAge:         relayMaxConnAge,
	tableMax:           relaySourceTableMax,
}

// sourceOf returns the remote IP address of a, the key every per-source limit
// is kept under. An address that is not host:port is its own key.
func sourceOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort().Addr().Unmap().String()
	}
	return sourceOfString(a.String())
}

// sourceOfString is sourceOf for an address already rendered as a string, as
// http.Request.RemoteAddr is.
func sourceOfString(s string) string {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().String()
	}
	return s
}

// relayConn is what a connection carries into each request's context: when it
// was accepted and how many requests it has served. requests is touched only
// by the connection's own serving goroutine, which serves one request at a time.
type relayConn struct {
	opened   time.Time
	requests int
}

// relayConnKey is the context key a relayConn is stored under.
type relayConnKey struct{}

// sourceLimiter is the handler in front of the gate that applies the request
// and write buckets and the per-connection reuse bound.
type sourceLimiter struct {
	next http.Handler
	lim  relayLimits
	now  func() time.Time

	mu      sync.Mutex // guards sources
	sources map[string]*sourceBuckets
}

// sourceBuckets are one address's two buckets.
type sourceBuckets struct {
	requests, writes bucketState
}

// bucketState is one reservation-style token bucket. tokens may go negative:
// a negative balance is the reservations already promised to waiting requests.
type bucketState struct {
	tokens float64
	last   time.Time
}

func newSourceLimiter(next http.Handler, lim relayLimits, now func() time.Time) *sourceLimiter {
	if now == nil {
		now = time.Now
	}
	return &sourceLimiter{next: next, lim: lim, now: now, sources: map[string]*sourceBuckets{}}
}

// ConnContext stamps a new connection with its relayConn. It is the
// http.Server's ConnContext.
func (s *sourceLimiter) ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, relayConnKey{}, &relayConn{opened: s.now()})
}

// ServeHTTP applies the limits, then hands the request to the gate.
func (s *sourceLimiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rc, ok := r.Context().Value(relayConnKey{}).(*relayConn); ok {
		rc.requests++
		if rc.requests >= s.lim.maxRequestsPerConn || s.now().Sub(rc.opened) >= s.lim.maxConnAge {
			// The server closes the connection after this response; the
			// response itself is served in full.
			w.Header().Set("Connection", "close")
		}
	}
	write := r.Method != http.MethodGet && r.Method != http.MethodHead
	delay, ok := s.reserve(sourceOfString(r.RemoteAddr), write)
	if !ok {
		w.Header().Set("Retry-After", retryAfterSeconds(delay))
		ociError(w, r, http.StatusTooManyRequests, codeTooMany, "too many requests from this address; retry")
		return
	}
	if delay > 0 {
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-r.Context().Done():
			t.Stop()
			return
		}
	}
	s.next.ServeHTTP(w, r)
}

// reserve takes one token from src's request bucket and, for a write, one from
// its write bucket. It returns how long the request must wait for them, or
// false, with the wait it would have needed, when either wait would exceed its
// bound; a refused request takes nothing from either bucket.
func (s *sourceLimiter) reserve(src string, write bool) (time.Duration, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.sources[src]
	if !ok {
		s.makeRoom(now)
		b = &sourceBuckets{
			requests: bucketState{tokens: s.lim.requestBurst, last: now},
			writes:   bucketState{tokens: s.lim.writeBurst, last: now},
		}
		s.sources[src] = b
	}
	b.requests.refill(now, s.lim.requestRate, s.lim.requestBurst)
	b.writes.refill(now, s.lim.writeRate, s.lim.writeBurst)
	delay, ok := b.requests.wait(s.lim.requestRate, s.lim.requestWait)
	if !ok {
		return delay, false
	}
	if write {
		wd, ok := b.writes.wait(s.lim.writeRate, s.lim.writeWait)
		if !ok {
			return wd, false
		}
		delay = max(delay, wd)
		b.writes.tokens--
	}
	b.requests.tokens--
	return delay, true
}

// makeRoom keeps the table under its bound. It is called with s.mu held.
func (s *sourceLimiter) makeRoom(now time.Time) {
	if len(s.sources) < s.lim.tableMax {
		return
	}
	for k, b := range s.sources {
		if b.requests.idle(now, s.lim.requestRate, s.lim.requestBurst) && b.writes.idle(now, s.lim.writeRate, s.lim.writeBurst) {
			delete(s.sources, k)
		}
	}
	if len(s.sources) >= s.lim.tableMax {
		s.sources = map[string]*sourceBuckets{}
	}
}

// refill credits the tokens accrued since the last refill, up to burst.
func (b *bucketState) refill(now time.Time, rate, burst float64) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(burst, b.tokens+el*rate)
	}
	b.last = now
}

// wait returns how long until one more token is available, or false when that
// is longer than bound. It takes nothing.
func (b *bucketState) wait(rate float64, bound time.Duration) (time.Duration, bool) {
	if b.tokens >= 1 {
		return 0, true
	}
	d := time.Duration((1 - b.tokens) / rate * float64(time.Second))
	return d, d <= bound
}

// idle reports whether the bucket would be full by now, which is the state a
// fresh bucket starts in, so dropping it changes nothing.
func (b *bucketState) idle(now time.Time, rate, burst float64) bool {
	return b.tokens+now.Sub(b.last).Seconds()*rate >= burst
}

// sourceCounts counts the open connections per source, for the listener's
// per-source share.
type sourceCounts struct {
	mu sync.Mutex // guards n
	n  map[string]int
}

// take counts one more connection from src, or reports false when src is
// already at max.
func (c *sourceCounts) take(src string, max int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n[src] >= max {
		return false
	}
	c.n[src]++
	return true
}

// give returns one of src's connections.
func (c *sourceCounts) give(src string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n[src] <= 1 {
		delete(c.n, src)
		return
	}
	c.n[src]--
}

// retryAfterSeconds renders d as a whole-second Retry-After value, at least 1.
func retryAfterSeconds(d time.Duration) string {
	s := int((d + time.Second - 1) / time.Second)
	return strconv.Itoa(max(1, s))
}
