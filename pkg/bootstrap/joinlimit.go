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
	"math"
	"sync"
	"time"
)

// JoinRateBurst and JoinRateRefill tune the per-token join rate limit
// (joinRateLimiter): how many joins one token may make back to back, and how
// long one spent unit takes to come back.
//
// The burst is sized from what a HEALTHY node legitimately does, not from what
// an attacker would like: one join per start, plus the retry a launchd-orphaned
// agent makes when its first attempt died with the process, plus an operator's
// own repeat while watching it. Five covers that with room, and the refill puts
// a sustained rate of five joins a minute behind it, which is far below what the
// round trip costs and far above what a node needs.
//
// Onboarding several Macs against ONE token is the case this deliberately does
// not widen the burst for. The mitigation is a fresh token per batch, which is
// cheap and already the normal way to hand out a join (see
// docs/user/multi-node.md); widening the burst instead would buy the attacker
// the same room it bought the operator.
const (
	JoinRateBurst  = 5
	JoinRateRefill = 12 * time.Second
)

// joinRateMaxBuckets is the size at which allow sweeps refilled buckets. It is a
// SOFT cap: reaching it triggers the sweep, it never refuses a request. The keys
// are operator-minted token ids rather than anything a caller supplies, so a
// stranger cannot grow this map at all and the bookkeeping is deliberately
// simple; the cap exists only so a long-lived control plane that has minted many
// tokens over months does not retain a bucket for each of them forever.
const joinRateMaxBuckets = 1024

// unparsedTokenBucket is the shared key for a presented token this package
// cannot parse. It carries a NUL, which no well-formed token id can, so it
// cannot collide with a real one.
const unparsedTokenBucket = "\x00unparsed"

// joinRateBucket is one token id's remaining budget: units left (fractional as
// it refills) as of instant at.
type joinRateBucket struct {
	units float64
	at    time.Time
}

// joinRateLimiter is a per-token token bucket over the join handler's
// POST-AUTHENTICATION work.
//
// WHAT IT BOUNDS. Everything handleJoin does from the node-password bind
// onwards: the first-write-wins name binding, the CSR parse and policy checks,
// the mesh enroll's index carve and the release that gives it back, and up to
// two signatures. A holder of ONE valid worker token could otherwise drive that
// whole round trip as fast as the network allows, enrolling and releasing
// without bound.
//
// WHAT IT DOES NOT BOUND, said plainly because it decides what this is worth:
// the token verification that runs BEFORE it. A request naming a known token id
// still costs a bcrypt compare inside TokenStore.Verify whether or not this
// limiter then refuses it, because a request cannot be keyed until its token has
// been parsed and its holder proven. This limits post-authentication work by an
// authenticated holder; it is not a defence against unauthenticated flooding,
// and nothing here should be read as one.
//
// Locking discipline: mu guards buckets. now is the injected clock (this
// package's idiom, as NewTokenStore takes) so a test advances the refill instead
// of sleeping.
type joinRateLimiter struct {
	now    func() time.Time
	burst  int
	refill time.Duration

	mu      sync.Mutex
	buckets map[string]joinRateBucket
}

// newJoinRateLimiter returns a limiter at the shipped tuning. now defaults to
// time.Now when nil.
func newJoinRateLimiter(now func() time.Time) *joinRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &joinRateLimiter{
		now:     now,
		burst:   JoinRateBurst,
		refill:  JoinRateRefill,
		buckets: map[string]joinRateBucket{},
	}
}

// allow spends one unit of id's budget. It reports whether the request may
// proceed and, when it may not, how long until one unit is available again.
//
// An id never seen before starts at the full burst, which is what makes a
// refilled bucket and an absent bucket the same thing and lets sweepLocked drop
// the former.
func (l *joinRateLimiter) allow(id string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, seen := l.buckets[id]
	if !seen {
		b = joinRateBucket{units: float64(l.burst), at: now}
	}
	if elapsed := now.Sub(b.at); elapsed > 0 {
		b.units = math.Min(float64(l.burst), b.units+float64(elapsed)/float64(l.refill))
	}
	b.at = now
	if b.units < 1 {
		l.buckets[id] = b
		return false, time.Duration((1 - b.units) * float64(l.refill))
	}
	b.units--
	if len(l.buckets) >= joinRateMaxBuckets {
		l.sweepLocked(now)
	}
	l.buckets[id] = b
	return true, 0
}

// sweepLocked drops every bucket that has refilled to full as of now. A full
// bucket and an absent one behave identically (allow starts an unseen id at the
// burst), so this frees memory without handing anybody budget they had not
// already recovered. Callers hold mu.
func (l *joinRateLimiter) sweepLocked(now time.Time) {
	for id, b := range l.buckets {
		if b.units+float64(now.Sub(b.at))/float64(l.refill) >= float64(l.burst) {
			delete(l.buckets, id)
		}
	}
}

// joinTokenID is the limiter key for a presented join token: the token's PUBLIC
// id (its user field), and nothing else.
//
// The node name is deliberately NOT part of it. That name is the caller's to
// choose and to change on every request, so keying on it — alone or in a
// composite — would hand any token holder a fresh bucket per request and leave
// the limiter measuring nothing at all.
//
// A token this package cannot parse has no id. It cannot reach here through
// either shipped verifier (TokenStore, FileTokenStore), both of which parse with
// ParseToken before they verify, so it would mean a verifier admitting some
// other shape; those requests share one bucket rather than escaping the limit.
// The TokenVerifier doc makes ParseToken-compatibility part of the contract, and
// TestJoinTokenIDMatchesEveryShippedVerifier holds every implementation to it.
func joinTokenID(tok string) string {
	t, err := ParseToken(tok)
	// Defensive only: ParseToken already rejects an empty user.
	if err != nil || t.User == "" {
		return unparsedTokenBucket
	}
	return t.User
}

// retryAfterSeconds renders d as the whole seconds of a Retry-After header,
// rounded UP and never below 1: the header's unit is seconds, and a truthful
// sub-second wait that rounded down to 0 would invite exactly the immediate
// retry it exists to prevent.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return int(math.Ceil(d.Seconds()))
}
