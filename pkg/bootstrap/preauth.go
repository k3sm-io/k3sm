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
	"net"
	"sync"
	"time"
)

// PreAuthSourceBurst and PreAuthSourceRefill tune the per-source half of the
// pre-authentication join bound (preAuthLimiter): how many join requests one
// source address may send back to back, and how long one spent unit takes to
// come back.
//
// The burst is sized for the most a LEGITIMATE source does in one go: a lab of
// Macs behind one NAT onboarded as a batch. They all present the same
// RemoteAddr host, so they share this bucket, and sixteen covers a batch plus
// the retries a few of them make. The refill (one unit per 2s, a sustained 30
// a minute) is far above what any real onboarding needs and far below what
// makes a single source's bcrypt traffic matter.
const (
	PreAuthSourceBurst  = 16
	PreAuthSourceRefill = 2 * time.Second
)

// PreAuthGlobalBurst and PreAuthGlobalRefill tune the global half: the ceiling
// on pre-authentication admissions from ALL sources together.
//
// This is the bound that makes the CPU cost finite. Every admitted request may
// pay one bcrypt compare in TokenVerifier.VerifyToken, and at bcrypt.DefaultCost
// that is roughly 50–100ms of one core. A refill of one unit per 250ms (four a
// second) holds the sustained cost to about 0.2–0.4 of one core however many
// source addresses a flood rotates through; the burst of 64 lets a large batch
// onboard at once and bounds the momentary spike to a few core-seconds.
const (
	PreAuthGlobalBurst  = 64
	PreAuthGlobalRefill = 250 * time.Millisecond
)

// preAuthMaxSources is the HARD cap on tracked per-source buckets. Unlike
// joinRateMaxBuckets (a soft sweep trigger, safe only because its keys are
// operator-minted), the key here is a network address the caller influences,
// so the map must never grow past this: a new source arriving at the cap is
// charged to the one shared overflow bucket (the unparsedTokenBucket pattern,
// held in its own field so no address string can ever collide with it, and
// run at the per-source tuning) instead of getting one of its own.
const preAuthMaxSources = 1024

// preAuthSweepInterval is how often allow drops per-source buckets that have
// refilled to full, so the map drains after a flood instead of pinning new
// sources to the overflow bucket for the life of the process. It is the time a
// fully spent source bucket takes to refill, so one interval after a flood
// stops every flood bucket is eligible.
const preAuthSweepInterval = PreAuthSourceBurst * PreAuthSourceRefill

// preAuthBucket is one token bucket's remaining budget: units left (fractional
// as it refills) as of instant at.
type preAuthBucket struct {
	units float64
	at    time.Time
}

// refilled returns b brought forward to now at the given tuning, capped at
// burst. A zero bucket (never seen) is full.
func (b preAuthBucket) refilled(now time.Time, burst int, refill time.Duration) preAuthBucket {
	if b.at.IsZero() {
		return preAuthBucket{units: float64(burst), at: now}
	}
	if elapsed := now.Sub(b.at); elapsed > 0 {
		b.units = math.Min(float64(burst), b.units+float64(elapsed)/float64(refill))
	}
	b.at = now
	return b
}

// wait is how long until b holds one whole unit at the given refill; zero when
// it already does.
func (b preAuthBucket) wait(refill time.Duration) time.Duration {
	if b.units >= 1 {
		return 0
	}
	return time.Duration((1 - b.units) * float64(refill))
}

// preAuthLimiter is the IDENTITY-BLIND bound on join requests that runs before
// anything about the request is parsed or verified — in particular before the
// bcrypt compare TokenVerifier.VerifyToken pays for every well-formed token.
// joinRateLimiter bounds only post-authentication work and says so; this is
// the bound on anonymous volume that sits ahead of it.
//
// THE KEY is the host part of the connection's RemoteAddr (preAuthSourceKey),
// and nothing a client can set. X-Forwarded-For and every other request header
// are deliberately NOT consulted: no reverse proxy is documented in front of
// the bootstrap listener, so any such header is the caller's own claim, and
// honoring it would hand a flooder a fresh bucket per request.
//
// TWO LAYERS, both token buckets, charged together under one mutex (a request
// is admitted only if BOTH hold a unit, and a refusal spends nothing):
//   - per source, in a map HARD-capped at preAuthMaxSources; a new source past
//     the cap shares the one overflow bucket, and full buckets are
//     swept every preAuthSweepInterval so the map drains after a flood;
//   - one global bucket, so total verification work stays bounded however many
//     addresses a flood rotates through. The map cap times the per-source rate
//     is NOT the ceiling; this bucket is.
//
// ACCEPTED FAILURE MODES, stated plainly because they decide what this is worth:
//  1. A distributed flood can crowd legitimate joiners out at the global bound.
//     Availability yields; keeping the bcrypt cost CPU-bounded is the job. A
//     refused joiner is told to retry (429 + Retry-After) and the join client
//     retries.
//  2. A refusal here costs no bcrypt, so it is answered faster than the
//     post-authentication 429 from joinRateLimiter. Response latency can
//     therefore disclose WHICH limiter fired. That discloses only "you were
//     throttled before verification", nothing about any token, and is accepted.
//  3. Several distinct Macs behind one NAT share one per-source bucket, by
//     design: the listener cannot tell them apart without trusting a header.
//     PreAuthSourceBurst is sized for that batch.
//
// Locking discipline: mu guards sources, overflow, global and lastSweep. now is
// the injected clock (this package's idiom, as NewTokenStore and
// joinRateLimiter take) so a test advances the refill instead of sleeping.
type preAuthLimiter struct {
	now func() time.Time

	sourceBurst  int
	sourceRefill time.Duration
	globalBurst  int
	globalRefill time.Duration
	maxSources   int

	mu        sync.Mutex
	sources   map[string]preAuthBucket
	overflow  preAuthBucket
	global    preAuthBucket
	lastSweep time.Time
}

// newPreAuthLimiter returns a limiter at the shipped tuning. now defaults to
// time.Now when nil.
func newPreAuthLimiter(now func() time.Time) *preAuthLimiter {
	if now == nil {
		now = time.Now
	}
	return &preAuthLimiter{
		now:          now,
		sourceBurst:  PreAuthSourceBurst,
		sourceRefill: PreAuthSourceRefill,
		globalBurst:  PreAuthGlobalBurst,
		globalRefill: PreAuthGlobalRefill,
		maxSources:   preAuthMaxSources,
		sources:      map[string]preAuthBucket{},
	}
}

// allow spends one unit from source's bucket and one from the global bucket.
// It reports whether the request may proceed and, when it may not, how long
// until both buckets hold a unit again. A refused request spends nothing, so a
// flood refused at the global bound does not also drain a quiet source's
// budget.
func (l *preAuthLimiter) allow(source string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastSweep.IsZero() {
		l.lastSweep = now
	} else if now.Sub(l.lastSweep) >= preAuthSweepInterval {
		l.sweepLocked(now)
		l.lastSweep = now
	}

	src, tracked := l.sources[source]
	overflow := !tracked && len(l.sources) >= l.maxSources
	if overflow {
		src = l.overflow
	}
	src = src.refilled(now, l.sourceBurst, l.sourceRefill)
	glob := l.global.refilled(now, l.globalBurst, l.globalRefill)

	if src.units < 1 || glob.units < 1 {
		// Persist the refill only for buckets that already exist: an unseen
		// source refused here stays absent (absent and full are the same
		// bucket), so a refused flood of fresh addresses grows nothing.
		l.global = glob
		switch {
		case overflow:
			l.overflow = src
		case tracked:
			l.sources[source] = src
		}
		return false, max(src.wait(l.sourceRefill), glob.wait(l.globalRefill))
	}

	src.units--
	glob.units--
	l.global = glob
	if overflow {
		l.overflow = src
	} else {
		l.sources[source] = src
	}
	return true, 0
}

// sweepLocked drops every per-source bucket that has refilled to full as of
// now. A full bucket and an absent one behave identically, so this frees
// memory without handing anybody budget they had not already recovered.
// Callers hold mu.
func (l *preAuthLimiter) sweepLocked(now time.Time) {
	for key, b := range l.sources {
		if b.units+float64(now.Sub(b.at))/float64(l.sourceRefill) >= float64(l.sourceBurst) {
			delete(l.sources, key)
		}
	}
}

// preAuthSourceKey is the per-source key for a request's RemoteAddr: its host
// part, so every connection from one address shares a bucket whatever its
// ephemeral port. RemoteAddr is set by net/http from the accepted connection,
// never from the request. If it does not split (a transport that fills it in
// some other shape), the raw string is the key: the request is still bounded,
// never waved through.
func preAuthSourceKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || host == "" {
		return remoteAddr
	}
	return host
}
