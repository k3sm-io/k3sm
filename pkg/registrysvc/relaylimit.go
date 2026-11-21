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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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
	// relayWriteProgress and relayReadProgress bound how long one write of a
	// response, or one read of a request body, may wait on the peer. They
	// bound progress, not total time: a blob streams for as long as it takes
	// while it keeps moving, and a peer that stops reading or sending loses
	// its connection, and its slot, one window later. The window is long on
	// purpose: the node's ordinary image puller does not resume a cut layer
	// with a Range request, so a cut costs a full re-download, and a client
	// may pause that long while it unpacks or syncs a large layer. The bound
	// exists to free a dead slot, not to police slow peers.
	relayWriteProgress = 5 * time.Minute
	relayReadProgress  = 5 * time.Minute
	// relaySourceTableMax bounds the per-address bucket table. A full table
	// drops its idle entries and, if still full, starts over: the cost is a
	// fresh bucket for every address, never a refusal.
	relaySourceTableMax = 4096
	// relayWarnEvery is the least time between two of the listener's warnings
	// of one kind (the relay full, a source refused at its share), so a flood
	// of either costs one line a minute.
	relayWarnEvery = time.Minute
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
	writeProgress, readProgress time.Duration
	tableMax                    int
	// rateFloor, in bytes a second, and rateWindow are the rate floor
	// (relayrate.go); zero in either disables it.
	rateFloor  float64
	rateWindow time.Duration
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
	writeProgress:      relayWriteProgress,
	readProgress:       relayReadProgress,
	tableMax:           relaySourceTableMax,
	rateFloor:          relayRateFloor,
	rateWindow:         relayRateWindow,
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
// was accepted, how many requests it has served, and its cut watch. requests is
// touched only by the connection's own serving goroutine, which serves one
// request at a time. cut is set once, before the connection is served, and is
// nil for a connection the relay's listener did not accept.
type relayConn struct {
	opened   time.Time
	requests int
	cut      *cutWatch
	// meter is the connection's rate meter, set with cut; nil when the rate
	// floor is off.
	meter *rateMeter
	// unbounded is set once the connection is logged as served without a
	// progress bound, so the line is written once per connection. The server
	// handles one request at a time on a connection, so no lock guards it.
	// That holds because the relay speaks HTTP/1.1 only: accept starts the
	// relay's HTTP server with Serve over a TLS listener, and the TLS config
	// pins http/1.1. Enabling HTTP/2 would need a lock here.
	unbounded bool
}

// Directions of a deadline cut, as the cut's log line names them.
const (
	cutWrite = "write"
	cutRead  = "read"
	cutFlush = "flush"
)

// cutWatch reports, once, that one of the relay's own deadlines cut its
// connection. The write deadline the relay last armed is recorded in armed, so
// a write that times out under it is told apart from one under a deadline the
// relay does not own: the server's TLS handshake deadline, or the one the TLS
// close alert sets for itself when the connection closes. The record is dropped
// when the connection sets any other write deadline, and when the response
// ends and the connection goes idle, so a later write that times out for
// another cause, such as a refusal the server writes before a next request
// reaches the relay, is not logged as a stalled response. A read is reported
// where it is observed, by the progressReader that armed its deadline just
// before. Both fields are atomic: the response is written from the handler's
// goroutine and the serving goroutine, and a request body can be read from
// another.
type cutWatch struct {
	log                         *slog.Logger
	remote                      string
	writeProgress, readProgress time.Duration
	armed                       atomic.Pointer[armedWrite] // the relay's write deadline in force, or nil
	logged                      atomic.Bool
}

// armedWrite is a write deadline the relay armed: which one, and when it fires.
type armedWrite struct {
	dir string // cutWrite or cutFlush
	at  time.Time
}

// armWrite records which of the relay's write deadlines is in force and when
// it fires; "" is none.
func (w *cutWatch) armWrite(dir string, at time.Time) {
	if w == nil {
		return
	}
	if dir == "" {
		w.armed.Store(nil)
		return
	}
	w.armed.Store(&armedWrite{dir: dir, at: at})
}

// writeDeadlineSet drops the record of the relay's write deadline when the
// connection is given a different one, which is then not the relay's.
func (w *cutWatch) writeDeadlineSet(t time.Time) {
	if w == nil {
		return
	}
	if a := w.armed.Load(); a != nil && !a.at.Equal(t) {
		w.armed.CompareAndSwap(a, nil)
	}
}

// wrote reports a cut when err is a write timing out under a relay deadline.
func (w *cutWatch) wrote(err error) {
	if w == nil || !isDeadline(err) {
		return
	}
	if a := w.armed.Load(); a != nil {
		w.cut(a.dir, w.writeProgress)
	}
}

// read reports a cut when err is a request-body read timing out under the
// read deadline the relay armed before it.
func (w *cutWatch) read(err error) {
	if w == nil || !isDeadline(err) {
		return
	}
	w.cut(cutRead, w.readProgress)
}

// cut logs the cut, at most once per connection.
func (w *cutWatch) cut(dir string, window time.Duration) {
	if w.log == nil || !w.logged.CompareAndSwap(false, true) {
		return
	}
	w.log.Warn("ingest registry relay cut a stalled connection: the peer made no progress within the window",
		"direction", dir, "window", window, "remote", w.remote)
}

// isDeadline reports whether err is a deadline expiring.
func isDeadline(err error) bool { return err != nil && errors.Is(err, os.ErrDeadlineExceeded) }

// relayConnKey is the context key a relayConn is stored under.
type relayConnKey struct{}

// sourceLimiter is the handler in front of the gate that applies the request
// and write buckets and the per-connection reuse bound.
type sourceLimiter struct {
	next http.Handler
	lim  relayLimits
	now  func() time.Time
	// log receives the line for a connection a relay deadline cut, and for one
	// served without a progress bound. Nil logs nothing.
	log *slog.Logger

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

// limitConnOf returns the connection the relay's listener accepted under c's
// TLS layer, if any, or nil.
func limitConnOf(c net.Conn) *limitConn {
	if t, ok := c.(interface{ NetConn() net.Conn }); ok {
		c = t.NetConn()
	}
	lc, _ := c.(*limitConn)
	return lc
}

// ConnState is the http.Server's ConnState. A connection going idle has
// written its response in full, so the relay's write deadline no longer stands
// for a response in progress and is dropped from the cut watch, and the rate
// floor stops measuring it until its next response.
func (s *sourceLimiter) ConnState(c net.Conn, st http.ConnState) {
	if st != http.StateIdle {
		return
	}
	if lc := limitConnOf(c); lc != nil {
		lc.cut.armWrite("", time.Time{})
		lc.meter.end()
	}
}

// ConnContext stamps a new connection with its relayConn and, when the relay's
// listener accepted it, hands the connection the same cut watch. It is the
// http.Server's ConnContext, so it runs before the connection is served.
func (s *sourceLimiter) ConnContext(ctx context.Context, c net.Conn) context.Context {
	rc := &relayConn{opened: s.now()}
	under := c
	if t, ok := under.(interface{ NetConn() net.Conn }); ok {
		under = t.NetConn()
	}
	if lc, ok := under.(*limitConn); ok {
		rc.cut = &cutWatch{log: s.log, remote: c.RemoteAddr().String(), writeProgress: s.lim.writeProgress, readProgress: s.lim.readProgress}
		lc.cut = rc.cut
		rc.meter = lc.meter
	}
	return context.WithValue(ctx, relayConnKey{}, rc)
}

// ServeHTTP applies the limits, then hands the request to the gate.
func (s *sourceLimiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w, r, done := s.bindProgress(w, r)
	defer done()
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

// bindProgress bounds the request by progress: every write of the response
// must reach the peer within writeProgress of its start, and every read of the
// request body within readProgress. A response or body that keeps moving is
// never cut, however long it takes; one that stalls fails its write or read,
// and the server closes the connection, which frees its slot. done arms the
// write deadline one more window ahead when the handler returns, because the
// server then flushes the response's buffered tail, and a peer that stops
// reading there must lose its slot too. The next request on the connection
// clears that deadline before its handler runs, so a long silent handler is not
// cut by a deadline left from the request before it. done clears the read
// deadline only for a request with no body or a body read to its end. A body
// still unread gets one more window for the server's drain after the handler;
// a body whose read failed, a timeout included, keeps the deadline already
// armed, so the drain fails at once and the connection closes. The errors
// from setting a deadline are ignored, except the first: a writer that cannot
// take a deadline is served unbounded rather than refused, and logged once per
// connection as served so. Each deadline armed is recorded in the
// connection's cut watch, so a cut it makes is logged once, where the timed-out
// write or read is observed.
func (s *sourceLimiter) bindProgress(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request, func()) {
	var cut *cutWatch
	conn, _ := r.Context().Value(relayConnKey{}).(*relayConn)
	if conn != nil {
		cut = conn.cut
		// A response is in flight from here until the connection goes idle,
		// and the rate floor measures it for that long.
		conn.meter.begin()
	}
	rc := http.NewResponseController(w)
	cut.armWrite("", time.Time{})
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		s.logUnbounded(conn, r.RemoteAddr, err)
	}
	pw := &progressWriter{ResponseWriter: w, rc: rc, d: s.lim.writeProgress, cut: cut}
	var pr *progressReader
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		// Armed before the handler runs: a handler that answers without
		// reading the body makes the server drain it before the response
		// goes out, and that drain is bounded by this deadline too.
		_ = rc.SetReadDeadline(time.Now().Add(s.lim.readProgress))
		pr = &progressReader{ReadCloser: r.Body, rc: rc, d: s.lim.readProgress, cut: cut}
		r.Body = pr
	}
	return pw, r, func() {
		at := time.Now().Add(s.lim.writeProgress)
		cut.armWrite(cutFlush, at)
		_ = rc.SetWriteDeadline(at)
		if pr != nil {
			pr.finish()
			return
		}
		_ = rc.SetReadDeadline(time.Time{})
	}
}

// logUnbounded logs a connection that is served with no progress bound.
// Its writer refused a deadline, http.ErrNotSupported included. A connection
// that has a relayConn record, set by ConnContext, is logged once. A request
// with no such record is logged every time.
func (s *sourceLimiter) logUnbounded(conn *relayConn, remote string, err error) {
	if s.log == nil {
		return
	}
	if conn != nil {
		if conn.unbounded {
			return
		}
		conn.unbounded = true
	}
	s.log.Warn("ingest registry relay serves a connection without a progress bound: its writer cannot take a deadline",
		"remote", remote, "error", err)
}

// progressWriter arms a fresh write deadline before each write to the peer.
type progressWriter struct {
	http.ResponseWriter
	rc  *http.ResponseController
	d   time.Duration
	cut *cutWatch
}

func (p *progressWriter) arm() {
	at := time.Now().Add(p.d)
	p.cut.armWrite(cutWrite, at)
	_ = p.rc.SetWriteDeadline(at)
}

func (p *progressWriter) WriteHeader(code int) {
	p.arm()
	p.ResponseWriter.WriteHeader(code)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.arm()
	return p.ResponseWriter.Write(b)
}

// Unwrap gives http.ResponseController, and so Flush, the response underneath.
// A flush the handler asks for goes through FlushError below, so it is bounded
// too.
func (p *progressWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// FlushError arms the write deadline, then flushes the response underneath.
func (p *progressWriter) FlushError() error {
	p.arm()
	return p.rc.Flush()
}

// Flush is FlushError for callers that only know http.Flusher.
func (p *progressWriter) Flush() { _ = p.FlushError() }

// Hijack hands over the connection underneath, for a caller that only knows
// http.Hijacker: the gate hijacks to close a read's connection with no
// response when the registry is gone.
func (p *progressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return p.rc.Hijack() }

// progressReader arms a fresh read deadline before each read of the request
// body, and clears it once the body is read to io.EOF: the server then reads
// the connection in the background to notice the peer leaving, and that read
// must not time out. A read that fails any other way, a timeout included,
// leaves the armed deadline in place and marks the read failed, so the
// server's drain of the rest is bounded by it and the connection closes.
//
// The body can be read on a goroutine other than the handler's: the proxy's
// transport sends it upstream from its own, and goes on doing so after the
// registry has answered. Once the body is closed, or the handler has returned
// and the connection belongs to the server again, a read sets no deadline:
// one set then could land on the connection while it serves its next request.
// mu orders every deadline this reader sets against that end, and guards the
// state done reads.
type progressReader struct {
	io.ReadCloser
	rc  *http.ResponseController
	d   time.Duration
	cut *cutWatch

	mu     sync.Mutex
	closed bool // the body was closed or the handler returned: set no more deadlines
	ended  bool // a read returned an error, io.EOF included
	failed bool // a read returned an error other than io.EOF
}

func (p *progressReader) Read(b []byte) (int, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return p.ReadCloser.Read(b)
	}
	_ = p.rc.SetReadDeadline(time.Now().Add(p.d))
	p.mu.Unlock()
	n, err := p.ReadCloser.Read(b)
	if err != nil {
		p.mu.Lock()
		p.ended = true
		eof := errors.Is(err, io.EOF)
		if !eof {
			p.failed = true
		}
		if eof && !p.closed {
			_ = p.rc.SetReadDeadline(time.Time{})
		}
		p.mu.Unlock()
		p.cut.read(err)
	}
	return n, err
}

// Close ends the body: no read after it sets a deadline.
func (p *progressReader) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return p.ReadCloser.Close()
}

// finish runs when the handler returns. It stops the reader from setting any
// further deadline and, under the same lock, sets the read deadline the
// server's drain and next request start from: none for a body read to its
// end, one more window for a body still unread, and the one already armed for
// a body whose read failed, so the drain of the rest fails at once and the
// connection closes.
func (p *progressReader) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	switch {
	case p.failed:
		// The armed deadline stays: clearing it would let the server's
		// drain of the unread rest block for good on a stalled peer.
	case !p.ended:
		_ = p.rc.SetReadDeadline(time.Now().Add(p.d))
	default:
		_ = p.rc.SetReadDeadline(time.Time{})
	}
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

// warnGate lets one log line of a kind through per interval and counts the
// lines it drops in between.
type warnGate struct {
	mu         sync.Mutex // guards the fields below
	logged     bool
	last       time.Time
	suppressed int
}

// allow reports whether a line may be logged at now, every being the least
// time between two lines, and how many lines were dropped since the last one.
func (g *warnGate) allow(now time.Time, every time.Duration) (dropped int, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.logged && now.Sub(g.last) < every {
		g.suppressed++
		return 0, false
	}
	dropped = g.suppressed
	g.logged, g.last, g.suppressed = true, now, 0
	return dropped, true
}

// retryAfterSeconds renders d as a whole-second Retry-After value, at least 1.
func retryAfterSeconds(d time.Duration) string {
	s := int((d + time.Second - 1) / time.Second)
	return strconv.Itoa(max(1, s))
}
