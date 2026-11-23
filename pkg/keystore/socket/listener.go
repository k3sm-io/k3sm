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

package socket

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The bounds on connections (docs/design/keystore.md, "Bounds"). A
// connection past either is closed at accept with nothing written.
const (
	// MaxConns is how many connections are served at once, in all.
	MaxConns = 64
	// MaxConnsPerUID is how many of them one peer uid may hold.
	MaxConnsPerUID = 2
)

// The eligible peer uids: login users. Below MinPeerUID are system accounts;
// above MaxPeerUID, nobody among them, no login user, and a signed 32-bit
// reading would turn the uid negative. The service uid is refused too.
const (
	MinPeerUID = 501
	MaxPeerUID = 2147483647
)

// Clock is the listener's time: Now for the rate limit, and After for the
// once-a-minute refusal summary. After returns a channel that receives once
// d has passed and a function that stops it.
type Clock interface {
	Now() time.Time
	After(d time.Duration) (<-chan time.Time, func() bool)
}

// errServed is a second Serve on one Listener.
var errServed = errors.New("keystore socket: the listener is already served")

// Listener admits connections accepted from a listening socket it is given
// and serves each admitted one with a Handler. Admission happens at accept,
// before any byte is read from the peer, and fails closed: a peer whose uid
// is not eligible, a sandboxed peer, or one whose credentials or sandbox
// state cannot be read is refused, its connection closed with nothing
// written and the refusal sent through the per-uid rate limit to the
// RefusalAuditor.
type Listener struct {
	ln         net.Listener
	creds      PeerCredSource
	sandbox    PeerSandboxSource
	serviceUID uint32
	clock      Clock
	refusals   *refusalLimiter
	queue      *auditQueue // between refusals and the auditor; drained by Serve's writer
	h          *Handler
	served     atomic.Bool
	log        *slog.Logger // receives a recovered goroutine panic

	mu     sync.Mutex // guards open and perUID
	open   int
	perUID map[uint32]int
}

// NewListener returns a Listener over ln. Every parameter is required:
// creds reads each accepted connection's peer, sandbox reports whether that
// peer is sandboxed, serviceUID is the uid the server runs as (refused as a
// peer), clock times the refusal summaries, audit receives the refusals and h
// serves each admitted connection.
func NewListener(ln net.Listener, creds PeerCredSource, sandbox PeerSandboxSource, serviceUID uint32, clock Clock, audit RefusalAuditor, h *Handler) (*Listener, error) {
	switch {
	case ln == nil:
		return nil, errors.New("keystore socket: nil listening socket")
	case creds == nil:
		return nil, errors.New("keystore socket: nil peer-credential source")
	case sandbox == nil:
		return nil, errors.New("keystore socket: nil peer-sandbox source")
	case clock == nil:
		return nil, errors.New("keystore socket: nil clock")
	case audit == nil:
		return nil, errors.New("keystore socket: nil refusal auditor")
	case h == nil:
		return nil, errors.New("keystore socket: nil handler")
	}
	q := newAuditQueue(audit, slog.Default())
	refusals := newRefusalLimiter(q, clock.Now)
	q.overflow = refusals.count
	return &Listener{
		ln:         ln,
		creds:      creds,
		sandbox:    sandbox,
		serviceUID: serviceUID,
		clock:      clock,
		refusals:   refusals,
		queue:      q,
		h:          h,
		log:        slog.Default(),
		perUID:     make(map[uint32]int),
	}, nil
}

// Serve accepts until ctx is done or Accept fails, admitting each
// connection and serving each admitted one in its own goroutine. When ctx is
// done Serve closes the listening socket, which ends the pending Accept;
// when Accept fails it leaves the socket open. Either way it cuts the open
// connections, waits for their goroutines, queues the last dropped-count
// summaries, lets the audit writer drain the queue for at most
// AuditDrainWait and returns: nil when ctx is done, the Accept error
// otherwise. A Listener is served once.
//
// The refusal audit runs in one writer goroutine Serve starts and waits
// for: admission only queues a line, so a slow audit append never holds up
// accept.
func (l *Listener) Serve(ctx context.Context) error {
	if !l.served.CompareAndSwap(false, true) {
		return errServed
	}
	l.queue.log = l.log
	writerCtx, stopWriter := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWriter()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer l.recovered("refusal audit")
		l.queue.run(writerCtx)
	}()
	defer l.drainAudit(stopWriter, writerDone)
	stopClose := context.AfterFunc(ctx, func() {
		_ = l.ln.Close() // ends Accept; a close error leaves nothing to undo
	})
	connCtx, cut := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// Every exit, a panic included, stops the close (so it cannot reach a
	// socket a later run reuses), cuts and waits for the connections and
	// queues the last summaries, all before the audit queue is drained.
	defer func() {
		stopClose()
		cut()
		wg.Wait()
		l.refusals.summarize()
	}()
	wg.Go(func() {
		defer l.recovered("refusal summary")
		l.summarizeEvery(connCtx)
	})
	retry := time.Duration(0)
	for {
		c, err := l.ln.Accept()
		if err == nil {
			retry = 0
			l.admit(connCtx, &wg, c)
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		if !transientAcceptError(err) {
			return err
		}
		retry = min(max(2*retry, AcceptRetryMin), AcceptRetryMax)
		if !l.sleep(ctx, retry) {
			return nil
		}
	}
}

// The accept loop's wait after a transient Accept error: AcceptRetryMin,
// doubling on each further one up to AcceptRetryMax, back to the start
// after an Accept succeeds. Neither connections nor the supervisor's
// backoff are touched.
const (
	AcceptRetryMin = 5 * time.Millisecond
	AcceptRetryMax = time.Second
)

// transientAcceptError reports whether err is an Accept error the loop
// waits out: out of descriptors (EMFILE, ENFILE), a connection aborted
// before it was accepted (ECONNABORTED), an interrupted call (EINTR), or a
// net.Error that says it is temporary and is not a deadline (an expired
// deadline is how a paused socket ends Accept).
func transientAcceptError(err error) bool {
	switch {
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE),
		errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.EINTR):
		return true
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, net.ErrClosed):
		return false
	}
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

// sleep waits d on the clock, reporting false when ctx ends it first.
func (l *Listener) sleep(ctx context.Context, d time.Duration) bool {
	tick, stop := l.clock.After(d)
	defer stop()
	select {
	case <-ctx.Done():
		return false
	case <-tick:
		return true
	}
}

// drainAudit closes the audit queue and waits for the writer to drain it,
// for at most AuditDrainWait; past that it cancels the writer, which gives
// up its call in flight (a contextAuditor's) and discards the rest, and
// waits for it to return. Serve defers it, so nothing queues after.
func (l *Listener) drainAudit(stopWriter context.CancelFunc, writerDone <-chan struct{}) {
	close(l.queue.items)
	tick, stop := l.clock.After(AuditDrainWait)
	defer stop()
	select {
	case <-writerDone:
		return
	case <-tick:
	}
	stopWriter()
	<-writerDone
}

// summarizeEvery sends the dropped-count summaries once a minute until ctx
// is done.
func (l *Listener) summarizeEvery(ctx context.Context) {
	for {
		tick, stop := l.clock.After(refusalWindow)
		select {
		case <-ctx.Done():
			stop()
			return
		case <-tick:
		}
		l.refusals.summarize()
	}
}

// admit refuses c, closes it over a cap, or serves it until it ends or ctx
// is done.
func (l *Listener) admit(ctx context.Context, wg *sync.WaitGroup, c net.Conn) {
	// A panic deciding admission closes c before it goes on to end the
	// run, so the connection is never left open.
	served := false
	defer func() {
		if !served {
			if v := recover(); v != nil {
				_ = c.Close() // never admitted: nothing was written
				panic(v)
			}
		}
	}()
	uid, reason := l.check(c)
	if reason != "" {
		_ = c.Close() // refused: nothing was written, nothing is owed
		l.refusals.refuse(uid, reason)
		return
	}
	if !l.acquire(uid) {
		_ = c.Close() // over a cap: nothing was written, nothing is owed
		return
	}
	served = true
	wg.Go(func() {
		// A panic serving one connection ends that connection only: it is
		// recovered here, after the deferred close and release have run.
		defer l.recovered("connection")
		defer l.release(uid)
		defer func() { _ = c.Close() }() // the connection is over either way
		// How the connection ended is its own business: a client that
		// closes, breaks the protocol or times out has been answered or cut.
		_ = l.h.Serve(ctx, c)
	})
}

// recovered, deferred at the top of a goroutine the Listener starts, stops
// a panic there and logs it, so it never reaches the process.
func (l *Listener) recovered(what string) {
	if v := recover(); v != nil {
		l.log.Error("keystore socket: recovered a panic", "goroutine", what, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
	}
}

// check reads c's peer and returns the reason it is refused, or "" for an
// eligible peer, with the uid a refusal names. The uid range is judged as
// soon as a uid is read, before anything read after it, so an ineligible
// peer is refused under its own uid even when a later read fails; an
// eligible uid whose later reads fail is refused as cred-unreadable under
// that uid, and NoUID is named only when no uid was read. The token must
// then name the uid and pid read beside it.
func (l *Listener) check(c net.Conn) (uint32, string) {
	pc, err := l.creds.PeerCred(c)
	if !pc.UIDRead {
		return NoUID, ReasonCredUnreadable // a source that read no uid fails closed, error or not
	}
	if reason := uidRefusal(pc.UID, l.serviceUID); reason != "" {
		return pc.UID, reason
	}
	if err != nil {
		return pc.UID, ReasonCredUnreadable
	}
	if pc.TokenEUID != pc.UID || pc.TokenPID != pc.PID {
		return pc.UID, ReasonTokenMismatch
	}
	sandboxed, err := l.sandbox.Sandboxed(pc.Token)
	if err != nil {
		return pc.UID, ReasonSandboxUnknown
	}
	if sandboxed {
		return pc.UID, ReasonSandboxed
	}
	return pc.UID, ""
}

// uidRefusal returns the reason uid is not an eligible peer, or "".
func uidRefusal(uid, serviceUID uint32) string {
	switch {
	case uid == 0:
		return ReasonRoot
	case uid == serviceUID:
		return ReasonServiceUID
	case uid < MinPeerUID:
		return ReasonSystemUID
	case uid > MaxPeerUID:
		return ReasonHighUID
	}
	return ""
}

// acquire takes a connection slot for uid, or reports a cap reached.
func (l *Listener) acquire(uid uint32) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open >= MaxConns || l.perUID[uid] >= MaxConnsPerUID {
		return false
	}
	l.open++
	l.perUID[uid]++
	return true
}

// release gives back uid's slot.
func (l *Listener) release(uid uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	if l.perUID[uid]--; l.perUID[uid] == 0 {
		delete(l.perUID, uid)
	}
}
