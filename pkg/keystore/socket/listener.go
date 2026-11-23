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
	"net"
	"sync"
	"sync/atomic"
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
	h          *Handler
	served     atomic.Bool

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
	return &Listener{
		ln:         ln,
		creds:      creds,
		sandbox:    sandbox,
		serviceUID: serviceUID,
		clock:      clock,
		refusals:   newRefusalLimiter(audit, clock.Now),
		h:          h,
		perUID:     make(map[uint32]int),
	}, nil
}

// Serve accepts until ctx is done or Accept fails, admitting each
// connection and serving each admitted one in its own goroutine. When ctx is
// done Serve closes the listening socket, which ends the pending Accept;
// when Accept fails it leaves the socket open. Either way it cuts the open
// connections, waits for their goroutines, writes the last dropped-count
// summaries and returns: nil when ctx is done, the Accept error otherwise.
// A Listener is served once.
func (l *Listener) Serve(ctx context.Context) error {
	if !l.served.CompareAndSwap(false, true) {
		return errServed
	}
	stopClose := context.AfterFunc(ctx, func() {
		_ = l.ln.Close() // ends Accept; a close error leaves nothing to undo
	})
	connCtx, cut := context.WithCancel(ctx)
	defer cut()
	var wg sync.WaitGroup
	wg.Go(func() { l.summarizeEvery(connCtx) })
	var err error
	for {
		c, aerr := l.ln.Accept()
		if aerr != nil {
			err = aerr
			break
		}
		l.admit(connCtx, &wg, c)
	}
	stopClose()
	cut()
	wg.Wait()
	l.refusals.summarize()
	if ctx.Err() != nil {
		return nil
	}
	return err
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
	wg.Go(func() {
		defer l.release(uid)
		defer func() { _ = c.Close() }() // the connection is over either way
		// How the connection ended is its own business: a client that
		// closes, breaks the protocol or times out has been answered or cut.
		_ = l.h.Serve(ctx, c)
	})
}

// check reads c's peer and returns the reason it is refused, or "" for an
// eligible peer, with the uid a refusal names.
func (l *Listener) check(c net.Conn) (uint32, string) {
	pc, err := l.creds.PeerCred(c)
	if err != nil {
		return NoUID, ReasonCredUnreadable
	}
	if reason := uidRefusal(pc.UID, l.serviceUID); reason != "" {
		return pc.UID, reason
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
