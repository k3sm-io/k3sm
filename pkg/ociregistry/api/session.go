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

package api

import (
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
)

// The upload session state machine.
//
// A session lives on disk as a plain file whose length is its offset (the
// store owns that file and serialises operations on it with a flock). The
// server keeps, per session it has seen, only what makes the next request
// cheaper and bounded:
//
//	hashing:  the running sha256 of the file's first n bytes is known; a
//	          chunk appended at offset n extends it while the bytes stream.
//	unhashed: the running state is lost (a restart, a session another
//	          process wrote, or an append that failed part-way); the commit
//	          hashes the file again.
//
// A new session starts hashing at n = 0. An append keeps hashing only when it
// succeeded and started exactly at n; any other outcome moves the session to
// unhashed, which it never leaves. A commit or a cancel removes the entry.
// Being wrong in the unhashed direction costs a re-read; the hashing state is
// trusted only for bytes appended through it, and the store checks again at
// commit that the file is still exactly n bytes with one link.

// hashState is the running hash of a session's first n bytes; h is nil once
// the state is lost.
type hashState struct {
	h hash.Hash
	n int64
	// teed counts the bytes the current append fed to h.
	teed int64
}

func newHashState() hashState { return hashState{h: sha256.New()} }

// writer returns where the current append's bytes are teed: the running hash,
// or nothing once the state is lost.
func (s *hashState) writer() io.Writer {
	s.teed = 0
	if s.h == nil {
		return io.Discard
	}
	return hashWriter{s}
}

type hashWriter struct{ s *hashState }

func (w hashWriter) Write(p []byte) (int, error) {
	w.s.teed += int64(len(p))
	return w.s.h.Write(p)
}

// settle records an append's outcome: newLen is the session length the store
// reported after it, err its error. The state survives only an append that
// succeeded and started at n, or one that failed before reading a byte.
func (s *hashState) settle(newLen int64, err error) {
	if s.h == nil {
		return
	}
	switch {
	case err != nil && s.teed == 0:
		// Refused before the body was read (an offset mismatch): the file
		// and the hash are unchanged.
	case err == nil && newLen-s.teed == s.n:
		s.n = newLen
	default:
		s.lose()
	}
	s.teed = 0
}

// lose moves the state to unhashed.
func (s *hashState) lose() {
	s.h = nil
	s.n = 0
	s.teed = 0
}

// sum returns the digest of the first n bytes in algorithm alg, and false when
// it is not known (state lost, or a different algorithm).
func (s *hashState) sum(alg digest.Algorithm) (digest.Digest, int64, bool) {
	if s.h == nil || alg != digest.SHA256 {
		return "", 0, false
	}
	// Sum appends to its argument and leaves the running state unchanged.
	return digest.NewDigestFromBytes(digest.SHA256, s.h.Sum(nil)), s.n, true
}

// errTooManySessions is a new session refused because MaxSessions are in use.
var errTooManySessions = errors.New("too many upload sessions")

// sessions is the table of upload sessions this server has seen. mu guards the
// map and each entry's busy, last and confirmed fields; an entry's own mu
// serialises the requests on that session and guards its hash state. Lock
// order: an entry's mu is never taken while the table's mu is held.
//
// Only confirmed entries count against max: a session this server created,
// or one the store has accepted an operation on. An entry acquire creates for
// an id the server has not seen is unconfirmed until then, and the caller
// drops it on a store error, so ids a client makes up cannot fill the table.
// There is no per-principal cap: one client may use every slot.
type sessions struct {
	max  int
	idle time.Duration
	now  func() time.Time

	mu       sync.Mutex
	m        map[string]*session
	reserved int
}

type session struct {
	mu   sync.Mutex
	hash hashState

	// Guarded by sessions.mu.
	busy      int
	last      time.Time
	confirmed bool
}

func newSessions(max int, idle time.Duration, now func() time.Time) *sessions {
	return &sessions{max: max, idle: idle, now: now, m: map[string]*session{}}
}

// prune drops entries idle longer than the idle bound. The caller holds mu.
func (t *sessions) prune() {
	cut := t.now().Add(-t.idle)
	for k, e := range t.m {
		if e.busy == 0 && e.last.Before(cut) {
			delete(t.m, k)
		}
	}
}

// inUse counts the confirmed entries and the reserved slots. The caller
// holds mu.
func (t *sessions) inUse() int {
	n := t.reserved
	for _, e := range t.m {
		if e.confirmed {
			n++
		}
	}
	return n
}

// admit reserves a slot for a new session, refusing with errTooManySessions
// when max sessions are in use or reserved. The entry is returned locked and
// is not yet in the table; bind adds it under the session's key once the
// session exists, abandon gives the slot back. release unlocks it.
func (t *sessions) admit() (*session, func(), error) {
	t.mu.Lock()
	t.prune()
	if t.inUse() >= t.max {
		t.mu.Unlock()
		return nil, nil, errTooManySessions
	}
	t.reserved++
	e := &session{hash: newHashState(), busy: 1, last: t.now(), confirmed: true}
	t.mu.Unlock()
	e.mu.Lock()
	return e, t.releaser(e), nil
}

// bind adds an admitted entry under key.
func (t *sessions) bind(key string, e *session) {
	t.mu.Lock()
	t.reserved--
	t.m[key] = e
	t.mu.Unlock()
}

// abandon gives back an admitted entry's slot.
func (t *sessions) abandon() {
	t.mu.Lock()
	t.reserved--
	t.mu.Unlock()
}

// acquire returns the entry for key locked; release unlocks it. A key the
// server has not seen gets a new unhashed, unconfirmed entry.
func (t *sessions) acquire(key string) (*session, func()) {
	t.mu.Lock()
	e, ok := t.m[key]
	if !ok {
		e = &session{}
		t.m[key] = e
	}
	e.busy++
	e.last = t.now()
	t.mu.Unlock()
	e.mu.Lock()
	return e, t.releaser(e)
}

func (t *sessions) releaser(e *session) func() {
	return func() {
		e.mu.Unlock()
		t.mu.Lock()
		e.busy--
		e.last = t.now()
		t.mu.Unlock()
	}
}

// confirm marks e as a session the store holds.
func (t *sessions) confirm(e *session) {
	t.mu.Lock()
	e.confirmed = true
	t.mu.Unlock()
}

// isConfirmed reports whether e is confirmed.
func (t *sessions) isConfirmed(e *session) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return e.confirmed
}

// forget removes key's entry: the session was committed, cancelled or is gone.
func (t *sessions) forget(key string) {
	t.mu.Lock()
	delete(t.m, key)
	t.mu.Unlock()
}

// drop removes key's entry only while it is still e, so a request that
// fails late never removes an entry a newer request created.
func (t *sessions) drop(key string, e *session) {
	t.mu.Lock()
	if t.m[key] == e {
		delete(t.m, key)
	}
	t.mu.Unlock()
}
