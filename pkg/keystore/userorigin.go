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

package keystore

import (
	"errors"
	"sync/atomic"
)

// This file is where a user-scope operation's audit line learns where the
// operation came from, and the store's account of the audit appends that
// failed (docs/design/keystore.md § "The audit log": fields, audit before
// reply, fail closed).

// Origin is the path a user-scope operation came by and the peer that sent
// it, for the operation's audit line: its via and its caller. The zero
// Origin is an operation inside this package (a test, the start step's
// catch-up), whose lines carry neither.
type Origin struct {
	via string
	pid int32
}

// SocketOrigin is the Origin of an operation that arrived on the user
// socket: its lines carry via "socket" and the caller, the peer's uid (the
// scope's own, since a view serves only its uid) and pid. The pid is
// advisory, read with the peer credentials at accept and reusable; zero or
// a negative pid writes none.
func SocketOrigin(pid int32) Origin {
	return Origin{via: auditViaSocket, pid: max(pid, 0)}
}

// WithOrigin returns a copy of the view whose operations state o in their
// audit lines. The socket takes one per request, so each operation carries
// its own peer; the view it was taken from is unchanged.
func (u *UserScope) WithOrigin(o Origin) *UserScope {
	c := *u
	c.origin = o
	return &c
}

// stamp sets l's scope, and its via and caller from the view's origin.
func (u *UserScope) stamp(l auditLine) auditLine {
	l.scope = u.scope
	if u.origin.via != "" {
		l.via = u.origin.via
		l.caller = &auditCaller{UID: u.uid, PID: u.origin.pid}
	}
	return l
}

// audit appends l, stamped, to the audit sink, and records the outcome in
// the store's audit state: a success ends a global failure; a failure that
// is not one uid's own share or budget (uidLogRefusal) starts one.
func (u *UserScope) audit(l auditLine) error {
	err := u.s.auditSink.append(u.stamp(l))
	u.s.audit.note(err)
	return err
}

// auditState is the store's in-memory account of its audit appends:
// whether appends are failing for everyone (a full disk, an I/O error, the
// hard cap), and how many committed operations went unaudited. A pointer on
// FileStore, so a copy of the store shares it; New allocates it.
type auditState struct {
	failing   atomic.Bool
	unaudited atomic.Uint64
}

// note records an append's outcome. A share or revocation-budget refusal is
// one uid's state alone and changes nothing here (docs/design/keystore.md §
// "Per-uid fairness": a share refusal is one uid's alone).
func (a *auditState) note(err error) {
	if a == nil {
		return
	}
	switch {
	case err == nil:
		a.failing.Store(false)
	case !uidLogRefusal(err):
		a.failing.Store(true)
	}
}

// countUnaudited counts one committed operation whose audit line was not
// written: a revocation (rm, rotate, withdraw) that commits first and
// appends after, and goes ahead while appends fail.
func (a *auditState) countUnaudited() {
	if a != nil {
		a.unaudited.Add(1)
	}
}

// UnauditedOps is the number of committed user-scope operations whose audit
// line could not be written since the store was made: the count doctor
// shows (U112). It is kept in memory, as the design states.
func (s *FileStore) UnauditedOps() uint64 {
	if s.audit == nil {
		return 0
	}
	return s.audit.unaudited.Load()
}

// AuditFailing reports whether the last user-scope audit append failed for
// a cause that is not one uid's own share or budget: the global append
// failure, during which every uid's mutations and reads are refused and
// only revocations go ahead. The next append that succeeds clears it.
func (s *FileStore) AuditFailing() bool {
	return s.audit != nil && s.audit.failing.Load()
}

// uidLogRefusal reports whether err is one uid's own log refusal: its share
// spent (errShareSpent), or the revocation budget a line draws on spent
// (errBudgetSpent). Each matches ErrLogFull too; neither is the global
// append failure.
func uidLogRefusal(err error) bool {
	return errors.Is(err, errShareSpent) || errors.Is(err, errBudgetSpent)
}
