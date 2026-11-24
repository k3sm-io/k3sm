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
	"context"
	"errors"
	"fmt"
	"slices"
)

// This file is the post-frame refused line: the audit line of a request
// the socket refused itself, after the peer was admitted and before the
// store was called (docs/design/keystore.md § "The audit log", refused
// lines). Its fields are the view's origin (via socket, the caller's uid
// and pid), the peer's own scope, the operation refused and the reason,
// each from a closed set, and never a value, an entry name or any other
// text the peer sent. It is charged to the caller's share like every line
// of its uid, and is not in the revocation class.

// The reasons a request is refused by the socket after its first frame:
// a closed set.
const (
	RefusedBadHeader    = "bad-header"    // a header field of the wrong type, a kind the socket does not store, a header over its cap
	RefusedBadValue     = "bad-value"     // a value missing, empty, oversize, or where the operation takes none
	RefusedNotServed    = "not-served"    // an operation the server does not serve yet
	RefusedRateLimited  = "rate-limited"  // past the uid's rate limit
	RefusedAuditFailing = "audit-failing" // the fail-closed rule: appends fail for everyone
	// RefusedIneligibleUID is a peer the listener admitted whose uid the
	// store gives no user scope (outside the login range, or the store's
	// own service uid): written by RefusedIneligible.
	RefusedIneligibleUID = "ineligible-uid"
)

// refusedReasons and refusedOps are the closed sets a post-frame refused
// line takes: the reasons above, and the operations named as the audit log
// names them (read-for-exec as exec-read).
var (
	refusedReasons = []string{RefusedBadHeader, RefusedBadValue, RefusedNotServed, RefusedRateLimited, RefusedAuditFailing, RefusedIneligibleUID}
	refusedOps     = []string{"put", "rotate", "rm", "list", "exec-read", "deliver", "withdraw", "deliveries"}
)

// errRefusedField is a post-frame refused line asked for with an operation
// or reason outside its closed set: nothing is written.
var errRefusedField = errors.New("a refused line names an operation or reason outside its closed set")

// Refused appends the post-frame refused line of op, refused for reason,
// under the store lock taken for the append alone. op is the audit log's
// name of the operation (put, rotate, rm, list, exec-read, deliver,
// withdraw, deliveries) and reason one of the Refused* constants; anything
// else writes nothing. A line past the caller's share is not written
// (LogShareRefused); the caller counts it dropped. Its append's outcome is
// the store's audit state's like any other: one that succeeds ends the
// global append failure.
func (u *UserScope) Refused(ctx context.Context, op, reason string) error {
	if !slices.Contains(refusedOps, op) || !slices.Contains(refusedReasons, reason) {
		return errRefusedField
	}
	return u.appendBriefly(ctx, auditLine{op: auditOpRefused, request: op, result: reason})
}

// RefusedIneligible appends the post-frame refused line of op for uid, a
// peer the socket admitted that has no user scope (IneligibleUID), with
// pid as its caller's: reason RefusedIneligibleUID, under the store lock
// taken for the append alone. It names no scope, as uid has none, so it
// is charged to no uid's share; the socket rate-limits it per uid like
// every refused line. op is as for Refused; anything else writes nothing.
func (s *FileStore) RefusedIneligible(ctx context.Context, uid uint32, pid int32, op string) error {
	if !slices.Contains(refusedOps, op) {
		return errRefusedField
	}
	u := &UserScope{s: s, uid: uid, origin: SocketOrigin(pid)}
	return u.appendBriefly(ctx, auditLine{op: auditOpRefused, request: op, result: RefusedIneligibleUID})
}

// RefusedDropped appends the summary of n post-frame refused lines of the
// view's uid that were not written (its rate limit, its share, a failed
// append) since its last summary: a refused line with result dropped and
// the count. n of zero writes nothing.
func (u *UserScope) RefusedDropped(ctx context.Context, n uint64) error {
	if n == 0 {
		return nil
	}
	return u.appendBriefly(ctx, auditLine{op: auditOpRefused, result: auditResultDropped, dropped: n})
}

// appendBriefly appends l, stamped, under the exclusive store lock taken
// for the append alone. A line for which the lock cannot be had is not
// written, as for auditBriefly.
func (u *UserScope) appendBriefly(ctx context.Context, l auditLine) error {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	_, done, err := u.s.openLocked(ctx, false, true)
	if err != nil {
		return fmt.Errorf("a refused line: %w", err)
	}
	defer done()
	return u.audit(l)
}
