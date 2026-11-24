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
)

// This file is what the socket server reads of a user-scope operation's
// error to choose its reply (docs/design/keystore.md § "The socket",
// "Error codes on the socket"), and the server's start step. The refusals
// it names are the store's own unexported states; each predicate matches
// through wrapping and errors.Join.

// errAuditLost marks the ErrCommitted of a change whose audit line could
// not be appended after it committed (appendAudit): the change stands and
// is counted unaudited.
var errAuditLost = errors.New("the change stands, but its audit line was not written")

// StartUserScopes is the server's start step for the user scope: the log
// bounds check, then the delivery catch-up (startUserScopes). Until it has
// run, every user-scope request is refused (UserScopeOff). The socket
// server calls it once, before it serves.
func (s *FileStore) StartUserScopes(ctx context.Context) error {
	return s.startUserScopes(ctx)
}

// ScopesNotCaughtUp reports whether err, from StartUserScopes, is only the
// named scopes the pass could not catch up, with the log bounds check
// passed and every other scope started. Any other error of the step (the
// bounds check failed, or the catch-up failed as a whole) is not, on any
// pass, even when an earlier pass started the user scope.
func ScopesNotCaughtUp(err error) bool { return errors.Is(err, errScopesNotCaughtUp) }

// UserScopesStarted reports whether the start step (StartUserScopes) has
// started the user scope. The step can return an error and still have
// started it: a scope it could not catch up is named in the error while
// every other scope starts.
func (s *FileStore) UserScopesStarted() bool {
	return s.userScopesStarted != nil && s.userScopesStarted.Load()
}

// LogShareRefused reports whether err is one uid's own log refusal: a line
// past that uid's share, or a revocation past the budget it draws on. It
// matches ErrLogFull too, and is never the global append failure
// (AuditFailing): another uid is not refused for it.
func LogShareRefused(err error) bool { return uidLogRefusal(err) }

// AuditLost reports whether err followed a change that committed and
// stands, but whose audit line could not be appended: the socket answers
// ok with the warning "committed; audit failed", and the operation is
// counted (UnauditedOps).
func AuditLost(err error) bool { return Committed(err) && errors.Is(err, errAuditLost) }

// AuditRefused reports whether err refused an operation because its audit
// line could not be appended: a grant, which wrote nothing, or a read,
// which returns no value. A revocation is never refused so (AuditLost).
func AuditRefused(err error) bool {
	return errors.Is(err, errAuditRefused) || errors.Is(err, errReadAuditRefused)
}

// LockBusy reports whether err is the store lock not taken within the
// store's lock wait (Config.LockWait).
func LockBusy(err error) bool { return errors.Is(err, errLockTimeout) }

// UserScopeOff reports whether err is the user scope refused because the
// server's start step has not run (StartUserScopes).
func UserScopeOff(err error) bool { return errors.Is(err, errUserScopesNotStarted) }

// FloorDegraded reports whether err is a grant or read refused because the
// user-scope floor holds damage that could hide this scope's tombstone or
// later sequence, or because the start step quarantined the scope. rm and
// withdraw are never refused so.
func FloorDegraded(err error) bool { return errors.Is(err, errFloorDegraded) }
