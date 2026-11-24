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
	"errors"

	"k3sm.io/k3sm/pkg/keystore"
)

// WarnAuditFailed is the warning of an ok reply to a change that committed
// but whose audit line could not be appended (docs/design/keystore.md §
// "The audit log": audit before reply).
const WarnAuditFailed = "committed; audit failed"

// ErrRateLimited is a request past its uid's rate limit; it is answered
// rate-limited and the connection stays open.
var ErrRateLimited = errors.New("keystore socket: the uid's rate limit is reached")

// outcomeOf maps an operation's error to its reply: the error code, or ""
// for an ok reply, with the warning the ok reply carries. The table is the
// design's (docs/design/keystore.md § "The socket", "Store errors on the
// wire"); every store error maps to one code of the closed set, and an
// error the table does not name is internal.
func outcomeOf(err error) (Code, string) {
	switch {
	case err == nil:
		return "", ""
	case keystore.Committed(err):
		// The change stands, so the reply is ok; ErrCommitted matches no
		// other sentinel of the store, whatever its cause.
		if keystore.AuditLost(err) {
			return "", WarnAuditFailed
		}
		return "", ""
	case errors.Is(err, ErrBusy), keystore.LockBusy(err):
		return CodeBusy, ""
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited, ""
	case errors.Is(err, keystore.ErrLogFull):
		// The uid's own share or budget (keystore.LogShareRefused), or the
		// log past its hard cap; checked before AuditRefused, which wraps
		// the append's own error, and before ErrRequestRefused, so the
		// fail-closed refusal past the hard cap (ErrAuditFailingFull) is
		// log-full.
		return CodeLogFull, ""
	case keystore.UserScopeOff(err):
		return CodeUserScopeOff, ""
	case errors.Is(err, keystore.ErrNotFound), errors.Is(err, keystore.ErrVersionNotFound), errors.Is(err, keystore.ErrScopeAbsent):
		return CodeNotFound, ""
	case errors.Is(err, keystore.ErrQuota):
		return CodeQuota, ""
	case errors.Is(err, keystore.ErrScopeOwnerChanged):
		return CodeScopeOwnerChanged, ""
	case errors.Is(err, keystore.ErrScopeOwnerUnknown):
		return CodeScopeOwnerUnknown, ""
	case errors.Is(err, ErrRequestRefused),
		keystore.AuditRefused(err),
		errors.Is(err, keystore.ErrExists),
		errors.Is(err, keystore.ErrInvalidName),
		errors.Is(err, keystore.ErrKindMismatch),
		errors.Is(err, keystore.ErrTypedCredential),
		errors.Is(err, keystore.ErrRewrapInProgress),
		errors.Is(err, keystore.ErrOrphanVersion),
		keystore.IneligibleUID(err),
		keystore.FloorDegraded(err):
		return CodeRefused, ""
	}
	return CodeInternal, ""
}
