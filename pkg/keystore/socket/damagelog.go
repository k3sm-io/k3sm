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
	"sync"
	"time"

	keyentry "k3sm.io/apis/keystore/entry"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/internal/strictjson"
)

// A damage class: what the server's log says of a store error that is
// damage, from a closed set, with a fixed remedy each. The error's own
// text is never logged: a chain can carry text a decoder built from what
// it decrypted.
const (
	DamageOrphanVersion     = "orphan-version"
	DamageFloorRecordsEntry = "floor-records-entry"
	DamageFloorDegraded     = "floor-degraded"
	DamageCorrupt           = "corrupt"
	DamageUnsupportedKind   = "unsupported-kind"
	DamageScopeIncomplete   = "scope-incomplete"
	DamageInternal          = "internal"
)

// damageRemedies is each class's fixed remedy, the only text a line
// carries beside its class.
var damageRemedies = map[string]string{
	DamageOrphanVersion:     "a sealed version lies above the entry's current pointer; the scope's owner can rm the entry and put its value again",
	DamageFloorRecordsEntry: "the floor still records the entry but its directory is missing (a restored or rolled-back keystore); root runs sudo k3sm doctor",
	DamageFloorDegraded:     "the user-scope floor holds damage, or the start step quarantined the scope; grants and reads are refused, rm still runs; root runs sudo k3sm doctor",
	DamageCorrupt:           "a record of the entry fails authentication or does not parse; restore it from backup, or rm the entry and put its value again",
	DamageUnsupportedKind:   "a record of the entry has a kind or envelope version this build cannot read, written by a newer k3sm or altered to read as one; upgrade k3sm, and if it is already current, restore the entry from backup or rm the entry and put its value again",
	DamageScopeIncomplete:   "part of the user scope is missing (a scope.key with no entries/ directory or deliveries record beside it, or entries with no scope.key), as a partial restore leaves; root restores the whole scope from one backup, or runs sudo k3sm keys rm-scope user/<uid> --yes and then sudo k3sm keys floor --rebuild, after which the owner puts its values again",
	DamageInternal:          "the store could not serve the request (a missing or untrusted master key, or another failure only root can repair); root runs sudo k3sm doctor",
}

// damageClass is err's class when it is damage, and "" when it is not:
// the ordinary outcomes (not-found, exists, quota, rate-limited, busy,
// log-full, the socket's own refusals), a change that committed, and a
// cancelled or timed-out request, which is the server stopping or the
// request's bound, not damage.
//
// The class is judged inside the reply outcomeOf gives err, so the two
// never disagree on an error whose chain matches more than one sentinel:
// a chain that is both the floor's damage and ErrCorrupt answers internal
// and logs corrupt, and one that is both ErrOrphanVersion and ErrNotFound
// answers not-found and logs nothing. An incomplete scope answers
// not-found and logs scope-incomplete; an interrupted put, which also
// answers not-found, is a put that never committed and is not damage.
func damageClass(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ""
	}
	switch code, _ := outcomeOf(err); code {
	case CodeInternal:
		switch {
		case errors.Is(err, keystore.ErrFloorRecordsEntry):
			return DamageFloorRecordsEntry
		case errors.Is(err, keystore.ErrKindUnsupported):
			// Before ErrCorrupt: a typed decode can wrap an unsupported
			// envelope version in ErrCorrupt, and its repair is an upgrade,
			// never the corrupt class's rm and put.
			return DamageUnsupportedKind
		case errors.Is(err, keystore.ErrCorrupt):
			return DamageCorrupt
		}
		return DamageInternal
	case CodeNotFound:
		// The answer stays not-found: nothing on the socket path deletes on
		// it. Only the absence of a scope's part beside the rest is damage;
		// a uid with no scope yet is not.
		if keystore.ScopeIncomplete(err) {
			return DamageScopeIncomplete
		}
	case CodeRefused:
		switch {
		case errors.Is(err, keystore.ErrOrphanVersion):
			return DamageOrphanVersion
		case keystore.FloorDegraded(err):
			return DamageFloorDegraded
		}
	}
	return ""
}

// DamageLogInterval is how often one (uid, op, class) key may log a line;
// the lines it suppresses meanwhile are counted on its next one.
const DamageLogInterval = 10 * time.Second

// damageLimiter passes at most one line per (uid, op, class) key each
// DamageLogInterval and counts the rest, so one uid's standing damage
// never suppresses another uid's line. Its keys are bounded: op is one of
// the Handler's registered operations and class one of the closed set, so
// one uid holds a few dozen at most, and maxDamageKeys caps them across
// uids: a new key past it evicts the key whose last line is the oldest.
type damageLimiter struct {
	mu   sync.Mutex
	keys map[damageKey]*damageCount
	// evicted is the lines suppressed under keys evicted since a line last
	// passed, which the next line to pass reports.
	evicted uint64
}

type damageKey struct {
	uid       uint32
	op, class string
}

type damageCount struct {
	last       time.Time
	suppressed uint64
}

// maxDamageKeys caps the limiter's keys. An evicted key's next line passes
// at once and carries no suppressed figure: the count it suppressed since
// its last line moves to the limiter's evicted total, which the next line
// to pass, of any key, reports. The cap bounds memory, and a uid's lines
// stay bounded by its request rate.
const maxDamageKeys = 1024

// pass reports whether a line for k may be logged at now, with the count
// suppressed since the key's last line and the count suppressed under keys
// evicted since the last line passed.
func (l *damageLimiter) pass(k damageKey, now time.Time) (ok bool, suppressed, evicted uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.keys == nil {
		l.keys = make(map[damageKey]*damageCount)
	}
	c, ok := l.keys[k]
	if !ok {
		if len(l.keys) >= maxDamageKeys {
			l.evictOldest()
		}
		c = &damageCount{}
		l.keys[k] = c
	} else if now.Sub(c.last) < DamageLogInterval {
		c.suppressed++
		return false, 0, 0
	}
	n, e := c.suppressed, l.evicted
	c.last, c.suppressed, l.evicted = now, 0, 0
	return true, n, e
}

// evictOldest drops the key whose last line is the oldest. l.mu is held.
func (l *damageLimiter) evictOldest() {
	var (
		oldest damageKey
		at     time.Time
		found  bool
	)
	for k, c := range l.keys {
		if !found || c.last.Before(at) {
			oldest, at, found = k, c.last, true
		}
	}
	if found {
		l.evicted += l.keys[oldest].suppressed
	}
	delete(l.keys, oldest)
}

// logStoreError logs err, op's error for p, at Warn when it is damage,
// at most once per uid, op and class each DamageLogInterval: the op, the
// peer's uid, the entry the request named when it is a valid name
// (requested_entry), the class and its fixed remedy, the lines suppressed
// under the whole key since its last line (suppressed: any entry the key's
// requests named, not only the one this line names), and the lines
// suppressed under keys evicted since a line last passed (evicted). Never the error's text, a value or a
// value's length.
func (h *Handler) logStoreError(op string, p Peer, header []byte, err error) {
	class := damageClass(err)
	if class == "" {
		return
	}
	ok, suppressed, evicted := h.dmg.pass(damageKey{uid: p.UID, op: op, class: class}, h.now())
	if !ok {
		return
	}
	attrs := []any{"op", op, "uid", p.UID}
	if e, ok := requestEntry(header); ok {
		attrs = append(attrs, "requested_entry", e)
	}
	attrs = append(attrs, "class", class, "remedy", damageRemedies[class])
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	if evicted > 0 {
		attrs = append(attrs, "evicted", evicted)
	}
	h.log.Warn("keystore socket: the store reports damage", attrs...)
}

// logPanicked logs, at Error, an operation that panicked, before the panic
// goes on to the listener, which recovers it and logs its stack: the op,
// the peer's uid and requested_entry when the header names a valid entry.
// It is how an operation the store counted unaudited for a panic
// (keystore.FileStore.UnauditedOps) is told apart. It does not recover.
func (h *Handler) logPanicked(op string, p Peer, header []byte) {
	attrs := []any{"op", op, "uid", p.UID}
	if e, ok := requestEntry(header); ok {
		attrs = append(attrs, "requested_entry", e)
	}
	h.log.Error("keystore socket: an operation panicked", attrs...)
}

// requestEntry is the entry a request header names, read by its exact
// name, when it is a valid entry name in the API grammar; nothing else of
// the header is read.
func requestEntry(header []byte) (string, bool) {
	fields, err := strictjson.Object(header, "entry")
	if err != nil {
		return "", false
	}
	var s string
	if decodeField(fields["entry"], &s) != nil || s == "" {
		return "", false
	}
	e, err := keyentry.Parse(s)
	if err != nil {
		return "", false
	}
	return e.String(), true
}
