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
	DamageInternal          = "internal"
)

// damageRemedies is each class's fixed remedy, the only text a line
// carries beside its class.
var damageRemedies = map[string]string{
	DamageOrphanVersion:     "a sealed version lies above the entry's current pointer; the scope's owner can rm the entry and put its value again",
	DamageFloorRecordsEntry: "the floor still records the entry but its directory is missing (a restored or rolled-back keystore); root runs sudo k3sm doctor",
	DamageFloorDegraded:     "the user-scope floor holds damage, or the start step quarantined the scope; grants and reads are refused, rm still runs; root runs sudo k3sm doctor",
	DamageCorrupt:           "a record of the entry fails authentication or does not parse; restore it from backup, or rm the entry and put its value again",
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
// answers not-found and logs nothing.
func damageClass(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ""
	}
	switch code, _ := outcomeOf(err); code {
	case CodeInternal:
		switch {
		case errors.Is(err, keystore.ErrFloorRecordsEntry):
			return DamageFloorRecordsEntry
		case errors.Is(err, keystore.ErrCorrupt):
			return DamageCorrupt
		}
		return DamageInternal
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
}

type damageKey struct {
	uid       uint32
	op, class string
}

type damageCount struct {
	last       time.Time
	suppressed uint64
}

// maxDamageKeys caps the limiter's keys. An evicted key loses the count it
// suppressed since its last line, and its next line passes at once: the
// cap bounds memory, and a uid's lines stay bounded by its request rate.
const maxDamageKeys = 1024

// pass reports whether a line for k may be logged at now, with the count
// suppressed since the key's last line.
func (l *damageLimiter) pass(k damageKey, now time.Time) (bool, uint64) {
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
		return false, 0
	}
	n := c.suppressed
	c.last, c.suppressed = now, 0
	return true, n
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
	delete(l.keys, oldest)
}

// logStoreError logs err, op's error for p, at Warn when it is damage,
// at most once per uid, op and class each DamageLogInterval: the op, the
// peer's uid, the entry the request named when it is a valid name
// (requested_entry), the class and its fixed remedy, and the lines
// suppressed since the key's last. Never the error's text, a value or a
// value's length.
func (h *Handler) logStoreError(op string, p Peer, header []byte, err error) {
	class := damageClass(err)
	if class == "" {
		return
	}
	ok, suppressed := h.dmg.pass(damageKey{uid: p.UID, op: op, class: class}, h.now())
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
	h.log.Warn("keystore socket: the store reports damage", attrs...)
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
