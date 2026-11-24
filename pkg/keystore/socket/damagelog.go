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
func damageClass(err error) string {
	switch {
	case err == nil, keystore.Committed(err),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ""
	case errors.Is(err, keystore.ErrOrphanVersion):
		return DamageOrphanVersion
	case errors.Is(err, keystore.ErrFloorRecordsEntry):
		return DamageFloorRecordsEntry
	case keystore.FloorDegraded(err):
		return DamageFloorDegraded
	case errors.Is(err, keystore.ErrCorrupt):
		return DamageCorrupt
	}
	if code, _ := outcomeOf(err); code == CodeInternal {
		return DamageInternal
	}
	return ""
}

// DamageLogInterval is how often one (op, class) pair may log a line;
// the lines it suppresses meanwhile are counted on its next one.
const DamageLogInterval = 10 * time.Second

// damageLimiter passes at most one line per (op, class) pair each
// DamageLogInterval and counts the rest. Its pairs are bounded: op is one
// of the Handler's registered operations and class one of the closed set,
// and maxDamageKeys caps them besides.
type damageLimiter struct {
	mu   sync.Mutex
	keys map[damageKey]*damageCount
}

type damageKey struct{ op, class string }

type damageCount struct {
	last       time.Time
	suppressed uint64
}

// maxDamageKeys caps the limiter's pairs; a pair past it is suppressed
// unlogged and uncounted, which the closed sets never reach.
const maxDamageKeys = 64

// pass reports whether a line for k may be logged at now, with the count
// suppressed since the pair's last line.
func (l *damageLimiter) pass(k damageKey, now time.Time) (bool, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.keys == nil {
		l.keys = make(map[damageKey]*damageCount)
	}
	c, ok := l.keys[k]
	if !ok {
		if len(l.keys) >= maxDamageKeys {
			return false, 0
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

// logStoreError logs err, op's error for p, at Warn when it is damage,
// at most once per op and class each DamageLogInterval: the op, the
// peer's uid, the entry the request named when it is a valid name
// (requested_entry), the class and its fixed remedy, and the lines
// suppressed since the pair's last. Never the error's text, a value or a
// value's length.
func (h *Handler) logStoreError(op string, p Peer, header []byte, err error) {
	class := damageClass(err)
	if class == "" {
		return
	}
	ok, suppressed := h.dmg.pass(damageKey{op, class}, h.now())
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
