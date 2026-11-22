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
	"bytes"
	"log/slog"
	"strings"

	"golang.org/x/sys/unix"
)

// The floor's damage is scoped (docs/design/keystore.md § "The user-scope
// floor", "Damage and taint"). Every damaged line the reader skips, a torn
// last line included, is classified by what it could have been:
//
//   - a taint on (scope, name), when its leading fields parse strictly as
//     "<scope> <name> " and the rest is a prefix of a generation: lowercase
//     hex, under 32 digits;
//   - a taint on (scope, name, generation), when the rest is a whole
//     generation of 32 lowercase hex digits, then nothing, or a space and
//     nothing, "r" or "rm" (a tombstone's prefix), or a canonical decimal
//     prefix of at most 20 digits (a live line's);
//   - a taint on a name prefix, when the line is "<scope> <partial>": the
//     scope parses with its space and partial, with no space, is a prefix of
//     the delivery record's name or of a valid entry name; it covers every
//     name of the scope that starts with partial;
//   - a taint on a scope prefix, when the line, with no space, is "user/"
//     and at least one digit, with no leading zero, and extends to a uid in
//     range; it covers every scope whose canonical text starts with it;
//   - unattributable damage, for anything else: a scope or name that does
//     not parse and is no valid prefix, a scope prefix shorter than "user/"
//     and a digit, a rest that is the prefix of no line, or a line over
//     maxLogLine.
//
// A tainted key's every generation (a name or prefix taint) or the one
// generation (a generation taint) is refused, whatever the floor knows of it: the skipped
// line could have been its tombstone, or a live line above what the floor
// holds. Unattributable damage keeps the floor-wide rule: no live line for
// a generation the floor has no line for, and no put or deliver line. The
// taint set is capped at maxTaintKeys entries and maxTaintBytes bytes; a
// taint past the cap is counted as unattributable damage instead.

const (
	// maxUIDDigits is the most digits of a user scope's uid.
	maxUIDDigits = 10
	// maxTaintKeys and maxTaintBytes cap the floor's taint set.
	maxTaintKeys  = 64
	maxTaintBytes = 64 << 10
	// taintEntryOverhead is what one taint entry is charged beyond its
	// scope and name bytes: its generation and its map slot.
	taintEntryOverhead = generationSize + 32
	// maxSeqDigits is the most digits of a canonical uint64.
	maxSeqDigits = 20
)

// taintKind is what a damaged floor line could have been.
type taintKind uint8

const (
	// taintName is a line torn inside its generation: any generation of
	// (scope, name).
	taintName taintKind = iota + 1
	// taintGen is a line whose generation is whole: (scope, name, gen).
	taintGen
	// taintUnattributable is a line no key can be read from.
	taintUnattributable
	// taintNamePrefix is a line torn inside its name: every name of the
	// scope that starts with the partial name.
	taintNamePrefix
	// taintScopePrefix is a line torn inside its scope: every scope whose
	// canonical text starts with the partial scope.
	taintScopePrefix
)

// classifyFloorDamage is the taint a damaged floor line, without its
// newline, carries, and the key it names: for taintName the key's gen is
// zero and unused.
func classifyFloorDamage(line []byte) (taintKind, floorKey) {
	var k floorKey
	if len(line)+1 > maxLogLine {
		return taintUnattributable, k
	}
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 {
		// Torn inside its scope: every scope it is a prefix of.
		if scopePrefixOK(line) {
			k.scope = string(line)
			return taintScopePrefix, k
		}
		return taintUnattributable, k
	}
	scope := string(line[:sp])
	if uid := scopeUID(scope); uid == 0 || userScopeOf(uid) != scope {
		return taintUnattributable, k
	}
	rest := line[sp+1:]
	sp = bytes.IndexByte(rest, ' ')
	if sp < 0 {
		// Torn inside its name: every name of the scope it is a prefix of.
		if namePrefixOK(string(rest)) {
			k.scope, k.name = scope, string(rest)
			return taintNamePrefix, k
		}
		return taintUnattributable, k
	}
	name := string(rest[:sp])
	if name != deliveriesFloorName && checkName(name) != nil {
		return taintUnattributable, k
	}
	k.scope, k.name = scope, name
	rest = rest[sp+1:]
	n := 0
	for n < len(rest) && n < 2*generationSize && unhex(rest[n]) >= 0 {
		n++
	}
	if n < 2*generationSize {
		if n == len(rest) {
			return taintName, k
		}
		return taintUnattributable, floorKey{}
	}
	for i := range generationSize {
		k.gen[i] = byte(unhex(rest[2*i])<<4 | unhex(rest[2*i+1]))
	}
	rest = rest[2*generationSize:]
	if len(rest) == 0 {
		return taintGen, k
	}
	if rest[0] != ' ' {
		return taintUnattributable, floorKey{}
	}
	rest = rest[1:]
	switch {
	case len(rest) == 0, string(rest) == "r", string(rest) == floorTombstone:
		return taintGen, k
	case canonicalSeqPrefix(rest):
		return taintGen, k
	}
	return taintUnattributable, floorKey{}
}

// scopePrefixOK reports whether p is the prefix, "user/" and at least one
// digit, of the canonical text of some user scope: no leading zero, and a
// uid in range among its extensions.
func scopePrefixOK(p []byte) bool {
	digits, ok := bytes.CutPrefix(p, []byte(userScopePrefix))
	if !ok || len(digits) == 0 || digits[0] == '0' || len(digits) > maxUIDDigits {
		return false
	}
	var lo uint64
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
		lo = lo*10 + uint64(c-'0')
	}
	// Each extension to l digits spans [lo*10^m, lo*10^m + 10^m - 1].
	span := uint64(1)
	for l := len(digits); l <= maxUIDDigits; l++ {
		if lo+span-1 >= minScopeUID && lo <= maxScopeUID {
			return true
		}
		lo, span = lo*10, span*10
	}
	return false
}

// namePrefixOK reports whether p is the prefix of the delivery record's
// floor name or of some valid entry name.
func namePrefixOK(p string) bool {
	if strings.HasPrefix(deliveriesFloorName, p) {
		return true
	}
	return checkName(p) == nil || (len(p) < maxNameLen && checkName(p+"a") == nil)
}

// canonicalSeqPrefix reports whether b, which is not empty, is a prefix of
// a canonical decimal uint64: digits, no leading zero but a lone "0", at
// most maxSeqDigits of them.
func canonicalSeqPrefix(b []byte) bool {
	if len(b) > maxSeqDigits || (len(b) > 1 && b[0] == '0') {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// taintLine records the taint of the damaged line line, without its
// newline, that starts at off: into the taint set, or, past its cap or for
// a line no key can be read from, as unattributable damage at off.
func (s *logState) taintLine(off int64, line []byte) {
	kind, k := classifyFloorDamage(line)
	switch kind {
	case taintName:
		nk := nameKey{k.scope, k.name}
		if s.taintNames[nk] {
			return
		}
		if !s.taintRoom(k) {
			s.unattributable(off)
			return
		}
		if s.taintNames == nil {
			s.taintNames = map[nameKey]bool{}
		}
		s.taintNames[nk] = true
	case taintNamePrefix, taintScopePrefix:
		pk := prefixTaint{kind, k.scope, k.name}
		if s.taintPrefixes[pk] {
			return
		}
		if !s.taintRoom(k) {
			s.unattributable(off)
			return
		}
		if s.taintPrefixes == nil {
			s.taintPrefixes = map[prefixTaint]bool{}
		}
		s.taintPrefixes[pk] = true
	case taintGen:
		if s.taintGens[k] {
			return
		}
		if !s.taintRoom(k) {
			s.unattributable(off)
			return
		}
		if s.taintGens == nil {
			s.taintGens = map[floorKey]bool{}
		}
		s.taintGens[k] = true
	default:
		s.unattributable(off)
		return
	}
	s.taintBytes += len(k.scope) + len(k.name) + taintEntryOverhead
}

// taintRoom reports whether the taint set has room for one more entry
// for k.
func (s *logState) taintRoom(k floorKey) bool {
	return len(s.taintNames)+len(s.taintGens)+len(s.taintPrefixes) < maxTaintKeys &&
		s.taintBytes+len(k.scope)+len(k.name)+taintEntryOverhead <= maxTaintBytes
}

// unattributable records unattributable damage at off, keeping the latest.
func (s *logState) unattributable(off int64) {
	if !s.unattrib || off > s.unattribAt {
		s.unattrib, s.unattribAt = true, off
	}
}

// tornTaint classifies the torn last line, its bytes torn, at off.
func (s *logState) tornTaint(off int64, torn []byte) {
	s.tornKind, s.tornKey = classifyFloorDamage(torn)
	s.tornAt = off
}

// tainted reports whether k is tainted: its (scope, name), or k itself, by
// a skipped line or by the torn last line.
func (s *logState) tainted(k floorKey) bool {
	if s.nameTainted(k.scope, k.name) || s.taintGens[k] {
		return true
	}
	return s.tornSize != 0 && s.tornKind == taintGen && s.tornKey == k
}

// nameTainted reports whether (scope, name) is tainted as a name, every
// generation of it: by a name taint, or by a scope or name prefix that
// covers it.
func (s *logState) nameTainted(scope, name string) bool {
	if s.taintNames[nameKey{scope, name}] {
		return true
	}
	for p := range s.taintPrefixes {
		if p.covers(scope, name) {
			return true
		}
	}
	if s.tornSize == 0 {
		return false
	}
	switch s.tornKind {
	case taintName:
		return s.tornKey.scope == scope && s.tornKey.name == name
	case taintNamePrefix, taintScopePrefix:
		return prefixTaint{s.tornKind, s.tornKey.scope, s.tornKey.name}.covers(scope, name)
	}
	return false
}

// prefixTaint is a line torn inside its scope or name: kind
// taintScopePrefix with scope the partial scope, or taintNamePrefix with
// scope whole and name the partial name.
type prefixTaint struct {
	kind        taintKind
	scope, name string
}

// covers reports whether (scope, name) is a key p taints.
func (p prefixTaint) covers(scope, name string) bool {
	if p.kind == taintScopePrefix {
		return strings.HasPrefix(scope, p.scope)
	}
	return scope == p.scope && strings.HasPrefix(name, p.name)
}

// unattributedAt reports the start of the latest unattributable damage,
// the torn last line included, and whether there is any.
func (s *logState) unattributedAt() (int64, bool) {
	at, ok := s.unattribAt, s.unattrib
	if s.tornSize != 0 && s.tornKind == taintUnattributable && (!ok || s.tornAt > at) {
		at, ok = s.tornAt, true
	}
	return at, ok
}

// fileID is one file's identity, as logState keeps it.
type fileID struct {
	dev, ino uint64
	birth    unix.Timespec
}

// warnServedOverDamage logs at Warn, once per process for each damaged
// floor file, that a known, untainted generation is served while the floor
// holds damage. The caller holds l.mu.
func (l *appendLog) warnServedOverDamage(s *logState) {
	id := fileID{s.dev, s.ino, s.birth}
	if l.servedWarned[id] {
		return
	}
	if l.servedWarned == nil {
		l.servedWarned = map[fileID]bool{}
	}
	l.servedWarned[id] = true
	slog.Warn("the user-scope floor holds damaged lines; generations it has a line for and no damaged line could name are still served", "log", l.name, "damaged", s.damaged(), "first", s.badAt)
}
