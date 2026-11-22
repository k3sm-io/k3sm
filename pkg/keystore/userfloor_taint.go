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
// floor", "Damage and taint"). Every floor line ends in a checksum
// (appendFloorCRC), so a line torn or flipped in place never parses: it is
// skipped and classified by what of it still parses, its leading fields
// read strictly, each with the space after it:
//
//   - a whole line in the grammar, five fields, whose checksum does not
//     match is corruption in place, not a tear, and the flip could be in
//     any field: a taint on (scope, name) and unattributable damage too;
//   - a line with more than the grammar's four spaces cannot be a tear:
//     unattributable damage;
//   - a line with three spaces whose last field is shaped like a checksum
//     (8 lowercase hex digits) is a tear inside a long sequence or a whole
//     line with a separator flipped away: a taint on the (scope, name) its
//     fields name and unattributable damage too, or unattributable damage
//     alone when its name does not parse;
//   - a taint on (scope, name, generation), when "<scope> <name> " is
//     followed by a whole generation, 32 lowercase hex digits, then a space
//     or nothing;
//   - a taint on (scope, name), when "<scope> <name> " parses and the
//     generation does not;
//   - a taint on a name prefix, when the line is "<scope> <partial>": the
//     scope parses with its space and partial, with no space, is a prefix of
//     the delivery record's name or of a valid entry name; it covers every
//     name of the scope that starts with partial;
//   - a taint on the scope, every name of it, when "<scope> " parses and
//     the rest is none of the above;
//   - a taint on a scope prefix, when the line, with no space, is "user/"
//     and at least one digit, with no leading zero, and extends to a uid in
//     range; it covers every scope whose canonical text starts with it;
//   - unattributable damage, for anything else: a scope that does not
//     parse and is no valid prefix, a scope prefix shorter than "user/" and
//     a digit, or a line over maxLogLine.
//
// A tainted key's every generation (a name, scope or prefix taint) or the
// one generation (a generation taint) is refused, whatever the floor knows
// of it: the skipped line could have been its tombstone, or a live line
// above what the floor holds. Unattributable damage keeps the floor-wide
// rule: no live line for a generation the floor has no line for, and no put
// or deliver line. The taint set is capped at maxTaintKeys entries; a taint
// past the cap overflows it (logState.taintOverflow), which sticks for the
// file: every generation of every key, known or not, is refused for grants
// and reads, as though each were tainted. The overflow is never demoted to
// unattributable damage, so an acknowledgement does not lift it; rm and
// withdraw still run, as they do over any taint.

const (
	// maxUIDDigits is the most digits of a user scope's uid.
	maxUIDDigits = 10
	// maxTaintKeys caps the floor's taint set. An entry's scope and name
	// are each a line's field, so 64 entries hold at most 64 lines' bytes:
	// the count is the only cap.
	maxTaintKeys = 64
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
	// taintNameFlip is a whole line in the grammar whose checksum does not
	// match: (scope, name) as taintName, and unattributable damage too.
	taintNameFlip
)

// classifyFloorDamage is the taint a damaged floor line, without its
// newline, carries, and the key it names: for taintName, taintNameFlip and
// a scope taint (taintNamePrefix with an empty name) the key's gen is zero
// and unused.
func classifyFloorDamage(line []byte) (taintKind, floorKey) {
	kind, k := classifyFloorLadder(line)
	if bytes.Count(line, []byte{' '}) != 3 {
		return kind, k
	}
	if _, canonical, _ := splitFloorCRC(line); !canonical {
		return kind, k
	}
	// Three separators and a last field shaped like a checksum: a tear
	// inside a long sequence, or a whole line with one separator flipped
	// away, which merged two fields. Both readings are kept: the key the
	// fields name as a name taint, and unattributable damage.
	switch kind {
	case taintGen, taintName, taintNameFlip:
		return taintNameFlip, floorKey{scope: k.scope, name: k.name}
	}
	return taintUnattributable, floorKey{}
}

// classifyFloorLadder is classifyFloorDamage's ladder, before the
// three-separator rule.
func classifyFloorLadder(line []byte) (taintKind, floorKey) {
	var k floorKey
	if len(line)+1 > maxLogLine {
		return taintUnattributable, k
	}
	if bytes.Count(line, []byte{' '}) > 4 {
		// A tear only shortens a line: more separators than the grammar's
		// is a byte flipped into one, which could have split any field.
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
	k.scope = scope
	rest := line[sp+1:]
	sp = bytes.IndexByte(rest, ' ')
	if sp < 0 {
		// Torn inside its name: every name of the scope it is a prefix of.
		if namePrefixOK(string(rest)) {
			k.name = string(rest)
			return taintNamePrefix, k
		}
		return taintNamePrefix, floorKey{scope: scope} // the scope, whole
	}
	name := string(rest[:sp])
	if name != deliveriesFloorName && checkName(name) != nil {
		return taintNamePrefix, floorKey{scope: scope} // the scope, whole
	}
	k.name = name
	if body, canonical, match := splitFloorCRC(line); canonical && !match {
		if _, err := parseFloorBody(body); err == nil {
			// Whole and in the grammar, its checksum wrong: flipped in
			// place, any field of it, the generation included.
			return taintNameFlip, k
		}
	}
	rest = rest[sp+1:]
	if len(rest) < 2*generationSize || (len(rest) > 2*generationSize && rest[2*generationSize] != ' ') {
		return taintName, k
	}
	for i := range generationSize {
		hi, lo := unhex(rest[2*i]), unhex(rest[2*i+1])
		if hi < 0 || lo < 0 {
			return taintName, k
		}
		k.gen[i] = byte(hi<<4 | lo)
	}
	return taintGen, k
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

// taintLine records the taint of the damaged line line, without its
// newline, that starts at off: into the taint set, or, past its cap, as the
// taint set's overflow, or, for a line no key can be read from, as
// unattributable damage at off.
func (s *logState) taintLine(off int64, line []byte) {
	kind, k := classifyFloorDamage(line)
	if kind == taintNameFlip {
		s.unattributable(off)
		kind = taintName
	}
	switch kind {
	case taintName:
		nk := nameKey{k.scope, k.name}
		if s.taintNames[nk] {
			return
		}
		if !s.taintRoom() {
			s.taintOverflow = true
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
		if !s.taintRoom() {
			s.taintOverflow = true
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
		if !s.taintRoom() {
			s.taintOverflow = true
			return
		}
		if s.taintGens == nil {
			s.taintGens = map[floorKey]bool{}
		}
		s.taintGens[k] = true
	default:
		s.unattributable(off)
	}
}

// taintRoom reports whether the taint set has room for one more entry.
func (s *logState) taintRoom() bool {
	return len(s.taintNames)+len(s.taintGens)+len(s.taintPrefixes) < maxTaintKeys
}

// unattributable records unattributable damage at off, keeping the latest
// and counting each damaged line once.
func (s *logState) unattributable(off int64) {
	if s.unattrib && off == s.unattribAt {
		return
	}
	s.unattribN++
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
// a skipped line or by the torn last line, or every key, by the taint set's
// overflow.
func (s *logState) tainted(k floorKey) bool {
	if s.nameTainted(k.scope, k.name) || s.taintGens[k] {
		return true
	}
	return s.tornSize != 0 && s.tornKind == taintGen && s.tornKey == k
}

// nameTainted reports whether (scope, name) is tainted as a name, every
// generation of it: by a name taint, by a scope or name prefix that covers
// it, or by the taint set's overflow, which covers every name.
func (s *logState) nameTainted(scope, name string) bool {
	if s.taintOverflow || s.taintNames[nameKey{scope, name}] {
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
	case taintName, taintNameFlip:
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
	if s.tornSize != 0 && (s.tornKind == taintUnattributable || s.tornKind == taintNameFlip) && (!ok || s.tornAt > at) {
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
