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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"slices"
	"strconv"
	"syscall"
	"time"
)

// PreFrameDroppedName is the server-counts file in the store directory:
// the counts that live in the server's memory and must outlast it, for
// doctor (another process) and the next root audit --rotate. Its name says
// pre-frame, but it carries three kinds of count (docs/design/keystore.md §
// "Per-uid fairness" and § "The audit log"): the pre-frame refusals counted
// as dropped and not yet written to the audit log, by class and uid; the
// post-frame refused lines the socket's limiter or the caller's share
// dropped and not yet summarized, by uid (countClassPostFrame); and the
// committed revocations whose audit line could not be written
// (countClassUnaudited), with no uid. The audit log's directory is root's,
// so the server keeps it in the store directory it owns; the leading dot
// keeps it out of every enumerator of entries, which refuse a name that is
// not one (checkName).
const PreFrameDroppedName = ".preframe-dropped"

// The persisted counts' format: one header line, then at most
// preFrameDroppedUIDs uids' lines "<uid> <class> <count>", sorted by uid
// then class, then at most one "others <class> <count>" line per class, in
// class order: for a uid class, the count of the uids past
// preFrameDroppedUIDs; for countClassUnaudited, which names no uid, its
// whole count, and it is written in no other form. No line is longer than
// preFrameDroppedMaxLine; every count is above 0; a file with only the
// header holds no count.
const (
	preFrameDroppedHeader  = "k3sm-preframe-dropped 1\n"
	preFrameDroppedOthers  = "others"
	preFrameDroppedUIDs    = 256
	preFrameDroppedMaxLine = 64
	// maxPreFrameDroppedSize bounds the file: the header, a line for each
	// named uid in each class a uid line may carry, and an others line for
	// each class, each at the fixed maximum.
	maxPreFrameDroppedSize = (1 + preFrameDroppedUIDs*(countClassesN-1) + countClassesN) * preFrameDroppedMaxLine
	// countClassesN is len(countClasses), untyped, so the bound above stays
	// an untyped constant; the array checks below hold the two equal.
	countClassesN = 7
	// preFrameDroppedEvery is the least time between two writes of the
	// file: a change inside it waits for the next call past it, or Close.
	preFrameDroppedEvery = time.Second
)

// The classes the file carries past the pre-frame ones (preFrameClasses).
// They are never a pre-frame line's class: the pre-frame charge and its
// summaries know only preFrameClasses.
const (
	// countClassPostFrame is a uid's post-frame refused lines the socket's
	// limiter or the caller's share dropped, not yet in a summary line.
	countClassPostFrame preFrameClass = "post-frame"
	// countClassUnaudited is the committed revocations whose audit line
	// could not be written; it names no uid.
	countClassUnaudited preFrameClass = "unaudited"
)

// countClasses is every class the file carries: the pre-frame classes in
// their order, then countClassPostFrame and countClassUnaudited. An array,
// so its length bounds the file as a constant.
var countClasses = [...]preFrameClass{
	preFrameClassLogin, preFrameClassRoot, preFrameClassServiceUID, preFrameClassNoUID, preFrameClassSystemHigh,
	countClassPostFrame, countClassUnaudited,
}

// countClasses holds exactly countClassesN classes: a class added alone
// fails to compile (a negative array length).
var (
	_ [len(countClasses) - countClassesN]struct{}
	_ [countClassesN - len(countClasses)]struct{}
)

// preFrameCount reports whether c is a pre-frame class, which the server's
// pre-frame summaries write, rather than one of the server's other counts.
func preFrameCount(c preFrameClass) bool { return slices.Contains(preFrameClasses, c) }

// errPreFrameDroppedMalformed refuses a persisted-count file that does not
// parse strictly.
var errPreFrameDroppedMalformed = errors.New("the persisted server counts do not parse")

// preFrameDropped is the persisted counts: each uid's, by class, and the
// folded others, by class.
type preFrameDropped struct {
	uids   map[preFrameKey]uint64
	others map[preFrameClass]uint64
}

func newPreFrameDropped() preFrameDropped {
	return preFrameDropped{uids: map[preFrameKey]uint64{}, others: map[preFrameClass]uint64{}}
}

// satAdd is a+b, held at the largest uint64.
func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// satSub is a-b, held at 0.
func satSub(a, b uint64) uint64 {
	if b >= a {
		return 0
	}
	return a - b
}

// empty reports whether d holds no count.
func (d preFrameDropped) empty() bool {
	for _, c := range d.uids {
		if c > 0 {
			return false
		}
	}
	for _, c := range d.others {
		if c > 0 {
			return false
		}
	}
	return true
}

// clone is a copy of d.
func (d preFrameDropped) clone() preFrameDropped {
	out := newPreFrameDropped()
	for k, c := range d.uids {
		out.uids[k] = c
	}
	for k, c := range d.others {
		out.others[k] = c
	}
	return out
}

// totals is each class's count, its uids' and its others' together.
func (d preFrameDropped) totals() map[preFrameClass]uint64 {
	out := map[preFrameClass]uint64{}
	for k, c := range d.uids {
		out[k.class] = satAdd(out[k.class], c)
	}
	for k, c := range d.others {
		out[k] = satAdd(out[k], c)
	}
	return out
}

// PreFrameDroppedCounts is what doctor shows of the persisted counts: the
// pre-frame refusals not yet in the audit log, the uids named, and the
// count folded into the others lines (uids past the file's limit, not
// named); the post-frame refused lines dropped and not yet summarized, and
// the uids named for them; and the committed revocations with no audit
// line.
type PreFrameDroppedCounts struct {
	Refusals uint64
	UIDs     int
	Others   uint64
	// PostFrame is the post-frame refused lines dropped, the others line's
	// included, and PostFrameUIDs the uids named for them.
	PostFrame     uint64
	PostFrameUIDs int
	// Unaudited is the committed revocations whose audit line could not be
	// written.
	Unaudited uint64
}

// counts is d summarised for doctor.
func (d preFrameDropped) counts() PreFrameDroppedCounts {
	var out PreFrameDroppedCounts
	pre, post := map[uint32]bool{}, map[uint32]bool{}
	for k, c := range d.uids {
		switch {
		case c == 0:
		case k.class == countClassPostFrame:
			out.PostFrame = satAdd(out.PostFrame, c)
			post[k.uid] = true
		case preFrameCount(k.class):
			out.Refusals = satAdd(out.Refusals, c)
			pre[k.uid] = true
		}
	}
	for k, c := range d.others {
		switch {
		case k == countClassPostFrame:
			out.PostFrame = satAdd(out.PostFrame, c)
		case k == countClassUnaudited:
			out.Unaudited = satAdd(out.Unaudited, c)
		case preFrameCount(k):
			out.Refusals = satAdd(out.Refusals, c)
			out.Others = satAdd(out.Others, c)
		}
	}
	out.UIDs, out.PostFrameUIDs = len(pre), len(post)
	return out
}

// split is d's pre-frame counts and its other counts, each a copy.
func (d preFrameDropped) split() (pre, other preFrameDropped) {
	pre, other = newPreFrameDropped(), newPreFrameDropped()
	for k, c := range d.uids {
		if preFrameCount(k.class) {
			pre.uids[k] = c
		} else {
			other.uids[k] = c
		}
	}
	for k, c := range d.others {
		if preFrameCount(k) {
			pre.others[k] = c
		} else {
			other.others[k] = c
		}
	}
	return pre, other
}

// join is a copy of a's counts and b's together.
func join(a, b preFrameDropped) preFrameDropped {
	out := a.clone()
	for k, c := range b.uids {
		out.uids[k] = satAdd(out.uids[k], c)
	}
	for k, c := range b.others {
		out.others[k] = satAdd(out.others[k], c)
	}
	return out
}

// encodePreFrameDropped is d in the file's format: the lowest uids named,
// in order, while they fit, and every count past that folded into one
// others line per class; countClassUnaudited, which names no uid, is
// written on its others line alone. A uid line is folded, with every line
// after it, once it would name more than preFrameDroppedUIDs uids, be
// longer than preFrameDroppedMaxLine, or take the uid lines past the room
// maxPreFrameDroppedSize leaves after the header and one others line per
// class (countClasses) at the line bound. So the output always parses
// (parsePreFrameDropped) and always fits, whatever d holds, and each
// class's total is kept.
func encodePreFrameDropped(d preFrameDropped) []byte {
	others := map[preFrameClass]uint64{}
	for k, c := range d.others {
		others[k] = c
	}
	keys := make([]preFrameKey, 0, len(d.uids))
	for k, c := range d.uids {
		switch {
		case c == 0:
		case k.class == countClassUnaudited:
			others[k.class] = satAdd(others[k.class], c) // it names no uid
		default:
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, comparePreFrameKey)
	var b bytes.Buffer
	b.WriteString(preFrameDroppedHeader)
	room := maxPreFrameDroppedSize - len(preFrameDroppedHeader) - len(countClasses)*preFrameDroppedMaxLine
	named, folding := 0, false
	var last uint32
	for _, k := range keys {
		if !folding {
			n := named
			if n == 0 || k.uid != last {
				n++
			}
			line := fmt.Sprintf("%d %s %d\n", k.uid, k.class, d.uids[k])
			if n > preFrameDroppedUIDs || len(line) > preFrameDroppedMaxLine || len(line) > room {
				folding = true
			} else {
				b.WriteString(line)
				room -= len(line)
				named, last = n, k.uid
				continue
			}
		}
		others[k.class] = satAdd(others[k.class], d.uids[k])
	}
	classes := slices.Clone(countClasses[:])
	slices.Sort(classes)
	for _, c := range classes {
		if others[c] > 0 {
			fmt.Fprintf(&b, "%s %s %d\n", preFrameDroppedOthers, c, others[c])
		}
	}
	return b.Bytes()
}

// comparePreFrameKey orders keys by uid, then class.
func comparePreFrameKey(a, b preFrameKey) int {
	if c := cmp.Compare(a.uid, b.uid); c != 0 {
		return c
	}
	return cmp.Compare(a.class, b.class)
}

// parsePreFrameDropped reads b strictly: the header exactly, then lines in
// the order encodePreFrameDropped writes them, each ending in a newline, no
// longer than preFrameDroppedMaxLine, with canonical decimal numbers, a
// class of the closed set (countClasses) and a count above 0, the
// unaudited count on an others line only; at most preFrameDroppedUIDs uids
// named. Anything else is errPreFrameDroppedMalformed.
func parsePreFrameDropped(b []byte) (preFrameDropped, error) {
	d := newPreFrameDropped()
	bad := func(why string, args ...any) (preFrameDropped, error) {
		return preFrameDropped{}, fmt.Errorf("%w: %s", errPreFrameDroppedMalformed, fmt.Sprintf(why, args...))
	}
	if len(b) > maxPreFrameDroppedSize {
		return bad("%d bytes, over %d", len(b), maxPreFrameDroppedSize)
	}
	rest, ok := bytes.CutPrefix(b, []byte(preFrameDroppedHeader))
	if !ok {
		return bad("no header")
	}
	var prev preFrameKey
	var prevOthers preFrameClass
	named, line := 0, 1
	for len(rest) > 0 {
		line++
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			return bad("line %d has no newline", line)
		}
		if i+1 > preFrameDroppedMaxLine {
			return bad("line %d is over %d bytes", line, preFrameDroppedMaxLine)
		}
		f := bytes.Split(rest[:i], []byte{' '})
		rest = rest[i+1:]
		if len(f) != 3 {
			return bad("line %d has %d fields", line, len(f))
		}
		class := preFrameClass(f[1])
		if !slices.Contains(countClasses[:], class) {
			return bad("line %d names no class", line)
		}
		n, ok := canonicalUint(f[2], 64)
		if !ok || n == 0 {
			return bad("line %d has no count above 0", line)
		}
		if string(f[0]) == preFrameDroppedOthers {
			if prevOthers != "" && class <= prevOthers {
				return bad("line %d is out of order", line)
			}
			prevOthers = class
			d.others[class] = n
			continue
		}
		if prevOthers != "" {
			return bad("line %d names a uid after an others line", line)
		}
		if class == countClassUnaudited {
			return bad("line %d names a uid for a count that has none", line)
		}
		u, ok := canonicalUint(f[0], 32)
		if !ok {
			return bad("line %d names no uid", line)
		}
		k := preFrameKey{class: class, uid: uint32(u)}
		if named > 0 && comparePreFrameKey(prev, k) >= 0 {
			return bad("line %d is out of order", line)
		}
		if named == 0 || k.uid != prev.uid {
			named++
		}
		if named > preFrameDroppedUIDs {
			return bad("more than %d uids", preFrameDroppedUIDs)
		}
		prev = k
		d.uids[k] = n
	}
	return d, nil
}

// canonicalUint parses b as an unsigned decimal of bits bits in its
// canonical form: no sign, no leading zero.
func canonicalUint(b []byte, bits int) (uint64, bool) {
	n, err := strconv.ParseUint(string(b), 10, bits)
	return n, err == nil && strconv.FormatUint(n, 10) == string(b)
}

// readPreFrameDropped reads the persisted counts in root, the store
// directory: never following a symlink, a regular file of one link, the
// service user's at mode 0600, at most maxPreFrameDroppedSize bytes, parsed
// strictly. An absent file holds no count.
func (s *FileStore) readPreFrameDropped(root *os.Root) (preFrameDropped, error) {
	b, fi, err := readFile(root, PreFrameDroppedName, maxPreFrameDroppedSize)
	if errors.Is(err, fs.ErrNotExist) {
		return newPreFrameDropped(), nil
	}
	if err != nil {
		return preFrameDropped{}, fmt.Errorf("read %s: %w", PreFrameDroppedName, err)
	}
	if err := s.judgePreFrameDropped(fi); err != nil {
		return preFrameDropped{}, fmt.Errorf("%s: %w", PreFrameDroppedName, err)
	}
	d, err := parsePreFrameDropped(b)
	if err != nil {
		return preFrameDropped{}, fmt.Errorf("%s: %w", PreFrameDroppedName, err)
	}
	return d, nil
}

// judgePreFrameDropped refuses fi unless it is the service user's, mode
// 0600 exactly, with one link.
func (s *FileStore) judgePreFrameDropped(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || st == nil:
		return errors.New("owner unknown")
	case st.Uid != s.uid:
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, s.uid)
	case fi.Mode().Perm() != fileMode:
		return fmt.Errorf("mode %04o, want %04o", fi.Mode().Perm(), fileMode)
	case st.Nlink != 1:
		return fmt.Errorf("%d links", st.Nlink)
	}
	return nil
}

// writePreFrameDropped replaces the persisted counts in root with d's:
// a temporary file beside it, created O_EXCL|O_NOFOLLOW at 0600 and the
// service user's, written and fsynced, renamed over the name, then the
// directory fsynced, all through root's descriptor (writeFile).
func (s *FileStore) writePreFrameDropped(root *os.Root, d preFrameDropped) error {
	return s.writeFile(root, PreFrameDroppedName, encodePreFrameDropped(d))
}

// PreFrameDropped reads the persisted pre-frame refusal counts, read-only,
// for doctor: the store directory opened and judged, the file read as the
// server reads it at open. It takes no lock and writes nothing. An absent
// store directory or file holds no count.
func (s *FileStore) PreFrameDropped(ctx context.Context) (PreFrameDroppedCounts, error) {
	if err := s.checkConfig(); err != nil {
		return PreFrameDroppedCounts{}, err
	}
	if err := ctx.Err(); err != nil {
		return PreFrameDroppedCounts{}, err
	}
	root, err := s.openDir(s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return PreFrameDroppedCounts{}, nil
	}
	if err != nil {
		return PreFrameDroppedCounts{}, err
	}
	defer func() { _ = root.Close() }() // read-only
	d, err := s.readPreFrameDropped(root)
	if err != nil {
		return PreFrameDroppedCounts{}, err
	}
	return d.counts(), nil
}

// loadDroppedLocked reads the persisted counts and merges them into l's,
// the pre-frame counts, and the store's (serverCounts), the others:
// each count moves by what the file gained or lost since l last wrote it,
// so a count already in memory is not added twice, and a count a root
// rotate wrote to the audit log and took out of the file leaves memory too.
// A file that does not read turns persistence off, so it is never
// overwritten: the counts stay in memory, the error is kept for
// DroppedPersistError, and doctor reads the file itself.
func (l *ServerLogs) loadDroppedLocked() {
	root, err := l.s.openDir(l.s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return // no store directory yet: nothing persisted, nothing to write into
	}
	var d preFrameDropped
	if err == nil {
		d, err = l.s.readPreFrameDropped(root)
		_ = root.Close() // read-only
	}
	if err != nil {
		l.droppedErr = err
		l.s.logger().Warn("keystore: the persisted server counts are unreadable; the server keeps its counts in memory and does not overwrite the file", "file", PreFrameDroppedName, "err", err)
		return
	}
	l.droppedErr = nil
	pre, other := d.split()
	mergeDelta(l.pending, pre.uids, l.written.uids)
	mergeDelta(l.others, pre.others, l.written.others)
	l.written = pre
	l.s.counts.merge(other)
}

// mergeDelta moves each count in mem by what file holds past, or short of,
// written, held at 0; a count at 0 is removed.
func mergeDelta[K comparable](mem, file, written map[K]uint64) {
	keys := map[K]bool{}
	for k := range file {
		keys[k] = true
	}
	for k := range written {
		keys[k] = true
	}
	for k := range keys {
		f, w := file[k], written[k]
		v := mem[k]
		if f >= w {
			v = satAdd(v, f-w)
		} else {
			v = satSub(v, w-f)
		}
		if v > 0 {
			mem[k] = v
		} else {
			delete(mem, k)
		}
	}
}

// persistDropped writes the pending counts, and the store's other counts
// (serverCounts), to PreFrameDroppedName when either changed since the
// last write, at most once per preFrameDroppedEvery
// on the store's clock unless force is set. It runs under l.mu, the
// in-process mutex, and never takes the store lock: the lock may be what
// a dropped line timed out on. A write that fails keeps the change for the
// next call and is logged; a file read as unreadable is never written.
func (l *ServerLogs) persistDropped(force bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if (!l.droppedDirty && l.s.counts.generation() == l.countsGen) || l.droppedErr != nil {
		return
	}
	now := l.s.now()
	if !force && !l.droppedAt.IsZero() && now.Sub(l.droppedAt) < preFrameDroppedEvery {
		return
	}
	root, err := l.s.openDir(l.s.dir, false)
	if err != nil {
		l.s.logger().Warn("keystore: could not persist the server counts", "file", PreFrameDroppedName, "err", err)
		return
	}
	defer func() { _ = root.Close() }() // the write is synced through it
	d := preFrameDropped{uids: l.pending, others: l.others}.clone()
	other, gen := l.s.counts.snapshot()
	if err := l.s.writePreFrameDropped(root, join(d, other)); err != nil {
		l.s.logger().Warn("keystore: could not persist the server counts", "file", PreFrameDroppedName, "err", err)
		return
	}
	l.s.counts.wrote(other)
	l.written, l.droppedAt, l.droppedDirty, l.countsGen = d, now, false, gen
}

// DroppedPersistError is why the persisted pre-frame refusal count was
// not read at the last open or reopen, or nil.
func (l *ServerLogs) DroppedPersistError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.droppedErr
}
