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

// PreFrameDroppedName is the file in the store directory that persists the
// pre-frame refusals counted as dropped and not yet written to the audit log
// (docs/design/keystore.md § "Per-uid fairness": the count is persisted, not
// kept only in memory). The audit log's directory is root's, so the server
// keeps it in the store directory it owns; the leading dot keeps it out of
// every enumerator of entries, which refuse a name that is not one
// (checkName).
const PreFrameDroppedName = ".preframe-dropped"

// The persisted counts' format: one header line, then at most
// preFrameDroppedUIDs uids' lines "<uid> <class> <count>", sorted by uid
// then class, then at most one "others <class> <count>" line per class for
// the uids past preFrameDroppedUIDs, in class order. No line is longer than
// preFrameDroppedMaxLine; every count is above 0; a file with only the header
// holds no count.
const (
	preFrameDroppedHeader  = "k3sm-preframe-dropped 1\n"
	preFrameDroppedOthers  = "others"
	preFrameDroppedUIDs    = 256
	preFrameDroppedMaxLine = 64
	// maxPreFrameDroppedSize bounds the file: the header and every line it
	// can hold, each at the fixed maximum.
	maxPreFrameDroppedSize = (1 + preFrameDroppedUIDs + 5) * preFrameDroppedMaxLine
	// preFrameDroppedEvery is the least time between two writes of the
	// file: a change inside it waits for the next call past it, or Close.
	preFrameDroppedEvery = time.Second
)

// errPreFrameDroppedMalformed refuses a persisted-count file that does not
// parse strictly.
var errPreFrameDroppedMalformed = errors.New("the persisted pre-frame refusal count does not parse")

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
// refusals not yet in the audit log, the uids named, and the count folded
// into the others lines (uids past the file's limit, not named).
type PreFrameDroppedCounts struct {
	Refusals uint64
	UIDs     int
	Others   uint64
}

// counts is d summarised for doctor.
func (d preFrameDropped) counts() PreFrameDroppedCounts {
	var out PreFrameDroppedCounts
	seen := map[uint32]bool{}
	for k, c := range d.uids {
		if c == 0 {
			continue
		}
		out.Refusals = satAdd(out.Refusals, c)
		seen[k.uid] = true
	}
	for _, c := range d.others {
		out.Refusals = satAdd(out.Refusals, c)
		out.Others = satAdd(out.Others, c)
	}
	out.UIDs = len(seen)
	return out
}

// encodePreFrameDropped is d in the file's format: the preFrameDroppedUIDs
// lowest uids named, the rest folded into one others line per class.
func encodePreFrameDropped(d preFrameDropped) []byte {
	keys := make([]preFrameKey, 0, len(d.uids))
	for k, c := range d.uids {
		if c > 0 {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, comparePreFrameKey)
	others := map[preFrameClass]uint64{}
	for k, c := range d.others {
		others[k] = c
	}
	var b bytes.Buffer
	b.WriteString(preFrameDroppedHeader)
	named := 0
	var last uint32
	for _, k := range keys {
		if named == 0 || k.uid != last {
			named++
			last = k.uid
		}
		if named > preFrameDroppedUIDs {
			others[k.class] = satAdd(others[k.class], d.uids[k])
			continue
		}
		fmt.Fprintf(&b, "%d %s %d\n", k.uid, k.class, d.uids[k])
	}
	classes := slices.Clone(preFrameClasses)
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
// class of the closed set and a count above 0; at most preFrameDroppedUIDs
// uids named. Anything else is errPreFrameDroppedMalformed.
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
		if !slices.Contains(preFrameClasses, class) {
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

// loadDroppedLocked reads the persisted counts and merges them into l's:
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
		l.s.logger().Warn("keystore: the persisted pre-frame refusal count is unreadable; the server keeps its counts in memory and does not overwrite the file", "file", PreFrameDroppedName, "err", err)
		return
	}
	l.droppedErr = nil
	mergeDelta(l.pending, d.uids, l.written.uids)
	mergeDelta(l.others, d.others, l.written.others)
	l.written = d
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

// persistDropped writes the pending counts to PreFrameDroppedName when
// they changed since the last write, at most once per preFrameDroppedEvery
// on the store's clock unless force is set. It runs under l.mu, the
// in-process mutex, and never takes the store lock: the lock may be what
// a dropped line timed out on. A write that fails keeps the change for the
// next call and is logged; a file read as unreadable is never written.
func (l *ServerLogs) persistDropped(force bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.droppedDirty || l.droppedErr != nil {
		return
	}
	now := l.s.now()
	if !force && !l.droppedAt.IsZero() && now.Sub(l.droppedAt) < preFrameDroppedEvery {
		return
	}
	root, err := l.s.openDir(l.s.dir, false)
	if err != nil {
		l.s.logger().Warn("keystore: could not persist the pre-frame refusal count", "file", PreFrameDroppedName, "err", err)
		return
	}
	defer func() { _ = root.Close() }() // the write is synced through it
	d := preFrameDropped{uids: l.pending, others: l.others}.clone()
	if err := l.s.writePreFrameDropped(root, d); err != nil {
		l.s.logger().Warn("keystore: could not persist the pre-frame refusal count", "file", PreFrameDroppedName, "err", err)
		return
	}
	l.written, l.droppedAt, l.droppedDirty = d, now, false
}

// DroppedPersistError is why the persisted pre-frame refusal count was
// not read at the last open or reopen, or nil.
func (l *ServerLogs) DroppedPersistError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.droppedErr
}
