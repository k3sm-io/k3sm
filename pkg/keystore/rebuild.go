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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The root maintenance verb floor --rebuild (docs/design/keystore.md §
// "Root maintenance verbs"): it writes a new user-scope floor from the old
// one and every scope's entries, and swaps it in under the maintenance
// procedure, through one data-root descriptor.

const (
	// maintenanceMarkerName is present in the data root only while a
	// maintenance verb runs; the listener stays down while it is.
	maintenanceMarkerName = "keystore-maintenance"
	// stagingDirName is the maintenance verbs' staging directory in the data
	// root: root's 0700, so no other user can reach a replacement directory
	// while it is built, or a retired one. It is on the data root's volume,
	// so a replacement directory is swapped out of it into the logs
	// directory.
	stagingDirName = "keystore-staging"
	// stagingDirMode is the staging directory's mode.
	stagingDirMode = 0o700
	// maintenanceLockWait bounds a maintenance verb's wait for the
	// exclusive store lock.
	maintenanceLockWait = 30 * time.Second
	// markerMode is the marker's mode: root 0644.
	markerMode = 0o644
)

// FileAttrWriter is the file-attribute writer the maintenance verbs act
// through: each call acts on a held descriptor, never a path. The caller
// (cmd/k3sm) supplies its seam, so a unit test records each call.
type FileAttrWriter interface {
	Fchown(fd, uid, gid int) error
	Fchmod(fd int, mode uint32) error
	Fchflags(fd, flags int) error
}

// SwapStepper is the optional step seam of a FileAttrWriter: when the
// writer also implements it, the maintenance verbs call BeforeSwapStep
// with the step's name before each step of the swap that makes no
// attribute call of its own (the swapStep names below), so a root-run test
// can probe, or stop the verb at, every step. An error fails the step as a
// crash there would leave it.
type SwapStepper interface {
	BeforeSwapStep(step string) error
}

// RebuildReport is what floor --rebuild did: the scopes it read, the keys
// the new floor holds, and what it dropped, by class: the old floor's lines
// that did not parse (a torn last line among them), its lines over the
// per-line bound, its live lines with no key on disk that the key bound
// left no room for (the forgeable ones, dropped first), and the keys of
// scopes root removed and recorded, which it did not carry forward.
type RebuildReport struct {
	Scopes, Keys, Dropped, OverLong, PastShare, AbsentScopes, RemovedKeys int
	// Earlier is set when the report is an earlier run's, which committed
	// and was not reported: this run printed it and did not rebuild.
	Earlier bool
}

// Lost reports whether the rebuild dropped any line or key.
func (r RebuildReport) Lost() bool {
	return r.Dropped+r.OverLong+r.PastShare+r.AbsentScopes+r.RemovedKeys > 0
}

// errRebuildRefused marks a rebuild that refused before it touched the old
// floor: nothing changed.
var errRebuildRefused = errors.New("floor --rebuild refused and changed nothing")

// RebuildFloor rebuilds the user-scope floor (floor --rebuild). Run as
// root: it takes the floor lock, then the exclusive store lock, waiting at
// most 30 s, then writes the maintenance marker (beginMaintenance). It
// opens the old floor and judges it on its descriptor (openOldLog: flagged,
// or unflagged and root's after a restore; an old floor with more than one
// link is read, with a Warn, since the rebuild replaces its inode), and
// reads it once, streamed and bounded by its size at open: lines appended
// after that are dropped, and only a hostile process appends then, since
// every legitimate writer holds the store lock. It carries forward every
// line that parses, opens every scope under .user/ without the
// GeneratedUID check, and writes one line per key: every carried tombstone,
// which no entry line overrides, and per live key the higher of the carried
// sequence and the one on disk. A line of a uid rm-scope recorded is
// dropped when it starts before the floor offset recorded at the removal,
// and kept at or after it (a re-minted scope's lines), but only when the
// removal was recorded against the inode of the floor it reads. Any scope
// that does not open refuses the rebuild, naming the scope, before anything
// changes.
//
// It never writes the removed-scopes record: only rm-scope does. An
// offset names a position in one floor file, the one whose inode it was
// recorded with; the floor this rebuild swaps in has a new inode, so a
// later rebuild applies no stale offset, and a refused or crashed rebuild
// has changed nothing.
//
// The new floor is swapped in as a whole directory (swapLogDir). A rerun
// after a crash past the swap prints the crashed run's report and does not
// run again; after a crash before it, it runs again from the start.
func (s *FileStore) RebuildFloor(ctx context.Context, attrs FileAttrWriter) (RebuildReport, error) {
	var rep RebuildReport
	if err := s.checkConfig(); err != nil {
		return rep, err
	}
	m, err := s.beginMaintenance(ctx, verbRebuild, userFloorLogName, errRebuildRefused, attrs)
	if err != nil {
		return rep, err
	}
	defer m.end()
	if m.saved != nil {
		rep = rebuildReportOf(m.saved)
		rep.Earlier = true
		return rep, nil
	}
	if err := m.step(swapStepReadOld); err != nil {
		return rep, fmt.Errorf("%w: %w", errRebuildRefused, err)
	}
	removed, err := s.readRemovedScopes(m.dfd)
	if err != nil {
		return rep, fmt.Errorf("%w: %w", errRebuildRefused, err)
	}
	in, err := s.rebuildScopes(ctx, m.root, s.floorLog().keyBound())
	if err != nil {
		return rep, fmt.Errorf("%w: %w", errRebuildRefused, err)
	}
	rep.Scopes = len(in.present)
	old, err := s.readOldFloor(m.lfd, in, removed)
	if err != nil {
		return rep, fmt.Errorf("%w: the old floor %s cannot be read: %w", errRebuildRefused, userFloorLogName, err)
	}
	rep.Dropped, rep.OverLong, rep.PastShare, rep.AbsentScopes, rep.RemovedKeys = old.dropped, old.overLong, old.pastShare, old.absent, old.removed
	lines, keys := mergeFloor(old, in.disk)
	rep.Keys = keys
	content := func(w io.Writer) error {
		for _, l := range lines {
			if _, err := w.Write(l); err != nil {
				return err
			}
		}
		return nil
	}
	if err := s.swapLogDir(m, userFloorLogName, content, nil, rep.fields(), attrs); err != nil {
		return rep, err
	}
	return rep, nil
}

// fields is r as the marker records it.
func (r RebuildReport) fields() map[string]int64 {
	return map[string]int64{
		"scopes": int64(r.Scopes), "keys": int64(r.Keys), "dropped": int64(r.Dropped),
		"overlong": int64(r.OverLong), "past-share": int64(r.PastShare), "absent": int64(r.AbsentScopes), "removed": int64(r.RemovedKeys),
	}
}

// rebuildReportOf is the report a marker recorded (fields).
func rebuildReportOf(f map[string]int64) RebuildReport {
	return RebuildReport{
		Scopes: int(f["scopes"]), Keys: int(f["keys"]), Dropped: int(f["dropped"]),
		OverLong: int(f["overlong"]), PastShare: int(f["past-share"]), AbsentScopes: int(f["absent"]), RemovedKeys: int(f["removed"]),
	}
}

// floorLog is the file-backed floor's appendLog, for its key bound.
func (s *FileStore) floorLog() *appendLog {
	if f, ok := s.userFloor.(*fileFloorLog); ok {
		return f.log
	}
	return newFileFloorLog(s).log
}

// oldFloor is the old floor as rebuild read it: the descriptor it read,
// the keys admitted to the new floor with their highest carried sequence,
// the carried tombstones, and the counts of what was dropped, by class.
type oldFloor struct {
	maxSeq map[floorKey]uint64
	buried map[floorKey]bool
	// dropped counts the lines that did not parse and a torn last line;
	// overLong the lines over the per-line bound, skipped to their newline;
	// pastShare the lines of scopes on disk past their uid's key share;
	// absent the lines of scopes absent from disk left out; removed the
	// keys of scopes root removed and recorded.
	dropped, overLong, pastShare, absent, removed int
}

// rebuildInput is what rebuild knows before it reads the old floor: the
// keys on disk, the scopes present, the (scope, name) of every entry
// directory present, and per scope rm-scope recorded as removed the floor
// offset its lines are dropped before.
type rebuildInput struct {
	disk    map[floorKey]uint64
	present map[string]bool
	names   map[nameKey]bool
	removed map[string]int64
}

// errFloorLineTooLong is a line over the per-line bound, skipped to its
// newline.
var errFloorLineTooLong = errors.New("a floor line is over the per-line bound")

// floorLines streams r line by line through a buffer of lineBound bytes
// (a line and its newline): fn gets each whole line, without its newline,
// and the offset it starts at, or errFloorLineTooLong for one over the
// bound, which is skipped to its newline. It returns the offset just past the last whole line, and
// whether a torn last line (no newline) followed it; memory stays at the
// buffer whatever the size of r.
func floorLines(r io.Reader, lineBound int, fn func(line []byte, start int64, err error) error) (int64, bool, error) {
	br := bufio.NewReaderSize(r, lineBound)
	var off, pos int64
	long := false
	for {
		b, err := br.ReadSlice('\n')
		pos += int64(len(b))
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			long = true
			continue
		case errors.Is(err, io.EOF):
			return off, len(b) > 0 || long, nil
		case err != nil:
			return off, false, err
		}
		start := off
		off = pos
		line := b[:len(b)-1]
		var ferr error
		if long {
			line, ferr, long = nil, errFloorLineTooLong, false
		}
		if len(line) == 0 && ferr == nil {
			continue // an append's leading newline
		}
		if err := fn(line, start, ferr); err != nil {
			return off, false, err
		}
	}
}

// readOldFloor opens the canonical floor in its judged directory under
// lfd and judges it (openOldLog, step 2), and streams it once, bounded by
// its size at open, with memory bounded by the key bound and one line
// (readOldFloorFrom). A removal in the record removed applies only when it
// was recorded against this floor's inode (dropBefore).
func (s *FileStore) readOldFloor(lfd int, in rebuildInput, removed *removedScopes) (*oldFloor, error) {
	o, err := s.openOldLog(lfd, userFloorLogName)
	if err != nil {
		return nil, err
	}
	defer o.close()
	in.removed = removed.dropBefore(o.ino)
	return readOldFloorFrom(o.f, o.size, in, s.floorLog().keyBound(), s.floorLog().keyShare(), maxLogLine)
}

// readOldFloorFrom reads the first size bytes of the old floor f in
// streamed passes and admits its keys by these rules
// (docs/design/keystore.md § "Rebuild reads a flooded floor"):
//
//  1. a scope present on disk: every line whose key is on disk, and every
//     tombstone, whatever the uid's share: the writer takes a revocation's
//     tombstone past the share, and dropping one would reopen a copy-back;
//  2. a scope present on disk, every other live line (another generation
//     with no entry): oldest first, up to the uid's key share and while the
//     total stays under keyBound; the rest is dropped and counted in
//     pastShare;
//  3. a scope absent from disk and not recorded as removed: its tombstones
//     first, uids in first-appearance order, while the total stays under
//     keyBound; then, only when every such tombstone is in, its live lines,
//     per uid up to the share, in the same order; the rest is dropped and
//     counted in absent;
//  4. a scope rm-scope recorded: a line starting before its recorded floor
//     offset is dropped and its key counted in removed; a later line is a
//     re-minted scope's, and falls in rule 1, 2 or 3.
//
// A line over lineBound is skipped to its newline and counted, and a line
// that does not parse and a torn last line are dropped and counted. The
// one refusal left is rule 1 alone past keyBound; it names the scopes with
// the most keys, and rm-scope of one is the repair. Forged tombstones for
// a present uid can force it, and then the repair removes that uid's
// scope. Memory is the keys and names on disk, which rebuildScopes held to
// keyBound before this read, the admitted keys, at most keyBound, the
// present scopes' counts and one line's buffer, whatever the file's size.
func readOldFloorFrom(f io.ReaderAt, size int64, in rebuildInput, keyBound, share, lineBound int) (*oldFloor, error) {
	o := &oldFloor{maxSeq: map[floorKey]uint64{}, buried: map[floorKey]bool{}}
	total := len(in.disk)
	uidKeys := map[string]int{}
	for k := range in.disk {
		uidKeys[k.scope]++
	}
	removedSeen := map[floorKey]bool{}
	gone := func(k floorKey, start int64) bool { return start < in.removed[k.scope] }
	admitted := func(k floorKey) bool {
		_, live := o.maxSeq[k]
		return live || o.buried[k]
	}
	// take carries line r into the admitted key k, already counted.
	take := func(r floorRec) {
		switch {
		case r.tomb:
			o.buried[r.key] = true
			delete(o.maxSeq, r.key)
		case !o.buried[r.key]:
			o.maxSeq[r.key] = max(o.maxSeq[r.key], r.seq)
		}
	}
	// Pass 1: rules 1 and 4, and the lines that do not parse.
	off, torn, err := floorLines(io.NewSectionReader(f, 0, size), lineBound, func(line []byte, start int64, lerr error) error {
		if lerr != nil {
			o.overLong++
			return nil
		}
		r, err := parseFloorLine(line)
		if err != nil {
			o.dropped++
			return nil
		}
		_, onDisk := in.disk[r.key]
		switch {
		case gone(r.key, start):
			if !removedSeen[r.key] {
				if len(removedSeen) < keyBound {
					removedSeen[r.key] = true
				}
				o.removed++
			}
			return nil
		case !in.present[r.key.scope] || (!onDisk && !r.tomb):
			return nil // rule 3 or 2, a later pass
		case !onDisk && !admitted(r.key):
			uidKeys[r.key.scope]++
			total++
			if total > keyBound {
				return fmt.Errorf("the keys of the scopes on disk and their tombstones pass the new floor's key bound of %d, so dropping any would lower a real scope's floor or reopen a copy-back; remove a scope (sudo k3sm keys rm-scope); the scopes with the most keys: %s", keyBound, topScopes(uidKeys, 3))
			}
		}
		take(r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if torn {
		o.dropped++
	}
	// Pass 2: rule 2.
	err = floorRecsIn(f, off, lineBound, func(r floorRec, start int64) {
		_, onDisk := in.disk[r.key]
		switch {
		case gone(r.key, start) || !in.present[r.key.scope] || onDisk || r.tomb:
		case admitted(r.key):
			take(r)
		case uidKeys[r.key.scope] >= share || total >= keyBound:
			o.pastShare++
		default:
			uidKeys[r.key.scope]++
			total++
			take(r)
		}
	})
	if err != nil {
		return nil, err
	}
	// Pass 3: rule 3. fill admits the absent scopes' lines want selects:
	// holders are the absent scopes holding keys fill admitted, in
	// first-appearance order; once the bound is met, an earlier scope's new
	// key evicts one of the last holder's, so the result is the first
	// scopes' keys, in order, whatever the interleaving. A scope holds at
	// most limit(scope) keys. It reports whether it left any key out.
	fill := func(want func(floorRec) bool, limit func(string) int) (map[string]int, bool, error) {
		type holder struct {
			scope string
			keys  []floorKey
		}
		var holders []*holder
		held := map[string]*holder{}
		short := false
		err := floorRecsIn(f, off, lineBound, func(r floorRec, start int64) {
			if in.present[r.key.scope] || gone(r.key, start) || !want(r) {
				return
			}
			if admitted(r.key) {
				take(r)
				return
			}
			h := held[r.key.scope]
			switch {
			case h != nil && len(h.keys) >= limit(r.key.scope):
				short = true
				return
			case total < keyBound:
			case h == nil || holders[len(holders)-1] == h:
				short = true
				return
			default:
				last := holders[len(holders)-1]
				ev := last.keys[len(last.keys)-1]
				last.keys = last.keys[:len(last.keys)-1]
				delete(o.maxSeq, ev)
				delete(o.buried, ev)
				total--
				short = true
				if len(last.keys) == 0 {
					holders = holders[:len(holders)-1]
					delete(held, last.scope)
				}
			}
			if h == nil {
				h = &holder{scope: r.key.scope}
				holders = append(holders, h)
				held[r.key.scope] = h
			}
			h.keys = append(h.keys, r.key)
			total++
			take(r)
		})
		count := make(map[string]int, len(holders))
		for _, h := range holders {
			count[h.scope] = len(h.keys)
		}
		return count, short, err
	}
	tombs, short, err := fill(func(r floorRec) bool { return r.tomb }, func(string) int { return keyBound })
	if err != nil {
		return nil, err
	}
	if !short {
		_, _, err = fill(func(r floorRec) bool { return !r.tomb }, func(sc string) int { return max(share-tombs[sc], 0) })
		if err != nil {
			return nil, err
		}
	}
	// Pass 4: count the rule 3 lines left out.
	err = floorRecsIn(f, off, lineBound, func(r floorRec, start int64) {
		if !in.present[r.key.scope] && !gone(r.key, start) && !admitted(r.key) {
			o.absent++
		}
	})
	if err != nil {
		return nil, err
	}
	return o, nil
}

// floorRecsIn streams the first off bytes of f and calls fn with each line
// that parses and the offset it starts at.
func floorRecsIn(f io.ReaderAt, off int64, lineBound int, fn func(floorRec, int64)) error {
	_, _, err := floorLines(io.NewSectionReader(f, 0, off), lineBound, func(line []byte, start int64, lerr error) error {
		if lerr != nil {
			return nil
		}
		if r, err := parseFloorLine(line); err == nil {
			fn(r, start)
		}
		return nil
	})
	return err
}

// topScopes names the n scopes holding the most keys in count, with their
// counts, for the rebuild's one refusal.
func topScopes(count map[string]int, n int) string {
	scopes := make([]string, 0, len(count))
	for sc := range count {
		scopes = append(scopes, sc)
	}
	slices.SortFunc(scopes, func(a, b string) int {
		if c := count[b] - count[a]; c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	parts := make([]string, 0, n)
	for _, sc := range scopes[:min(n, len(scopes))] {
		parts = append(parts, fmt.Sprintf("%s (%d keys)", sc, count[sc]))
	}
	return strings.Join(parts, ", ")
}

// errDiskPastBound stops rebuildScope once the keys or entry names it
// collected pass the key bound.
var errDiskPastBound = errors.New("the keys on disk pass the floor's key bound")

// rebuildScopes opens every scope under .user/ without the GeneratedUID
// check and returns the line each key on disk gets, and the set of scopes
// present. Any scope that does not open refuses, naming it. It stops
// collecting once the keys or the entry names on disk pass keyBound, and
// refuses, naming the scopes with the most entries, before the old floor
// is read: its memory is held to the bound. The scope walk is bounded by
// eachScopeDir's listing bound.
func (s *FileStore) rebuildScopes(ctx context.Context, root *os.Root, keyBound int) (rebuildInput, error) {
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{}, names: map[nameKey]bool{}}
	exists, err := rootHasUserScopes(root)
	if err != nil || !exists {
		return in, err
	}
	k, err := s.loadMasterLocked()
	if err != nil {
		return rebuildInput{}, err
	}
	err = s.eachScopeDir(ctx, root, func(name string, _ *os.Root) error {
		id, _ := strconv.ParseUint(name, 10, 32) // eachScopeDir passes only decimal uids
		u := &UserScope{s: s, uid: uint32(id), scope: userScopeOf(uint32(id))}
		in.present[u.scope] = true
		err := u.rebuildScope(root, k, in, keyBound)
		if errors.Is(err, errDiskPastBound) {
			count := map[string]int{}
			for nk := range in.names {
				count[nk.scope]++
			}
			return fmt.Errorf("the entries of the scopes on disk pass the new floor's key bound of %d, so the rebuild would lower a real scope's floor; remove a scope (sudo k3sm keys rm-scope); the scopes with the most entries: %s", keyBound, topScopes(count, 3))
		}
		if err != nil {
			return fmt.Errorf("the scope %s does not open, so the rebuild would lower its floor: %w; repair it, or remove it (sudo k3sm keys rm-scope %s --yes)", u.scope, err, u.scope)
		}
		return nil
	})
	if err != nil {
		return rebuildInput{}, err
	}
	return in, nil
}

// rebuildScope adds u's lines to disk: its delivery record's at its
// authenticated sequence, and one per entry directory holding a generation
// file, at the pointer's sequence when the pointer authenticates and at 0
// for the generation file's generation when it does not. It stops with
// errDiskPastBound once the keys or names collected pass keyBound.
func (u *UserScope) rebuildScope(root *os.Root, k keys, in rebuildInput, keyBound int) error {
	disk := in.disk
	o, err := u.openScopeForRevoke(root, k)
	if err != nil {
		return err
	}
	defer o.close()
	seq, _, err := u.readDeliveriesUnfloored(o)
	if err != nil {
		return err
	}
	disk[floorKey{u.scope, deliveriesFloorName, o.gen}] = seq
	in.names[nameKey{u.scope, deliveriesFloorName}] = true
	entries, err := u.s.openSubdir(o.dir, scopeEntriesName, false)
	if err != nil {
		return fmt.Errorf("%s: %w", scopeEntriesName, err)
	}
	defer func() { _ = entries.Close() }() // read-only
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return fmt.Errorf("list %s: %w", scopeEntriesName, err)
	}
	for _, name := range names {
		if len(in.disk) > keyBound || len(in.names) > keyBound {
			return errDiskPastBound
		}
		if checkName(name) != nil {
			continue // a temporary name, never an entry
		}
		e, err := openEntryDirRaw(entries, name)
		if err != nil {
			continue // no entry directory: no generation file to record
		}
		in.names[nameKey{u.scope, name}] = true
		gen, gerr := readGeneration(e.root)
		pgen, pseq, ok := authenticatedPointer(e, o.uk)
		e.close()
		switch {
		case ok:
			disk[floorKey{u.scope, name, pgen}] = max(disk[floorKey{u.scope, name, pgen}], pseq)
		case gerr == nil:
			kk := floorKey{u.scope, name, gen}
			if _, seen := disk[kk]; !seen {
				disk[kk] = 0
			}
		}
	}
	if len(in.disk) > keyBound || len(in.names) > keyBound {
		return errDiskPastBound
	}
	return nil
}

// readDeliveriesUnfloored reads and authenticates u's delivery record
// without checking it against the floor (which rebuild is writing), and
// returns its sequence and entries.
func (u *UserScope) readDeliveriesUnfloored(o *openedScope) (uint64, []delivery, error) {
	b, fi, err := readFile(o.dir, deliveriesName, maxDeliveriesRecordSize)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0, nil, fmt.Errorf("%w: the scope has a scope key and no %s record", ErrScopeAbsent, deliveriesName)
	case errors.Is(err, errBadFile):
		return 0, nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, deliveriesName, err)
	case err != nil:
		return 0, nil, fmt.Errorf("read %s: %w", deliveriesName, err)
	}
	if err := u.s.checkOwned(fi, fileMode); err != nil {
		return 0, nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, deliveriesName, err)
	}
	r, err := parseDeliveriesRecord(b)
	if err != nil {
		return 0, nil, err
	}
	if r.generation != o.gen {
		return 0, nil, fmt.Errorf("%w: %s is not bound to this scope's owner", ErrCorrupt, deliveriesName)
	}
	pt, err := r.open(o.key, u.scope)
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", deliveriesName, err)
	}
	ds, err := parseDeliveries(pt)
	if err != nil {
		return 0, nil, err
	}
	return r.version, ds, nil
}

// mergeFloor is the new floor's lines, in key order: every tombstone the
// reader admitted, and per live key the higher of the admitted and the
// on-disk sequence, a buried key getting its tombstone only. It returns the
// lines and the key count.
func mergeFloor(old *oldFloor, disk map[floorKey]uint64) ([][]byte, int) {
	type out struct {
		seq  uint64
		tomb bool
	}
	keys := map[floorKey]out{}
	for k := range old.buried {
		keys[k] = out{tomb: true}
	}
	for k, seq := range old.maxSeq {
		if !old.buried[k] {
			keys[k] = out{seq: seq}
		}
	}
	for k, seq := range disk {
		if old.buried[k] {
			continue
		}
		if o, ok := keys[k]; !ok || seq > o.seq {
			keys[k] = out{seq: seq}
		}
	}
	order := make([]floorKey, 0, len(keys))
	for k := range keys {
		order = append(order, k)
	}
	slices.SortFunc(order, func(a, b floorKey) int {
		if c := strings.Compare(a.scope, b.scope); c != 0 {
			return c
		}
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		return bytes.Compare(a.gen[:], b.gen[:])
	})
	lines := make([][]byte, 0, len(order))
	for _, k := range order {
		var (
			line []byte
			err  error
		)
		if o := keys[k]; o.tomb {
			line, err = tombLine(k.scope, k.name, k.gen)
		} else {
			line, err = floorLine(k.scope, k.name, k.gen, o.seq)
		}
		if err == nil { // every key here parsed or came from a checked name
			lines = append(lines, line)
		}
	}
	return lines, len(lines)
}
