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

	"golang.org/x/sys/unix"
)

// The root maintenance verb floor --rebuild (docs/design/keystore.md §
// "Root maintenance verbs"): it writes a new user-scope floor from the old
// one and every scope's entries, and swaps it in under the maintenance
// procedure, through one data-root descriptor.

const (
	// maintenanceMarkerName is present in the data root only while a
	// maintenance verb runs; the listener stays down while it is.
	maintenanceMarkerName = "keystore-maintenance"
	// floorStagingName is floor --rebuild's staging file.
	floorStagingName = userFloorLogName + ".new"
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

// RebuildReport is what floor --rebuild did: the scopes it read, the keys
// the new floor holds, the old floor's lines it dropped because they did
// not parse, and the keys of removed scopes it did not carry forward.
type RebuildReport struct {
	Scopes, Keys, Dropped, RemovedKeys int
}

// errRebuildRefused marks a rebuild that refused before it touched the old
// floor: nothing changed.
var errRebuildRefused = errors.New("floor --rebuild refused and changed nothing")

// RebuildFloor rebuilds the user-scope floor (floor --rebuild). Run as
// root: it takes the exclusive store lock, waiting at most 30 s, then the
// floor lock, writes the maintenance marker, reads the old floor on its own
// descriptor (unflagged and root's after a restore, or flagged and the
// service user's), carries forward every line that parses, opens every
// scope under .user/ without the GeneratedUID check, and writes one line
// per key: every carried tombstone, which no entry line overrides, and per
// live key the higher of the carried sequence and the one on disk. A key of
// a scope whose directory is gone is dropped. Any scope that does not open
// refuses the rebuild, naming the scope, before the old floor is touched.
//
// The new file is created root-owned 0600 with O_CREAT|O_EXCL|O_NOFOLLOW,
// written and fsynced; then the old file's flag is cleared and it is made
// root's 0600, in one step on its descriptor; the new file is renamed over
// the canonical name; sappnd is set on the new file's held descriptor, and
// only then is it handed to the service user. The marker is removed last.
func (s *FileStore) RebuildFloor(ctx context.Context, attrs FileAttrWriter) (RebuildReport, error) {
	var rep RebuildReport
	if err := s.checkConfig(); err != nil {
		return rep, err
	}
	m, err := s.beginMaintenance(ctx, errRebuildRefused)
	if err != nil {
		return rep, err
	}
	defer m.end()
	old, err := s.readOldFloor(m.dfd)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: the old floor %s cannot be read: %w", errRebuildRefused, userFloorLogName, err)
	}
	defer func() { _ = old.f.Close() }() // read-only until its attributes change
	rep.Dropped = old.dropped
	disk, present, err := s.rebuildScopes(ctx, m.root)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRebuildRefused, err)
	}
	rep.Scopes = len(present)
	lines, keys, removed := mergeFloor(old, disk, present)
	rep.Keys, rep.RemovedKeys = keys, removed
	if bound := s.floorLog().keyBound(); keys > bound {
		m.refused()
		return rep, fmt.Errorf("%w: the new floor would hold %d keys, past its key bound of %d", errRebuildRefused, keys, bound)
	}
	if err := s.swapLog(m, old.f, floorStagingName, userFloorLogName, lines, attrs, swapHooks{}); err != nil {
		return rep, err
	}
	return rep, nil
}

// floorLog is the file-backed floor's appendLog, for its key bound.
func (s *FileStore) floorLog() *appendLog {
	if f, ok := s.userFloor.(*fileFloorLog); ok {
		return f.log
	}
	return newFileFloorLog(s).log
}

// maintenance is a maintenance verb's hold: the floor lock, the store lock,
// the keystore root and the judged data-root descriptor.
type maintenance struct {
	s      *FileStore
	root   *os.Root
	done   func()
	fl     *floorLock
	dfd    int
	marker bool
	// refusal is the verb's refused-and-changed-nothing error, which a
	// refusal before the old file's flag clear wraps.
	refusal error
	// keep leaves the marker in place: a step past the old file's flag
	// clear failed, so the listener must stay down until a rerun.
	keep bool
}

// lockMaintenance takes a maintenance verb's two locks in the order every
// verb that takes both keeps (docs/design/keystore.md § "Concurrency"):
// keystore-lock first, then the exclusive store lock, waiting at most
// maintenanceLockWait for it. A failure releases what it took.
func (s *FileStore) lockMaintenance(ctx context.Context, root *os.Root) (*floorLock, func(), error) {
	fl, _, err := s.lockFloor(ctx)
	if err != nil {
		return nil, nil, err
	}
	saved := s.lockWait
	s.lockWait = maintenanceLockWait
	unlock, err := s.lock(ctx, root, true)
	s.lockWait = saved
	if err != nil {
		fl.unlock()
		return nil, nil, err
	}
	return fl, unlock, nil
}

// beginMaintenance takes keystore-lock, then the exclusive store lock (at
// most maintenanceLockWait; lockMaintenance), opens and judges the data
// root and writes the marker. refusal is the verb's
// refused-and-changed-nothing error.
func (s *FileStore) beginMaintenance(ctx context.Context, refusal error) (*maintenance, error) {
	root, err := s.openDir(s.dir, false)
	if err != nil {
		return nil, err
	}
	fl, unlock, err := s.lockMaintenance(ctx, root)
	if err != nil {
		_ = root.Close() // nothing written
		return nil, err
	}
	m := &maintenance{s: s, root: root, fl: fl, done: func() { unlock(); _ = root.Close() }, dfd: -1, refusal: refusal}
	if m.dfd, err = s.openLogDataRoot(); err != nil {
		m.end()
		return nil, err
	}
	if err := m.writeMarker(); err != nil {
		m.end()
		return nil, err
	}
	return m, nil
}

// writeMarker creates the marker O_CREAT|O_EXCL|O_NOFOLLOW. A marker a
// crashed run left is kept when it is a regular file of the data root's
// owner; anything else at the name refuses.
func (m *maintenance) writeMarker() error {
	fd, err := unix.Openat(m.dfd, maintenanceMarkerName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, markerMode)
	if errors.Is(err, unix.EEXIST) {
		var st unix.Stat_t
		if err := unix.Fstatat(m.dfd, maintenanceMarkerName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("stat %s: %w", maintenanceMarkerName, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(m.s.floorUID) {
			return fmt.Errorf("%w: %s is not a regular file of the data root's owner", errLogUntrusted, maintenanceMarkerName)
		}
		m.marker = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", maintenanceMarkerName, err)
	}
	m.marker = true
	err = unix.Fsync(fd)
	if cerr := unix.Close(fd); err == nil {
		err = cerr
	}
	return err
}

// refused marks a refusal before the old file was touched: the marker
// goes.
func (m *maintenance) refused() { m.keep = false }

// end removes the marker unless keep, then releases the locks.
func (m *maintenance) end() {
	if m.marker && !m.keep {
		_ = unix.Unlinkat(m.dfd, maintenanceMarkerName, 0) // a marker left only keeps the listener down
		_ = unix.Fsync(m.dfd)
	}
	if m.dfd >= 0 {
		_ = unix.Close(m.dfd) // read-only directory descriptor
	}
	if m.fl != nil {
		m.fl.unlock()
	}
	m.done()
}

// oldFloor is the old floor as rebuild read it: the descriptor it read,
// every key's highest carried sequence, the carried tombstones, and the
// count of lines dropped because they did not parse.
type oldFloor struct {
	f       *os.File
	maxSeq  map[floorKey]uint64
	buried  map[floorKey]bool
	dropped int
}

// readOldFloor opens the canonical floor through dfd O_NOFOLLOW, refuses
// anything but a regular file with one link, reads it within the reader's
// size bound and parses it line by line. A torn last line, a line over
// maxLogLine, a line outside the grammar and a line that would add a key
// past the reader's key bound are dropped and counted. Its owner and flag
// are not judged: after a restore it is root's and unflagged.
func (s *FileStore) readOldFloor(dfd int) (*oldFloor, error) {
	f, err := openOldLog(dfd, userFloorLogName)
	if err != nil {
		return nil, err
	}
	bound := s.logReadBound()
	b, err := io.ReadAll(io.LimitReader(f, bound+1))
	if err != nil {
		_ = f.Close() // read-only
		return nil, err
	}
	if int64(len(b)) > bound {
		_ = f.Close() // read-only
		return nil, errLogTooLarge
	}
	o := &oldFloor{f: f, maxSeq: map[floorKey]uint64{}, buried: map[floorKey]bool{}}
	keyBound := s.floorLog().readKeyBound()
	keys := 0
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			o.dropped++ // a torn last line
			break
		}
		line := b[:i]
		b = b[i+1:]
		if len(line) == 0 {
			continue // an append's leading newline
		}
		r, err := parseFloorLine(line)
		if err != nil {
			o.dropped++
			continue
		}
		_, inSeq := o.maxSeq[r.key]
		if !inSeq && !o.buried[r.key] {
			if keys >= keyBound {
				o.dropped++
				continue
			}
			keys++
		}
		switch {
		case r.tomb:
			o.buried[r.key] = true
		case !inSeq || r.seq > o.maxSeq[r.key]:
			o.maxSeq[r.key] = r.seq
		}
	}
	return o, nil
}

// openOldLog opens name, a log or an archive in the data root, read-only
// through dfd with O_NOFOLLOW, and refuses anything but a regular file
// with one link: a planted symlink, FIFO or hard link refuses the verb.
// Its owner and flag are not judged: after a restore it is root's and
// unflagged.
func openOldLog(dfd int, name string) (*os.File, error) {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close() // read-only
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		_ = f.Close() // read-only
		return nil, fmt.Errorf("%w: %s is not a regular file with one link", errLogUntrusted, name)
	}
	return f, nil
}

// rebuildScopes opens every scope under .user/ without the GeneratedUID
// check and returns the line each key on disk gets, and the set of scopes
// present. Any scope that does not open refuses, naming it.
func (s *FileStore) rebuildScopes(ctx context.Context, root *os.Root) (map[floorKey]uint64, map[string]bool, error) {
	disk := map[floorKey]uint64{}
	present := map[string]bool{}
	exists, err := rootHasUserScopes(root)
	if err != nil || !exists {
		return disk, present, err
	}
	k, err := s.loadMasterLocked()
	if err != nil {
		return nil, nil, err
	}
	err = s.eachScopeDir(ctx, root, func(name string, _ *os.Root) error {
		id, _ := strconv.ParseUint(name, 10, 32) // eachScopeDir passes only decimal uids
		u := &UserScope{s: s, uid: uint32(id), scope: userScopeOf(uint32(id))}
		present[u.scope] = true
		if err := u.rebuildScope(root, k, disk); err != nil {
			return fmt.Errorf("the scope %s does not open, so the rebuild would lower its floor: %w", u.scope, err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return disk, present, nil
}

// rebuildScope adds u's lines to disk: its delivery record's at its
// authenticated sequence, and one per entry directory holding a generation
// file, at the pointer's sequence when the pointer authenticates and at 0
// for the generation file's generation when it does not.
func (u *UserScope) rebuildScope(root *os.Root, k keys, disk map[floorKey]uint64) error {
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
		if checkName(name) != nil {
			continue // a temporary name, never an entry
		}
		e, err := openEntryDirRaw(entries, name)
		if err != nil {
			continue // no entry directory: no generation file to record
		}
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

// mergeFloor is the new floor's lines, in key order: every carried
// tombstone of a present scope, and per live key of a present scope the
// higher of the carried and the on-disk sequence, a buried key getting its
// tombstone only. It returns the lines, the key count and the count of
// carried keys dropped because their scope is gone.
func mergeFloor(old *oldFloor, disk map[floorKey]uint64, present map[string]bool) ([][]byte, int, int) {
	type out struct {
		seq  uint64
		tomb bool
	}
	keys := map[floorKey]out{}
	removed := 0
	for k := range old.buried {
		if !present[k.scope] {
			removed++
			continue
		}
		keys[k] = out{tomb: true}
	}
	for k, seq := range old.maxSeq {
		if old.buried[k] {
			continue
		}
		if !present[k.scope] {
			removed++
			continue
		}
		keys[k] = out{seq: seq}
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
	return lines, len(lines), removed
}

// swapHooks are the steps a verb adds to swapLog's: afterClear runs once
// the old file is unflagged and root's 0600, before the new file is
// renamed over canonical (audit --rotate shifts the archives there and
// moves the old log to .1), and afterFlag once the new file is flagged,
// before it is handed to the service user (rotate flags .1 there). Either
// may be nil; a failure in either keeps the marker.
type swapHooks struct {
	afterClear, afterFlag func() error
}

// swapLog writes lines to the staging file and swaps it in for canonical,
// whose descriptor old the caller holds: write and fsync the new file
// (root's 0600), clear old's flag and make it root's 0600 in one step,
// run hooks.afterClear, rename the new file over canonical, set sappnd on
// the new file's held descriptor, run hooks.afterFlag and only then hand
// the new file to the service user. A flagged file is never renamed and
// nothing is renamed over one. A failure past old's flag clear keeps the
// marker, so the listener stays down until a rerun.
func (s *FileStore) swapLog(m *maintenance, old *os.File, staging, canonical string, lines [][]byte, attrs FileAttrWriter, hooks swapHooks) error {
	if err := removeStale(m.dfd, staging, attrs); err != nil {
		m.refused()
		return fmt.Errorf("%w: %w", m.refusal, err)
	}
	fd, err := unix.Openat(m.dfd, staging, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, logMode)
	if err != nil {
		m.refused()
		return fmt.Errorf("%w: create %s: %w", m.refusal, staging, err)
	}
	nf := os.NewFile(uintptr(fd), staging)
	defer func() { _ = nf.Close() }() // fsynced below
	unstage := func(err error) error {
		_ = unix.Unlinkat(m.dfd, staging, 0) // the old log is untouched
		m.refused()
		return fmt.Errorf("%w: %w", m.refusal, err)
	}
	if err := attrs.Fchown(fd, s.floorUID, s.floorGID); err != nil {
		return unstage(fmt.Errorf("own %s: %w", staging, err))
	}
	if err := attrs.Fchmod(fd, logMode); err != nil {
		return unstage(fmt.Errorf("chmod %s: %w", staging, err))
	}
	if _, err := nf.Write(bytes.Join(lines, nil)); err != nil {
		return unstage(fmt.Errorf("write %s: %w", staging, err))
	}
	if err := nf.Sync(); err != nil {
		return unstage(fmt.Errorf("fsync %s: %w", staging, err))
	}
	// The old name must still be the file read.
	var named, held unix.Stat_t
	if err := unix.Fstatat(m.dfd, canonical, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unstage(fmt.Errorf("stat %s: %w", canonical, err))
	}
	if err := unix.Fstat(int(old.Fd()), &held); err != nil {
		return unstage(fmt.Errorf("stat %s: %w", canonical, err))
	}
	if named.Dev != held.Dev || named.Ino != held.Ino {
		return unstage(fmt.Errorf("%w: %s was replaced while the verb held it", errLogUntrusted, canonical))
	}
	// From here a failure leaves the marker: the listener stays down.
	m.keep = true
	if err := s.unflagToRoot(int(old.Fd()), "the old "+canonical, attrs); err != nil {
		return err
	}
	if hooks.afterClear != nil {
		if err := hooks.afterClear(); err != nil {
			return err
		}
	}
	if err := unix.Renameat(m.dfd, staging, m.dfd, canonical); err != nil {
		return fmt.Errorf("rename %s over %s: %w; rerun the verb", staging, canonical, err)
	}
	if err := attrs.Fchflags(fd, sfAppend); err != nil {
		return fmt.Errorf("flag the new %s append-only: %w; rerun the verb", canonical, err)
	}
	if hooks.afterFlag != nil {
		if err := hooks.afterFlag(); err != nil {
			return err
		}
	}
	if err := attrs.Fchown(fd, int(s.uid), int(s.gid)); err != nil {
		return fmt.Errorf("hand the new %s to the service user: %w; rerun the verb", canonical, err)
	}
	if err := unix.Fsync(m.dfd); err != nil {
		return fmt.Errorf("fsync the data root: %w; rerun the verb", err)
	}
	m.keep = false
	return nil
}

// unflagToRoot clears the flag of the file fd holds and, in the same
// step, makes it root's 0600 on that descriptor (Open requirement 1), so
// the service user can never open it while it is unflagged. what names it
// in the error, which asks for a rerun: the marker stays.
func (s *FileStore) unflagToRoot(fd int, what string, attrs FileAttrWriter) error {
	if err := attrs.Fchflags(fd, 0); err != nil {
		return fmt.Errorf("clear the flag of %s: %w; rerun the verb", what, err)
	}
	if err := attrs.Fchown(fd, s.floorUID, s.floorGID); err != nil {
		return fmt.Errorf("own %s: %w; rerun the verb", what, err)
	}
	if err := attrs.Fchmod(fd, logMode); err != nil {
		return fmt.Errorf("chmod %s: %w; rerun the verb", what, err)
	}
	return nil
}

// removeStale removes a staging file a crashed run left at name: opened
// O_NOFOLLOW through dfd, refused unless a regular file, its flag cleared
// on its descriptor, then unlinked with unlinkat. A missing name is fine.
func removeStale(dfd int, name string, attrs FileAttrWriter) error {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errLogUntrusted, name, err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s is not a regular file", errLogUntrusted, name)
	}
	if err := attrs.Fchflags(fd, 0); err != nil {
		return fmt.Errorf("clear the flag of %s: %w", name, err)
	}
	return unix.Unlinkat(dfd, name, 0)
}
