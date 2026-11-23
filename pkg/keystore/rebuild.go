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
	"log/slog"
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
	// floorStagingName is floor --rebuild's staging file, in the staging
	// directory.
	floorStagingName = userFloorLogName + ".new"
	// stagingDirName is the maintenance verbs' staging directory in the data
	// root: root's 0700, so no other user can reach, and so hard-link, a
	// staging file while it is written. It is on the data root's volume, so
	// the staging file is renamed out of it into the logs directory.
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

// The steps a SwapStepper is called before, in the order the swap runs
// them (docs/design/keystore.md § "The swap"). The attribute calls between
// them (the new log's fchown and fchmod, the gate's close and open, the old
// log's flag clear, the new log's flag) reach the writer itself.
const (
	swapStepReadOld       = "read-old"
	swapStepStageArchive  = "stage-archive"
	swapStepStage         = "stage"
	swapStepReadTail      = "read-tail"
	swapStepUnlinkOld     = "unlink-old"
	swapStepShiftArchives = "shift-archives"
	swapStepPlaceArchive  = "place-archive"
	swapStepRename        = "rename"
	swapStepEnd           = "end"
)

// RebuildReport is what floor --rebuild did: the scopes it read, the keys
// the new floor holds, and what it dropped, by class: the old floor's lines
// that did not parse (a torn last line among them), its lines over the
// per-line bound, its live lines with no key on disk that the key bound
// left no room for (the forgeable ones, dropped first), and the keys of
// scopes root removed and recorded, which it did not carry forward.
type RebuildReport struct {
	Scopes, Keys, Dropped, OverLong, ForgedLive, RemovedKeys int
}

// Lost reports whether the rebuild dropped any line or key.
func (r RebuildReport) Lost() bool {
	return r.Dropped+r.OverLong+r.ForgedLive+r.RemovedKeys > 0
}

// errRebuildRefused marks a rebuild that refused before it touched the old
// floor: nothing changed.
var errRebuildRefused = errors.New("floor --rebuild refused and changed nothing")

// RebuildFloor rebuilds the user-scope floor (floor --rebuild). Run as
// root: it writes the maintenance marker, takes the floor lock, then the
// exclusive store lock, waiting at most 30 s, reads the old floor on its own
// descriptor (unflagged and root's after a restore, or flagged and the
// service user's; an old floor with more than one link is read, with a
// Warn, since the rebuild replaces its inode), carries forward every line
// that parses, opens every
// scope under .user/ without the GeneratedUID check, and writes one line
// per key: every carried tombstone, which no entry line overrides, and per
// live key the higher of the carried sequence and the one on disk. A key of
// a scope whose directory is gone is dropped. Any scope that does not open
// refuses the rebuild, naming the scope, before the old floor is touched.
//
// The old floor is read while still flagged, and the new one swapped in by
// the gated swap (swapLog): lines the old floor gained after the first read
// are re-read under the closed gate and merged (mergeTail). A rerun after a
// crash finishes from whatever state the crash left (resumeSwap). The
// marker is removed last.
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
	m.hook, _ = attrs.(SwapStepper)
	done, err := s.resumeSwap(m, userFloorLogName, floorStagingName, nil, attrs)
	if done || err != nil {
		return rep, err
	}
	if err := m.step(swapStepReadOld); err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRebuildRefused, err)
	}
	removed, err := s.readRemovedScopes(m.dfd)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRebuildRefused, err)
	}
	in, err := s.rebuildScopes(ctx, m.root)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRebuildRefused, err)
	}
	in.removed = removed.scopes()
	rep.Scopes = len(in.present)
	old, err := s.readOldFloor(m.lfd, in)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: the old floor %s cannot be read: %w", errRebuildRefused, userFloorLogName, err)
	}
	defer func() { _ = old.f.Close() }() // read-only
	rep.Dropped, rep.OverLong, rep.ForgedLive, rep.RemovedKeys = old.dropped, old.overLong, old.forged, old.removed
	lines, keys := mergeFloor(old, in.disk)
	rep.Keys = keys
	sw := logSwap{
		canonical: userFloorLogName,
		staging:   floorStagingName,
		old:       old.f,
		off:       old.off,
		content:   bytes.Join(lines, nil),
		tail:      func(b []byte) ([]byte, error) { return mergeTail(b, in), nil },
	}
	if err := s.swapLog(m, sw, attrs); err != nil {
		return rep, err
	}
	return rep, nil
}

// mergeTail is the lines the old floor gained after rebuild read it (step
// 5), to append to the new floor: every whole line that parses, but of a
// scope root removed and recorded. The floor's reader takes a key's highest sequence and its
// tombstone over all its lines, so appending them merges them.
func mergeTail(b []byte, in rebuildInput) []byte {
	var out []byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break // a torn last line
		}
		line := b[:i]
		b = b[i+1:]
		if len(line) == 0 {
			continue
		}
		r, err := parseFloorLine(line)
		if err != nil || (!in.present[r.key.scope] && in.removed[r.key.scope]) {
			continue
		}
		out = append(append(out, line...), '\n')
	}
	return out
}

// floorLog is the file-backed floor's appendLog, for its key bound.
func (s *FileStore) floorLog() *appendLog {
	if f, ok := s.userFloor.(*fileFloorLog); ok {
		return f.log
	}
	return newFileFloorLog(s).log
}

// maintenance is a maintenance verb's hold: the floor lock, the store lock,
// the keystore root, the judged data-root descriptor and the staging
// directory's.
type maintenance struct {
	s      *FileStore
	root   *os.Root
	done   func()
	fl     *floorLock
	dfd    int
	sfd    int
	lfd    int
	marker bool
	// crashed is a marker an earlier run left: it stood before this run
	// wrote one and still stood once this run held both locks, so no verb
	// that ran in between removed it.
	crashed bool
	// refusal is the verb's refused-and-changed-nothing error, which a
	// refusal before the old file's flag clear wraps.
	refusal error
	// keep leaves the marker in place: a step past the old file's flag
	// clear failed, so the listener must stay down until a rerun.
	keep bool
	// hook is the attribute writer's step seam, or nil.
	hook SwapStepper
}

// step calls the step seam, when there is one, before the step name.
func (m *maintenance) step(name string) error {
	if m.hook == nil {
		return nil
	}
	if err := m.hook.BeforeSwapStep(name); err != nil {
		return fmt.Errorf("before the step %s: %w; rerun the verb", name, err)
	}
	return nil
}

// errStoreLockHeld is the maintenance verbs' refusal when the store lock
// is not had within maintenanceLockWait. The verb already holds
// keystore-lock, which every root verb takes first, so the holder is a
// process running as the service user: the server or one of its processes.
var errStoreLockHeld = errors.New("a process running as the service user held the store lock (keystore/.lock) for 30 s: stop the server (sudo k3sm stop) or that process, then rerun; nothing was changed")

// lockMaintenance takes a maintenance verb's two locks in the order every
// verb that takes both keeps (docs/design/keystore.md § "Concurrency"):
// keystore-lock first, then the exclusive store lock, waiting at most
// maintenanceLockWait for it (errStoreLockHeld past it). A failure
// releases what it took.
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
		if errors.Is(err, errLockTimeout) {
			return nil, nil, errStoreLockHeld
		}
		return nil, nil, err
	}
	return fl, unlock, nil
}

// beginMaintenance opens and judges the data root, writes the marker, then
// takes keystore-lock and the exclusive store lock (at most
// maintenanceLockWait; lockMaintenance), as the design orders it: the marker
// first, so the listener stops while the verb waits. The marker is no lock,
// so the lock order is untouched. Holding both locks it writes the marker
// again when a verb that ran in the meantime removed it, and opens and
// judges the staging directory. refusal is the verb's
// refused-and-changed-nothing error. A failure before the locks are held
// removes only a marker this run created.
func (s *FileStore) beginMaintenance(ctx context.Context, refusal error) (*maintenance, error) {
	root, err := s.openDir(s.dir, false)
	if err != nil {
		return nil, err
	}
	m := &maintenance{s: s, root: root, done: func() { _ = root.Close() }, dfd: -1, sfd: -1, lfd: -1, refusal: refusal}
	if m.dfd, err = s.openLogDataRoot(); err != nil {
		m.end()
		return nil, err
	}
	pre, err := m.writeMarker()
	if err != nil {
		m.end()
		return nil, err
	}
	fl, unlock, err := s.lockMaintenance(ctx, root)
	if err != nil {
		m.marker = pre // a marker another run wrote stays
		m.end()
		return nil, err
	}
	m.fl = fl
	m.done = func() { unlock(); _ = root.Close() }
	post, err := m.writeMarker()
	if err != nil {
		m.end()
		return nil, err
	}
	m.marker = true
	m.crashed = !pre && !post
	if m.sfd, err = m.openStagingDir(); err != nil {
		m.end()
		return nil, fmt.Errorf("%w: %w", refusal, err)
	}
	// A rerun after a crash finds the gate closed, and opens it once done.
	if m.lfd, err = s.openLogsDir(m.dfd, true); err != nil {
		m.end()
		return nil, fmt.Errorf("%w: %w", refusal, err)
	}
	for _, name := range []string{userFloorLogName, auditLogName} {
		var st unix.Stat_t
		if unix.Fstatat(m.dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
			m.end()
			return nil, fmt.Errorf("%w: %w", refusal, errLogOldLocation(name))
		}
	}
	return m, nil
}

// writeMarker creates the marker O_CREAT|O_EXCL|O_NOFOLLOW and reports
// whether it did. A marker already there is kept when it is a regular file
// with one link, of the data root's owner (root); anything else at the name
// refuses.
func (m *maintenance) writeMarker() (bool, error) {
	fd, err := unix.Openat(m.dfd, maintenanceMarkerName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, markerMode)
	if errors.Is(err, unix.EEXIST) {
		var st unix.Stat_t
		if err := unix.Fstatat(m.dfd, maintenanceMarkerName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false, fmt.Errorf("stat %s: %w", maintenanceMarkerName, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int64(st.Uid) != int64(m.s.floorUID) {
			return false, fmt.Errorf("%w: %s is not a regular file with one link, of the data root's owner", errLogUntrusted, maintenanceMarkerName)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create %s: %w", maintenanceMarkerName, err)
	}
	m.marker = true
	err = unix.Fsync(fd)
	if cerr := unix.Close(fd); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Fsync(m.dfd)
	}
	return true, err
}

// openStagingDir creates the staging directory in the data root, root's
// 0700, or keeps the one a crashed run left, and opens it
// O_DIRECTORY|O_NOFOLLOW and judges it on its descriptor: a directory of
// the data root's owner (root), mode 0700, with no file flag beside
// SF_APPEND and no extended ACL. Only root can reach a name in it, so no
// other user can hard-link a staging file while it is written.
func (m *maintenance) openStagingDir() (int, error) {
	if err := unix.Mkdirat(m.dfd, stagingDirName, stagingDirMode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("create %s: %w", stagingDirName, err)
	}
	fd, err := unix.Openat(m.dfd, stagingDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: %s: %w", errLogUntrusted, stagingDirName, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("stat %s: %w", stagingDirName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int64(st.Uid) != int64(m.s.floorUID) || st.Mode&0o7777 != stagingDirMode {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("%w: %s is not a directory of the data root's owner at mode 0700", errLogUntrusted, stagingDirName)
	}
	if err := judgeFlagsACL(fd, fdFlags); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("%s: %w", stagingDirName, err)
	}
	return fd, nil
}

// refused marks a refusal before the old file was touched: the marker
// goes.
func (m *maintenance) refused() { m.keep = false }

// end removes the staging directory, when empty, and the marker unless
// keep, then releases the locks.
func (m *maintenance) end() {
	if m.lfd >= 0 {
		_ = unix.Close(m.lfd) // read-only directory descriptor
	}
	if m.sfd >= 0 {
		_ = unix.Close(m.sfd) // read-only directory descriptor
		if !m.keep {
			_ = unix.Unlinkat(m.dfd, stagingDirName, unix.AT_REMOVEDIR) // a staging directory left is reused by the rerun
		}
	}
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
// the keys admitted to the new floor with their highest carried sequence,
// the carried tombstones, and the counts of what was dropped, by class.
type oldFloor struct {
	f *os.File
	// off is the offset just past the last whole line read: the tail
	// re-read (step 5) starts there.
	off    int64
	maxSeq map[floorKey]uint64
	buried map[floorKey]bool
	// dropped counts the lines that did not parse and a torn last line;
	// overLong the lines over the per-line bound, skipped to their newline;
	// forged the live lines with no key on disk that the key bound left no
	// room for; removed the keys of scopes root removed and recorded.
	dropped, overLong, forged, removed int
}

// rebuildInput is what rebuild knows before it reads the old floor: the
// keys on disk, the scopes present, the (scope, name) of every entry
// directory present, and the scopes rm-scope recorded as removed.
type rebuildInput struct {
	disk    map[floorKey]uint64
	present map[string]bool
	names   map[nameKey]bool
	removed map[string]bool
}

// errFloorLineTooLong is a line over the per-line bound, skipped to its
// newline.
var errFloorLineTooLong = errors.New("a floor line is over the per-line bound")

// floorLines streams r line by line through a buffer of lineBound bytes
// (a line and its newline): fn gets each whole line, without its newline,
// or errFloorLineTooLong for one over the bound, which is skipped to its
// newline. It returns the offset just past the last whole line, and
// whether a torn last line (no newline) followed it; memory stays at the
// buffer whatever the size of r.
func floorLines(r io.Reader, lineBound int, fn func(line []byte, err error) error) (int64, bool, error) {
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
		off = pos
		line := b[:len(b)-1]
		var ferr error
		if long {
			line, ferr, long = nil, errFloorLineTooLong, false
		}
		if len(line) == 0 && ferr == nil {
			continue // an append's leading newline
		}
		if err := fn(line, ferr); err != nil {
			return off, false, err
		}
	}
}

// readOldFloor opens the canonical floor through the logs directory lfd
// O_NOFOLLOW (step 2 of the swap: read under the flag), refuses anything
// but a regular file, and streams it with no size bound and memory bounded
// by the key bound and one line (readOldFloorFrom). Its owner and flag are
// not judged: after a restore it is root's and unflagged.
func (s *FileStore) readOldFloor(lfd int, in rebuildInput) (*oldFloor, error) {
	f, err := openOldLog(lfd, userFloorLogName)
	if err != nil {
		return nil, err
	}
	o, err := readOldFloorFrom(f, in, s.floorLog().keyBound(), maxLogLine)
	if err != nil {
		_ = f.Close() // read-only
		return nil, err
	}
	o.f = f
	return o, nil
}

// readOldFloorFrom reads the old floor f in two streamed passes and admits
// its keys against keyBound, counting the keys on disk first, in this
// order (docs/design/keystore.md § "Rebuild reads a flooded floor"):
//
//  1. every tombstone, of any scope rm-scope did not record as removed,
//     and every live line whose key is on disk;
//  2. then, only while under the bound, live lines with no key on disk
//     whose entry directory stands (another generation of it);
//  3. then, only while under the bound, live lines with no entry directory
//     on disk: the ones the service user can forge, dropped first.
//
// A live line of steps 2 and 3 the bound leaves no room for is dropped and
// counted in forged.
//
// A line over lineBound is skipped to its newline and counted, a line that
// does not parse and a torn last line are dropped and counted, and a key of
// a recorded removed scope is dropped and counted. If the tombstones and
// the keys on disk alone pass the bound, it refuses, naming the scopes with
// the most keys: the one refusal left. Memory is the admitted keys, at most
// keyBound, and one line's buffer, whatever the file's size.
func readOldFloorFrom(f io.ReaderAt, in rebuildInput, keyBound, lineBound int) (*oldFloor, error) {
	o := &oldFloor{maxSeq: map[floorKey]uint64{}, buried: map[floorKey]bool{}}
	total := len(in.disk)
	removedSeen := map[floorKey]bool{}
	gone := func(k floorKey) bool { return !in.present[k.scope] && in.removed[k.scope] }
	off, torn, err := floorLines(io.NewSectionReader(f, 0, 1<<62), lineBound, func(line []byte, lerr error) error {
		if lerr != nil {
			o.overLong++
			return nil
		}
		r, err := parseFloorLine(line)
		if err != nil {
			o.dropped++
			return nil
		}
		switch {
		case gone(r.key):
			if !removedSeen[r.key] {
				if len(removedSeen) < keyBound {
					removedSeen[r.key] = true
				}
				o.removed++
			}
		case r.tomb:
			if o.buried[r.key] {
				return nil
			}
			o.buried[r.key] = true
			delete(o.maxSeq, r.key)
			if _, onDisk := in.disk[r.key]; !onDisk {
				total++
			}
			if total > keyBound {
				return fmt.Errorf("the tombstones and the keys on disk alone pass the new floor's key bound of %d, so dropping any would lower the floor; the scopes with the most keys: %s", keyBound, topScopes(o.buried, in.disk, 3))
			}
		default:
			if _, onDisk := in.disk[r.key]; onDisk && !o.buried[r.key] {
				o.maxSeq[r.key] = max(o.maxSeq[r.key], r.seq)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	o.off = off
	if torn {
		o.dropped++
	}
	// Live lines with no key on disk: those whose entry directory stands
	// first, then those with none, each only while under the bound.
	for _, withDir := range []bool{true, false} {
		_, _, err = floorLines(io.NewSectionReader(f, 0, off), lineBound, func(line []byte, lerr error) error {
			if lerr != nil {
				return nil
			}
			r, err := parseFloorLine(line)
			if err != nil || r.tomb || gone(r.key) || o.buried[r.key] || in.names[nameKey{r.key.scope, r.key.name}] != withDir {
				return nil
			}
			if _, onDisk := in.disk[r.key]; onDisk {
				return nil
			}
			if seq, ok := o.maxSeq[r.key]; ok {
				o.maxSeq[r.key] = max(seq, r.seq)
				return nil
			}
			if total >= keyBound {
				o.forged++
				return nil
			}
			o.maxSeq[r.key] = r.seq
			total++
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

// topScopes names the n scopes holding the most of the buried and on-disk
// keys, with their counts, for the rebuild's one refusal.
func topScopes(buried map[floorKey]bool, disk map[floorKey]uint64, n int) string {
	count := map[string]int{}
	for k := range buried {
		count[k.scope]++
	}
	for k := range disk {
		if !buried[k] {
			count[k.scope]++
		}
	}
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

// openOldLog opens name, a canonical log in the logs directory, read-only
// through lfd with O_NOFOLLOW, and refuses anything but a regular file: a
// planted symlink or FIFO refuses the verb. Its owner and flag are not
// judged: after a restore it is root's and unflagged. A log with more than
// one link is read as input, with a Warn naming it: the verb retires the
// canonical inode and swaps in a fresh one, so the other link keeps only
// the old file. The steady-state check (judgeLog) still refuses it until
// the verb has run.
func openOldLog(lfd int, name string) (*os.File, error) {
	fd, err := unix.Openat(lfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close() // read-only
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = f.Close() // read-only
		return nil, fmt.Errorf("%w: %s is not a regular file", errLogUntrusted, name)
	}
	if st.Nlink > 1 {
		slog.Warn("a keystore append-only log has more than one link; the maintenance verb replaces it with a fresh file, and the other link keeps only the old one", "log", name, "links", st.Nlink)
	}
	return f, nil
}

// rebuildScopes opens every scope under .user/ without the GeneratedUID
// check and returns the line each key on disk gets, and the set of scopes
// present. Any scope that does not open refuses, naming it.
func (s *FileStore) rebuildScopes(ctx context.Context, root *os.Root) (rebuildInput, error) {
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
		if err := u.rebuildScope(root, k, in); err != nil {
			return fmt.Errorf("the scope %s does not open, so the rebuild would lower its floor: %w", u.scope, err)
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
// for the generation file's generation when it does not.
func (u *UserScope) rebuildScope(root *os.Root, k keys, in rebuildInput) error {
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
