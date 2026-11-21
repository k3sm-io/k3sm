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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"syscall"
)

// This file is the pointer floor (docs/design/keystore.md § "Pointer sequence
// and floor"): per entry, the generation and the highest pointer sequence the
// store has committed, kept in keystore-floor.json under the data root. The
// data root is root:wheel 0755 and the file root:wheel 0644, so the service
// user can read the floor but cannot replace it, which is what lets the floor
// refuse a previously valid current pointer copied back over the live one.

const (
	// floorName is the floor file, directly under the data root.
	floorName = "keystore-floor.json"
	// floorFileMode is the floor file's mode: root writes it, everyone reads.
	floorFileMode fs.FileMode = 0o644
	// floorFormat is the floor file's format version.
	floorFormat = 1
	// maxFloorSize bounds a floor read, and every floor write refuses a
	// result over it (errFloorFull), so a written floor always reads back. An
	// entry costs under 400 bytes (a 253-byte name, a 32-character generation
	// and a sequence), so this holds some ten thousand entries.
	maxFloorSize = 4 << 20
	// minFloorEntrySize is the fewest bytes an entry adds to the floor file:
	// a one-character name at sequence 1, and the comma before it.
	minFloorEntrySize = len(`,"a":{"generation":"`) + 2*generationSize + len(`","seq":1}`)
	// maxFloorEntries is the most entries a floor file under maxFloorSize can
	// hold. A keystore with more cannot have them all recorded.
	maxFloorEntries = maxFloorSize / minFloorEntrySize
)

var (
	// errFloorUntrusted refuses a floor, or a data root holding it, that the
	// service user could have written. It is about every entry, so it fails the
	// whole call.
	errFloorUntrusted = errors.New("the keystore floor is not trusted: keystore-floor.json must be a regular file, and it and the data root holding it must be owned by root and not group- or other-writable")
	// errFloorNotWritable refuses a verb that changes the keystore when this
	// process cannot write the floor, before it changes anything.
	errFloorNotWritable = errors.New("the keystore floor cannot be written by this process: a keys verb that changes the keystore runs as root")
	// errFloorMalformed refuses a floor file that does not parse, or that is
	// not the system scope's. It matches ErrCorrupt, with its own advice.
	errFloorMalformed error = &floorMalformedError{}
	// errFloorFull refuses a floor write whose result would be larger than
	// maxFloorSize, before anything is written, so the floor on disk stays
	// the last one that fit and still reads.
	errFloorFull = fmt.Errorf("the keystore floor is full: recording this change would make keystore-floor.json larger than %d bytes; delete entries that are no longer used to make room", maxFloorSize)
)

// floor is the recorded floor, by entry name. A nil floor is an absent file:
// nothing is checked against it.
type floor map[string]floorEntry

// floorEntry is one entry's recorded floor.
type floorEntry struct {
	// Generation is the entry's generation, hex.
	Generation string `json:"generation"`
	// Seq is the highest pointer sequence committed for it.
	Seq uint64 `json:"seq"`
}

// floorFile is the floor's encoding. Scope names the scope whose entries it
// records, always scopeSystem: the floor is the system store's.
type floorFile struct {
	Version int    `json:"version"`
	Scope   string `json:"scope"`
	Entries floor  `json:"entries"`
}

// floorMalformedError is errFloorMalformed's type. It matches ErrCorrupt
// but carries its own text, because the fix is not a restore from backup.
type floorMalformedError struct{}

func (*floorMalformedError) Error() string {
	return "the keystore floor does not parse: remove keystore-floor.json as root, then run any sudo k3sm keys verb to rebuild it from the current pointers"
}

func (*floorMalformedError) Unwrap() error { return ErrCorrupt }

// marshalFloor encodes fl as the floor file, newline-terminated.
func marshalFloor(fl floor) ([]byte, error) {
	if fl == nil {
		fl = floor{}
	}
	b, err := json.Marshal(floorFile{Version: floorFormat, Scope: scopeSystem, Entries: fl})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// size is the length of fl's encoding by marshalFloor, computed without
// encoding it: an entry's name is a checkName name and its generation hex, so
// neither is escaped.
func (fl floor) size() int {
	n := len(`{"version":`) + len(strconv.Itoa(floorFormat)) + len(`,"scope":"`) + len(scopeSystem) + len(`","entries":{}}`) + 1
	for name, e := range fl {
		n += floorEntrySize(name, e)
	}
	if len(fl) > 0 {
		n += len(fl) - 1 // the commas between entries
	}
	return n
}

// floorEntrySize is the length of name's entry e in the floor's encoding,
// without the comma that separates it from the one before.
func floorEntrySize(name string, e floorEntry) int {
	return len(`"":{"generation":"`) + len(name) + len(e.Generation) + len(`","seq":}`) + len(strconv.FormatUint(e.Seq, 10))
}

// grow is how many bytes recording e for name would add to fl's encoding.
func (fl floor) grow(name string, e floorEntry) int {
	if old, ok := fl[name]; ok {
		return floorEntrySize(name, e) - floorEntrySize(name, old)
	}
	if len(fl) == 0 {
		return floorEntrySize(name, e)
	}
	return floorEntrySize(name, e) + 1
}

// room refuses, as errFloorFull, recording e for name when the floor would
// then be larger than maxFloorSize. A verb asks it before it writes anything,
// so a full floor refuses the verb rather than a write after its entry files.
func (fl floor) room(name string, e floorEntry) error {
	if n := fl.size() + fl.grow(name, e); n > maxFloorSize {
		return fmt.Errorf("%w (%d bytes)", errFloorFull, n)
	}
	return nil
}

// staleError refuses a current pointer the floor rules out. It matches
// ErrCorrupt but carries its own text, because ErrCorrupt's advice to restore
// from backup is the opposite of the fix: an older copy is what produced it.
//
// The generation case is refused only once a Put after the Delete has
// recorded a new generation for the name. A completed Delete removes the
// name's floor entry, so an older copy of the deleted entry put back before
// any new Put has nothing to be refused against and is accepted
// (docs/design/keystore.md § "Pointer sequence and floor").
type staleError struct {
	name       string
	seq, floor uint64
	generation bool
}

func (e *staleError) Error() string {
	what := fmt.Sprintf("the current pointer (sequence %d) is older than the recorded floor (sequence %d); an older copy of this entry was put back", e.seq, e.floor)
	if e.generation {
		what = "the current pointer belongs to another generation of this entry than the recorded floor; an older copy of a deleted entry was put back after a newer put of the name, or a delete and the put after it were both interrupted"
	}
	return fmt.Sprintf("keystore entry %q: %s. Do not restore from backup. If that was deliberate, follow \"Restoring an older keystore/\" in docs/user/backup-restore.md", e.name, what)
}

func (e *staleError) Unwrap() error { return ErrCorrupt }

// check refuses a pointer of name at generation gen and sequence seq unless
// the floor has no entry for name, or records the same generation at a
// sequence no higher than seq.
func (fl floor) check(name string, gen [generationSize]byte, seq uint64) error {
	f, ok := fl[name]
	if !ok {
		return nil
	}
	if f.Generation != hex.EncodeToString(gen[:]) {
		return &staleError{name: name, seq: seq, floor: f.Seq, generation: true}
	}
	if seq < f.Seq {
		return &staleError{name: name, seq: seq, floor: f.Seq}
	}
	return nil
}

// raise is Raise applied to fl: it records seq for name at generation gen
// when the floor has no entry for name or holds a lower sequence of the same
// generation (the maximum of the two), and reports whether it changed
// anything. A floor of another generation is left alone: readers refuse that
// pointer, and only a Put, which mints a new generation, replaces it (set).
func (fl floor) raise(name string, gen [generationSize]byte, seq uint64) bool {
	g := hex.EncodeToString(gen[:])
	f, ok := fl[name]
	if ok && (f.Generation != g || f.Seq >= seq) {
		return false
	}
	fl[name] = floorEntry{Generation: g, Seq: seq}
	return true
}

// set is Put applied to fl: it records sequence 1 for name at generation
// gen when the floor has no entry for name or one of another generation, and
// reports whether it changed anything. The entry of the same generation is
// left alone: it can only be higher, raised since.
func (fl floor) set(name string, gen [generationSize]byte) bool {
	g := hex.EncodeToString(gen[:])
	if f, ok := fl[name]; ok && f.Generation == g {
		return false
	}
	fl[name] = floorEntry{Generation: g, Seq: 1}
	return true
}

// remove is Delete applied to fl: it removes name's entry when it records
// generation gen, and reports whether it changed anything. An entry of
// another generation belongs to a Put after the Delete, and stays.
func (fl floor) remove(name string, gen [generationSize]byte) bool {
	if f, ok := fl[name]; !ok || f.Generation != hex.EncodeToString(gen[:]) {
		return false
	}
	delete(fl, name)
	return true
}

// openFloor opens the data root and reads the floor in it, both judged on
// the opened descriptor: owned by root (floorUID) and not group- or
// other-writable, and the file regular and not a symlink. An absent file is a
// nil floor; an absent data root is an error, since every install has one.
// The caller closes the returned root.
func (s *FileStore) openFloor() (*os.Root, floor, error) {
	if s.dataRoot == "" {
		return nil, nil, errors.New("the keystore floor needs the data root, and none is configured")
	}
	named, err := os.Lstat(s.dataRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	if !named.IsDir() {
		return nil, nil, fmt.Errorf("%w: %s is not a directory (mode %s)", errFloorUntrusted, s.dataRoot, named.Mode())
	}
	dir, err := os.OpenRoot(s.dataRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	fl, err := s.readFloor(dir, named)
	if err != nil {
		_ = dir.Close() // abandoned; nothing was written
		return nil, nil, err
	}
	return dir, fl, nil
}

// readFloor checks dir (which Lstat saw as named) and reads the floor in it.
func (s *FileStore) readFloor(dir *os.Root, named fs.FileInfo) (floor, error) {
	opened, err := dir.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("the keystore floor: %w", err)
	}
	if !os.SameFile(named, opened) {
		return nil, fmt.Errorf("%w: %s changed while it was opened", errFloorUntrusted, s.dataRoot)
	}
	if err := s.floorOwned(opened); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, s.dataRoot, err)
	}
	b, fi, err := readFile(dir, floorName, maxFloorSize)
	if errors.Is(err, fs.ErrNotExist) {
		// An absent floor switches the check off, so absent must mean no
		// name at all: a dangling symlink also fails the open as not found.
		if _, lerr := dir.Lstat(floorName); !errors.Is(lerr, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s is present but cannot be opened: %v", errFloorUntrusted, floorName, err)
		}
		return nil, nil
	}
	if errors.Is(err, errBadFile) {
		return nil, fmt.Errorf("%w: %w", errFloorUntrusted, err)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", floorName, err)
	}
	if err := s.floorOwned(fi); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorName, err)
	}
	return parseFloor(b)
}

// floorOwned refuses fi unless root (floorUID) owns it and its mode grants
// no write to group or others.
func (s *FileStore) floorOwned(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return errors.New("owner unknown")
	}
	if st.Uid != s.floorUID {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, s.floorUID)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("mode %04o is group- or other-writable", perm)
	}
	return nil
}

// parseFloor decodes a floor file, refusing anything a root verb would not
// have written.
func parseFloor(b []byte) (floor, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f floorFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %w", errFloorMalformed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: data after the floor object", errFloorMalformed)
	}
	if f.Version != floorFormat {
		return nil, fmt.Errorf("%w: format version %d, want %d", errFloorMalformed, f.Version, floorFormat)
	}
	if f.Scope != scopeSystem {
		return nil, fmt.Errorf("%w: scope %q, want %q", errFloorMalformed, f.Scope, scopeSystem)
	}
	if f.Entries == nil {
		f.Entries = floor{}
	}
	for name, e := range f.Entries {
		g, err := hex.DecodeString(e.Generation)
		if checkName(name) != nil || err != nil || len(g) != generationSize || hex.EncodeToString(g) != e.Generation || e.Seq == 0 {
			return nil, fmt.Errorf("%w: entry %q", errFloorMalformed, name)
		}
	}
	return f.Entries, nil
}

// floorLock is the data root held under its own flock, which every floor
// write takes: dir is the data root opened O_NOFOLLOW|O_DIRECTORY and
// flocked, locked its info, and root the os.Root the floor is read and
// written through, checked to be the same directory.
//
// Lock order: a verb takes the store's .lock (openLocked) first and the
// data-root lock second, and releases them in reverse; readers take only
// .lock. The data-root lock defends the floor against a writer under a
// swapped .lock, which .lock does not serialize with.
//
// The data root is root:wheel 0755, so any local process that can open it,
// not only the service user, can flock it and hold the lock. A verb that
// writes the floor then fails with errLockTimeout after the bounded wait: a
// denial of service against root's write verbs, with no loss of integrity,
// since holding the lock writes nothing and readers do not take it.
type floorLock struct {
	s      *FileStore
	dir    *os.File
	locked fs.FileInfo
	root   *os.Root
}

// openDataRoot opens the data root without following a symlink and judges
// it on that descriptor: owned by root (floorUID), not group- or
// other-writable, and writable by this process, which a verb that changes
// the keystore must be before it changes anything (errFloorNotWritable).
func (s *FileStore) openDataRoot() (*os.File, fs.FileInfo, error) {
	if s.dataRoot == "" {
		return nil, nil, errors.New("the keystore floor needs the data root, and none is configured")
	}
	dir, err := os.OpenFile(s.dataRoot, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return nil, nil, fmt.Errorf("%w: %s is not a directory: %w", errFloorUntrusted, s.dataRoot, err)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	fi, err := dir.Stat()
	if err == nil {
		if oerr := s.floorOwned(fi); oerr != nil {
			err = fmt.Errorf("%w: %s: %w", errFloorUntrusted, s.dataRoot, oerr)
		}
	}
	if err == nil {
		err = s.floorWritable(fi)
	}
	if err != nil {
		_ = dir.Close() // abandoned; nothing was written
		return nil, nil, err
	}
	return dir, fi, nil
}

// floorWritable refuses fi, the data root, unless this process can create
// and rename files in it: as root, or as its owner with the owner's write
// bit. floorOwned already refuses group and other write, so no one else can.
// It asks the process's own euid, not the euid seam, which stands for the
// creator of the store's directories.
func (s *FileStore) floorWritable(fi fs.FileInfo) error {
	euid := os.Geteuid()
	if euid == 0 {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil || int64(st.Uid) != int64(euid) || fi.Mode().Perm()&0o200 == 0 {
		return fmt.Errorf("%w: %s is mode %04o, and this process is uid %d", errFloorNotWritable, s.dataRoot, fi.Mode().Perm(), euid)
	}
	return nil
}

// checkFloorWritable is openDataRoot's checks alone, which every verb that
// changes the keystore makes first, before it takes .lock (which creates the
// entries' directory on a first Put).
func (s *FileStore) checkFloorWritable() error {
	dir, _, err := s.openDataRoot()
	if err != nil {
		return err
	}
	return dir.Close()
}

// lockFloor takes the data-root lock, waiting at most lockWait or until ctx
// is done, and reads the floor under it. The data root is opened and judged
// by openDataRoot. The caller holds .lock, and releases the returned lock
// with unlock.
func (s *FileStore) lockFloor(ctx context.Context) (*floorLock, floor, error) {
	dir, fi, err := s.openDataRoot()
	if err != nil {
		return nil, nil, err
	}
	l := &floorLock{s: s, dir: dir, locked: fi}
	if err := s.flockWait(ctx, dir, syscall.LOCK_EX); err != nil {
		l.unlock()
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	if l.root, err = os.OpenRoot(s.dataRoot); err != nil {
		l.unlock()
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	fl, err := l.read()
	if err != nil {
		l.unlock()
		return nil, nil, err
	}
	return l, fl, nil
}

// read reads the floor through l.root, refused unless l.root is still the
// directory the lock is held on.
func (l *floorLock) read() (floor, error) {
	return l.s.readFloor(l.root, l.locked)
}

// update re-reads the floor under the lock, applies op to what it read, and
// writes the result if op reports a change, returning the floor as it now
// is. The lock is held through the rename and the directory fsync. op sees
// a non-nil floor; an absent file it leaves unchanged stays absent.
func (l *floorLock) update(op func(floor) bool) (floor, error) {
	fl, err := l.read()
	if err != nil {
		return nil, err
	}
	absent := fl == nil
	if absent {
		fl = floor{}
	}
	if !op(fl) {
		if absent {
			return nil, nil
		}
		return fl, nil
	}
	b, err := marshalFloor(fl)
	if err != nil {
		return nil, err
	}
	if len(b) > maxFloorSize {
		return nil, fmt.Errorf("%w (%d bytes)", errFloorFull, len(b))
	}
	if err := l.s.writeFileAs(l.root, floorName, b, l.s.floorUID, l.s.floorGID, floorFileMode); err != nil {
		return nil, err
	}
	return fl, nil
}

// unlock releases the data-root lock and closes what lockFloor opened.
func (l *floorLock) unlock() {
	if l.root != nil {
		_ = l.root.Close() // writes are fsynced by update
	}
	_ = syscall.Flock(int(l.dir.Fd()), syscall.LOCK_UN) // the close below releases it regardless
	_ = l.dir.Close()
}

// syncFloor is how every root-run verb begins: it raises each entry's floor
// to the sequence of its authenticated current pointer and writes the floor
// file if that changed anything. That closes the window a crash between a
// pointer flip and its floor write leaves (the floor one behind), and it is
// also how an absent floor file is rebuilt. An entry whose pointer does not
// open, or that the floor already rules out, is left as it is: the verb that
// reads it reports it. The caller holds the exclusive lock and l.
//
// The floor never grows past maxFloorSize: a keystore with more entries than
// a floor can hold is refused (errFloorFull) before any is raised, and a raise
// that would take the floor over the size is left out, so that entry's floor
// stays where it was, behind its pointer, which readers accept.
func (s *FileStore) syncFloor(entries *os.Root, l *floorLock, fl floor, k keys) (floor, error) {
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	type raised struct {
		name string
		gen  [generationSize]byte
		seq  uint64
	}
	var found []raised
	for _, name := range names {
		if checkName(name) != nil {
			continue
		}
		e, err := openEntry(entries, name, fl)
		if err != nil {
			continue
		}
		_, seq, err := e.pointer(k)
		e.close()
		if err == nil {
			found = append(found, raised{name, e.generation, seq})
		}
	}
	if len(found) > maxFloorEntries {
		return nil, fmt.Errorf("%w: the keystore holds %d entries, and the floor can hold at most %d", errFloorFull, len(found), maxFloorEntries)
	}
	return l.update(func(fl floor) bool {
		changed := false
		size := fl.size()
		for _, r := range found {
			old, had := fl[r.name]
			if !fl.raise(r.name, r.gen, r.seq) {
				continue
			}
			raised := fl[r.name]
			if had {
				fl[r.name] = old
			} else {
				delete(fl, r.name)
			}
			grow := fl.grow(r.name, raised)
			if size+grow > maxFloorSize {
				continue // left where it was: see above
			}
			fl[r.name] = raised
			size += grow
			changed = true
		}
		return changed
	})
}
