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
	// floorLockName is the floor's lock file, directly under the data root:
	// root:wheel 0600, so only root can open it, and so only root can hold
	// the lock every floor write takes.
	floorLockName = "keystore-lock"
	// floorLockMode is the floor lock file's mode.
	floorLockMode fs.FileMode = 0o600
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
	// maxTombstoneSize is the most of the floor file its tombstones may take:
	// the "tombstones" object, with the comma before it. Live entries may use
	// all of maxFloorSize, and tombstones only this much of what they leave;
	// every floor write prunes tombstones, oldest first, to fit both (prune).
	// A tombstone costs under 330 bytes, so this holds some 3,500 of the
	// longest names and some 16,000 short ones.
	maxTombstoneSize = 1 << 20
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

// floor is the recorded floor, by entry name: each name's live entry or its
// tombstone, never both. A nil floor is an absent file: nothing is checked
// against it.
type floor map[string]floorEntry

// floorEntry is one name's record in the floor: a live entry (Seq set,
// Deleted 0) or a tombstone (Deleted set, Seq 0), which records that a Delete
// removed the entry of that generation (docs/design/keystore.md § "Pointer
// sequence and floor", "A deleted entry put back is refused").
type floorEntry struct {
	// Generation is the entry's generation, hex.
	Generation string `json:"generation"`
	// Seq is the highest pointer sequence committed for it.
	Seq uint64 `json:"seq"`
	// Deleted is a tombstone's delete sequence, which orders tombstones for
	// pruning: one more than the highest in the floor when it was written. It
	// is encoded in the tombstones object, never in an entry.
	Deleted uint64 `json:"-"`
}

// tombstone is the encoding of a tombstone in the floor file.
type tombstone struct {
	Generation string `json:"generation"`
	Deleted    uint64 `json:"deleted"`
}

// floorFile is the floor's encoding. Scope names the scope whose entries it
// records, always scopeSystem: the floor is the system store's. Tombstones is
// written only when the floor holds one, so a floor from before tombstones
// is still the encoding of a floor with none.
type floorFile struct {
	Version    int                  `json:"version"`
	Scope      string               `json:"scope"`
	Entries    floor                `json:"entries"`
	Tombstones map[string]tombstone `json:"tombstones,omitempty"`
}

// floorMalformedError is errFloorMalformed's type. It matches ErrCorrupt
// but carries its own text, because the fix is not a restore from backup.
type floorMalformedError struct{}

func (*floorMalformedError) Error() string {
	return "the keystore floor does not parse. Removing keystore-floor.json turns replay protection off until a root keys verb rebuilds it, and the rebuild records whatever pointers are under keystore/ as current, an older copy put back included: remove it as root only once those pointers are known to be current, then run any sudo k3sm keys verb to rebuild it"
}

func (*floorMalformedError) Unwrap() error { return ErrCorrupt }

// marshalFloor encodes fl as the floor file, newline-terminated.
func marshalFloor(fl floor) ([]byte, error) {
	f := floorFile{Version: floorFormat, Scope: scopeSystem, Entries: floor{}}
	for name, e := range fl {
		if e.Deleted != 0 {
			if f.Tombstones == nil {
				f.Tombstones = map[string]tombstone{}
			}
			f.Tombstones[name] = tombstone{Generation: e.Generation, Deleted: e.Deleted}
			continue
		}
		f.Entries[name] = e
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// size is the length of fl's encoding by marshalFloor, computed without
// encoding it: an entry's name is a checkName name and its generation hex, so
// neither is escaped.
func (fl floor) size() int {
	dead, sum := 0, 0
	for name, e := range fl {
		if e.Deleted != 0 {
			dead++
			sum += tombstoneSize(name, e)
		}
	}
	return fl.liveSize() + tombstonesSize(dead, sum)
}

// liveSize is the length fl's encoding would have with no tombstones: what
// its live entries need, since every tombstone can be pruned to make room.
func (fl floor) liveSize() int {
	n := len(`{"version":`) + len(strconv.Itoa(floorFormat)) + len(`,"scope":"`) + len(scopeSystem) + len(`","entries":{}}`) + 1
	live := 0
	for name, e := range fl {
		if e.Deleted == 0 {
			n += floorEntrySize(name, e)
			live++
		}
	}
	if live > 0 {
		n += live - 1 // the commas between entries
	}
	return n
}

// liveCount is how many live entries fl holds.
func (fl floor) liveCount() int {
	n := 0
	for _, e := range fl {
		if e.Deleted == 0 {
			n++
		}
	}
	return n
}

// tombstoneSize is the length of name's tombstone e in the floor's encoding,
// without the comma that separates it from the one before.
func tombstoneSize(name string, e floorEntry) int {
	return len(`"":{"generation":"`) + len(name) + len(e.Generation) + len(`","deleted":}`) + len(strconv.FormatUint(e.Deleted, 10))
}

// tombstonesSize is the length of the tombstones object, with the comma
// before it, holding n tombstones whose tombstoneSize sums to sum: nothing
// for none, since marshalFloor then leaves the field out.
func tombstonesSize(n, sum int) int {
	if n == 0 {
		return 0
	}
	return len(`,"tombstones":{}`) + sum + n - 1
}

// floorEntrySize is the length of name's entry e in the floor's encoding,
// without the comma that separates it from the one before.
func floorEntrySize(name string, e floorEntry) int {
	return len(`"":{"generation":"`) + len(name) + len(e.Generation) + len(`","seq":}`) + len(strconv.FormatUint(e.Seq, 10))
}

// grow is how many bytes recording the live entry e for name would add to
// fl's live entries' encoding (liveSize). A tombstone for name is replaced,
// and counts as nothing, like every tombstone: prune makes room by them.
func (fl floor) grow(name string, e floorEntry) int {
	if old, ok := fl[name]; ok && old.Deleted == 0 {
		return floorEntrySize(name, e) - floorEntrySize(name, old)
	}
	if fl.liveCount() == 0 {
		return floorEntrySize(name, e)
	}
	return floorEntrySize(name, e) + 1
}

// room refuses, as errFloorFull, recording e for name when the floor's live
// entries would then be larger than maxFloorSize. Tombstones do not count:
// the write prunes them to make room, so a tombstone never refuses a Put or
// a Rotate. A verb asks it before it writes anything, so a full floor
// refuses the verb rather than a write after its entry files.
func (fl floor) room(name string, e floorEntry) error {
	if n := fl.liveSize() + fl.grow(name, e); n > maxFloorSize {
		return fmt.Errorf("%w (%d bytes)", errFloorFull, n)
	}
	return nil
}

// prune removes tombstones, oldest first (the lowest Deleted, then by name),
// until they fit in maxTombstoneSize and the whole floor in maxFloorSize. It
// never removes a live entry. A pruned tombstone's name loses its refusal: an
// old copy of that deleted entry put back is accepted again, until a Put of
// the name records a new generation.
func (fl floor) prune() {
	var names []string
	sum := 0
	for name, e := range fl {
		if e.Deleted != 0 {
			names = append(names, name)
			sum += tombstoneSize(name, e)
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := fl[names[i]], fl[names[j]]
		if a.Deleted != b.Deleted {
			return a.Deleted < b.Deleted
		}
		return names[i] < names[j]
	})
	live, n := fl.liveSize(), len(names)
	for _, name := range names {
		if t := tombstonesSize(n, sum); t <= maxTombstoneSize && live+t <= maxFloorSize {
			return
		}
		sum -= tombstoneSize(name, fl[name])
		n--
		delete(fl, name)
	}
}

// staleError refuses a current pointer the floor rules out. It matches
// ErrCorrupt but carries its own text, because ErrCorrupt's advice to restore
// from backup is the opposite of the fix: an older copy is what produced it.
//
// A completed Delete leaves a tombstone of the deleted generation, so an
// older copy of the deleted entry put back is refused (deleted) until the
// tombstone is pruned; after a new Put of the name, the new generation
// refuses it (generation) (docs/design/keystore.md § "Pointer sequence and
// floor").
type staleError struct {
	name       string
	seq, floor uint64
	generation bool
	deleted    bool
}

func (e *staleError) Error() string {
	what := fmt.Sprintf("the current pointer (sequence %d) is older than the recorded floor (sequence %d); an older copy of this entry was put back", e.seq, e.floor)
	switch {
	case e.deleted:
		what = "the entry directory belongs to a generation of this entry that the floor records as deleted; an older copy of a deleted entry was put back, and rm removes it"
	case e.generation:
		what = "the current pointer belongs to another generation of this entry than the recorded floor; an older copy of a deleted entry was put back after a newer put of the name, or a delete and the put after it were both interrupted"
	}
	return fmt.Sprintf("keystore entry %q: %s. Do not restore from backup. If that was deliberate, follow \"Restoring an older keystore/\" in docs/user/backup-restore.md", e.name, what)
}

func (e *staleError) Unwrap() error { return ErrCorrupt }

// check refuses a pointer of name at generation gen and sequence seq unless
// the floor has no live entry for name and no tombstone of gen, or records
// the same generation at a sequence no higher than seq.
func (fl floor) check(name string, gen [generationSize]byte, seq uint64) error {
	if err := fl.buried(name, gen); err != nil {
		return err
	}
	f, ok := fl[name]
	if !ok || f.Deleted != 0 {
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

// buried refuses (a staleError, matching ErrCorrupt) an entry directory of
// name at generation gen when the floor's tombstone for name records gen: an
// older copy of a deleted entry put back.
func (fl floor) buried(name string, gen [generationSize]byte) error {
	if f, ok := fl[name]; ok && f.Deleted != 0 && f.Generation == hex.EncodeToString(gen[:]) {
		return &staleError{name: name, deleted: true}
	}
	return nil
}

// raise is Raise applied to fl: it records seq for name at generation gen
// when the floor has no entry for name, a tombstone of another generation
// (a Put that crashed before its floor write), or a lower sequence of the
// same generation (the maximum of the two), and reports whether it changed
// anything. A live floor of another generation is left alone: readers refuse
// that pointer, and only a Put, which mints a new generation, replaces it
// (set). A tombstone of gen is never raised over: that is a deleted entry.
func (fl floor) raise(name string, gen [generationSize]byte, seq uint64) bool {
	g := hex.EncodeToString(gen[:])
	f, ok := fl[name]
	if ok && f.Deleted != 0 {
		if f.Generation == g {
			return false
		}
	} else if ok && (f.Generation != g || f.Seq >= seq) {
		return false
	}
	fl[name] = floorEntry{Generation: g, Seq: seq}
	return true
}

// set is Put applied to fl: it records sequence 1 for name at generation
// gen when the floor has no entry for name, a tombstone (which the new
// generation clears), or a live entry of another generation, and reports
// whether it changed anything. The live entry of the same generation is left
// alone: it can only be higher, raised since.
func (fl floor) set(name string, gen [generationSize]byte) bool {
	g := hex.EncodeToString(gen[:])
	if f, ok := fl[name]; ok && f.Deleted == 0 && f.Generation == g {
		return false
	}
	fl[name] = floorEntry{Generation: g, Seq: 1}
	return true
}

// bury is Delete applied to fl: it replaces name's record with a tombstone
// of gen, the deleted directory's generation, or, when gen is nil (the
// generation file did not read), of the generation the floor records live
// for name, and reports whether it changed anything. A live entry of another
// generation than gen is kept and no tombstone written: it is a newer Put's,
// recorded while this Delete ran, and its generation already refuses gen. A
// tombstone of the same generation is kept as it is, and with no generation
// to record nothing changes. The new tombstone's delete sequence is one more
// than the highest in the floor.
func (fl floor) bury(name string, gen *[generationSize]byte) bool {
	f, ok := fl[name]
	var g string
	switch {
	case gen != nil:
		g = hex.EncodeToString(gen[:])
	case ok && f.Deleted == 0:
		g = f.Generation
	default:
		return false
	}
	if ok && f.Generation == g && f.Deleted != 0 {
		return false
	}
	if ok && f.Generation != g && f.Deleted == 0 {
		return false
	}
	var last uint64
	for _, e := range fl {
		last = max(last, e.Deleted)
	}
	fl[name] = floorEntry{Generation: g, Deleted: last + 1}
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
	if int64(st.Uid) != int64(s.floorUID) {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, s.floorUID)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("mode %04o is group- or other-writable", perm)
	}
	return nil
}

// parseFloor decodes a floor file, refusing anything a root verb would not
// have written. encoding/json matches a field name in any case and keeps the
// last of a duplicate key, so what it decodes is encoded again and must be
// the bytes it read, with or without marshalFloor's trailing newline: one
// encoding per floor, and no file with two answers for one field.
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
		if !floorGeneration(name, e.Generation) || e.Seq == 0 {
			return nil, fmt.Errorf("%w: entry %q", errFloorMalformed, name)
		}
	}
	for name, t := range f.Tombstones {
		if _, live := f.Entries[name]; live || !floorGeneration(name, t.Generation) || t.Deleted == 0 {
			return nil, fmt.Errorf("%w: tombstone %q", errFloorMalformed, name)
		}
		f.Entries[name] = floorEntry{Generation: t.Generation, Deleted: t.Deleted}
	}
	canon, err := marshalFloor(f.Entries)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFloorMalformed, err)
	}
	if !bytes.Equal(b, canon) && !bytes.Equal(b, canon[:len(canon)-1]) {
		return nil, fmt.Errorf("%w: not in the form a keys verb writes (a duplicate or differently cased key, reordered fields or extra whitespace)", errFloorMalformed)
	}
	return f.Entries, nil
}

// floorGeneration reports whether name is a name put accepts and gen the
// canonical hex of a generation.
func floorGeneration(name, gen string) bool {
	g, err := hex.DecodeString(gen)
	return checkName(name) == nil && err == nil && len(g) == generationSize && hex.EncodeToString(g) == gen
}

// floorLock is the floor held under its lock, which every floor write
// takes: lock is keystore-lock in the data root, opened O_RDONLY|O_NOFOLLOW|
// O_NONBLOCK, judged on that descriptor, flocked, and checked again after the
// flock to be the file at that name; locked the data root's
// info, judged on its own descriptor; and root the os.Root the floor is read
// and written through, checked to be the same directory.
//
// Lock order: a verb takes the store's .lock (openLocked) first and
// keystore-lock second, each with the bounded wait lockWait, and releases
// them in reverse; readers take only .lock. keystore-lock defends the floor
// against a writer under a swapped .lock, which .lock does not serialize
// with.
//
// keystore-lock is root:wheel 0600 and refused unless it is a regular file
// owned by root (floorUID) that grants no group or other access, so only
// root can open it and only root can hold the lock. The data root itself is
// root:wheel 0755, and a flock any local process takes on it blocks nothing:
// the lock is not taken there.
type floorLock struct {
	s      *FileStore
	lock   *os.File
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

// lockFloor takes the floor lock, keystore-lock, waiting at most lockWait
// or until ctx is done, and reads the floor under it. The data root is
// opened and judged by openDataRoot, and the lock file by openFloorLock
// through that same directory. The caller holds .lock, and releases the
// returned lock with unlock.
func (s *FileStore) lockFloor(ctx context.Context) (*floorLock, floor, error) {
	f, fi, lockRoot, err := s.openFloorLock()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = lockRoot.Close() }() // only Lstats through it
	l := &floorLock{s: s, lock: f, locked: fi}
	if err := s.flockWait(ctx, f, syscall.LOCK_EX); err != nil {
		l.unlock()
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	s.dataRootLocked()
	if err := recheckFloorLock(lockRoot, f); err != nil {
		l.unlock()
		return nil, nil, err
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

// recheckFloorLock refuses (errFloorUntrusted) the flocked keystore-lock f
// unless the name, Lstat'd again through root, the data root f was opened in,
// is still the file f holds: a name replaced after the open would let two
// writers lock different files. The link count is not judged: macOS lets any
// local user hard-link a file it cannot read (it has no protected_hardlinks),
// so refusing a second link would let anyone block every floor verb, and a
// link elsewhere is the same inode, which changes nothing about the lock.
func recheckFloorLock(root *os.Root, f *os.File) error {
	held, err := f.Stat()
	if err != nil {
		return fmt.Errorf("the keystore floor: %w", err)
	}
	named, err := root.Lstat(floorLockName)
	if err != nil {
		return fmt.Errorf("%w: %s was replaced while it was locked: %w", errFloorUntrusted, floorLockName, err)
	}
	if !os.SameFile(held, named) {
		return fmt.Errorf("%w: %s was replaced while it was locked", errFloorUntrusted, floorLockName)
	}
	return nil
}

// openFloorLock opens keystore-lock in the data root, creating it root:wheel
// 0600 if it is absent, and returns it with the data root's info and the
// os.Root it was opened through, which the caller closes. The data
// root is judged by openDataRoot and opened as an os.Root that must be the
// directory judged. The file is created O_CREAT|O_EXCL|O_NOFOLLOW (exclusive
// for the reason lock gives for .lock, and owned only if this call made it),
// then opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK (flock needs no write access,
// as for .lock) and refused (errFloorUntrusted)
// unless, on that descriptor, it is a regular file owned by root (floorUID)
// with no group or other access.
func (s *FileStore) openFloorLock() (*os.File, fs.FileInfo, *os.Root, error) {
	dir, fi, err := s.openDataRoot()
	if err != nil {
		return nil, nil, nil, err
	}
	_ = dir.Close() // judged; read-only
	root, err := os.OpenRoot(s.dataRoot)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	f, err := s.openFloorLockIn(root, fi)
	if err != nil {
		_ = root.Close() // only opened through
		return nil, nil, nil, err
	}
	return f, fi, root, nil
}

// openFloorLockIn is openFloorLock's work inside root, the data root opened,
// which must be the directory fi describes.
func (s *FileStore) openFloorLockIn(root *os.Root, fi fs.FileInfo) (*os.File, error) {
	opened, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("the keystore floor: %w", err)
	}
	if !os.SameFile(fi, opened) {
		return nil, fmt.Errorf("%w: %s changed while it was opened", errFloorUntrusted, s.dataRoot)
	}
	if c, err := root.OpenFile(floorLockName, os.O_RDONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, floorLockMode); err == nil {
		err = s.ownAs(c, uint32(s.floorUID), uint32(s.floorGID), floorLockMode)
		if cerr := c.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", floorLockName, err)
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create %s: %w", floorLockName, err)
	}
	f, lfi, err := openRegular(root, floorLockName, os.O_RDONLY, 0)
	if errors.Is(err, errBadFile) || errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.ELOOP) || errors.Is(err, fs.ErrNotExist) {
		// Not found after the create is a dangling symlink, which the
		// exclusive create refuses as present.
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorLockName, err)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", floorLockName, err)
	}
	if err := s.floorLockOwned(lfi); err != nil {
		_ = f.Close() // refused; nothing written
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorLockName, err)
	}
	return f, nil
}

// floorLockOwned refuses fi, keystore-lock, unless floorOwned accepts it
// (owned by root, not group- or other-writable) and it grants no group or
// other access at all: one who could open it could hold the lock.
func (s *FileStore) floorLockOwned(fi fs.FileInfo) error {
	if err := s.floorOwned(fi); err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode %04o is group- or other-accessible", perm)
	}
	return nil
}

// read reads the floor through l.root, refused unless l.root is still the
// directory the lock is held on.
func (l *floorLock) read() (floor, error) {
	return l.s.readFloor(l.root, l.locked)
}

// update re-reads the floor under the lock, applies op to what it read, and
// writes the result if op reports a change, returning the floor as it now
// is. A change is pruned (prune) before it is written, so tombstones never
// take a live entry's room. The lock is held through the rename and the directory fsync. op sees
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
	fl.prune()
	b, err := marshalFloor(fl)
	if err != nil {
		return nil, err
	}
	if len(b) > maxFloorSize {
		return nil, fmt.Errorf("%w (%d bytes)", errFloorFull, len(b))
	}
	if err := l.s.writeFileAs(l.root, floorName, b, uint32(l.s.floorUID), uint32(l.s.floorGID), floorFileMode); err != nil {
		return nil, err
	}
	return fl, nil
}

// unlock releases the floor lock and closes what lockFloor opened.
func (l *floorLock) unlock() {
	if l.root != nil {
		_ = l.root.Close() // writes are fsynced by update
	}
	_ = syscall.Flock(int(l.lock.Fd()), syscall.LOCK_UN) // the close below releases it regardless
	_ = l.lock.Close()
}

// loopEvery is how many iterations a loop over a directory's names (up to
// maxDirNames of them) runs between checks of its context.
const loopEvery = 64

// loopCtx is ctx's error at every loopEvery-th iteration i, the first
// included, so a loop that opens or removes a file per name stops soon after
// its context is done.
func loopCtx(ctx context.Context, i int) error {
	if i%loopEvery != 0 {
		return nil
	}
	return ctx.Err()
}

// syncFloor is how Put, Rotate and RaiseFloor begin, and Delete when the
// master opens (with none, Delete raises nothing): it raises each entry's floor
// to the sequence of its authenticated current pointer and writes the floor
// file if that changed anything. That closes the window a crash between a
// pointer flip and its floor write leaves (the floor one behind), and it is
// also how an absent floor file is rebuilt. An entry whose pointer does not
// open, or that the floor already rules out, is left as it is: the verb that
// reads it reports it. The caller holds the exclusive lock and l.
//
// It stops with ctx's error, writing nothing, when ctx is done (see loopCtx).
//
// The floor never grows past maxFloorSize: a keystore with more entries than
// a floor can hold is refused (errFloorFull) before any is raised, and a raise
// that would take the floor over the size is left out, so that entry's floor
// stays where it was, behind its pointer, which readers accept.
func (s *FileStore) syncFloor(ctx context.Context, entries *os.Root, l *floorLock, fl floor, k keys) (floor, error) {
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
	for i, name := range names {
		if err := loopCtx(ctx, i); err != nil {
			return nil, err
		}
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
		// Sized by the live entries alone: update prunes tombstones to fit.
		size, live := fl.liveSize(), fl.liveCount()
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
			replaces := had && old.Deleted == 0
			grow := floorEntrySize(r.name, raised)
			switch {
			case replaces:
				grow -= floorEntrySize(r.name, old)
			case live > 0:
				grow++ // the comma before it
			}
			if size+grow > maxFloorSize {
				continue // left where it was: see above
			}
			fl[r.name] = raised
			size += grow
			if !replaces {
				live++
			}
			changed = true
		}
		return changed
	})
}
