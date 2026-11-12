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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
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
	// maxFloorSize bounds a floor read. An entry costs under 400 bytes (a
	// 253-byte name, a 32-character generation and a sequence), so this holds
	// some ten thousand entries.
	maxFloorSize = 4 << 20
)

var (
	// errFloorUntrusted refuses a floor, or a data root holding it, that the
	// service user could have written. It is about every entry, so it fails the
	// whole call.
	errFloorUntrusted = errors.New("the keystore floor is not trusted: keystore-floor.json must be a regular file, and it and the data root holding it must be owned by root and not group- or other-writable")
	// errFloorMalformed refuses a floor file that does not parse.
	errFloorMalformed = errors.New("the keystore floor does not parse: remove keystore-floor.json as root, then run any sudo k3sm keys verb to rebuild it from the current pointers")
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

// floorFile is the floor's encoding.
type floorFile struct {
	Version int   `json:"version"`
	Entries floor `json:"entries"`
}

// staleError refuses a current pointer the floor rules out. It matches
// ErrCorrupt but carries its own text, because ErrCorrupt's advice to restore
// from backup is the opposite of the fix: an older copy is what produced it.
type staleError struct {
	name       string
	seq, floor uint64
	generation bool
}

func (e *staleError) Error() string {
	what := fmt.Sprintf("the current pointer (sequence %d) is older than the recorded floor (sequence %d); an older copy of this entry was put back", e.seq, e.floor)
	if e.generation {
		what = "the current pointer belongs to another generation of this entry than the recorded floor; an older copy of a deleted entry was put back, or a delete and the put after it were both interrupted"
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

// raise records seq for name at generation gen when the floor has no entry
// for name or holds a lower sequence of the same generation, and reports
// whether it changed anything. A floor of another generation is left alone:
// readers refuse that pointer, and only a Put, which mints a new generation,
// replaces it (set).
func (fl floor) raise(name string, gen [generationSize]byte, seq uint64) bool {
	g := hex.EncodeToString(gen[:])
	f, ok := fl[name]
	if ok && (f.Generation != g || f.Seq >= seq) {
		return false
	}
	fl[name] = floorEntry{Generation: g, Seq: seq}
	return true
}

// set records seq for name at generation gen, whatever was recorded before.
func (fl floor) set(name string, gen [generationSize]byte, seq uint64) {
	fl[name] = floorEntry{Generation: hex.EncodeToString(gen[:]), Seq: seq}
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

// writeFloor replaces the floor file in dir with fl, root-owned at
// floorFileMode, through the same temporary-file-and-rename as every other
// write.
func (s *FileStore) writeFloor(dir *os.Root, fl floor) error {
	if fl == nil {
		fl = floor{}
	}
	b, err := json.Marshal(floorFile{Version: floorFormat, Entries: fl})
	if err != nil {
		return err
	}
	return s.writeFileAs(dir, floorName, append(b, '\n'), s.floorUID, s.floorGID, floorFileMode)
}

// syncFloor is how every root-run verb begins: it raises each entry's floor
// to the sequence of its authenticated current pointer and writes the floor
// file if that changed anything. That closes the window a crash between a
// pointer flip and its floor write leaves (the floor one behind), and it is
// also how an absent floor file is rebuilt. An entry whose pointer does not
// open, or that the floor already rules out, is left as it is: the verb that
// reads it reports it. The caller holds the exclusive lock.
func (s *FileStore) syncFloor(entries, dir *os.Root, fl floor, k keys) (floor, error) {
	names, err := readDirNames(entries)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	absent := fl == nil
	if absent {
		fl = floor{}
	}
	changed := false
	for _, name := range names {
		if checkName(name) != nil {
			continue
		}
		e, err := openEntry(entries, name)
		if err != nil {
			continue
		}
		_, seq, err := e.pointer(k)
		e.close()
		if err == nil && fl.raise(name, e.generation, seq) {
			changed = true
		}
	}
	if changed {
		if err := s.writeFloor(dir, fl); err != nil {
			return nil, err
		}
	}
	return fl, nil
}
