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
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"time"
)

const (
	// generationName is an entry's generation file, currentName its pointer.
	generationName = "generation"
	currentName    = "current"
	// generationFileSize is the generation file's size: hex and a newline.
	generationFileSize = 2*generationSize + 1
)

// Config locates a FileStore and names the user it belongs to.
type Config struct {
	// Dir is the entries' directory, <server work dir>/keystore.
	Dir string
	// MasterDir is the master pair's directory,
	// <server work dir>/cred/keystore-master. Its parent must not be Dir.
	MasterDir string
	// UID and GID are the service user's. Every file and directory the store
	// creates is handed to them, and every one it reads must be owned by UID.
	UID, GID uint32
}

// FileStore is the keystore on disk, laid out as docs/design/keystore.md §
// "On-disk layout" gives. Every method takes the store-wide lock for its
// duration: exclusive to write, shared to read.
//
// Rotate and Rewrap land in later pull requests, so FileStore does not yet
// satisfy Store.
type FileStore struct {
	dir       string
	masterDir string
	uid, gid  uint32

	// The seams below are fixed by New; tests replace them.
	rand     io.Reader
	now      func() time.Time
	chown    func(f *os.File, uid, gid int) error
	lockWait time.Duration
	// step, when non-nil, is called at each durable step of a write; a
	// non-nil return aborts the write there, as a crash would.
	step func(name string) error
}

// New returns the FileStore cfg describes. It touches nothing on disk.
func New(cfg Config) *FileStore {
	return &FileStore{
		dir:       cfg.Dir,
		masterDir: cfg.MasterDir,
		uid:       cfg.UID,
		gid:       cfg.GID,
		rand:      rand.Reader,
		now:       time.Now,
		chown:     (*os.File).Chown,
		lockWait:  lockTimeout,
		step:      func(string) error { return nil },
	}
}

// Put creates name at version 1 holding value, minting the master on the
// keystore's first Put. The entry is written generation, then version 1, then
// the current pointer; an entry directory without a pointer is an interrupted
// Put, which the next Put of that name discards.
func (s *FileStore) Put(ctx context.Context, name string, kind Kind, value []byte) (Version, error) {
	if err := checkName(name); err != nil {
		return Version{}, err
	}
	if err := checkValue(kind, value); err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
	}
	root, err := s.openDir(s.dir, true)
	if err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
	}
	defer func() { _ = root.Close() }() // writes are fsynced by writeFile
	unlock, err := s.lock(ctx, root, true)
	if err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
	}
	defer unlock()
	k, err := s.masterForPut(root)
	if err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
	}
	e, err := s.createEntry(root, name)
	if err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
	}
	defer e.close()
	v, err := s.writeEntry(e, k, kind, value)
	if err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
	}
	return v, nil
}

// createEntry makes name's directory with a fresh generation. A directory
// with a current pointer is ErrExists; one without is an interrupted Put and
// is discarded first.
func (s *FileStore) createEntry(root *os.Root, name string) (*entry, error) {
	err := s.mkdirAt(root, name)
	if errors.Is(err, fs.ErrExist) {
		if _, serr := root.Lstat(name + "/" + currentName); serr == nil {
			return nil, ErrExists
		} else if !errors.Is(serr, fs.ErrNotExist) {
			return nil, serr
		}
		if err := root.RemoveAll(name); err != nil {
			return nil, fmt.Errorf("discard an interrupted put: %w", err)
		}
		err = s.mkdirAt(root, name)
	}
	if err != nil {
		return nil, fmt.Errorf("create the entry directory: %w", err)
	}
	if err := syncDir(root); err != nil {
		return nil, err
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	e := &entry{root: sub, name: name}
	if err := s.readRandom(e.generation[:]); err != nil {
		e.close()
		return nil, err
	}
	if err := s.writeFile(sub, generationName, []byte(hex.EncodeToString(e.generation[:])+"\n")); err != nil {
		e.close()
		return nil, err
	}
	return e, nil
}

// writeEntry seals value as version 1 of e, then the pointer naming it.
func (s *FileStore) writeEntry(e *entry, k keys, kind Kind, value []byte) (Version, error) {
	created := s.now().Unix()
	rec := record{kind: byte(kind), name: e.name, version: 1, generation: e.generation, created: created}
	if err := rec.seal(k.seal, value, s.rand); err != nil {
		return Version{}, err
	}
	if err := s.writeFile(e.root, versionName(1), rec.marshal()); err != nil {
		return Version{}, err
	}
	ptr := record{kind: kindPointer, name: e.name, generation: e.generation, created: created}
	if err := ptr.seal(k.seal, pointerPlaintext(1, 1), s.rand); err != nil {
		return Version{}, err
	}
	if err := s.writeFile(e.root, currentName, ptr.marshal()); err != nil {
		return Version{}, err
	}
	return versionOf(rec, kind, value, k), nil
}

// Current returns the version the current pointer names, with its value.
func (s *FileStore) Current(ctx context.Context, name string) (Version, []byte, error) {
	var (
		v   Version
		val []byte
	)
	err := s.read(ctx, name, func(e *entry, k keys) error {
		cur, err := e.pointer(k)
		if err != nil {
			return err
		}
		v, val, err = e.version(k, cur)
		return err
	})
	return v, val, err
}

// Get returns version of name with its value. A version above the one the
// current pointer names is ErrVersionNotFound: it is not yet committed.
func (s *FileStore) Get(ctx context.Context, name string, version uint64) (Version, []byte, error) {
	var (
		v   Version
		val []byte
	)
	err := s.read(ctx, name, func(e *entry, k keys) error {
		cur, err := e.pointer(k)
		if err != nil {
			return err
		}
		if version == 0 || version > cur {
			return ErrVersionNotFound
		}
		v, val, err = e.version(k, version)
		return err
	})
	return v, val, err
}

// read runs fn on name's entry under the shared lock. A missing entries'
// directory, entry directory or current pointer is ErrNotFound.
func (s *FileStore) read(ctx context.Context, name string, fn func(*entry, keys) error) error {
	if err := checkName(name); err != nil {
		return err
	}
	root, err := s.openDir(s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = root.Close() }() // read-only; nothing to flush
	unlock, err := s.lock(ctx, root, false)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer unlock()
	e, err := openEntry(root, name)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer e.close()
	k, err := s.loadMaster()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := fn(e, k); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// List returns every entry, sorted by name. An entry that cannot be opened is
// returned with Err set and nothing else. A directory that is not an entry (an
// interrupted Put, or a name Put would refuse) is not listed.
func (s *FileStore) List(ctx context.Context) ([]Entry, error) {
	root, err := s.openDir(s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	defer func() { _ = root.Close() }() // read-only; nothing to flush
	unlock, err := s.lock(ctx, root, false)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	defer unlock()
	names, err := readDirNames(root)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	sort.Strings(names)
	var (
		out    []Entry
		k      keys
		loaded bool
	)
	for _, name := range names {
		if checkName(name) != nil {
			continue
		}
		e, err := openEntry(root, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err == nil && !loaded {
			// The master is needed only once there is an entry to open, and
			// its failure is about every entry, so it fails the whole call.
			if k, err = s.loadMaster(); err != nil {
				e.close()
				return nil, fmt.Errorf("list: %w", err)
			}
			loaded = true
		}
		out = append(out, listEntry(e, err, k, name))
		if e != nil {
			e.close()
		}
	}
	return out, nil
}

// listEntry opens every committed version of e for List. Any failure,
// including openErr from opening e itself, is the entry's Err.
func listEntry(e *entry, openErr error, k keys, name string) Entry {
	if openErr != nil {
		return Entry{Name: name, Err: openErr}
	}
	cur, err := e.pointer(k)
	if err != nil {
		return Entry{Name: name, Err: err}
	}
	out := Entry{Name: name, Versions: make([]Version, 0, cur)}
	for n := uint64(1); n <= cur; n++ {
		v, _, err := e.version(k, n)
		if err != nil {
			return Entry{Name: name, Err: fmt.Errorf("version %d: %w", n, err)}
		}
		out.Versions = append(out.Versions, v)
	}
	out.Current = out.Versions[len(out.Versions)-1]
	return out
}

// Delete removes name and every version of it. The pointer is removed first,
// so an interrupted Delete leaves an interrupted Put: not an entry, and
// discarded by the next Put of the name.
func (s *FileStore) Delete(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	root, err := s.openDir(s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete %s: %w", name, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	defer func() { _ = root.Close() }() // removals are fsynced below
	unlock, err := s.lock(ctx, root, true)
	if err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	defer unlock()
	e, err := openEntry(root, name)
	if err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	err = e.root.Remove(currentName)
	if err == nil {
		err = syncDir(e.root)
	}
	e.close()
	if err == nil {
		err = s.step("delete " + name)
	}
	if err == nil {
		err = root.RemoveAll(name)
	}
	if err == nil {
		err = syncDir(root)
	}
	if err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

// entry is one open entry directory and its generation.
type entry struct {
	root       *os.Root
	name       string
	generation [generationSize]byte
}

// openEntry opens name's directory and reads its generation. A missing
// directory, or one without a current pointer, is ErrNotFound.
func openEntry(root *os.Root, name string) (*entry, error) {
	fi, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: the entry is not a directory (mode %s)", ErrCorrupt, fi.Mode())
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	e := &entry{root: sub, name: name}
	// OpenRoot follows a symlink inside the root, so the opened directory must
	// be the one Lstat saw.
	if opened, err := sub.Stat("."); err != nil || !os.SameFile(fi, opened) {
		e.close()
		return nil, fmt.Errorf("%w: the entry directory was replaced while it was opened", ErrCorrupt)
	}
	if _, err := sub.Lstat(currentName); err != nil {
		e.close()
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	b, _, err := readFile(sub, generationName, generationFileSize)
	if err == nil && (len(b) != generationFileSize || b[len(b)-1] != '\n') {
		err = errors.New("malformed")
	}
	if err == nil {
		_, err = hex.Decode(e.generation[:], b[:len(b)-1])
	}
	if err != nil {
		e.close()
		return nil, fmt.Errorf("%w: the generation file: %w", ErrCorrupt, err)
	}
	return e, nil
}

func (e *entry) close() { _ = e.root.Close() } // read-only or already fsynced

// openRecord reads the record file name of e and opens it, refusing a record
// that does not belong there: a pointer where a version belongs or the
// reverse, or another name, version or generation.
func (e *entry) openRecord(k keys, name string, pointer bool, version uint64) (record, []byte, error) {
	b, _, err := readFile(e.root, name, maxRecordSize)
	if errors.Is(err, fs.ErrNotExist) {
		return record{}, nil, fmt.Errorf("%w: %s is missing", ErrCorrupt, name)
	}
	if err != nil {
		return record{}, nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, name, err)
	}
	r, err := parseRecord(b)
	if err != nil {
		return record{}, nil, err
	}
	kindOK := r.kind == byte(KindEd25519) || r.kind == byte(KindOpaque)
	if pointer {
		kindOK = r.kind == kindPointer
	}
	if !kindOK || r.name != e.name || r.version != version || r.generation != e.generation {
		return record{}, nil, fmt.Errorf("%w: %s does not belong to this entry", ErrCorrupt, name)
	}
	pt, err := r.open(k.seal)
	if err != nil {
		return record{}, nil, err
	}
	return r, pt, nil
}

// pointer opens e's current pointer and returns the version it names.
//
// The pointer's sequence is read but not yet checked against a recorded
// floor; that check lands with Rotate (docs/design/keystore.md § "Pointer
// sequence and floor").
func (e *entry) pointer(k keys) (uint64, error) {
	_, pt, err := e.openRecord(k, currentName, true, 0)
	if err != nil {
		return 0, err
	}
	if len(pt) != pointerSize {
		return 0, fmt.Errorf("%w: the pointer is %d bytes", ErrCorrupt, len(pt))
	}
	v := binary.BigEndian.Uint64(pt[:8])
	if v == 0 {
		return 0, fmt.Errorf("%w: the pointer names version 0", ErrCorrupt)
	}
	return v, nil
}

// version opens version n of e.
func (e *entry) version(k keys, n uint64) (Version, []byte, error) {
	r, value, err := e.openRecord(k, versionName(n), false, n)
	if err != nil {
		return Version{}, nil, err
	}
	kind := Kind(r.kind)
	// The value authenticated, so it is what a Put sealed; a value that does
	// not validate is still refused rather than handed to a fingerprint that
	// assumes a valid key.
	if err := checkValue(kind, value); err != nil {
		return Version{}, nil, fmt.Errorf("%w: version %d: %w", ErrCorrupt, n, err)
	}
	return versionOf(r, kind, value, k), value, nil
}

// versionOf is the metadata of the version r seals value as.
func versionOf(r record, kind Kind, value []byte, k keys) Version {
	return Version{
		Name:        r.name,
		Version:     r.version,
		Kind:        kind,
		Created:     time.Unix(r.created, 0),
		Fingerprint: fingerprint(kind, value, k.fingerprint),
	}
}

// versionName is version n's file name.
func versionName(n uint64) string { return "v" + strconv.FormatUint(n, 10) }

// pointerPlaintext is a pointer's plaintext: the version it names, then its
// sequence.
func pointerPlaintext(version, seq uint64) []byte {
	b := binary.BigEndian.AppendUint64(nil, version)
	return binary.BigEndian.AppendUint64(b, seq)
}
