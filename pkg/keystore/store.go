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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// generationName is an entry's generation file, currentName its pointer.
	generationName = "generation"
	currentName    = "current"
	// generationFileSize is the generation file's size: hex and a newline.
	generationFileSize = 2*generationSize + 1
	// maxVersion is the highest version a current pointer may name. The
	// pointer authenticates, but whoever holds the master can seal any value,
	// and List sizes its result by it and opens every version up to it, so a
	// pointer above the bound is ErrCorrupt rather than an allocation or a walk
	// it chooses. 65536 versions is far beyond any rotation cadence, and an
	// entry directory at the bound still lists under maxDirNames.
	maxVersion = 1 << 16
)

var (
	// errInterruptedPut is an entry directory with no current pointer that
	// holds only what a crashed Put leaves: generation and at most v1. It is not
	// an entry, so it matches ErrNotFound, and only a Put touches it.
	errInterruptedPut = fmt.Errorf("%w: an interrupted put left a directory with no current pointer", ErrNotFound)
	// errNoPointer is an entry directory with no current pointer that is not
	// an interrupted Put: damage, or an interrupted Delete. List reports it,
	// Put refuses it, and Delete clears it. It is one of the two below.
	errNoPointer = fmt.Errorf("%w: the current pointer is missing", ErrCorrupt)
	// errDamagedShape is errNoPointer for a directory that holds more than a
	// crashed Put leaves: Put never writes that before the pointer.
	errDamagedShape = fmt.Errorf("%w, and the directory holds more than an interrupted put leaves", errNoPointer)
	// errLostPointer is errNoPointer for a directory in the shape a crashed Put
	// leaves whose generation the floor records: Put records the floor only
	// after its pointer, so this entry's pointer was committed and then lost.
	errLostPointer = fmt.Errorf("%w, although the floor records that this entry committed one", errNoPointer)
	// errInvalidConfig reports a Config every operation refuses.
	errInvalidConfig = errors.New("invalid keystore config")
)

// Config locates a FileStore and names the user it belongs to.
type Config struct {
	// Dir is the entries' directory, <server work dir>/keystore.
	Dir string
	// MasterDir is the master pair's directory,
	// <server work dir>/cred/keystore-master.
	MasterDir string
	// UID and GID are the service user's. Every file and directory the store
	// creates is handed to them, and the entries' directory, cred/, the master
	// directory and the master file must be owned by UID.
	//
	// A UID of 0, a Dir, MasterDir or DataRoot that is not absolute or not
	// equal to its own filepath.Clean, or a MasterDir equal to or inside Dir
	// makes every operation fail.
	UID, GID uint32
	// DataRoot is the data root, /var/lib/k3sm, which holds the root-owned
	// pointer floor, keystore-floor.json.
	DataRoot string
	// FloorUID and FloorGID name the owner of the data root and the floor.
	// They are for tests only: production leaves them 0 (root), and only a
	// non-root test, which cannot make a root-owned file, sets them.
	//
	// A negative value, or a nonzero one in a process whose effective uid is
	// 0, makes every operation fail: root's floor belongs to root.
	FloorUID, FloorGID int
}

// FileStore is the keystore on disk, laid out as docs/design/keystore.md §
// "On-disk layout" gives. Every method takes the store-wide lock for its
// duration: exclusive to write, shared to read.
type FileStore struct {
	dir       string
	masterDir string
	dataRoot  string
	uid, gid  uint32
	// scope is the scope every record is sealed and opened under, supplied
	// from the store's identity and never read from a file. New sets
	// scopeSystem, the only scope Phase A constructs.
	scope string

	// The seams below are fixed by New; tests replace them.
	rand     io.Reader
	now      func() time.Time
	chown    func(f *os.File, uid, gid int) error
	lockWait time.Duration
	// step is called at each durable step of a write; a non-nil return aborts
	// the write there, as a crash would.
	step func(name string) error
	// floorUID and floorGID own the floor and the data root, from
	// Config.FloorUID and Config.FloorGID: root in production, the test user
	// in a non-root test. checkConfig refuses a negative one, so the
	// conversion to a uid_t after it is exact.
	floorUID, floorGID int
	// entryMade is called between a new entry directory's mkdir and its open,
	// where a test swaps the directory.
	entryMade func(name string)
	// dirMade is called inside mkdirAt, between the mkdir and the Lstat that
	// takes the new directory's identity, where a test swaps the directory.
	dirMade func(name string)
	// dataRootLocked is called in lockFloor between keystore-lock's flock
	// and its re-check (then the OpenRoot the floor is read through), where
	// a test swaps the data root or the lock file.
	dataRootLocked func()
	// euid is the effective uid that creates the store's directories, which
	// a new directory must be owned by before it is handed over.
	euid func() int
	// userFloor and auditSink are the user-scope floor and the audit log
	// (userlogs.go). New installs ones that refuse every call.
	userFloor userFloorLog
	auditSink auditSink
}

var _ Store = (*FileStore)(nil)

// New returns the FileStore cfg describes. It touches nothing on disk, and it
// does not judge cfg: every operation does that first (see checkConfig).
func New(cfg Config) *FileStore {
	return &FileStore{
		dir:            cfg.Dir,
		masterDir:      cfg.MasterDir,
		dataRoot:       cfg.DataRoot,
		uid:            cfg.UID,
		gid:            cfg.GID,
		floorUID:       cfg.FloorUID,
		floorGID:       cfg.FloorGID,
		scope:          scopeSystem,
		rand:           rand.Reader,
		now:            time.Now,
		chown:          (*os.File).Chown,
		lockWait:       lockTimeout,
		step:           func(string) error { return nil },
		entryMade:      func(string) {},
		dirMade:        func(string) {},
		dataRootLocked: func() {},
		euid:           os.Geteuid,
		userFloor:      unbuiltUserFloor{},
		auditSink:      unbuiltAudit{},
	}
}

// checkConfig refuses a store every operation must fail closed on: a zero
// service uid, which would hand the service user's files to root and accept
// root-owned ones; a Dir, MasterDir or DataRoot that is empty or relative,
// which would resolve against the working directory, or not equal to its own
// filepath.Clean, whose last component (a trailing slash, a "..") would not be
// the directory the store opens it as; a MasterDir equal to or inside Dir,
// which would put the master among the entries and in every backup of them;
// or a negative FloorUID or FloorGID, or, in a process whose effective uid
// (the euid seam) is 0, a nonzero one, which would trust a floor root does
// not own.
func (s *FileStore) checkConfig() error {
	switch {
	case s.uid == 0:
		return fmt.Errorf("%w: the service user's UID is 0", errInvalidConfig)
	case s.floorUID < 0 || s.floorGID < 0:
		return fmt.Errorf("%w: FloorUID %d or FloorGID %d is negative", errInvalidConfig, s.floorUID, s.floorGID)
	case s.euid() == 0 && (s.floorUID != 0 || s.floorGID != 0):
		return fmt.Errorf("%w: running as root, the floor's owner must be root, not %d:%d", errInvalidConfig, s.floorUID, s.floorGID)
	case s.dir == "":
		return fmt.Errorf("%w: Dir is empty", errInvalidConfig)
	case s.masterDir == "":
		return fmt.Errorf("%w: MasterDir is empty", errInvalidConfig)
	case s.dataRoot == "":
		return fmt.Errorf("%w: DataRoot is empty", errInvalidConfig)
	}
	for _, p := range []struct{ field, path string }{{"Dir", s.dir}, {"MasterDir", s.masterDir}, {"DataRoot", s.dataRoot}} {
		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("%w: %s %q is not absolute", errInvalidConfig, p.field, p.path)
		}
		if c := filepath.Clean(p.path); c != p.path {
			return fmt.Errorf("%w: %s %q is not clean (%q)", errInvalidConfig, p.field, p.path, c)
		}
	}
	if rel, err := filepath.Rel(s.dir, s.masterDir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: MasterDir %q is Dir %q or inside it", errInvalidConfig, s.masterDir, s.dir)
	}
	return nil
}

// Put creates name at version 1 holding value, minting the master on the
// keystore's first Put. The entry is written generation, then version 1, then
// the current pointer, then its floor; an entry directory without a pointer
// in the shape a crashed Put leaves, whose generation the floor does not
// record, is an interrupted Put, which the next Put of that name discards.
func (s *FileStore) Put(ctx context.Context, name string, kind Kind, value []byte) (Version, error) {
	v, err := s.put(ctx, name, kind, value)
	if err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
	}
	return v, nil
}

func (s *FileStore) put(ctx context.Context, name string, kind Kind, value []byte) (Version, error) {
	if err := s.checkConfig(); err != nil {
		return Version{}, err
	}
	if err := checkName(name); err != nil {
		return Version{}, err
	}
	if err := checkValue(kind, value); err != nil {
		return Version{}, err
	}
	// The floor is judged writable before anything is created, and locked
	// before anything is written, a master minted included.
	if err := s.checkFloorWritable(); err != nil {
		return Version{}, err
	}
	root, done, err := s.openLocked(ctx, true, true)
	if err != nil {
		return Version{}, err
	}
	defer done()
	fdir, fl, err := s.lockFloor(ctx)
	if err != nil {
		return Version{}, err
	}
	defer fdir.unlock()
	k, err := s.masterForPut(root)
	if err != nil {
		return Version{}, err
	}
	if fl, err = s.syncFloor(ctx, root, fdir, fl, k); err != nil {
		return Version{}, err
	}
	// A floor with no room for the new entry refuses the Put before its
	// directory is made. The generation is not minted yet; every one encodes
	// to the same length.
	if err := fl.room(name, floorEntry{Generation: hex.EncodeToString(make([]byte, generationSize)), Seq: 1}); err != nil {
		return Version{}, err
	}
	e, err := s.createEntry(root, name, fl)
	if err != nil {
		return Version{}, err
	}
	defer e.close()
	v, err := s.writeEntry(e, k, kind, value)
	if err != nil {
		return Version{}, err
	}
	// A new generation replaces whatever an interrupted Delete left recorded
	// for the name.
	if _, err := fdir.update(func(fl floor) bool { return fl.set(name, e.generation) }); err != nil {
		return Version{}, fmt.Errorf("the entry is stored, but recording its floor failed (the next keys verb records it): %w", err)
	}
	return v, nil
}

// createEntry makes name's directory with a fresh generation. A directory
// with a current pointer is ErrExists, and so is one without a pointer that
// holds more than an interrupted Put leaves, which is damage for rm to clear
// and is left untouched. An interrupted Put is discarded first.
//
// The directory is opened again after its mkdir, and OpenRoot follows a
// symlink that stays inside root, so the opened directory must be the one the
// mkdir made: a name swapped in between would otherwise have the new entry's
// generation written over another entry's.
func (s *FileStore) createEntry(root *os.Root, name string, fl floor) (*entry, error) {
	made, err := s.mkdirAt(root, name)
	if errors.Is(err, fs.ErrExist) {
		old, oerr := openEntryDir(root, name, fl)
		switch {
		case oerr == nil:
			old.close()
			return nil, ErrExists
		case errors.Is(oerr, errNoPointer):
			return nil, fmt.Errorf("%w: the entry is damaged, so rm it first: %w", ErrExists, oerr)
		case !errors.Is(oerr, errInterruptedPut):
			return nil, oerr
		}
		if err := root.RemoveAll(name); err != nil {
			return nil, fmt.Errorf("discard an interrupted put: %w", err)
		}
		made, err = s.mkdirAt(root, name)
	}
	if err != nil {
		return nil, fmt.Errorf("create the entry directory: %w", err)
	}
	return s.initEntry(root, name, made)
}

// initEntry opens the entry directory name, which mkdirAt just made as made,
// checks it is that directory, and writes a fresh generation into it.
func (s *FileStore) initEntry(root *os.Root, name string, made fs.FileInfo) (*entry, error) {
	s.entryMade(name)
	sub, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	e := &entry{root: sub, name: name}
	if opened, err := sub.Stat("."); err != nil || !os.SameFile(made, opened) {
		e.close()
		return nil, fmt.Errorf("%w: the new entry directory was replaced before it was opened", ErrCorrupt)
	}
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
	if err := rec.seal(k.seal, k.scope, value, s.rand); err != nil {
		return Version{}, err
	}
	if err := s.writeFile(e.root, versionName(1), rec.marshal()); err != nil {
		return Version{}, err
	}
	ptr := record{kind: kindPointer, name: e.name, generation: e.generation, created: created}
	if err := ptr.seal(k.seal, k.scope, pointerPlaintext(1, 1), s.rand); err != nil {
		return Version{}, err
	}
	if err := s.writeFile(e.root, currentName, ptr.marshal()); err != nil {
		return Version{}, err
	}
	return versionOf(rec, value, k.fingerprint), nil
}

// Current returns the version the current pointer names, with its value.
func (s *FileStore) Current(ctx context.Context, name string) (Version, []byte, error) {
	var (
		v   Version
		val []byte
	)
	err := s.read(ctx, name, func(e *entry, k keys, fl floor) error {
		cur, _, err := e.checkedPointer(k, fl)
		if err != nil {
			return err
		}
		v, val, err = e.version(k, cur)
		return err
	})
	return v, val, err
}

// Absent reports whether name is definitively not an entry, for a caller
// that must act on a deletion (the delivery reconciler deletes the Secret it
// delivered for a deleted entry), with the Identity of the entries'
// directory it read, so the caller can tell that directory from one restored
// or recreated since. Current answers ErrNotFound both for a name with no
// entry and for an entries' directory that is not there; only the first is an
// answer about name, since a data root restored without its keystore, or not
// yet mounted, is not every entry deleted. So Absent is true only when the
// entries' directory opens and is trusted under the shared lock, the recorded
// floor reads, and name has no directory there or holds only what an
// interrupted Put leaves (not an entry, as for Current). A missing entries'
// directory, an entry Current reports as corrupt (a lost pointer included)
// and any other failure is false with the error. It reads no record and does
// not load the master key, so it names no value.
func (s *FileStore) Absent(ctx context.Context, name string) (absent bool, identity string, err error) {
	absent, identity, err = s.absent(ctx, name)
	if err != nil {
		return false, "", fmt.Errorf("%s: %w", name, err)
	}
	return absent, identity, nil
}

func (s *FileStore) absent(ctx context.Context, name string) (bool, string, error) {
	if err := s.checkConfig(); err != nil {
		return false, "", err
	}
	if err := checkName(name); err != nil {
		return false, "", err
	}
	// Unlike read, a missing entries' directory stays fs.ErrNotExist: it is
	// not an answer about name.
	root, done, err := s.openLocked(ctx, false, false)
	if err != nil {
		return false, "", err
	}
	defer done()
	id, err := rootIdentity(root)
	if err != nil {
		return false, "", err
	}
	fdir, fl, err := s.openFloor()
	if err != nil {
		return false, "", err
	}
	_ = fdir.Close() // read-only; nothing to flush
	e, err := openEntry(root, name, fl)
	switch {
	case err == nil:
		e.close()
		return false, id, nil
	case errors.Is(err, ErrNotFound):
		return true, id, nil
	default:
		return false, "", err
	}
}

// Identity names the entries' directory as it stands: its device and inode,
// as "<dev>:<ino>". A restore that moves keystore/ aside and puts a copy in
// its place, or a keystore deleted and created again by the next Put, gets a
// new one; a Put, Rotate or Delete inside it does not change it. It is what
// the delivery reconciler compares across sweeps before it deletes a Secret
// on Absent's word. It reads only the directory's metadata, after the
// directory checks every open makes, and takes no lock. A missing entries'
// directory is an error matching fs.ErrNotExist.
func (s *FileStore) Identity(ctx context.Context) (string, error) {
	if err := s.checkConfig(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		return "", fmt.Errorf("the keystore identity: %w", err)
	}
	defer func() { _ = root.Close() }() // read-only
	id, err := rootIdentity(root)
	if err != nil {
		return "", fmt.Errorf("the keystore identity: %w", err)
	}
	return id, nil
}

// rootIdentity is the device and inode of the directory root is open on.
func rootIdentity(root *os.Root) (string, error) {
	fi, err := root.Stat(".")
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return "", errors.New("the entries' directory has no device and inode")
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10), nil
}

// Get returns version of name with its value. A version above the one the
// current pointer names is ErrVersionNotFound: it is not yet committed.
func (s *FileStore) Get(ctx context.Context, name string, version uint64) (Version, []byte, error) {
	var (
		v   Version
		val []byte
	)
	err := s.read(ctx, name, func(e *entry, k keys, fl floor) error {
		cur, _, err := e.checkedPointer(k, fl)
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

// read runs fn on name's entry under the shared lock, with the recorded
// floor. A missing entries' directory or entry directory, or an interrupted
// Put, is ErrNotFound.
func (s *FileStore) read(ctx context.Context, name string, fn func(*entry, keys, floor) error) error {
	err := func() error {
		if err := s.checkConfig(); err != nil {
			return err
		}
		if err := checkName(name); err != nil {
			return err
		}
		root, done, err := s.openLocked(ctx, false, false)
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		defer done()
		fdir, fl, err := s.openFloor()
		if err != nil {
			return err
		}
		_ = fdir.Close() // read-only; nothing to flush
		e, err := openEntry(root, name, fl)
		if err != nil {
			return err
		}
		defer e.close()
		k, err := s.loadMaster()
		if err != nil {
			return err
		}
		return fn(e, k, fl)
	}()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// List returns every entry, sorted by name. An entry that cannot be opened,
// or any of whose committed versions cannot, is returned with Err set and
// nothing else. A directory that is not an entry (an interrupted Put, or a
// name Put would refuse) is not listed.
func (s *FileStore) List(ctx context.Context) ([]Entry, error) {
	out, err := s.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	return out, nil
}

func (s *FileStore) list(ctx context.Context) ([]Entry, error) {
	if err := s.checkConfig(); err != nil {
		return nil, err
	}
	root, done, err := s.openLocked(ctx, false, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer done()
	// The floor decides what is an entry, and a floor that cannot be trusted
	// is about every entry, so it fails the whole call.
	fdir, fl, err := s.openFloor()
	if err != nil {
		return nil, err
	}
	_ = fdir.Close() // read-only; nothing to flush
	names, err := readDirNames(root, maxDirNames)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var (
		out []Entry
		k   keys
	)
	for _, name := range names {
		if checkName(name) != nil {
			continue
		}
		e, err := openEntry(root, name, fl)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			out = append(out, Entry{Name: name, Err: err})
			continue
		}
		// The master is needed only once there is an entry to open, and its
		// failure is about every entry, so it fails the whole call.
		if k.seal == nil {
			if k, err = s.loadMaster(); err != nil {
				e.close()
				return nil, err
			}
		}
		out = append(out, listEntry(e, k, fl))
		e.close()
	}
	return out, nil
}

// listEntry opens every committed version of e for List. Any failure, a
// pointer the floor rules out included, is the entry's Err.
func listEntry(e *entry, k keys, fl floor) Entry {
	cur, _, err := e.checkedPointer(k, fl)
	if err != nil {
		return Entry{Name: e.name, Err: err}
	}
	out := Entry{Name: e.name, Versions: make([]Version, 0, cur)}
	for n := uint64(1); n <= cur; n++ {
		v, _, err := e.version(k, n)
		if err != nil {
			return Entry{Name: e.name, Err: fmt.Errorf("version %d: %w", n, err)}
		}
		out.Versions = append(out.Versions, v)
	}
	out.Current = out.Versions[len(out.Versions)-1]
	return out
}

// Delete removes name and every version of it. The pointer is removed first
// and the entry's floor last, so an interrupted Delete leaves a directory with
// no pointer whose generation the floor still records: damage that List
// reports and Delete, called again, clears. With no floor file to say so, a
// directory holding only generation and v1 is an interrupted Put instead,
// which is not an entry: Delete, called again, removes it and answers
// ErrNotFound, and so does the next Put of the name. Delete reads nothing
// inside the entry but its generation, so it removes one List reports as
// corrupt, whatever is planted at its current, and still removes the floor
// entry that records its generation. A symlink or any other non-directory at
// the name is unlinked without being followed.
//
// The floor is changed only for an entry it records: an interrupted Put's
// generation is never recorded (or it would be a lost pointer), and a
// non-directory has none, so removing either leaves the floor alone. A crash
// after the directory is gone leaves a floor for a name with no entry, which
// the next Put of the name replaces.
func (s *FileStore) Delete(ctx context.Context, name string) error {
	if err := s.delete(ctx, name); err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

func (s *FileStore) delete(ctx context.Context, name string) error {
	if err := s.checkConfig(); err != nil {
		return err
	}
	if err := checkName(name); err != nil {
		return err
	}
	if err := s.checkFloorWritable(); err != nil {
		return err
	}
	root, done, err := s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	defer done()
	fdir, fl, err := s.lockFloor(ctx)
	if err != nil {
		return err
	}
	defer fdir.unlock()
	// Delete must work without the master, so the other entries' floors are
	// raised only when it opens. A keystore with more entries than the floor
	// holds is not raised, but Delete still runs: it is how room is made.
	if k, kerr := s.loadMasterLocked(); kerr == nil {
		synced, err := s.syncFloor(ctx, root, fdir, fl, k)
		switch {
		case err == nil:
			fl = synced
		case !errors.Is(err, errFloorFull):
			return err
		}
	}
	// Anything but a directory at the name was planted there, since Put makes
	// only directories: it is unlinked, and a symlink is removed itself,
	// never followed.
	if fi, err := root.Lstat(name); err == nil && !fi.IsDir() {
		if err := root.Remove(name); err != nil {
			return err
		}
		return syncDir(root)
	}
	// The generation is read before anything is removed: the floor entry is
	// removed only if it records this one. A directory whose generation does
	// not read leaves the floor as it is, for the next Put of the name.
	gen, genErr := [generationSize]byte{}, error(nil)
	if raw, err := openEntryDirRaw(root, name); err == nil {
		gen, genErr = readGeneration(raw.root)
		raw.close()
	} else {
		genErr = err
	}
	e, err := openEntryDir(root, name, fl)
	damaged := errors.Is(err, errNoPointer)
	if errors.Is(err, errInterruptedPut) {
		// Not an entry, so the answer is ErrNotFound, but the directory may
		// hold a sealed v1 (a Delete that crashed after removing the pointer,
		// with no floor file to record the entry, leaves one), so it is
		// removed first.
		if err := root.RemoveAll(name); err != nil {
			return err
		}
		if err := syncDir(root); err != nil {
			return err
		}
		return ErrNotFound
	}
	if err != nil && !damaged {
		return err
	}
	if !damaged {
		defer e.close()
		// RemoveAll, not Remove: anything may be planted at current, and a
		// non-empty directory there would fail Remove on every retry.
		// RemoveAll removes a symlink itself, never what it names.
		if err := e.root.RemoveAll(currentName); err != nil {
			return err
		}
		if err := syncDir(e.root); err != nil {
			return err
		}
		if err := s.step("delete " + name); err != nil {
			return err
		}
	}
	if err := root.RemoveAll(name); err != nil {
		return err
	}
	if err := syncDir(root); err != nil {
		return err
	}
	if genErr != nil {
		return nil
	}
	_, err = fdir.update(func(fl floor) bool { return fl.remove(name, gen) })
	return err
}

// Rotate seals value as the next version of name, of the kind name already
// has, then flips the current pointer to it at the next sequence, then raises
// the floor: docs/design/keystore.md § "Rotation and rollback". A crash
// before the flip leaves the old version current and an unreferenced next
// version, which the next Rotate discards before sealing the value it was
// given; it never promotes it.
func (s *FileStore) Rotate(ctx context.Context, name string, value []byte) (Version, error) {
	v, err := s.rotate(ctx, name, value)
	if err != nil {
		return Version{}, fmt.Errorf("rotate %s: %w", name, err)
	}
	return v, nil
}

func (s *FileStore) rotate(ctx context.Context, name string, value []byte) (Version, error) {
	if err := s.checkConfig(); err != nil {
		return Version{}, err
	}
	if err := checkName(name); err != nil {
		return Version{}, err
	}
	if err := s.checkFloorWritable(); err != nil {
		return Version{}, err
	}
	root, done, err := s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, err
	}
	defer done()
	fdir, fl, err := s.lockFloor(ctx)
	if err != nil {
		return Version{}, err
	}
	defer fdir.unlock()
	e, err := openEntry(root, name, fl)
	if err != nil {
		return Version{}, err
	}
	defer e.close()
	k, err := s.loadMasterLocked()
	if err != nil {
		return Version{}, err
	}
	if fl, err = s.syncFloor(ctx, root, fdir, fl, k); err != nil {
		return Version{}, err
	}
	cur, seq, err := e.checkedPointer(k, fl)
	if err != nil {
		return Version{}, err
	}
	// The current version is opened, not only named: the new version takes
	// its kind, and a Rotate over a current version that does not open would
	// hide the damage behind a new one.
	old, _, err := e.version(k, cur)
	if err != nil {
		return Version{}, err
	}
	if err := checkValue(old.Kind, value); err != nil {
		return Version{}, err
	}
	if cur >= maxVersion || seq == math.MaxUint64 {
		return Version{}, fmt.Errorf("%w: the pointer is at the last version or sequence", ErrCorrupt)
	}
	// A floor with no room for the next sequence refuses the Rotate before
	// anything is written.
	if err := fl.room(name, floorEntry{Generation: hex.EncodeToString(e.generation[:]), Seq: seq + 1}); err != nil {
		return Version{}, err
	}
	if err := discardOrphans(ctx, e, cur); err != nil {
		return Version{}, err
	}
	next := cur + 1
	created := s.now().Unix()
	rec := record{kind: byte(old.Kind), name: name, version: next, generation: e.generation, created: created}
	if err := rec.seal(k.seal, k.scope, value, s.rand); err != nil {
		return Version{}, err
	}
	if err := s.writeFile(e.root, versionName(next), rec.marshal()); err != nil {
		return Version{}, err
	}
	ptr := record{kind: kindPointer, name: name, generation: e.generation, created: created}
	if err := ptr.seal(k.seal, k.scope, pointerPlaintext(next, seq+1), s.rand); err != nil {
		return Version{}, err
	}
	if err := s.writeFile(e.root, currentName, ptr.marshal()); err != nil {
		return Version{}, err
	}
	if _, err := fdir.update(func(fl floor) bool { return fl.raise(name, e.generation, seq+1) }); err != nil {
		return Version{}, fmt.Errorf("version %d is current, but recording its floor failed (the next keys verb records it): %w", next, err)
	}
	return versionOf(rec, value, k.fingerprint), nil
}

// discardOrphans removes every version file of e numbered above cur: what a
// Rotate interrupted before its pointer flip leaves. Each holds the value the
// interrupted attempt carried, so none is ever promoted. It stops with ctx's
// error when ctx is done (see loopCtx); what it removed stays removed, and the
// next Rotate removes the rest.
//
// While the floor lags its pointer (a Rotate whose floor write failed), an
// older pointer copied back passes the floor check, and the version the live
// pointer named is then discarded here as an orphan. docs/design/keystore.md
// § "Rotation and rollback" accepts that window: a crash before the flip
// leaves the same state, and its orphan must be discarded.
func discardOrphans(ctx context.Context, e *entry, cur uint64) error {
	names, err := readDirNames(e.root, maxDirNames)
	if err != nil {
		return err
	}
	removed := false
	for i, n := range names {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		v, ok := parseVersionName(n)
		if !ok || v <= cur {
			continue
		}
		if err := e.root.Remove(n); err != nil {
			return fmt.Errorf("discard the orphaned %s: %w", n, err)
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return syncDir(e.root)
}

// parseVersionName returns the version a version file name names, if it is
// one: "v" and a version number in its canonical form.
func parseVersionName(n string) (uint64, bool) {
	if !strings.HasPrefix(n, "v") {
		return 0, false
	}
	v, err := strconv.ParseUint(n[1:], 10, 64)
	if err != nil || v == 0 || versionName(v) != n {
		return 0, false
	}
	return v, true
}

// RaiseFloor raises every entry's floor to its current pointer's sequence
// and writes keystore-floor.json if that changes it, which also rebuilds an
// absent floor (the restore procedure in docs/design/keystore.md § "Backup
// and snapshots"). Put, Rotate and Delete raise it themselves at their start.
// The read verbs (the CLI's list and show, in a later pull request) must call
// RaiseFloor at their start to raise a floor that lags its pointers; until
// they do, nothing raises it on read: Current, Get and List only check it. It
// takes the exclusive lock and the floor's lock, and runs as root. A keystore
// with no entries directory or no master has nothing to raise.
func (s *FileStore) RaiseFloor(ctx context.Context) error {
	if err := s.raiseFloor(ctx); err != nil {
		return fmt.Errorf("raise the keystore floor: %w", err)
	}
	return nil
}

func (s *FileStore) raiseFloor(ctx context.Context) error {
	if err := s.checkConfig(); err != nil {
		return err
	}
	if err := s.checkFloorWritable(); err != nil {
		return err
	}
	root, done, err := s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer done()
	fdir, fl, err := s.lockFloor(ctx)
	if err != nil {
		return err
	}
	defer fdir.unlock()
	k, err := s.loadMasterLocked()
	if errors.Is(err, ErrMasterMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.syncFloor(ctx, root, fdir, fl, k)
	return err
}

// entry is one open entry directory and its generation.
type entry struct {
	root       *os.Root
	name       string
	generation [generationSize]byte
}

// openEntry opens name's directory and reads its generation.
func openEntry(root *os.Root, name string, fl floor) (*entry, error) {
	e, err := openEntryDir(root, name, fl)
	if err != nil {
		return nil, err
	}
	if e.generation, err = readGeneration(e.root); err != nil {
		e.close()
		return nil, err
	}
	return e, nil
}

// readGeneration reads and decodes dir's generation file. A missing file or
// one of the wrong shape is ErrCorrupt (see readError).
func readGeneration(dir *os.Root) ([generationSize]byte, error) {
	var gen [generationSize]byte
	b, _, err := readFile(dir, generationName, generationFileSize)
	if err == nil && (len(b) != generationFileSize || b[len(b)-1] != '\n') {
		err = fmt.Errorf("%w: malformed", errBadFile)
	}
	if err == nil {
		if _, herr := hex.Decode(gen[:], b[:len(b)-1]); herr != nil {
			err = fmt.Errorf("%w: %w", errBadFile, herr)
		}
	}
	if err != nil {
		return gen, readError(generationName, err)
	}
	return gen, nil
}

// openEntryDir opens name's directory. A missing directory is ErrNotFound, and
// one that is not a real directory is ErrCorrupt. A real directory without a
// current pointer is errInterruptedPut or errNoPointer: interruptedPut tells
// them apart by shape, and committedBefore by the floor, since a directory in
// the shape a crashed Put leaves whose generation the floor records once had
// a committed pointer.
func openEntryDir(root *os.Root, name string, fl floor) (*entry, error) {
	e, err := openEntryDirRaw(root, name)
	if err != nil {
		return nil, err
	}
	if _, err := e.root.Lstat(currentName); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			e.close()
			return nil, err
		}
		interrupted, ierr := interruptedPut(e.root)
		committed := false
		if ierr == nil && interrupted {
			committed, ierr = committedBefore(e.root, name, fl)
		}
		e.close()
		switch {
		case ierr != nil:
			return nil, ierr
		case committed:
			return nil, errLostPointer
		case interrupted:
			return nil, errInterruptedPut
		}
		return nil, errDamagedShape
	}
	return e, nil
}

// committedBefore reports whether the floor records, for name, the
// generation in dir's generation file. Put records the floor only after its
// pointer, so a recorded generation means this entry committed a pointer. A
// directory with no generation file never did. A generation file that does
// not read while the floor records the name is damage: a crashed Put writes
// that file whole, by rename. The two are compared as generation bytes, as
// every reader decodes them, not as text.
func committedBefore(dir *os.Root, name string, fl floor) (bool, error) {
	f, ok := fl[name]
	if !ok {
		return false, nil
	}
	gen, err := readGeneration(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case errors.Is(err, errBadFile):
		return false, fmt.Errorf("%w: the generation file does not read", errDamagedShape)
	case err != nil:
		return false, err
	}
	recorded, err := hex.DecodeString(f.Generation)
	if err != nil {
		return false, fmt.Errorf("%w: entry %q", errFloorMalformed, name)
	}
	return bytes.Equal(recorded, gen[:]), nil
}

// interruptedPut reports whether dir holds only what a crashed Put leaves
// before its pointer: nothing, generation, or generation and v1, plus
// temporary files, which no reader opens. Put writes generation before v1, so
// v1 without generation cannot come from a crash.
//
// A temporary file is a regular file named as writeFile names one for a file
// Put writes (see putTemp); a directory, a symlink or any other dot name is
// not one, so it makes the directory damage rather than vanish with the next
// Put's discard.
func interruptedPut(dir *os.Root) (bool, error) {
	names, err := readDirNames(dir, maxDirNames)
	if err != nil {
		return false, err
	}
	var generation, v1 bool
	for _, n := range names {
		switch {
		case n == generationName:
			generation = true
		case n == versionName(1):
			v1 = true
		case putTemp(n):
			fi, err := dir.Lstat(n)
			if err != nil {
				return false, err
			}
			if !fi.Mode().IsRegular() {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return generation || !v1, nil
}

// putTemp reports whether n is the name of a temporary file writeFile makes
// while a Put writes an entry: for generation, v1 or current.
func putTemp(n string) bool {
	return isTempName(n, generationName) || isTempName(n, versionName(1)) || isTempName(n, currentName)
}

// openEntryDirRaw opens name's directory without asking for a current pointer.
func openEntryDirRaw(root *os.Root, name string) (*entry, error) {
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
	return e, nil
}

func (e *entry) close() { _ = e.root.Close() } // read-only or already fsynced

// readError classifies an error reading name inside an entry: a missing file
// or one of the wrong shape is ErrCorrupt, and anything else (a permission or
// I/O error) is returned as it is, because restoring from backup does not fix
// it.
func readError(name string, err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errBadFile) {
		return fmt.Errorf("%w: %s: %w", ErrCorrupt, name, err)
	}
	return fmt.Errorf("read %s: %w", name, err)
}

// openRecord reads the record file name of e and opens it, refusing a record
// that does not belong there: a pointer where a version belongs or the
// reverse, or another name, version or generation.
func (e *entry) openRecord(k keys, name string, pointer bool, version uint64) (record, []byte, error) {
	b, _, err := readFile(e.root, name, maxRecordSize)
	if err != nil {
		return record{}, nil, readError(name, err)
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
	pt, err := k.open(&r)
	if err != nil {
		return record{}, nil, err
	}
	return r, pt, nil
}

// pointer opens e's current pointer and returns the version it names, at
// most maxVersion, and its sequence, without consulting the floor
// (checkedPointer does). It is the one decoder of a pointer, so every reader
// gets the bound.
func (e *entry) pointer(k keys) (version, seq uint64, err error) {
	_, pt, err := e.openRecord(k, currentName, true, 0)
	if err != nil {
		return 0, 0, err
	}
	if len(pt) != pointerSize {
		return 0, 0, fmt.Errorf("%w: the pointer is %d bytes", ErrCorrupt, len(pt))
	}
	version = binary.BigEndian.Uint64(pt[:8])
	seq = binary.BigEndian.Uint64(pt[8:])
	if version == 0 || seq == 0 {
		return 0, 0, fmt.Errorf("%w: the pointer names version %d at sequence %d", ErrCorrupt, version, seq)
	}
	if version > maxVersion {
		return 0, 0, fmt.Errorf("%w: the pointer names version %d, over the %d-version limit", ErrCorrupt, version, maxVersion)
	}
	return version, seq, nil
}

// checkedPointer is pointer, refused (a staleError, matching ErrCorrupt)
// when the floor rules it out (docs/design/keystore.md § "Pointer sequence
// and floor").
func (e *entry) checkedPointer(k keys, fl floor) (version, seq uint64, err error) {
	version, seq, err = e.pointer(k)
	if err != nil {
		return 0, 0, err
	}
	if err := fl.check(e.name, e.generation, seq); err != nil {
		return 0, 0, err
	}
	return version, seq, nil
}

// version opens version n of e.
func (e *entry) version(k keys, n uint64) (Version, []byte, error) {
	r, value, err := e.openRecord(k, versionName(n), false, n)
	if err != nil {
		return Version{}, nil, err
	}
	// The value authenticated, so it is what a Put sealed; a value that does
	// not validate is still refused rather than handed to a fingerprint that
	// assumes a valid key.
	if err := checkValue(Kind(r.kind), value); err != nil {
		return Version{}, nil, fmt.Errorf("%w: version %d: %w", ErrCorrupt, n, err)
	}
	return versionOf(r, value, k.fingerprint), value, nil
}

// versionOf is the metadata of the version r seals value as.
func versionOf(r record, value, fpKey []byte) Version {
	kind := Kind(r.kind)
	return Version{
		Name:        r.name,
		Version:     r.version,
		Kind:        kind,
		Created:     time.Unix(r.created, 0).UTC(),
		Fingerprint: fingerprint(kind, value, fpKey),
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
