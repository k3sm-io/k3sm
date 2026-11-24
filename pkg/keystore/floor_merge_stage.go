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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// preRestoreDirName is the root-only directory in the data root the
	// restore recipe stages both keystore trees in.
	preRestoreDirName = "pre-restore.d"
	// plantedPrefix names what the merge moves aside from the store's Dir
	// into pre-restore.d: planted-<unix>.
	plantedPrefix = "planted-"
	// stagedTreeName is the backup's keystore/, as the recipe's root ditto
	// copied it into pre-restore.d; the merge moves it into place.
	stagedTreeName = "restored"
	// asideTreeName is the live keystore/ the recipe moved aside into
	// pre-restore.d.
	asideTreeName = "keystore"
	// maxStagedDepth bounds how deep the staged-tree walk descends: the
	// deepest node the store writes is a user-scope entry's file,
	// .user/<uid>/entries/<name>/<file>, five levels below keystore/.
	maxStagedDepth = 5
	// unknownUID is the owner macOS reports for every file on a volume that
	// ignores ownership (_unknown): a backup copied from one carries it.
	unknownUID = 99
)

// syncStaged fsyncs one node of the staged tree as the merge hands it
// over, before the tree's rename. It is a variable so a test can observe
// each fsync.
var syncStaged = func(f *os.File) error { return f.Sync() }

// statDev is the device of the directory f holds (fstat). It is a
// variable so a test can report two devices.
var statDev = func(f *os.File) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", f.Name(), err)
	}
	return uint64(st.Dev), nil
}

// stagedNameLimit bounds how many names the staged-tree walk accepts in one
// directory: maxDirNames, which tests lower.
var stagedNameLimit = maxDirNames

// stagedNodeLimit bounds how many nodes one walk of the staged tree visits
// in all, the tree's own directory included: the per-directory and depth
// bounds alone allow far more than any keystore holds. It is
// maxStagedNodes, which tests lower.
var stagedNodeLimit = maxStagedNodes

// maxStagedNodes is stagedNodeLimit's production value: 2^22 nodes, room
// for every entry a full floor records with several versions each.
const maxStagedNodes = 1 << 22

// stagedWalk is one walk's state: its context, checked as it goes, and how
// many more nodes it visits.
type stagedWalk struct {
	ctx  context.Context
	seen int
}

// errNotStaged refuses a merge that would change the floor while the
// restored keystore/ is not staged in pre-restore.d.
var errNotStaged = errors.New("the restored keystore/ is not staged: the merge reads it only from pre-restore.d/restored in the data root, where the restore recipe's ditto puts it, and moves it into place itself. Nothing is written. Follow the restore steps in docs/user/keys.md")

// mergeStaging is pre-restore.d as the merge opened it, through the data root
// the floor lock judged, and the directory the store's keystore/ goes in.
type mergeStaging struct {
	// dir and dirF are pre-restore.d, or nil when it is absent.
	dir  *os.Root
	dirF *os.File
	// staged is set when pre-restore.d/restored is present.
	staged bool
	// parent is the directory the store's Dir is in, and target its base
	// name; targetExists is set when anything, a symlink included, is
	// there, and targetType names its file type.
	parent       *os.File
	target       string
	targetExists bool
	targetType   string
	// checked is set once checkStaged has walked the tree and found it in
	// shape, so the handover does not walk it read-only a second time.
	checked bool
}

// close releases what openStaging opened.
func (st *mergeStaging) close() {
	for _, f := range []*os.File{st.dirF, st.parent} {
		if f != nil {
			_ = f.Close() // read-only handles; renames are synced
		}
	}
	if st.dir != nil {
		_ = st.dir.Close() // read-only handle
	}
}

// openStaging opens pre-restore.d through l.root, the data root the lock
// judged: a real directory, never followed, owned by root (floorUID) and
// granting nothing to group or others, by its mode or an extended ACL. The
// recipe's ditto keeps the backup's owner inside it, so the directory's own
// permissions are what keep the service user out of both trees, and any
// that let it search pre-restore.d would let it write into the staged tree. An absent pre-restore.d is no staging.
// It also opens the directory the store's Dir is in and records whether
// anything is at Dir.
func (s *FileStore) openStaging(l *floorLock) (st *mergeStaging, err error) {
	st = &mergeStaging{target: filepath.Base(s.dir)}
	defer func() {
		if err != nil {
			st.close()
			st = nil
		}
	}()
	st.parent, err = os.OpenFile(filepath.Dir(s.dir), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return st, fmt.Errorf("open the directory of %s: %w", s.dir, err)
	}
	var ts unix.Stat_t
	switch err := unix.Fstatat(int(st.parent.Fd()), st.target, &ts, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		st.targetExists, st.targetType = true, statTypeName(uint32(ts.Mode))
	case !errors.Is(err, syscall.ENOENT):
		return st, fmt.Errorf("look for %s: %w", s.dir, err)
	}
	named, err := l.root.Lstat(preRestoreDirName)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if !named.IsDir() {
		return st, fmt.Errorf("%w: %s has mode %s", errFloorUntrusted, preRestoreDirName, named.Mode())
	}
	if st.dir, err = l.root.OpenRoot(preRestoreDirName); err != nil {
		return st, err
	}
	if st.dirF, err = st.dir.Open("."); err != nil {
		return st, err
	}
	opened, err := st.dirF.Stat()
	if err != nil {
		return st, err
	}
	if !os.SameFile(named, opened) {
		return st, fmt.Errorf("%w: %s changed while it was opened", errFloorUntrusted, preRestoreDirName)
	}
	if err := s.floorOwned(opened); err != nil {
		return st, fmt.Errorf("%w: %s: %w", errFloorUntrusted, preRestoreDirName, err)
	}
	if perm := opened.Mode().Perm(); perm&0o077 != 0 {
		return st, fmt.Errorf("%w: %s is mode %04o: it must grant nothing to group or others (sudo mkdir -m 0700)", errFloorUntrusted, preRestoreDirName, perm)
	}
	// An ACL entry grants past the mode, so one on pre-restore.d could let
	// the service user into the staged tree; it is read on the descriptor.
	switch acl, err := hasExtendedACL(int(st.dirF.Fd())); {
	case err != nil:
		return st, fmt.Errorf("%s: %w", preRestoreDirName, err)
	case acl:
		return st, fmt.Errorf("%w: %s has an extended ACL, which can grant past its mode: it must grant nothing to anyone but root (sudo chmod -N %s removes it)", errFloorUntrusted, preRestoreDirName, preRestoreDirName)
	}
	// The staged tree moves to the store's Dir by rename, and what is
	// planted there moves into pre-restore.d the same way: both
	// directories must be on one device, judged on the descriptors before
	// anything is written.
	pd, err := statDev(st.parent)
	if err != nil {
		return st, err
	}
	sd, err := statDev(st.dirF)
	if err != nil {
		return st, err
	}
	if pd != sd {
		return st, fmt.Errorf("%s (device %d) and %s, the directory the keystore is in (device %d), are on different devices: the merge moves the restored keystore/ between them by rename, which cannot cross devices. Nothing is written; make pre-restore.d in the data root on the keystore's volume, as docs/user/keys.md describes", preRestoreDirName, sd, filepath.Dir(s.dir), pd)
	}
	switch fi, err := st.dir.Lstat(stagedTreeName); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return st, err
	case !fi.IsDir():
		return st, fmt.Errorf("%w: %s/%s has mode %s", errFloorUntrusted, preRestoreDirName, stagedTreeName, fi.Mode())
	default:
		st.staged = true
	}
	return st, nil
}

// tree opens the directory name inside pre-restore.d, never followed: nil
// when pre-restore.d or name is absent.
func (st *mergeStaging) tree(name string) (*os.Root, error) {
	if st.dir == nil {
		return nil, nil
	}
	named, err := st.dir.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !named.IsDir() {
		return nil, fmt.Errorf("%w: %s/%s has mode %s", errFloorUntrusted, preRestoreDirName, name, named.Mode())
	}
	root, err := st.dir.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	if opened, err := root.Stat("."); err != nil || !os.SameFile(named, opened) {
		_ = root.Close() // abandoned
		return nil, fmt.Errorf("%w: %s/%s changed while it was opened", errFloorUntrusted, preRestoreDirName, name)
	}
	return root, nil
}

// errStagedTargetExists refuses the move of the staged tree onto a Dir that
// came to hold something after the merge moved what was there aside: it is
// only ever returned once the floor is written, so it names the rerun.
func errStagedTargetExists(dir string) error {
	return fmt.Errorf("%w: %s came to exist, a symlink counted, after the merge moved what was there aside: the merge moves the staged tree there itself, never through or over what is there, so the restored keystore/ is left staged. Run the same merge again, which moves it aside into pre-restore.d too", errFloorUntrusted, dir)
}

// statTypeName names the file type in mode, an lstat st_mode, widened to uint32
// (darwin's Stat_t.Mode is uint16, linux's uint32).
func statTypeName(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return "directory"
	case unix.S_IFLNK:
		return "symlink"
	case unix.S_IFREG:
		return "regular file"
	case unix.S_IFIFO:
		return "FIFO"
	case unix.S_IFSOCK:
		return "socket"
	}
	return "device"
}

// plantedName is the first pre-restore.d/planted-<unix>, from now, that is
// free.
func (s *FileStore) plantedName(st *mergeStaging) (string, error) {
	at := s.now().Unix()
	for tries := 0; tries < maxMergedTries; tries++ {
		n := fmt.Sprintf("%s%d", plantedPrefix, at+int64(tries))
		switch _, err := st.dir.Lstat(n); {
		case errors.Is(err, fs.ErrNotExist):
			return n, nil
		case err != nil:
			return "", err
		}
	}
	return "", fmt.Errorf("%s/%s%d and the %d seconds after it are all taken", preRestoreDirName, plantedPrefix, at, maxMergedTries-1)
}

// moveTargetAside renames what is at the store's Dir, with the restored tree
// staged, into pre-restore.d as name (plantedName), through the two directory
// descriptors and never over anything there (renameExcl): pre-restore.d is
// root-only, so the planted object is out of the service user's reach, and a
// symlink is moved itself, never followed. Something gone from Dir since
// openStaging looked is no error. Both directories are fsynced.
func (s *FileStore) moveTargetAside(st *mergeStaging, name string) error {
	if err := s.step("merge move aside"); err != nil {
		return err
	}
	switch err := renameExcl(int(st.parent.Fd()), st.target, int(st.dirF.Fd()), name); {
	case errors.Is(err, syscall.ENOENT):
		return nil
	case err != nil:
		return fmt.Errorf("move %s aside to %s/%s: %w", s.dir, preRestoreDirName, name, err)
	}
	slog.Warn("keystore floor: something was at the keystore directory while the restored keystore/ was staged, which the restore recipe leaves absent; the merge moved it aside into the root-only pre-restore.d", "dir", s.dir, "type", st.targetType, "to", filepath.Join(preRestoreDirName, name))
	for _, d := range []*os.File{st.parent, st.dirF} {
		if err := d.Sync(); err != nil {
			return fmt.Errorf("fsync %s after moving %s aside: %w", d.Name(), s.dir, err)
		}
	}
	return nil
}

// stagedKind is what a node of the staged tree is, by where it sits: the
// tree itself, an entry's directory, the user scopes' directory, one user
// scope, a user scope's entries' directory, a file, the persisted
// pre-frame refusal counts (PreFrameDroppedName), a file judged more
// strictly and parsed, or their temporary file, judged as any other file.
type stagedKind int

const (
	stagedTree stagedKind = iota
	stagedEntry
	stagedUsers
	stagedScope
	stagedScopeEntries
	stagedFile
	stagedDropped
	stagedDroppedTemp
)

// file reports whether a node of kind k is a file.
func (k stagedKind) file() bool {
	return k == stagedFile || k == stagedDropped || k == stagedDroppedTemp
}

// stagedChild is what name may be inside a node of kind parent, and, for a
// file, its size cap: only what the store itself writes there (the entry-file
// allowlist of docs/design/keystore.md § "Restoring with the saved floor").
// ok is false for any other name.
func stagedChild(parent stagedKind, name string) (kind stagedKind, maxSize int64, ok bool) {
	switch parent {
	case stagedTree:
		switch {
		case name == lockName:
			// The lock is created empty and only ever flocked.
			return stagedFile, 0, true
		case name == userScopesName:
			return stagedUsers, 0, true
		case name == PreFrameDroppedName:
			return stagedDropped, maxPreFrameDroppedSize, true
		case isTempName(name, PreFrameDroppedName):
			// A backup taken mid-write can hold the server's half-written
			// temporary file. Its content is never read, so it is judged
			// as an entry's temporary file is (type, one link, owner, the
			// cap), never parsed, and carried into place with the tree as
			// those are: the merge discards no staged temporary file and
			// keeps no count of one.
			return stagedDroppedTemp, maxPreFrameDroppedSize, true
		case checkName(name) == nil:
			return stagedEntry, 0, true
		}
	case stagedEntry:
		if c, ok := entryFileCap(name); ok {
			return stagedFile, c, true
		}
	case stagedUsers:
		if scopeDirName(name) {
			return stagedScope, 0, true
		}
	case stagedScope:
		if name == scopeEntriesName {
			return stagedScopeEntries, 0, true
		}
		if c, ok := scopeFileCap(name); ok {
			return stagedFile, c, true
		}
	case stagedScopeEntries:
		if checkName(name) == nil {
			return stagedEntry, 0, true
		}
	}
	return 0, 0, false
}

// tempBase is the name writeFile made the temporary file n for, when n is
// one (isTempName).
func tempBase(n string) (string, bool) {
	rest, ok := strings.CutSuffix(n, ".tmp")
	if !ok || !strings.HasPrefix(rest, ".") {
		return "", false
	}
	i := strings.LastIndexByte(rest, '.')
	if i <= 1 {
		return "", false
	}
	base := rest[1:i]
	return base, isTempName(n, base)
}

// entryFileCap is the size cap of n in an entry's directory, when the store
// writes a file of that name there: generation, current, v<N> up to
// maxVersion, the .new sibling Rewrap seals current and v<N> into, and the
// temporary file writeFile makes for each.
func entryFileCap(n string) (int64, bool) {
	if base, ok := tempBase(n); ok {
		n = base
	}
	if n == generationName {
		return int64(generationFileSize), true
	}
	n = strings.TrimSuffix(n, newSuffix)
	if v, ok := parseVersionName(n); n == currentName || ok && v <= maxVersion {
		return int64(maxRecordSize), true
	}
	return 0, false
}

// scopeFileCap is the size cap of n in a user scope's directory: scope.key,
// its Rewrap sibling, the deliveries record, and the temporary file
// writeFile makes for each.
func scopeFileCap(n string) (int64, bool) {
	if base, ok := tempBase(n); ok {
		n = base
	}
	switch n {
	case scopeKeyName, scopeKeyName + newSuffix:
		return int64(maxScopeKeyRecordSize), true
	case deliveriesName:
		return int64(maxDeliveriesRecordSize), true
	}
	return 0, false
}

// scopeDirName reports whether n names a user scope's directory: a uid in
// the eligible range, in its canonical decimal form.
func scopeDirName(n string) bool {
	u, err := strconv.ParseUint(n, 10, 32)
	return err == nil && strconv.FormatUint(u, 10) == n && u >= minScopeUID && u <= maxScopeUID
}

// holdsUserScopes reports whether the staged tree holds a user scope's
// directory under .user: user-scope entries, which the system floor the
// merge writes does not record. It reads after checkStaged, which judged
// the tree's shape.
func (st *mergeStaging) holdsUserScopes() (bool, error) {
	tree, err := st.tree(stagedTreeName)
	if err != nil || tree == nil {
		return false, err
	}
	defer func() { _ = tree.Close() }() // read-only
	d, err := tree.Open(userScopesName)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = d.Close() }() // read-only
	names, err := d.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return len(names) > 0, nil
}

// checkStaged walks pre-restore.d/restored read-only and refuses it
// (ErrCorrupt, naming the path inside the tree) unless every node is one the
// keystore writes, in the shape it writes it (judgeStaged), and the tree
// holds at most stagedNodeLimit nodes. Both a dry run and the merge run it
// before anything changes, so they refuse alike; it stops with ctx's error.
func (s *FileStore) checkStaged(ctx context.Context, st *mergeStaging) error {
	if err := s.walkStaged(ctx, st, false); err != nil {
		return err
	}
	st.checked = true
	return nil
}

// chownStaged hands pre-restore.d/restored and everything in it to the
// service user, at the modes Put writes (dirMode, fileMode), after
// checkStaged (run here unless it already passed on st), and fsyncs each
// node (syncStaged) before the tree's rename. Each node is opened by descriptor, never followed
// (O_NOFOLLOW, O_NONBLOCK so a FIFO cannot block), judged again on that
// descriptor, and changed through it (fchmod, fchown); an fstat after
// confirms a file still has one link, or its owner and mode are put back
// and the tree refused. pre-restore.d grants nothing to anyone but root, so
// nothing should change the tree during the walk; the checks on the
// descriptor are what keep a change from reaching another file if
// something does.
func (s *FileStore) chownStaged(ctx context.Context, st *mergeStaging) error {
	if !st.checked {
		if err := s.checkStaged(ctx, st); err != nil {
			return err
		}
	}
	return s.walkStaged(ctx, st, true)
}

// walkStaged is the walk of checkStaged (hand unset) and chownStaged.
func (s *FileStore) walkStaged(ctx context.Context, st *mergeStaging, hand bool) error {
	if st.dirF == nil {
		return errNotStaged
	}
	return s.stagedNode(&stagedWalk{ctx: ctx}, int(st.dirF.Fd()), stagedTreeName, ".", stagedTree, 0, 0, hand)
}

// stagedShapeError is the refusal of the staged tree at a path inside it,
// matching ErrCorrupt. Its text says nothing is written; once the floor is
// written, committedShape words it as committed.
type stagedShapeError struct{ where string }

func (e *stagedShapeError) Error() string {
	return fmt.Sprintf("%v: %s: the restored keystore/ holds only what the keystore writes, so nothing is handed to the service user and nothing is written", ErrCorrupt, e.where)
}

// Is matches ErrCorrupt.
func (e *stagedShapeError) Is(target error) bool { return target == ErrCorrupt }

// errStagedShape is the refusal of the staged tree at rel.
func errStagedShape(rel, why string, args ...any) error {
	return &stagedShapeError{where: fmt.Sprintf("%s/%s/%s %s", preRestoreDirName, stagedTreeName, rel, fmt.Sprintf(why, args...))}
}

// committedShape words err, a refusal of the staged tree on a merge whose
// floor is already written, as committed: the floor stays merged, so it
// never says nothing is written. Any other err is wrapped as committed.
func committedShape(err error) error {
	if se := (*stagedShapeError)(nil); errors.As(err, &se) {
		return fmt.Errorf("%w: the merge is written, but the restored keystore/ still staged in pre-restore.d/restored is refused (%w: %s), so it is neither handed to the service user nor moved into place. The floor stays merged and keystore-floor.json.pre-restore stays in place; remove that path from pre-restore.d/restored and run the same merge again", errCommitted, ErrCorrupt, se.where)
	}
	return fmt.Errorf("%w: the merge is written, but the restored keystore/ is still staged in pre-restore.d/restored: %w; run the same merge again", errCommitted, err)
}

// stagedNode judges name in the directory dirfd, a node of kind k at rel
// inside the tree, depth levels below it, hands it over when hand is set,
// and descends into a directory. Each node counts against w's budget
// (stagedNodeLimit), and the walk stops with w.ctx's error.
func (s *FileStore) stagedNode(w *stagedWalk, dirfd int, name, rel string, k stagedKind, maxSize int64, depth int, hand bool) error {
	if err := loopCtx(w.ctx, w.seen); err != nil {
		return err
	}
	if w.seen++; w.seen > stagedNodeLimit {
		return errStagedShape(rel, "is past the %d nodes the walk takes", stagedNodeLimit)
	}
	if depth > maxStagedDepth {
		return errStagedShape(rel, "is more than %d levels deep", maxStagedDepth)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat %s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	// The type is judged before the open: a socket does not open, and a
	// FIFO or device is no file of the keystore's.
	if err := judgeStagedType(rel, &named, k); err != nil {
		return err
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errStagedShape(rel, "does not open without following it: %v", err)
	}
	f := os.NewFile(uintptr(fd), rel)
	defer func() { _ = f.Close() }() // changes are made through fchown and fchmod, and fsynced (syncNode)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return fmt.Errorf("stat %s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino {
		return errStagedShape(rel, "changed while it was opened")
	}
	if err := s.judgeStaged(fd, rel, &opened, k, maxSize); err != nil {
		return err
	}
	if hand {
		if err := s.step("merge chown " + rel); err != nil {
			return err
		}
		if err := s.handStaged(fd, rel, &opened, k); err != nil {
			return err
		}
	}
	// A crash after the tree's rename must not leave a key file truncated
	// or a directory without its names: each node handed over is fsynced
	// before the rename, a file here, a directory once its children are.
	syncNode := func() error {
		if !hand {
			return nil
		}
		if err := syncStaged(f); err != nil {
			return fmt.Errorf("fsync %s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
		}
		return nil
	}
	if k == stagedDropped {
		if err := judgeStagedDropped(f, rel, maxSize); err != nil {
			return err
		}
	}
	if k.file() {
		return syncNode()
	}
	names, err := f.Readdirnames(stagedNameLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("list %s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	if len(names) > stagedNameLimit {
		return errStagedShape(rel, "holds more than %d names", stagedNameLimit)
	}
	sort.Strings(names)
	for _, n := range names {
		childRel := n
		if rel != "." {
			childRel = rel + "/" + n
		}
		ck, cmax, ok := stagedChild(k, n)
		if !ok {
			return errStagedShape(childRel, "is no name the keystore writes there")
		}
		if err := s.stagedNode(w, fd, n, childRel, ck, cmax, depth+1, hand); err != nil {
			return err
		}
	}
	return syncNode()
}

// judgeStagedType refuses a node whose type is not the one its place holds:
// a regular file for a file, a directory for anything else. A symlink is
// neither.
func judgeStagedType(rel string, st *unix.Stat_t, k stagedKind) error {
	typ := st.Mode & unix.S_IFMT
	if k.file() && typ != unix.S_IFREG {
		return errStagedShape(rel, "is not a regular file (type %#o)", typ)
	}
	if !k.file() && typ != unix.S_IFDIR {
		return errStagedShape(rel, "is not a directory (type %#o)", typ)
	}
	return nil
}

// judgeStaged refuses the node fd holds, at rel, of kind k, unless it is in
// the shape the keystore writes: its type (judgeStagedType), one link for a
// file (a second is the same inode as a file elsewhere, and handing it over
// would hand that file over), no setuid, setgid or sticky bit, no file flag,
// no extended ACL, a file at most maxSize bytes, and owned by the service
// user or by the unknown owner an ownership-ignoring volume reports, the
// persisted pre-frame refusal counts included (a backup copied off such a
// volume carries them at uid 99 like every other file). A root-owned node
// is refused: a ditto of the backup keeps the service user's owner, so a
// root file there is a copied link to one of root's.
func (s *FileStore) judgeStaged(fd int, rel string, st *unix.Stat_t, k stagedKind, maxSize int64) error {
	if err := judgeStagedType(rel, st, k); err != nil {
		return err
	}
	switch {
	case k.file() && st.Nlink != 1:
		return errStagedShape(rel, "has %d links", st.Nlink)
	case st.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0:
		return errStagedShape(rel, "has the setuid, setgid or sticky bit (mode %#o)", st.Mode&0o7777)
	case statFlags(st) != 0:
		return errStagedShape(rel, "has file flags %#x", statFlags(st))
	case k.file() && st.Size > maxSize:
		return errStagedShape(rel, "is %d bytes, over the %d its name allows", st.Size, maxSize)
	case k == stagedDropped && uint32(st.Mode)&0o777 != uint32(fileMode):
		return errStagedShape(rel, "is mode %#o, not the %#o the server writes it at", st.Mode&0o777, fileMode)
	case st.Uid != s.uid && st.Uid != unknownUID:
		return errStagedShape(rel, "is owned by uid %d, neither the service user (%d) nor the unknown owner (%d)", st.Uid, s.uid, unknownUID)
	}
	acl, err := hasExtendedACL(fd)
	if err != nil {
		return fmt.Errorf("%s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	if acl {
		return errStagedShape(rel, "has an extended ACL")
	}
	return nil
}

// judgeStagedDropped reads the persisted pre-frame refusal counts through
// f, at most maxSize bytes, and refuses a
// copy that does not parse strictly (parsePreFrameDropped), as any other
// malformed staged content is refused.
func judgeStagedDropped(f *os.File, rel string, maxSize int64) error {
	b, err := io.ReadAll(io.LimitReader(io.NewSectionReader(f, 0, maxSize+1), maxSize+1))
	if err != nil {
		return fmt.Errorf("read %s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	if int64(len(b)) > maxSize {
		return errStagedShape(rel, "is over the %d bytes its name allows", maxSize)
	}
	if _, err := parsePreFrameDropped(b); err != nil {
		return errStagedShape(rel, "does not parse: %v", err)
	}
	return nil
}

// handStaged sets the node fd holds to the mode Put writes and hands it to
// the service user, through the descriptor, then confirms a file still has
// one link: a link made between the checks and the fchown would share the
// handover, so its owner and mode are put back and the tree refused.
func (s *FileStore) handStaged(fd int, rel string, before *unix.Stat_t, k stagedKind) error {
	mode := uint32(fileMode)
	if !k.file() {
		mode = uint32(dirMode)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return fmt.Errorf("set the mode of %s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	if err := unix.Fchown(fd, int(s.uid), int(s.gid)); err != nil {
		return fmt.Errorf("hand %s/%s/%s to the service user: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return fmt.Errorf("stat %s/%s/%s: %w", preRestoreDirName, stagedTreeName, rel, err)
	}
	if k.file() && after.Nlink != 1 {
		// Put back what the other name had; a failure leaves the refusal.
		_ = unix.Fchown(fd, int(before.Uid), int(before.Gid))
		_ = unix.Fchmod(fd, uint32(before.Mode&0o7777))
		return errStagedShape(rel, "gained a link (%d) while it was handed over", after.Nlink)
	}
	return nil
}

// refusedStaged is each entry name, sorted, in pre-restore.d/restored
// whose staged generation the floor fl refuses: one fl buries and does not
// hold live, or one of dropped, the burials the write drops (a copy of
// which would otherwise be accepted again). An entry directory without a
// readable generation file is left.
func (s *FileStore) refusedStaged(st *mergeStaging, fl floor, dropped []pruned) ([]string, error) {
	tree, err := st.tree(stagedTreeName)
	if err != nil || tree == nil {
		return nil, err
	}
	defer func() { _ = tree.Close() }() // read-only
	d, err := tree.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(stagedNameLimit + 1)
	_ = d.Close() // read-only
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var out []string
	for _, name := range names {
		if checkName(name) != nil {
			continue
		}
		fi, err := tree.Lstat(name)
		if err != nil || !fi.IsDir() {
			continue
		}
		dir, err := tree.OpenRoot(name)
		if err != nil {
			return nil, err
		}
		gen, gerr := readGeneration(dir)
		_ = dir.Close() // read-only
		if gerr != nil {
			continue
		}
		g := hex.EncodeToString(gen[:])
		e := fl[name]
		refused := e.buries(g) && !(e.live() && e.Generation == g)
		for _, p := range dropped {
			if p.name == name && p.generation == g && !(e.live() && e.Generation == g) {
				refused = true
			}
		}
		if refused {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// removeStaged removes the directory of each of names from
// pre-restore.d/restored, through the tree opened by descriptor inside the
// root-only pre-restore.d (st.tree): os.Root's RemoveAll never follows a
// symlink, removing one itself, and never leaves the tree. A name already
// absent is no error. It returns the names it removed, those removed
// before a failure included.
func (s *FileStore) removeStaged(st *mergeStaging, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	tree, err := st.tree(stagedTreeName)
	if err != nil {
		return nil, err
	}
	if tree == nil {
		return nil, errNotStaged
	}
	defer func() { _ = tree.Close() }() // removals are synced below
	var removed []string
	for _, name := range names {
		if err := checkName(name); err != nil {
			return removed, err
		}
		if err := s.step("merge remove staged " + name); err != nil {
			return removed, removedErr(removed, err)
		}
		if err := tree.RemoveAll(name); err != nil {
			return removed, removedErr(removed, fmt.Errorf("remove the staged directory of %s, which the merged floor refuses, from %s/%s: %w", name, preRestoreDirName, stagedTreeName, err))
		}
		removed = append(removed, name)
	}
	if err := syncDir(tree); err != nil {
		return removed, removedErr(removed, err)
	}
	return removed, nil
}

// removedErr is err, a failure of removeStaged once it removed the staged
// directories of removed: the floor is not written, and, when any was
// removed, it names them rather than saying nothing is written.
func removedErr(removed []string, err error) error {
	if len(removed) == 0 {
		return fmt.Errorf("%w; nothing is written, run the merge again", err)
	}
	return fmt.Errorf("%w; the floor is not written, but the staged directories of %s, which the merged floor refuses, were removed from %s/%s; run the merge again", err, strings.Join(removed, ", "), preRestoreDirName, stagedTreeName)
}

// errMovedNotSynced is a directory fsync that failed after the staged
// tree's rename: the tree is in place, but the rename may not survive a
// crash.
var errMovedNotSynced = errors.New("a directory fsync after the restored keystore/'s rename failed")

// moveStaged renames pre-restore.d/restored to the store's Dir, through the
// two directory descriptors, refusing when anything, a symlink included, is
// at Dir (renameExcl). A failed fsync of either directory after the rename
// is returned (errMovedNotSynced): the rename stands, and the merge is
// committed.
func (s *FileStore) moveStaged(st *mergeStaging) error {
	if err := s.step("merge tree rename"); err != nil {
		return err
	}
	if err := renameExcl(int(st.dirF.Fd()), stagedTreeName, int(st.parent.Fd()), st.target); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return errStagedTargetExists(s.dir)
		}
		return fmt.Errorf("move %s/%s to %s: %w", preRestoreDirName, stagedTreeName, s.dir, err)
	}
	// The tree in place now holds the staged scopes, each under the same
	// scope.key as before it. The restore recipe stops the server first,
	// so its restart holds no figure: that is the protection. This covers
	// only a figure this process holds, should it be the one merging.
	s.usage.forgetAll()
	for _, d := range []*os.File{st.parent, st.dirF} {
		if err := syncMovedDir(d); err != nil {
			return fmt.Errorf("%w: fsync %s: %w", errMovedNotSynced, d.Name(), err)
		}
	}
	return nil
}

// syncMovedDir fsyncs a directory after the staged tree's rename. It is a
// variable so a test can fail it.
var syncMovedDir = func(d *os.File) error { return d.Sync() }
