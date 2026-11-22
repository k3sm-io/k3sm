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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// preRestoreDirName is the root-only directory in the data root the
	// restore recipe stages both keystore trees in.
	preRestoreDirName = "pre-restore.d"
	// stagedTreeName is the backup's keystore/, as the recipe's root ditto
	// copied it into pre-restore.d; the merge moves it into place.
	stagedTreeName = "restored"
	// asideTreeName is the live keystore/ the recipe moved aside into
	// pre-restore.d.
	asideTreeName = "keystore"
	// maxStagedDepth bounds how deep chownStaged descends: keystore/<name>/
	// <file> is two levels, so anything deeper is not a keystore.
	maxStagedDepth = 4
)

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
	// name; targetExists is set when anything, a symlink included, is there.
	parent       *os.File
	target       string
	targetExists bool
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
// granting nothing to group or others. The recipe's ditto keeps the backup's
// owner inside it, so the directory's own mode is what keeps the service
// user out of both trees, and a mode that let it search pre-restore.d would
// let it write into the staged tree. An absent pre-restore.d is no staging.
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
		st.targetExists = true
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
// holds anything.
func errStagedTargetExists(dir string) error {
	return fmt.Errorf("%w: %s exists, a symlink counted, while the restored keystore/ is staged in pre-restore.d/restored: the restore recipe leaves it absent, and the merge moves the staged tree there itself, never through or over what is there. Nothing is written. Move %s aside (sudo mv %s %s.unexpected) and run the merge again", errFloorUntrusted, dir, dir, dir, dir)
}

// chownStaged hands pre-restore.d/restored and everything in it to the
// service user through descriptors: fchownat with AT_SYMLINK_NOFOLLOW, so a
// symlink is changed itself and never followed, descending only into
// directories, at most maxStagedDepth deep and maxDirNames names in each.
// pre-restore.d grants nothing to anyone but root, so nothing changes the
// tree during the walk; a recursive chown in the recipe is never needed.
func (s *FileStore) chownStaged(st *mergeStaging) error {
	if err := s.chownAt(st.dirF, stagedTreeName); err != nil {
		return err
	}
	tree, err := st.tree(stagedTreeName)
	if err != nil {
		return err
	}
	if tree == nil {
		return errNotStaged
	}
	defer func() { _ = tree.Close() }() // read-only handle
	return s.chownTree(tree, 1)
}

// chownAt hands name in dir to the service user, unless it already is.
func (s *FileStore) chownAt(dir *os.File, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Uid == s.uid && st.Gid == s.gid {
		return nil
	}
	// A file with a second link is the same inode as a file elsewhere: a
	// ditto of the backup makes none (the keystore never links), so one
	// here was planted, and handing it over would hand over the other.
	if st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Nlink > 1 {
		return fmt.Errorf("%w: %s/%s holds %s with %d links: nothing is handed to the service user through it", ErrCorrupt, preRestoreDirName, stagedTreeName, name, st.Nlink)
	}
	if err := unix.Fchownat(int(dir.Fd()), name, int(s.uid), int(s.gid), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("hand %s to the service user: %w", name, err)
	}
	return nil
}

// chownTree is chownStaged's walk of root, depth levels below restored.
func (s *FileStore) chownTree(root *os.Root, depth int) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }() // read-only
	names, err := d.Readdirnames(maxDirNames + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) > maxDirNames {
		return fmt.Errorf("%w: a directory in %s/%s holds more than %d names", ErrCorrupt, preRestoreDirName, stagedTreeName, maxDirNames)
	}
	for _, name := range names {
		if err := s.chownAt(d, name); err != nil {
			return err
		}
		fi, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			continue
		}
		if depth >= maxStagedDepth {
			return fmt.Errorf("%w: %s/%s is more than %d levels deep", ErrCorrupt, preRestoreDirName, stagedTreeName, maxStagedDepth)
		}
		sub, err := root.OpenRoot(name)
		if err != nil {
			return err
		}
		if opened, serr := sub.Stat("."); serr != nil || !os.SameFile(fi, opened) {
			_ = sub.Close() // abandoned
			return fmt.Errorf("%w: %s changed during the walk", ErrCorrupt, name)
		}
		err = s.chownTree(sub, depth+1)
		_ = sub.Close() // read-only handle
		if err != nil {
			return err
		}
	}
	return nil
}

// removeStaged removes the directory of each of names from
// pre-restore.d/restored, through the tree opened by descriptor inside the
// root-only pre-restore.d (st.tree): os.Root's RemoveAll never follows a
// symlink, removing one itself, and never leaves the tree. A name already
// absent is no error.
func (s *FileStore) removeStaged(st *mergeStaging, names []string) error {
	if len(names) == 0 {
		return nil
	}
	tree, err := st.tree(stagedTreeName)
	if err != nil {
		return err
	}
	if tree == nil {
		return errNotStaged
	}
	defer func() { _ = tree.Close() }() // removals are synced below
	for _, name := range names {
		if err := checkName(name); err != nil {
			return err
		}
		if err := tree.RemoveAll(name); err != nil {
			return fmt.Errorf("remove the staged directory of %s, deleted under the guard, from %s/%s: %w; nothing is written, run the merge again", name, preRestoreDirName, stagedTreeName, err)
		}
	}
	return syncDir(tree)
}

// moveStaged renames pre-restore.d/restored to the store's Dir, through the
// two directory descriptors, refusing when anything, a symlink included, is
// at Dir (renameExcl). Once the rename is made it stands: a failed fsync of
// either directory after it is logged at Warn, not returned.
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
	for _, d := range []*os.File{st.parent, st.dirF} {
		if err := d.Sync(); err != nil {
			slog.Warn("keystore floor: the restored keystore/ is moved into place, but a directory fsync after the rename failed; the rename stands", "dir", d.Name(), "err", err)
		}
	}
	return nil
}
