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

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	// ufNoUnlink is UF_NOUNLINK (`uunlnk`): 0x10 in the BSD header, commented
	// out in Darwin's, so x/sys has no name for it.
	ufNoUnlink = 0x10
	// userLockingFlags are the flags a file's owner can set that keep it from
	// being changed, appended to only, or removed: `uchg`, `uappnd`, `uunlnk`.
	userLockingFlags = unix.UF_IMMUTABLE | unix.UF_APPEND | ufNoUnlink
	// systemLockingFlags are the superuser's flags of the same kind. They are
	// never cleared: root cannot clear them outside single-user mode.
	systemLockingFlags = unix.SF_IMMUTABLE | unix.SF_APPEND | unix.SF_NOUNLINK
)

// errCrossesMount reports a directory in the tree that is on another volume.
var errCrossesMount = errors.New("it is on another volume; unmount it and run the command again")

// errFlaggedHardLink reports a file whose locking flag is shared with another
// name, which may be outside the tree, so the flag is not the removal's to clear.
var errFlaggedHardLink = errors.New("hard-linked file with a locking flag; its other names share the flag, so clear it by hand, remove this name, set it again if they need it, and run the command again")

// removeTreeFlagged deletes path and everything under it, for the staging and
// swap leftovers os.RemoveAll wedged on: a file or directory carrying a user
// locking flag answers EPERM until the flag is cleared, and a walk holding one
// descriptor per level answers EMFILE once a tree is deeper than the process's
// limit. Either one failed the uninstall on every re-run.
//
// The rules of the walk:
//
//   - No symlink is followed. Every step is relative to a directory descriptor
//     and opened with O_NOFOLLOW or O_SYMLINK, and a symlink is unlinked as
//     itself. Ancestors of path are resolved as os.RemoveAll resolves them: the
//     callers judge path before they get here.
//   - No mount point is crossed. A directory whose device differs from that of
//     path's parent is left alone, with everything in it, and the removal
//     reports errCrossesMount; path itself being a mount point counts.
//   - Flags are cleared only after EPERM, on a descriptor checked to be the
//     entry just looked at, and only inside the tree: the directory holding
//     path keeps its flags, so an EPERM from it stays an error. System flags
//     are left, and the error names them. A device or a socket is not opened
//     to clear its flags, because opening a device is an action of its own; it
//     stays an EPERM if it carries one.
//   - A hard link shares its flags with every other name of the file, which may
//     be outside the tree, and a kill between a clear and a restore would lose
//     the flag there. So a flagged file with more than one link is never cleared:
//     it stays where it is and the removal reports errFlaggedHardLink, on every
//     re-run, until the operator deals with it.
//   - At the descriptor limit, the directory that could not be opened is renamed
//     up to the tree's root and removed from there once the walk has unwound
//     and released its descriptors, so no ".." is trusted on the way back.
//     Directly under the root there is nothing to gain, so EMFILE is an error.
//   - An entry that cannot be removed does not stop the others. The first error
//     is returned, and a re-run starts over.
//
// A tree not owned by root. The owner of path is checked by the callers
// (stagingTrustVerdict): a top-level directory not owned by root never reaches
// this function, is left in place, and the command reports it. Below the top
// nothing is checked: an entry owned by another user inside a trusted tree is
// removed like any other, its flags cleared, because root can do both and the
// tree is what is being deleted. What such an owner can do during the walk is
// bounded by the rules above: it can swap an entry for a symlink, which is
// unlinked, mount a volume on its directory, which is refused, or link in a
// flagged file from elsewhere, which is refused with its flags untouched. That
// refusal fails the sweep, as a system flag does: such an owner can keep the
// tree from going, and nothing more. It can also move its directory
// out of the tree mid-walk, which removes that directory's contents at its new
// place; those are entries that user already controlled.
func removeTreeFlagged(path string) error {
	return newTreeRemover().remove(path)
}

// treeRemover is one removal's state. It is not safe for concurrent use.
type treeRemover struct {
	// fstat is unix.Fstat, swapped by the test that models a mount point.
	fstat func(fd int, st *unix.Stat_t) error
	// dev is the device of path's parent: the volume the walk stays on.
	dev int32
	// rootFD is the tree root's descriptor, where the limit fallback moves
	// directories to; -1 until it is open.
	rootFD int
	// reserve is a spare descriptor, closed to make room to clear the flags of
	// an entry met at the limit; -1 when it is not held.
	reserve int
	// moved names the directories the fallback put directly under the root.
	moved []string
	// movedCount numbers those names, and never repeats in one removal.
	movedCount int
	// firstErr is the first failure.
	firstErr error
}

func newTreeRemover() *treeRemover {
	return &treeRemover{fstat: unix.Fstat, rootFD: -1, reserve: -1}
}

// note keeps the first error.
func (r *treeRemover) note(err error) {
	if err != nil && r.firstErr == nil {
		r.firstErr = err
	}
}

// remove deletes path. A path that does not exist is success, as in
// os.RemoveAll.
func (r *treeRemover) remove(path string) error {
	clean := filepath.Clean(path)
	name := filepath.Base(clean)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return fmt.Errorf("refusing to remove %q: %w", path, unix.EINVAL)
	}
	parentFD, err := unix.Open(filepath.Dir(clean), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("open the parent directory: %w", err)
	}
	defer closeFD(parentFD)
	var parent unix.Stat_t
	if err := r.fstat(parentFD, &parent); err != nil {
		return fmt.Errorf("stat the parent directory: %w", err)
	}
	r.dev = parent.Dev
	r.removeEntry(parentFD, name, false)
	if r.reserve >= 0 {
		closeFD(r.reserve)
	}
	return r.firstErr
}

// removeEntry removes name in parentFD, whatever it is. parentInTree says
// whether parentFD is part of the tree, and so whether its flags may be cleared.
func (r *treeRemover) removeEntry(parentFD int, name string, parentInTree bool) {
	var st unix.Stat_t
	switch err := unix.Fstatat(parentFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		r.note(fmt.Errorf("lstat %s: %w", name, err))
	case st.Mode&unix.S_IFMT == unix.S_IFDIR:
		r.removeDir(parentFD, name, &st, parentInTree)
	default:
		r.note(r.removeNonDir(parentFD, name, &st, parentInTree))
	}
}

// removeNonDir unlinks a file, symlink or anything else that is not a directory.
func (r *treeRemover) removeNonDir(parentFD int, name string, st *unix.Stat_t, parentInTree bool) error {
	err := ignoreGone(unix.Unlinkat(parentFD, name, 0))
	if !errors.Is(err, unix.EPERM) {
		return wrapRemove(name, err)
	}
	if isFlaggedHardLink(st) {
		return wrapRemove(name, errFlaggedHardLink)
	}
	if parentInTree {
		if err := r.clearFlagsOf(parentFD); err != nil {
			return fmt.Errorf("clear the flags of the directory holding %s: %w", name, err)
		}
	}
	if st.Flags&userLockingFlags == 0 || !clearableByOpen(st.Mode) {
		return flagError(name, st, ignoreGone(unix.Unlinkat(parentFD, name, 0)))
	}
	return r.withEntry(parentFD, name, st, unix.O_SYMLINK, func(fd int) error {
		// Asked again on the descriptor: a link made since the look above is a
		// link all the same. One made after this check is the window left.
		var now unix.Stat_t
		if err := r.fstat(fd, &now); err != nil {
			return fmt.Errorf("stat %s: %w", name, err)
		}
		if isFlaggedHardLink(&now) {
			return wrapRemove(name, errFlaggedHardLink)
		}
		if err := unix.Fchflags(fd, int(now.Flags&^userLockingFlags)); err != nil {
			return fmt.Errorf("clear the flags of %s: %w", name, err)
		}
		return flagError(name, &now, ignoreGone(unix.Unlinkat(parentFD, name, 0)))
	})
}

// isFlaggedHardLink reports a file with a user locking flag and another name.
func isFlaggedHardLink(st *unix.Stat_t) bool {
	return st.Flags&userLockingFlags != 0 && st.Nlink > 1
}

// clearableByOpen reports whether a descriptor may be opened on an entry of this
// mode just to change its flags.
func clearableByOpen(mode uint16) bool {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFLNK, unix.S_IFIFO:
		return true
	}
	return false
}

// removeDir removes a directory and everything in it.
func (r *treeRemover) removeDir(parentFD int, name string, st *unix.Stat_t, parentInTree bool) {
	atTop := r.rootFD < 0
	fd, names, err := r.openAndList(parentFD, name)
	switch {
	case err == nil:
	case errors.Is(err, unix.ENOENT):
		return
	case isDescriptorLimit(err) && !atTop && parentFD != r.rootFD:
		r.note(r.moveToRoot(parentFD, name, st))
		return
	default:
		r.note(fmt.Errorf("open %s: %w", name, err))
		return
	}
	defer closeFD(fd)
	if atTop {
		r.rootFD = fd
		reserve, err := unix.Dup(fd)
		if err != nil {
			r.note(fmt.Errorf("reserve a descriptor: %w", err))
			return
		}
		unix.CloseOnExec(reserve)
		r.reserve = reserve
	}
	for _, child := range names {
		r.removeEntry(fd, child, true)
	}
	if atTop {
		for len(r.moved) > 0 {
			next := r.moved[len(r.moved)-1]
			r.moved = r.moved[:len(r.moved)-1]
			r.removeEntry(fd, next, true)
		}
	}
	err = ignoreGone(unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR))
	if errors.Is(err, unix.EPERM) {
		if err := r.clearFlagsOf(fd); err != nil {
			r.note(fmt.Errorf("clear the flags of %s: %w", name, err))
			return
		}
		if parentInTree {
			if err := r.clearFlagsOf(parentFD); err != nil {
				r.note(fmt.Errorf("clear the flags of the directory holding %s: %w", name, err))
				return
			}
		}
		err = ignoreGone(unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR))
	}
	if errors.Is(err, unix.ENOTEMPTY) && r.firstErr != nil {
		// What failed earlier is still in here, and is the error to report.
		return
	}
	r.note(flagError(name, st, err))
}

// openAndList opens the directory name in parentFD, refuses it if it is on
// another volume, and reads its names. Only the returned descriptor stays open:
// reading a directory takes further descriptors, and they are released before
// the walk goes deeper, so a level holds one.
func (r *treeRemover) openAndList(parentFD int, name string) (int, []string, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	var st unix.Stat_t
	if err := r.fstat(fd, &st); err != nil {
		closeFD(fd)
		return -1, nil, err
	}
	if st.Dev != r.dev {
		closeFD(fd)
		return -1, nil, errCrossesMount
	}
	listFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		closeFD(fd)
		return -1, nil, err
	}
	list := os.NewFile(uintptr(listFD), name)
	names, err := list.Readdirnames(-1)
	_ = list.Close() // read-only: nothing a failed close could lose
	if err != nil {
		closeFD(fd)
		return -1, nil, err
	}
	return fd, names, nil
}

// moveToRoot is the fallback at the descriptor limit: it renames the directory
// directly under the tree's root, for removal once the walk has unwound.
// RENAME_EXCL keeps it from landing on an entry that has the name already.
func (r *treeRemover) moveToRoot(parentFD int, name string, st *unix.Stat_t) error {
	cleared := false
	for {
		r.movedCount++
		target := fmt.Sprintf(".k3sm-sweep-%d", r.movedCount)
		err := unix.RenameatxNp(parentFD, name, r.rootFD, target, unix.RENAME_EXCL)
		switch {
		case err == nil:
			r.moved = append(r.moved, target)
			return nil
		case errors.Is(err, unix.ENOENT):
			return nil
		case errors.Is(err, unix.EEXIST):
			continue
		case !errors.Is(err, unix.EPERM) || cleared:
			return fmt.Errorf("move %s out of the way at the descriptor limit: %w", name, err)
		}
		cleared = true
		if err := r.clearMoveFlags(parentFD, name, st); err != nil {
			return err
		}
	}
}

// clearMoveFlags clears the flags that can refuse a rename: those of the
// directory, of the one it is in and of the root it moves to.
func (r *treeRemover) clearMoveFlags(parentFD int, name string, st *unix.Stat_t) error {
	for _, fd := range []int{parentFD, r.rootFD} {
		if err := r.clearFlagsOf(fd); err != nil {
			return fmt.Errorf("clear the flags of a directory to move %s: %w", name, err)
		}
	}
	if st.Flags&userLockingFlags == 0 {
		return nil
	}
	return r.withEntry(parentFD, name, st, unix.O_DIRECTORY|unix.O_NOFOLLOW, func(fd int) error {
		if err := unix.Fchflags(fd, int(st.Flags&^userLockingFlags)); err != nil {
			return fmt.Errorf("clear the flags of %s: %w", name, err)
		}
		return nil
	})
}

// withEntry runs fn on a descriptor for name in parentFD, opened with extra
// flags, after checking it is still the entry st describes and on the tree's
// volume. At the descriptor limit it spends the reserve to make room.
func (r *treeRemover) withEntry(parentFD int, name string, st *unix.Stat_t, extra int, fn func(fd int) error) error {
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | extra
	fd, err := unix.Openat(parentFD, name, flags, 0)
	if isDescriptorLimit(err) && r.reserve >= 0 {
		closeFD(r.reserve)
		r.reserve = -1
		fd, err = unix.Openat(parentFD, name, flags, 0)
	}
	if err != nil {
		return fmt.Errorf("open %s to clear its flags: %w", name, err)
	}
	defer func() {
		closeFD(fd)
		if r.reserve < 0 && r.rootFD >= 0 {
			if reserve, err := unix.Dup(r.rootFD); err == nil {
				unix.CloseOnExec(reserve)
				r.reserve = reserve
			}
		}
	}()
	var now unix.Stat_t
	if err := r.fstat(fd, &now); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if now.Dev != r.dev {
		return fmt.Errorf("%s: %w", name, errCrossesMount)
	}
	if now.Ino != st.Ino || now.Dev != st.Dev {
		return fmt.Errorf("%s changed while it was being removed: %w", name, unix.EPERM)
	}
	return fn(fd)
}

// clearFlagsOf clears the user locking flags of an open directory in the tree.
func (r *treeRemover) clearFlagsOf(fd int) error {
	var st unix.Stat_t
	if err := r.fstat(fd, &st); err != nil {
		return err
	}
	if st.Flags&userLockingFlags == 0 {
		return nil
	}
	return unix.Fchflags(fd, int(st.Flags&^userLockingFlags))
}

// flagError wraps a failed removal, naming a system flag when it carries one,
// because then nothing short of single-user mode clears it.
func flagError(name string, st *unix.Stat_t, err error) error {
	if errors.Is(err, unix.EPERM) && st.Flags&systemLockingFlags != 0 {
		return fmt.Errorf("remove %s: it carries a system flag (flags %#x) only single-user mode can clear: %w", name, st.Flags, err)
	}
	return wrapRemove(name, err)
}

func wrapRemove(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("remove %s: %w", name, err)
}

func ignoreGone(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func isDescriptorLimit(err error) bool {
	return errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE)
}

func closeFD(fd int) {
	_ = unix.Close(fd) // a directory or read-only descriptor: nothing to lose
}
