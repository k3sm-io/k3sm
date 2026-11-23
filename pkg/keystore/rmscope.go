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
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// errScopeHasDeliveries refuses an rm-scope of a scope whose delivery
// record names any delivery: removing it would leave each delivered Secret
// with no record to find it by, and rm-scope's revocation of those Secrets
// (docs/design/keystore.md § "rm-scope revokes first") is not built yet.
var errScopeHasDeliveries = errors.New("the scope's delivery record names deliveries, and rm-scope does not yet delete their Secrets: withdraw each delivery first; nothing was changed")

// RemoveScope removes uid's user scope (rm-scope), as root: under the
// floor lock and then the exclusive store lock (at most 30 s;
// lockMaintenance) it opens the scope's key under W without the
// GeneratedUID check and reads its delivery record, refusing while the
// record names any delivery, then lists the scope key's identity in the
// removed-scopes record (keystore-removed-scopes.json, through the judged
// data-root descriptor) with the user-scope floor's byte size at that
// moment, then removes .user/<uid>/ by descriptor (removeScopeTree),
// walking from the keystore root it opened and judged first, never from
// the path again. A scope directory copied back after it is refused at
// every open, since its scope.key's identity is listed, and the next floor
// --rebuild drops the uid's floor lines written before the recorded size,
// and keeps the ones after it (a re-minted scope's). A full record does
// not stop the removal: recorded reports false, the scope is removed
// unlisted, and floor --rebuild keeps its floor keys (fail closed for a
// copy-back). A record that does not read refuses, changing nothing.
//
// A rerun finishes an rm-scope that stopped part-way: a scope whose key is
// already listed is removed without reading its delivery record again, and
// a scope directory left without its scope.key is removed as it stands.
func (s *FileStore) RemoveScope(ctx context.Context, uid uint32) (recorded bool, err error) {
	if err := s.checkConfig(); err != nil {
		return false, err
	}
	if err := s.eligibleUID(uid); err != nil {
		return false, err
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }() // removals are fsynced in their directories
	fl, unlock, err := s.lockMaintenance(ctx, root)
	if err != nil {
		return false, err
	}
	defer fl.unlock()
	defer unlock()
	k, err := s.loadMasterLocked()
	if err != nil {
		return false, err
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return false, fmt.Errorf("%w; nothing was changed", err)
	}
	defer func() { _ = unix.Close(dfd) }() // the record's rename is fsynced in it
	removed, err := s.readRemovedScopes(dfd)
	if err != nil {
		return false, fmt.Errorf("%w; nothing was changed", err)
	}
	name := strconv.FormatUint(uint64(uid), 10)
	u := &UserScope{s: s, uid: uid, scope: userScopeOf(uid), allowRemoved: true}
	o, err := u.openScopeForRevoke(root, k)
	if errors.Is(err, errNoScopeKey) && scopeDirPresent(root, name) {
		// An earlier rm-scope removed scope.key, then stopped: no open
		// serves the directory, and there is no key to list.
		if err := removeScopeTree(root, name, s.uid); err != nil {
			return false, fmt.Errorf("%w; the directory keystore/%s/%s has no scope.key and is partly or wholly present: rerun sudo k3sm keys rm-scope %s --yes to finish removing it", err, userScopesName, name, u.scope)
		}
		return removed.listed(uid), nil
	}
	if err != nil {
		return false, fmt.Errorf("open the scope %s: %w; nothing was changed", u.scope, err)
	}
	id := o.id
	recorded = removed.has(uid, id)
	_, ds, derr := u.readDeliveriesUnfloored(o)
	_, eerr := o.dir.Lstat(scopeEntriesName)
	o.close()
	switch {
	case recorded:
		// An earlier rm-scope listed the key, then stopped part-way.
	case derr == nil && len(ds) > 0:
		return false, fmt.Errorf("%s: %w", u.scope, errScopeHasDeliveries)
	case derr == nil:
	case errors.Is(derr, ErrScopeAbsent) && errors.Is(eerr, os.ErrNotExist):
		// An earlier rm-scope, unlisted (a full record), removed entries/
		// and the record, then stopped.
	default:
		return false, fmt.Errorf("read the delivery record of %s: %w; nothing was changed", u.scope, derr)
	}
	if !recorded {
		size, err := s.floorSize(dfd)
		if err != nil {
			return false, fmt.Errorf("read the size of the user-scope floor %s: %w; nothing was changed", userFloorLogName, err)
		}
		if removed.add(uid, id, size) {
			if err := writeRemovedScopes(dfd, removed); err != nil {
				return false, fmt.Errorf("record the removed scope %s in %s: %w; the record may or may not list it, and the scope directory is untouched: rerun sudo k3sm keys rm-scope %s --yes", u.scope, removedScopesName, err, u.scope)
			}
			recorded = true
		}
	}
	if err := removeScopeTree(root, name, s.uid); err != nil {
		state := "is listed as removed in " + removedScopesName + ", so no open serves it"
		if !recorded {
			state = "is not listed in " + removedScopesName + ", which is full"
		}
		return recorded, fmt.Errorf("%w; the scope %s %s, and its directory keystore/%s/%s is partly or wholly present: rerun sudo k3sm keys rm-scope %s --yes to finish removing it", err, u.scope, state, userScopesName, name, u.scope)
	}
	return recorded, nil
}

// floorSize is the user-scope floor's byte size, through the judged data
// root dfd: 0 when there is no floor yet.
func (s *FileStore) floorSize(dfd int) (int64, error) {
	lfd, err := s.openLogsDir(dfd)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(lfd) }() // read-only directory descriptor
	var st unix.Stat_t
	err = s.statLog(lfd, userFloorLogName, &st)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return st.Size, nil
}

// scopeDirPresent reports whether keystore/.user/<name> names anything.
func scopeDirPresent(root *os.Root, name string) bool {
	_, err := root.Lstat(userScopesName + "/" + name)
	return err == nil
}

const (
	// maxRemovePasses bounds removeScopeTree's passes over a tree in which
	// names keep appearing.
	maxRemovePasses = 3
	// maxScopeTreeDepth bounds the descent below the scope directory, one
	// descriptor per level: the layout puts files two levels down.
	maxScopeTreeDepth = 32
)

// errScopeTreeBusy is a scope tree in which new names kept appearing over
// maxRemovePasses removal passes.
var errScopeTreeBusy = fmt.Errorf("new names kept appearing in the scope directory over %d removal passes: a process running as the service user is still writing there; stop the server (sudo k3sm stop) and any such process", maxRemovePasses)

// errScopeFlagLinked is a file in the scope tree carrying a user flag
// whose other links are not all in the tree: its flag is shared with a
// name outside the scope, so rm-scope does not clear it.
var errScopeFlagLinked = errors.New("a file in the scope directory carries a user flag (uchg, uappnd or uunlnk) and has a link outside the scope directory, so rm-scope does not clear the flag; clear it on the other link (chflags nouchg), then rerun")

// errScopeFlagBudget is a scope tree whose user flags would take more
// opens than rm-scope makes.
var errScopeFlagBudget = fmt.Errorf("the scope directory holds more flagged files than rm-scope opens to clear their user flags (%d)", maxFlagOpens)

// rmWalk is one removeScopeTree: the service user's uid, whose own files'
// user flags it clears, how many files it has opened to do so, and, per
// pass, how many names of each flagged file with more than one link it has
// met in the tree.
type rmWalk struct {
	svc   uint32
	opens int
	seen  map[[2]uint64]int
	// linked is set when a flagged file's links were not all met in a
	// pass: it may have one outside the tree.
	linked bool
}

// removeScopeTree removes keystore/.user/<uid>/ by descriptor, starting
// from keystore, the already-judged keystore root, so a directory swapped
// in at the keystore's path since it was judged is never walked. Each
// directory is opened relative to its parent with O_NOFOLLOW|O_DIRECTORY,
// re-checked with fstat against the parent's fstatat of the name
// (SameFile), emptied, and removed with unlinkat(AT_REMOVEDIR); every other
// name, whatever its type (a regular file, FIFO, symlink, device or
// socket), is removed with unlinkat, which never follows. scope.key goes
// last, once nothing else is left beside it. A name that vanishes under
// the walk is skipped. When names keep appearing, it makes at most
// maxRemovePasses passes and then fails (errScopeTreeBusy).
//
// The service user (svc) can set a user flag (uchg, uappnd, uunlnk) on its
// own files, which makes root's unlinkat fail with EPERM. So before a name
// is removed, a user flag on it is cleared (clearScopeFlags): on a
// descriptor opened O_NOFOLLOW (O_SYMLINK for a symlink), never by path,
// re-checked as the name, and only when the service user owns it. A
// non-directory with more than one link is cleared only when it is a
// regular file and all its links were met in the tree in the same pass;
// its earlier names are then removed in the next pass.
func removeScopeTree(keystore *os.Root, uid string, svc uint32) error {
	kd, err := keystore.Open(".")
	if err != nil {
		return fmt.Errorf("open the keystore directory: %w", err)
	}
	defer func() { _ = kd.Close() }() // read-only
	ufd, ust, err := openDirAt(int(kd.Fd()), userScopesName)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(ufd) }() // fsynced below
	w := &rmWalk{svc: svc}
	if err := w.clearHeld(ufd, &ust); err != nil {
		return err
	}
	for range maxRemovePasses {
		w.seen, w.linked = map[[2]uint64]int{}, false
		dfd, dst, err := openDirAt(ufd, uid)
		if errors.Is(err, unix.ENOENT) {
			return unix.Fsync(ufd)
		}
		if err != nil {
			return err
		}
		err = w.clearHeld(dfd, &dst)
		if err == nil {
			err = w.emptyScopeDir(dfd)
		}
		_ = unix.Close(dfd) // fsynced in emptyScopeDir
		if err != nil {
			return err
		}
		err = unix.Unlinkat(ufd, uid, unix.AT_REMOVEDIR)
		switch {
		case err == nil, errors.Is(err, unix.ENOENT):
			return unix.Fsync(ufd)
		case !errors.Is(err, unix.ENOTEMPTY):
			return fmt.Errorf("remove the scope directory: %w", err)
		}
	}
	if w.linked {
		return errScopeFlagLinked
	}
	return errScopeTreeBusy
}

// emptyScopeDir removes every name in the scope directory dfd, scope.key
// last and only when nothing else is left beside it.
func (w *rmWalk) emptyScopeDir(dfd int) error {
	if err := w.emptyDir(dfd, 0, scopeKeyName); err != nil {
		return err
	}
	names, err := listDir(dfd)
	if err != nil {
		return err
	}
	if len(names) == 1 && names[0] == scopeKeyName {
		if err := w.removeName(dfd, scopeKeyName, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(dfd)
}

// emptyDir removes every name in the directory dfd but keep, at depth
// below the scope directory. A subdirectory that is not empty by the time
// it is removed (a name appeared in it) is left for the next pass.
func (w *rmWalk) emptyDir(dfd, depth int, keep string) error {
	names, err := listDir(dfd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == keep {
			continue
		}
		if err := w.removeName(dfd, n, depth); err != nil {
			return err
		}
	}
	return nil
}

// removeName removes name in the directory pfd: a directory is opened by
// descriptor (openDirAt), its user flags cleared, emptied and removed with
// AT_REMOVEDIR; any other name has its user flags cleared
// (clearScopeFlags) and is removed with unlinkat, unless it is a flagged
// file whose links are not all met yet, which is left for the next pass.
// A name already gone is not an error.
func (w *rmWalk) removeName(pfd int, name string, depth int) error {
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		leave, err := w.clearScopeFlags(pfd, name, &st)
		if err != nil || leave {
			return err
		}
		if err := unix.Unlinkat(pfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove %s: %w", name, err)
		}
		return nil
	}
	if depth >= maxScopeTreeDepth {
		return fmt.Errorf("%w: %s is nested more than %d directories below the scope directory", errPlanted, name, maxScopeTreeDepth)
	}
	fd, dst, err := openDirAt(pfd, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	err = w.clearHeld(fd, &dst)
	if err == nil {
		err = w.emptyDir(fd, depth+1, "")
	}
	if err == nil {
		err = unix.Fsync(fd)
	}
	_ = unix.Close(fd) // fsynced above
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	err = unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR)
	if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTEMPTY) {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	return nil
}

// clearHeld clears the user flags of the directory held at fd, which st
// describes, when it carries one and the service user owns it.
func (w *rmWalk) clearHeld(fd int, st *unix.Stat_t) error {
	fl := statFlags(st)
	if fl&userLockingFlags == 0 || st.Uid != w.svc {
		return nil
	}
	if err := scopeFchflags(fd, int(fl&^userLockingFlags)); err != nil {
		return fmt.Errorf("clear the user flags of a scope directory: %w", err)
	}
	return nil
}

// clearScopeFlags clears the user flags of the non-directory name in pfd,
// which st describes (fstatat, not followed), before its removal. Nothing
// is done unless it carries one and the service user owns it (a file of
// another owner is left for unlinkat to refuse). A file with more than one
// link is cleared only when it is a regular file and every link has been
// met in the tree in this pass; until then leave is true and the name is
// left for the next pass. The file is opened O_NOFOLLOW (a symlink
// O_SYMLINK, which opens the link itself), never by path, re-checked as
// the name (device, inode, link count), and changed with fchflags on the
// descriptor. At most flagOpenLimit files are opened in all.
func (w *rmWalk) clearScopeFlags(pfd int, name string, st *unix.Stat_t) (leave bool, err error) {
	fl := statFlags(st)
	if fl&userLockingFlags == 0 || st.Uid != w.svc {
		return false, nil
	}
	typ := st.Mode & unix.S_IFMT
	if st.Nlink > 1 {
		if typ != unix.S_IFREG {
			w.linked = true
			return true, nil
		}
		id := [2]uint64{uint64(st.Dev), st.Ino}
		w.seen[id]++
		if w.seen[id] < int(st.Nlink) {
			w.linked = true
			return true, nil
		}
	}
	var flags int
	switch typ {
	case unix.S_IFREG, unix.S_IFIFO:
		flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	case unix.S_IFLNK:
		flags = unix.O_RDONLY | oSymlink | unix.O_NONBLOCK | unix.O_CLOEXEC
	default:
		// A device or socket is not opened; unlinkat reports the flag.
		return false, nil
	}
	if w.opens >= flagOpenLimit {
		return false, errScopeFlagBudget
	}
	w.opens++
	fd, err := unix.Openat(pfd, name, flags, 0)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("open %s to clear its user flags: %w", name, err)
	}
	defer func() { _ = unix.Close(fd) }() // only its flags change
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		return false, fmt.Errorf("stat %s: %w", name, err)
	}
	if got.Dev != st.Dev || got.Ino != st.Ino || got.Nlink != st.Nlink || got.Uid != w.svc {
		// Replaced or relinked under the walk: the next pass sees it anew.
		return true, nil
	}
	if err := scopeFchflags(fd, int(statFlags(&got)&^userLockingFlags)); err != nil {
		return false, fmt.Errorf("clear the user flags of %s: %w", name, err)
	}
	return false, nil
}

// errPlanted is a name in a service-user tree that the layout does not put
// there: a symlink, a FIFO, any non-regular file, or a misplaced directory.
var errPlanted = errors.New("a symlink, FIFO, non-regular file or misplaced directory is in the scope's tree")

// openDirAt opens the directory name under parent O_DIRECTORY|O_NOFOLLOW
// and re-checks that it is the directory fstatat named (SameFile), so a
// directory swapped between the two is never followed.
func openDirAt(parent int, name string) (int, unix.Stat_t, error) {
	var named, opened unix.Stat_t
	if err := unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, named, err
	}
	if named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, named, fmt.Errorf("%w: %s", errPlanted, name)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, named, fmt.Errorf("%w: %s: %w", errPlanted, name, err)
	}
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, named, err
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino {
		_ = unix.Close(fd) // read-only
		return -1, named, fmt.Errorf("%w: %s was replaced while it was opened", errPlanted, name)
	}
	return fd, opened, nil
}

// listDir lists the directory dfd, bounded at maxDirNames: the descriptor
// is duplicated, so dfd stays open for the caller.
func listDir(dfd int) ([]string, error) {
	dup, err := unix.Dup(dfd)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(dup), "dir")
	defer func() { _ = d.Close() }() // read-only
	if _, err := unix.Seek(dup, 0, io.SeekStart); err != nil {
		return nil, err
	}
	var names []string
	for {
		batch, err := d.Readdirnames(dirBatch)
		names = append(names, batch...)
		if len(names) > maxDirNames {
			return nil, fmt.Errorf("a directory holds over %d names", maxDirNames)
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
