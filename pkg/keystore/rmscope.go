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
		if err := removeScopeTree(root, name); err != nil {
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
	if err := removeScopeTree(root, name); err != nil {
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
func removeScopeTree(keystore *os.Root, uid string) error {
	kd, err := keystore.Open(".")
	if err != nil {
		return fmt.Errorf("open the keystore directory: %w", err)
	}
	defer func() { _ = kd.Close() }() // read-only
	ufd, _, err := openDirAt(int(kd.Fd()), userScopesName)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(ufd) }() // fsynced below
	for range maxRemovePasses {
		dfd, _, err := openDirAt(ufd, uid)
		if errors.Is(err, unix.ENOENT) {
			return unix.Fsync(ufd)
		}
		if err != nil {
			return err
		}
		err = emptyScopeDir(dfd)
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
	return errScopeTreeBusy
}

// emptyScopeDir removes every name in the scope directory dfd, scope.key
// last and only when nothing else is left beside it.
func emptyScopeDir(dfd int) error {
	if err := emptyDir(dfd, 0, scopeKeyName); err != nil {
		return err
	}
	names, err := listDir(dfd)
	if err != nil {
		return err
	}
	if len(names) == 1 && names[0] == scopeKeyName {
		if err := removeName(dfd, scopeKeyName, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(dfd)
}

// emptyDir removes every name in the directory dfd but keep, at depth
// below the scope directory. A subdirectory that is not empty by the time
// it is removed (a name appeared in it) is left for the next pass.
func emptyDir(dfd, depth int, keep string) error {
	names, err := listDir(dfd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == keep {
			continue
		}
		if err := removeName(dfd, n, depth); err != nil {
			return err
		}
	}
	return nil
}

// removeName removes name in the directory pfd: a directory is opened by
// descriptor (openDirAt), emptied and removed with AT_REMOVEDIR; any other
// name is removed with unlinkat. A name already gone is not an error.
func removeName(pfd int, name string, depth int) error {
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(pfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove %s: %w", name, err)
		}
		return nil
	}
	if depth >= maxScopeTreeDepth {
		return fmt.Errorf("%w: %s is nested more than %d directories below the scope directory", errPlanted, name, maxScopeTreeDepth)
	}
	fd, _, err := openDirAt(pfd, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	err = emptyDir(fd, depth+1, "")
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
