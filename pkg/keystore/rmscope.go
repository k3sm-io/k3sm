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
// lockMaintenance) it opens the
// scope's key under W without the GeneratedUID check and reads its delivery
// record, refusing while the record names any delivery, then lists the
// scope key's identity in the removed-scopes record
// (keystore-removed-scopes.json, through the judged data-root descriptor),
// then removes .user/<uid>/ by descriptor (removeScopeTree), walking from
// the keystore root it opened and judged first, never from the path again.
// A scope directory copied back after it is refused at every open, since
// its scope.key's identity is listed, and the next floor --rebuild drops
// every floor key of the scope. A full record does not stop the removal:
// recorded reports false, the scope is removed unlisted, and floor
// --rebuild keeps its floor keys (fail closed for a copy-back). A record
// that does not read refuses, changing nothing. A scope whose entries/ and
// delivery record are both gone is an earlier rm-scope that stopped
// part-way, and is finished.
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
	u := &UserScope{s: s, uid: uid, scope: userScopeOf(uid), allowRemoved: true}
	o, err := u.openScopeForRevoke(root, k)
	if err != nil {
		return false, fmt.Errorf("open the scope %s: %w; nothing was changed", u.scope, err)
	}
	id := o.id
	_, ds, derr := u.readDeliveriesUnfloored(o)
	_, eerr := o.dir.Lstat(scopeEntriesName)
	o.close()
	switch {
	case derr == nil && len(ds) > 0:
		return false, fmt.Errorf("%s: %w", u.scope, errScopeHasDeliveries)
	case derr == nil:
	case errors.Is(derr, ErrScopeAbsent) && errors.Is(eerr, os.ErrNotExist):
		// An earlier rm-scope removed entries/ and the record, then stopped.
	default:
		return false, fmt.Errorf("read the delivery record of %s: %w; nothing was changed", u.scope, derr)
	}
	recorded = removed.has(uid, id)
	if !recorded && removed.add(uid, id) {
		if err := writeRemovedScopes(dfd, removed); err != nil {
			return false, fmt.Errorf("record the removed scope %s in %s: %w; nothing else was changed", u.scope, removedScopesName, err)
		}
		recorded = true
	}
	return recorded, removeScopeTree(root, strconv.FormatUint(uint64(uid), 10))
}

// removeScopeTree removes keystore/.user/<uid>/ by descriptor, starting
// from keystore, the already-judged keystore root, so a directory swapped in
// at the keystore's path since it was judged is never walked: each step is
// openat relative to its parent with O_NOFOLLOW (and O_DIRECTORY), re-checked
// with fstat against the parent's fstatat of the name (SameFile), each
// removal is unlinkat relative to its parent, and each listing is bounded.
// A symlink, FIFO, socket, device or any other non-regular file refuses, and
// so does a directory anywhere but entries/ and entries/<name>/. It walks
// the tree twice: once to judge it, changing nothing, and once to remove
// it, judging each step again. The entries come first, then every file but
// scope.key, then scope.key, then the directory.
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
	for _, remove := range []bool{false, true} {
		if err := walkScopeDir(ufd, uid, remove); err != nil {
			if remove {
				return fmt.Errorf("remove keystore/%s/%s: %w; rerun rm-scope to finish", userScopesName, uid, err)
			}
			return fmt.Errorf("keystore/%s/%s: %w; nothing was changed", userScopesName, uid, err)
		}
	}
	if err := unix.Unlinkat(ufd, uid, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove keystore/%s/%s: %w; rerun rm-scope to finish", userScopesName, uid, err)
	}
	return unix.Fsync(ufd)
}

// errPlanted refuses a name in a service-user tree that the layout does not
// put there: a symlink, a FIFO, any non-regular file, or a misplaced
// directory.
var errPlanted = errors.New("a symlink, FIFO, non-regular file or misplaced directory is in the scope's tree")

// walkScopeDir judges, or with remove removes the contents of, the scope
// directory uid under parent.
func walkScopeDir(parent int, uid string, remove bool) error {
	dfd, _, err := openDirAt(parent, uid)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }() // fsynced below
	names, err := listDir(dfd)
	if err != nil {
		return err
	}
	var files []string
	hasKey := false
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch {
		case n == scopeEntriesName && st.Mode&unix.S_IFMT == unix.S_IFDIR:
			if err := walkEntries(dfd, remove); err != nil {
				return err
			}
		case st.Mode&unix.S_IFMT != unix.S_IFREG:
			return fmt.Errorf("%w: %s", errPlanted, n)
		case n == scopeKeyName:
			hasKey = true
		default:
			files = append(files, n)
		}
	}
	if !remove {
		return nil
	}
	if hasKey {
		files = append(files, scopeKeyName)
	}
	for _, n := range files {
		if err := unlinkRegular(dfd, n); err != nil {
			return err
		}
	}
	return unix.Fsync(dfd)
}

// walkEntries judges, or removes, entries/ under the scope directory dfd:
// each name a directory holding only regular files.
func walkEntries(scope int, remove bool) error {
	efd, _, err := openDirAt(scope, scopeEntriesName)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(efd) }() // fsynced below
	names, err := listDir(efd)
	if err != nil {
		return err
	}
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(efd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if remove {
				if err := unlinkRegular(efd, n); err != nil {
					return err
				}
			}
		case unix.S_IFDIR:
			if err := walkEntryDir(efd, n, remove); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %s/%s", errPlanted, scopeEntriesName, n)
		}
	}
	if !remove {
		return nil
	}
	if err := unix.Fsync(efd); err != nil {
		return err
	}
	return unix.Unlinkat(scope, scopeEntriesName, unix.AT_REMOVEDIR)
}

// walkEntryDir judges, or removes, entries/<name>/: regular files only.
func walkEntryDir(entries int, name string, remove bool) error {
	fd, _, err := openDirAt(entries, name)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }() // fsynced below
	names, err := listDir(fd)
	if err != nil {
		return err
	}
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%w: %s/%s/%s", errPlanted, scopeEntriesName, name, n)
		}
		if remove {
			if err := unlinkRegular(fd, n); err != nil {
				return err
			}
		}
	}
	if !remove {
		return nil
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	return unix.Unlinkat(entries, name, unix.AT_REMOVEDIR)
}

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

// unlinkRegular removes name under dfd with unlinkat after fstatat finds a
// regular file there, so a name swapped for a directory is refused.
func unlinkRegular(dfd int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s", errPlanted, name)
	}
	return unix.Unlinkat(dfd, name, 0)
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
