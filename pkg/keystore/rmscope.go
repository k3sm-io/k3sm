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
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

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
// record names any delivery. A record that does not read (the service user
// can damage its own) does not stop it, since listing needs only
// scope.key: the scope is removed and the result is errCommitted, saying
// its deliveries were not checked. It then lists the scope key's identity in the
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
// A scope.key that is present but cannot be trusted (errScopeKeyUntrusted)
// is treated as a missing one: the tree is removed unlisted, its floor
// lines are kept, and the result is errCommitted, saying so.
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
	if errors.Is(err, errScopeKeyUntrusted) {
		// scope.key is present but cannot be trusted, which the service
		// user can cause: there is no key identity to list, so the scope
		// is removed unlisted, as with no scope.key, and its floor lines
		// are kept. Refusing would leave a scope rebuild refuses and names
		// rm-scope for.
		if err := removeScopeTree(root, s.dir, name, s.uid); err != nil {
			return false, fmt.Errorf("%w; the directory %s has a scope.key that cannot be trusted and is partly or wholly present: rerun sudo k3sm keys rm-scope %s --yes to finish removing it", err, quoteName("keystore/"+userScopesName+"/"+name), u.scope)
		}
		return false, fmt.Errorf("%w: %s", errCommitted, scopeRemovedUntrusted(u.scope, err))
	}
	if errors.Is(err, errNoScopeKey) && scopeDirPresent(root, name) {
		// An earlier rm-scope removed scope.key, then stopped: no open
		// serves the directory, and there is no key to list.
		if err := removeScopeTree(root, s.dir, name, s.uid); err != nil {
			return false, fmt.Errorf("%w; the directory %s has no scope.key and is partly or wholly present: rerun sudo k3sm keys rm-scope %s --yes to finish removing it", err, quoteName("keystore/"+userScopesName+"/"+name), u.scope)
		}
		if removed.listed(uid) {
			return true, nil
		}
		// Not listed: an interrupted run that never listed it, or
		// tampering. The tree is gone, but there was no key to list.
		return false, fmt.Errorf("%w: %s", errCommitted, scopeRemovedUnlisted(u.scope))
	}
	if err != nil {
		return false, fmt.Errorf("open the scope %s: %w; nothing was changed: repair what the error names (sudo k3sm doctor lists it), then rerun", u.scope, err)
	}
	id := o.id
	recorded = removed.has(uid, id)
	_, ds, derr := u.readDeliveriesUnfloored(o)
	_, eerr := o.dir.Lstat(scopeEntriesName)
	o.close()
	var unread error
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
		// The service user can damage its own record; listing needs only
		// scope.key, so the scope is removed, and the result says what
		// went unchecked.
		unread = derr
	}
	if !recorded {
		fid, size, err := s.floorSize(dfd)
		if err != nil {
			return false, fmt.Errorf("read the size of the user-scope floor %s: %w; nothing was changed: repair what the error names (sudo k3sm doctor lists it), then rerun", userFloorLogName, err)
		}
		if removed.add(uid, id, fid, size) {
			if err := writeRemovedScopes(dfd, removed); err != nil {
				return false, fmt.Errorf("record the removed scope %s in %s: %w; the record may or may not list it, and the scope directory is untouched: rerun sudo k3sm keys rm-scope %s --yes", u.scope, removedScopesName, err, u.scope)
			}
			recorded = true
		}
	}
	if err := removeScopeTree(root, s.dir, name, s.uid); err != nil {
		state := "is listed as removed in " + removedScopesName + ", so no open serves it"
		if !recorded {
			state = "is not listed in " + removedScopesName + ", which is full"
		}
		return recorded, fmt.Errorf("%w; the scope %s %s, and its directory %s is partly or wholly present: rerun sudo k3sm keys rm-scope %s --yes to finish removing it", err, u.scope, state, quoteName("keystore/"+userScopesName+"/"+name), u.scope)
	}
	if unread != nil {
		return recorded, fmt.Errorf("%w: %s", errCommitted, scopeRemovedUnread(u.scope, unread))
	}
	return recorded, nil
}

// scopeRemovedUnread is rm-scope's committed report for a scope removed
// although its delivery record did not read (err).
func scopeRemovedUnread(scope string, err error) string {
	return "removed " + scope + ", but its delivery record could not be read (" + safeText(err.Error()) + "), so deliveries from this scope were not checked: any Secret it delivered stays until it is withdrawn or removed by hand"
}

// floorSize is the user-scope floor's identity and byte size, through the
// judged data root dfd: zero when there is no floor yet.
func (s *FileStore) floorSize(dfd int) (floorIdentity, int64, error) {
	lfd, err := s.openLogsDir(dfd)
	if err != nil {
		return floorIdentity{}, 0, err
	}
	defer func() { _ = unix.Close(lfd) }() // read-only directory descriptor
	var st unix.Stat_t
	err = s.statLog(lfd, userFloorLogName, &st)
	if errors.Is(err, unix.ENOENT) {
		return floorIdentity{}, 0, nil
	}
	if err != nil {
		return floorIdentity{}, 0, err
	}
	return floorIdentityOf(&st), st.Size, nil
}

// scopeRemovedUnlisted is rm-scope's committed report for a scope
// directory with no scope.key whose uid the record does not list.
func scopeRemovedUnlisted(scope string) string {
	return "removed " + scope + " without listing it in " + removedScopesName + ", because its scope.key was absent (an interrupted earlier rm-scope, or tampering): a copy of its directory put back would open; its floor lines are kept, so the floor still refuses rolled-back or deleted entries"
}

// scopeRemovedUntrusted is rm-scope's committed report for a scope
// directory whose scope.key was present but could not be trusted (err).
func scopeRemovedUntrusted(scope string, err error) string {
	return "removed " + scope + " without listing it in " + removedScopesName + ", because its scope.key could not be trusted (" + safeText(err.Error()) + "): a copy of its directory put back would open; its floor lines are kept, so the floor still refuses rolled-back or deleted entries"
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

// errScopeFlagBudget is a scope tree whose user flags would take more
// flag clears than rm-scope makes.
var errScopeFlagBudget = fmt.Errorf("the scope directory holds more flagged files than rm-scope clears the user flags of (%d)", maxFlagOpens)

// rmWalk is one removeScopeTree: the service user's uid, whose own
// entries' user flags it clears, how many entries it has cleared or opened
// to do so, the scope directory's path, which its repair command names,
// and the scope, which its rerun names.
type rmWalk struct {
	svc   uint32
	opens int
	base  string
	scope string
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
// own entries, which makes root's unlinkat fail with EPERM. So before a
// name is removed, a user flag on it is cleared (clearScopeFlags) when the
// service user owns it, whatever its link count (the owner could clear the
// flag itself, so leaving it would only let it stall the removal): on a
// descriptor opened O_NOFOLLOW (O_SYMLINK for a symlink), never by path,
// and re-checked as the name; a FIFO, device or socket is not opened (an
// open has side effects, or macOS refuses it) but changed by directory
// descriptor and name with setattrlistat, which never follows a symlink.
// An entry another user owns is left alone: its unlinkat fails with EPERM,
// and the error names the entry for reading only and offers one repair
// whose only path is the scope directory's (flagKept). dir is the
// keystore's path, which the repair names.
func removeScopeTree(keystore *os.Root, dir, uid string, svc uint32) error {
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
	w := &rmWalk{svc: svc, base: filepath.Join(dir, userScopesName, uid), scope: userScopePrefix + uid}
	if err := w.clearHeld(ufd, &ust); err != nil {
		return err
	}
	for range maxRemovePasses {
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
	return errScopeTreeBusy
}

// emptyScopeDir removes every name in the scope directory dfd, scope.key
// last and only when nothing else is left beside it.
func (w *rmWalk) emptyScopeDir(dfd int) error {
	if err := w.emptyDir(dfd, "", 0, scopeKeyName); err != nil {
		return err
	}
	names, err := listDir(dfd)
	if err != nil {
		return err
	}
	if len(names) == 1 && names[0] == scopeKeyName {
		if err := w.removeName(dfd, "", scopeKeyName, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(dfd)
}

// emptyDir removes every name in the directory dfd but keep, at rel and
// depth below the scope directory. A subdirectory that is not empty by
// the time it is removed (a name appeared in it) is left for the next
// pass.
func (w *rmWalk) emptyDir(dfd int, rel string, depth int, keep string) error {
	names, err := listDir(dfd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == keep {
			continue
		}
		if err := w.removeName(dfd, rel, n, depth); err != nil {
			return err
		}
	}
	return nil
}

// removeName removes name in the directory pfd, rel below the scope
// directory: a directory is opened by descriptor (openDirAt), its user
// flags cleared, emptied and removed with AT_REMOVEDIR; any other name has
// its user flags cleared (clearScopeFlags) and is removed with unlinkat,
// unless it changed under the walk, which leaves it for the next pass. A
// name already gone is not an error.
func (w *rmWalk) removeName(pfd int, rel, name string, depth int) error {
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", quoteName(name), err)
	}
	rel = filepath.Join(rel, name)
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		leave, err := w.clearScopeFlags(pfd, name, rel, &st)
		if err != nil || leave {
			return err
		}
		if err := unix.Unlinkat(pfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return w.flagKept(rel, &st, err)
		}
		return nil
	}
	if depth >= maxScopeTreeDepth {
		return fmt.Errorf("%w: %s is nested more than %d directories below the scope directory", errPlanted, quoteName(name), maxScopeTreeDepth)
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
		err = w.emptyDir(fd, rel, depth+1, "")
	}
	if err == nil {
		err = unix.Fsync(fd)
	}
	_ = unix.Close(fd) // fsynced above
	if err != nil {
		return fmt.Errorf("%s: %w", quoteName(name), err)
	}
	err = unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR)
	if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTEMPTY) {
		return w.flagKept(rel, &dst, err)
	}
	return nil
}

// flagKept is the error for the entry rel below the scope directory,
// which st describes, whose removal failed with err. When it carries a
// user flag rm-scope left because another user owns it, the error names the entry for reading only, quoted with its
// control bytes removed (quoteName), and offers the repair, whose one
// command names only the scope directory (repairHint), never the entry.
func (w *rmWalk) flagKept(rel string, st *unix.Stat_t, err error) error {
	p := quoteName(filepath.Join(w.base, rel))
	if statFlags(st)&userLockingFlags == 0 {
		return fmt.Errorf("remove %s: %w", p, err)
	}
	why := "the service user does not own it (uid " + strconv.FormatUint(uint64(st.Uid), 10) + ")"
	if st.Uid == w.svc {
		// Its user flag was cleared (clearScopeFlags, clearHeld): the
		// failure is not the flag's.
		return fmt.Errorf("remove %s: %w", p, err)
	}
	return fmt.Errorf("remove the entry %s (named for reading, not for pasting): %w: it carries a user flag (uchg or uappnd) that rm-scope does not clear, because %s; %s", p, err, why, w.repairHint())
}

// repairHint is the one repair rm-scope offers for a flag it leaves
// (repairCommands, in order).
func (w *rmWalk) repairHint() string {
	c := repairCommands(w.base, w.scope)
	return "to clear it, run " + c[0] + ", then " + c[1] + ", then rerun " + c[2]
}

// repairCommands are the commands of rm-scope's repair: stop the server,
// clear the user locking flags of everything under the scope directory
// base as root, never following a symlink, and rerun. The one path in them
// is base, which the caller builds from the keystore's path and the
// numeric uid, never from a name in the service user's tree, and it is
// single-quoted (shellQuote) so a shell expands nothing in it. scope is
// the scope's name, the prefix and the numeric uid.
func repairCommands(base, scope string) [3]string {
	return [3]string{
		"sudo k3sm stop",
		"sudo chflags -R -P nouchg,nouappnd " + shellQuote(base),
		"sudo k3sm keys rm-scope " + scope + " --yes",
	}
}

// shellQuote is s single-quoted for a POSIX shell: inside single quotes a
// shell expands nothing, and a single quote in s is closed, escaped and
// reopened ('\”).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
// rel below the scope directory, which st describes (fstatat, not
// followed), before its removal. Nothing is done unless it carries one and
// the service user owns it (an entry of another owner is left for unlinkat
// to refuse, flagKept naming it), at any link count: a link outside the
// tree shares the flag, but its owner could clear the flag itself. A
// regular file is opened O_NOFOLLOW and a symlink O_SYMLINK (the link
// itself), never by path; both opens are free of side effects. The
// descriptor is re-checked as the name (device, inode, link count, owner;
// leave is true and the name left for the next pass when it changed) and
// changed with fchflags. A FIFO or device is not opened (an open can
// unblock a writer or start a driver), nor a socket (macOS refuses its open
// with EOPNOTSUPP): clearUnopened changes it by name. At most flagOpenLimit
// entries are cleared in all.
func (w *rmWalk) clearScopeFlags(pfd int, name, rel string, st *unix.Stat_t) (leave bool, err error) {
	fl := statFlags(st)
	if fl&userLockingFlags == 0 || st.Uid != w.svc {
		return false, nil
	}
	var flags int
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	case unix.S_IFLNK:
		flags = unix.O_RDONLY | oSymlink | unix.O_NONBLOCK | unix.O_CLOEXEC
	default:
		return w.clearUnopened(pfd, name, rel, st)
	}
	if w.opens >= flagOpenLimit {
		return false, w.budgetErr()
	}
	w.opens++
	fd, err := unix.Openat(pfd, name, flags, 0)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("open the entry %s (named for reading, not for pasting) to clear its user flags: %w; %s", quoteName(filepath.Join(w.base, rel)), err, w.repairHint())
	}
	defer func() { _ = unix.Close(fd) }() // only its flags change
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		return false, fmt.Errorf("stat %s: %w", quoteName(name), err)
	}
	if got.Dev != st.Dev || got.Ino != st.Ino || got.Nlink != st.Nlink || got.Uid != w.svc {
		// Replaced or relinked under the walk: the next pass sees it anew.
		return true, nil
	}
	if err := scopeFchflags(fd, int(statFlags(&got)&^userLockingFlags)); err != nil {
		return false, fmt.Errorf("clear the user flags of the entry %s (named for reading, not for pasting): %w; %s", quoteName(filepath.Join(w.base, rel)), err, w.repairHint())
	}
	return false, nil
}

// clearUnopened clears the user flags of the FIFO, socket or device name
// in pfd, which st describes (fstatat, not followed, owned by the service
// user and carrying a user flag), without opening it: setattrlistat by
// directory descriptor and name, FSOPT_NOFOLLOW (setFlagsAt). An entry
// that also carries a system flag is left, so the write sets user flags
// only. The name is then stat'ed again: when it is
// no longer the file st describes, or no longer the service user's, leave
// is true and the next pass sees it anew; when it still carries a user
// locking flag the error says so and offers the repair. A name replaced
// between the stat and the write by another file the service user could
// link in has at most its user flags set to st's less the locking ones.
// An entry carrying a system flag is left as it is (the write would set
// it), and its unlinkat fails.
func (w *rmWalk) clearUnopened(pfd int, name, rel string, st *unix.Stat_t) (leave bool, err error) {
	fl := statFlags(st)
	if fl&sfFlagsMask != 0 {
		return false, nil
	}
	if w.opens >= flagOpenLimit {
		return false, w.budgetErr()
	}
	w.opens++
	err = setFlagsAt(pfd, name, fl&^userLockingFlags)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("clear the user flags of the entry %s (named for reading, not for pasting): %w; %s", quoteName(filepath.Join(w.base, rel)), err, w.repairHint())
	}
	var got unix.Stat_t
	if err := unix.Fstatat(pfd, name, &got, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("stat %s: %w", quoteName(name), err)
	}
	if got.Dev != st.Dev || got.Ino != st.Ino || got.Uid != w.svc {
		return true, nil
	}
	if statFlags(&got)&userLockingFlags != 0 {
		return false, fmt.Errorf("setattrlistat left a user flag (flags %#x) on the entry %s (named for reading, not for pasting); %s", statFlags(&got), quoteName(filepath.Join(w.base, rel)), w.repairHint())
	}
	return false, nil
}

// budgetErr is errScopeFlagBudget with the repair.
func (w *rmWalk) budgetErr() error {
	return fmt.Errorf("%w; %s", errScopeFlagBudget, w.repairHint())
}

// errPlanted is a name in a service-user tree that the layout does not put
// there: a symlink, a FIFO, any non-regular file, or a misplaced directory.
var errPlanted = errors.New("a symlink, FIFO, non-regular file or misplaced directory is in the scope's tree: remove it as root, then rerun")

// openDirAt opens the directory name under parent O_DIRECTORY|O_NOFOLLOW
// and re-checks that it is the directory fstatat named (SameFile), so a
// directory swapped between the two is never followed.
func openDirAt(parent int, name string) (int, unix.Stat_t, error) {
	var named, opened unix.Stat_t
	if err := unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, named, err
	}
	if named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, named, fmt.Errorf("%w: %s", errPlanted, quoteName(name))
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, named, fmt.Errorf("%w: %s: %w", errPlanted, quoteName(name), err)
	}
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, named, err
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino {
		_ = unix.Close(fd) // read-only
		return -1, named, fmt.Errorf("%w: %s was replaced while it was opened", errPlanted, quoteName(name))
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
			return nil, fmt.Errorf("a directory holds over %d names: remove some as root, then rerun", maxDirNames)
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// safeText is s, a text that may hold a name from the service user's
// tree, with its control characters and invalid bytes removed, so an error
// or hint that prints it cannot move the cursor, start a new line or
// carry an escape sequence.
func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}

// quoteName renders a name or path from the service user's tree for an
// error to read: control characters removed, then Go-quoted (%q). A shell
// still expands $(...), backticks and $VAR inside double quotes, so no
// command rm-scope offers ever holds it.
func quoteName(s string) string { return strconv.Quote(safeText(s)) }
