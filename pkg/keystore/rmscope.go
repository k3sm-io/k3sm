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
	"log/slog"
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
// record names any delivery. A damaged record (deliveriesDamaged: the
// service user can damage its own) does not stop it, since listing needs
// only scope.key: the scope is removed and the result is errCommitted,
// saying its deliveries were not checked. Any other failure to read it
// refuses, changing nothing. It then lists the scope key's identity in the
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
// A scope.key the judge refuses only for its link count or mode, which any
// local user can cause, is read again without those two checks
// (openScopeForRmLoose): when it authenticates under the master it is
// listed and the tree removed, and the result is errCommitted, noting the
// link count or mode. A scope.key that is present but does not parse or
// authenticate (errScopeKeyUntrusted) is treated as a missing one: the
// tree is removed unlisted, its floor lines are kept, and the result is
// errCommitted, saying so.
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
	var judged string
	if errors.Is(err, errScopeKeyUntrusted) {
		// A second link or a wider mode fails the judge, and any local
		// user can cause either; a key that still authenticates under the
		// master is listed, so a copy put back stays refused.
		if lo, why, lerr := u.openScopeForRmLoose(root, k); lerr == nil {
			o, judged, err = lo, why, nil
		}
	}
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
	_, ds, derr := rmReadDeliveries(u, o)
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
	case deliveriesDamaged(derr):
		// The service user can damage its own record; listing needs only
		// scope.key, so the scope is removed, and the result says what
		// went unchecked.
		unread = derr
	default:
		// A transient failure (a cancelled context, EINTR, EMFILE, EIO)
		// says nothing of the record: proceeding would leave its
		// deliveries unchecked for no cause.
		return false, fmt.Errorf("read the delivery record of %s: %s; nothing was changed; run it again", u.scope, safeText(derr.Error()))
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
	var notes []string
	if judged != "" {
		notes = append(notes, scopeRemovedJudged(u.scope, judged, recorded))
	}
	if unread != nil {
		notes = append(notes, scopeRemovedUnread(u.scope, unread))
	}
	if len(notes) > 0 {
		return recorded, fmt.Errorf("%w: %s", errCommitted, strings.Join(notes, "; "))
	}
	return recorded, nil
}

// scopeRemovedJudged is rm-scope's committed note for a scope whose
// scope.key failed its judge only for its link count or mode (why) and
// still authenticated under the master, so it was listed when recorded.
func scopeRemovedJudged(scope, why string, recorded bool) string {
	state := "listed it in " + removedScopesName + ", so a copy of its directory put back is refused"
	if !recorded {
		state = "could not list it in " + removedScopesName + ", which is full"
	}
	return "removed " + scope + " and " + state + ", but its scope.key's link count or mode was wrong (" + safeText(why) + "): another name or a reader of the key file may have kept a copy of it"
}

// rmReadDeliveries is rm-scope's read of the delivery record; tests
// replace it to inject a failure.
var rmReadDeliveries = (*UserScope).readDeliveriesUnfloored

// deliveriesDamaged reports whether err, from readDeliveriesUnfloored, is
// a damaged record rather than a failure to read it: ErrCorrupt (a record
// that does not parse, authenticate or bind, or the judge's refusal of its
// type, owner, mode, flags or links, errBadFile), a planted name
// (errPlanted), or a record missing beside scope.key (ErrScopeAbsent), all
// of which the service user can cause and a rerun would meet again.
func deliveriesDamaged(err error) bool {
	return errors.Is(err, ErrCorrupt) || errors.Is(err, errBadFile) || errors.Is(err, errPlanted) || errors.Is(err, ErrScopeAbsent)
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
	return "removed " + scope + " without listing it in " + removedScopesName + ", because its scope.key was absent (an interrupted earlier rm-scope, or tampering): a copy of its directory put back would open only if it carries a key the master accepts; its floor lines are kept, so the floor still refuses rolled-back or deleted entries"
}

// scopeRemovedUntrusted is rm-scope's committed report for a scope
// directory whose scope.key was present but could not be trusted (err).
func scopeRemovedUntrusted(scope string, err error) string {
	return "removed " + scope + " without listing it in " + removedScopesName + ", because its scope.key could not be trusted (" + safeText(err.Error()) + "): a copy of its directory put back would open only if it carries a key the master accepts; its floor lines are kept, so the floor still refuses rolled-back or deleted entries"
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

// errScopeFlagBudget is a scope tree whose locking flags would take more
// flag clears than one rm-scope run makes. The budget is per run: a rerun
// clears up to as many more.
var errScopeFlagBudget = fmt.Errorf("the scope directory holds more flagged entries than one rm-scope run unlocks (%d): run rm-scope for this scope again; each run unlocks up to %d more", maxFlagOpens, maxFlagOpens)

// rmWalk is one removeScopeTree: the service user's uid, how many entries
// it has cleared or opened to clear their flags, the scope directory's
// path, which its errors name entries under, and the scope, which its
// warnings name.
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
// A user locking flag (uchg, uappnd, uunlnk) makes root's unlinkat fail
// with EPERM. So before a name is removed, its user locking flags are
// cleared, whoever owns it, when it carries no system flag and has one
// link (a flagged file cannot be hard-linked, so a flagged entry with one
// link is debris of the tree being removed), and also at any link count
// when the service user owns a regular file or symlink (its owner could
// clear the flag itself). A directory, a regular file and a symlink are
// changed on a descriptor (opened O_NOFOLLOW, O_SYMLINK for a symlink),
// never by path, re-checked as the name; a FIFO, device or socket is not
// opened (an open has side effects, or macOS refuses it) and has its flags
// set to exactly 0 by directory descriptor and name with setattrlistat
// (clearUnopened). What is left fails its unlinkat with EPERM, and the
// error names the entry for reading only and offers no command (flagKept):
// an entry with a system flag, which only root sets, and one another user
// owns with more than one link. dir is the keystore's path, which the
// errors name entries under.
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
// flag rm-scope left, the error names the entry for reading only, quoted
// with its control bytes removed (quoteName), says why it was left, and
// offers no command: a system flag is for the administrator who set it to
// clear, and a command holding a name from the service user's tree, or a
// recursive flag change over a tree it writes, is what the design bans.
func (w *rmWalk) flagKept(rel string, st *unix.Stat_t, err error) error {
	p := quoteName(filepath.Join(w.base, rel))
	fl := statFlags(st)
	switch {
	case fl&sfFlagsMask != 0:
		return fmt.Errorf("remove the entry %s (named for reading, not for pasting): %w: a system flag is set on it (flags %#x); only root sets one, and only the administrator who set it should clear it, so rm-scope leaves it; once it is cleared, run rm-scope for this scope again", p, err, fl)
	case fl&userLockingFlags != 0 && st.Nlink > 1:
		return fmt.Errorf("remove the entry %s (named for reading, not for pasting): %w: it carries a user flag (uchg, uappnd or uunlnk) and has %d links, so rm-scope does not clear it: another name of the same file may be outside the scope directory; once its owner clears the flag or the other link is removed, run rm-scope for this scope again", p, err, st.Nlink)
	}
	return fmt.Errorf("remove %s: %w", p, err)
}

// clearable reports whether rm-scope clears the user locking flags of the
// entry st describes: it carries one and no system flag (only root sets
// those, and a write could not leave them as they are), and it has one
// link, or the service user owns it and it is opened (a regular file or a
// symlink; its owner could clear the flag itself).
func (w *rmWalk) clearable(st *unix.Stat_t, opened bool) bool {
	fl := statFlags(st)
	if fl&userLockingFlags == 0 || fl&sfFlagsMask != 0 {
		return false
	}
	return st.Nlink == 1 || (opened && st.Uid == w.svc)
}

// clearHeld clears the user locking flags of the directory held at fd,
// which st describes, whoever owns it, when it carries one and no system
// flag: the descriptor is the directory openDirAt re-checked as the name.
func (w *rmWalk) clearHeld(fd int, st *unix.Stat_t) error {
	fl := statFlags(st)
	if fl&userLockingFlags == 0 || fl&sfFlagsMask != 0 {
		return nil
	}
	if err := scopeFchflags(fd, int(fl&^userLockingFlags)); err != nil {
		return fmt.Errorf("clear the user flags of a scope directory: %w", err)
	}
	return nil
}

// clearScopeFlags clears the user locking flags of the non-directory name
// in pfd, rel below the scope directory, which st describes (fstatat, not
// followed), before its removal, when clearable allows it; otherwise the
// entry is left for unlinkat to refuse, flagKept naming it. A regular file
// is opened O_NOFOLLOW and a symlink O_SYMLINK (the link itself), never by
// path; both opens are free of side effects. The descriptor is re-checked
// as the name (device, inode, link count, owner; leave is true and the
// name left for the next pass when it changed) and changed with fchflags,
// keeping its other flags. A FIFO or device is not opened (an open can
// unblock a writer or start a driver), nor a socket (macOS refuses its
// open with EOPNOTSUPP): clearUnopened writes 0 by name. At most
// flagOpenLimit entries are cleared per run.
func (w *rmWalk) clearScopeFlags(pfd int, name, rel string, st *unix.Stat_t) (leave bool, err error) {
	var flags int
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	case unix.S_IFLNK:
		flags = unix.O_RDONLY | oSymlink | unix.O_NONBLOCK | unix.O_CLOEXEC
	default:
		if !w.clearable(st, false) {
			return false, nil
		}
		return w.clearUnopened(pfd, name, rel, st)
	}
	if !w.clearable(st, true) {
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
		return false, fmt.Errorf("open the entry %s (named for reading, not for pasting) to clear its user flags: %w", quoteName(filepath.Join(w.base, rel)), err)
	}
	defer func() { _ = unix.Close(fd) }() // only its flags change
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		return false, fmt.Errorf("stat %s: %w", quoteName(name), err)
	}
	if got.Dev != st.Dev || got.Ino != st.Ino || got.Nlink != st.Nlink || got.Uid != st.Uid || statFlags(&got)&sfFlagsMask != 0 {
		// Replaced or relinked under the walk: the next pass sees it anew.
		return true, nil
	}
	if err := scopeFchflags(fd, int(statFlags(&got)&^userLockingFlags)); err != nil {
		return false, fmt.Errorf("clear the user flags of the entry %s (named for reading, not for pasting): %w", quoteName(filepath.Join(w.base, rel)), err)
	}
	return false, nil
}

// clearUnopened clears the flags of the FIFO, socket or device name in
// pfd, which st describes (fstatat, not followed: one link, a user locking
// flag, no system flag), without opening it: setattrlistat by directory
// descriptor and name, FSOPT_NOFOLLOW (setFlagsAt), writing exactly 0. A
// write by name can land on another file swapped in at the name since the
// fstatat, so it can never set a flag: a flagged file cannot be hard-linked
// (measured, U195), so a file the service user links in has no flags, and
// 0 leaves it as it was. Clearing the entry's other user flags (hidden,
// nodump) with the locking ones costs nothing, since it is about to be
// unlinked. The name is then stat'ed again: when it is no longer the file
// st describes (device, inode, owner), a Warn names the scope and leave is
// true, so it counts as not cleared and the next pass sees it anew; when
// it still carries a user locking flag the error says so.
func (w *rmWalk) clearUnopened(pfd int, name, rel string, st *unix.Stat_t) (leave bool, err error) {
	if st.Nlink != 1 || statFlags(st)&sfFlagsMask != 0 {
		return false, nil
	}
	if w.opens >= flagOpenLimit {
		return false, errScopeFlagBudget
	}
	w.opens++
	err = setFlagsAt(pfd, name, 0)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("clear the user flags of the entry %s (named for reading, not for pasting): %w", quoteName(filepath.Join(w.base, rel)), err)
	}
	var got unix.Stat_t
	if err := unix.Fstatat(pfd, name, &got, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("stat %s: %w", quoteName(name), err)
	}
	if got.Dev != st.Dev || got.Ino != st.Ino || got.Uid != st.Uid {
		slog.Warn("rm-scope's flag clear by name found another file at the name afterwards; it wrote 0, which sets no flag, and leaves the name for the next pass", "scope", w.scope)
		return true, nil
	}
	if statFlags(&got)&userLockingFlags != 0 {
		return false, fmt.Errorf("setattrlistat left a user flag (flags %#x) on the entry %s (named for reading, not for pasting)", statFlags(&got), quoteName(filepath.Join(w.base, rel)))
	}
	return false, nil
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
