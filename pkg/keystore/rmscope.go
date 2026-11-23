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
	"syscall"
	"unicode"

	"golang.org/x/sys/unix"
)

// errScopeHasDeliveries refuses an rm-scope of a scope whose delivery
// record names any delivery: removing it would leave each delivered Secret
// with no record to find it by, and rm-scope's revocation of those Secrets
// (docs/design/keystore.md § "rm-scope revokes first") is not built yet.
var errScopeHasDeliveries = errors.New("the scope's delivery record names deliveries, and rm-scope does not yet delete their Secrets: withdraw each delivery first; nothing was changed")

// RemoveScopeResult is what a clean RemoveScope did.
type RemoveScopeResult struct {
	// Recorded reports whether the removed scope is listed in the
	// removed-scopes record; false when the record is full.
	Recorded bool
	// Cleared, when set, says rm-scope cleared a user flag on the shared
	// .user directory to remove the scope directory in it: a line of the
	// verb's output. When the run is committed, or stops after clearing
	// it, the error carries it instead (withCleared, rmStopped).
	Cleared string
}

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
// not stop the removal: Recorded reports false, the scope is removed
// unlisted, and floor --rebuild keeps its floor keys (fail closed for a
// copy-back). A record that does not read refuses, changing nothing.
//
// A scope.key the judge refuses only for its link count or mode, which any
// local user can cause, is read again without those two checks
// (openScopeForRmLoose): when it authenticates under the master it is
// listed and the tree removed, and the result is errCommitted, noting the
// link count or mode. A scope.key that is present but does not parse or
// authenticate (errScopeKeyUntrusted) is treated as a missing one.
//
// The directory held at the name is checked before anything in it is
// taken (rmRun.check, the rerun rule). The service user cannot create a
// root-owned directory, and cannot move one into .user from another
// parent: the only root-owned 0700 directory it can put at .user/<uid> is
// another uid's leftover that an earlier rm-scope took, renamed within
// .user, and no open ever serves a taken directory. So a root-owned 0700
// directory held at the name (the owner and device rule already passed) is
// always removed, whatever scope.key it holds, and a stop anywhere after a
// take leaves a directory a rerun accepts. A service user's directory is
// removed only on what was judged: on the judged path its scope.key must
// open to the judged identity; on the paths without one it must hold what
// the path found (no scope.key, or one that cannot be trusted), or a key
// already listed for the uid. Before the removal, a scope.key in the held
// directory that opens as this scope's is listed when the record does not
// list it yet, and the record is made durable again when it already did.
//
// The result says the scope is removed and listed (a nil error, Recorded)
// only when the identity of the scope.key read in the held directory is in
// the record (has); a directory that held no key, or an untrusted one, is
// removed with errCommitted, saying its key could not be confirmed as
// listed. A directory gone from its name when the walk opens it is never
// reported removed.
func (s *FileStore) RemoveScope(ctx context.Context, uid uint32) (RemoveScopeResult, error) {
	if err := s.checkConfig(); err != nil {
		return RemoveScopeResult{}, err
	}
	if err := s.eligibleUID(uid); err != nil {
		return RemoveScopeResult{}, err
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		return RemoveScopeResult{}, err
	}
	defer func() { _ = root.Close() }() // removals are fsynced in their directories
	fl, unlock, err := s.lockMaintenance(ctx, root)
	if err != nil {
		return RemoveScopeResult{}, err
	}
	defer fl.unlock()
	defer unlock()
	k, err := s.loadMasterLocked()
	if err != nil {
		return RemoveScopeResult{}, err
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return RemoveScopeResult{}, fmt.Errorf("%w; nothing was changed", err)
	}
	defer func() { _ = unix.Close(dfd) }() // the record's rename is fsynced in it
	removed, err := s.readRemovedScopes(dfd)
	if err != nil {
		return RemoveScopeResult{}, fmt.Errorf("%w; nothing was changed", err)
	}
	name := strconv.FormatUint(uint64(uid), 10)
	svc := rmServiceUID(s)
	u := &UserScope{s: s, uid: uid, scope: userScopeOf(uid), allowRemoved: true}
	r := &rmRun{s: s, u: u, k: k, removed: removed, dfd: dfd, svc: svc, name: name}
	if scopeDirTaken(root, name, svc) {
		// An earlier rm-scope took the directory from the service user, then
		// stopped: no open serves a root-owned scope directory, and the
		// rerun rule removes it whatever it holds.
		r.path = rmPathTaken
		return r.finish(root, fmt.Sprintf("the directory %s, which an earlier rm-scope took from the service user, is partly or wholly present", quoteName("keystore/"+userScopesName+"/"+name)), nil)
	}
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
		// is removed unconfirmed, as with no scope.key, and its floor lines
		// are kept. Refusing would leave a scope rebuild refuses and names
		// rm-scope for.
		r.path, r.untrusted = rmPathUntrusted, err
		return r.finish(root, fmt.Sprintf("the directory %s has a scope.key that cannot be trusted and is partly or wholly present", quoteName("keystore/"+userScopesName+"/"+name)), nil)
	}
	if errors.Is(err, errNoScopeKey) && scopeDirPresent(root, name) {
		// An earlier rm-scope removed scope.key, then stopped, or the
		// service user did: no open serves the directory.
		r.path = rmPathNoKey
		return r.finish(root, fmt.Sprintf("the directory %s has no scope.key and is partly or wholly present", quoteName("keystore/"+userScopesName+"/"+name)), nil)
	}
	if err != nil {
		return RemoveScopeResult{}, fmt.Errorf("open the scope %s: %w; nothing was changed: repair what the error names (sudo k3sm doctor lists it), then rerun", u.scope, err)
	}
	id := o.id
	recorded := removed.has(uid, id)
	_, ds, derr := rmReadDeliveries(u, o)
	_, eerr := o.dir.Lstat(scopeEntriesName)
	o.close()
	var unread error
	switch {
	case recorded:
		// An earlier rm-scope listed the key, then stopped part-way.
	case derr == nil && len(ds) > 0:
		return RemoveScopeResult{}, fmt.Errorf("%s: %w", u.scope, errScopeHasDeliveries)
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
		return RemoveScopeResult{}, fmt.Errorf("read the delivery record of %s: %s; nothing was changed; run it again", u.scope, safeText(derr.Error()))
	}
	// The judged key is listed, or the record made durable again, before
	// the walk: the tree is then removed only while the directory at the
	// name holds that scope.key (or is a taken leftover, rmRun.check).
	r.path, r.judged = rmPathJudged, id
	if err := r.list(id); err != nil {
		return RemoveScopeResult{Recorded: r.wrote || r.renewed}, err
	}
	var notes []string
	if judged != "" {
		notes = append(notes, scopeRemovedJudged(u.scope, judged, r.removed.has(uid, id)))
	}
	if unread != nil {
		notes = append(notes, scopeRemovedUnread(u.scope, unread))
	}
	state := "is listed as removed in " + removedScopesName + ", so no open serves it"
	if !r.removed.has(uid, id) {
		state = "is not listed in " + removedScopesName + ", which is full"
	}
	return r.finish(root, fmt.Sprintf("the scope %s %s, and its directory %s is partly or wholly present", u.scope, state, quoteName("keystore/"+userScopesName+"/"+name)), notes)
}

// rmServiceUID is the service user RemoveScope judges owners by; tests
// replace it to stand for another uid, so their own 0700 directories are
// root's, as an earlier run's take leaves them.
var rmServiceUID = func(s *FileStore) uint32 { return s.uid }

// rmPath is which of RemoveScope's paths removes the tree: the judged
// path, with a judged key identity, or a path without one: a directory an
// earlier run took (rmPathTaken), one with no scope.key (rmPathNoKey), or
// one whose scope.key cannot be trusted (rmPathUntrusted).
type rmPath int

const (
	rmPathJudged rmPath = iota
	rmPathTaken
	rmPathNoKey
	rmPathUntrusted
)

// rmRun is one RemoveScope's state around its walk: the path, the judged
// identity (rmPathJudged only), what the check read in the held directory
// (held, once read), and what it did to the record: wrote it (wrote),
// rewrote a record already listing the key to make it durable again
// (renewed), or found it full (full). stopErr is a record failure's own
// complete error, returned as it stands.
type rmRun struct {
	s         *FileStore
	u         *UserScope
	k         keys
	removed   *removedScopes
	dfd       int
	svc       uint32
	name      string
	path      rmPath
	judged    string
	untrusted error
	held      heldKey
	heldRead  bool
	wrote     bool
	renewed   bool
	full      bool
	stopErr   error
}

// check is the rerun rule, run on the scope directory held at the name
// before anything in it is taken. A directory root owns (at 0700 on .user's
// device: removeScopeTree's owner rule passed, and st.Uid is not the
// service user's) is always accepted: the service user can place no
// root-owned directory at the name but another uid's taken leftover, and a
// taken directory is never served, so finishing its removal is safe. A
// service user's directory is accepted on the judged path only while its
// scope.key opens to the judged identity; on the other paths when its
// scope.key is already listed for the uid, or when it holds what the path
// found: no scope.key on the no-key path, one that does not open as this
// scope's on the untrusted path; the taken path accepts none (root's
// directory was judged). A scope.key that opens as this scope's and is not
// listed is a valid, unlisted scope, never removed without its judge.
// Once accepted, a scope.key that opens as this scope's is listed, or the
// record made durable again (list), before anything is taken.
func (r *rmRun) check(dfd int, st *unix.Stat_t) (string, error) {
	hk, err := r.u.scopeKeyAt(dfd, r.k)
	if err != nil {
		return "", err
	}
	if st.Uid == r.svc {
		if why := r.serviceUserRule(hk); why != "" {
			return why, nil
		}
	}
	r.held, r.heldRead = hk, true
	if hk.id == "" {
		return "", nil
	}
	return "", r.list(hk.id)
}

// serviceUserRule is check's rule for a directory the service user owns:
// a non-empty why refuses it.
func (r *rmRun) serviceUserRule(hk heldKey) string {
	if r.path == rmPathJudged {
		switch {
		case !hk.present:
			return "it holds no scope.key, and the scope rm-scope judged had one"
		case hk.id != r.judged:
			return "its scope.key is not the one rm-scope judged and listed"
		}
		return ""
	}
	switch {
	case hk.id != "" && r.removed.has(r.u.uid, hk.id):
		return ""
	case r.path == rmPathTaken:
		return "rm-scope found root's directory at the name, which an earlier rm-scope took, and the service user's is there now"
	case hk.id != "":
		return "it holds a scope.key that opens as this scope's and is not listed as removed"
	case r.path == rmPathNoKey && hk.present:
		return "rm-scope found no scope.key there, and one is there now"
	case r.path == rmPathUntrusted && !hk.present:
		return "rm-scope found a scope.key it could not trust there, and none is there now"
	}
	return ""
}

// list lists uid's scope key id in the record before the removal, through
// the normal writer (writeRemovedScopes: temporary file, fsync, rename,
// fsync of the data root), with the floor's size at this moment. When the
// record lists id already and this run has not written it, it is
// rewritten through the same writer, so the listing a rerun relies on is
// durable again. A full record lists nothing (full). Its errors are
// complete (stopErr): a failure before the rename is a refusal, nothing
// changed; one after it, or any failure of a rewrite, is errCommitted,
// saying the record lists the scope but its durability is unknown.
func (r *rmRun) list(id string) error {
	uid, scope := r.u.uid, r.u.scope
	if r.removed.has(uid, id) {
		if r.wrote || r.renewed {
			return nil
		}
		r.renewed = true
		if _, err := writeRemovedScopes(r.dfd, r.removed); err != nil {
			r.stopErr = fmt.Errorf("%w: make %s durable again: %w; the record lists the scope %s but its durability is unknown, and the scope directory is untouched: rerun sudo k3sm keys rm-scope %s --yes", errCommitted, removedScopesName, err, scope, scope)
			return r.stopErr
		}
		return nil
	}
	fid, size, err := r.s.floorSize(r.dfd)
	if err != nil {
		r.stopErr = fmt.Errorf("read the size of the user-scope floor %s: %w; nothing was changed: repair what the error names (sudo k3sm doctor lists it), then rerun", userFloorLogName, err)
		return r.stopErr
	}
	if !r.removed.add(uid, id, fid, size) {
		r.full = true
		return nil
	}
	renamed, err := writeRemovedScopes(r.dfd, r.removed)
	if err != nil && renamed {
		// The rename landed: the record lists the scope, as far as any
		// later read sees, though a crash may yet lose it.
		r.wrote = true
		r.stopErr = fmt.Errorf("%w: record the removed scope %s in %s: %w; the record lists the scope but its durability is unknown, and the scope directory is untouched: rerun sudo k3sm keys rm-scope %s --yes", errCommitted, scope, removedScopesName, err, scope)
		return r.stopErr
	}
	if err != nil {
		// Nothing landed: the key add listed is dropped again.
		r.removed.drop(uid, id)
		r.stopErr = fmt.Errorf("record the removed scope %s in %s: %w; the record does not list it, and nothing was changed: rerun sudo k3sm keys rm-scope %s --yes", scope, removedScopesName, err, scope)
		return r.stopErr
	}
	r.wrote = true
	return nil
}

// proven reports whether the scope.key read in the held directory opened
// as this scope's and its identity is in the record: the only ground for
// saying the removal is listed.
func (r *rmRun) proven() bool {
	return r.heldRead && r.held.id != "" && r.removed.has(r.u.uid, r.held.id)
}

// finish removes the tree under check and reports it: state says what
// remains when the walk stops, notes are the judged path's committed notes.
func (r *rmRun) finish(root *os.Root, state string, notes []string) (RemoveScopeResult, error) {
	uid, scope := r.u.uid, r.u.scope
	tree, err := removeScopeTree(root, r.s.dir, r.name, r.svc, rmTreeOpts{listedNow: r.proven, check: r.check})
	if r.stopErr != nil {
		return RemoveScopeResult{Recorded: r.wrote || r.renewed}, r.stopErr
	}
	if err != nil {
		if errors.Is(err, errNotJudgedScope) && r.wrote {
			err = fmt.Errorf("%w; %s now lists the key of %s that rm-scope judged, so no open serves that key", err, removedScopesName, scope)
		}
		return RemoveScopeResult{Recorded: r.proven()}, rmStopped(err, r.wrote || tree.changed, state, scope, tree.cleared)
	}
	if tree.absent {
		switch {
		case r.wrote:
			return RemoveScopeResult{Recorded: true}, fmt.Errorf("%w: rm-scope listed %s in %s, but the directory was not at its name: found absent when it came to remove it, so it removed nothing", errCommitted, scope, removedScopesName)
		case r.renewed:
			return RemoveScopeResult{Recorded: true}, fmt.Errorf("%w: %s is listed in %s, but the directory was not at its name: found absent when rm-scope came to remove it, so it removed nothing", errCommitted, scope, removedScopesName)
		}
		return RemoveScopeResult{}, fmt.Errorf("rm-scope found the directory of %s absent at its name when it came to remove it: nothing was changed and nothing removed", scope)
	}
	switch {
	case r.proven():
		if len(notes) > 0 {
			return RemoveScopeResult{Recorded: true}, fmt.Errorf("%w: %s", errCommitted, withCleared(strings.Join(notes, "; "), tree.cleared))
		}
		return RemoveScopeResult{Recorded: true, Cleared: tree.cleared}, nil
	case r.full && r.held.id != "":
		// The key opened as this scope's, and the record is full.
		if len(notes) > 0 {
			return RemoveScopeResult{}, fmt.Errorf("%w: %s", errCommitted, withCleared(strings.Join(notes, "; "), tree.cleared))
		}
		return RemoveScopeResult{Cleared: tree.cleared}, nil
	}
	note := scopeRemovedUnconfirmed(scope, r.held, r.untrusted, r.removed.count(uid))
	if len(notes) > 0 {
		note = strings.Join(append(notes, note), "; ")
	}
	return RemoveScopeResult{}, fmt.Errorf("%w: %s", errCommitted, withCleared(note, tree.cleared))
}

// rmStopped is RemoveScope's error for a removeScopeTree of scope that
// failed (err), followed by state, which says what remains, and the rerun
// that finishes it, unless the stop would stop a rerun the same way
// (rmRerunCannotHelp): then its own text says what was left. A directory at the name that is not the scope judged
// (errNotJudgedScope) is not what remains of the scope, so neither state
// nor a rerun is said. cleared, removeScopeTree's note of a flag it
// cleared on .user before it stopped, is carried at the end. When this run changed something first (changed: it wrote the
// removed-scopes record, or the walk unlinked an entry, took a directory or
// cleared a flag), the removal was made in part and the error is committed
// (exit 4, audited committed); otherwise it is a refusal.
func rmStopped(err error, changed bool, state, scope, cleared string) error {
	switch {
	case errors.Is(err, errNotJudgedScope):
		// The directory at the name is not the scope's: what remains of
		// the scope is not there, and a rerun would judge that directory.
		state = ""
	case !rmRerunCannotHelp(err):
		state += ": rerun sudo k3sm keys rm-scope " + scope + " --yes to finish removing it"
	}
	if state != "" {
		err = fmt.Errorf("%w; %s", err, state)
	}
	if cleared != "" {
		err = fmt.Errorf("%w; %s", err, cleared)
	}
	if changed {
		return fmt.Errorf("%w: rm-scope began removing the scope, then stopped: %w", errCommitted, err)
	}
	return err
}

// rmRerunCannotHelp reports whether err stops a rerun of rm-scope the
// same way, so rmStopped offers none: a directory that is not the scope's
// (errScopeForeignDir), a tree nested too deep (errScopeTreeDeep), an
// emptied scope directory no longer at its name (errScopeDirMoved), a
// planted name (errPlanted), or another user's flag on .user
// (errSharedDirFlag).
func rmRerunCannotHelp(err error) bool {
	for _, e := range []error{errScopeForeignDir, errScopeTreeDeep, errScopeDirMoved, errPlanted, errSharedDirFlag} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// withCleared is the committed note with removeScopeTree's report of a
// flag it cleared on .user, when there is one.
func withCleared(note, cleared string) string {
	if cleared == "" {
		return note
	}
	return note + "; " + cleared
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

// scopeRemovedUnconfirmed is rm-scope's committed report for a scope
// directory removed whose held scope.key gave no listed identity: none
// (held.present false), or one that does not open as this scope's
// (untrusted, the judge's error, when that path found it). n is how many
// keys the record lists for the uid: whether the removed directory's key
// was among them cannot be told, so a copy put back may open.
func scopeRemovedUnconfirmed(scope string, held heldKey, untrusted error, n int) string {
	why := "its scope.key was absent (an interrupted earlier rm-scope, or tampering)"
	if held.present {
		why = "its scope.key could not be trusted"
		if untrusted != nil {
			why += " (" + safeText(untrusted.Error()) + ")"
		}
	}
	if n == 0 {
		return "removed " + scope + " without listing it in " + removedScopesName + ", because " + why + "; the record lists no key for this uid, so " + unlistedCopyBack
	}
	return fmt.Sprintf("removed the directory of %s, but %s, so rm-scope could not confirm that its key is listed in %s, which lists %d keys for this uid; if it is not among them, %s", scope, why, removedScopesName, n, unlistedCopyBack)
}

// unlistedCopyBack is what an unlisted removal leaves open: the service
// user can put back a copy of the directory, key file and all, and it
// opens again, held only to the scope's floor lines, which are kept.
const unlistedCopyBack = "a copy of its directory put back by the service user opens again, held only to the scope's floor lines, which are kept, so the floor still refuses an entry rolled back or deleted against them"

// scopeDirTaken reports whether keystore/.user/<name> is a directory root
// owns at mode 0700 and the service user (svc) does not: an earlier
// rm-scope's take (rmTakeDir), which the service user cannot make.
func scopeDirTaken(root *os.Root, name string, svc uint32) bool {
	fi, err := root.Lstat(userScopesName + "/" + name)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == rmRootUID && st.Uid != svc && st.Mode&0o7777 == 0o700
}

// scopeDirPresent reports whether keystore/.user/<name> names anything.
func scopeDirPresent(root *os.Root, name string) bool {
	_, err := root.Lstat(userScopesName + "/" + name)
	return err == nil
}

const (
	// maxScopeTreeDepth bounds the descent below the scope directory, one
	// descriptor per level: the layout puts files two levels down.
	maxScopeTreeDepth = 32
	// maxTakeAttempts bounds how often rm-scope clears a directory's user
	// flags and tries again to take it, while its owner, still the service
	// user, keeps setting them.
	maxTakeAttempts = 3
	// maxForeignDirs bounds how many directories that are not the scope's
	// one walk leaves in place before it stops.
	maxForeignDirs = 16
)

// rmRootUID and rmRootGID are the owner rm-scope gives each directory of
// the scope tree before it touches the directory's entries: root. A
// non-root test run sets its own ids (TestMain).
var rmRootUID, rmRootGID = 0, 0

// rmDirBatch is how many names rm-scope reads from a directory before it
// removes them and reads again from the start; tests lower it.
var rmDirBatch = dirBatch

// rmReadBatch is rm-scope's listing of a directory (readBatch); tests
// wrap it to see every listing the walk makes.
var rmReadBatch = readBatch

// rmTakeDir takes the directory held at fd from the service user, all on
// the descriptor: fchmod 0700, fchown to root, fchmod 0700 again, its
// extended ACL removed, then fstat, which must show root's at 0700. No
// service-user process can then create a name in it or rename one into
// it. The first fchmod comes before the fchown, so a take that stops after
// it leaves a service user's 0700 directory, and one that stops after the
// fchown a root-owned 0700 one: the owner rule accepts both, and a rerun
// finishes either. On macOS an entry in it that carries an ACL entry
// allowing its deletion can still be renamed out of it or unlinked by that
// process; the walk takes each name as it finds it. Tests wrap it to stop
// a walk part-way.
var rmTakeDir = func(fd int) error {
	for step := range rmTakeSteps {
		if rmTakeStep != nil {
			if err := rmTakeStep(step); err != nil {
				return err
			}
		}
		if err := rmTakeSteps[step](fd); err != nil {
			return err
		}
	}
	return nil
}

// rmTakeSteps are rmTakeDir's steps, in order.
var rmTakeSteps = [...]func(fd int) error{
	func(fd int) error { return unix.Fchmod(fd, 0o700) },
	func(fd int) error { return unix.Fchown(fd, rmRootUID, rmRootGID) },
	func(fd int) error { return unix.Fchmod(fd, 0o700) },
	removeExtendedACL,
	func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if int(st.Uid) != rmRootUID || st.Mode&0o7777 != 0o700 {
			return fmt.Errorf("after the take it is uid %d's at mode %#o, not root's at 0700", st.Uid, st.Mode&0o7777)
		}
		return nil
	},
}

// rmTakeStep, when set, runs before each of rmTakeDir's steps (its index
// in rmTakeSteps); tests return an error to stop the take there.
var rmTakeStep func(step int) error

// errScopeTreeBusy is a name in a scope directory after the walk emptied
// it, or a name that kept changing, although rm-scope had taken the
// directory from the service user first.
var errScopeTreeBusy = errors.New("names changed in a scope directory after rm-scope took it from the service user, which only root can now do")

// errScopeForeignDir is a directory in the scope tree that is not the
// scope's: another user owns it, root owns it with a mode other than 0700,
// or it is on another device. rm-scope leaves it and everything in it.
var errScopeForeignDir = errors.New("a directory in the scope tree is not the scope's")

// errScopeFlagBudget is a scope tree whose locking flags would take more
// flag clears than one rm-scope run makes. The budget is per run: a rerun
// clears up to as many more.
var errScopeFlagBudget = fmt.Errorf("the scope directory holds more flagged entries than one rm-scope run unlocks (%d): run rm-scope for this scope again; each run unlocks up to %d more", maxFlagOpens, maxFlagOpens)

// rmWalk is one removeScopeTree: the service user's uid, how many entries
// it has cleared or opened to clear their flags, the scope directory's
// path, which its errors name entries under, the scope, which its warnings
// name, whether the scope is listed as removed, the device of .user, the
// baseline every directory of the tree must share, the directories it left
// in place as not the scope's, and whether it changed anything (changed).
type rmWalk struct {
	svc     uint32
	opens   int
	base    string
	scope   string
	listed  bool
	dev     uint64
	foreign []error
	// changed is set once the walk unlinks an entry, takes a directory that
	// was not already root's at 0700, or clears a flag: a failure after it
	// is a removal made in part.
	changed bool
}

// rmTree is what removeScopeTree did: cleared is its note of a flag it
// cleared on .user, when it cleared one, changed reports whether it
// changed anything in the tree or on .user, failed or not, and absent that
// there was no scope directory to remove.
type rmTree struct {
	cleared string
	changed bool
	// absent reports that the scope directory was not at its name when
	// the walk came to open it: nothing was removed.
	absent bool
}

// rmOutcome is what removeName did with a name.
type rmOutcome int

const (
	// rmGone: the name was removed, or was already gone.
	rmGone rmOutcome = iota
	// rmChanged: the name changed under the walk; the rescan sees it anew.
	rmChanged
	// rmLeft: the name is, or holds, a directory that is not the scope's,
	// left in place.
	rmLeft
)

// removeScopeTree removes keystore/.user/<uid>/ by descriptor, starting
// from keystore, the already-judged keystore root, so a directory swapped
// in at the keystore's path since it was judged is never walked. Each
// directory is opened relative to its parent with O_NOFOLLOW|O_DIRECTORY,
// re-checked with fstat against the parent's fstatat of the name
// (SameFile), and then, before any of its entries is listed or touched,
// taken from the service user (take: fchown to root, fchmod 0700, its ACL
// removed, on the held descriptor), so no service-user process can then
// create a name in it or rename one into it (on macOS an entry carrying an
// ACL entry that allows its deletion can still be renamed out). A
// subdirectory is
// descended into only when the service user owns it, or root does with mode
// 0700 (an earlier run's work), on .user's device; any other is left in
// place and the removal fails naming it (errScopeForeignDir). The scope
// directory itself is held to the same rule before it is taken: one that
// fails it is not taken, changed or emptied, and the removal fails naming
// it.
// Each directory is emptied a batch of rmDirBatch names at a time, read
// again from its start after each batch until a read returns none, and
// removed with unlinkat(AT_REMOVEDIR), the scope directory itself only
// while its name in .user is still the directory emptied (rmdirHeld);
// every other name, whatever its type (a regular file, FIFO, symlink,
// device or socket), is removed with unlinkat, which never follows.
// scope.key goes last, once nothing else is left beside it. A name that vanishes under the walk is skipped. A name
// left in a directory the walk emptied fails it (errScopeTreeBusy).
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
// errors name entries under; listed says whether the scope is already
// listed as removed, which they report.
//
// .user itself, which every scope shares, keeps its flags unless the
// scope directory's removal from it fails with EPERM: then a user locking
// flag on it is cleared, on the held descriptor, and the removal tried
// once more, only when the service user owns it (it could clear the flag
// itself), and cleared says so for the result; another owner's flag is
// left and the removal fails naming .user.
func removeScopeTree(keystore *os.Root, dir, uid string, svc uint32, opts rmTreeOpts) (tree rmTree, err error) {
	if rmBeforeTree != nil {
		rmBeforeTree()
	}
	kd, err := keystore.Open(".")
	if err != nil {
		return rmTree{}, fmt.Errorf("open the keystore directory: %w", err)
	}
	defer func() { _ = kd.Close() }() // read-only
	ufd, ust, err := openDirAt(int(kd.Fd()), userScopesName)
	if err != nil {
		return rmTree{}, err
	}
	defer func() { _ = unix.Close(ufd) }() // fsynced below
	w := &rmWalk{svc: svc, base: filepath.Join(dir, userScopesName, uid), scope: userScopePrefix + uid, listed: opts.listed}
	defer func() { tree.changed = w.changed }()
	dfd, dst, err := openDirAt(ufd, uid)
	if errors.Is(err, unix.ENOENT) {
		return rmTree{absent: true}, unix.Fsync(ufd)
	}
	if err != nil {
		return rmTree{}, err
	}
	// The service user owns .user/ and can rename any directory in at the
	// name between the by-path judgement and this open: the held directory
	// is taken only when it passes the owner rule nested directories pass,
	// on .user's own device, which is the walk's baseline.
	w.dev = rmDev(&ust)
	if !w.owned(&dst) || rmDev(&dst) != w.dev {
		_ = unix.Close(dfd) // read-only, untouched
		return rmTree{}, fmt.Errorf("%w: the scope directory %s (named for reading, not for pasting): %s; it is not the scope's, so rm-scope took nothing, changed nothing and removed nothing in it; inspect it", errScopeForeignDir, quoteName(w.base), w.foreignWhy(&dst, ".user"))
	}
	// The name may hold another of the service user's scope directories
	// than the one judged: the held directory's own scope.key, read by
	// descriptor, must match what the caller judged (opts.check).
	if opts.check != nil {
		why, cerr := opts.check(dfd, &dst)
		if cerr == nil && why != "" {
			cerr = fmt.Errorf("%w: the directory %s (named for reading, not for pasting): %s; rm-scope took nothing, changed nothing and removed nothing in it", errNotJudgedScope, quoteName(w.base), why)
		}
		if cerr != nil {
			_ = unix.Close(dfd) // read-only, untouched
			return rmTree{}, cerr
		}
	}
	// The scope directory stays held through its rmdir, which checks on
	// this descriptor that it was the directory removed.
	defer func() { _ = unix.Close(dfd) }() // fsynced in emptyScopeDir
	err = w.take(dfd, &dst, "")
	if err == nil {
		err = w.emptyScopeDir(dfd)
	}
	if err != nil {
		return rmTree{}, err
	}
	err = w.rmdirHeld(ufd, uid, dfd, &dst)
	if errors.Is(err, unix.EPERM) {
		// .user is shared by every scope: its user locking flags are
		// cleared only when its removal of this one needs it, and only
		// when the service user owns it and could clear them itself.
		var unlocked bool
		tree.cleared, unlocked, err = w.unlockShared(ufd, err)
		if unlocked {
			w.changed = true
			err = w.rmdirHeld(ufd, uid, dfd, &dst)
		}
	}
	switch {
	case err == nil:
		w.changed = true
		return tree, unix.Fsync(ufd)
	case errors.Is(err, errScopeDirMoved):
		return tree, err
	}
	return tree, fmt.Errorf("remove the scope directory: %w", err)
}

// rmTreeOpts is how removeScopeTree treats one scope: check, when set,
// judges the scope directory held at the name before anything in it is
// taken: a non-empty why refuses it (errNotJudgedScope); listed says
// whether the scope is listed as removed, which its errors report, unless
// listedNow is set: then it is asked after the check, which may list it.
type rmTreeOpts struct {
	listed    bool
	listedNow func() bool
	check     func(dfd int, st *unix.Stat_t) (why string, err error)
}

// rmBeforeTree, when set, runs as removeScopeTree starts, after
// RemoveScope's judge; tests swap the name.
var rmBeforeTree func()

// errNotJudgedScope is a directory at the scope's name in .user that is
// not the scope RemoveScope judged: rm-scope takes nothing in it.
var errNotJudgedScope = errors.New("the directory at the scope's name is not the scope rm-scope judged")

// heldKey is what the scope directory held at a descriptor holds as
// scope.key: nothing (present false), or a file, with id its identity
// (scopeKeyID) when it opens under the master as this scope's key, and
// empty when it does not.
type heldKey struct {
	present bool
	id      string
}

// scopeKeyAt reads scope.key in the scope directory held at dfd, never by
// path: fstatat, not followed, and, only for a regular file within a scope
// key record's size, openat O_NOFOLLOW re-checked as that file (device,
// inode), read bounded, parsed (parseScopeKey) and opened under the master
// (openScopeKey; a listed key opens, since rm-scope's scope allows it). A
// FIFO, device or socket is never opened. Anything that does not parse or
// open is present with no identity; a failure to read is an error.
func (u *UserScope) scopeKeyAt(dfd int, k keys) (heldKey, error) {
	var st unix.Stat_t
	err := unix.Fstatat(dfd, scopeKeyName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return heldKey{}, nil
	}
	if err != nil {
		return heldKey{}, fmt.Errorf("stat %s in the scope directory: %w", scopeKeyName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > int64(maxScopeKeyRecordSize) {
		return heldKey{present: true}, nil
	}
	fd, err := unix.Openat(dfd, scopeKeyName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return heldKey{}, fmt.Errorf("open %s in the scope directory: %w", scopeKeyName, err)
	}
	f := os.NewFile(uintptr(fd), scopeKeyName)
	defer func() { _ = f.Close() }() // read-only
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		return heldKey{}, fmt.Errorf("stat %s in the scope directory: %w", scopeKeyName, err)
	}
	if got.Dev != st.Dev || got.Ino != st.Ino {
		return heldKey{}, fmt.Errorf("%s in the scope directory was replaced while rm-scope read it", scopeKeyName)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(maxScopeKeyRecordSize)+1))
	if err != nil {
		return heldKey{}, fmt.Errorf("read %s in the scope directory: %w", scopeKeyName, err)
	}
	if len(b) > maxScopeKeyRecordSize {
		return heldKey{present: true}, nil
	}
	r, err := parseScopeKey(b)
	if err != nil {
		return heldKey{present: true}, nil
	}
	ku, err := u.openScopeKey(r, k)
	if errors.Is(err, ErrCorrupt) {
		return heldKey{present: true}, nil
	}
	if err != nil {
		return heldKey{}, err
	}
	id := scopeKeyID(u.scope, ku)
	clear(ku)
	return heldKey{present: true, id: id}, nil
}

// errScopeDirMoved is a scope directory rm-scope emptied that was no longer
// at its name in .user when it came to remove it.
var errScopeDirMoved = errors.New("the scope directory was moved away from its name after rm-scope emptied it, and is not removed")

// rmdirStep is where rmBeforeScopeRmdir runs in rmdirHeld.
type rmdirStep int

const (
	// rmdirBeforeStat: before the name is stat'ed.
	rmdirBeforeStat rmdirStep = iota
	// rmdirBeforeUnlink: after the stat matched, before the unlinkat.
	rmdirBeforeUnlink
)

// rmBeforeScopeRmdir, when set, runs at each step of rm-scope's final
// removal of the scope directory; tests swap the name.
var rmBeforeScopeRmdir func(rmdirStep)

// rmGoneProbe is the name rmdirHeld creates in the held scope directory to
// learn whether the unlinkat removed it: a removed directory refuses a new
// name (ENOENT), one still linked takes it.
const rmGoneProbe = ".rm-scope-removed-check"

// rmdirHeld removes the name uid from .user, held at ufd, only while it is
// still the emptied directory held at fd, which held describes: .user is
// the service user's, so the name can be renamed away or another
// directory put at it. The name is stat'ed (not followed) first, and a
// different device or inode removes nothing; a name missing then, or at
// the unlinkat, is errScopeDirMoved, never success. The name can still
// change between the stat and the unlinkat, so after the unlinkat removes a
// directory the held one is asked whether it was it: on macOS (APFS) an
// fstat of a removed directory still held open reports its link count as
// before (2), so the link count cannot say; mkdirat of rmGoneProbe in it
// fails with ENOENT once it is removed, on macOS and Linux alike. When it
// is still linked, the probe is removed again and the error says another
// directory was removed at the name and the emptied one remains. Every
// failure here is errScopeDirMoved: the emptied directory is not at the
// name, and a rerun would meet whatever is.
func (w *rmWalk) rmdirHeld(ufd int, uid string, fd int, held *unix.Stat_t) error {
	if rmBeforeScopeRmdir != nil {
		rmBeforeScopeRmdir(rmdirBeforeStat)
	}
	var st unix.Stat_t
	err := unix.Fstatat(ufd, uid, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return w.moved()
	}
	if err != nil {
		return fmt.Errorf("stat the scope directory: %w", err)
	}
	if st.Dev != held.Dev || st.Ino != held.Ino {
		return fmt.Errorf("%w: the name %s (named for reading, not for pasting) is no longer the directory rm-scope emptied, so nothing at it was removed", errScopeDirMoved, quoteName(w.base))
	}
	if rmBeforeScopeRmdir != nil {
		rmBeforeScopeRmdir(rmdirBeforeUnlink)
	}
	err = unix.Unlinkat(ufd, uid, unix.AT_REMOVEDIR)
	switch {
	case errors.Is(err, unix.ENOENT):
		return w.moved()
	case errors.Is(err, unix.ENOTEMPTY), errors.Is(err, unix.EEXIST):
		return fmt.Errorf("%w: a non-empty directory is now at the name %s (named for reading, not for pasting), so nothing at it was removed", errScopeDirMoved, quoteName(w.base))
	case errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%w: something other than a directory is now at the name %s (named for reading, not for pasting), so nothing at it was removed", errScopeDirMoved, quoteName(w.base))
	case err != nil:
		return err
	}
	w.changed = true
	err = unix.Mkdirat(fd, rmGoneProbe, 0o700)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil
	case err == nil:
		_ = unix.Unlinkat(fd, rmGoneProbe, unix.AT_REMOVEDIR) // the held directory is root's; the probe goes again
		fallthrough
	case errors.Is(err, unix.EEXIST):
		return fmt.Errorf("%w: another directory was removed at the name %s (named for reading, not for pasting), and the emptied one remains, no longer at that name", errScopeDirMoved, quoteName(w.base))
	}
	return fmt.Errorf("%w: a directory was removed at the name %s (named for reading, not for pasting), and rm-scope could not tell whether it was the emptied one: %w", errScopeDirMoved, quoteName(w.base), err)
}

// moved is errScopeDirMoved naming the scope directory's name.
func (w *rmWalk) moved() error {
	return fmt.Errorf("%w: %s (named for reading, not for pasting)", errScopeDirMoved, quoteName(w.base))
}

// errSharedDirFlag is a user flag on the shared .user directory that
// another user than the service user owns: rm-scope clears nothing on it,
// so a rerun meets it again.
var errSharedDirFlag = errors.New("a user flag on the shared directory, owned by another user than the service user, stops the scope directory's removal")

// rmSharedOwner is the owner unlockShared judges .user by; tests replace
// it to stand for another user.
var rmSharedOwner = func(st *unix.Stat_t) uint32 { return st.Uid }

// unlockShared answers the EPERM (perm) of the scope directory's removal
// from .user, held at ufd. When .user carries a user locking flag and no
// system flag, and the service user owns it, the flags are cleared on the
// descriptor and unlocked is true, with cleared the note that says so;
// when another user owns it, nothing is cleared and the error names it.
// Otherwise err is perm, for the caller to report.
func (w *rmWalk) unlockShared(ufd int, perm error) (cleared string, unlocked bool, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(ufd, &st); err != nil {
		return "", false, err
	}
	fl := statFlags(&st)
	if fl&userLockingFlags == 0 || fl&sfFlagsMask != 0 {
		return "", false, perm
	}
	shared := quoteName(filepath.Dir(w.base))
	if owner := rmSharedOwner(&st); owner != w.svc {
		return "", false, fmt.Errorf("%w: %w: the shared directory %s (named for reading, not for pasting) carries a user flag (uchg, uappnd or uunlnk; flags %#x), and uid %d owns it, not the service user (uid %d), so rm-scope clears nothing on it; the scope directory in it is emptied and root's", errSharedDirFlag, perm, shared, fl, owner, w.svc)
	}
	if err := scopeFchflags(ufd, int(fl&^userLockingFlags)); err != nil {
		return "", false, fmt.Errorf("clear the user flags of the shared directory %s (named for reading, not for pasting): %w", shared, err)
	}
	return fmt.Sprintf("rm-scope cleared a user flag (flags %#x) on the shared directory %s (named for reading, not for pasting), which the service user owns and could clear itself, to remove the scope directory in it", fl, shared), true, nil
}

// take clears the user locking flags of the directory held at fd, which
// st describes, and takes it from the service user (rmTakeDir), before any
// of its entries is listed. Its owner can set a flag again between the
// two, which fails the fchown with EPERM; it is cleared and the take tried
// again, at most maxTakeAttempts times. rel is the directory below the
// scope directory, which the error names.
func (w *rmWalk) take(fd int, st *unix.Stat_t, rel string) error {
	for attempt := 1; ; attempt++ {
		if err := w.clearHeld(fd, st); err != nil {
			return err
		}
		err := rmTakeDir(fd)
		if err == nil {
			if !w.taken(st) {
				w.changed = true
			}
			return nil
		}
		// A take that failed part-way may have changed the owner or mode
		// already.
		var now unix.Stat_t
		if serr := unix.Fstat(fd, &now); serr != nil || now.Uid != st.Uid || now.Mode != st.Mode {
			w.changed = true
		}
		if !errors.Is(err, unix.EPERM) || attempt == maxTakeAttempts {
			return fmt.Errorf("take the directory %s (named for reading, not for pasting) from the service user: %w", quoteName(filepath.Join(w.base, rel)), err)
		}
		if err := unix.Fstat(fd, st); err != nil {
			return err
		}
	}
}

// taken reports whether the directory st describes is already root's at
// 0700, so a take changes nothing of it.
func (w *rmWalk) taken(st *unix.Stat_t) bool {
	return int(st.Uid) == rmRootUID && st.Mode&0o7777 == 0o700
}

// busy is errScopeTreeBusy for the directory rel below the scope
// directory.
func (w *rmWalk) busy(rel string) error {
	return fmt.Errorf("%w: the directory %s (named for reading, not for pasting)", errScopeTreeBusy, quoteName(filepath.Join(w.base, rel)))
}

// ours reports whether the directory st describes is the scope's to
// descend into: the service user owns it, or root does with mode 0700 (an
// earlier rm-scope took it, then stopped), and it is on .user's device,
// which the scope directory shares. Otherwise it records why in w.foreign.
func (w *rmWalk) ours(rel string, st *unix.Stat_t) bool {
	if w.owned(st) && rmDev(st) == w.dev {
		return true
	}
	w.foreign = append(w.foreign, fmt.Errorf("%w: the directory %s (named for reading, not for pasting): %s; it may have been renamed into the tree from a directory it shares with another user, so rm-scope left it and everything in it in place, and the scope directory that holds it stays; what it holds may be another user's", errScopeForeignDir, quoteName(filepath.Join(w.base, rel)), w.foreignWhy(st, "the scope directory")))
	return false
}

// owned reports whether the directory st describes passes the scope's
// owner rule: the service user owns it, or root does with mode 0700 (an
// earlier rm-scope took it, then stopped).
func (w *rmWalk) owned(st *unix.Stat_t) bool {
	return st.Uid == w.svc || (int(st.Uid) == rmRootUID && st.Mode&0o7777 == 0o700)
}

// foreignWhy says why the directory st describes is not the scope's: its
// owner and mode, or, when those pass, its device, unlike baseline's.
func (w *rmWalk) foreignWhy(st *unix.Stat_t, baseline string) string {
	if w.owned(st) {
		return "it is on another device than " + baseline
	}
	return fmt.Sprintf("uid %d owns it with mode %#o, and it is neither the service user's (uid %d) nor root's at 0700", st.Uid, st.Mode&0o7777, w.svc)
}

// rmDev is the device st describes, as one type on every OS (st_dev is
// int32 on Darwin, uint64 on Linux); tests replace it to report another
// device for a chosen inode.
var rmDev = func(st *unix.Stat_t) uint64 { return uint64(st.Dev) }

// foreignErr is the error for the directories the walk left as not the
// scope's.
func (w *rmWalk) foreignErr() error {
	if len(w.foreign) == 1 {
		return w.foreign[0]
	}
	return errors.Join(w.foreign...)
}

// emptyScopeDir removes every name in the scope directory dfd, scope.key
// last and only when nothing else is left beside it, on every path: a stop
// part-way leaves the key a rerun reads to list the removal.
func (w *rmWalk) emptyScopeDir(dfd int) error {
	if err := w.emptyDir(dfd, "", 0, scopeKeyName); err != nil {
		return err
	}
	if len(w.foreign) > 0 {
		return w.foreignErr()
	}
	// The directory is root's: no name can appear, and this one re-list is
	// a check.
	names, err := rmReadBatch(dfd, 2, nil)
	if err != nil {
		return err
	}
	switch {
	case len(names) == 1 && names[0] == scopeKeyName:
		if _, err := w.removeName(dfd, "", scopeKeyName, 0); err != nil {
			return err
		}
	case len(names) > 0:
		return w.busy("")
	}
	return unix.Fsync(dfd)
}

// emptyDir removes every name in the directory dfd but keep, at rel and
// depth below the scope directory, rmDirBatch names at a time, reading
// again from the start after each batch until a read returns none, so
// memory is bounded by the batch whatever the directory holds. A directory
// left as not the scope's is skipped from then on. A batch in which no name
// went and none was left fails it (errScopeTreeBusy): the directory is
// root's, so no name can keep changing.
func (w *rmWalk) emptyDir(dfd int, rel string, depth int, keep string) error {
	skip := map[string]bool{}
	if keep != "" {
		skip[keep] = true
	}
	for {
		names, err := rmReadBatch(dfd, rmDirBatch, skip)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			return nil
		}
		progress := false
		for _, n := range names {
			out, err := w.removeName(dfd, rel, n, depth)
			if err != nil {
				return err
			}
			switch out {
			case rmGone:
				progress = true
			case rmLeft:
				skip[n] = true
				progress = true
				if len(w.foreign) >= maxForeignDirs {
					return w.foreignErr()
				}
			}
		}
		if !progress {
			return w.busy(rel)
		}
	}
}

// removeName removes name in the directory pfd, rel below the scope
// directory: a directory is opened by descriptor (openDirAt), checked as
// the scope's (ours), taken from the service user (take), emptied and
// removed with AT_REMOVEDIR; any other name has its user flags cleared
// (clearScopeFlags) and is removed with unlinkat, unless it changed under
// the walk (rmChanged). A name already gone is rmGone.
func (w *rmWalk) removeName(pfd int, rel, name string, depth int) (rmOutcome, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return rmGone, nil
	} else if err != nil {
		return 0, fmt.Errorf("stat %s: %w", quoteName(name), err)
	}
	rel = filepath.Join(rel, name)
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		leave, err := w.clearScopeFlags(pfd, name, rel, &st)
		if err != nil {
			return 0, err
		}
		if leave {
			return rmChanged, nil
		}
		if err := unix.Unlinkat(pfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return 0, w.flagKept(rel, &st, err)
		} else if err == nil {
			w.changed = true
		}
		return rmGone, nil
	}
	if depth >= maxScopeTreeDepth {
		return 0, w.tooDeep(rel)
	}
	if !w.ours(rel, &st) {
		return rmLeft, nil
	}
	fd, dst, err := openDirAt(pfd, name)
	if errors.Is(err, unix.ENOENT) {
		return rmGone, nil
	}
	if err != nil {
		return 0, err
	}
	if !w.ours(rel, &dst) {
		_ = unix.Close(fd) // read-only, untouched
		return rmLeft, nil
	}
	left := len(w.foreign)
	err = w.take(fd, &dst, rel)
	if err == nil {
		err = w.emptyDir(fd, rel, depth+1, "")
	}
	if err == nil {
		err = unix.Fsync(fd)
	}
	_ = unix.Close(fd) // fsynced above
	if err != nil {
		return 0, fmt.Errorf("%s: %w", quoteName(name), err)
	}
	if len(w.foreign) > left {
		return rmLeft, nil
	}
	err = unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR)
	switch {
	case err == nil:
		w.changed = true
		return rmGone, nil
	case errors.Is(err, unix.ENOENT):
		return rmGone, nil
	case errors.Is(err, unix.ENOTEMPTY):
		return 0, w.busy(rel)
	}
	return 0, w.flagKept(rel, &dst, err)
}

// errScopeTreeDeep is a directory nested deeper below the scope directory
// than rm-scope descends (maxScopeTreeDepth).
var errScopeTreeDeep = errors.New("the scope tree is nested deeper than rm-scope descends")

// tooDeep is errScopeTreeDeep for the directory rel below the scope
// directory, which the walk did not open: it names the directory relative
// to the scope directory, for reading only, says nothing below it was
// removed, and offers no command, since the tree is the service user's.
func (w *rmWalk) tooDeep(rel string) error {
	return fmt.Errorf("%w: the directory %s below the scope directory (named for reading, not for pasting) is nested more than %d directories deep; rm-scope removed nothing below it", errScopeTreeDeep, quoteName(rel), maxScopeTreeDepth)
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
		state := "The scope is not listed as removed, and the directory left behind blocks a fresh scope for this uid"
		if w.listed {
			state = "The scope is already listed as removed, so no open serves it, and the directory left behind blocks only a fresh scope for this uid"
		}
		if w.clearedKept(st) {
			// clearable cleared it (the service user's own regular file or
			// symlink, or a directory), and the flag was set again.
			return fmt.Errorf("remove the entry %s (named for reading, not for pasting): %w: it carries a user flag (uchg, uappnd or uunlnk) and has %d links; rm-scope cleared the flag, and it was set again before the removal. %s. Run rm-scope for this scope again once nothing sets the flag", p, err, st.Nlink, state)
		}
		who := "it"
		if st.Uid != w.svc {
			who = fmt.Sprintf("another user (uid %d) owns it, it", st.Uid)
		}
		return fmt.Errorf("remove the entry %s (named for reading, not for pasting): %w: %s carries a user flag (uchg, uappnd or uunlnk) and has %d links, so rm-scope does not clear it: another name of the same file may be outside the scope directory. %s. Root may clear the flag on this one file after inspecting it, or its owner may; then run rm-scope for this scope again", p, err, who, st.Nlink, state)
	}
	return fmt.Errorf("remove %s: %w", p, err)
}

// clearedKept reports whether rm-scope cleared the user locking flags of
// the entry st describes (before its removal) although it has more than
// one link: a directory (clearHeld clears it, whoever owns it), or the
// service user's regular file or symlink (clearable).
func (w *rmWalk) clearedKept(st *unix.Stat_t) bool {
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return true
	case unix.S_IFREG, unix.S_IFLNK:
		return w.clearable(st, true)
	}
	return false
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
	w.changed = true
	return nil
}

// clearScopeFlags clears the user locking flags of the non-directory name
// in pfd, rel below the scope directory, which st describes (fstatat, not
// followed), before its removal, when clearable allows it; otherwise the
// entry is left for unlinkat to refuse, flagKept naming it. A regular file
// is opened O_NOFOLLOW and a symlink O_SYMLINK (the link itself), never by
// path; both opens are free of side effects. The descriptor is re-checked
// as the name (device, inode, link count, owner; leave is true and the
// name left for the rescan when it changed) and changed with fchflags,
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
		// Replaced or relinked under the walk: the rescan sees it anew.
		return true, nil
	}
	if err := scopeFchflags(fd, int(statFlags(&got)&^userLockingFlags)); err != nil {
		return false, fmt.Errorf("clear the user flags of the entry %s (named for reading, not for pasting): %w", quoteName(filepath.Join(w.base, rel)), err)
	}
	w.changed = true
	return false, nil
}

// clearUnopened clears the flags of the FIFO, socket or device name in
// pfd, which st describes (fstatat, not followed: one link, a user locking
// flag, no system flag), without opening it: setattrlistat by directory
// descriptor and name, FSOPT_NOFOLLOW (setFlagsAt), writing exactly 0. A
// write by name can land on another file swapped in at the name since the
// fstatat, so it can never set a flag. The directory pfd is root's by now
// (take), so no service-user process can swap a name in it; the rule and
// the re-stat stay as defence in depth. Clearing the entry's other user
// flags (hidden, nodump) with the locking ones costs nothing, since it is
// about to be unlinked. The name is then stat'ed again: when it is no
// longer the file st describes (device, inode, owner), a Warn names the
// scope and leave is true, so it counts as not cleared and the rescan sees
// it anew; when it still carries a user locking flag the error says so.
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
	w.changed = true
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

// readBatch reads up to n names of the directory dfd from its start, but
// none in skip: the descriptor is duplicated, so dfd stays open for the
// caller. Memory is bounded by n and skip, never by the directory.
func readBatch(dfd, n int, skip map[string]bool) ([]string, error) {
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
	for len(names) < n {
		batch, err := d.Readdirnames(n - len(names))
		for _, b := range batch {
			if !skip[b] {
				names = append(names, b)
			}
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return names, nil
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
