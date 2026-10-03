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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
)

// The purge is `k3sm uninstall --purge --yes`: the ordinary uninstall, then
// every artifact the ordinary uninstall deliberately keeps (the dispPreserve
// entries of the SAME manifest it walked). Its order is fixed and each step
// gates the next:
//
//  1. preflight, before anything is torn down: every tree it will delete must
//     pass purgeGuard, every file must pass the path rules, the service user
//     record must be the one k3sm created, and every preserved kind must have
//     a handler. A refusal here leaves the Mac exactly as it was.
//  2. the ordinary uninstall. Any error in it stops the purge: nothing
//     preserved is removed.
//  3. every loaded io.k3sm.* launchd job is booted out, and must be gone.
//  4. the service user's own launchd domain (user/<uid>) is booted out, so
//     launchd stops respawning the per-user agents it keeps there; then no
//     process may still run as the service user: a bounded wait, one SIGKILL
//     of exactly those pids, one short re-check, and a refusal naming any
//     survivor.
//  5. the data volume, if one is recorded, through datavol.Delete (unmount,
//     deleteVolume, keychain item, fstab line, record) — never by deleting
//     into the mounted tree.
//  6. the data root and the log dir, through purgeGuard again and PurgeTree.
//  7. the preserved files outside those trees, and both arguments records
//     whether or not the manifest names them.
//  8. the k3sm context in the human's kubeconfig, and nothing else in it.
//  9. the service user record, last, and only if every step above succeeded,
//     under its own bound (purgeUserDeleteTimeout, or purgeUserRetryTimeout
//     for an account an earlier purge already left disabled). macOS gates
//     deleting a user record behind a privacy approval a person gives at the
//     screen, so this step can fail where nothing else did. Its failure is not
//     a purge refusal: the account is left disabled and the purge says how to
//     finish.
//
// The result (what this run removed, and an account it could not) is written
// to Config.Out, the command's stdout; the progress goes to Config.Logger.

// ErrPurgeNotConfirmed is returned by a purge that was not confirmed with
// --yes. It is returned before any system call.
var ErrPurgeNotConfirmed = errors.New("uninstall --purge deletes the cluster's data and the k3sm service user, and needs --yes")

// ErrPurgeRefused is what every purge safety refusal wraps. Match it with
// errors.Is.
var ErrPurgeRefused = errors.New("purge refused")

// ErrPurgeTreeChanged is what PurgeTree returns when the tree at the path is
// no longer the directory the guard approved. Unlike an ordinary walk failure
// (a busy file), it means the ground moved under the purge, so the purge
// aborts rather than going on to the next step.
var ErrPurgeTreeChanged = errors.New("the tree is no longer the directory that was checked")

// purgeCommandTimeout bounds each subprocess the purge runs (launchctl, the
// dscl reads), except the user deletion.
const purgeCommandTimeout = 30 * time.Second

// purgeUserDeleteTimeout bounds the service user's deletion (dscl . -delete).
// On macOS 26 deleting a local user record needs a privacy approval
// ("administer your computer"). Run from a terminal, dscl waits until a person
// at the screen answers that prompt; run with no one to ask (a LaunchDaemon,
// ssh) it fails at once with eDSPermissionError. The bound is long enough for
// a person at the screen to click Allow and short enough that an unattended
// purge does not hang on a prompt nobody will answer.
const purgeUserDeleteTimeout = 90 * time.Second

// purgeUserRetryTimeout bounds the deletion of an account an earlier purge
// already left disabled. That purge printed how to delete it by hand; a re-run
// tries once more, briefly, and repeats the instruction rather than waiting
// out the full bound for a prompt the operator has already been told about.
const purgeUserRetryTimeout = 10 * time.Second

// errServiceUserDeleteDenied is what DeleteServiceUser wraps when macOS
// refused the deletion outright (eDSPermissionError, -14120): no approval
// could be asked for, so none will come.
var errServiceUserDeleteDenied = errors.New("macOS refused to delete the user record (eDSPermissionError -14120)")

// dsclPermissionDenied reports whether dscl's combined output carries the
// directory-service permission error.
func dsclPermissionDenied(out string) bool {
	return strings.Contains(out, "-14120") || strings.Contains(out, "eDSPermissionError")
}

// purgeLabelPrefix is the launchd label namespace every k3sm job lives in.
const purgeLabelPrefix = "io.k3sm."

// The purge's waits. They are variables so a test can shrink them.
var (
	// purgeSettle bounds the wait for booted-out jobs to leave launchd's list.
	purgeSettle = 15 * time.Second
	// purgeGrace bounds the wait for service-user processes to exit by
	// themselves (a daemon still draining after its bootout) before the kill.
	purgeGrace = 10 * time.Second
	// purgeKillWait bounds the wait for the killed processes to be reaped.
	purgeKillWait = 5 * time.Second
	// purgeRecheck is the one further wait before a process that outlived
	// purgeKillWait is a refusal: launchd tearing down the service user's
	// domain can still be reaping its agents.
	purgeRecheck = 3 * time.Second
	// purgePoll is the re-check interval for the polled waits.
	purgePoll = 200 * time.Millisecond
)

// PathStat is what StatNoFollow reports about a path: an lstat, so a symlink
// is described, never followed.
type PathStat struct {
	Kind EntryKind
	Dev  uint64
	Ino  uint64
}

// ServiceUserRecord is the directory-service record of the service user, as
// far as the purge needs it.
type ServiceUserRecord struct {
	// Exists is false when no such user exists; the other fields are then zero.
	Exists   bool
	UID      uint32
	RealName string
	Shell    string
	Home     string
	// Hidden reports IsHidden set as install sets it.
	Hidden bool
}

// purgeGuardFS is the read-only seam purgeGuard judges a tree through. It is
// defined here at the consumer; System satisfies it, and a test injects
// ownership, devices and symlinks no unprivileged process could create.
type purgeGuardFS interface {
	ResolvePath(path string) (string, error)
	StatNoFollow(path string) (PathStat, error)
	ReadDataRootMarker(dir string) (dataroot.MarkerFacts, error)
	DirIsEmpty(dir string) (bool, error)
}

// guardedRoot is a tree purgeGuard approved, with the identity it observed so
// PurgeTree can refuse a directory swapped in after the check.
type guardedRoot struct {
	path     string
	dev, ino uint64
	// empty reports an EMPTY directory with no marker: a tree already purged
	// whose final rmdir did not happen, or the mount point a deleted data
	// volume leaves behind. There is nothing in it to protect, so it is removed
	// with an rmdir (which refuses anything non-empty), not walked.
	empty bool
}

// purgeDenyExact are the directories a purge never deletes, compared
// lowercased (APFS is case-insensitive by default) after symlink resolution.
// They are EXACT matches: /private/var/lib/k3sm, where /var/lib/k3sm resolves,
// must pass, and only the directories themselves are denied. /Users and
// /Volumes are additionally denied as whole subtrees in purgePathRules.
var purgeDenyExact = map[string]bool{
	"/":             true,
	"/private":      true,
	"/private/var":  true,
	"/private/etc":  true,
	"/private/tmp":  true,
	"/var":          true,
	"/etc":          true,
	"/tmp":          true,
	"/users":        true,
	"/users/shared": true,
	"/volumes":      true,
	"/system":       true,
	"/library":      true,
	"/applications": true,
}

// firmlinkData is the data volume's own spelling of the paths macOS
// firmlinks into the root (/System/Volumes/Data/Users is /Users). A target is
// judged under both spellings, so the deny rules cannot be stepped around by
// naming the firmlink target.
const firmlinkData = "/system/volumes/data"

// purgePathRules is the path half of the purge guard, pure: it judges the
// target as given and as resolved, against the deny list, the /Users and
// /Volumes subtrees, and the invoking human's home (homes is that home and,
// when it resolves, its resolution). It never touches the filesystem.
func purgePathRules(target, resolved string, homes []string) error {
	for _, p := range []string{target, resolved} {
		for _, form := range pathForms(p) {
			if err := purgePathRule(form, homes); err != nil {
				return fmt.Errorf("%s: %w", target, err)
			}
		}
	}
	return nil
}

// pathForms returns p lowercased and cleaned, plus its root-relative spelling
// when it is written under the data volume's firmlink root.
func pathForms(p string) []string {
	low := strings.ToLower(filepath.Clean(p))
	forms := []string{low}
	if rest, ok := strings.CutPrefix(low, firmlinkData+"/"); ok {
		forms = append(forms, "/"+rest)
	} else if low == firmlinkData {
		forms = append(forms, "/")
	}
	return forms
}

// purgePathRule judges one lowercased, cleaned spelling.
func purgePathRule(p string, homes []string) error {
	switch {
	case !filepath.IsAbs(p):
		return fmt.Errorf("not an absolute path: %w", ErrPurgeRefused)
	case purgeDenyExact[p]:
		return fmt.Errorf("%s is a system directory: %w", p, ErrPurgeRefused)
	case strings.Count(p, "/") < 2:
		return fmt.Errorf("%s is a top-level directory: %w", p, ErrPurgeRefused)
	case strings.HasPrefix(p, "/users/"), strings.HasPrefix(p, "/volumes/"):
		return fmt.Errorf("%s is under /Users or /Volumes, where k3sm never keeps state: %w", p, ErrPurgeRefused)
	}
	for _, h := range homes {
		if h == "" {
			continue
		}
		h = strings.ToLower(filepath.Clean(h))
		if p == h || pathWithin(p, h) || pathWithin(h, p) {
			return fmt.Errorf("%s overlaps the home directory %s: %w", p, h, ErrPurgeRefused)
		}
	}
	return nil
}

// pathWithin reports whether p lies strictly inside dir. Both are cleaned.
func pathWithin(p, dir string) bool {
	if dir == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, dir+"/")
}

// purgeGuard decides whether the tree at target may be deleted whole, as root.
// It reports exists=false (and no error) when there is nothing at target, and
// approves an empty, unmarked directory as already purged (guardedRoot.empty).
//
// The rules, all of which must hold: target is absolute and clean; it is a
// real directory, not a symlink; its resolution passes purgePathRules; it is
// not a mount point (its device is its parent's) unless allowMount, which only
// the preflight sets, for a data root on the recorded k3sm volume that the
// purge deletes with datavol.Delete before it ever walks the tree; and it
// carries a k3sm marker naming exactly target (dataroot.CheckMarker).
func purgeGuard(fsys purgeGuardFS, target string, homes []string, allowMount bool) (guardedRoot, bool, error) {
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return guardedRoot{}, false, fmt.Errorf("%q is not an absolute, clean path: %w", target, ErrPurgeRefused)
	}
	st, err := fsys.StatNoFollow(target)
	if errors.Is(err, fs.ErrNotExist) {
		return guardedRoot{}, false, nil
	}
	if err != nil {
		return guardedRoot{}, false, fmt.Errorf("inspect %s: %v: %w", target, err, ErrPurgeRefused)
	}
	switch st.Kind {
	case EntrySymlink:
		return guardedRoot{}, true, fmt.Errorf("%s is a symlink; a purge deletes only the real directory install made: %w", target, ErrPurgeRefused)
	case EntryDir:
	default:
		return guardedRoot{}, true, fmt.Errorf("%s is not a directory: %w", target, ErrPurgeRefused)
	}
	resolved, err := fsys.ResolvePath(target)
	if err != nil {
		return guardedRoot{}, true, fmt.Errorf("resolve %s: %v: %w", target, err, ErrPurgeRefused)
	}
	if err := purgePathRules(target, resolved, homes); err != nil {
		return guardedRoot{}, true, err
	}
	parent, err := fsys.StatNoFollow(filepath.Dir(resolved))
	if err != nil {
		return guardedRoot{}, true, fmt.Errorf("inspect the parent of %s: %v: %w", target, err, ErrPurgeRefused)
	}
	if parent.Dev != st.Dev && !allowMount {
		return guardedRoot{}, true, fmt.Errorf("%s is a mount point; a purge never deletes into a mounted filesystem: %w", target, ErrPurgeRefused)
	}
	facts, err := fsys.ReadDataRootMarker(target)
	if errors.Is(err, fs.ErrNotExist) {
		if empty, eerr := fsys.DirIsEmpty(target); eerr == nil && empty {
			return guardedRoot{path: target, dev: st.Dev, ino: st.Ino, empty: true}, true, nil
		}
		return guardedRoot{}, true, fmt.Errorf("%s carries no %s marker (an install from before markers existed): run `sudo k3sm install` once, which writes it, then `sudo k3sm uninstall --purge --yes`: %w",
			target, dataroot.MarkerName, ErrPurgeRefused)
	}
	if err != nil {
		return guardedRoot{}, true, fmt.Errorf("read the marker in %s: %v: %w", target, err, ErrPurgeRefused)
	}
	if err := dataroot.CheckMarker(target, facts); err != nil {
		return guardedRoot{}, true, fmt.Errorf("%v: %w", err, ErrPurgeRefused)
	}
	return guardedRoot{path: target, dev: st.Dev, ino: st.Ino}, true, nil
}

// purgeFileRule judges a preserved FILE outside the purged trees: the path
// rules on its lexical form and on its resolved parent. The removal itself
// (RemoveEntry) unlinks the entry and never follows it.
func purgeFileRule(fsys purgeGuardFS, path string, homes []string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%q is not an absolute, clean path: %w", path, ErrPurgeRefused)
	}
	resolved := path
	if dir, err := fsys.ResolvePath(filepath.Dir(path)); err == nil {
		resolved = filepath.Join(dir, filepath.Base(path))
	}
	return purgePathRules(path, resolved, homes)
}

// purgePlan is what the preflight decided, from the manifest the uninstall
// walked. Every preserved entry lands in exactly one bucket.
type purgePlan struct {
	// roots are the trees deleted whole, in manifest order; a preserved
	// directory inside another is covered by it and not listed.
	roots []string
	// files are the preserved files outside every root.
	files []string
	// kubeUsers are the humans whose kubeconfig carries the k3sm context.
	kubeUsers []string
	// serviceUsers are the service-user records to delete.
	serviceUsers []string
	// volume is the recorded k3sm data volume of the data root, nil if none.
	volume *dataroot.Record
	// fstabOnly reports an /etc/fstab line for the data root with no record
	// behind it, removed through datavol's own helper.
	fstabOnly bool
	// serviceUID is the service user's uid, valid when hasServiceUID.
	serviceUID    uint32
	hasServiceUID bool
	// homes is the invoking human's home, and its resolution.
	homes []string
}

// planPurge is the preflight. It runs before the uninstall tears anything
// down, over the manifest the uninstall is about to walk, and refuses rather
// than plan anything it cannot carry out safely.
func planPurge(ctx context.Context, sys System, cfg Config, m []artifact, st dataroot.State) (purgePlan, error) {
	var plan purgePlan
	plan.homes = []string{cfg.TargetHome}
	if cfg.TargetHome != "" {
		if r, err := sys.ResolvePath(cfg.TargetHome); err == nil && r != cfg.TargetHome {
			plan.homes = append(plan.homes, r)
		}
	}
	plan.volume = st.Volume
	plan.fstabOnly = st.Volume == nil && slices.Contains(st.DeclaredBy, "fstab")

	var dirs, files []string
	for _, a := range m {
		if a.disp != dispPreserve {
			continue
		}
		switch a.kind {
		case kindDir:
			dirs = append(dirs, a.path)
		case kindFile:
			files = append(files, a.path)
		case kindKubeconfig:
			plan.kubeUsers = append(plan.kubeUsers, a.user)
		case kindServiceUser:
			plan.serviceUsers = append(plan.serviceUsers, a.user)
		default:
			// A preserved kind with no purge handler must not fall through
			// silently: the purge would report success with it still there.
			return plan, fmt.Errorf("a preserved %v artifact (%s%s) has no purge handler: %w", a.kind, a.path, a.label, ErrPurgeRefused)
		}
	}
	// The arguments records are removed whatever the manifest says. It names
	// only the configured role's record, and the other role's only while that
	// role's plist is on disk, so a purge re-run after a partial one (plists
	// gone) would otherwise leave a record behind for the next install to
	// carry over.
	for _, f := range []string{cfg.ServerArgsRecord, cfg.AgentArgsRecord} {
		if f != "" {
			files = append(files, f)
		}
	}
	for _, d := range dirs {
		if !coveredBy(d, dirs) && !slices.Contains(plan.roots, d) {
			plan.roots = append(plan.roots, d)
		}
	}
	for _, f := range files {
		if !coveredBy(f, plan.roots) && !slices.Contains(plan.files, f) {
			plan.files = append(plan.files, f)
		}
	}

	for _, root := range plan.roots {
		allowMount := root == cfg.DataRoot && plan.volume != nil
		if _, _, err := purgeGuard(sys, root, plan.homes, allowMount); err != nil {
			return plan, err
		}
	}
	for _, f := range plan.files {
		if err := purgeFileRule(sys, f, plan.homes); err != nil {
			return plan, err
		}
	}
	// After the guards, so a path the rules refuse is refused for that reason.
	if st.Mounted && st.Volume == nil {
		return plan, fmt.Errorf("%s is a mounted filesystem with no k3sm data-volume record; unmount it yourself first: %w", cfg.DataRoot, ErrPurgeRefused)
	}
	for _, u := range plan.kubeUsers {
		if u == "" {
			return plan, fmt.Errorf("no invoking user is known, so the k3sm context cannot be removed from a kubeconfig; run through sudo: %w", ErrPurgeRefused)
		}
	}
	for _, name := range plan.serviceUsers {
		rec, err := sys.ServiceUser(ctx, name)
		if err != nil {
			return plan, fmt.Errorf("read the %s user record: %v: %w", name, err, ErrPurgeRefused)
		}
		if !rec.Exists {
			continue
		}
		if err := checkServiceUser(name, rec, cfg.DataRoot); err != nil {
			return plan, err
		}
		if name == cfg.ServiceUser {
			if err := checkServiceUID(name, rec.UID); err != nil {
				return plan, err
			}
			plan.serviceUID, plan.hasServiceUID = rec.UID, true
		}
	}
	return plan, nil
}

// coveredBy reports whether p lies strictly inside one of dirs.
func coveredBy(p string, dirs []string) bool {
	for _, d := range dirs {
		if p != d && pathWithin(filepath.Clean(p), filepath.Clean(d)) {
			return true
		}
	}
	return false
}

// checkServiceUser refuses a user record that is not the one EnsureServiceUser
// creates: an account that merely shares the name is never deleted. Three
// RealName shapes are k3sm's: the current serviceUserRealName, the
// serviceUserDisabledRealName a purge that could not delete the account left
// it with, and the legacy shape an older install left (no RealName set, which
// dscl reports as empty or as the account name). The legacy shape carries no
// k3sm-specific marker, so it is accepted only with a uid in the hidden range
// EnsureServiceUser allocates from; the shell and home checks below apply to
// every shape.
func checkServiceUser(name string, rec ServiceUserRecord, dataRoot string) error {
	legacy := rec.RealName == "" || rec.RealName == name
	switch {
	case rec.RealName != serviceUserRealName && rec.RealName != serviceUserDisabledRealName && !legacy:
		return fmt.Errorf("the %s user's RealName is %q, not %q (or, for an account an older install created, empty or %q); it is not the account k3sm created: %w",
			name, rec.RealName, serviceUserRealName, name, ErrPurgeRefused)
	case legacy && (rec.UID < systemUIDFloor || rec.UID > systemUIDCeil):
		return fmt.Errorf("the %s user's RealName is %q, not %q, and its uid %d is outside the range [%d,%d] an older install created it in; it is not the account k3sm created: %w",
			name, rec.RealName, serviceUserRealName, rec.UID, systemUIDFloor, systemUIDCeil, ErrPurgeRefused)
	case rec.Shell != serviceUserShell:
		return fmt.Errorf("the %s user's shell is %q, not %s; it is not the account k3sm created: %w", name, rec.Shell, serviceUserShell, ErrPurgeRefused)
	case filepath.Clean(rec.Home) != filepath.Clean(dataRoot):
		return fmt.Errorf("the %s user's home is %q, not the data root %s; it is not the account k3sm created: %w", name, rec.Home, dataRoot, ErrPurgeRefused)
	}
	return nil
}

// checkServiceUID refuses a service uid the purge must never enumerate or
// kill the processes of: root, and anything outside the hidden system range
// EnsureServiceUser allocates the account from. Killing "every process of
// uid 0" would kill the Mac.
func checkServiceUID(name string, uid uint32) error {
	if uid == 0 || uid < systemUIDFloor || uid > systemUIDCeil {
		return fmt.Errorf("the %s user has uid %d, outside the range [%d,%d] k3sm creates it in; refusing to kill its processes: %w",
			name, uid, systemUIDFloor, systemUIDCeil, ErrPurgeRefused)
	}
	return nil
}

// purge is Uninstall with cfg.Purge set. See the order at the top of this file.
func purge(ctx context.Context, sys System, cfg Config) error {
	if !cfg.PurgeConfirmed {
		return ErrPurgeNotConfirmed
	}
	var plan purgePlan
	_, err := uninstall(ctx, sys, cfg, func(m []artifact, st dataroot.State, stErr error) error {
		if stErr != nil {
			// Whether the data root is a mount point is unknown, and that
			// decides whether deleting it would delete into a filesystem.
			return fmt.Errorf("inspect the data root %s: %v: %w", cfg.DataRoot, stErr, ErrPurgeRefused)
		}
		p, err := planPurge(ctx, sys, cfg, m, st)
		plan = p
		return err
	})
	if err != nil {
		if errors.Is(err, ErrPurgeRefused) {
			return fmt.Errorf("uninstall --purge: %w (nothing was removed)", err)
		}
		return fmt.Errorf("%w (the purge did not run: nothing the uninstall keeps was removed)", err)
	}

	if err := settleLaunchd(ctx, sys); err != nil {
		return err
	}
	if plan.hasServiceUID {
		if err := assertNoServiceProcesses(ctx, sys, cfg.ServiceUser, plan.serviceUID); err != nil {
			return err
		}
	}
	if err := purgeDataVolume(ctx, sys, cfg, plan); err != nil {
		return err
	}

	var removed []string
	var errs []error
	for _, root := range plan.roots {
		// The guard runs again because the ground has moved since the
		// preflight: the volume is gone, and its mount point (if any) is what
		// is at the data root now. A refusal here, or a tree that is no longer
		// the one the guard approved, aborts the purge: nothing further is
		// removed and the service user is kept, so a re-run can finish.
		g, exists, err := purgeGuard(sys, root, plan.homes, false)
		switch {
		case err != nil:
			return fmt.Errorf("uninstall --purge: %w (stopped: nothing further was removed, the service user is kept)", err)
		case !exists:
		case g.empty:
			if err := sys.RemoveEntry(filepath.Dir(root), filepath.Base(root)); err != nil {
				errs = append(errs, fmt.Errorf("remove the empty %s: %w", root, err))
				continue
			}
			removed = append(removed, root)
		default:
			if err := sys.PurgeTree(g.path, g.dev, g.ino); err != nil {
				if errors.Is(err, ErrPurgeTreeChanged) {
					return fmt.Errorf("uninstall --purge: purge %s: %w (stopped: nothing further was removed, the service user is kept)", root, err)
				}
				errs = append(errs, fmt.Errorf("purge %s: %w", root, err))
				continue
			}
			removed = append(removed, root)
		}
	}
	for _, f := range plan.files {
		// The summary names only what this run removed: the arguments records
		// are on the list whether or not they exist, and a re-run finds them
		// gone. The removal still runs, since an absent entry is its success.
		_, statErr := sys.StatNoFollow(f)
		if err := sys.RemoveEntry(filepath.Dir(f), filepath.Base(f)); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", f, err))
			continue
		}
		if statErr == nil {
			removed = append(removed, f)
		}
	}
	for _, u := range plan.kubeUsers {
		had, err := sys.RemoveAdminKubeconfigContext(u)
		if err != nil {
			errs = append(errs, fmt.Errorf("remove the %s context from %s's kubeconfig: %w (remedy: kubectl config delete-context %s)", adminContextName, u, err, adminContextName))
			continue
		}
		if had {
			removed = append(removed, "the "+adminContextName+" context in "+u+"'s kubeconfig")
		}
	}
	if len(errs) > 0 {
		// The service user is the data root's owner of record; keeping it
		// keeps a re-run of the purge able to finish what this one could not.
		return fmt.Errorf("uninstall --purge: %w (the service user is kept; fix the above and re-run)", errors.Join(errs...))
	}
	var remains []string
	for _, name := range plan.serviceUsers {
		d, err := deleteServiceUser(ctx, sys, name, cfg.DataRoot)
		if err != nil {
			return fmt.Errorf("uninstall --purge: %w (everything else was removed)", err)
		}
		switch d.outcome {
		case userDeleted:
			removed = append(removed, "the "+name+" service user")
		case userDenied, userTimedOut:
			remains = append(remains, serviceUserLeftMessage(ctx, sys, name, d))
		}
	}
	// Result lines, on the command's stdout. Write errors are not checked: the
	// purge is done, and a closed stdout cannot undo it.
	if len(removed) == 0 {
		_, _ = fmt.Fprintln(cfg.Out, "k3sm purged; nothing else was left to remove")
	} else {
		_, _ = fmt.Fprintln(cfg.Out, "k3sm purged; removed: "+strings.Join(removed, ", "))
	}
	for _, msg := range remains {
		_, _ = fmt.Fprintln(cfg.Out, msg)
	}
	return nil
}

// serviceUserOutcome is what became of the service user's record.
type serviceUserOutcome int

const (
	// userAbsent: there was no record to delete.
	userAbsent serviceUserOutcome = iota
	// userDeleted: the record is gone.
	userDeleted
	// userDenied: macOS refused the deletion outright; no approval could be
	// asked for.
	userDenied
	// userTimedOut: the deletion was still waiting at its bound, which is
	// what an approval prompt nobody answered looks like.
	userTimedOut
)

// userDeletion is what deleteServiceUser reports: the outcome, the bound the
// deletion ran under, and whether the account was already in the disabled
// shape an earlier purge leaves.
type userDeletion struct {
	outcome serviceUserOutcome
	bound   time.Duration
	// wasDisabled: the record already carried serviceUserDisabledRealName, the
	// no-login shell and IsHidden, so there is nothing to disable again.
	wasDisabled bool
}

// disabledShape reports whether rec is the account DisableServiceUser leaves.
func disabledShape(rec ServiceUserRecord) bool {
	return rec.RealName == serviceUserDisabledRealName && rec.Shell == serviceUserShell && rec.Hidden
}

// serviceUserLeftMessage disables the account the purge could not delete,
// unless an earlier purge already did, and returns the final line that says
// so: which account remains, why, and the command that finishes the job.
func serviceUserLeftMessage(ctx context.Context, sys System, name string, d userDeletion) string {
	state := "disabled: no login shell, hidden, no home directory"
	if !d.wasDisabled {
		if err := sys.DisableServiceUser(ctx, name); err != nil {
			// The account was created hidden with no login shell, so it is
			// harmless either way; only the relabel did not happen.
			state = "hidden, with no login shell or home directory; relabelling it failed: " + err.Error()
		}
	}
	why := "macOS would not let an unattended process delete it"
	if d.outcome == userTimedOut {
		why = fmt.Sprintf("macOS did not allow the deletion within %s, and an approval prompt may still be waiting on the screen", d.bound)
	}
	return fmt.Sprintf("the %s account remains (%s): %s. Deleting a user account needs a person at the screen to approve it. "+
		"To delete it by hand, run `sudo dscl . -delete /Users/%s` in Terminal and click Allow when macOS asks to administer your computer. "+
		"Re-running `sudo k3sm uninstall --purge --yes` on this Mac also tries again",
		name, state, why, name)
}

// settleLaunchd boots out every io.k3sm.* job launchd still has loaded, and
// refuses unless the list empties within purgeSettle. The uninstall already
// booted out every job its manifest names; this catches anything it did not
// (a job a different build installed) and waits out a bootout that returned
// before launchd let the job go.
func settleLaunchd(ctx context.Context, sys System) error {
	labels, err := sys.LoadedLabels(ctx, purgeLabelPrefix)
	if err != nil {
		return fmt.Errorf("uninstall --purge: list the loaded k3sm jobs: %w", err)
	}
	// A bootout error is not the verdict: launchd can report a failure for a
	// job that is on its way out (the race with a job exiting by itself). The
	// verdict is whether the label is still loaded once the poll ends, and the
	// errors are kept only to explain a refusal.
	var bootoutErrs []error
	for _, l := range labels {
		if err := sys.LaunchctlBootout(l); err != nil {
			bootoutErrs = append(bootoutErrs, err)
		}
	}
	left, err := pollUntilEmpty(ctx, purgeSettle, func() ([]string, error) { return sys.LoadedLabels(ctx, purgeLabelPrefix) })
	if err != nil {
		return fmt.Errorf("uninstall --purge: list the loaded k3sm jobs: %w", err)
	}
	if len(left) > 0 {
		cause := ""
		if len(bootoutErrs) > 0 {
			cause = " (" + errors.Join(bootoutErrs...).Error() + ")"
		}
		return fmt.Errorf("uninstall --purge: still loaded after bootout: %s%s: %w (nothing the uninstall keeps was removed)", strings.Join(left, ", "), cause, ErrPurgeRefused)
	}
	return nil
}

// assertNoServiceProcesses boots out the service user's launchd domain, then
// waits for every process running as the service user (real or effective uid)
// to exit, kills exactly the ones that do not, once, re-checks once after
// purgeRecheck, and refuses if any survives. Deleting the data root, or the
// account, from under a live process is what this prevents.
//
// The domain bootout comes first because launchd keeps a per-user domain for
// the account (distnoted and the other per-user system agents) and respawns
// its agents after a SIGKILL; a sweep without it refuses on every real Mac. A
// bootout error is not the verdict, for the same reason as in settleLaunchd:
// whether a process survives is, and the error only explains a refusal.
func assertNoServiceProcesses(ctx context.Context, sys System, name string, uid uint32) error {
	if err := checkServiceUID(name, uid); err != nil {
		return fmt.Errorf("uninstall --purge: %w", err)
	}
	domainErr := sys.BootoutUserDomain(ctx, uid)
	list := func() ([]string, error) {
		pids, err := sys.ProcessesOfUID(uid)
		out := make([]string, 0, len(pids))
		for _, p := range pids {
			out = append(out, strconv.Itoa(p))
		}
		return out, err
	}
	left, err := pollUntilEmpty(ctx, purgeGrace, list)
	if err != nil {
		return fmt.Errorf("uninstall --purge: list the %s processes: %w", name, err)
	}
	if len(left) == 0 {
		return nil
	}
	for _, s := range left {
		pid, _ := strconv.Atoi(s) // produced by strconv.Itoa above
		if err := sys.KillProcess(pid); err != nil {
			return fmt.Errorf("uninstall --purge: %w", err)
		}
	}
	survivors, err := pollUntilEmpty(ctx, purgeKillWait, list)
	if err == nil && len(survivors) > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(purgeRecheck):
		}
		survivors, err = list()
	}
	if err != nil {
		return fmt.Errorf("uninstall --purge: list the %s processes: %w", name, err)
	}
	if len(survivors) > 0 {
		cause := ""
		if domainErr != nil {
			cause = " (" + domainErr.Error() + ")"
		}
		return fmt.Errorf("uninstall --purge: processes still running as %s after SIGKILL: %s%s: %w (nothing the uninstall keeps was removed)",
			name, strings.Join(survivors, ", "), cause, ErrPurgeRefused)
	}
	return nil
}

// launchctlDomainGone reports whether launchctl's output for a failed
// `bootout user/<uid>` says the domain is already gone, which is success.
func launchctlDomainGone(out string) bool {
	for _, s := range []string{"Could not find", "No such process", "not found"} {
		if strings.Contains(out, s) {
			return true
		}
	}
	return false
}

// pollUntilEmpty calls list until it returns nothing or budget passes, and
// returns the last answer.
func pollUntilEmpty(ctx context.Context, budget time.Duration, list func() ([]string, error)) ([]string, error) {
	deadline := time.Now().Add(budget)
	for {
		left, err := list()
		if err != nil || len(left) == 0 || !time.Now().Before(deadline) {
			return left, err
		}
		select {
		case <-ctx.Done():
			return left, nil
		case <-time.After(purgePoll):
		}
	}
}

// purgeDataVolume deletes the recorded data volume through datavol.Delete —
// unmount, deleteVolume, the keychain item, the fstab line, the record — so the
// purge never deletes into a mounted filesystem. With no record but an fstab
// line declaring the data root, it removes that line through datavol's helper.
// A failure stops the purge before any tree is touched.
func purgeDataVolume(ctx context.Context, sys System, cfg Config, plan purgePlan) error {
	switch {
	case plan.volume != nil:
		rec := *plan.volume
		loaded := loadedJobs(func(label string) bool {
			labels, err := sys.LoadedLabels(ctx, label)
			return err != nil || slices.Contains(labels, label)
		})
		err := datavol.Delete(ctx, cfg.DataVolumeDeps, cfg.DataRootFS, loaded, dataroot.DefaultRecordPath, rec, datavol.DeleteOptions{
			Yes:                 true,
			FstabPath:           dataroot.FstabPath,
			NetdLabel:           NetdLabel,
			ServerLabel:         daemonLabel(cfg.Role),
			ProtectedMountpoint: cfg.DataRoot,
		})
		if err != nil {
			return fmt.Errorf("uninstall --purge: delete the data volume %s (%s): %w (no tree was removed)", rec.Name, rec.UUID, err)
		}
		cfg.Logger.Info(fmt.Sprintf("deleted the data volume %s (%s), its fstab line and its record", rec.Name, rec.UUID))
	case plan.fstabOnly:
		if _, err := datavol.RemoveFstabLine(cfg.DataRootFS, dataroot.FstabPath, cfg.DataRoot); err != nil {
			return fmt.Errorf("uninstall --purge: remove the %s line for %s: %w (no tree was removed)", dataroot.FstabPath, cfg.DataRoot, err)
		}
	}
	return nil
}

// loadedJobs answers datavol.Delete's one launchd question. purgeDataVolume
// builds it from the System's loaded-label list, where an unreadable list
// answers "loaded", so Delete refuses.
type loadedJobs func(label string) bool

// Loaded implements datavol.Launchd.
func (l loadedJobs) Loaded(label string) bool { return l(label) }

// deleteServiceUser deletes the service user's record after re-reading it and
// confirming it is still the one k3sm created. A missing record is userAbsent.
// Only the user record is deleted: install creates no group (the account's
// primary group is 20, staff, shared by every login user), and no group is
// ever touched here.
//
// A refusal by macOS (userDenied) or a deletion still waiting at the bound
// (userTimedOut) is an outcome, not an error: everything else the purge owns
// is already gone, and the caller leaves the account disabled. A deletion that
// reports success is believed only once the record no longer reads back.
//
// The bound is purgeUserDeleteTimeout, or purgeUserRetryTimeout for an account
// already in the disabled shape: a re-run after a purge that could not delete
// it, whose operator was already told how to finish by hand.
func deleteServiceUser(ctx context.Context, sys System, name, dataRoot string) (userDeletion, error) {
	rec, err := sys.ServiceUser(ctx, name)
	if err != nil {
		return userDeletion{}, fmt.Errorf("read the %s user record: %w", name, err)
	}
	if !rec.Exists {
		return userDeletion{outcome: userAbsent}, nil
	}
	if err := checkServiceUser(name, rec, dataRoot); err != nil {
		return userDeletion{}, err
	}
	d := userDeletion{bound: purgeUserDeleteTimeout, wasDisabled: disabledShape(rec)}
	if d.wasDisabled {
		d.bound = purgeUserRetryTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, d.bound)
	defer cancel()
	err = sys.DeleteServiceUser(dctx, name)
	switch {
	case errors.Is(err, errServiceUserDeleteDenied):
		d.outcome = userDenied
		return d, nil
	case errors.Is(err, context.DeadlineExceeded):
		d.outcome = userTimedOut
		return d, nil
	case err != nil:
		return userDeletion{}, fmt.Errorf("delete the %s user: %w", name, err)
	}
	after, err := sys.ServiceUser(ctx, name)
	if err != nil {
		return userDeletion{}, fmt.Errorf("read the %s user record after deleting it: %w", name, err)
	}
	if after.Exists {
		d.outcome = userDenied
		return d, nil
	}
	d.outcome = userDeleted
	return d, nil
}
