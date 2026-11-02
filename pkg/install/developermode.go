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
	"strings"
	"time"
)

// Developer mode is an install-time choice that turns the signature checks
// off, so a build from source can be installed and driven by a development
// build of k3sm.app. Its one record is a marker file beside the install root
// (outside the tree a swap replaces): `k3sm install --developer-mode on`
// creates it, `--developer-mode off` removes it, and uninstall removes it.
// Without the flag, an install from a k3sm.app staging directory removes it
// only when the whole staged tree is signed by the team the signing continuity
// check requires (developerModeOff), and any other install removes it when its
// k3sm carries a Developer ID signature (plainInstallTeam). Presence is
// the whole record; the content is never parsed.
//
// The marker counts only when it is a root-owned regular file nobody else
// can write and that carries no ACL, and every directory above it, from /, is
// a real directory held to the same owner, mode and ACL checks
// (DeveloperModeMarkerState). It is the predicate k3sm.app applies before a
// root step. A marker that fails any of those checks is reported as invalid
// and counts as absent, so the checks stay on.

// DeveloperModeMarkerPath is the developer-mode marker. k3sm.app hardcodes the same path.
const DeveloperModeMarkerPath = "/Library/k3sm.developer-mode"

// developerModeMarkerMode is the marker's mode: root:wheel 0644.
const developerModeMarkerMode fs.FileMode = 0o644

// DeveloperModeMarkerContent is the one fixed line the marker carries.
func DeveloperModeMarkerContent(now time.Time) []byte {
	return []byte("developer mode enabled by k3sm install on " + now.UTC().Format(time.RFC3339) + "\n")
}

// DeveloperMode is `k3sm install --developer-mode`: DeveloperModeUnset when the
// flag was not passed, else on or off.
type DeveloperMode string

const (
	// DeveloperModeUnset keeps the marker as it is, except that a
	// team-signed install removes it (developerModeOff for a staging
	// directory, plainInstallTeam otherwise).
	DeveloperModeUnset DeveloperMode = ""
	// DeveloperModeOn writes the marker and skips the signing continuity check.
	DeveloperModeOn DeveloperMode = "on"
	// DeveloperModeOff removes the marker.
	DeveloperModeOff DeveloperMode = "off"
)

// ParseDeveloperMode accepts exactly "on" or "off".
func ParseDeveloperMode(s string) (DeveloperMode, error) {
	switch DeveloperMode(s) {
	case DeveloperModeOn, DeveloperModeOff:
		return DeveloperMode(s), nil
	}
	return DeveloperModeUnset, fmt.Errorf("developer mode is %q, want on or off", s)
}

// DeveloperModeOptions is the part of Config that `k3sm install
// --developer-mode` adds. It is embedded in Config, so its fields read as
// Config's own.
type DeveloperModeOptions struct {
	// DeveloperMode is `k3sm install --developer-mode`, accepted on every
	// install shape. DeveloperModeOn writes the developer-mode marker
	// (DeveloperModeMarkerPath) before the install root is swapped, leaves it
	// there if the install then fails, and skips the --from-staging signing
	// continuity check; DeveloperModeOff removes the marker once the swap has
	// committed, and a revert of the install root puts it back;
	// DeveloperModeUnset keeps it as it is, except that an install from a
	// staging directory whose staged k3sm and every other Mach-O carry the
	// Developer ID signature of the team the continuity check requires
	// removes it (developerModeOff); any other install whose k3sm carries a
	// Developer ID signature removes it (plainInstallTeam). Under
	// --from-staging a valid marker on disk turns developer mode on when the
	// flag is not passed. The marker that read is read again under the install lock, and a change refuses
	// the install (ErrDeveloperModeChanged). --require-team-signature, the
	// staging directory checks and the downgrade rule apply whatever the mode.
	DeveloperMode DeveloperMode
	// markerState reads the marker on disk when DeveloperMode is unset
	// (resolveDeveloperMode sets it). Nil reads as absent.
	markerState func() DeveloperModeState
	// preLockMarker is the marker state the --from-staging predicate read and
	// acted on, before the install lock; empty when it was not read.
	preLockMarker DeveloperModeState
	// offTeam is the team whose signature covers the whole staged tree, set by
	// the --from-staging predicate when the flag is unset and a marker is
	// there (developerModeOff); empty keeps the marker, for keepReason.
	offTeam    string
	keepReason string
}

// readMarker reads the marker through markerState and records the first read
// in preLockMarker, which the read under the install lock is compared with.
func (o *DeveloperModeOptions) readMarker() DeveloperModeState {
	state := DeveloperModeAbsent
	if o.markerState != nil {
		state = o.markerState()
	}
	if o.preLockMarker == "" {
		o.preLockMarker = state
	}
	return state
}

// developerModeOn reports whether this install runs in developer mode: the
// flag said on, or it was not passed and a valid marker is on disk. It skips
// checkSigningContinuity.
func (o *DeveloperModeOptions) developerModeOn() bool {
	switch o.DeveloperMode {
	case DeveloperModeOn:
		return true
	case DeveloperModeUnset:
		return o.readMarker() == DeveloperModeMarkerOn
	}
	return false
}

// ErrDeveloperModeChanged is a developer-mode marker that changed between the
// read the --from-staging predicate acted on and the read under the install
// lock. The install is refused, because the signing checks it ran, or skipped,
// followed the first read.
var ErrDeveloperModeChanged = errors.New("the developer-mode marker changed during the install")

// DeveloperModeState is what the marker on disk says.
type DeveloperModeState string

const (
	// DeveloperModeAbsent means nothing is at the marker path.
	DeveloperModeAbsent DeveloperModeState = "absent"
	// DeveloperModeMarkerOn means a valid marker is there: developer mode is on.
	DeveloperModeMarkerOn DeveloperModeState = "on"
	// DeveloperModeInvalid means something is at the marker path that fails a
	// check (a symlink, not a regular file, not root-owned, writable by group
	// or others, an ACL, or unreadable facts). It counts as absent.
	DeveloperModeInvalid DeveloperModeState = "invalid"
)

// DeveloperModeFacts is what an lstat and an ACL probe say about the marker
// path and the directories above it. Exists false means nothing is there; Err
// is a probe that failed for any other reason.
type DeveloperModeFacts struct {
	Exists bool
	Entry  OwnedEntry
	HasACL bool
	Err    error
	// Ancestors describes every directory above the marker, from / down. It
	// is read only for a marker that is a regular file without an ACL, and a
	// marker with no ancestor described is invalid.
	Ancestors []DeveloperModeAncestor
}

// DeveloperModeAncestor is what an lstat and an ACL probe say about one
// directory above the marker. Err is a probe that failed, including a
// directory that is not there.
type DeveloperModeAncestor struct {
	Entry  OwnedEntry
	HasACL bool
	Err    error
}

// DeveloperModeMarkerState judges the facts: on only for a regular file (not a
// symlink) owned by uid 0, with no group or other write bit and no ACL, under
// directories that are each a real directory (not a symlink) owned by uid 0,
// with no group or other write bit and no ACL.
func DeveloperModeMarkerState(f DeveloperModeFacts) DeveloperModeState {
	return developerModeState(f, 0)
}

// developerModeState is DeveloperModeMarkerState with every path owned by
// owner. Only the on-disk test passes anything but root.
func developerModeState(f DeveloperModeFacts, owner int) DeveloperModeState {
	held := func(e OwnedEntry, acl bool) bool {
		return e.UID == owner && e.Mode.Perm()&0o022 == 0 && !acl
	}
	switch {
	case f.Err != nil:
		return DeveloperModeInvalid
	case !f.Exists:
		return DeveloperModeAbsent
	case f.Entry.Kind != EntryRegular, !held(f.Entry, f.HasACL), len(f.Ancestors) == 0:
		return DeveloperModeInvalid
	}
	for _, a := range f.Ancestors {
		if a.Err != nil || a.Entry.Kind != EntryDir || !held(a.Entry, a.HasACL) {
			return DeveloperModeInvalid
		}
	}
	return DeveloperModeMarkerOn
}

// ReadDeveloperModeFacts lstats the marker at path and every directory above
// it, from /, through sys, and probes each for an ACL. It never follows a
// symlink.
func ReadDeveloperModeFacts(sys System, path string) DeveloperModeFacts {
	return readDeveloperModeFacts(sys, "/", path)
}

// readDeveloperModeFacts is ReadDeveloperModeFacts with the ancestors read
// from root down instead of from /. Only the on-disk test passes a root other
// than /, to judge a tree it can build without privilege.
func readDeveloperModeFacts(sys System, root, path string) DeveloperModeFacts {
	e, err := sys.Owner(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return DeveloperModeFacts{}
	case err != nil:
		return DeveloperModeFacts{Exists: true, Err: err}
	}
	f := DeveloperModeFacts{Exists: true, Entry: e}
	if e.Kind != EntryRegular {
		return f
	}
	if f.HasACL, f.Err = sys.HasACL(path); f.Err != nil || f.HasACL {
		return f
	}
	dirs, err := markerAncestors(root, path)
	if err != nil {
		f.Err = err
		return f
	}
	for _, dir := range dirs {
		a := DeveloperModeAncestor{}
		a.Entry, a.Err = sys.Owner(dir)
		if a.Err == nil && a.Entry.Kind == EntryDir {
			a.HasACL, a.Err = sys.HasACL(dir)
		}
		f.Ancestors = append(f.Ancestors, a)
	}
	return f
}

// markerAncestors lists root and every directory below it down to path's
// parent, in that order: /, /Library for the real marker.
func markerAncestors(root, path string) ([]string, error) {
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, filepath.Dir(filepath.Clean(path)))
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("the developer-mode marker %s is not under %s", path, root)
	}
	dirs := []string{root}
	if rel == "." {
		return dirs, nil
	}
	cur := root
	for _, c := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, c)
		dirs = append(dirs, cur)
	}
	return dirs, nil
}

// ReadDeveloperModeState is DeveloperModeMarkerState of the marker at path.
func ReadDeveloperModeState(sys System, path string) DeveloperModeState {
	return DeveloperModeMarkerState(ReadDeveloperModeFacts(sys, path))
}

// WriteDeveloperModeMarker writes the marker at path root:wheel 0644, to a
// temp name renamed over the path, so a symlink planted at the path is
// replaced and never followed.
func WriteDeveloperModeMarker(sys System, path string, now time.Time) error {
	if err := sys.WriteRootOnlyFile(path, DeveloperModeMarkerContent(now), developerModeMarkerMode); err != nil {
		return fmt.Errorf("write the developer-mode marker %s: %w", path, err)
	}
	return nil
}

// RemoveDeveloperModeMarker unlinks whatever is at path, never following a
// symlink. Absent is success.
func RemoveDeveloperModeMarker(sys System, path string) error {
	if err := sys.RemoveEntry(filepath.Dir(path), filepath.Base(path)); err != nil {
		return fmt.Errorf("remove the developer-mode marker %s: %w", path, err)
	}
	return nil
}

// resolveDeveloperMode validates DeveloperMode and wires the marker reader
// developerModeOn consults. It makes no system call: the --from-staging
// predicate reads the marker only once every refusal that needs no system
// call has passed.
func resolveDeveloperMode(sys System, cfg *Config) error {
	switch cfg.DeveloperMode {
	case DeveloperModeOn, DeveloperModeOff, DeveloperModeUnset:
	default:
		return fmt.Errorf("install: DeveloperMode is %q, want on, off or unset", cfg.DeveloperMode)
	}
	cfg.markerState = func() DeveloperModeState { return ReadDeveloperModeState(sys, DeveloperModeMarkerPath) }
	return nil
}

// applyDeveloperMode records the mode on disk, under the install lock and
// before the install root is swapped: on writes the marker (and a failed
// install leaves it). A removal is only decided here and returned, for the
// install to carry out once the swap has committed, so a failed swap leaves
// the marker as it was: off removes it, and not passed
// removes it only when the --from-staging predicate found the whole staged
// tree signed by the k3sm team (developerModeOff) or a plain install's k3sm is
// team-signed (plainInstallTeam). The removal happens as the swap commits
// (markerRemoval.drop), and a revert of the install root restores it. Not passed, it reads the marker again first
// and refuses the install if that read differs from the one the predicate
// acted on.
func applyDeveloperMode(ctx context.Context, sys System, cfg Config) (*markerRemoval, error) {
	path := DeveloperModeMarkerPath
	switch cfg.DeveloperMode {
	case DeveloperModeOn:
		if err := WriteDeveloperModeMarker(sys, path, time.Now()); err != nil {
			return nil, fmt.Errorf("install: %w", err)
		}
		cfg.Logger.Warn("developer mode is on: the signature of the k3sm that runs as root is not checked", "marker", path)
		return nil, nil
	case DeveloperModeOff:
		return &markerRemoval{path: path}, nil
	}
	if cfg.Signer == nil {
		return nil, nil
	}
	state := ReadDeveloperModeState(sys, path)
	if cfg.preLockMarker != "" && state != cfg.preLockMarker {
		return nil, fmt.Errorf("install: %w: it was %s when the signing checks ran and is %s now; run the install again", ErrDeveloperModeChanged, cfg.preLockMarker, state)
	}
	if state == DeveloperModeAbsent {
		return nil, nil
	}
	team, keepReason := cfg.offTeam, cfg.keepReason
	if cfg.FromStagingDir == "" {
		team, keepReason = plainInstallTeam(ctx, cfg)
	}
	if team == "" {
		if state == DeveloperModeInvalid {
			cfg.Logger.Warn("ignored invalid marker: it does not turn developer mode on, and it stays because "+keepReason, "marker", path)
			return nil, nil
		}
		cfg.Logger.Warn("developer mode stays on: "+keepReason+"; run k3sm install --developer-mode off to turn it off", "marker", path)
		return nil, nil
	}
	return &markerRemoval{path: path, team: team, invalid: state == DeveloperModeInvalid}, nil
}

// markerRemoval is a developer-mode marker removal applyDeveloperMode decided
// on. team is the signing team that turned developer mode off, empty for
// --developer-mode off; invalid says the marker was judged invalid. drop
// fills saved and savedMode with a valid marker's bytes and mode before it
// removes it, so restore can put it back if the install root is reverted.
type markerRemoval struct {
	path      string
	team      string
	invalid   bool
	removed   bool
	saved     []byte
	savedMode fs.FileMode
}

// markerDisownUID is nobody (uid -2 on macOS). A marker that cannot be
// removed is handed to it, which the predicate reads as invalid.
const markerDisownUID = 0xFFFFFFFE

// drop removes the marker. The install calls it the moment the swap has
// committed and before the daemons are wired and restarted, so the app's root
// steps never read developer mode as on beside the signed tree. It fails
// toward developer mode off, never on:
//   - A valid marker is read first, without following a symlink, and kept for
//     restore. If it cannot be read it is removed anyway, so a rollback
//     leaves developer mode off, and the read error is returned.
//   - A removal that fails is tried once more, then the marker is handed to
//     nobody (Chown, which never follows a symlink), so it reads invalid. An
//     error naming the remedy is returned only if it still reads on.
//
// The install reports what drop returns once it has finished; nil does nothing.
func (r *markerRemoval) drop(sys System, cfg Config) error {
	if r == nil {
		return nil
	}
	var readErr error
	if ReadDeveloperModeState(sys, r.path) == DeveloperModeMarkerOn {
		content, mode, err := sys.ReadRegularFileWithMode(r.path)
		if err != nil {
			readErr = fmt.Errorf("install: the developer-mode marker %s could not be read to keep a copy, so it is removed without one and a rollback leaves developer mode off: %w", r.path, err)
			cfg.Logger.Warn("the developer-mode marker could not be read to keep a copy; removing it anyway, so a rollback leaves developer mode off", "marker", r.path, "err", err)
		} else {
			r.saved, r.savedMode = content, mode.Perm()
		}
	}
	err := RemoveDeveloperModeMarker(sys, r.path)
	if err != nil {
		err = RemoveDeveloperModeMarker(sys, r.path)
	}
	if err != nil {
		r.saved = nil
		return errors.Join(readErr, r.disown(sys, cfg, err))
	}
	r.removed = true
	switch {
	case r.team == "":
	case r.invalid:
		cfg.Logger.Info("removed an invalid developer-mode marker by an install whose k3sm is signed", "signer-team-id", r.team, "marker", r.path)
	default:
		cfg.Logger.Info("developer mode turned off by an install whose k3sm is signed", "signer-team-id", r.team, "marker", r.path)
	}
	return readErr
}

// disown is drop's fallback for a marker that could not be removed: it hands
// a regular file at the path to nobody, then reads the marker again. It
// returns an error with the remedy only when the marker still reads on.
func (r *markerRemoval) disown(sys System, cfg Config, removeErr error) error {
	chownErr := errors.New("it is not a regular file")
	if e, err := sys.Owner(r.path); err != nil {
		chownErr = err
	} else if e.Kind == EntryRegular {
		chownErr = sys.Chown(r.path, markerDisownUID, e.GID)
	}
	if state := ReadDeveloperModeState(sys, r.path); state != DeveloperModeMarkerOn {
		cfg.Logger.Warn("the developer-mode marker could not be removed; it now reads "+string(state)+" and does not turn developer mode on", "marker", r.path, "err", removeErr)
		return nil
	}
	return fmt.Errorf("install: k3sm is installed, but %w, and handing the marker to nobody failed too (%v), so developer mode is still on; run k3sm install --developer-mode off", removeErr, chownErr)
}

// restore puts back the valid marker drop removed, with its bytes and its mode
// without the group and other write bits, through the root-only
// temp-and-rename write. revertInstallRoot calls it once the previous tree is
// live again, so a build from source that is rolled back to stays in developer
// mode. An invalid marker, or one drop could not read, is not restored.
// Failures are logged, never returned: the install is already failing.
func (r *markerRemoval) restore(sys System, cfg Config) {
	if r == nil || !r.removed || r.saved == nil {
		return
	}
	if err := sys.WriteRootOnlyFile(r.path, r.saved, r.savedMode&^0o022); err != nil {
		cfg.Logger.Warn("the developer-mode marker could not be restored with the rolled-back install root; run k3sm install --developer-mode on to turn developer mode on again", "marker", r.path, "err", err)
		return
	}
	if state := ReadDeveloperModeState(sys, r.path); state != DeveloperModeMarkerOn {
		cfg.Logger.Warn("the restored developer-mode marker reads "+string(state)+"; run k3sm install --developer-mode on to turn developer mode on again", "marker", r.path)
		return
	}
	cfg.Logger.Warn("restored the developer-mode marker with the rolled-back install root", "marker", r.path)
}

// plainInstallTeam decides whether an install that is not from a staging
// directory, without the flag, turns developer mode off: the k3sm doing the
// install (or, without an Executable, the one being installed) must carry a
// Developer ID Application signature, whose team it returns. A plain install
// has no staged tree to walk, so this is the one check it can make; it fails
// toward removal only for a team-signed binary, and removing the marker only
// turns the signature checks back on. It returns "" and why on any doubt.
//
// The team it returns names the signer of that binary. It is not an identity
// check against the release team, and the log line says so by calling it the
// signer team.
//
// Three limits are accepted, because each fails closed (a wrong verdict can
// only remove the marker, which re-arms the checks). The signature is read
// by path, not by bytes: it is the running binary's path that is checked, not
// the bytes later copied into the install root, so a swap in that window goes
// unseen. Any Developer ID team
// qualifies: no release team is pinned, and the installed build is not
// consulted. The sibling payloads and helpers are not checked; only the
// --from-staging path can walk a tree (developerModeOff).
func plainInstallTeam(ctx context.Context, cfg Config) (string, string) {
	exe := cfg.Executable
	if exe == "" {
		exe = cfg.BinarySource
	}
	if exe == "" {
		return "", "this install names no k3sm binary whose signature could be read"
	}
	team, err := cfg.Signer.TeamID(ctx, exe)
	if err != nil {
		return "", "the k3sm doing the install carries no Developer ID team signature (" + reason(err) + ")"
	}
	if err := requireDeveloperID(ctx, cfg.Signer, exe, team); err != nil {
		return "", "the k3sm doing the install is not signed with a Developer ID (" + reason(err) + ")"
	}
	return team, ""
}

// developerModeOff decides whether an install from a staging directory without
// the flag turns developer mode off: the staged k3sm and every other Mach-O of
// the staged tree must carry the Developer ID Application signature of the
// team checkSigningContinuity requires. That is the installed k3sm's team when
// it is team-signed, and the staged k3sm's own team when what is installed is
// ad-hoc signed or absent. There is no other team pin: the installed build is
// the record. It returns that team, or "" and why the marker stays.
// installed is the installed k3sm as preflightFromStaging resolved it.
func developerModeOff(ctx context.Context, cfg Config, installed string, entries []StagedEntry) (string, string) {
	team, err := cfg.Signer.TeamID(ctx, installed)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, ErrNoTeamID):
		team, err = stagedTeam(ctx, cfg)
		if err != nil {
			return "", "the staged k3sm carries no Developer ID team signature (" + reason(err) + ")"
		}
	case err != nil:
		return "", "the signature of the installed k3sm could not be read (" + reason(err) + ")"
	default:
		if err := requireDeveloperID(ctx, cfg.Signer, installed, team); err != nil {
			return "", "the installed k3sm names no Developer ID team (" + reason(err) + ")"
		}
		if err := requireTeam(ctx, cfg.Signer, cfg.Executable, team); err != nil {
			return "", "the staged k3sm is not signed by the installed team " + team + " (" + reason(err) + ")"
		}
	}
	if err := requireTreeTeam(ctx, cfg, entries, team); err != nil {
		return "", "not every binary in the staged tree is signed by team " + team + " (" + reason(err) + ")"
	}
	return team, ""
}

// reason is err's text without the package prefix, for a keepReason.
func reason(err error) string {
	return strings.TrimPrefix(err.Error(), "install: ")
}
