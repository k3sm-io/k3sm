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
// creates it, `--developer-mode off` removes it, and uninstall removes it. An
// install from a k3sm.app staging directory without the flag removes it only
// when the whole staged tree is signed by the team the signing continuity
// check requires (developerModeOff); every other install keeps it. Presence is
// the whole record; the content is never parsed.
//
// The marker counts only when it is a root-owned regular file nobody else
// can write and that carries no ACL (DeveloperModeMarkerState). A marker that
// fails any of those checks is reported as invalid and counts as absent, so
// the checks stay on.

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
	// DeveloperModeUnset keeps the marker as it is, except that an install
	// from a staging directory whose whole tree is signed by the k3sm team
	// removes it (developerModeOff).
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
	// continuity check; DeveloperModeOff removes the marker;
	// DeveloperModeUnset keeps it as it is, except that an install from a
	// staging directory whose staged k3sm and every other Mach-O carry the
	// Developer ID signature of the team the continuity check requires
	// removes it (developerModeOff). Under --from-staging a valid marker on
	// disk turns developer mode on when the flag is not passed. The marker
	// that read is read again under the install lock, and a change refuses
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
// path. Exists false means nothing is there; Err is a probe that failed for
// any other reason.
type DeveloperModeFacts struct {
	Exists bool
	Entry  OwnedEntry
	HasACL bool
	Err    error
}

// DeveloperModeMarkerState judges the facts: on only for a regular file (not a
// symlink) owned by uid 0, with no group or other write bit and no ACL.
func DeveloperModeMarkerState(f DeveloperModeFacts) DeveloperModeState {
	switch {
	case f.Err != nil:
		return DeveloperModeInvalid
	case !f.Exists:
		return DeveloperModeAbsent
	case f.Entry.Kind != EntryRegular,
		f.Entry.UID != 0,
		f.Entry.Mode.Perm()&0o022 != 0,
		f.HasACL:
		return DeveloperModeInvalid
	}
	return DeveloperModeMarkerOn
}

// ReadDeveloperModeFacts lstats the marker at path through sys and probes it
// for an ACL. It never follows a symlink.
func ReadDeveloperModeFacts(sys System, path string) DeveloperModeFacts {
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
	f.HasACL, f.Err = sys.HasACL(path)
	return f
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
// install leaves it), off removes it, and not passed keeps it unless the
// --from-staging predicate found the whole staged tree signed by the k3sm team
// (developerModeOff), which turns developer mode off. Not passed, it reads the
// marker again first and refuses the install if that read differs from the
// one the predicate acted on.
func applyDeveloperMode(ctx context.Context, sys System, cfg Config) error {
	path := DeveloperModeMarkerPath
	switch cfg.DeveloperMode {
	case DeveloperModeOn:
		if err := WriteDeveloperModeMarker(sys, path, time.Now()); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		cfg.Logger.Warn("developer mode is on: the signature of the k3sm that runs as root is not checked", "marker", path)
		return nil
	case DeveloperModeOff:
		if err := RemoveDeveloperModeMarker(sys, path); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		return nil
	}
	if cfg.Signer == nil {
		return nil
	}
	state := ReadDeveloperModeState(sys, path)
	if cfg.preLockMarker != "" && state != cfg.preLockMarker {
		return fmt.Errorf("install: %w: it was %s when the signing checks ran and is %s now; run the install again", ErrDeveloperModeChanged, cfg.preLockMarker, state)
	}
	if state == DeveloperModeAbsent {
		return nil
	}
	team := cfg.offTeam
	if cfg.FromStagingDir == "" {
		cfg.Logger.Warn("developer mode stays on: only an install from a k3sm.app staging directory can show that every binary it installs is signed by the k3sm team; run k3sm install --developer-mode off to turn it off", "marker", path)
		return nil
	}
	if team == "" {
		cfg.Logger.Warn("developer mode stays on: "+cfg.keepReason+"; run k3sm install --developer-mode off to turn it off", "marker", path)
		return nil
	}
	if err := RemoveDeveloperModeMarker(sys, path); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	cfg.Logger.Info("developer mode turned off by a signed install", "team-id", team, "marker", path)
	return nil
}

// developerModeOff decides whether an install from a staging directory without
// the flag turns developer mode off: the staged k3sm and every other Mach-O of
// the staged tree must carry the Developer ID Application signature of the
// team checkSigningContinuity requires. That is the installed k3sm's team when
// it is team-signed, and the staged k3sm's own team when what is installed is
// ad-hoc signed or absent. There is no other team pin: the installed build is
// the record. It returns that team, or "" and why the marker stays.
func developerModeOff(ctx context.Context, cfg Config, entries []StagedEntry) (string, string) {
	installed := cfg.installedBinary()
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
