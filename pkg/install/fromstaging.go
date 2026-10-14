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
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
)

// `k3sm install --from-staging <dir>`: the install side of k3sm.app.
//
// The app never runs anything from its own bundle as root, because an admin
// account can rewrite /Applications. Its root step copies the whole bundle into
// a fresh directory under the staging root, refuses unsafe entries, chowns the
// copy to root, verifies the Developer ID signature, and only then runs the
// staged CLI with --from-staging naming that directory. Everything that step
// proved is re-proved here, from the CLI's side, before a byte is written:
//
//   - no component of <dir> is a symlink, and <dir> is a direct child of the
//     staging root, both root:wheel 0700 on one device;
//   - the whole tree under <dir> is root-owned, with no group or other write,
//     no symlink, no setuid or setgid bit and no special file;
//   - this running binary, and every file the install copies, lies inside
//     <dir>;
//   - a --token-file is a direct child of <dir>, root-owned, mode exactly
//     0600, a regular file with one link, read once and unlinked at once;
//   - the staged version is a release version no lower than the installed one
//     (unless --allow-downgrade);
//   - on an update, the staged binary is signed by the same Team ID as the
//     installed /Library/k3sm/k3sm.
//
// Any doubt refuses. The copy-out removes its staging directory on every exit
// path, so a refusal costs one re-run and leaves nothing behind.

// DefaultStagingRoot is the k3sm.app copy-out's staging root. Each copy-out
// makes one directory directly inside it and removes it when it exits.
const DefaultStagingRoot = "/Library/k3sm.staging"

// stagingRootMode is the only mode the staging root and a staged directory may
// carry: root-only, so nothing but root can enter, list or write either.
const stagingRootMode fs.FileMode = 0o700

// stagedTokenMode is the only mode a --from-staging token file may carry.
const stagedTokenMode fs.FileMode = 0o600

// TeamIDRecordName is the file, under the install root, in which a
// --from-staging install records the signing Team ID of the binary it
// installed. It is a record for the operator, rewritten on every such install;
// the continuity check reads the installed binary's own signature, never this
// file.
const TeamIDRecordName = "signing-team-id"

// teamIDRecordMode is the record's mode. A Team ID is public.
const teamIDRecordMode fs.FileMode = 0o644

// StagingLockPath is the lock beside the staging root that serialises the
// k3sm.app copy-outs (/Library/k3sm.staging.lock): the outer of the two
// install locks.
func StagingLockPath(root string) string { return filepath.Clean(root) + installLockSuffix }

var (
	// ErrStagingBusy reports that another process holds the staging lock.
	ErrStagingBusy = errors.New("a k3sm.app install step holds the staging lock on this Mac")
	// ErrStagingUntrusted reports a --from-staging directory (or a staged
	// executable) that fails the staging predicate.
	ErrStagingUntrusted = errors.New("the --from-staging directory is not a trusted k3sm.app staging directory")
	// ErrStagedTokenUntrusted reports a --token-file that fails the strict
	// rules a --from-staging install applies to it.
	ErrStagedTokenUntrusted = errors.New("the --token-file is not a trusted staged token file")
	// ErrUnversioned reports a staged build that carries no release version.
	ErrUnversioned = errors.New("the staged k3sm carries no release version")
	// ErrDowngrade reports a staged version lower than the installed one, or
	// an installed version this install cannot compare against.
	ErrDowngrade = errors.New("the staged k3sm would replace a newer or unknown installed version")
	// ErrTeamIDMismatch reports a staged binary whose signing Team ID differs
	// from the installed binary's, or an installed binary with none.
	ErrTeamIDMismatch = errors.New("the staged k3sm is not signed by the team that signed the installed one")
	// ErrNoTeamID reports a binary with no Developer ID Team ID: ad-hoc
	// signed, or unsigned.
	ErrNoTeamID = errors.New("the binary carries no Developer ID Team ID (it is ad-hoc signed or unsigned)")
)

// StagedEntry is what an lstat says about one path: the full mode (type and
// permission bits), the owner, the device and the link count.
type StagedEntry struct {
	Path  string
	Mode  fs.FileMode
	UID   uint32
	GID   uint32
	Dev   uint64
	Nlink uint64
}

// StagingFS is the read-only filesystem seam the --from-staging predicate is
// judged through. It describes and never follows: every method that names a
// path lstats it or opens it with O_NOFOLLOW.
type StagingFS interface {
	// Lstat describes path without following a symlink. A missing path has
	// an error matching fs.ErrNotExist.
	Lstat(path string) (StagedEntry, error)
	// WalkNoFollow describes every entry beneath dir (not dir itself),
	// descending into real directories only.
	WalkNoFollow(dir string) ([]StagedEntry, error)
	// ReadTokenFile opens path refusing a symlink, judges the open descriptor
	// (a non-regular file matches ErrNotRegularFile) and returns its bytes with
	// the descriptor's facts, so the file judged and the file read are one.
	ReadTokenFile(path string) ([]byte, StagedEntry, error)
	// RemoveFile unlinks path, never following it. Absent is success.
	RemoveFile(path string) error
	// BinaryVersion is the release version stamped into the k3sm binary at
	// path. A missing binary has an error matching fs.ErrNotExist.
	BinaryVersion(path string) (string, error)
}

// TeamIDReader reads the Developer ID Team ID a binary is signed with.
type TeamIDReader interface {
	// TeamID returns path's signing Team ID: an error matching ErrNoTeamID for
	// an ad-hoc or unsigned binary, and one matching fs.ErrNotExist when there
	// is no file.
	TeamID(path string) (string, error)
}

// StagingOptions is the part of Config that `install --from-staging` and the
// k3sm.app staging root add. It is embedded in Config, so its fields read as
// Config's own.
type StagingOptions struct {
	// FromStagingDir is `k3sm install --from-staging <dir>`: the k3sm.app
	// copy-out's staged directory, a direct child of StagingRoot, that this
	// running binary and every file it installs must come from. Empty is a
	// plain install. See preflightFromStaging for the fail-closed predicate.
	FromStagingDir string
	// StagingRoot is the k3sm.app staging root; empty means
	// DefaultStagingRoot (see stagingRoot). Its lock
	// (StagingLockPath) is the outer of the two install locks, and uninstall
	// sweeps the root.
	StagingRoot string
	// Executable is the resolved path of the running k3sm binary. Under
	// --from-staging it must lie inside FromStagingDir; on uninstall it tells
	// a staging lock held by the copy-out that started this binary from one
	// held by anything else.
	Executable string
	// StagedVersion is the running binary's release version. Under
	// --from-staging an unversioned build is refused, and a version lower than
	// the installed one is refused unless AllowDowngrade.
	StagedVersion string
	// AllowDowngrade is --allow-downgrade (with --from-staging only).
	AllowDowngrade bool
	// StagingFS and Signer are the read-only seams the --from-staging
	// predicate and the Team ID continuity check judge through. Install
	// refuses --from-staging when either is nil.
	StagingFS StagingFS
	Signer    TeamIDReader
	// stagedToken is the --token-file content read once, under the strict
	// rules, by preflightFromStaging. When set, operatorJoinToken parses it
	// instead of reading TokenFile, which is already unlinked.
	stagedToken *string
	// stagedTeamID is the staged binary's signing Team ID, recorded into the
	// install root (TeamIDRecordName) by a --from-staging install.
	stagedTeamID string
}

// stagingRoot is StagingRoot, defaulted and cleaned.
func (o StagingOptions) stagingRoot() string {
	if o.StagingRoot == "" {
		return DefaultStagingRoot
	}
	return filepath.Clean(o.StagingRoot)
}

// untrusted builds a staging-predicate refusal.
func untrusted(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrStagingUntrusted, fmt.Sprintf(format, a...))
}

// checkStagingDir is the directory part of the --from-staging predicate:
// dir is a clean absolute path, a DIRECT child of root, no component of it is
// a symlink, root and dir are root:wheel 0700 on one device, and every entry
// beneath dir is a root-owned real directory or regular file with no group or
// other write and no setuid or setgid bit, on that same device.
func checkStagingDir(sfs StagingFS, root, dir string) error {
	if err := checkStagingDirSelf(sfs, root, dir); err != nil {
		return err
	}
	return checkStagingTree(sfs, dir)
}

// checkStagingDirSelf is the directory half of the predicate, without the
// tree: the path shape, no symlink component, root:wheel 0700 on one device.
func checkStagingDirSelf(sfs StagingFS, root, dir string) error {
	root = filepath.Clean(root)
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return untrusted("%s is not a clean absolute path", dir)
	}
	if filepath.Dir(dir) != root || dir == root {
		return untrusted("%s is not a directory directly inside %s", dir, root)
	}
	// Every component from the top down, so the first symlink named is the one
	// nearest the filesystem root.
	var comps []string
	for p := dir; p != filepath.Dir(p); p = filepath.Dir(p) {
		comps = append(comps, p)
	}
	byPath := map[string]StagedEntry{}
	for i := len(comps) - 1; i >= 0; i-- {
		e, err := sfs.Lstat(comps[i])
		if err != nil {
			return fmt.Errorf("%w: inspect %s: %w", ErrStagingUntrusted, comps[i], err)
		}
		switch {
		case e.Mode&fs.ModeSymlink != 0:
			return untrusted("%s is a symlink", comps[i])
		case !e.Mode.IsDir():
			return untrusted("%s is not a directory", comps[i])
		}
		byPath[comps[i]] = e
	}
	rootE, dirE := byPath[root], byPath[dir]
	for _, name := range []string{root, dir} {
		e := byPath[name]
		if e.UID != 0 || e.GID != 0 {
			return untrusted("%s is owned by %d:%d, not root:wheel", name, e.UID, e.GID)
		}
		if e.Mode.Perm() != stagingRootMode || e.Mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
			return untrusted("%s is mode %04o, not %04o", name, e.Mode.Perm(), stagingRootMode)
		}
	}
	if rootE.Dev != dirE.Dev {
		return untrusted("%s and %s are on different devices", root, dir)
	}
	return nil
}

// checkStagingTree is the tree half of the predicate: every entry beneath dir
// is a root-owned real directory or regular file with no group or other write
// and no setuid or setgid bit, on dir's device. Run it only after
// checkStagingDirSelf has accepted dir.
func checkStagingTree(sfs StagingFS, dir string) error {
	dirE, err := sfs.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: inspect %s: %w", ErrStagingUntrusted, dir, err)
	}
	entries, err := sfs.WalkNoFollow(dir)
	if err != nil {
		return fmt.Errorf("%w: walk %s: %w", ErrStagingUntrusted, dir, err)
	}
	for _, e := range entries {
		switch {
		case e.Mode&fs.ModeSymlink != 0:
			return untrusted("%s is a symlink", e.Path)
		case !e.Mode.IsRegular() && !e.Mode.IsDir():
			return untrusted("%s is a special file", e.Path)
		case e.UID != 0:
			return untrusted("%s is owned by uid %d, not root", e.Path, e.UID)
		case e.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0:
			return untrusted("%s is setuid or setgid", e.Path)
		case e.Mode.Perm()&0o022 != 0:
			return untrusted("%s is writable by its group or by others (mode %04o)", e.Path, e.Mode.Perm())
		case e.Dev != dirE.Dev:
			return untrusted("%s is on a different device from %s", e.Path, dir)
		}
	}
	return nil
}

// pathInside reports whether the absolute path p lies strictly inside dir,
// lexically. The tree walk is what rules out a symlink on the way.
func pathInside(dir, p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	rel, err := filepath.Rel(dir, filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// preflightFromStaging runs the whole --from-staging predicate on cfg, before
// anything is written. It is a no-op on a plain install. On success it leaves
// the token bytes (when there is a --token-file) and the staged Team ID on cfg.
//
// The staged directory itself is judged first, because every later step
// trusts paths inside it. The token is read and unlinked second, so it is gone
// before any other refusal (the tree walk included) can return and before any
// daemon exists.
func preflightFromStaging(cfg *Config) error {
	if cfg.FromStagingDir == "" {
		if cfg.AllowDowngrade {
			return fmt.Errorf("install: AllowDowngrade applies only to an install from a k3sm.app staging directory")
		}
		return nil
	}
	if cfg.StagingFS == nil || cfg.Signer == nil {
		return fmt.Errorf("install: an install from a staging directory needs its filesystem and signature seams")
	}
	dir := cfg.FromStagingDir
	if err := checkStagingDirSelf(cfg.StagingFS, cfg.stagingRoot(), dir); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	// The token straight after the directory itself is proven root-only, and
	// before the tree walk, so a tree refusal still finds it unlinked.
	if cfg.TokenFile != "" {
		token, err := readStagedToken(cfg.StagingFS, dir, cfg.TokenFile)
		if err != nil {
			return fmt.Errorf("install: %w", err)
		}
		cfg.stagedToken = &token
	}
	if err := checkStagingTree(cfg.StagingFS, dir); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if !pathInside(dir, cfg.Executable) {
		return fmt.Errorf("install: %w", untrusted("this k3sm runs from %s, which is not inside %s", cfg.Executable, dir))
	}
	for _, src := range stagingSources(*cfg) {
		if src != "" && !pathInside(dir, src) {
			return fmt.Errorf("install: %w", untrusted("%s is not inside %s, and an install from a staging directory copies nothing from anywhere else", src, dir))
		}
	}
	if err := checkStagedVersion(*cfg); err != nil {
		return err
	}
	teamID, err := checkTeamIDContinuity(*cfg)
	if err != nil {
		return err
	}
	cfg.stagedTeamID = teamID
	return nil
}

// readStagedToken applies the strict --from-staging rules to the token file:
// a direct child of dir, opened without following a symlink, a regular file
// owned by root with mode exactly 0600 and one link. It is read once and
// unlinked straight after the read, whatever the read found, so no refusal
// below and no later failure can leave it behind. Neither the bytes nor any
// part of them appear in an error.
func readStagedToken(sfs StagingFS, dir, path string) (string, error) {
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrStagedTokenUntrusted, fmt.Sprintf(format, a...))
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != dir {
		return "", refuse("%s is not a file directly inside %s", path, dir)
	}
	raw, e, readErr := sfs.ReadTokenFile(path)
	if err := sfs.RemoveFile(path); err != nil {
		return "", refuse("remove %s after reading it: %v", path, err)
	}
	switch {
	case errors.Is(readErr, ErrNotRegularFile):
		return "", refuse("%s is not a regular file", path)
	case readErr != nil:
		return "", fmt.Errorf("%w: read %s: %w", ErrStagedTokenUntrusted, path, readErr)
	case e.UID != 0:
		return "", refuse("%s is owned by uid %d, not root", path, e.UID)
	case e.Mode.Perm() != stagedTokenMode || e.Mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0:
		return "", refuse("%s is mode %04o, not %04o", path, e.Mode.Perm(), stagedTokenMode)
	case e.Nlink != 1:
		return "", refuse("%s has %d links, not 1", path, e.Nlink)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", refuse("%s is empty", path)
	}
	return token, nil
}

// checkStagedVersion refuses an unversioned staged build, and a staged version
// lower than the installed one unless AllowDowngrade. An installed version
// that cannot be read or compared is treated as a downgrade: the override is
// the same flag, and the default is to refuse.
func checkStagedVersion(cfg Config) error {
	staged, ok := parseReleaseVersion(cfg.StagedVersion)
	if !ok {
		return fmt.Errorf("install: %w: %q is not a release version, and an install from a staging directory takes only a release build", ErrUnversioned, cfg.StagedVersion)
	}
	installedPath := cfg.installedBinary()
	raw, err := cfg.StagingFS.BinaryVersion(installedPath)
	var reason string
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		reason = fmt.Sprintf("the version of the installed %s could not be read (%v)", installedPath, err)
	default:
		installed, ok := parseReleaseVersion(raw)
		switch {
		case !ok:
			reason = fmt.Sprintf("the installed %s reports %q, which is not a release version", installedPath, raw)
		case staged.compare(installed) < 0:
			reason = fmt.Sprintf("the installed k3sm is %s and this one is %s", raw, cfg.StagedVersion)
		default:
			return nil
		}
	}
	if cfg.AllowDowngrade {
		cfg.Logger.Warn("installing over a newer or unknown version because --allow-downgrade was passed", "reason", reason)
		return nil
	}
	return fmt.Errorf("install: %w: %s; pass --allow-downgrade to install it anyway", ErrDowngrade, reason)
}

// checkTeamIDContinuity returns the staged binary's signing Team ID after
// proving it may replace what is installed: the staged binary must carry a
// Team ID, and on an update the installed binary must carry the same one. An
// ad-hoc or unsigned installed binary refuses, because nothing then ties the
// staged build to whoever installed the current one. A first install has
// nothing to compare and records the Team ID.
func checkTeamIDContinuity(cfg Config) (string, error) {
	staged, err := cfg.Signer.TeamID(cfg.Executable)
	if err != nil {
		return "", fmt.Errorf("install: read the signing Team ID of the staged %s: %w", cfg.Executable, err)
	}
	installedPath := cfg.installedBinary()
	installed, err := cfg.Signer.TeamID(installedPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		cfg.Logger.Info("first install from a k3sm.app staging directory: recording the signing Team ID", "team-id", staged)
		return staged, nil
	case errors.Is(err, ErrNoTeamID):
		return "", fmt.Errorf("install: %w: the installed %s carries no Team ID (it is ad-hoc signed or unsigned), so nothing ties the staged build to it; run `sudo k3sm uninstall` and install again", ErrTeamIDMismatch, installedPath)
	case err != nil:
		return "", fmt.Errorf("install: read the signing Team ID of the installed %s: %w", installedPath, err)
	case installed != staged:
		return "", fmt.Errorf("install: %w: the installed %s is signed by team %s and the staged one by team %s", ErrTeamIDMismatch, installedPath, installed, staged)
	}
	return staged, nil
}

// releaseVersion is a parsed semantic version. Build metadata is dropped, as
// semver orders it.
type releaseVersion struct {
	major, minor, patch uint64
	pre                 []string
}

// semverPattern is MAJOR.MINOR.PATCH with an optional leading v, an optional
// pre-release and optional build metadata.
var semverPattern = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// pseudoVersionTail is the timestamp-and-commit tail of a Go pseudo-version
// (v0.0.0-20261013000000-abcdefabcdef and its variants): the version a build
// with no release stamp reports, which is not a release.
var pseudoVersionTail = regexp.MustCompile(`(^|[.-])\d{14}-[0-9a-f]{12}$`)

// parseReleaseVersion parses a release version. "dev", an empty string, a Go
// pseudo-version and anything else that is not semver report false.
func parseReleaseVersion(s string) (releaseVersion, bool) {
	m := semverPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return releaseVersion{}, false
	}
	if m[4] != "" && pseudoVersionTail.MatchString(m[4]) {
		return releaseVersion{}, false
	}
	var v releaseVersion
	var err error
	if v.major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return releaseVersion{}, false
	}
	if v.minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return releaseVersion{}, false
	}
	if v.patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return releaseVersion{}, false
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

// compare orders two versions by semver precedence: -1, 0 or 1.
func (v releaseVersion) compare(o releaseVersion) int {
	for _, d := range [][2]uint64{{v.major, o.major}, {v.minor, o.minor}, {v.patch, o.patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	// A release outranks any of its pre-releases.
	switch {
	case len(v.pre) == 0 && len(o.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1
	case len(o.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		if c := comparePreIdent(v.pre[i], o.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(v.pre) < len(o.pre):
		return -1
	case len(v.pre) > len(o.pre):
		return 1
	}
	return 0
}

// comparePreIdent orders two pre-release identifiers: numeric ones
// numerically and below alphanumeric ones, alphanumeric ones in ASCII order.
func comparePreIdent(a, b string) int {
	an, aerr := strconv.ParseUint(a, 10, 64)
	bn, berr := strconv.ParseUint(b, 10, 64)
	switch {
	case aerr == nil && berr == nil:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// lockMode says which caller is taking the two locks, because the two answer
// a staging lock someone else holds differently.
type lockMode int

const (
	// lockInstallFromStaging is `install --from-staging`: the predicate has
	// already proved this binary runs from a live staged directory, which
	// exists only while the copy-out that made it holds the staging lock. A
	// held lock is therefore that copy-out's, and is accepted.
	lockInstallFromStaging lockMode = iota
	// lockUninstall is `uninstall`: a held staging lock is accepted only when
	// this binary itself runs from a staged directory that passes the
	// predicate (the app's own uninstall step); otherwise a copy-out is
	// running and the uninstall is refused.
	lockUninstall
)

// lockStagingThenInstall takes the two locks in the one fixed order: the
// staging lock (outer), then the install lock (inner). Every holder of both
// takes them in this order, so no two of them can each hold one and wait on
// the other. A plain install takes only the inner one, which keeps the order.
// The returned release drops them in reverse.
func lockStagingThenInstall(sys System, cfg Config, mode lockMode) (func(), error) {
	var releases []func()
	release := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	stagingLock := StagingLockPath(cfg.stagingRoot())
	unlockStaging, err := sys.LockStaging(stagingLock)
	switch {
	case errors.Is(err, ErrStagingBusy):
		if mode == lockUninstall && !runsFromStaging(cfg) {
			return nil, err
		}
		cfg.Logger.Info("the staging lock is held by the k3sm.app step that started this command", "path", stagingLock)
	case err != nil:
		return nil, err
	default:
		releases = append(releases, func() {
			if err := unlockStaging(); err != nil {
				cfg.Logger.Warn("could not release the staging lock", "path", stagingLock, "err", err)
			}
		})
	}
	unlockInstall, err := sys.LockInstall(cfg.installLockPath())
	if err != nil {
		release()
		return nil, err
	}
	releases = append(releases, func() {
		if err := unlockInstall(); err != nil {
			cfg.Logger.Warn("could not release the install lock", "path", cfg.installLockPath(), "err", err)
		}
	})
	return release, nil
}

// lockForInstall takes the locks an install holds from its first write to its
// return: the install lock, and before it the staging lock when the install is
// from a k3sm.app staging directory.
func lockForInstall(sys System, cfg Config) (func(), error) {
	if cfg.FromStagingDir != "" {
		return lockStagingThenInstall(sys, cfg, lockInstallFromStaging)
	}
	unlock, err := sys.LockInstall(cfg.installLockPath())
	if err != nil {
		return nil, err
	}
	return func() {
		if err := unlock(); err != nil {
			cfg.Logger.Warn("could not release the install lock", "path", cfg.installLockPath(), "err", err)
		}
	}, nil
}

// recordTeamID writes the signing Team ID a --from-staging install proved
// (checkTeamIDContinuity) into the staged install root, so it is published
// with the binary it describes. A plain install records nothing.
func recordTeamID(sys System, cfg Config) error {
	if cfg.stagedTeamID == "" {
		return nil
	}
	record := cfg.stagedPath(filepath.Join(cfg.InstallDir, TeamIDRecordName))
	if err := sys.WriteRootOnlyFile(record, []byte(cfg.stagedTeamID+"\n"), teamIDRecordMode); err != nil {
		return fmt.Errorf("install: record the signing Team ID at %s: %w", record, err)
	}
	return nil
}

// uninstallLocked is Uninstall with its defaults applied: an unconfirmed purge
// refuses before anything is touched; otherwise both locks are taken (staging
// first), the teardown or purge runs, and a teardown that succeeded ends with
// the staging sweep. A failed one leaves the staging trees for the re-run, so
// a purge that reports "nothing was removed" removed nothing.
func uninstallLocked(ctx context.Context, sys System, cfg Config) error {
	if cfg.Purge && !cfg.PurgeConfirmed {
		return ErrPurgeNotConfirmed
	}
	release, err := lockStagingThenInstall(sys, cfg, lockUninstall)
	if err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	defer release()
	if cfg.Purge {
		err = purge(ctx, sys, cfg)
	} else {
		_, err = uninstall(ctx, sys, cfg, nil)
	}
	if err != nil {
		return err
	}
	if err := sweepStaging(sys, cfg); err != nil {
		return fmt.Errorf("uninstall: staging sweep: %w", err)
	}
	return nil
}

// runsFromStaging reports whether cfg.Executable lies inside a direct child of
// the staging root that passes the staging predicate: the k3sm.app root step's
// own staged CLI.
func runsFromStaging(cfg Config) bool {
	if cfg.StagingFS == nil || cfg.Executable == "" {
		return false
	}
	root := cfg.stagingRoot()
	if !pathInside(root, cfg.Executable) {
		return false
	}
	rel, err := filepath.Rel(root, filepath.Clean(cfg.Executable))
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	child := filepath.Join(root, first)
	if child == filepath.Clean(cfg.Executable) {
		return false
	}
	return checkStagingDir(cfg.StagingFS, root, child) == nil
}

// sweepStaging removes the k3sm.app staging root and any install swap tree
// left by an interrupted install. It runs under both locks, judges each path
// with an lstat first (a symlink, a non-directory, a non-root owner or a
// group- or other-writable directory is refused, never followed), and removes
// a trusted tree without following any symlink inside it. A tree an older
// build left at the staging root under the old swap name is removed here, and
// only here.
func sweepStaging(sys System, cfg Config) error {
	var firstErr error
	for _, path := range []string{cfg.stagingRoot(), cfg.swapDir()} {
		present, err := trustedStagingPath(sys, path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !present {
			continue
		}
		if err := sys.RemoveTree(path); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("remove %s: %w", path, err)
			}
			continue
		}
		cfg.Logger.Info("removed a k3sm staging directory", "path", path)
	}
	return firstErr
}

// versionStampPrefix is the -X flag the release pipeline stamps the version
// with (pkg/version.Version).
const versionStampPrefix = "k3sm.io/k3sm/pkg/version.Version="

// stampedVersion is the version a k3sm binary reports, from its build
// information: the -X stamp in the recorded -ldflags when there is one,
// otherwise the main module's version, otherwise "dev".
func stampedVersion(bi *debug.BuildInfo) string {
	for _, s := range bi.Settings {
		if s.Key != "-ldflags" {
			continue
		}
		fields := strings.Fields(s.Value)
		for i, f := range fields {
			f = strings.Trim(f, `"'`)
			switch {
			case f == "-X" && i+1 < len(fields):
				if v, ok := strings.CutPrefix(strings.Trim(fields[i+1], `"'`), versionStampPrefix); ok {
					return v
				}
			case strings.HasPrefix(f, "-X="):
				if v, ok := strings.CutPrefix(strings.TrimPrefix(f, "-X="), versionStampPrefix); ok {
					return v
				}
			}
		}
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return "dev"
}

// parseTeamIdentifier reads the TeamIdentifier line of `codesign -dv` output.
// "not set", an ad-hoc signature, or no line at all match ErrNoTeamID; a value
// that is not ten uppercase letters or digits is an error.
func parseTeamIdentifier(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "not set" || v == "" {
			return "", ErrNoTeamID
		}
		if !validTeamID(v) {
			return "", fmt.Errorf("codesign reported TeamIdentifier %q, which is not a Team ID", v)
		}
		return v, nil
	}
	return "", ErrNoTeamID
}

// validTeamID reports whether s is a Team ID: exactly ten uppercase ASCII
// letters or digits.
func validTeamID(s string) bool {
	if len(s) != 10 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
