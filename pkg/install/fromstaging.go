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
//     0600, a regular file with one link, read once and unlinked at once
//     (stagingtoken.go);
//   - the staged version is a release version no lower than the installed one
//     (unless --allow-downgrade; releaseversion.go);
//   - the tree's signing follows the installed build (checkSigningContinuity):
//     a team-signed install takes only that team's Developer ID signature on
//     every Mach-O, an ad-hoc signed install takes an ad-hoc tree or a
//     team-signed one, and a first install takes only a team-signed tree;
//   - with --require-team-signature, every Mach-O in the tree, the staged k3sm
//     included, carries a valid Developer ID Application signature of its own
//     team, judged on its own and not against the installed build.
//
// Any doubt refuses. The copy-out removes its staging directory on every exit
// path, so a refusal costs one re-run and leaves nothing behind. The two locks
// and uninstall's staging sweep are in staginglock.go.

// DefaultStagingRoot is the k3sm.app copy-out's staging root. Each copy-out
// makes one directory directly inside it and removes it when it exits.
const DefaultStagingRoot = "/Library/k3sm.staging"

// stagingRootMode is the only mode the staging root and a staged directory may
// carry: root-only, so nothing but root can enter, list or write either.
const stagingRootMode fs.FileMode = 0o700

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
	// ErrTeamIDMismatch reports a binary whose signing Team ID differs from
	// the staged k3sm's, or an installed binary with none.
	ErrTeamIDMismatch = errors.New("the binary is not signed by the team that signed the staged k3sm")
	// ErrNoTeamID reports a binary with no valid identity signature: ad-hoc
	// signed, unsigned, or failing verification.
	ErrNoTeamID = errors.New("the binary carries no Developer ID Team ID (it is ad-hoc signed, unsigned or invalid)")
	// ErrNotDeveloperID reports a signature from the right team that is not a
	// Developer ID Application signature (an Apple Development one, say).
	ErrNotDeveloperID = errors.New("the binary is not signed with a Developer ID Application certificate")
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
	// MachO reports whether the regular file at path starts with a Mach-O or
	// universal-binary magic number, opening it without following a symlink.
	MachO(path string) (bool, error)
}

// TeamIDReader reads and checks the code signature of a binary.
type TeamIDReader interface {
	// TeamID returns the Team ID of path's valid identity signature: an error
	// matching ErrNoTeamID for an ad-hoc, unsigned or invalid one, and one
	// matching fs.ErrNotExist when there is no file.
	TeamID(ctx context.Context, path string) (string, error)
	// DeveloperID reports whether path's signature verifies strictly against
	// the Developer ID Application requirement for teamID.
	DeveloperID(ctx context.Context, path, teamID string) (bool, error)
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
	// DefaultStagingRoot (see stagingRoot). Its lock (StagingLockPath) is the
	// outer of the two install locks, and uninstall sweeps the root.
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
	// RequireTeamSignature is --require-team-signature (with --from-staging
	// only): refuse the tree unless every Mach-O in it carries a Developer ID
	// Application team signature, whatever the installed build carries. The
	// managed update passes it for the required signature policy. The
	// same-team continuity check runs as well.
	RequireTeamSignature bool
	// StagingFS and Signer are the read-only seams the --from-staging
	// predicate and the signing continuity check judge through. Install
	// refuses --from-staging when either is nil.
	StagingFS StagingFS
	Signer    TeamIDReader
	// stagedToken is the --token-file content read once, under the strict
	// rules, by preflightFromStaging. When set, operatorJoinToken parses it
	// instead of reading TokenFile, which is already unlinked. It prints and
	// logs as a redaction (see secretToken).
	stagedToken *secretToken
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
// checkStagingDirSelf, then checkStagingTree.
func checkStagingDir(sfs StagingFS, root, dir string) error {
	if err := checkStagingDirSelf(sfs, root, dir); err != nil {
		return err
	}
	_, err := checkStagingTree(sfs, dir)
	return err
}

// checkStagingDirSelf is the directory half of the predicate, without the
// tree: dir is a clean absolute path and a DIRECT child of root, no component
// of it is a symlink, and root and dir are root:wheel 0700 on one device.
func checkStagingDirSelf(sfs StagingFS, root, dir string) error {
	root = filepath.Clean(root)
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return untrusted("%s is not a clean absolute path", dir)
	}
	if filepath.Dir(dir) != root || dir == root {
		return untrusted("%s is not a directory directly inside %s", dir, root)
	}
	byPath, err := lstatComponents(sfs, dir)
	if err != nil {
		return err
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

// lstatComponents lstats every component of dir from the top down and
// refuses the first that is a symlink or not a directory, so the one named is
// the one nearest the filesystem root.
func lstatComponents(sfs StagingFS, dir string) (map[string]StagedEntry, error) {
	var comps []string
	for p := dir; p != filepath.Dir(p); p = filepath.Dir(p) {
		comps = append(comps, p)
	}
	byPath := map[string]StagedEntry{}
	for i := len(comps) - 1; i >= 0; i-- {
		e, err := sfs.Lstat(comps[i])
		if err != nil {
			return nil, fmt.Errorf("%w: inspect %s: %w", ErrStagingUntrusted, comps[i], err)
		}
		switch {
		case e.Mode&fs.ModeSymlink != 0:
			return nil, untrusted("%s is a symlink", comps[i])
		case !e.Mode.IsDir():
			return nil, untrusted("%s is not a directory", comps[i])
		}
		byPath[comps[i]] = e
	}
	return byPath, nil
}

// checkStagingTree is the tree half of the predicate: every entry beneath dir
// is a root-owned real directory or regular file with no group or other write
// and no setuid or setgid bit, on dir's device. It returns the entries, which
// the signing continuity check scans for Mach-O files. Run it only after
// checkStagingDirSelf has accepted dir.
func checkStagingTree(sfs StagingFS, dir string) ([]StagedEntry, error) {
	dirE, err := sfs.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect %s: %w", ErrStagingUntrusted, dir, err)
	}
	entries, err := sfs.WalkNoFollow(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: walk %s: %w", ErrStagingUntrusted, dir, err)
	}
	for _, e := range entries {
		switch {
		case e.Mode&fs.ModeSymlink != 0:
			return nil, untrusted("%s is a symlink", e.Path)
		case !e.Mode.IsRegular() && !e.Mode.IsDir():
			return nil, untrusted("%s is a special file", e.Path)
		case e.UID != 0:
			return nil, untrusted("%s is owned by uid %d, not root", e.Path, e.UID)
		case e.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0:
			return nil, untrusted("%s is setuid or setgid", e.Path)
		case e.Mode.Perm()&0o022 != 0:
			return nil, untrusted("%s is writable by its group or by others (mode %04o)", e.Path, e.Mode.Perm())
		case e.Dev != dirE.Dev:
			return nil, untrusted("%s is on a different device from %s", e.Path, dir)
		}
	}
	return entries, nil
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
// the token (when there is a --token-file) on cfg.
//
// The staged directory itself is judged first, because every later step
// trusts paths inside it. The token is read and unlinked second, so it is gone
// before any other refusal (the tree walk included) can return and before any
// daemon exists. A refusal that comes before the token could be read still
// unlinks it, unread, when it sits where a copy-out puts one
// (DiscardStagedToken).
func preflightFromStaging(ctx context.Context, cfg *Config) error {
	if cfg.FromStagingDir == "" {
		if cfg.AllowDowngrade {
			return fmt.Errorf("install: AllowDowngrade applies only to an install from a k3sm.app staging directory")
		}
		if cfg.RequireTeamSignature {
			return fmt.Errorf("install: RequireTeamSignature applies only to an install from a k3sm.app staging directory")
		}
		return nil
	}
	if cfg.StagingFS == nil || cfg.Signer == nil {
		return fmt.Errorf("install: an install from a staging directory needs its filesystem and signature seams")
	}
	dir := cfg.FromStagingDir
	if err := checkStagingDirSelf(cfg.StagingFS, cfg.stagingRoot(), dir); err != nil {
		cfg.discardToken()
		return fmt.Errorf("install: %w", err)
	}
	if cfg.TokenFile != "" {
		token, err := readStagedToken(cfg.StagingFS, dir, cfg.TokenFile)
		if err != nil {
			cfg.discardToken()
			return fmt.Errorf("install: %w", err)
		}
		cfg.stagedToken = token
	}
	entries, err := checkStagingTree(cfg.StagingFS, dir)
	if err != nil {
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
	if cfg.RequireTeamSignature {
		if err := requireTeamSignatures(ctx, *cfg, entries); err != nil {
			return err
		}
	}
	if err := checkSigningContinuity(ctx, *cfg, entries); err != nil {
		return err
	}
	// Last, because it runs the installed binary: only a tree that passed
	// every signing check gets that far.
	return checkStagedVersion(*cfg)
}

// requireTeamSignatures is --require-team-signature: the staged k3sm and every
// other Mach-O in the staged tree must carry a valid identity signature whose
// certificate is a Developer ID Application certificate of the team it names.
// It never consults the installed binary, so an ad-hoc signed installed build
// does not relax it.
func requireTeamSignatures(ctx context.Context, cfg Config, entries []StagedEntry) error {
	others, err := treeMachOs(cfg, entries)
	if err != nil {
		return err
	}
	for _, p := range append([]string{cfg.Executable}, others...) {
		team, err := cfg.Signer.TeamID(ctx, p)
		if err != nil {
			return fmt.Errorf("install: --require-team-signature: %s: %w", p, err)
		}
		if err := requireDeveloperID(ctx, cfg.Signer, p, team); err != nil {
			return fmt.Errorf("--require-team-signature: %w", err)
		}
	}
	return nil
}

// discardToken is DiscardStagedToken for cfg's --token-file.
func (c Config) discardToken() {
	if c.TokenFile != "" && c.StagingFS != nil {
		DiscardStagedToken(c.StagingFS, c.stagingRoot(), c.TokenFile)
	}
}

// checkSigningContinuity proves the staged tree may replace what is installed,
// and the installed build decides the rule:
//
//   - a team-signed install (a Developer ID Application signature) takes only
//     a tree whose staged k3sm and every other Mach-O carry that same team's
//     Developer ID Application signature, so an ad-hoc tree never replaces it;
//   - an ad-hoc signed install takes either a tree signed by one Developer ID
//     team (the staged k3sm's, on every Mach-O) or an ad-hoc tree, in which
//     no Mach-O carries a team signature;
//   - a first install, with nothing installed, takes only a team-signed tree:
//     the installed binary's signature is the record the next update is
//     checked against.
//
// "Ad-hoc" here is what TeamID reports as ErrNoTeamID: ad-hoc, unsigned or
// failing verification. macOS on Apple Silicon refuses to run an unsigned or
// invalid Mach-O, so such a tree installs a build that will not start rather
// than one that runs unchecked. --require-team-signature
// (requireTeamSignatures) refuses any tree without a team signature first,
// whatever is installed.
func checkSigningContinuity(ctx context.Context, cfg Config, entries []StagedEntry) error {
	installed := cfg.installedBinary()
	installedTeam, err := cfg.Signer.TeamID(ctx, installed)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		team, err := stagedTeam(ctx, cfg)
		if err != nil {
			return err
		}
		if err := requireTreeTeam(ctx, cfg, entries, team); err != nil {
			return err
		}
		cfg.Logger.Info("first install from a k3sm.app staging directory", "team-id", team)
		return nil
	case errors.Is(err, ErrNoTeamID):
		team, err := cfg.Signer.TeamID(ctx, cfg.Executable)
		switch {
		case errors.Is(err, ErrNoTeamID):
			if err := requireTreeAdHoc(ctx, cfg, entries); err != nil {
				return err
			}
			cfg.Logger.Info("updating an ad-hoc signed install with an ad-hoc signed build")
			return nil
		case err != nil:
			return fmt.Errorf("install: read the signing Team ID of the staged %s: %w", cfg.Executable, err)
		}
		if err := requireDeveloperID(ctx, cfg.Signer, cfg.Executable, team); err != nil {
			return err
		}
		if err := requireTreeTeam(ctx, cfg, entries, team); err != nil {
			return err
		}
		cfg.Logger.Info("updating an ad-hoc signed install with a team-signed build", "team-id", team)
		return nil
	case err != nil:
		return fmt.Errorf("install: read the signing Team ID of the installed %s: %w", installed, err)
	}
	if err := requireDeveloperID(ctx, cfg.Signer, installed, installedTeam); err != nil {
		return err
	}
	if err := requireTeam(ctx, cfg.Signer, cfg.Executable, installedTeam); err != nil {
		return err
	}
	return requireTreeTeam(ctx, cfg, entries, installedTeam)
}

// stagedTeam is the Team ID of the staged k3sm's Developer ID Application
// signature, or a refusal.
func stagedTeam(ctx context.Context, cfg Config) (string, error) {
	team, err := cfg.Signer.TeamID(ctx, cfg.Executable)
	if err != nil {
		return "", fmt.Errorf("install: read the signing Team ID of the staged %s: %w", cfg.Executable, err)
	}
	if err := requireDeveloperID(ctx, cfg.Signer, cfg.Executable, team); err != nil {
		return "", err
	}
	return team, nil
}

// treeMachOs returns every regular file of the staged tree, other than the
// staged k3sm, that is a Mach-O.
func treeMachOs(cfg Config, entries []StagedEntry) ([]string, error) {
	var out []string
	for _, e := range entries {
		if !e.Mode.IsRegular() || e.Path == cfg.Executable {
			continue
		}
		macho, err := cfg.StagingFS.MachO(e.Path)
		if err != nil {
			return nil, fmt.Errorf("install: %w", untrusted("read %s: %v", e.Path, err))
		}
		if macho {
			out = append(out, e.Path)
		}
	}
	return out, nil
}

// requireTreeTeam refuses the tree unless every Mach-O other than the staged
// k3sm carries team's Developer ID Application signature.
func requireTreeTeam(ctx context.Context, cfg Config, entries []StagedEntry, team string) error {
	paths, err := treeMachOs(cfg, entries)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := requireTeam(ctx, cfg.Signer, p, team); err != nil {
			return err
		}
	}
	return nil
}

// requireTreeAdHoc refuses an ad-hoc staged tree in which some Mach-O carries
// a team signature anyway: a tree is signed one way or the other.
func requireTreeAdHoc(ctx context.Context, cfg Config, entries []StagedEntry) error {
	paths, err := treeMachOs(cfg, entries)
	if err != nil {
		return err
	}
	for _, p := range paths {
		team, err := cfg.Signer.TeamID(ctx, p)
		switch {
		case errors.Is(err, ErrNoTeamID):
		case err != nil:
			return fmt.Errorf("install: read the signing Team ID of %s: %w", p, err)
		default:
			return fmt.Errorf("install: %w: %s is signed by team %s and the staged k3sm is ad-hoc signed", ErrTeamIDMismatch, p, team)
		}
	}
	return nil
}

// requireTeam refuses path unless its signature names team and is a
// Developer ID Application signature.
func requireTeam(ctx context.Context, r TeamIDReader, path, team string) error {
	got, err := r.TeamID(ctx, path)
	switch {
	case errors.Is(err, ErrNoTeamID):
		return fmt.Errorf("install: %w: %s carries no Team ID, and the staged k3sm is signed by team %s: %w", ErrTeamIDMismatch, path, team, err)
	case err != nil:
		return fmt.Errorf("install: read the signing Team ID of %s: %w", path, err)
	case got != team:
		return fmt.Errorf("install: %w: %s is signed by team %s and the staged k3sm by team %s", ErrTeamIDMismatch, path, got, team)
	}
	return requireDeveloperID(ctx, r, path, team)
}

// requireDeveloperID refuses path unless it verifies against the Developer ID
// Application requirement for team.
func requireDeveloperID(ctx context.Context, r TeamIDReader, path, team string) error {
	ok, err := r.DeveloperID(ctx, path, team)
	if err != nil {
		return fmt.Errorf("install: check %s against the Developer ID requirement: %w", path, err)
	}
	if !ok {
		return fmt.Errorf("install: %w: %s (team %s)", ErrNotDeveloperID, path, team)
	}
	return nil
}

// isMachOMagic reports whether the first four bytes of a file are a Mach-O
// magic number (MH_MAGIC, MH_MAGIC_64 and their byte-swapped forms) or a
// universal-binary one (FAT_MAGIC, FAT_MAGIC_64 and theirs).
func isMachOMagic(b [4]byte) bool {
	be := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	switch be {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return true
	}
	return false
}
