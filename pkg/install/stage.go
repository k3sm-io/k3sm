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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// The staged install root: why the copies do not land in /Library/k3sm.
//
// Install lays down about ten artifacts under InstallDir — the binary, four
// sibling helpers, the control-plane payload and its version marker — and it
// used to copy them straight into the live tree, one after another. Every one of
// those copies is a moment at which a full disk, an I/O error, a signal or a
// power loss leaves the tree HALF NEW: the new binary beside the old helpers,
// with the daemons still running the previous build. That state is not merely
// untidy. The LaunchDaemon plists name fixed paths under InstallDir and launchd's
// KeepAlive re-execs whatever is at those paths on the next respawn, so a crash
// in that window promotes a combination of artifacts nothing ever tested.
//
// So the whole tree is built at a SIBLING path first and published in one step:
//
//	stage  → every artifact is copied into <InstallDir>.staging
//	swap   → the staged tree and the live tree exchange places (SwapInstallRoot)
//	plists → rendered and written, naming the same fixed live paths as before
//	restart + verify → the daemons come up on the new tree and are proven healthy
//	reap   → and only THEN is the previous tree, still sitting at the staging
//	         path, removed
//
// Deferring the reap to the very end is what makes the window recoverable: until
// it runs, the previous install is intact at a known path, and one more swap puts
// it back (revertInstallRoot). A failure before the swap leaves the live root
// byte-for-byte as it was and has nothing to undo.
//
// What the swap does NOT claim: rename(2) is documented atomic with respect to
// other processes, and its crash/power-loss durability on APFS follows from the
// filesystem's transactional metadata design rather than from any statement in
// the manual page — which does not restate even the same-process guarantee for
// the swap variant. The claim this code makes is the one the page supports: no
// observer ever sees a partially published tree. The crash case is an inference,
// and it is written here as one.
//
// One behavioural consequence of publishing a whole tree rather than overwriting
// files in it: the live root after an install is EXACTLY what this install
// staged. A file an older build left under InstallDir and this one does not write
// — the kine version marker, when the payload has none — is gone rather than
// inherited. That is the truthful outcome (the tree now describes the payload
// that was installed), and nothing under InstallDir is state: everything there is
// re-copied from source on every install, and the uninstall manifest already
// sweeps the whole directory.

const (
	// installStagingSuffix makes the staging directory a SIBLING of the install
	// root rather than a child of it. Sibling is structural, not stylistic: the
	// publish step exchanges the two paths, which the kernel will only do within
	// one filesystem, and /Library is a firmlink onto the Data volume, so a
	// sibling under /Library is guaranteed to be on the same filesystem as
	// /Library/k3sm. A child of the install root could not be swapped with its
	// own parent at all.
	installStagingSuffix = ".staging"
	// installLockSuffix names the install-wide lock file, likewise beside the
	// install root rather than inside it — a lock held on a file in the tree
	// being swapped would follow the tree out of the way mid-install.
	installLockSuffix = ".lock"
)

// stagingDirMode is the staging tree's mode, and it is the install root's own
// (root:wheel 0755) rather than a tighter one: the directory BECOMES the install
// root moments later, so staging it at 0700 would publish a tree whose mode
// nothing afterwards corrects.
const stagingDirMode fs.FileMode = 0o755

// installLockMode is the lock file's mode. It carries no content and is read by
// nobody; only root ever opens it.
const installLockMode fs.FileMode = 0o600

// ErrInstallInProgress reports that another install already holds the
// install-wide lock. It is a sentinel so the CLI (and a test) can recognise the
// refusal without matching text.
var ErrInstallInProgress = errors.New("another k3sm install is already running on this Mac")

// ErrInstallRootCrossDevice reports that the staging directory and the install
// root are on different filesystems, which no rename can cross.
//
// It is named explicitly even though the default layout makes it unreachable —
// /Library is a firmlink onto the Data volume, so <InstallDir>.staging is always
// the install root's filesystem — because Config.InstallDir is a public field and
// a caller may point it somewhere else. An EXDEV reported as a bare errno would
// read as a permissions problem; this one names the cause.
var ErrInstallRootCrossDevice = errors.New("the staging directory and the install root are on different filesystems, so the staged tree cannot be published with a rename")

// stagingDir is the sibling directory this install builds the whole install root
// in before publishing it. See the file comment for why it is a sibling.
func (c Config) stagingDir() string { return filepath.Clean(c.InstallDir) + installStagingSuffix }

// installLockPath is the install-wide lock file guarding the staging tree and
// the publish. See System.LockInstall.
func (c Config) installLockPath() string { return filepath.Clean(c.InstallDir) + installLockSuffix }

// stagedPath maps an artifact's FINAL path to where THIS install writes it: a
// path under the install root is redirected into the staging tree, and any other
// path is returned unchanged.
//
// The pass-through arm is the contract, not a fallback. Install writes in three
// places — the install root, the data root, and the launchd/preferences trees —
// and only the first is republished by the swap; a mapping that refused
// everything else would have to be guarded at every call site, and a mapping that
// redirected everything would move the plists out from under launchd. So the
// rule is stated once, here: what is under InstallDir is staged, everything else
// is written where it says it is.
func (c Config) stagedPath(p string) string {
	root := filepath.Clean(c.InstallDir)
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p
	}
	return filepath.Join(c.stagingDir(), rel)
}

// The staged counterpart of each installed* path. They exist so no call site
// spells the redirection itself: the installed* accessor stays the one name for
// where an artifact ENDS UP (what the plists exec and what the launcher points
// at), and these say where this install PUTS it on the way there.

func (c Config) stagedBinary() string   { return c.stagedPath(c.installedBinary()) }
func (c Config) stagedExecShim() string { return c.stagedPath(c.installedExecShim()) }
func (c Config) stagedPathShim() string { return c.stagedPath(c.installedPathShim()) }
func (c Config) stagedDNSShim() string  { return c.stagedPath(c.installedDNSShim()) }
func (c Config) stagedVMHost() string   { return c.stagedPath(c.installedVMHost()) }

// stagedPayloadFile is where a control-plane payload file (a binary, or the kine
// version marker) is staged. Its live counterpart is InstallDir/bin/<name>.
func (c Config) stagedPayloadFile(name string) string {
	return c.stagedPath(filepath.Join(c.InstallDir, "bin", name))
}

// stagingSources are the files this install copies into the staging tree, named
// once so the free-space preflight measures exactly what the copies will write.
// The payload SOURCE DIRECTORY stands for every file in it; a source that is
// absent contributes nothing, because the copy that needs it owns that message.
func stagingSources(cfg Config) []string {
	return []string{cfg.BinarySource, cfg.ExecShimSource, cfg.PathShimSource, cfg.DNSShimSource, cfg.VMHostSource, cfg.PayloadSource}
}

// stagingTrustVerdict reports whether path is something k3sm is willing to remove
// as root: a real directory (not a symlink to one), owned by root, and not group-
// or other-writable. An ABSENT path is not this function's business — the caller
// answers that before asking.
//
// It mirrors linkDirVerdict deliberately: same shape, same "decide on facts
// already read off the disk" split, so both refusals can be stated in a table
// without privilege and neither can be re-derived differently at a second call
// site. The one difference is that this verdict has no euid parameter. The
// launcher directory is judged by an installer that may be unprivileged, so the
// root-ownership arm there is conditional; this path is one k3sm creates itself,
// as root, in an install the caller has already verified is running as root — so
// there is no posture in which a non-root owner here is acceptable.
//
// WHAT THIS IS AND IS NOT WORTH, stated because the alternative is a comment that
// overclaims. The escalation this shape normally closes — an unprivileged local
// user planting a symlink at the path so a root-run removal follows it elsewhere
// — is NOT reachable on the target platform: /Library is root:wheel drwxr-xr-x on
// macOS 26, and a non-root admin is refused both a file and a symlink there
// (measured on macOS 26.6.2). This is defense in depth against a
// differently configured host and against k3sm's own future mistakes, not the
// closing of a live hole. It costs one lstat.
func stagingTrustVerdict(path string, e OwnedEntry) error {
	refuse := func(reason string) error {
		return fmt.Errorf("refusing to remove the install staging path %s as root: it %s — move it aside by hand and re-run the install", path, reason)
	}
	switch {
	case e.Kind == EntrySymlink:
		return refuse("is a symlink, not a real directory, and whoever can re-point it chooses what root would delete")
	case e.Kind != EntryDir:
		return refuse("is " + e.Kind.String() + ", not a directory")
	case e.UID != 0:
		return refuse(fmt.Sprintf("is owned by uid %d, not root", e.UID))
	case e.Mode.Perm()&stagingDirMaxMode != 0:
		return refuse(fmt.Sprintf("is group- or world-writable (mode %04o, want 755)", e.Mode.Perm()))
	}
	return nil
}

// stagingDirMaxMode is the permission bits the staging path may NOT carry —
// group or other write, linkDirMaxMode's value for the same reason it has it: a
// directory another account can write is one whose contents root must not be
// asked to delete.
const stagingDirMaxMode = 0o022

// trustedStagingPath answers the two questions a privileged removal of the
// staging path needs, in the order that makes the second one safe: is anything
// there, and — if so — is it something root may delete?
//
// Absence is a posture, never a failure: a first install has no staging tree, and
// a plain-rename publish leaves none behind.
func trustedStagingPath(sys System, path string) (present bool, err error) {
	e, err := sys.Owner(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("inspect the install staging path %s: %w", path, err)
	}
	if err := stagingTrustVerdict(path, e); err != nil {
		return true, err
	}
	return true, nil
}

// prepareStagingDir makes <InstallDir>.staging an empty, root-owned directory
// ready to receive the whole install root.
//
// A tree left there by an install that died mid-flight is REMOVED rather than
// written into: a staged tree is only meaningful as a complete set, and copying
// this install's artifacts over another run's leftovers would publish exactly the
// mixture the staging exists to prevent. The removal is trust-checked first, and
// the check is the only thing standing between "clean up after a crash" and "root
// deletes whatever is at this path".
func prepareStagingDir(sys System, cfg Config) error {
	staging := cfg.stagingDir()
	present, err := trustedStagingPath(sys, staging)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if present {
		cfg.Logger.Warn("removing an install staging tree left behind by an earlier run", "path", staging)
		if err := sys.RemoveTree(staging); err != nil {
			return fmt.Errorf("install: remove the stale install staging tree %s: %w", staging, err)
		}
	}
	if err := sys.EnsureRootDir(staging, stagingDirMode); err != nil {
		return fmt.Errorf("install: create the install staging directory %s: %w", staging, err)
	}
	return nil
}

// publishStagedRoot exchanges the staged tree with the live install root and
// reports whether there WAS a previous tree (which is now at the staging path,
// pending the reap, and is what a revert swaps back).
//
// The log line is emitted the instant the swap returns and before anything else
// happens, because after an interrupted upgrade it is the only artifact that says
// which side of the swap the Mac is on: it names the path that is live now and
// the path holding the tree that is about to be removed.
func publishStagedRoot(sys System, cfg Config) (previous bool, err error) {
	staging, live := cfg.stagingDir(), filepath.Clean(cfg.InstallDir)
	previous, err = sys.SwapInstallRoot(staging, live)
	if err != nil {
		return false, fmt.Errorf("install: publish the staged install root at %s: %w", live, err)
	}
	if previous {
		cfg.Logger.Info("published the staged install root", "live", live, "previous-tree-pending-removal", staging)
	} else {
		cfg.Logger.Info("published the staged install root", "live", live, "previous-tree-pending-removal", "none (first install)")
	}
	return previous, nil
}

// reapPreviousRoot removes the tree the swap displaced, which is sitting at the
// staging path. It runs LAST — after the daemons have restarted on the new tree
// and been verified healthy — because until it does, the previous install is
// intact and one more swap puts it back.
//
// A failure to remove it is reported and never fatal: the install has already
// succeeded by the time this runs, and refusing it over a directory that could
// not be deleted would turn a healthy Mac into a failed install. The next install
// removes it (prepareStagingDir), and the trust check runs there too.
func reapPreviousRoot(sys System, cfg Config) {
	staging := cfg.stagingDir()
	present, err := trustedStagingPath(sys, staging)
	if err != nil {
		cfg.Logger.Warn("the previous install root was left in place", "path", staging, "err", err)
		return
	}
	if !present {
		return
	}
	if err := sys.RemoveTree(staging); err != nil {
		cfg.Logger.Warn("could not remove the previous install root; it will be removed by the next install", "path", staging, "err", err)
		return
	}
	cfg.Logger.Info("removed the previous install root", "path", staging)
}

// freeSpaceVerdict reports whether a filesystem with free bytes free can hold a
// staged copy of need bytes.
//
// It is a LEGIBILITY check, not a correctness one, and the distinction is the
// whole reason it is written this way. The copies themselves are the authority on
// whether they fit; what this buys is that a Mac with no room says so in one
// sentence naming both numbers, instead of failing part-way through the payload
// with an ENOSPC from ditto. It is sized against CURRENTLY free space and makes
// no allowance for the space the previous tree frees at the reap, because APFS
// local snapshots can pin those blocks for hours — space-after-reap is not a
// number anything should plan against.
func freeSpaceVerdict(dir string, need, free uint64) error {
	if need == 0 || free >= need {
		return nil
	}
	return fmt.Errorf("install: %s has %s free, and staging this install's copy of the install root needs about %s — free up space and re-run (the staged tree is published only once it is complete, so nothing has been written)",
		dir, formatBytes(free), formatBytes(need))
}

// formatBytes renders a byte count the way the refusal above has to read: a
// whole number of the largest unit that keeps it readable. It is deliberately
// local rather than a dependency — the only consumer is one error string.
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// preflightInstallSpace is the free-space check, in the refuse-before-write
// block beside the other input-only refusals. A seam failure is NOT fatal: an
// estimate that cannot be taken is a missing nicety, not a reason to refuse an
// install that would have worked.
func preflightInstallSpace(sys System, cfg Config) error {
	free, need, err := sys.InstallSpace(filepath.Dir(filepath.Clean(cfg.InstallDir)), stagingSources(cfg))
	if err != nil {
		cfg.Logger.Warn("could not size the install against the free space on this volume", "err", err)
		return nil
	}
	return freeSpaceVerdict(filepath.Dir(filepath.Clean(cfg.InstallDir)), need, free)
}
