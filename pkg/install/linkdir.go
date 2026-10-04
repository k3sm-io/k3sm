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
	"fmt"
	"io/fs"
	"path/filepath"
)

// linkDirMaxMode is the permission bits a link directory may NOT carry: group or
// other write. A directory anyone in the `admin` group (or any local user) can
// write is a directory in which the launcher can be swapped for something else,
// and the launcher is what a human types.
const linkDirMaxMode = 0o022

// linkDirFacts is what a launcher directory IS, already read off the disk — the
// four properties linkDirVerdict decides on. It exists so that the decision can
// be a pure function of resolved inputs: the Lstat and the euid read stay in the
// darwin System, and every arm of the refusal (including the root-ownership arm,
// which an unprivileged test could not otherwise reach, since it cannot chown a
// temp dir to root) is stated in a table instead of in a live filesystem.
type linkDirFacts struct {
	// UID is the owning uid of the directory.
	UID uint32
	// Mode is the mode Lstat reported; only the permission bits are consulted.
	Mode fs.FileMode
	// IsDir reports whether the path is a directory.
	IsDir bool
	// IsSymlink reports whether the path ITSELF is a symlink — an Lstat question,
	// never a Stat one: a symlink to a trusted directory is not a trusted
	// directory, because whoever can re-point the link chooses the destination.
	IsSymlink bool
	// Absent reports that the judged path is not there at all. It is stated the
	// negative way round so the zero value describes a path that EXISTS, which is
	// every ordinary case; an absent path is routed through the same verdict
	// table as every other refusal rather than escaping as a bare Lstat error,
	// because "no such file or directory" tells an operator nothing about which
	// directory k3sm wanted or what to do about it.
	Absent bool
}

// linkDirVerdict reports whether dir may hold — or, when it is an ancestor,
// may come to hold — the `k3sm` launcher symlink for launcherDir: a REAL
// directory (not a symlink to one), not group- or other-writable, and — when
// euid is 0, the only posture in which the answer is meaningful — owned by root.
//
// dir and launcherDir are the same path in the ordinary case. They differ when
// the launcher directory does not exist yet and linkDirTrustTarget has ESCALATED
// the judgement to its parent — the directory whose permissions decide who could
// create the missing one. That distinction is carried into the message rather
// than left to the reader, because it changes the remedy: telling an operator to
// `remove /usr/local` because /usr/local/bin is missing would be advice to
// delete a base system directory, when what they actually need is to create the
// launcher directory under it.
//
// THE HAZARD, named here because the check has always asserted it without ever
// saying it: the launcher directory sits on ROOT's PATH, and /usr/local/bin
// precedes /usr/bin in the default /etc/paths. A launcher directory some local
// user can write is therefore a directory in which that user can leave a file
// called `k3sm` — and the next `sudo k3sm …`, install script or root-run helper
// that types the bare command executes it as root. That is a local privilege
// escalation k3sm would have created by linking there, which is why this refuses
// rather than warns. It is not hypothetical: on a Mac carrying an Intel-prefix
// Homebrew, /usr/local/bin is owned by the admin user who installed Homebrew
// (and /opt/homebrew/bin is, on an Apple Silicon one), so this is the ordinary
// state of a developer's machine rather than a misconfiguration.
//
// This is also the one deliberate exception to the privilege model's "the binary
// and plist live in /Library/k3sm, never a Homebrew, /usr/local or /Applications
// prefix an `admin`-group member could overwrite" rule (docs/privilege-model.md
// §Root-owned everything). The exception is narrow and is trusted ONLY because
// this check holds: nothing executable is placed in the link directory, only a
// symlink back into the root-owned tree, and the link is refused outright unless
// the directory holding it has the same trust properties /Library does.
//
// The refusal names the path, the property that is wrong, the literal command
// that fixes it, and why k3sm cares. An operator told only the rule has to guess
// the remedy, and guessing at chown under /usr/local is how a Homebrew tree gets
// broken; the uid-0 half is conditional on euid because an unprivileged caller
// (the unit table, a dry run) cannot chown anything anyway.
func linkDirVerdict(dir, launcherDir string, f linkDirFacts, euid int) error {
	if launcherDir == "" {
		launcherDir = dir
	}
	escalated := dir != launcherDir
	why := fmt.Sprintf("root's PATH searches %s, so anything named k3sm left there is what the next `sudo k3sm …` would run as root", launcherDir)
	// Three remedies, and which one applies is decided by what is wrong rather
	// than by how it was phrased: repair the judged directory's ownership/mode;
	// create the launcher directory under an ancestor that can never hold a link
	// itself; or clear the way when the LAUNCHER path is the thing that is not a
	// directory. Only the third ever says "remove", and it never names an
	// ancestor.
	chown := fmt.Sprintf("sudo chown root:wheel %s && sudo chmod 755 %s", dir, dir)
	create := fmt.Sprintf("create %s as a root-owned directory first: sudo mkdir -p %s && sudo chown root:wheel %s && sudo chmod 755 %s", launcherDir, launcherDir, launcherDir, launcherDir)
	remove := fmt.Sprintf("remove %s, or choose another directory already on your shell's PATH", dir)

	reason, remedy := "", ""
	switch {
	case f.Absent:
		reason, remedy = "does not exist", create
	case f.IsSymlink:
		reason, remedy = "is a symlink, not a real directory, and whoever can re-point it decides where the launcher lands", remove
		if escalated {
			remedy = create
		}
	case !f.IsDir:
		reason, remedy = "is not a directory", remove
		if escalated {
			remedy = create
		}
	case f.Mode.Perm()&linkDirMaxMode != 0:
		which := "group-writable"
		switch f.Mode.Perm() & linkDirMaxMode {
		case 0o002:
			which = "world-writable"
		case 0o022:
			which = "group- and world-writable"
		}
		reason, remedy = fmt.Sprintf("is %s (mode %04o, want 755)", which, f.Mode.Perm()), chown
	case euid == 0 && f.UID != 0:
		reason, remedy = fmt.Sprintf("is owned by uid %d, not root", f.UID), chown
	default:
		return nil
	}
	if escalated {
		return fmt.Errorf("refusing to create the k3sm launcher directory %s: its parent %s %s, so %s cannot be created under it — %s — fix it: %s", launcherDir, dir, reason, launcherDir, why, remedy)
	}
	return fmt.Errorf("refusing to link the k3sm launcher into %s: it %s — %s — fix it: %s", dir, reason, why, remedy)
}

// linkDirTrustTarget reports WHICH directory's trust decides whether the launcher
// may be linked at link, given whether link's parent already exists.
//
// When the parent does not exist the answer is its own parent: that is the
// directory whose permissions decide who could have created the missing one —
// and therefore who could own it — before k3sm gets there. parentAbsent is also
// the caller's signal that it must create the parent itself once the verdict is
// clean.
func linkDirTrustTarget(link string, parentExists bool) (dir string, parentAbsent bool) {
	parent := filepath.Dir(link)
	if parentExists {
		return parent, false
	}
	return filepath.Dir(parent), true
}
