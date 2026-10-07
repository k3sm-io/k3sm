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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/netdsvc"
	"k3sm.io/k3sm/pkg/nodecred"
)

// legacyAgentArtifacts is the FIXED table of leaf names the agent work dir is
// known to hold: the five artifacts of a stored node credential, plus the three
// this package and cmd/k3sm name themselves.
//
// The credential names come from nodecred.Store rather than being retyped, so
// the directory the installer repairs and the directory the daemon reads can
// never disagree about what lives in it. The dir value is irrelevant — only the
// leaf names are taken.
func legacyAgentArtifacts() map[string]bool {
	store := nodecred.Store{Dir: "."}
	known := make(map[string]bool, len(store.Paths())+3)
	for _, p := range store.Paths() {
		known[filepath.Base(p)] = true
	}
	for _, name := range []string{agentNodePasswordName, agentMeshKeyName, agentTokenName} {
		known[name] = true
	}
	return known
}

// serviceCanRead reports whether the service user can open e.
//
// Three ways, and the middle one is the trap this predicate exists to avoid.
// The owner can always read its own 0600 file. An other-read bit lets everyone
// read it, the service user included. A GROUP-read bit only helps when the group
// is one the service user is IN — and the only group this installer can assert
// that about is ServiceTreeGID (staff), the service user's primary group. A
// root:wheel 0640 file carries a group-read bit and is still unreadable to
// _k3sm, so a predicate that took any group-read bit as "readable" would wave
// exactly the file an operator most needs to be told about straight through.
func serviceCanRead(e OwnedEntry, svcUID, svcGID int) bool {
	switch {
	case e.UID == svcUID:
		return true
	case e.Mode&0o004 != 0:
		return true
	case e.Mode&0o040 != 0 && e.GID == svcGID:
		return true
	}
	return false
}

// adoptLegacyAgentFiles hands the agent work dir and the known artifacts inside
// it to the service user, on a reinstall over a worker that was installed before
// the node daemon moved from root to _k3sm.
//
// This is a MIGRATION to the posture a fresh install already produces — service
// uid, group staff, the mode untouched, which is exactly what
// WriteServiceUserFile writes the staged join token at — and NOT a widening of
// anything. Nothing becomes readable to an account that could not read it
// before: every file involved is 0600 both before and after, and the mode is
// carried across verbatim rather than re-decided. What changes is only WHICH
// single uid the 0600 names, from root to the unprivileged user the daemon now
// runs as.
//
// Without it, such a node crash-loops: `k3sm agent` starts as _k3sm, finds a
// root-owned 0600 node-password it cannot rewrite, and dies on "persist
// node-password: permission denied" — with the same fate waiting behind it for
// the mesh key and the node credential. Only root can hand those files over and
// only the installer runs as root, which is why this is an install step and not
// something the node does for itself at start-up (the reasoning EnsureRunDir and
// EnsureContainerLogDir already record for their own directories).
//
// Three limits, all deliberate:
//
//   - Only the entries in legacyAgentArtifacts are adopted. A file k3sm does not
//     recognise is never chowned, because giving an unknown file to the service
//     user IS the widening this function is careful not to be.
//   - An unrecognised regular file the service user cannot read REFUSES the
//     install, before a single chown happens. It would otherwise be a silent
//     landmine: the daemon may need it, nothing here can know, and an install
//     that reported success over it would hand back the crash-loop it was run to
//     fix. The operator is told the file and both remedies.
//   - An entry under one of the KNOWN names that is not a regular file refuses
//     the install too. An adoption is decided about a name and applied to what
//     the name resolves to, so a symlink standing in for node.key is not a file
//     to hand over.
//   - Nothing is walked. Subdirectories are not descended into and not judged:
//     this is the five-artifact credential directory, not a tree.
//
// The chowns are ordered files-first, directory-last, so the service user never
// owns the directory while a root-owned artifact inside it is still pending.
func adoptLegacyAgentFiles(sys System, cfg Config, uid uint32) error {
	dir := cfg.agentWorkDir()
	svcUID, svcGID := int(uid), ServiceTreeGID
	self, err := sys.Owner(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// No work dir yet: a first install, or one whose token staging is still
		// to create it. Nothing to migrate.
		return nil
	case err != nil:
		return fmt.Errorf("install: inspect the agent work dir %s: %w", dir, err)
	case self.Kind != EntryDir:
		return fmt.Errorf("install: the agent work dir %s is not a directory: the agent daemon keeps this node's credential there, so move whatever is at that path aside before reinstalling", dir)
	}
	entries, err := sys.ListOwned(dir)
	if err != nil {
		return fmt.Errorf("install: list the agent work dir %s: %w", dir, err)
	}

	// Two passes, and the split is the contract: everything is CLASSIFIED before
	// anything is changed, so a refusal leaves the directory exactly as it was
	// found rather than half-migrated.
	known := legacyAgentArtifacts()
	var adopt []OwnedEntry
	var unreadable, notRegular, ignored []string
	for _, e := range entries {
		switch {
		case known[filepath.Base(e.Path)]:
			switch {
			case e.Kind != EntryRegular:
				notRegular = append(notRegular, fmt.Sprintf("%s (%s)", e.Path, e.Kind))
			case e.UID == 0 && svcUID != 0:
				adopt = append(adopt, e)
			}
		case e.Kind != EntryRegular:
			// A subdirectory, a symlink, a socket under a name k3sm does not
			// claim: not this step's business, and never chowned.
		case !serviceCanRead(e, svcUID, svcGID):
			unreadable = append(unreadable, e.Path)
		default:
			ignored = append(ignored, e.Path)
		}
	}
	// The known-name-wrong-kind refusal comes first because it is the sharper
	// one. An adoption is a decision made about a NAME and applied to whatever
	// that name resolves to; a symlink at node.key, plantable by anything that
	// can write in this directory, would aim a root-run chown at a file
	// somewhere else on the Mac. Lchown means the link itself would move rather
	// than its target, so this is a refusal out of caution rather than a repair
	// of a live escalation — but "the artifact k3sm was about to hand over is
	// not the artifact" is never something to continue past.
	if len(notRegular) > 0 {
		return fmt.Errorf("install: the agent work dir %s holds an entry under one of this node's own state file names that is not a regular file; remove it and let the agent write its state afresh: %s — k3sm hands ownership of a state file to %s, never of something standing in for one",
			dir, strings.Join(notRegular, ", "), cfg.ServiceUser)
	}
	if len(unreadable) > 0 {
		return fmt.Errorf("install: the agent work dir %s holds file(s) the %s service user the node daemon runs as cannot read, and k3sm does not recognise them: %s — `sudo chown %s <file>` if the file belongs to this node's agent, or remove it if it is not k3sm's; k3sm will not hand a file it cannot account for to the service user on its own",
			dir, cfg.ServiceUser, strings.Join(unreadable, ", "), cfg.ServiceUser)
	}
	for _, path := range ignored {
		// The PATH only, never a byte of the file: an unrecognised file in a
		// credential directory is exactly the thing not to echo into a log. It is
		// still worth one line each, because "k3sm saw this and chose to leave it"
		// is the record an operator needs when they later wonder why it was not
		// repaired.
		cfg.Logger.Info("left an unrecognised file in the agent work dir alone: the service user can already read it, and k3sm does not adopt files it cannot account for", "path", path)
	}
	// The files FIRST and the directory LAST. In between, the directory is still
	// root's while its contents move — never the reverse. Handing the directory
	// over first would give the service user a 0700 directory it owns (and so
	// may rename or unlink within) for the duration of the remaining chowns,
	// while root-owned artifacts inside were still pending; ending with the
	// directory means that window does not exist.
	if self.UID == 0 && svcUID != 0 {
		adopt = append(adopt, self)
	}
	for _, e := range adopt {
		if err := sys.Chown(e.Path, svcUID, svcGID); err != nil {
			return fmt.Errorf("install: hand the agent state %s over to %s (uid %d): %w", e.Path, cfg.ServiceUser, svcUID, err)
		}
	}
	if len(adopt) > 0 {
		paths := make([]string, len(adopt))
		for i, e := range adopt {
			paths[i] = e.Path
		}
		cfg.Logger.Info("adopted agent state left root-owned by an install that predates the service user (the mode is unchanged; only the uid the 0600 names moves)",
			"user", cfg.ServiceUser, "uid", svcUID, "paths", strings.Join(paths, ","))
	}
	return nil
}

// podLogWalkMaxDepth bounds the pod-log adoption walk below the tree's root.
// The layout podlogs defines is exactly
// <root>/<ns>_<pod>_<uid>/<container>/<n>.log — three levels — so this bound is
// never reached by a tree k3sm itself wrote, and it is what keeps a walk run as
// root from descending forever into whatever a hand-run mkdir, a half-finished
// restore, or a rotation tool left behind. It bounds DEPTH rather than entries
// because the walk never follows a symlink: the only way down is for the
// directories to really be there.
const podLogWalkMaxDepth = 8

// AdoptPolicy says which entries at the TOP level of a tree AdoptTree may hand
// over. It exists because k3sm's two container-log directories have opposite
// rules about the one entry kind that matters, and neither rule is safe to apply
// to the other directory.
type AdoptPolicy int

const (
	// AdoptPodDirs is /var/log/pods: at the top level ONLY a directory whose
	// name has the <ns>_<pod>_<uid> shape podlogs writes is adopted, and then
	// everything inside it recursively (directories and regular files). A
	// symlink is never adopted and never descended into, at any level.
	//
	// It is the ZERO value so that a policy nobody set is the conservative one.
	AdoptPodDirs AdoptPolicy = iota
	// AdoptLogLinks is /var/log/containers: a FLAT directory of symlinks, which
	// is the one place a symlink is the artifact rather than an intruder — a log
	// shipper globs them and the node has to be able to replace them. They are
	// adopted with an lchown, so the link moves and its target is never touched,
	// and nothing is descended into.
	AdoptLogLinks
)

// SkippedEntry is one entry an adoption walk stepped over, and why — the record
// the installer turns into a line for the operator. It carries the PATH only:
// a log directory's name is namespace/pod/container, which the operator already
// knows, and nothing here ever reads a byte of a pod's output.
type SkippedEntry struct {
	Path   string
	Reason string
}

// TreeAdoption is what one AdoptTree walk did: how many entries it handed over,
// and every entry it did not.
//
// The skipped entries are RETURNED rather than logged inside the seam, because
// the seam performs syscalls and this package decides what an operator is told.
// The count is separate from len(Skipped) for nobody's benefit but the caller's
// summary line.
type TreeAdoption struct {
	Adopted int
	Skipped []SkippedEntry
}

// podLogDirName mirrors the pod-log directory name
// podlogs.BuildPodLogsDirectory writes: <namespace>_<pod>_<uid>, where the
// namespace and the pod name are DNS-1123 names (so neither can contain the `_`
// delimiter) and the uid is a Kubernetes UID.
//
// podlogs exports a parser (ParsePodUIDFromLogsDirectory) but not a validator —
// it answers "the last field" for any string at all, including one with no
// delimiter — so the shape is re-stated here as the smallest thing that can say
// NO. It is deliberately a shape check and not a lookup against live pods: the
// tree is full of directories whose pods are long gone, and adopting only the
// pods currently scheduled here would leave exactly the debris an operator
// cannot clean up.
var podLogDirName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?_[a-z0-9]([-a-z0-9.]*[a-z0-9])?_[A-Za-z0-9-]+$`)

// isPodLogDirName reports whether name is one of this node's own pod log
// directories. Getting it wrong in either direction is survivable and neither
// direction is silent: a genuine directory rejected here is reported to the
// operator and left root-owned, and debris accepted here is chowned inside a
// tree the service user already owns the root of. What it buys is that a
// root-run walk descends only into the shape k3sm itself writes.
func isPodLogDirName(name string) bool { return podLogDirName.MatchString(name) }

// adoptPodLogTree hands the per-pod log directories an OLDER install left
// root-owned over to the service user, on a reinstall over a node whose daemon
// once ran as root.
//
// It is adoptLegacyAgentFiles' sibling for the one tree that step deliberately
// does not touch, and it closes the failure that survived it: the log-dir step
// above chowns the ROOT of the tree, and only the root, so a node whose
// root-era daemon had already created <root>/<ns>_<pod>_<uid> directories
// (0700, root-owned) came back up as _k3sm and failed every CreatePod with
//
//	failed to create container log directory
//	/var/log/pods/<ns>_<pod>_<uid>/<container>: permission denied
//
// — a per-pod directory it can traverse to and not write in. Only root can hand
// those directories over and only the installer runs as root, which is the same
// reason EnsureContainerLogDir is an install step rather than something the node
// does for itself.
//
// This is a MIGRATION to the posture a fresh install already produces — service
// uid, group wheel (ContainerLogDirGID), the mode carried across verbatim — and
// widens nothing: a 0700 directory is readable by exactly one account before and
// after, and what moves is which uid that is.
//
// Four properties, all deliberate, and all different from the agent work dir's:
//
//   - The walk is performed by the System seam, DESCRIPTOR-relative (see
//     AdoptTree). Pods are running as the service user throughout an install,
//     so a path re-resolved after it was classified is a path something else
//     can have replaced in between.
//   - It NEVER refuses the install. The tree is GC-pending debris by nature —
//     pkg/provider/podlogs GC is its sole deleter and runs asynchronously — so
//     an unreadable directory or an entry k3sm cannot account for is reported
//     and stepped over, not turned into a failed install of an otherwise healthy
//     node.
//   - It DELETES nothing, for the same reason: the GC owns removal, and an
//     installer that also removed would be a second deleter racing it.
//   - It is unconditional across roles, exactly like the EnsureContainerLogDir
//     step it repairs: a single-node server runs pods and writes this same tree.
func adoptPodLogTree(sys System, cfg Config, uid uint32) {
	svcUID := int(uid)
	if svcUID == 0 {
		// Nothing to migrate TO: the service user is root, so the tree already
		// names the account the node runs as.
		return
	}
	trees := []struct {
		root   string
		policy AdoptPolicy
		depth  int
	}{
		{PodLogsDir, AdoptPodDirs, podLogWalkMaxDepth},
		// A flat directory: one level, and the bound says so rather than
		// relying on the policy never to descend.
		{ContainerLogsDir, AdoptLogLinks, 1},
	}
	var adopted, skipped int
	for _, t := range trees {
		rep, err := sys.AdoptTree(t.root, svcUID, ContainerLogDirGID, t.depth, t.policy)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// A node that has never run a pod has no tree. A posture, not a
			// problem, and not worth a line.
			continue
		case err != nil:
			cfg.Logger.Info("left a container-log directory alone", "path", t.root, "reason", err.Error())
			skipped++
			continue
		}
		for _, s := range rep.Skipped {
			cfg.Logger.Info("left an entry in the container-log tree alone", "path", s.Path, "reason", s.Reason)
		}
		adopted += rep.Adopted
		skipped += len(rep.Skipped)
	}
	if adopted > 0 || skipped > 0 {
		// One line, with counts rather than paths: a node with a long pod
		// history has thousands of entries, and the per-entry lines above are
		// already there for the ones that were NOT adopted.
		cfg.Logger.Info("adopted container-log entries left root-owned by an install that predates the service user (modes unchanged; only the uid the entries name moves)",
			"user", cfg.ServiceUser, "uid", svcUID, "gid", ContainerLogDirGID, "adopted", adopted, "skipped", skipped)
	}
}

// legacyKeyLeaves are the files an older build kept in LegacyMeshKeyDir, and so
// the ones the one-time move carries: both roles' mesh keys and the node
// identity netd persists beside them.
func legacyKeyLeaves() []string {
	return []string{MeshKeyRefServer, MeshKeyRefAgent, netdsvc.NodeIdentityFileName}
}

// migrateLegacyMeshKeys moves the files an older build kept in
// LegacyMeshKeyDir (inside the service-user-owned run dir) into MeshKeyDir
// (directly under the root-owned data root). It runs once per install, after
// MeshKeyDir exists and before provisionMeshKey reads it, and it is
// FORWARD-ONLY: a binary older than this move looks in LegacyMeshKeyDir, finds
// nothing, and mints a new identity, so the remedy before a downgrade is to copy
// the files back by hand.
//
// Per leaf, in this order:
//
//  1. When MeshKeyDir has no copy, the legacy bytes are copied in root-only
//     (WriteRootOnlyFile, fsynced), read back, and compared. A key is also
//     validated as a wireguard private key first: the legacy directory was the
//     service user's, so its content is whatever the last writer left.
//  2. Only when the new copy exists (just written and verified, or already
//     there) is the legacy leaf removed. Removal is independent of the copy: a
//     stale legacy leaf beside an existing new copy is removed and nothing is
//     copied, because the new copy is the identity the node already uses.
//  3. The emptied legacy directory is removed last.
//
// A symlink at the legacy directory, at its parent, or at a legacy leaf is a
// hard error and nothing is touched: those are service-user-writable places, and
// following a link planted there would have root copy or delete a file of the
// planter's choosing. Nothing is ever minted here; minting stays
// provisionMeshKey's, under its rule that it happens only when neither copy
// exists.
func migrateLegacyMeshKeys(sys System, logger *slog.Logger) error {
	// The run dir sits in the root-owned data root (ensured at step 1a, which
	// refuses a symlink there), so nothing unprivileged can swap it from here
	// on; it is checked once for a clear error.
	parent := filepath.Dir(LegacyMeshKeyDir)
	switch e, err := sys.Owner(parent); {
	case errors.Is(err, fs.ErrNotExist):
		return nil // no run dir: a fresh install
	case err != nil:
		return fmt.Errorf("install: inspect %s: %w", parent, err)
	case e.Kind != EntryDir:
		return fmt.Errorf("install: %s is %s, not a directory; refusing to move keys through it (remove it by hand, then re-run `sudo k3sm install`)", parent, e.Kind)
	}
	// The keys dir itself is INSIDE the service user's run dir, so it is held
	// by one descriptor opened without following a symlink, and every read and
	// removal below goes through that descriptor: the service user can rename
	// the path at any moment, but not the directory this install already holds.
	legacyDir, err := sys.OpenDirNoFollow(LegacyMeshKeyDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil // no legacy tree: a fresh install, or one already moved
	case err != nil:
		return fmt.Errorf("install: open the legacy mesh key dir %s: %w (refusing to move keys through it; remove it by hand, then re-run `sudo k3sm install`)", LegacyMeshKeyDir, err)
	}
	defer func() { _ = legacyDir.Close() }()

	// acted records whether this run moved or dropped a known leaf. A run that
	// finds nothing k3sm knows in the legacy dir (the keys were moved by an
	// earlier run) says nothing above Debug, whatever else the dir holds.
	acted := false
	for _, leaf := range legacyKeyLeaves() {
		legacy := filepath.Join(LegacyMeshKeyDir, leaf)
		dest := filepath.Join(MeshKeyDir, leaf)
		old, err := legacyDir.ReadEntry(leaf)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return fmt.Errorf("install: read the legacy %s: %w (refusing to move it; remove it by hand if it is not this node's, then re-run `sudo k3sm install`)", legacy, err)
		}
		cur, err := sys.ReadRegularFile(dest)
		switch {
		case err == nil && bytes.Equal(cur, old):
			// Already moved, and the legacy copy is the same bytes: only the
			// leftover goes.
			logger.Info("dropping a legacy mesh key file the root-owned key dir already holds, byte for byte", "legacy", legacy, "path", dest)
		case err == nil:
			// Both places hold this leaf and they DIFFER. The root-owned copy is
			// never silently overwritten, and the legacy one is never silently
			// deleted: which identity this node keeps is the operator's call.
			return fmt.Errorf("install: %s and %s both exist and differ; the root-owned %s is what this node uses now: delete %s by hand if it is stale (or copy it over %s if it is the identity the node's peers know), then re-run `sudo k3sm install`",
				legacy, dest, dest, legacy, dest)
		case errors.Is(err, fs.ErrNotExist):
			if err := validateLegacyLeaf(leaf, old); err != nil {
				return fmt.Errorf("install: the legacy %s %w (it was not moved; remove it only if you accept that this node's mesh identity changes)", legacy, err)
			}
			if err := sys.WriteRootOnlyFile(dest, old, MeshKeyFileMode); err != nil {
				return fmt.Errorf("install: move the legacy %s to %s: %w", legacy, dest, err)
			}
			got, rerr := sys.ReadRegularFile(dest)
			if rerr != nil {
				return fmt.Errorf("install: verify the moved %s: %w (the legacy copy %s is kept)", dest, rerr, legacy)
			}
			if !bytes.Equal(got, old) {
				return fmt.Errorf("install: verify the moved %s: its bytes differ from %s (the legacy copy is kept)", dest, legacy)
			}
			logger.Info("moved a mesh key file out of the service user's run dir into the root-owned key dir (one-time; a binary older than this move would not find it)",
				"from", legacy, "to", dest)
		default:
			return fmt.Errorf("install: read %s: %w", dest, err)
		}
		if err := legacyDir.RemoveEntry(leaf); err != nil {
			return fmt.Errorf("install: remove the legacy %s: %w", legacy, err)
		}
		acted = true
	}
	// The directory goes only when it is empty. Anything left in it is not a
	// file k3sm wrote (the known leaves are gone by now): it is reported by
	// name and kept, never deleted and never a reason to fail the install. k3s
	// does not fail on unknown files in its data dir either.
	leftovers, err := legacyDir.ListEntries()
	if err != nil {
		return fmt.Errorf("install: list the legacy mesh key dir %s: %w", LegacyMeshKeyDir, err)
	}
	if len(leftovers) > 0 {
		level := slog.LevelDebug
		if acted {
			level = slog.LevelWarn
		}
		logger.Log(context.Background(), level, "the mesh keys were moved out of the legacy key dir, but it still holds files k3sm does not know; they are kept, and may be deleted by hand",
			"dir", LegacyMeshKeyDir, "entries", strings.Join(leftovers, ","))
		return nil
	}
	if err := sys.RemoveEntry(parent, filepath.Base(LegacyMeshKeyDir)); err != nil {
		return fmt.Errorf("install: remove the empty legacy mesh key dir %s: %w", LegacyMeshKeyDir, err)
	}
	return nil
}

// validateLegacyLeaf checks a legacy file's bytes before they are promoted into
// the root-only key dir: the legacy dir was the service user's, so its content
// is whatever the last writer left there. A key must be a usable wireguard
// private key; the node identity must be one parseable CIDR, the only thing
// netd ever writes there.
func validateLegacyLeaf(leaf string, b []byte) error {
	if leaf == netdsvc.NodeIdentityFileName {
		if _, err := netip.ParsePrefix(strings.TrimSpace(string(b))); err != nil {
			return fmt.Errorf("is not a parseable CIDR: %w", err)
		}
		return nil
	}
	if _, err := bootstrap.WireguardPublicKey(string(b)); err != nil {
		return fmt.Errorf("is not a usable wireguard private key: %w", err)
	}
	return nil
}
