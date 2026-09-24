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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/dataroot"
)

// darwinSystem is the production System: it performs the privileged operations
// via the macOS tools (dscl for the service user, ditto for the root-owned copy,
// launchctl for the daemons) and os.Chown for ownership. It is exercised by the
// install acceptance gate (the one-time root install), NOT by unit tests — the
// standards forbid real privilege in unit tests, so install_test.go uses the
// fake instead.
type darwinSystem struct{}

// NewDarwinSystem returns the production darwin System.
func NewDarwinSystem() System { return darwinSystem{} }

// systemUIDFloor/Ceil bound the search for a free hidden service-user uid (the
// macOS daemon range below the 500 login-user floor).
const (
	systemUIDFloor = 250
	systemUIDCeil  = 400
)

// EnsureServiceUser idempotently creates name as a hidden, no-login system user
// whose home is dataRoot, and ensures that data root exists owned by it (so the
// _k3sm control plane can write its work-dir there). It returns the uid.
func (darwinSystem) EnsureServiceUser(name, dataRoot string) (uint32, error) {
	// Never create or chown into a data root that is declared as a mount point
	// but is not mounted: that would hand the service user the bare mountpoint
	// on the boot disk and let the control plane build an empty datastore over
	// the real volume's.
	if err := refuseShadowedDataRoot(dataroot.OSFS{}, dataRoot); err != nil {
		return 0, err
	}
	record := "/Users/" + name
	if u, err := user.Lookup(name); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		// A reinstall may name a different data root than the account record
		// still carries; keep the two in agreement, same as the creation path
		// below.
		if u.HomeDir != dataRoot {
			out, err := exec.Command("dscl", ".", "-create", record, "NFSHomeDirectory", dataRoot).CombinedOutput()
			if err != nil {
				return 0, fmt.Errorf("update service user home (dscl . -create %s NFSHomeDirectory %s): %w: %s", record, dataRoot, err, out)
			}
		}
		if err := EnsureDataRoot(dataRoot, uid); err != nil {
			return 0, err
		}
		return uint32(uid), nil
	}

	uid, err := freeSystemUID()
	if err != nil {
		return 0, err
	}
	steps := [][]string{
		{"dscl", ".", "-create", record},
		{"dscl", ".", "-create", record, "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", record, "RealName", "k3sm service user"},
		{"dscl", ".", "-create", record, "UniqueID", strconv.Itoa(uid)},
		{"dscl", ".", "-create", record, "PrimaryGroupID", "20"}, // staff
		{"dscl", ".", "-create", record, "NFSHomeDirectory", dataRoot},
		{"dscl", ".", "-create", record, "IsHidden", "1"},
	}
	for _, s := range steps {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			return 0, fmt.Errorf("create service user (%s): %w: %s", strings.Join(s, " "), err, out)
		}
	}
	if err := EnsureDataRoot(dataRoot, uid); err != nil {
		return 0, err
	}
	return uint32(uid), nil
}

// freeSystemUID returns the first uid in [floor,ceil] not already assigned.
func freeSystemUID() (int, error) {
	for uid := systemUIDFloor; uid <= systemUIDCeil; uid++ {
		if _, err := user.LookupId(strconv.Itoa(uid)); err != nil {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no free system uid in [%d,%d]", systemUIDFloor, systemUIDCeil)
}

// EnsureDataRoot creates dir with the data-root policy (idempotent) and chowns
// it to uid:staff so the service user owns it. Exported because `k3sm install`
// is not the only place that policy applies — the root netd helper applies the
// same ownership rule inline when it finds a drifted root at boot — and the two
// must agree.
func EnsureDataRoot(dir string, uid int) error { return ensureOwnedDir(dir, uid) }

// ensureOwnedDir creates dir DataRootMode (idempotent) and chowns it to
// uid:DataRootGID so the service user owns its data root.
func ensureOwnedDir(dir string, uid int) error {
	if err := os.MkdirAll(dir, DataRootMode); err != nil {
		return fmt.Errorf("create data root %s: %w", dir, err)
	}
	if err := refuseSymlinkAt(dir); err != nil {
		return fmt.Errorf("data root %s: %w", dir, err)
	}
	if err := os.Chown(dir, uid, DataRootGID); err != nil {
		return fmt.Errorf("chown data root %s to %d: %w", dir, uid, err)
	}
	return nil
}

// EnsureLogDir creates (or repairs) the log dir owned by the service uid, group
// admin, LogDirMode — so launchd, opening the UserName=_k3sm server job's
// StandardOut/ErrorPath AS _k3sm, can traverse it and append to server.log (the
// root netd and datavol jobs are unaffected by perms) — and pre-creates the
// daemon logs inside it at LogFileMode. Owner+mode are re-applied even
// when the dir and the files already exist, repairing a dir auto-created
// root-only by a prior netd spawn AND an install whose logs were left
// world-readable by the spawning job's umask.
func (darwinSystem) EnsureLogDir(dir string, uid uint32) error {
	return ensureLogDir(dir, logOwnership{serviceUID: int(uid), rootUID: 0, gid: LogDirGID})
}

// logOwnership is who owns the daemon log tree. The three fields are taken
// explicitly — rather than read from the constants and from a hard-coded 0 —
// so the policy can be exercised with the test process's own identity, on a
// machine where chowning to _k3sm, to root, or to group admin needs privilege
// the standards forbid a unit test from having.
type logOwnership struct {
	// serviceUID owns the directory and the server/agent logs: launchd opens a
	// UserName=_k3sm job's log AS that user, so it must be able to append.
	serviceUID int
	// rootUID owns netd.log and datavol.log, whose jobs run as root.
	rootUID int
	// gid is the group of every path in the tree: LogDirGID (admin).
	gid int
}

// logFile is one daemon log and the uid of the launchd job that writes it.
type logFile struct {
	path string
	uid  int
}

// logFiles returns the daemon logs inside dir, in a fixed order. The leaf
// names come from the exported path helpers the plists already use rather than
// from three more literals, so the file the installer prepares is by
// construction the one launchd is pointed at; only the directory is rebased,
// which is what lets an unprivileged test exercise the policy in a temp dir.
func logFiles(dir string, own logOwnership) []logFile {
	return []logFile{
		{filepath.Join(dir, filepath.Base(ServerLogPath())), own.serviceUID},
		// The agent log is pre-created on EVERY install, whichever role this Mac
		// carries. The file's mode is what a role change must not get wrong: launchd
		// reuses an existing file rather than re-creating it, so a log left behind by
		// a previous install is the one the next daemon appends to, and preparing it
		// unconditionally costs an empty 0640 file on a machine that never runs the
		// agent. Owned like server.log, because both jobs run as the service user.
		{filepath.Join(dir, filepath.Base(AgentLogPath())), own.serviceUID},
		{filepath.Join(dir, filepath.Base(NetdLogPath())), own.rootUID},
		{filepath.Join(dir, filepath.Base(DatavolLogPath())), own.rootUID},
	}
}

// ensureLogDir applies the daemon-log ownership policy to dir and to the three
// logs inside it.
func ensureLogDir(dir string, own logOwnership) error {
	if err := os.MkdirAll(dir, LogDirMode); err != nil {
		return fmt.Errorf("create log dir %s: %w", dir, err)
	}
	if err := refuseSymlinkAt(dir); err != nil {
		return fmt.Errorf("log dir %s: %w", dir, err)
	}
	if err := os.Chown(dir, own.serviceUID, own.gid); err != nil {
		return fmt.Errorf("chown log dir %s to %d:%d: %w", dir, own.serviceUID, own.gid, err)
	}
	// MkdirAll skips an existing directory, so the chmod is what repairs one an
	// earlier build created 0755 — i.e. readable by every account on the Mac.
	if err := os.Chmod(dir, LogDirMode); err != nil {
		return fmt.Errorf("chmod log dir %s %#o: %w", dir, LogDirMode, err)
	}
	for _, f := range logFiles(dir, own) {
		if err := ensureLogFile(f.path, f.uid, own.gid); err != nil {
			return err
		}
	}
	return nil
}

// ensureLogFile makes path exist with the log-file policy WITHOUT truncating
// it: launchd only creates a StandardOut/ErrorPath that is missing (see
// launchd.plist(5)), so a file that is already there is opened as it stands and
// keeps the mode set here. O_CREATE without O_TRUNC is what preserves the
// history of an install being repaired, and the explicit chmod is what tightens
// a file an earlier daemon spawn created at its own umask. O_NOFOLLOW makes
// the open itself the symlink guard: a log planted as a link fails with ELOOP
// instead of creating or opening its target for the chown/chmod that follow.
func ensureLogFile(path string, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, LogFileMode)
	if errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("log file %s: %w", path, errSymlinkRefused)
	}
	if err != nil {
		return fmt.Errorf("create log file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close log file %s: %w", path, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown log file %s to %d:%d: %w", path, uid, gid, err)
	}
	if err := os.Chmod(path, LogFileMode); err != nil {
		return fmt.Errorf("chmod log file %s %#o: %w", path, LogFileMode, err)
	}
	return nil
}

// EnsureContainerLogDir creates (or repairs) one directory of the container-log
// tree owned by the service uid, group wheel, mode 0700. See the System
// interface for why the installer, not the node, must create it, and see
// ContainerLogDirMode for why the mode is tighter than EnsureLogDir's.
func (darwinSystem) EnsureContainerLogDir(dir string, uid uint32) error {
	return ensureContainerLogDir(dir, int(uid), ContainerLogDirGID)
}

// ensureContainerLogDir applies the container-log ownership policy to dir. It
// takes uid and gid explicitly — rather than reading the constants — so the
// policy can be exercised with the test process's own identity, on a machine
// where chowning to another uid or to group wheel needs root.
func ensureContainerLogDir(dir string, uid, gid int) error {
	if err := os.MkdirAll(dir, ContainerLogDirMode); err != nil {
		return fmt.Errorf("create container log dir %s: %w", dir, err)
	}
	if err := refuseSymlinkAt(dir); err != nil {
		return fmt.Errorf("container log dir %s: %w", dir, err)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("chown container log dir %s to %d:%d: %w", dir, uid, gid, err)
	}
	// MkdirAll skips an existing directory, so the chmod is what repairs a tree an
	// earlier build or a hand-run mkdir left group- or world-readable.
	if err := os.Chmod(dir, ContainerLogDirMode); err != nil {
		return fmt.Errorf("chmod container log dir %s %#o: %w", dir, ContainerLogDirMode, err)
	}
	return nil
}

// AdoptTree performs the container-log adoption walk. See the System interface
// for the contract, and for why every step of it is descriptor-relative.
//
// The ownership it hands entries TO is a parameter and the ownership it takes
// them FROM is root, because root-owned is exactly what "written before the
// daemon moved to _k3sm" means. adoptTree below takes both explicitly, for the
// same reason ensureContainerLogDir does: the policy is then exercisable by a
// test process with its own identity, on a machine where chowning to another
// uid needs privilege this package's unit tests must not have.
func (darwinSystem) AdoptTree(root string, uid, gid, maxDepth int, policy AdoptPolicy) (TreeAdoption, error) {
	return adoptTree(root, 0, uid, gid, maxDepth, policy)
}

// treeWalk is one adoptTree run: who it takes from, who it gives to, how deep it
// goes, which top-level rule applies, and what it has done so far.
type treeWalk struct {
	fromUID  int
	uid, gid int
	maxDepth int
	policy   AdoptPolicy
	rep      TreeAdoption
}

// adoptTree opens root without following it and walks from that descriptor.
//
// A missing root is returned as an error carrying the errno, so the caller's
// errors.Is(err, fs.ErrNotExist) sees it; a root that is a SYMLINK fails the
// O_NOFOLLOW open with ELOOP, which is the correct answer rather than an
// inconvenience — /var/log/pods being a link is not a tree to adopt.
func adoptTree(root string, fromUID, uid, gid, maxDepth int, policy AdoptPolicy) (TreeAdoption, error) {
	fd, err := openDirNoFollow(root)
	if err != nil {
		return TreeAdoption{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	w := &treeWalk{fromUID: fromUID, uid: uid, gid: gid, maxDepth: maxDepth, policy: policy}
	w.walk(fd, root, 1)
	return w.rep, nil
}

// walk lists one directory THROUGH ITS DESCRIPTOR and visits each child. depth
// is the level of the children being listed: 1 is the top of the tree, where the
// policy applies.
//
// dirPath is carried for reporting ONLY. Nothing in this walk resolves it: it is
// what an operator reads in a log line, never an argument to a syscall.
func (w *treeWalk) walk(dirfd int, dirPath string, depth int) {
	if depth > w.maxDepth {
		w.skip(dirPath, fmt.Sprintf("it is deeper than the %d levels k3sm walks", w.maxDepth))
		return
	}
	names, err := readDirNames(dirfd, dirPath)
	if err != nil {
		w.skip(dirPath, fmt.Sprintf("it could not be listed (%v)", err))
		return
	}
	// Sorted so a walk over the same tree reports and acts in the same order
	// twice, which is what makes the order assertable at all.
	slices.Sort(names)
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			w.skip(filepath.Join(dirPath, name), fmt.Sprintf("it could not be inspected (%v)", err))
			continue
		}
		w.visit(dirfd, dirPath, name, st, depth)
	}
}

// visit decides what happens to one child, having just classified it against its
// parent's descriptor.
func (w *treeWalk) visit(dirfd int, dirPath, name string, st unix.Stat_t, depth int) {
	path := filepath.Join(dirPath, name)
	kind := statKind(st.Mode)
	mine := int(st.Uid) == w.fromUID
	if depth > 1 {
		// Inside a pod directory already adopted: the layout's own files and
		// subdirectories, whatever they are named.
		switch kind {
		case EntryDir:
			w.descend(dirfd, name, path, depth)
		case EntryRegular:
			if mine {
				w.chownat(dirfd, name, path)
			}
		default:
			w.skip(path, "it is "+kind.String()+", which k3sm does not follow or chown here")
		}
		return
	}
	if !mine {
		// Already the service user's (or somebody else's entirely): not this
		// step's business, and not worth a line on a node with a long pod
		// history where every healthy directory would produce one.
		return
	}
	switch w.policy {
	case AdoptLogLinks:
		if kind != EntrySymlink && kind != EntryRegular {
			w.skip(path, "it is "+kind.String()+", which is not a container log link")
			return
		}
		w.chownat(dirfd, name, path)
	default: // AdoptPodDirs
		switch {
		case kind != EntryDir:
			w.skip(path, "it is "+kind.String()+" at the root of the pod log tree, which k3sm did not write")
			return
		case !isPodLogDirName(name):
			w.skip(path, "its name is not the <namespace>_<pod>_<uid> shape k3sm writes, so k3sm does not descend into it")
			return
		}
		w.descend(dirfd, name, path, depth)
	}
}

// descend opens a subdirectory without following it, hands it over if it is
// still the old owner's, and walks INSIDE THE DESCRIPTOR it opened.
//
// The chown is on the open descriptor (fchown) and comes BEFORE the children, so
// the object handed over is exactly the object about to be walked — a rename
// underneath the walk changes which name leads here and nothing about what is
// being changed — and nothing is left inside a directory the service user cannot
// yet traverse.
func (w *treeWalk) descend(dirfd int, name, path string, depth int) {
	childfd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		w.skip(path, fmt.Sprintf("it could not be opened (%v)", err))
		return
	}
	defer func() { _ = unix.Close(childfd) }()
	var st unix.Stat_t
	if err := unix.Fstat(childfd, &st); err != nil {
		w.skip(path, fmt.Sprintf("it could not be inspected (%v)", err))
		return
	}
	if int(st.Uid) == w.fromUID {
		if err := unix.Fchown(childfd, w.uid, w.gid); err != nil {
			w.skip(path, fmt.Sprintf("it could not be handed over (%v)", err))
			return
		}
		w.rep.Adopted++
	}
	w.walk(childfd, path, depth+1)
}

// chownat hands one non-directory entry over by name AGAINST ITS PARENT'S
// DESCRIPTOR, never following a symlink — so in the link directory the link
// itself moves and its target is untouched, and anywhere else a name that has
// become a link since it was classified moves the link and nothing beyond it.
func (w *treeWalk) chownat(dirfd int, name, path string) {
	if err := unix.Fchownat(dirfd, name, w.uid, w.gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		w.skip(path, fmt.Sprintf("it could not be handed over (%v)", err))
		return
	}
	w.rep.Adopted++
}

// skip records an entry the walk stepped over. A failed chown is a skip and
// never an error: this tree is GC-pending debris whose entries can vanish
// mid-walk, and no install fails over it.
func (w *treeWalk) skip(path, reason string) {
	w.rep.Skipped = append(w.rep.Skipped, SkippedEntry{Path: path, Reason: reason})
}

// openDirNoFollow opens a directory without following a final symlink, keeping
// ReadFile's missing-entry contract for the caller.
func openDirNoFollow(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return fd, nil
}

// readDirNames lists a directory through a descriptor.
//
// It reads through a DUP because os.File owns the descriptor it is handed and
// would close the caller's on Close — and the caller still needs it for the
// fstatat/openat/fchownat calls that make this walk safe. The dup shares the
// directory offset, which costs nothing here: each descriptor is listed exactly
// once.
func readDirNames(dirfd int, path string) ([]string, error) {
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(dup)
	f := os.NewFile(uintptr(dup), path)
	defer func() { _ = f.Close() }()
	return f.Readdirnames(-1)
}

// statKind projects a stat's type bits onto EntryKind. It is entryKind's sibling
// for the walk, which classifies from a raw fstatat rather than from an
// fs.FileInfo — the projection has to happen somewhere, and doing it once here
// keeps the two spellings of "is this a symlink" from drifting apart.
func statKind(mode uint16) EntryKind {
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return EntryDir
	case unix.S_IFREG:
		return EntryRegular
	case unix.S_IFLNK:
		return EntrySymlink
	}
	return EntryOther
}

// EnsureRunDir creates (or repairs) the runtime run dir owned by the service
// uid, group staff, mode 0700 — the directory the _k3sm node binds its runtimed
// control socket in. See the System interface for why the installer, not a
// daemon, must be the one to create it.
func (darwinSystem) EnsureRunDir(dir string, uid uint32) error {
	return ensureServiceOwnedDir(dir, uid, "run dir")
}

// EnsureVMRunDir creates (or repairs) the vm guest-agent socket dir owned by the
// service uid, group staff, mode 0700.
//
// Its PARENT — the run dir — is ensured first, through the same helper and with
// the same owner and mode. A bare MkdirAll of the leaf would create a missing
// parent root-owned, which _k3sm could not then traverse; and re-applying the
// parent's ownership here (rather than assuming Install already did) keeps this
// function correct on its own terms instead of correct only in one call order.
func (darwinSystem) EnsureVMRunDir(dir string, uid uint32) error {
	parent := filepath.Dir(dir)
	if err := ensureServiceOwnedDir(parent, uid, "vm run dir parent"); err != nil {
		return err
	}
	return ensureServiceOwnedDir(dir, uid, "vm run dir")
}

// ensureServiceOwnedDir creates dir and re-applies owner uid:staff and mode 0700
// on EVERY call. MkdirAll skips an existing directory, so an install over a tree
// an earlier build (or a root daemon that got there first) left root-owned is
// repaired rather than silently left unwritable by the service user. what names
// the directory in any error, so a failure says which one.
func ensureServiceOwnedDir(dir string, uid uint32, what string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s %s: %w", what, dir, err)
	}
	if err := refuseSymlinkAt(dir); err != nil {
		return fmt.Errorf("%s %s: %w", what, dir, err)
	}
	if err := os.Chown(dir, int(uid), 20); err != nil { // group staff (_k3sm's primary)
		return fmt.Errorf("chown %s %s to %d:staff: %w", what, dir, uid, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s %s 0700: %w", what, dir, err)
	}
	return nil
}

// refuseSymlinkAt lstats path and refuses it if it is a symlink. It exists for
// every caller here that is about to Chown/Chmod BY PATH — both of which follow
// a symlink to whatever it points at — right after an os.MkdirAll that is a
// no-op against a path that already exists. Without this, a directory replaced
// by a symlink between two runs (or one a lower-privileged writer plants ahead
// of a root-run repair) would have its target chowned/chmodded instead of being
// refused, the same confused-deputy shape Owner's own doc comment describes for
// a single file, applied here to a directory MkdirAll believes it already
// created. Found during the 2026-09-23 A1 audit.
//
// It is a check followed by path-based Chown/Chmod, so a narrower window remains
// between the Lstat and those calls; that is acceptable for the pre-planted
// threat model it closes. The race-free shape is the descriptor-bound one
// adoptTree uses (openDirNoFollow, then Fchown/Fchmod on the fd).
func refuseSymlinkAt(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return errSymlinkRefused
	}
	return nil
}

// errSymlinkRefused is refuseSymlinkAt's (and ensureLogFile's) refusal, a
// sentinel so callers and tests match it with errors.Is, never by message.
var errSymlinkRefused = errors.New("is a symlink: refusing to chown/chmod through it")

// Owner reports the ownership, permission bits and kind of path. See the System
// interface for the contract.
//
// Lstat, not Stat: a symlink is described as itself. Following it would let a
// link planted in the agent work dir point the ownership judgement — and then
// the Chown below — at a file somewhere else entirely.
func (darwinSystem) Owner(path string) (OwnedEntry, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return OwnedEntry{}, err
	}
	return ownedEntry(path, fi)
}

// ListOwned lists the entries directly inside dir, each as Owner describes it.
// os.ReadDir's per-entry Info is itself lstat-derived, so a symlink in the
// directory is described rather than followed, exactly as in Owner.
func (darwinSystem) ListOwned(dir string) ([]OwnedEntry, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]OwnedEntry, 0, len(ents))
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			// The entry went away between the read and the stat. A directory
			// being judged before a chown must be described completely or not at
			// all, so this is an error rather than a skipped entry.
			return nil, fmt.Errorf("stat %s: %w", filepath.Join(dir, e.Name()), err)
		}
		owned, err := ownedEntry(filepath.Join(dir, e.Name()), fi)
		if err != nil {
			return nil, err
		}
		out = append(out, owned)
	}
	return out, nil
}

// ownedEntry projects an fs.FileInfo onto OwnedEntry. The unix ownership comes
// from the syscall.Stat_t behind it, which is the only place uid/gid live; an
// fs.FileInfo that carries none is an ERROR rather than a zero uid, because
// "owned by root" is precisely the verdict a zero value would fabricate.
func ownedEntry(path string, fi fs.FileInfo) (OwnedEntry, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return OwnedEntry{}, fmt.Errorf("cannot read the ownership of %s", path)
	}
	return OwnedEntry{
		Path: path,
		UID:  int(st.Uid),
		GID:  int(st.Gid),
		Mode: fi.Mode().Perm(),
		Kind: entryKind(fi.Mode()),
	}, nil
}

// entryKind names what the mode bits say the entry is. The symlink arm is first
// because fs.FileMode reports a symlink as its own type and never as a regular
// file, and because the one caller that acts on this distinction has to be able
// to SAY "a symlink" when it refuses.
func entryKind(mode fs.FileMode) EntryKind {
	switch {
	case mode&fs.ModeSymlink != 0:
		return EntrySymlink
	case mode.IsDir():
		return EntryDir
	case mode.IsRegular():
		return EntryRegular
	}
	return EntryOther
}

// Chown sets path's owner to uid:gid and touches nothing else — no chmod, so
// the mode the file was found at is the mode it keeps.
//
// Lchown rather than Chown, for Owner's reason: the ownership judgement was made
// about the entry itself, and following a symlink here would apply that verdict
// to a different file than the one it was made about.
func (darwinSystem) Chown(path string, uid, gid int) error {
	return os.Lchown(path, uid, gid)
}

// CopyToRootOwned copies src to exactly dst (parent dir created root:wheel 0755)
// using ditto (preserves the signature/extended attributes the notarized binary
// needs). dst is the caller's contract — never derived from src's basename, so a
// build artifact named `k3sm-m2` still lands at the installedBinary() path the
// LaunchDaemon plists exec. A final X_OK access check fails the install fast if
// the copy somehow left dst non-executable (the alternative is launchd's
// unrecoverable "Missing executable" job invalidation at bootstrap).
func (darwinSystem) CopyToRootOwned(src, dst string) error {
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create install dir %s: %w", dstDir, err)
	}
	if err := refuseSymlinkAt(dstDir); err != nil {
		return fmt.Errorf("install dir %s: %w", dstDir, err)
	}
	if err := os.Chown(dstDir, 0, 0); err != nil {
		return fmt.Errorf("chown install dir %s root:wheel: %w", dstDir, err)
	}
	if out, err := exec.Command("ditto", src, dst).CombinedOutput(); err != nil {
		return fmt.Errorf("ditto %s -> %s: %w: %s", src, dst, err, out)
	}
	if err := refuseSymlinkAt(dst); err != nil {
		return fmt.Errorf("installed binary %s: %w", dst, err)
	}
	if err := os.Chown(dst, 0, 0); err != nil {
		return fmt.Errorf("chown %s root:wheel: %w", dst, err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return fmt.Errorf("chmod %s 0755: %w", dst, err)
	}
	if err := unix.Access(dst, unix.X_OK); err != nil {
		return fmt.Errorf("installed binary %s is not executable (launchd would invalidate the daemons): %w", dst, err)
	}
	return nil
}

// checkLinkDirTrust reads dir off the disk and hands the facts that decide its
// trust to linkDirVerdict, which owns the judgement and the refusal message
// (install.go — including the reason the judgement exists at all: the launcher
// directory is on root's PATH). launcherDir is the directory the launcher is
// actually wanted in, which differs from dir only when the judgement has been
// escalated to an ancestor; the verdict needs it to choose a remedy that does
// not tell an operator to delete a system directory.
//
// An ABSENT dir is routed through the verdict table too, rather than returned as
// the raw Lstat error: ENOENT on a path the operator never named says nothing
// about what k3sm wanted. This wrapper is only the Lstat and the euid read; it
// creates nothing, which is what lets LinkDirTrust be called in Install's
// refuse-before-write phase.
func checkLinkDirTrust(dir, launcherDir string) error {
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return linkDirVerdict(dir, launcherDir, linkDirFacts{Absent: true}, os.Geteuid())
	case err != nil:
		return fmt.Errorf("stat link dir %s: %w", dir, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("refusing to link the k3sm launcher into %s: its ownership cannot be read, and an owner that cannot be read cannot be trusted", dir)
	}
	return linkDirVerdict(dir, launcherDir, linkDirFacts{
		UID:       st.Uid,
		Mode:      fi.Mode(),
		IsDir:     fi.IsDir(),
		IsSymlink: fi.Mode()&fs.ModeSymlink != 0,
	}, os.Geteuid())
}

// linkDirTrustFor applies that check for a launcher path, resolving which
// directory is actually judged (linkDirTrustTarget's parent-absent → grandparent
// rule) and reporting whether link's parent has still to be created.
//
// READ-ONLY, by contract: two Lstats and nothing else. Both callers depend on
// that — LinkDirTrust because it runs before install has written a single byte,
// EnsureSymlink because it must not create the parent before the directory that
// would hold it has been trusted.
func linkDirTrustFor(link string) (parentAbsent bool, err error) {
	parent := filepath.Dir(link)
	parentExists := true
	if _, err := os.Lstat(parent); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("stat link dir %s: %w", parent, err)
		}
		parentExists = false
	}
	trustDir, parentAbsent := linkDirTrustTarget(link, parentExists)
	// parent is passed as the launcher directory in BOTH cases: when the
	// judgement escalates, the verdict has to name the directory k3sm actually
	// wants (and would create) rather than the ancestor it is judging, or its
	// remedy reads as "delete /usr/local".
	if err := checkLinkDirTrust(trustDir, parent); err != nil {
		return parentAbsent, err
	}
	return parentAbsent, nil
}

// LinkDirTrust reports whether the launcher directory for link is trusted. See
// the System interface for the contract, and linkDirVerdict for the judgement.
func (darwinSystem) LinkDirTrust(link string) error {
	_, err := linkDirTrustFor(link)
	return err
}

// ResolveJoinHost resolves the join host to every address it names. See the
// System interface for why the answer is plural. An IP literal resolves to
// itself, which net.Resolver already does — there is no special case here,
// because a special case is where "the operator typed an address" and "the
// operator typed a name that happens to look like one" would drift apart.
func (darwinSystem) ResolveJoinHost(host string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

// DialJoinServer opens and immediately closes a TCP connection to addr. The
// close error is ignored deliberately: the connection proved what it was opened
// to prove the moment it was established, and a failure tearing it down says
// nothing about whether the control plane is reachable.
func (darwinSystem) DialJoinServer(addr string, timeout time.Duration) error {
	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// FetchJoinCA reads the cluster CA PEM the bootstrap listener at addr serves.
//
// The TLS posture is InsecureSkipVerify with NO replacement verification, which
// is the one place in k3sm that is true and is why the System interface states
// the reason at the seam: the join's own first hop (bootstrap.PinnedClient) does
// the opposite — it disables the default verification and re-imposes pinned-CA
// verification — because it is about to present a credential. This fetch
// presents nothing and trusts nothing. It reads a deliberately public document
// (the same bytes any client on the LAN can GET from /cacert), hashes it, and
// hands the hash to a comparison against the operator's token. A hostile
// listener can make that comparison FAIL; it cannot make it pass, because it
// would need the cluster CA whose hash the token carries, and it learns nothing
// from us either way.
func (darwinSystem) FetchJoinCA(addr string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Nothing is trusted on the strength of this handshake — see the
				// doc comment above. The bytes it returns are hashed and compared.
				InsecureSkipVerify: true,
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+bootstrap.CACertPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build the cluster-CA request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", bootstrap.CACertPath, resp.Status)
	}
	// Bounded: the CA is a couple of kilobytes, and an installer must not read an
	// unbounded body from a host it has not identified yet.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read the cluster CA: %w", err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("%s served an empty body", bootstrap.CACertPath)
	}
	return body, nil
}

// EnsureSymlink lays down (or repairs) the `k3sm` launcher symlink at link,
// pointing at target. See the System interface for the contract; this is where
// its two refusals get their concrete causes.
//
// Order matters: the directory-trust check runs FIRST, before any write, so an
// untrusted link directory is never even touched. Only then is a missing parent
// created (root:wheel 0755 when we are root), and only then is the link itself
// considered.
//
// Replacement is symlink-then-rename rather than remove-then-symlink: rename(2)
// is atomic on the same filesystem, so `k3sm` never transiently disappears from
// PATH while an upgrade re-points it. The residual window is the same one
// EnsureRunDir documents for its own check-then-act: link is re-Lstat'd
// immediately before the rename and the rename is refused if the kind changed,
// but a racing writer could still slip between that read and the syscall. With a
// root-owned, non-group/other-writable parent — which the trust check has just
// asserted — only root can be that writer, and root is who we already are.
func (darwinSystem) EnsureSymlink(target, link string) error {
	parent := filepath.Dir(link)
	// Trust the directory that will hold the link, BEFORE any write. Install has
	// already asked the same question through System.LinkDirTrust, in its
	// refuse-before-write phase; asking it again here is defense in depth over
	// one function rather than a second rule, and it is this call — not the
	// preflight — that guards the write.
	parentAbsent, err := linkDirTrustFor(link)
	if err != nil {
		return err
	}
	if parentAbsent {
		if err := os.Mkdir(parent, 0o755); err != nil {
			return fmt.Errorf("create link dir %s: %w", parent, err)
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(parent, 0, 0); err != nil {
				return fmt.Errorf("chown link dir %s root:wheel: %w", parent, err)
			}
		}
	}

	fi, err := os.Lstat(link)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Symlink(target, link); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", link, target, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("stat %s: %w", link, err)
	case fi.Mode()&fs.ModeSymlink == 0:
		// A regular file or a directory at link belongs to somebody else. k3sm
		// installs a launcher; it does not evict one.
		return fmt.Errorf("refusing to replace non-symlink %s; move it aside and re-run", link)
	}
	if got, err := os.Readlink(link); err == nil && got == target {
		return nil // already correct
	}

	// Stale (points elsewhere) or dangling: replace atomically.
	tmp := fmt.Sprintf("%s.k3sm-tmp-%d", link, os.Getpid())
	_ = os.Remove(tmp) // a temp left by an interrupted earlier run
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", tmp, target, err)
	}
	again, err := os.Lstat(link)
	if err != nil || again.Mode()&fs.ModeSymlink == 0 {
		_ = os.Remove(tmp)
		if err != nil {
			return fmt.Errorf("stat %s: %w", link, err)
		}
		return fmt.Errorf("refusing to replace non-symlink %s; move it aside and re-run", link)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, link, err)
	}
	return nil
}

// RemoveSymlink removes link only when it is a symlink still pointing at target.
// See the System interface for the contract: everything else is (false, nil) —
// "not ours", which is the whole point of the function, because link lives
// outside the trees uninstall may delete by path.
//
// The residual window is the check-then-unlink one EnsureSymlink documents above:
// link is read, judged, and then unlinked, and a racing writer could re-point it
// in between. The same containment applies — the parent is root-owned and not
// group/other-writable, so only root can race it.
func (darwinSystem) RemoveSymlink(link, target string) (bool, error) {
	if !filepath.IsAbs(link) {
		return false, fmt.Errorf("refusing to remove non-absolute link path %q", link)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", link, err)
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		return false, nil // a real file or directory — never k3sm's
	}
	got, err := os.Readlink(link)
	if err != nil {
		return false, fmt.Errorf("readlink %s: %w", link, err)
	}
	if got != target {
		return false, nil // re-pointed by someone else — leave it
	}
	if err := os.Remove(link); err != nil {
		return false, fmt.Errorf("remove %s: %w", link, err)
	}
	return true, nil
}

// VerifyVirtualizationEntitlement reads the code-signing entitlements off the
// Mach-O at path and requires VirtualizationEntitlement to be among them. See the
// System interface for the three-valued contract; this implementation is where the
// "any other error means refuse" arm gets its concrete causes.
//
// The oracle is `codesign -d --entitlements -`, the SAME invocation
// hack/release/stage.sh makes after it signs the helper. That identity is the
// reason for the choice: the release stager and the installer then judge an
// artifact by one mechanism instead of two that can disagree, and the property the
// stager asserts on the way out is the property the installer asserts on the way
// in.
//
// Reading the entitlement blob is not a signature VALIDITY check, and deliberately
// so. A stricter probe exists — runtimed's cgo SecStaticCodeCheckValidity read
// behind sandbox.VMBackend.Available — and it is the daemon's job, run at every
// boot against the INSTALLED helper. Duplicating it here would mean either a
// second cgo Security.framework shim in this repo or a Go re-implementation of
// signature validation, to catch a case (a helper mangled after signing) that the
// daemon already catches. What install adds is the case the daemon cannot report
// legibly: an entitlement that was never granted in the first place.
//
// An unsigned binary needs no separate arm: codesign exits non-zero on it ("code
// object is not signed at all"), which is already a refusal.
func (darwinSystem) VerifyVirtualizationEntitlement(path string) error {
	if _, err := os.Stat(path); err != nil {
		// Wraps fs.ErrNotExist for a missing file, which the caller reads as
		// "nothing staged" rather than "unentitled".
		return err
	}
	cmd := exec.Command("codesign", "-d", "--entitlements", "-", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Entitlements go to stdout; codesign's "Executable=<path>" banner goes to
	// stderr. Only stdout is matched, so a path that happens to contain the
	// entitlement string cannot satisfy the check.
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("codesign -d --entitlements - %s: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}
	if !bytes.Contains(out, []byte(VirtualizationEntitlement)) {
		return fmt.Errorf("signature grants no %s", VirtualizationEntitlement)
	}
	return nil
}

// EnsureRootDir creates dir root-owned at mode and re-applies both on an
// existing directory, so a staging mount point left behind by an interrupted
// migration is repaired rather than reused at whatever mode it was found with.
func (darwinSystem) EnsureRootDir(dir string, mode fs.FileMode) error {
	return ensureRootOwnedDir(dir, mode)
}

// EnsureMeshKeyDir creates (or repairs) the root-only mesh key dir at mode,
// owned by root:wheel. See the System interface for why it is its own method
// rather than a call on the run dir's, and provisionMeshKey for what the
// ownership does and does not fence off.
func (darwinSystem) EnsureMeshKeyDir(dir string, mode fs.FileMode) error {
	return ensureRootOwnedDir(dir, mode)
}

// ensureRootOwnedDir creates dir and re-applies owner root:wheel and mode on
// EVERY call — the root-owned counterpart of ensureServiceOwnedDir, and the one
// implementation both root-directory seams above are spelled in, so the two
// cannot drift into different answers to "what does root-owned mean here".
func ensureRootOwnedDir(dir string, mode fs.FileMode) error {
	return ensureDirOwnedBy(dir, 0, 0, mode)
}

// ensureDirOwnedBy is ensureRootOwnedDir with the owner taken explicitly, for
// ensureLogDir's reason: an unprivileged test cannot chown to root, so without
// the split a chown EPERM would mask whether the symlink guard ran at all.
func ensureDirOwnedBy(dir string, uid, gid int, mode fs.FileMode) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := refuseSymlinkAt(dir); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", dir, uid, gid, err)
	}
	// MkdirAll skips an existing directory, so the chmod is what repairs one.
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", dir, mode, err)
	}
	return nil
}

// CopyTree copies src into dst with ditto(1), the same tool CopyToRootOwned
// uses and for the same reason: it preserves ownership, modes, extended
// attributes and ACLs, every one of which the migration's verification then
// compares. The trailing separators matter — `ditto <src>/ <dst>/` copies the
// CONTENTS of src into dst, where `ditto <src> <dst>` would copy src as a child
// of dst on some argument shapes.
func (darwinSystem) CopyTree(src, dst string) error {
	out, err := exec.Command("ditto", filepath.Clean(src)+"/", filepath.Clean(dst)+"/").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ditto %s/ -> %s/: %w: %s", src, dst, err, out)
	}
	return nil
}

// Rename moves old to new within one filesystem.
func (darwinSystem) Rename(old, new string) error {
	if err := os.Rename(old, new); err != nil {
		return fmt.Errorf("rename %s to %s: %w", old, new, err)
	}
	return nil
}

// RemoveTree deletes path and everything under it. See the System interface for
// why it is separate from RemoveAll.
func (darwinSystem) RemoveTree(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// LockInstall takes the exclusive install-wide lock at path. See the System
// interface for why it exists and why it never waits.
//
// flock(2) rather than an O_CREAT|O_EXCL sentinel, deliberately: a sentinel file
// is not released when the process holding it is killed, so a `sudo k3sm
// install` stopped with ^C or by a panic would lock every later install out
// until somebody deleted a file they have no reason to know about. A flock is
// held by the open file description and the kernel drops it when the process
// dies, whatever killed it. The lock file itself is left on disk on purpose —
// it is empty, it is the lock's name, and removing it would race the next
// acquirer onto a different inode.
func (darwinSystem) LockInstall(path string) (func() error, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, uint32(installLockMode))
	if err != nil {
		return nil, fmt.Errorf("open the install lock %s: %w", path, err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (its lock is held at %s; wait for it to finish, or check for a stopped `k3sm install`)", ErrInstallInProgress, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() error {
		// Closing the descriptor releases the lock; the explicit unlock is here
		// so a close that fails still leaves the lock dropped rather than held
		// to process exit.
		if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("unlock %s: %w", path, err)
		}
		if err := unix.Close(fd); err != nil {
			return fmt.Errorf("close the install lock %s: %w", path, err)
		}
		return nil
	}, nil
}

// SwapInstallRoot exchanges the staged tree with the live install root. See the
// System interface for the contract, including what the atomicity claim is and
// is not.
//
// renamex_np(2) with RENAME_SWAP is the only primitive on darwin that publishes
// a directory over an existing one in a single step: plain rename(2) refuses a
// non-empty destination directory (ENOTEMPTY), and the remove-then-rename
// sequence it would otherwise take leaves a window with NO install root at all —
// during which launchd's KeepAlive would find the daemons' executable missing.
//
// An ENOENT destination is the first install and is the one case that falls back
// to a plain rename. The fallback is reached by ATTEMPTING the swap rather than
// by testing for the directory first, so there is no window between the test and
// the act in which the destination could appear.
func (darwinSystem) SwapInstallRoot(staging, live string) (bool, error) {
	err := unix.RenamexNp(staging, live, unix.RENAME_SWAP)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOENT):
		// Either the destination is absent (a first install) or the staged tree
		// itself is — and the plain rename below distinguishes them by failing
		// with a message that names both paths.
		if rerr := os.Rename(staging, live); rerr != nil {
			return false, fmt.Errorf("rename the staged install root %s to %s: %w", staging, live, rerr)
		}
		return false, nil
	case errors.Is(err, unix.EXDEV):
		return false, fmt.Errorf("%w: %s and %s", ErrInstallRootCrossDevice, staging, live)
	default:
		return false, fmt.Errorf("swap the staged install root %s with %s: %w", staging, live, err)
	}
}

// InstallSpace reports the free space on dir's filesystem and the size of the
// sources an install would stage onto it. See the System interface: it takes two
// stat families and makes no judgement.
//
// An absent source contributes zero rather than failing: the preflight runs
// before the copies, and a missing artifact is the copy's message to give, with
// the build command that produces it.
func (darwinSystem) InstallSpace(dir string, sources []string) (uint64, uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	var need uint64
	for _, src := range sources {
		if src == "" {
			continue
		}
		n, err := treeBytes(src)
		if err != nil {
			return 0, 0, err
		}
		need += n
	}
	return free, need, nil
}

// treeBytes is the total size of the regular files at path, which may be one
// file or a whole directory. A missing path is zero bytes, not an error — see
// InstallSpace. Symlinks are not followed, for the reason every other read in
// this file does not follow one.
func treeBytes(path string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return err
		case !d.Type().IsRegular():
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		total += uint64(info.Size())
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("size %s: %w", path, err)
	}
	return total, nil
}

// LookupServiceUID resolves the service account's uid. A user that does not
// exist is (0, false), not an error: install legitimately reaches this before
// EnsureServiceUser has created _k3sm.
func (darwinSystem) LookupServiceUID(name string) (int, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, false
	}
	return uid, true
}

// WriteDataVolumeRecord writes the record through pkg/dataroot, which owns its
// encoding, its version stamp, its 0644 mode and its temp-and-rename.
func (darwinSystem) WriteDataVolumeRecord(path string, rec dataroot.Record) error {
	return dataroot.WriteRecord(path, rec)
}

// WriteServerArgsRecord writes the server-arguments record through pkg/dataroot,
// which owns its encoding, its version stamp, its 0600 mode and its
// temp-and-rename (the same atomic helper the data-volume record uses).
//
// The file lands root:wheel in /Library/Preferences, and both halves of that
// matter: only root may rewrite what the next install splices into the server
// LaunchDaemon's argv, and only root may read it, because an operator argument
// can carry a credential (--datastore-endpoint carries a DSN password).
func (darwinSystem) WriteServerArgsRecord(path string, rec dataroot.ServerArgsRecord) error {
	return dataroot.WriteServerArgsRecord(path, rec)
}

// WriteAgentArgsRecord writes the agent-arguments record through pkg/dataroot,
// with WriteServerArgsRecord's contract and for the same reasons: root:wheel
// 0600 in /Library/Preferences, so only root can change what the next install
// splices into the agent LaunchDaemon's argv and only root can read it.
func (darwinSystem) WriteAgentArgsRecord(path string, rec dataroot.AgentArgsRecord) error {
	return dataroot.WriteAgentArgsRecord(path, rec)
}

// WriteServiceUserFile writes contents at path owned by the service uid at
// mode, creating the parent directory owned by the same uid at dirMode.
//
// The write is temp-and-rename INSIDE the parent directory, and the mode and
// owner are applied to the temp file before the rename, so no reader ever sees
// the file at a wider mode or a different owner than the one asked for — which
// matters because the only thing written this way is a credential.
//
// The group is the data root's (DataRootGID): the file lands in the service
// user's own tree, and its mode grants the group nothing, so the group is a
// consistency choice rather than an access one.
func (darwinSystem) WriteServiceUserFile(path string, contents []byte, uid uint32, mode, dirMode fs.FileMode) error {
	return writeServiceUserFile(path, contents, int(uid), DataRootGID, mode, dirMode)
}

// writeServiceUserFile is the method above with the owner taken explicitly.
//
// The split exists for the same reason ensureLogDir's does: chowning to _k3sm
// or to a group the test process is not in needs privilege these tests never
// take, and what has to be exercised against a real filesystem is the MODE, the
// repair of an existing tree, and the temp-and-rename — not whether this
// process may hand a file to another user.
func writeServiceUserFile(path string, contents []byte, uid, gid int, mode, dirMode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := refuseSymlinkAt(dir); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	// MkdirAll skips an existing directory, so owner and mode are re-applied:
	// an install over a tree an earlier build left root-owned must repair it,
	// not leave the daemon unable to read what was just written into it.
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", dir, uid, gid, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", dir, dirMode, err)
	}
	tmp, err := os.CreateTemp(dir, ".k3sm-*")
	if err != nil {
		return fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // a no-op once the rename succeeded
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chown(tmpName, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", tmpName, uid, gid, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", tmpName, mode, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// WriteRootOnlyFile writes contents at path root:wheel at mode. The parent
// directory is NOT created or re-owned here — the caller ensured it through its
// own seam, and a write that also decided a directory's terms could quietly
// loosen what that seam decided.
//
// The write is temp-and-rename inside the parent, with owner and mode applied to
// the temp file BEFORE the rename, so no reader ever observes the file at wider
// terms than the ones asked for. That matters for the only file written this way:
// a wireguard private key.
func (darwinSystem) WriteRootOnlyFile(path string, contents []byte, mode fs.FileMode) error {
	return writeRootOnlyFile(path, contents, 0, 0, mode)
}

// writeRootOnlyFile is the method above with the owner taken explicitly, the
// same split writeServiceUserFile and writeLaunchDaemon carry and for the same
// reason: chowning a file to root needs privilege these tests never take, while
// the MODE, the atomicity and the overwrite of an existing file are exactly what
// has to be exercised against a real filesystem.
func writeRootOnlyFile(path string, contents []byte, uid, gid int, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".k3sm-*")
	if err != nil {
		return fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // a no-op once the rename succeeded
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chown(tmpName, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", tmpName, uid, gid, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", tmpName, mode, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// WriteLaunchDaemon writes the plist root:wheel at mode (PlistMode for every
// daemon but the control plane, which is ServerPlistMode).
//
// The chmod is explicit rather than left to os.WriteFile because WriteFile
// applies the mode only when it CREATES the file: a reinstall over an existing
// 0644 plist would otherwise keep the old, wider mode, which is precisely the
// file a tightening install exists to replace.
func (darwinSystem) WriteLaunchDaemon(plistPath string, contents []byte, mode fs.FileMode) error {
	return writeLaunchDaemon(plistPath, contents, mode, 0, 0)
}

// writeLaunchDaemon is the method above with the owner taken explicitly.
//
// The split is writeServiceUserFile's, for the same reason: chowning a file to
// root needs privilege these tests never take, and what has to be exercised
// against a real filesystem is the MODE and its repair on a rewrite, not
// whether this process may give a file away.
//
// The chmod is explicit rather than left to os.WriteFile because WriteFile
// applies the mode only when it CREATES the file. Without it, a reinstall over
// the 0644 plist an earlier build laid down would keep that wider mode — which
// is precisely the file the tightening exists to replace.
func writeLaunchDaemon(plistPath string, contents []byte, mode fs.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return fmt.Errorf("create launchd dir: %w", err)
	}
	if err := os.WriteFile(plistPath, contents, mode); err != nil {
		return fmt.Errorf("write %s: %w", plistPath, err)
	}
	if err := os.Chmod(plistPath, mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", plistPath, mode, err)
	}
	if err := os.Chown(plistPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", plistPath, uid, gid, err)
	}
	return nil
}

// ReadRegularFile reads path without following a symlink and refuses anything
// that is not a regular file. See the System interface for the confused-deputy
// read it exists to prevent.
func (darwinSystem) ReadRegularFile(path string) ([]byte, error) {
	return readRegularFile(path)
}

// ReadRegularFileWithMode is ReadRegularFile plus the permission bits, both
// read off the same open descriptor as the content. See the System interface.
func (darwinSystem) ReadRegularFileWithMode(path string) ([]byte, fs.FileMode, error) {
	return readRegularFileWithMode(path)
}

// readRegularFile is the method above, split out so the on-disk test can
// exercise it directly — the same split the other privileged writers carry.
//
// Three details are load-bearing:
//
//   - O_NOFOLLOW makes the kernel refuse the open when the LAST path component
//     is a symlink (ELOOP), which is the swap this read has to survive. It says
//     nothing about a symlinked parent directory; nothing here can, and the
//     parent's ownership is the control that covers it.
//   - O_NONBLOCK keeps a planted fifo from parking the installer forever on the
//     open. A regular file is unaffected by it.
//   - the type is checked on the open DESCRIPTOR (f.Stat), never with a
//     path-based stat beforehand, so there is no window in which the thing
//     checked and the thing read could be two different files.
func readRegularFile(path string) ([]byte, error) {
	b, _, err := readRegularFileWithMode(path)
	return b, err
}

// readRegularFileWithMode is readRegularFile plus the permission bits, both
// read off the SAME open descriptor as the content. It exists for exactly one
// caller: operatorJoinToken, which has to judge a credential's mode before
// trusting its content the way every other reader here judges only the type
// (ReadRegularFile) or only the bytes (ReadFile). Getting the mode from a
// separate os.Stat call — the original shape, before the 2026-09-23 A1 audit —
// reopened the exact confused-deputy window readRegularFile's own doc comment
// describes: two path-based syscalls, no fd binding them together, so a
// symlink swapped in between them lets the mode judged and the bytes read
// belong to two different files.
func readRegularFileWithMode(path string) ([]byte, fs.FileMode, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		// A missing file keeps ReadFile's contract (callers read fs.ErrNotExist as
		// a posture); a symlink is reported as the refusal it is, because ELOOP
		// alone reads like a link cycle rather than a swap somebody performed.
		if errors.Is(err, unix.ELOOP) {
			return nil, 0, fmt.Errorf("open %s: %w: it is a symlink, and this read refuses to follow one", path, ErrNotRegularFile)
		}
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("open %s: %w: it is a %s", path, ErrNotRegularFile, fi.Mode().Type())
	}
	b, err := io.ReadAll(f)
	return b, fi.Mode().Perm(), err
}

// ReadFile reads a root-readable file, propagating os.ReadFile's error verbatim
// so a caller can distinguish "not there yet" (fs.ErrNotExist — a first install
// has neither the installed plist nor the cluster CA) from a real read failure.
func (darwinSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// LaunchctlBootstrap loads the daemon into the system domain. A failure launchd
// attributes to the domain still settling is wrapped with ErrLaunchctlTransient so
// the caller can retry exactly that class — see transientLaunchctlOutput. This is
// the ONLY place launchctl's output text is inspected; the orchestration above
// compares sentinels.
func (darwinSystem) LaunchctlBootstrap(label string) error {
	plist := filepath.Join(DefaultLaunchDaemonDir, label+".plist")
	out, err := exec.Command("launchctl", "bootstrap", "system", plist).CombinedOutput()
	if err == nil {
		return nil
	}
	if transientLaunchctlOutput(string(out)) {
		return fmt.Errorf("launchctl bootstrap %s: %w: %w: %s", label, ErrLaunchctlTransient, err, out)
	}
	return fmt.Errorf("launchctl bootstrap %s: %w: %s", label, err, out)
}

// transientErrno matches launchctl's "<verb> failed: <errno>: <text>" line for the
// two errnos launchd returns while a booted-out label is still leaving the system
// domain: 37 (EINPROGRESS — the removal is in flight) and 5 (EIO — observed for
// 1.77s while the label drained on a live install). The errno is anchored to the
// failure line so an unrelated ": 5:" elsewhere in the output cannot match.
var transientErrno = regexp.MustCompile(`(?im)^\s*\w+ failed:\s*(5|37):`)

// transientLaunchctlOutput reports whether launchctl's output describes the domain
// settling rather than a verdict on the job. It matches both the numeric form and
// the two strerror texts, because launchctl has printed each shape depending on
// the subcommand and the macOS release, and a missed classification here silently
// reverts the caller to the un-retried behaviour this exists to fix.
//
// Misclassifying a PERMANENT failure as transient costs only a bounded retry that
// fails identically and is then reported; the asymmetry is deliberate.
func transientLaunchctlOutput(out string) bool {
	lower := strings.ToLower(out)
	return strings.Contains(lower, "operation already in progress") ||
		strings.Contains(lower, "input/output error") ||
		transientErrno.MatchString(out)
}

// PathExists reports whether path exists, without opening it. Install verifies the
// netd unix socket this way because no file read can answer for a socket: opening
// one with the file API fails whether or not netd is listening. A not-exist stat is
// (false, nil); any other stat failure is returned, because "I could not tell" must
// never be reported as "absent". Lstat, not Stat, so a dangling symlink at the
// socket path is reported as present — it exists, and it is not this check's job to
// decide it is the wrong kind of thing.
func (darwinSystem) PathExists(path string) (bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ProbeNetd asks the netd helper at path to ANSWER, and is deliberately a round
// trip rather than a dial.
//
// A connect proves nothing about the process that bound the socket. connect(2)
// on a unix socket succeeds the moment the listen backlog has room — the kernel
// queues it — so a netd that is listening and wedged (still starting, deadlocked,
// stopped) accepts every attempt and serves none. A dial-only probe would
// therefore end the installer's wait in exactly one of the two states it exists
// to distinguish.
//
// So the probe writes one framed request whose verb is not in netd's set and
// waits for the daemon to do something about it. netd's dispatch answers an
// unknown verb with an error response (darwin-net's netd.Server), which is the
// reply this looks for; a netd that instead REJECTS the connection — the
// ordinary case, because the socket authorizes the service uid and `k3sm
// install` runs as root — closes it after its peer check, and that close is
// equally proof the accept loop and the handler behind it are running. Both are
// answers. The one thing that is not an answer is silence, and silence is the
// wedged case.
//
// The reject can also land on the WRITE side of the round trip: if netd's peer
// check closes the connection before the probe's single frame is delivered,
// the write itself fails with EPIPE, ECONNRESET or ENOTCONN (which of the three
// depends on how far the peer's close had progressed when the write was
// attempted; all three were observed on macOS 26). That is the same proof as a close seen
// on the read — the handler ran and acted on the connection — so it is
// likewise counted as an answer rather than surfaced as the probe's own
// failure.
//
// The verb is unknown ON PURPOSE: every verb netd does implement mutates
// privileged host state (an lo0 alias, the mesh, a pf anchor, a bound port), and
// a liveness probe must not be able to change the machine it is asking about.
func (darwinSystem) ProbeNetd(path string) error {
	payload, err := json.Marshal(wire.Request{Version: wire.CurrentVersion(), Verb: netdProbeVerb})
	if err != nil {
		return fmt.Errorf("encode the netd probe request: %w", err)
	}
	conn, err := net.DialTimeout("unix", path, netdProbeTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(netdProbeTimeout)); err != nil {
		return fmt.Errorf("arm the netd probe deadline: %w", err)
	}
	netdProbeBeforeWrite()
	if err := wire.WriteFrame(conn, payload); err != nil {
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENOTCONN) {
			// The peer closed before our write was delivered — the same
			// proof as a close seen on the read side. It acted, so it is up.
			return nil
		}
		return fmt.Errorf("send the netd probe request: %w", err)
	}
	_, err = wire.ReadFrame(conn, netdProbeMaxReply)
	switch {
	case err == nil:
		return nil // netd answered
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// The handler ran and closed the connection — netd's own peer check
		// declining a root client is the common shape. It acted, so it is up.
		return nil
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("accepted the connection but did not answer within %s (a socket that is bound while its daemon is not serving)", netdProbeTimeout)
	default:
		return fmt.Errorf("reading netd's reply: %w", err)
	}
}

// netdProbeVerb is the verb ProbeNetd sends. It is deliberately outside
// wire's closed set: netd answers it with an error response and changes nothing,
// which is the whole contract a liveness probe wants.
const netdProbeVerb = "k3sm-install-probe"

// netdProbeTimeout bounds one probe: the connect, the write and the wait for the
// answer. A unix round trip against a live daemon is microseconds, so a second is
// generous; it is a wedged-peer bound, not a patience budget (the caller's restart
// budget is that). It is a var, not a const, so a unit test that deliberately
// probes a wedged listener does not spend a real second per case; nothing in the
// product writes it.
var netdProbeTimeout = time.Second

// netdProbeBeforeWrite runs immediately before ProbeNetd writes its request
// frame. It is a var, not a const, so a unit test can force the write to wait
// until a peer close has already landed on the connection — the ordering a
// real accept-then-reject race only sometimes produces — and so deterministically
// exercise the EPIPE path above. Nothing in the product sets it.
var netdProbeBeforeWrite = func() {}

// netdProbeMaxReply caps the reply this reads. netd's error response is a few
// hundred bytes; the cap exists so a desynced or hostile stream cannot make the
// installer allocate.
const netdProbeMaxReply = 64 << 10

// LaunchctlBootout unloads the daemon. A not-loaded label (exit 113/3) is treated
// as success so uninstall is idempotent.
func (darwinSystem) LaunchctlBootout(label string) error {
	out, err := exec.Command("launchctl", "bootout", "system/"+label).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Could not find") || strings.Contains(string(out), "No such process") {
			return nil
		}
		return fmt.Errorf("launchctl bootout %s: %w: %s", label, err, out)
	}
	return nil
}

// LaunchctlKickstart force-restarts the daemon. An unloaded/absent label is an
// ERROR here (unlike Bootout's idempotent no-op): a caller asking for a restart must
// never be told a daemon that is not there was restarted. launchctl's output is
// trimmed because this error is surfaced verbatim in a CLI message.
//
// It returns once launchd has ACCEPTED the restart request. The old instance is
// still draining at that point (the control plane tears its components down
// serially, within the plist's ExitTimeOut), so anything that must observe the NEW
// instance polls LaunchctlServicePID for a changed pid.
func (darwinSystem) LaunchctlKickstart(label string) error {
	if out, err := exec.Command("launchctl", "kickstart", "-k", "system/"+label).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w: %s", label, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchctlServicePID reads the pid launchd reports for the job out of
// `launchctl print system/<label>`'s "pid = N" field. A loaded-but-not-running job
// has no such field and yields 0 (not an error — it is the normal respawn window);
// a label that is not loaded fails, because "no job" must never be reported as "no
// pid yet". Read-only: it starts, stops and changes nothing.
//
// Unlike the other launchctl wrappers this one does NOT put the command's output in
// its error. `launchctl print` dumps the whole job on success — including the
// daemon's argv, which carries the apiserver's static admin token — and this error
// string is surfaced verbatim in a CLI message. Only the exit status is reported;
// the operator is pointed at the command instead.
func (darwinSystem) LaunchctlServicePID(label string) (int, error) {
	out, err := exec.Command("launchctl", "print", "system/"+label).Output()
	if err != nil {
		return 0, fmt.Errorf("launchctl print system/%s (is the daemon loaded?): %w", label, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, fmt.Errorf("launchctl print system/%s: unparsable pid field %q: %w", label, rest, err)
		}
		return pid, nil
	}
	return 0, nil
}

// WriteUserKubeconfig MERGES the k3sm admin context (contents) into targetUser's
// ~/.kube/config, owned by targetUser (NOT root) so the human can kubectl without
// sudo. Any pre-existing clusters/contexts are preserved — install must never
// clobber a developer's other kubeconfigs (uninstall likewise leaves the file).
// The write is atomic (temp + rename) so a crash mid-write can't corrupt the file.
func (darwinSystem) WriteUserKubeconfig(targetUser string, contents []byte) error {
	u, err := user.Lookup(targetUser)
	if err != nil {
		return fmt.Errorf("lookup target user %s: %w", targetUser, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	kubeDir := filepath.Join(u.HomeDir, ".kube")
	if err := os.MkdirAll(kubeDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", kubeDir, err)
	}
	// ~/.kube is owned by the target user, so it is the most reachable plant of
	// all: refuse a link before the (best-effort) chown and the writes below.
	if err := refuseSymlinkAt(kubeDir); err != nil {
		return fmt.Errorf("%s: %w", kubeDir, err)
	}
	_ = os.Chown(kubeDir, uid, gid)
	path := filepath.Join(kubeDir, "config")

	existing, rerr := os.ReadFile(path)
	if rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("read existing kubeconfig %s: %w", path, rerr)
	}
	merged, err := mergeAdminKubeconfig(existing, contents, adminContextName)
	if err != nil {
		return fmt.Errorf("merge admin kubeconfig into %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(kubeDir, ".k3sm-kubeconfig-*")
	if err != nil {
		return fmt.Errorf("create temp kubeconfig: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp kubeconfig: %w", err)
	}
	if _, err := tmp.Write(merged); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp kubeconfig: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp kubeconfig: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename kubeconfig into place: %w", err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %s: %w", path, targetUser, err)
	}
	return nil
}

// ReapOrphans SIGKILLs any process whose command line references binPrefix — the
// control-plane children (kine/kube-apiserver/…) left behind when the server
// daemon died before Stop() reaped them. `pkill -9 -f` matches the absolute
// <DataRoot>/server/bin/ path, which is specific to this install's spawned
// children and never a bystander. Exit code 1 (no match) is the common no-op and
// is NOT an error; only a real failure (>1) is.
func (darwinSystem) ReapOrphans(binPrefix string) error {
	cmd := exec.Command("pkill", "-9", "-f", binPrefix)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nil // no matching process — nothing to reap
		}
		return fmt.Errorf("pkill orphaned control-plane children (%s): %w", binPrefix, err)
	}
	return nil
}

// RemoveAll removes a path tree.
func (darwinSystem) RemoveAll(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// FlushLo0Aliases lists lo0's live inet aliases (`ifconfig lo0`) and removes
// every one inside the given prefixes with `ifconfig lo0 -alias <ip>` — the
// root-privileged uninstall backstop for k3sm's durable alias state (pod /32s,
// Service VIPs, the node mesh-egress .1). Removal failures are collected and
// the flush continues, so one stuck alias never strands the rest; removing an
// address that vanished between list and remove is tolerated.
func (darwinSystem) FlushLo0Aliases(prefixes []netip.Prefix) error {
	out, err := exec.Command("ifconfig", "lo0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig lo0: %w\n%s", err, out)
	}
	var errs []error
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		// A v4 alias line reads "inet A.B.C.D netmask 0xffffffff".
		if len(fields) < 2 || fields[0] != "inet" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		owned := false
		for _, p := range prefixes {
			if p.Contains(ip) {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		if rmOut, err := exec.Command("ifconfig", "lo0", "-alias", ip.String()).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("ifconfig lo0 -alias %s: %w\n%s", ip, err, rmOut))
		}
	}
	return errors.Join(errs...)
}

// FlushMeshPFAnchor flushes every rule loaded into the mesh's MSS-clamp pf
// anchor (mesh.PFAnchor, "io.k3sm.mesh") — the root-privileged uninstall
// backstop for B274: the anchor is loaded against a utun interface number and
// nothing on the daemon-shutdown path ever flushes it, so it survives a
// booted-out netd scoped to a utun macOS will eventually recycle onto an
// unrelated tunnel. `pfctl -a <anchor> -F all` against an anchor that was
// never loaded flushes zero rules and exits 0, so this is safely unconditional
// on every uninstall — mesh or single-node.
func (darwinSystem) FlushMeshPFAnchor() error {
	out, err := exec.Command("pfctl", "-a", mesh.PFAnchor, "-F", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -F all: %w\n%s", mesh.PFAnchor, err, out)
	}
	return nil
}
