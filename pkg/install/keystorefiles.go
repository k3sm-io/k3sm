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
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The keystore's append-only files (docs/design/keystore.md § "The user-scope
// floor", flag variant, which the K0 spike picked): keystore-run/ in the
// root-owned data root, and the two logs, the user-scope floor and the audit
// log, in its keystore-logs/ (root's 0755).
// The logs are the service user's, mode 0600, flagged SF_APPEND, which only
// root can clear; the run directory is the service user's, 0700.

// keystoreLogMode is both logs' mode; keystoreRunDirMode the run
// directory's; keystoreLogsDirMode keystore-logs/'s with the gate open and
// keystoreGateMode with it closed; keystoreStagingDirMode keystore-staging/'s.
const (
	keystoreLogMode        = 0o600
	keystoreRunDirMode     = 0o700
	keystoreLogsDirMode    = 0o755
	keystoreGateMode       = 0o700
	keystoreStagingDirMode = 0o700
)

// keystoreKeystoreSubdir is the entries' directory in the server work dir,
// pkg/keystore's Config.Dir.
const keystoreKeystoreSubdir = "keystore"

var (
	// errKeystoreFilesNotRoot is the keystore step run without root: only
	// root can create a root-owned file and set SF_APPEND.
	errKeystoreFilesNotRoot = errors.New("the keystore's append-only files are created by root: run sudo k3sm install")
	// errKeystoreFileUntrusted is a name in the data root install will not
	// keep: a symlink, a non-regular file, a file with links, at another
	// mode, owned by someone else, or a service-user log whose flag is clear.
	errKeystoreFileUntrusted = errors.New("a keystore file in the data root is not what install creates; it is kept as found")
	// errKeystoreFloorWithScopes is a missing floor while user scopes exist:
	// a new, empty floor would lower every scope's floor.
	// errKeystoreMaintenance is the keystore step run while the maintenance
	// marker stands: a maintenance verb is running or stopped part-way, and
	// handing a log to the service user then could hand over a log the verb
	// has not finished.
	errKeystoreMaintenance     = errors.New("keystore-maintenance exists in the data root, so a keystore maintenance verb is running or stopped part-way; install changes nothing while it stands: rerun the verb that stopped (sudo k3sm keys floor --rebuild or sudo k3sm keys audit --rotate), which removes the marker, then rerun install")
	errKeystoreFloorWithScopes = errors.New("the user-scope floor is missing while user scopes exist; a new floor would lower every scope's floor, so install does not create one: restore keystore/, keystore/.user/ and both logs from one backup, then rebuild the floor")
)

// keystoreFilesSystem is the System method the keystore step calls.
type keystoreFilesSystem interface {
	// EnsureKeystoreFiles is ensureKeystoreFiles for the service uid.
	EnsureKeystoreFiles(dataRoot string, uid uint32) error
}

// keystoreStep is the state tree step's last act, on a server only:
// keystore-run/ and the user-scope floor and audit logs, in the root-owned
// data root the step has just made. The server's start step keeps the user
// scope off until both logs are the service user's and flagged.
func keystoreStep(sys System, cfg Config, uid uint32) error {
	if cfg.Role == RoleAgent {
		return nil
	}
	if err := sys.EnsureKeystoreFiles(cfg.DataRoot, uid); err != nil {
		return fmt.Errorf("install: ensure the keystore's append-only files in %s: %w", cfg.DataRoot, err)
	}
	return nil
}

// ensureKeystoreFiles creates keystore-run/, keystore-logs/ and both
// append-only logs in dataRoot, for the service user svcUID:svcGID, and
// keeps what an earlier install made. rootUID is the data root's owner: 0
// in production; only a non-root test passes its own uid. Every step goes
// through one descriptor on the data root, opened O_DIRECTORY|O_NOFOLLOW
// and judged on fstat, its flags and its ACL as the keystore judges it
// (keystore.JudgeDirFlagsACL). While the maintenance marker stands it
// refuses, changing nothing.
//
// SF_APPEND refuses root's fchown of a flagged file, so a new log is
// handed to the service user first and flagged last, behind the gate: it
// is created root's 0600 with O_CREAT|O_EXCL|O_NOFOLLOW in the root-only
// keystore-staging/, fchmod'd and fchown'd to the service user there,
// keystore-logs/ is closed to 0700, the log renamed in with RENAME_EXCL,
// flagged on the held descriptor and judged, and keystore-logs/ opened to
// 0755 again. A log that already passes the keystore's judge is left
// alone; one the service user owns at 0600 with no flag, found while the
// gate is closed, is the log of an install that stopped after its rename,
// and is flagged and judged. Anything else is refused and left as found.
func ensureKeystoreFiles(dataRoot string, svcUID, svcGID, rootUID int) error {
	if euidSeam() != 0 {
		return errKeystoreFilesNotRoot
	}
	dfd, err := unix.Open(dataRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the data root %s: %w", dataRoot, err)
	}
	defer func() { _ = unix.Close(dfd) }() // a directory, read-only
	var st unix.Stat_t
	if err := unix.Fstat(dfd, &st); err != nil {
		return fmt.Errorf("stat the data root %s: %w", dataRoot, err)
	}
	if int64(st.Uid) != int64(rootUID) || st.Mode&0o022 != 0 {
		return fmt.Errorf("the data root %s is not root's, or is group- or other-writable: %w", dataRoot, errKeystoreFileUntrusted)
	}
	if err := keystore.JudgeDirFlagsACL(dfd); err != nil {
		return fmt.Errorf("the data root %s: %w: %w", dataRoot, err, errKeystoreFileUntrusted)
	}
	if err := unix.Fstatat(dfd, keystore.MaintenanceMarkerName, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return errKeystoreMaintenance
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("look for %s: %w", keystore.MaintenanceMarkerName, err)
	}
	for _, name := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return fmt.Errorf("%s is at the top of the data root, where this build keeps no log (the logs live in %s/): clear its flag and remove it (sudo chflags nosappnd, then sudo rm), then rerun sudo k3sm install: %w", name, keystore.LogsDirName, errKeystoreFileUntrusted)
		}
	}
	if err := ensureKeystoreRunDir(dfd, svcUID, svcGID, rootUID); err != nil {
		return err
	}
	g, err := openKeystoreGate(dfd, rootUID)
	if err != nil {
		return err
	}
	defer g.close()
	for _, name := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		if err := g.ensureLog(name, svcUID, svcGID); err != nil {
			return err
		}
	}
	return g.finish()
}

// ensureKeystoreRunDir creates keystore-run/ under dfd and hands it to the
// service user at keystoreRunDirMode, on its own descriptor.
func ensureKeystoreRunDir(dfd, svcUID, svcGID, rootUID int) error {
	name := keystore.RunDirName
	if err := unix.Mkdirat(dfd, name, keystoreRunDirMode); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create %s: %w", name, err)
	}
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	defer func() { _ = unix.Close(fd) }() // a directory, read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if int64(st.Uid) != int64(rootUID) && int64(st.Uid) != int64(svcUID) {
		return fmt.Errorf("%s is owned by uid %d: %w", name, st.Uid, errKeystoreFileUntrusted)
	}
	if err := fileAttrSeam.Fchmod(fd, keystoreRunDirMode); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if err := fileAttrSeam.Fchown(fd, svcUID, svcGID); err != nil {
		return fmt.Errorf("chown %s: %w", name, err)
	}
	return nil
}

// keystoreFstatSeam is the fstat install judges a log by once it set its
// flag: unix.Fstat. A non-root test, whose fake attribute writer neither
// chowns nor flags, reports what root's calls would have left.
var keystoreFstatSeam = unix.Fstat

// keystoreGate is install's hold on keystore-logs/ and keystore-staging/.
type keystoreGate struct {
	dfd, lfd, sfd int
	rootUID       int
	// opened records that the gate stands open (0755) as install leaves it.
	opened bool
}

// openKeystoreGate creates keystore-logs/ (root's 0755) or keeps the one
// there, and opens and judges it: a directory of rootUID at 0755, or at
// 0700 (a gate an install stopped with closed), with no flag and no ACL.
func openKeystoreGate(dfd, rootUID int) (*keystoreGate, error) {
	g := &keystoreGate{dfd: dfd, lfd: -1, sfd: -1, rootUID: rootUID}
	var err error
	if g.lfd, err = openRootDir(dfd, keystore.LogsDirName, keystoreLogsDirMode, rootUID, keystoreLogsDirMode, keystoreGateMode); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(g.lfd, &st); err != nil {
		g.close()
		return nil, fmt.Errorf("stat %s: %w", keystore.LogsDirName, err)
	}
	g.opened = st.Mode&0o7777 == keystoreLogsDirMode
	return g, nil
}

// openRootDir creates name under dfd at mode, or keeps the directory
// there, and opens it O_DIRECTORY|O_NOFOLLOW and judges it: rootUID's, at
// one of modes, with no flag and no ACL.
func openRootDir(dfd int, name string, mode uint32, rootUID int, modes ...uint32) (int, error) {
	if err := unix.Mkdirat(dfd, name, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("create %s: %w", name, err)
	}
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int64(st.Uid) != int64(rootUID) || !slices.Contains(modes, uint32(st.Mode&0o7777)) || st.Flags != 0 {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("%s is not root's directory at its mode, with no flag: %w", name, errKeystoreFileUntrusted)
	}
	if err := keystore.JudgeDirFlagsACL(fd); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("%s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	return fd, nil
}

// close releases the directory descriptors, and removes keystore-staging/
// when empty.
func (g *keystoreGate) close() {
	if g.sfd >= 0 {
		_ = unix.Close(g.sfd)                                                // read-only
		_ = unix.Unlinkat(g.dfd, keystore.StagingDirName, unix.AT_REMOVEDIR) // a staging directory left is reused
	}
	if g.lfd >= 0 {
		_ = unix.Close(g.lfd) // read-only
	}
}

// staging opens keystore-staging/, root's 0700, creating it when missing.
func (g *keystoreGate) staging() (int, error) {
	if g.sfd >= 0 {
		return g.sfd, nil
	}
	fd, err := openRootDir(g.dfd, keystore.StagingDirName, keystoreStagingDirMode, g.rootUID, keystoreStagingDirMode)
	if err != nil {
		return -1, err
	}
	g.sfd = fd
	return fd, nil
}

// setGate sets keystore-logs/ to mode: 0700 closes it, 0755 opens it.
func (g *keystoreGate) setGate(mode uint32) error {
	if err := fileAttrSeam.Fchmod(g.lfd, mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", keystore.LogsDirName, mode, err)
	}
	g.opened = mode == keystoreLogsDirMode
	return nil
}

// finish fsyncs the directories and opens the gate when it is closed.
func (g *keystoreGate) finish() error {
	if err := unix.Fsync(g.lfd); err != nil {
		return fmt.Errorf("fsync %s: %w", keystore.LogsDirName, err)
	}
	if err := unix.Fsync(g.dfd); err != nil {
		return fmt.Errorf("fsync the data root: %w", err)
	}
	if g.opened {
		return nil
	}
	return g.setGate(keystoreLogsDirMode)
}

// ensureLog creates the log name in keystore-logs/, or finishes or keeps
// the one there (ensureKeystoreFiles).
func (g *keystoreGate) ensureLog(name string, svcUID, svcGID int) error {
	var st unix.Stat_t
	err := unix.Fstatat(g.lfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return g.keepLog(name, svcUID)
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("look for %s: %w", name, err)
	}
	if name == keystore.UserFloorLogName {
		scopes := filepath.Join(sandbox.ServerSubdir, keystoreKeystoreSubdir, keystore.UserScopesDirName)
		if err := unix.Fstatat(g.dfd, scopes, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return errKeystoreFloorWithScopes
		} else if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("look for the user scopes: %w", err)
		}
	}
	sfd, err := g.staging()
	if err != nil {
		return err
	}
	if err := removeStaged(sfd, name, g.rootUID, svcUID); err != nil {
		return err
	}
	fd, err := unix.Openat(sfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, keystoreLogMode)
	if err != nil {
		return fmt.Errorf("create %s in %s: %w", name, keystore.StagingDirName, err)
	}
	defer func() { _ = unix.Close(fd) }() // nothing was written
	// The umask may have narrowed the mode; it is set on the descriptor.
	if err := fileAttrSeam.Fchmod(fd, keystoreLogMode); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if err := fileAttrSeam.Fchown(fd, svcUID, svcGID); err != nil {
		return fmt.Errorf("chown %s: %w", name, err)
	}
	if err := g.setGate(keystoreGateMode); err != nil {
		return err
	}
	if err := unix.RenameatxNp(sfd, name, g.lfd, name, unix.RENAME_EXCL); err != nil {
		return fmt.Errorf("rename %s into %s: %w", name, keystore.LogsDirName, err)
	}
	if err := flagAndJudge(fd, name, svcUID); err != nil {
		return err
	}
	if err := unix.Fsync(g.lfd); err != nil {
		return fmt.Errorf("fsync %s: %w", keystore.LogsDirName, err)
	}
	return g.setGate(keystoreLogsDirMode)
}

// keepLog judges the log name already in keystore-logs/: one that passes
// the keystore's judge is left alone; the service user's 0600 log with no
// flag, found behind a closed gate, is flagged and judged; anything else is
// refused.
func (g *keystoreGate) keepLog(name string, svcUID int) error {
	fd, err := unix.Openat(g.lfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	defer func() { _ = unix.Close(fd) }() // read-only
	var st unix.Stat_t
	if err := keystoreFstatSeam(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG, st.Nlink != 1, st.Mode&0o7777 != keystoreLogMode:
		return fmt.Errorf("%s is not a 0600 regular file with one link: %w", name, errKeystoreFileUntrusted)
	case int64(st.Uid) != int64(svcUID):
		return fmt.Errorf("%s is owned by uid %d, not the service user: %w", name, st.Uid, errKeystoreFileUntrusted)
	case st.Flags == unix.SF_APPEND:
		return judgeLogACL(fd, name)
	case st.Flags == 0 && !g.opened:
		return flagAndJudge(fd, name, svcUID)
	case st.Flags == 0:
		return fmt.Errorf("%s is the service user's and its SF_APPEND flag is clear, so it could have been rewritten: %w", name, errKeystoreFileUntrusted)
	}
	return fmt.Errorf("%s carries a file flag beside SF_APPEND: %w", name, errKeystoreFileUntrusted)
}

// flagAndJudge sets SF_APPEND on the log open at fd and judges it on the
// descriptor: the service user's, 0600, one link, flags exactly SF_APPEND,
// no ACL.
func flagAndJudge(fd int, name string, svcUID int) error {
	if err := fileAttrSeam.Fchflags(fd, unix.SF_APPEND); err != nil {
		return fmt.Errorf("set SF_APPEND on %s: %w", name, err)
	}
	var st unix.Stat_t
	if err := keystoreFstatSeam(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0o7777 != keystoreLogMode || int64(st.Uid) != int64(svcUID) || st.Flags != unix.SF_APPEND {
		return fmt.Errorf("%s is not the service user's 0600 log with one link and SF_APPEND alone once flagged: %w", name, errKeystoreFileUntrusted)
	}
	return judgeLogACL(fd, name)
}

// judgeLogACL refuses the log open at fd when it carries an extended ACL
// (keystore.JudgeDirFlagsACL reads it, and the flag beside SF_APPEND).
func judgeLogACL(fd int, name string) error {
	if err := keystore.JudgeDirFlagsACL(fd); err != nil {
		return fmt.Errorf("%s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	return nil
}

// removeStaged removes a log a stopped install left at name in
// keystore-staging/, which no other user can reach: a regular file with
// one link, root's or the service user's, unflagged. A missing name is fine.
func removeStaged(sfd int, name string, rootUID, svcUID int) error {
	var st unix.Stat_t
	err := unix.Fstatat(sfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look for %s in %s: %w", name, keystore.StagingDirName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Flags != 0 || (int64(st.Uid) != int64(rootUID) && int64(st.Uid) != int64(svcUID)) {
		return fmt.Errorf("%s in %s is not an unflagged regular file with one link: %w", name, keystore.StagingDirName, errKeystoreFileUntrusted)
	}
	if err := unix.Unlinkat(sfd, name, 0); err != nil {
		return fmt.Errorf("remove %s from %s: %w", name, keystore.StagingDirName, err)
	}
	return nil
}
