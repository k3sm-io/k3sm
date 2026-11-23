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
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The keystore's append-only files (docs/design/keystore.md § "The user-scope
// floor", flag variant, which the K0 spike picked): keystore-run/ in the
// root-owned data root, and the two logs, the user-scope floor and the audit
// log, each in its own root-owned directory in keystore-logs/ (all root's
// 0755). The logs are the service user's, mode 0600, flagged SF_APPEND,
// which only root can clear; the run directory is the service user's, 0700.

// keystoreLogMode is both logs' mode; keystoreRunDirMode the run
// directory's; keystoreLogsDirMode keystore-logs/'s and each log
// directory's; keystoreStagingDirMode keystore-staging/'s.
const (
	keystoreLogMode        = 0o600
	keystoreRunDirMode     = 0o700
	keystoreLogsDirMode    = 0o755
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
	// errKeystoreMaintenance is the keystore step run while a maintenance
	// verb runs: the marker stands and keystore-lock is held.
	errKeystoreMaintenance = errors.New("a keystore maintenance verb is running (keystore-maintenance exists and keystore-lock is held); install changes nothing while it runs: rerun install once it is done")
	// errKeystoreFloorWithScopes is a missing floor while user scopes exist:
	// a new, empty floor would lower every scope's floor.
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
// (keystore.JudgeDirFlagsACL).
//
// It holds keystore-lock, taken without waiting, for its whole run: held
// by another process while the maintenance marker stands, a maintenance
// verb runs, and install refuses, changing nothing. Holding it, install
// cleans keystore-staging/ (keystore.CleanStagingDir: nothing in it is
// trusted or read), and a marker found then is a stale one, which it
// removes once the live set is ensured.
//
// A missing log is built with its directory in keystore-staging/, as the
// maintenance verbs build one (buildLogDir): the log created root's 0600
// with O_CREAT|O_EXCL|O_NOFOLLOW, handed to the service user, set to 0600
// and flagged SF_APPEND on its descriptor and judged, so it is flagged
// before it is reachable; the directory is then placed in keystore-logs/
// with renameatx_np(RENAME_EXCL). A log that passes the keystore's judge
// is left alone; anything else, an unflagged log among them, is refused
// and left as found.
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
	unlock, err := lockMaintenanceFree(dfd)
	if err != nil {
		return err
	}
	defer unlock()
	stale := false
	if err := unix.Fstatat(dfd, keystore.MaintenanceMarkerName, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		stale = true
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("look for %s: %w", keystore.MaintenanceMarkerName, err)
	}
	for _, name := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return errLogOldLocation(name)
		}
	}
	if err := ensureKeystoreRunDir(dfd, svcUID, svcGID, rootUID); err != nil {
		return err
	}
	g, err := openKeystoreLogs(dfd, rootUID)
	if err != nil {
		return err
	}
	defer g.close()
	for _, name := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		if err := unix.Fstatat(g.lfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return errLogOldLocation(name)
		}
	}
	for _, name := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		if err := g.ensureLog(name, svcUID, svcGID); err != nil {
			return err
		}
	}
	if err := g.finish(); err != nil {
		return err
	}
	if stale {
		// A committed run the marker records was not reported: report it
		// and audit it before the marker goes.
		if r := keystore.EarlierRunAtInstall(dfd, g.lfd, rootUID, time.Now()); r != nil {
			fmt.Fprintf(keystoreStderr, "install: %s\n", r)
		}
		if err := unix.Unlinkat(dfd, keystore.MaintenanceMarkerName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove the stale %s: %w", keystore.MaintenanceMarkerName, err)
		}
		if err := unix.Fsync(dfd); err != nil {
			return fmt.Errorf("fsync the data root: %w", err)
		}
	}
	return nil
}

// errLogOldLocation is a log at a location no release keeps one at: the
// top of the data root, or directly in keystore-logs/.
func errLogOldLocation(name string) error {
	return fmt.Errorf("%s is at a location this build keeps no log at (the log lives in %s/%s/): clear its flag and remove it (sudo chflags nosappnd, then sudo rm), then rerun sudo k3sm install: %w", name, keystore.LogsDirName, keystore.LogDirOf(name), errKeystoreFileUntrusted)
}

// lockMaintenanceFree takes keystore-lock in the data root dfd without
// waiting, when it exists, and returns its release: held by another
// process, a maintenance verb runs (errKeystoreMaintenance). A missing
// lock file is a data root no verb has run in.
func lockMaintenanceFree(dfd int) (func(), error) {
	fd, err := unix.Openat(dfd, keystore.FloorLockName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return func() {}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w: %w", keystore.FloorLockName, err, errKeystoreFileUntrusted)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd) // read-only
		return nil, fmt.Errorf("%s is not a regular file: %w", keystore.FloorLockName, errKeystoreFileUntrusted)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd) // read-only
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errKeystoreMaintenance
		}
		return nil, fmt.Errorf("lock %s: %w", keystore.FloorLockName, err)
	}
	return func() { _ = unix.Close(fd) }, nil // closing releases the flock
}

// ensureKeystoreRunDir creates keystore-run/ under dfd and hands it to the
// service user at keystoreRunDirMode, on its own descriptor: a user flag
// on it (the service user can set one) is cleared first, and the chmod and
// chown are made only when the mode or owner is not already right.
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
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || (int64(st.Uid) != int64(rootUID) && int64(st.Uid) != int64(svcUID)) {
		return fmt.Errorf("%s is not a directory, or is owned by uid %d: %w", name, st.Uid, errKeystoreFileUntrusted)
	}
	// The service user owns the directory, so it can set a user flag on it
	// (uchg, uappnd), which makes root's fchmod and fchown fail: clear the
	// user-settable flags first, on the judged descriptor.
	if fl := st.Flags & unix.UF_SETTABLE; fl != 0 {
		if err := fileAttrSeam.Fchflags(fd, int(st.Flags&^unix.UF_SETTABLE)); err != nil {
			return fmt.Errorf("clear the user flags %#x of %s: %w", fl, name, err)
		}
	}
	if st.Mode&0o7777 != keystoreRunDirMode {
		if err := fileAttrSeam.Fchmod(fd, keystoreRunDirMode); err != nil {
			return fmt.Errorf("chmod %s: %w", name, err)
		}
	}
	if int64(st.Uid) != int64(svcUID) || int64(st.Gid) != int64(svcGID) {
		if err := fileAttrSeam.Fchown(fd, svcUID, svcGID); err != nil {
			return fmt.Errorf("chown %s: %w", name, err)
		}
	}
	return nil
}

// keystoreStderr is where install prints a committed maintenance run it
// finds unreported in the marker it removes.
var keystoreStderr io.Writer = os.Stderr

// keystoreFstatSeam is the fstat install judges a log by once it set its
// flag: unix.Fstat. A non-root test, whose fake attribute writer neither
// chowns nor flags, reports what root's calls would have left.
var keystoreFstatSeam = unix.Fstat

// keystoreLogs is install's hold on keystore-logs/ and keystore-staging/.
type keystoreLogs struct {
	dfd, lfd, sfd int
	rootUID       int
}

// openKeystoreLogs creates keystore-logs/ (root's 0755) or keeps the one
// there, and opens and judges it: a directory of rootUID at 0755, with no
// flag and no ACL. It opens keystore-staging/ and cleans it.
func openKeystoreLogs(dfd, rootUID int) (*keystoreLogs, error) {
	g := &keystoreLogs{dfd: dfd, lfd: -1, sfd: -1, rootUID: rootUID}
	var err error
	if g.lfd, err = openRootDir(dfd, keystore.LogsDirName, keystoreLogsDirMode, rootUID, keystoreLogsDirMode); err != nil {
		return nil, err
	}
	if g.sfd, err = openRootDir(dfd, keystore.StagingDirName, keystoreStagingDirMode, rootUID, keystoreStagingDirMode); err != nil {
		g.close()
		return nil, err
	}
	if err := keystore.CleanStagingDir(g.sfd, fileAttrSeam); err != nil {
		g.close()
		return nil, fmt.Errorf("clean %s: %w", keystore.StagingDirName, err)
	}
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
	if err := judgeRootDir(fd, name, rootUID, modes...); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, err
	}
	return fd, nil
}

// judgeRootDir refuses the directory name open at fd unless it is
// rootUID's, at one of modes, with no flag and no ACL.
func judgeRootDir(fd int, name string, rootUID int, modes ...uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int64(st.Uid) != int64(rootUID) || !slices.Contains(modes, uint32(st.Mode&0o7777)) || st.Flags != 0 {
		return fmt.Errorf("%s is not root's directory at its mode, with no flag: %w", name, errKeystoreFileUntrusted)
	}
	if err := keystore.JudgeDirFlagsACL(fd); err != nil {
		return fmt.Errorf("%s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	return nil
}

// close releases the directory descriptors, and removes keystore-staging/
// when empty.
func (g *keystoreLogs) close() {
	if g.sfd >= 0 {
		_ = unix.Close(g.sfd)                                                // read-only
		_ = unix.Unlinkat(g.dfd, keystore.StagingDirName, unix.AT_REMOVEDIR) // a staging directory left is cleaned and reused
	}
	if g.lfd >= 0 {
		_ = unix.Close(g.lfd) // read-only
	}
}

// finish fsyncs keystore-logs/ and the data root.
func (g *keystoreLogs) finish() error {
	if err := unix.Fsync(g.lfd); err != nil {
		return fmt.Errorf("fsync %s: %w", keystore.LogsDirName, err)
	}
	if err := unix.Fsync(g.dfd); err != nil {
		return fmt.Errorf("fsync the data root: %w", err)
	}
	return nil
}

// ensureLog keeps the log name's directory in keystore-logs/ when its log
// passes the judge, or builds and places it when it is missing
// (ensureKeystoreFiles).
func (g *keystoreLogs) ensureLog(name string, svcUID, svcGID int) error {
	dir := keystore.LogDirOf(name)
	var st unix.Stat_t
	err := unix.Fstatat(g.lfd, dir, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return g.keepLog(name, svcUID)
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("look for %s/%s: %w", keystore.LogsDirName, dir, err)
	}
	if name == keystore.UserFloorLogName {
		scopes := filepath.Join(sandbox.ServerSubdir, keystoreKeystoreSubdir, keystore.UserScopesDirName)
		if err := unix.Fstatat(g.dfd, scopes, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return errKeystoreFloorWithScopes
		} else if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("look for the user scopes: %w", err)
		}
	}
	nd := dir + ".new"
	if err := beforeLogStep("create"); err != nil {
		return fmt.Errorf("before creating %s: %w", name, err)
	}
	if err := g.buildLogDir(nd, name, svcUID, svcGID); err != nil {
		_ = keystore.CleanStagingDir(g.sfd, fileAttrSeam) // the next install cleans what this leaves
		return err
	}
	if err := beforeLogStep("rename"); err != nil {
		return fmt.Errorf("before placing %s: %w", dir, err)
	}
	if err := unix.RenameatxNp(g.sfd, nd, g.lfd, dir, unix.RENAME_EXCL); err != nil {
		_ = keystore.CleanStagingDir(g.sfd, fileAttrSeam) // as above
		return fmt.Errorf("place %s in %s: %w", dir, keystore.LogsDirName, err)
	}
	if err := beforeLogStep("fsync"); err != nil {
		return fmt.Errorf("before fsyncing %s: %w", keystore.LogsDirName, err)
	}
	if err := unix.Fsync(g.lfd); err != nil {
		return fmt.Errorf("fsync %s: %w", keystore.LogsDirName, err)
	}
	return nil
}

// buildLogDir builds the directory nd in keystore-staging/ holding the
// new, empty log name: the directory created and opened
// O_DIRECTORY|O_NOFOLLOW and judged; the log created root's 0600 with
// O_CREAT|O_EXCL|O_NOFOLLOW, handed to the service user, set to 0600 and
// flagged SF_APPEND on its descriptor and judged (flagAndJudge); the
// directory set to root's 0755 and fsynced.
func (g *keystoreLogs) buildLogDir(nd, name string, svcUID, svcGID int) error {
	if err := unix.Mkdirat(g.sfd, nd, keystoreStagingDirMode); err != nil {
		return fmt.Errorf("create %s in %s: %w", nd, keystore.StagingDirName, err)
	}
	dfd, err := openRootDir(g.sfd, nd, keystoreStagingDirMode, g.rootUID, keystoreStagingDirMode)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }() // fsynced below
	fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, keystoreLogMode)
	if err != nil {
		return fmt.Errorf("create %s in %s: %w", name, keystore.StagingDirName, err)
	}
	defer func() { _ = unix.Close(fd) }() // nothing was written
	if err := fileAttrSeam.Fchown(fd, svcUID, svcGID); err != nil {
		return fmt.Errorf("chown %s: %w", name, err)
	}
	// The umask may have narrowed the mode; it is set on the descriptor.
	if err := fileAttrSeam.Fchmod(fd, keystoreLogMode); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if err := flagAndJudge(fd, name, svcUID); err != nil {
		return err
	}
	if err := unix.Fchmod(dfd, keystoreLogsDirMode); err != nil {
		return fmt.Errorf("chmod %s: %w", nd, err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("fsync %s: %w", nd, err)
	}
	return nil
}

// keepLog judges the log name's directory and the log in it, already in
// keystore-logs/: a log that passes the keystore's judge (the service
// user's 0600 regular file with one link, flags exactly SF_APPEND, no ACL,
// in a root 0755 directory with no flag and no ACL) is left alone; anything
// else, a missing or unflagged log among them, is refused and left as
// found.
func (g *keystoreLogs) keepLog(name string, svcUID int) error {
	dir := keystore.LogDirOf(name)
	ld, err := openExistingRootDir(g.lfd, dir, g.rootUID, keystoreLogsDirMode)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(ld) }() // read-only
	fd, err := unix.Openat(ld, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s/%s: %w: %w", dir, name, err, errKeystoreFileUntrusted)
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
	case st.Flags == 0:
		return fmt.Errorf("%s is the service user's and its SF_APPEND flag is clear, so it could have been rewritten: %w", name, errKeystoreFileUntrusted)
	}
	return fmt.Errorf("%s carries a file flag beside SF_APPEND: %w", name, errKeystoreFileUntrusted)
}

// openExistingRootDir opens the existing directory name under pfd
// O_DIRECTORY|O_NOFOLLOW and judges it: rootUID's, at mode, with no flag
// and no ACL.
func openExistingRootDir(pfd int, name string, rootUID int, mode uint32) (int, error) {
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	if err := judgeRootDir(fd, name, rootUID, mode); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, err
	}
	return fd, nil
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
