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

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The keystore's append-only files (docs/design/keystore.md § "The user-scope
// floor", flag variant, which the K0 spike picked): keystore-run/ and the two
// logs, the user-scope floor and the audit log, in the root-owned data root.
// The logs are the service user's, mode 0600, flagged SF_APPEND, which only
// root can clear; the run directory is the service user's, 0700.

// keystoreLogMode is both logs' mode; keystoreRunDirMode the run directory's.
const (
	keystoreLogMode    = 0o600
	keystoreRunDirMode = 0o700
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

// ensureKeystoreFiles creates keystore-run/ and both append-only logs in
// dataRoot, for the service user svcUID:svcGID, and keeps what an earlier
// install made. rootUID is the data root's owner: 0 in production; only a
// non-root test passes its own uid. Every step goes through one descriptor
// on the data root, opened O_DIRECTORY|O_NOFOLLOW and judged on fstat.
//
// A new log is made in the order that leaves no window for the service user:
// created root-owned 0600 with O_CREAT|O_EXCL|O_NOFOLLOW, nothing written,
// SF_APPEND set on the held descriptor, and only then fchown'd to the
// service user on that same descriptor. A log that is root's (an install
// that stopped between those steps) is finished the same way; a log that is
// the service user's must already be flagged, since while its flag was clear
// it could have been rewritten. Anything else is refused and left as found.
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
	if err := ensureKeystoreRunDir(dfd, svcUID, svcGID, rootUID); err != nil {
		return err
	}
	for _, name := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		if err := ensureKeystoreLog(dfd, name, svcUID, svcGID, rootUID); err != nil {
			return err
		}
	}
	return nil
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

// ensureKeystoreLog creates the log name under dfd, or finishes or keeps the
// one there (ensureKeystoreFiles).
func ensureKeystoreLog(dfd int, name string, svcUID, svcGID, rootUID int) error {
	if name == keystore.UserFloorLogName {
		var st unix.Stat_t
		err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			scopes := filepath.Join(sandbox.ServerSubdir, keystoreKeystoreSubdir, keystore.UserScopesDirName)
			if err := unix.Fstatat(dfd, scopes, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
				return errKeystoreFloorWithScopes
			} else if !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("look for the user scopes: %w", err)
			}
		}
	}
	fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, keystoreLogMode)
	switch {
	case err == nil:
		defer func() { _ = unix.Close(fd) }() // nothing was written
		// The umask may have narrowed the mode; it is set on the descriptor.
		if err := fileAttrSeam.Fchmod(fd, keystoreLogMode); err != nil {
			return fmt.Errorf("chmod %s: %w", name, err)
		}
		return flagThenChown(fd, name, svcUID, svcGID)
	case !errors.Is(err, unix.EEXIST):
		return fmt.Errorf("create %s: %w", name, err)
	}
	fd, err = unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w: %w", name, err, errKeystoreFileUntrusted)
	}
	defer func() { _ = unix.Close(fd) }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG, st.Nlink != 1, st.Mode&0o7777 != keystoreLogMode:
		return fmt.Errorf("%s is not a 0600 regular file with one link: %w", name, errKeystoreFileUntrusted)
	case st.Flags&^uint32(unix.SF_APPEND) != 0:
		return fmt.Errorf("%s carries a file flag beside SF_APPEND: %w", name, errKeystoreFileUntrusted)
	case int64(st.Uid) == int64(svcUID) && st.Flags&unix.SF_APPEND != 0:
		return nil
	case int64(st.Uid) == int64(rootUID):
		return flagThenChown(fd, name, svcUID, svcGID)
	case int64(st.Uid) == int64(svcUID):
		return fmt.Errorf("%s is the service user's and its SF_APPEND flag is clear, so it could have been rewritten: %w", name, errKeystoreFileUntrusted)
	}
	return fmt.Errorf("%s is owned by uid %d: %w", name, st.Uid, errKeystoreFileUntrusted)
}

// flagThenChown sets SF_APPEND on the root-owned log open at fd and only
// then hands it to the service user, on the same descriptor.
func flagThenChown(fd int, name string, svcUID, svcGID int) error {
	if err := fileAttrSeam.Fchflags(fd, unix.SF_APPEND); err != nil {
		return fmt.Errorf("set SF_APPEND on %s: %w", name, err)
	}
	if err := fileAttrSeam.Fchown(fd, svcUID, svcGID); err != nil {
		return fmt.Errorf("chown %s: %w", name, err)
	}
	return nil
}
