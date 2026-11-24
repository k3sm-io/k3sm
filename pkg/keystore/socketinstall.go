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

package keystore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/keystorepaths"
)

// sockDirMode is the socket directory's mode: root:wheel 0755, so no
// service-uid process can bind, unlink or replace a name in it
// (docs/design/keystore.md § "The socket's directory is root's").
const sockDirMode = 0o755

// installError is CheckSocketInstall's refusal: its text names what is
// wrong and no command, and it unwraps to the judge's own error.
type installError struct {
	text string
	err  error
}

func (e *installError) Error() string { return e.text }
func (e *installError) Unwrap() error { return e.err }

// CheckSocketInstall reports what install left wrong for the socket
// listener: the socket directory (keystorepaths.SockDir in the data root)
// must be a directory of the data root's owner and group (root:wheel),
// mode 0755, with no file flag and no extended ACL, judged on its
// descriptor through the judged data root; and each append-only log must
// pass the flag and owner check (CheckLogFlags). The error's text names
// what is wrong and carries no command: the caller adds the install hint.
func (s *FileStore) CheckSocketInstall(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkSockDir(); err != nil {
		return err
	}
	for _, name := range []string{userFloorLogName, auditLogName} {
		if err := s.checkLogFlag(ctx, name); err != nil {
			return &installError{text: logInstallText(name, err), err: err}
		}
	}
	return nil
}

// checkSockDir judges the socket directory.
func (s *FileStore) checkSockDir() error {
	dir := keystorepaths.SockDir
	bad := func(what string, err error) error {
		return &installError{text: "the socket directory " + dir + " " + what, err: err}
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return &installError{text: "the data root is not trusted", err: err}
	}
	defer func() { _ = unix.Close(dfd) }() // read-only directory descriptor
	fd, err := unix.Openat(dfd, dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return bad("is missing", fs.ErrNotExist)
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return bad("is not a directory", err)
	case err != nil:
		return bad("cannot be opened", err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only directory descriptor
	return JudgeSocketDir(fd, s.floorUID, s.floorGID)
}

// JudgeSocketDir judges the socket directory open at fd, as the server's
// start check does and as install does before it keeps one: a directory
// of uid in gid (root:wheel in production), mode 0755, with no file flag
// and no extended ACL. Its error's text names what is wrong and carries no
// command; install and the start check refuse with the same text.
func JudgeSocketDir(fd, uid, gid int) error {
	bad := func(what string, err error) error {
		return &installError{text: "the socket directory " + keystorepaths.SockDir + " " + what, err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return bad("cannot be read", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return bad("is not a directory", nil)
	case int64(st.Uid) != int64(uid) || int64(st.Gid) != int64(gid):
		return bad("is not owned by root:wheel", nil)
	case st.Mode&0o7777 != sockDirMode:
		return bad(fmt.Sprintf("is at mode %04o, not 0755", st.Mode&0o7777), nil)
	}
	fl, err := fdFlags(fd)
	if err != nil {
		return bad("has file flags that cannot be read", err)
	}
	if fl != 0 {
		return bad("carries a file flag", nil)
	}
	if err := judgeFlagsACL(fd, func(int) (uint32, error) { return fl, nil }); err != nil {
		return bad("carries an extended ACL, or its ACL cannot be read", err)
	}
	return nil
}

// logInstallText names what the log judge refused in name, with no
// command: the judge's own texts carry the remedy, which the caller of
// CheckSocketInstall gives instead.
func logInstallText(name string, err error) string {
	var linked logLinkedError
	switch {
	case errors.Is(err, errLogMissing):
		return "the append-only log " + name + " is missing"
	case errors.Is(err, errLogNotAppendOnly):
		return "the append-only log " + name + " is not flagged append-only"
	case errors.As(err, &linked):
		return "the append-only log " + name + " has more than one link"
	case errors.Is(err, errLogUntrusted):
		return "the append-only log " + name + ", its directory or the data root is not trusted (owner, mode, links, flags or ACL)"
	}
	return "the append-only log " + name + " cannot be checked"
}

// MaintenanceMarked reports whether anything stands at the maintenance
// marker's name (MaintenanceMarkerName) in the judged data root, read with
// fstatat, AT_SYMLINK_NOFOLLOW; a data root that cannot be judged is an
// error. The socket listener's supervisor polls it.
func (s *FileStore) MaintenanceMarked() (bool, error) { return s.maintenanceMarked() }
