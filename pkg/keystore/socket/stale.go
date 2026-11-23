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

package socket

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrNotStaleSocket is a path the self-bind form will not unlink: anything
// but a socket owned by the service user.
var ErrNotStaleSocket = errors.New("keystore socket: not a stale service-user socket")

// UnlinkStaleSocket is the self-bind form's start step (docs/design/
// keystore.md, "Lifecycle"; the activated form never unlinks): it removes
// name, one element in dir, only when an lstat through dir's descriptor
// shows a socket owned by serviceUID. A symlink is never followed, and
// anything else at name is left in place, logged as a Warn and refused with
// ErrNotStaleSocket. A name that is absent is not an error.
func UnlinkStaleSocket(dir *os.File, name string, serviceUID uint32, log *slog.Logger) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return fmt.Errorf("socket directory descriptor: %w", err)
	}
	var uerr error
	if err := rc.Control(func(fd uintptr) {
		uerr = unlinkStale(dirNodes{fd: int(fd)}, name, serviceUID, log)
	}); err != nil {
		return fmt.Errorf("socket directory descriptor: %w", err)
	}
	return uerr
}

// nodes is what unlinkStale needs of the socket's directory.
type nodes interface {
	// lstat returns name's file type (its S_IFMT bits) and owner, without
	// following a symlink.
	lstat(name string) (typ, uid uint32, err error)
	unlink(name string) error
}

// dirNodes reads and unlinks through a held directory descriptor.
type dirNodes struct{ fd int }

func (d dirNodes) lstat(name string) (uint32, uint32, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, 0, err
	}
	return uint32(st.Mode) & unix.S_IFMT, st.Uid, nil
}

func (d dirNodes) unlink(name string) error { return unix.Unlinkat(d.fd, name, 0) }

// unlinkStale applies UnlinkStaleSocket's rule through n.
func unlinkStale(n nodes, name string, serviceUID uint32, log *slog.Logger) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return fmt.Errorf("keystore socket: %q is not one path element", name)
	}
	typ, uid, err := n.lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lstat %s: %w", name, err)
	}
	if typ != unix.S_IFSOCK || uid != serviceUID {
		log.Warn("keystore socket: refusing to unlink a path that is not a stale service-user socket",
			"name", name, "socket", typ == unix.S_IFSOCK, "uid", uid, "service_uid", serviceUID)
		return fmt.Errorf("%w: %s", ErrNotStaleSocket, name)
	}
	if err := n.unlink(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("unlink stale %s: %w", name, err)
	}
	return nil
}
