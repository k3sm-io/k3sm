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

package boundedread

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// ErrRefused marks a file ReadFileBounded or ReadFileBoundedFollow would not
// read: a symlink (ReadFileBounded only), a FIFO, device, socket, directory or
// other non-regular file, or a file over the caller's bound. It is deliberately
// neither fs.ErrNotExist nor fs.ErrPermission, so a caller that falls back on
// either of those does not mistake a planted file for an absent or
// root-only one.
var ErrRefused = errors.New("file refused")

// ReadFileBounded reads the whole regular file at path, refusing one larger
// than max bytes. The file is opened O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC, typed and
// sized by fstat on that one descriptor, and read from it, so nothing can be
// swapped between the check and the read; O_NONBLOCK keeps a planted FIFO from
// blocking the open, and the regular-file check keeps it from blocking the
// read.
//
// The limit: O_NOFOLLOW covers the final path component only. A symlinked
// parent directory is followed, so a parent directory the service user owns
// can still be swapped for a link to elsewhere; the ownership of the
// directories above path is the control for that, not this function.
//
// A missing file returns an error satisfying errors.Is(err, fs.ErrNotExist),
// as os.ReadFile does, and an open denied by permissions one satisfying
// errors.Is(err, fs.ErrPermission). A symlink at path, a non-regular file, or
// one over max (at fstat, or grown past it before the read finished) returns
// an error satisfying errors.Is(err, ErrRefused).
func ReadFileBounded(path string, max int64) ([]byte, error) {
	return read(path, max, unix.O_NOFOLLOW)
}

// ReadFileBoundedFollow is ReadFileBounded for a path whose final component may
// legitimately be a symlink (an operator-chosen file such as the admin
// kubeconfig, which the operator may link to wherever they keep it). It follows
// that link, and keeps everything else: the non-blocking open, the
// regular-file check and the bound, both applied to the descriptor actually
// read, so the link can only lead to a regular file within max bytes.
func ReadFileBoundedFollow(path string, max int64) ([]byte, error) {
	return read(path, max, 0)
}

func read(path string, max int64, extra int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|extra, 0)
	if err != nil {
		if extra&unix.O_NOFOLLOW != 0 && errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s is a symlink: %w", path, ErrRefused)
		}
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file (mode %#o): %w", path, st.Mode&unix.S_IFMT, ErrRefused)
	}
	if st.Size > max {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte bound: %w", path, st.Size, max, ErrRefused)
	}
	// Read one byte past the bound, so a file that grew after the fstat is
	// refused rather than silently truncated.
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s grew past the %d-byte bound: %w", path, max, ErrRefused)
	}
	return b, nil
}
