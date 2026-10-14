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

package podlogs

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrUnsafeLogFile is returned by OpenNoFollow for a path that is a symlink or
// anything other than a regular file.
var ErrUnsafeLogFile = errors.New("log file is not a regular file")

// OpenNoFollow opens path read-only WITHOUT following a symlink in its final
// component, and confirms on the opened descriptor (fstat, not a path lookup
// that could race a rename) that it is a regular file. It is the Opener for a
// read whose path was derived rather than reported by the runtime.
//
// O_NONBLOCK keeps the open itself from blocking on a FIFO planted at the path;
// it is cleared again once the descriptor is known to be a regular file.
func OpenNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafeLogFile, path)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s", ErrUnsafeLogFile, path)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "fcntl", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
