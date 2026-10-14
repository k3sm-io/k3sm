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
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxStagedTokenBytes bounds the staged token read. A join token is well under
// a kilobyte; anything this large is not one.
const maxStagedTokenBytes = 64 << 10

// DarwinStagingFS is the real StagingFS: lstat, a non-following walk, an
// O_NOFOLLOW token read, unlink, and the version stamped into a k3sm binary.
type DarwinStagingFS struct{}

// NewDarwinStagingFS returns the real StagingFS.
func NewDarwinStagingFS() DarwinStagingFS { return DarwinStagingFS{} }

// stagedEntryOf converts an lstat or fstat result.
func stagedEntryOf(path string, fi fs.FileInfo) (StagedEntry, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return StagedEntry{}, fmt.Errorf("stat %s: no ownership information", path)
	}
	return StagedEntry{
		Path:  path,
		Mode:  fi.Mode(),
		UID:   st.Uid,
		GID:   st.Gid,
		Dev:   uint64(st.Dev),
		Nlink: uint64(st.Nlink),
	}, nil
}

// Lstat describes path without following a symlink.
func (DarwinStagingFS) Lstat(path string) (StagedEntry, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return StagedEntry{}, err
	}
	return stagedEntryOf(path, fi)
}

// WalkNoFollow describes every entry beneath dir. filepath.WalkDir never
// follows a symlink: a link is reported as itself and not descended into.
func (DarwinStagingFS) WalkNoFollow(dir string) ([]StagedEntry, error) {
	var out []StagedEntry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		e, err := stagedEntryOf(path, fi)
		if err != nil {
			return err
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReadTokenFile opens path with O_NOFOLLOW (a symlink as the last component is
// refused by the kernel) and O_NONBLOCK (a planted fifo cannot park the
// install), judges the open descriptor, and reads at most
// maxStagedTokenBytes. The facts and the bytes come from one descriptor.
func (DarwinStagingFS) ReadTokenFile(path string) ([]byte, StagedEntry, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, StagedEntry{}, fmt.Errorf("open %s: %w", path, ErrNotRegularFile)
		}
		return nil, StagedEntry{}, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }() // read-only; nothing to flush
	fi, err := f.Stat()
	if err != nil {
		return nil, StagedEntry{}, err
	}
	e, err := stagedEntryOf(path, fi)
	if err != nil {
		return nil, StagedEntry{}, err
	}
	if !fi.Mode().IsRegular() {
		return nil, e, fmt.Errorf("open %s: %w", path, ErrNotRegularFile)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxStagedTokenBytes+1))
	if err != nil {
		return nil, e, fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) > maxStagedTokenBytes {
		return nil, e, fmt.Errorf("read %s: larger than %d bytes, so it is not a join token", path, maxStagedTokenBytes)
	}
	return raw, e, nil
}

// RemoveFile unlinks path. unlink(2) removes a symlink itself, never its
// target. Absent is success.
func (DarwinStagingFS) RemoveFile(path string) error {
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return &fs.PathError{Op: "unlink", Path: path, Err: err}
	}
	return nil
}

// BinaryVersion reads the release version stamped into the k3sm binary at
// path from its embedded build information, without running it.
func (DarwinStagingFS) BinaryVersion(path string) (string, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the build information of %s: %w", path, err)
	}
	return stampedVersion(bi), nil
}

// CodesignTeamID is the real TeamIDReader. It verifies the signature with
// `codesign --verify --strict` and reads the TeamIdentifier from `codesign
// -dv --verbose=2`. It never signs anything.
type CodesignTeamID struct{}

// TeamID returns path's signing Team ID.
func (CodesignTeamID) TeamID(path string) (string, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}
	var verifyErr bytes.Buffer
	verify := exec.Command("/usr/bin/codesign", "--verify", "--strict", path)
	verify.Stderr = &verifyErr
	if err := verify.Run(); err != nil {
		if strings.Contains(verifyErr.String(), "not signed at all") {
			return "", fmt.Errorf("%s: %w", path, ErrNoTeamID)
		}
		return "", fmt.Errorf("codesign --verify --strict %s: %w: %s", path, err, strings.TrimSpace(verifyErr.String()))
	}
	var out bytes.Buffer
	display := exec.Command("/usr/bin/codesign", "-dv", "--verbose=2", path)
	display.Stderr = &out
	display.Stdout = &out
	if err := display.Run(); err != nil {
		return "", fmt.Errorf("codesign -dv %s: %w: %s", path, err, strings.TrimSpace(out.String()))
	}
	id, err := parseTeamIdentifier(out.String())
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return id, nil
}
