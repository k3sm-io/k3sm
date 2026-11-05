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
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/binsign"
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

// BinaryVersion is the release version of the k3sm binary at path (the
// installed one, root-owned under the install dir), as it reports itself
// (readBinaryVersion): it runs `version --short` with a minimal environment
// and falls back to the build information only when that run gives no
// answer.
//
// It runs the binary as the installing (root) user, so it first refuses
// anything that is not a root-owned regular file nobody else can write: the
// path is opened O_NOFOLLOW (a symlink is refused), fstat'd, and must be a
// regular file owned by uid 0 with no group or other write bit.
func (DarwinStagingFS) BinaryVersion(path string) (string, error) {
	return binaryVersionOwnedBy(path, 0)
}

// binaryVersionOwnedBy is BinaryVersion with the required owner uid a
// parameter, so tests can use files they own.
//
// Accepted residue: the binary is executed by path after the Fstat, so a swap
// between the two is possible; it needs write access to the root-owned
// install directory, which already confers everything this check protects.
// The signing checks that precede it are path-based in the same way.
func binaryVersionOwnedBy(path string, uid uint32) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return "", fmt.Errorf("%s is a symbolic link; refusing to run it", path)
		}
		return "", err
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return "", fmt.Errorf("%s is not a regular file; refusing to run it", path)
	case st.Uid != uid:
		return "", fmt.Errorf("%s is owned by uid %d, not %d; refusing to run it", path, st.Uid, uid)
	case st.Mode&(unix.S_IWGRP|unix.S_IWOTH) != 0:
		return "", fmt.Errorf("%s is group or world writable; refusing to run it", path)
	}
	return readBinaryVersion(path, execVersion, buildinfo.ReadFile)
}

// execVersion is the production versionRunner: the binary at path run as
// `version --short` in /, with only a system PATH in its environment, its
// stderr discarded and its stdout capped at maxVersionOutput.
func execVersion(ctx context.Context, path string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, "version", "--short")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out := &cappedBuffer{max: maxVersionOutput}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 2 * time.Second
	// Its own process group, killed whole on timeout and after the run, so a
	// binary that forks cannot outlive the bound.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	err := cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // reaps stragglers; ESRCH when none
	}
	if err != nil {
		return nil, fmt.Errorf("run %s version --short: %w", path, err)
	}
	if out.over {
		return nil, fmt.Errorf("%s version --short printed more than %d bytes", path, maxVersionOutput)
	}
	return out.buf.Bytes(), nil
}

// cappedBuffer keeps at most max bytes and records that more were written.
type cappedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// ResolveInstalled is resolveInstalledBinary over the real filesystem.
func (DarwinStagingFS) ResolveInstalled(path string) (string, error) {
	return resolveInstalledBinary(path, os.Lstat, filepath.EvalSymlinks)
}

// MachO reports whether the regular file at path starts with a Mach-O magic
// number (thin, either byte order, 32- or 64-bit) or a universal-binary one.
// It opens path with O_NOFOLLOW and reads four bytes. A file shorter than
// that is not a Mach-O.
func (DarwinStagingFS) MachO(path string) (bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }() // read-only; nothing to flush
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	return isMachOMagic(magic), nil
}

// CodesignTeamID is the real TeamIDReader, over internal/binsign's codesign
// inspector: TeamID reads a valid identity signature's Team ID, and
// DeveloperID checks the binary against binsign's Developer ID Application
// requirement. It never signs anything. The zero value is usable.
type CodesignTeamID struct {
	// Inspector runs codesign; the zero value runs the system tool by path.
	Inspector binsign.CodesignInspector
}

// TeamID returns path's signing Team ID.
func (c CodesignTeamID) TeamID(ctx context.Context, path string) (string, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}
	sig, err := c.Inspector.Inspect(ctx, path)
	if err != nil {
		return "", fmt.Errorf("inspect the signature of %s: %w", path, err)
	}
	if !sig.IdentitySigned() || sig.TeamID == "" {
		return "", fmt.Errorf("%s: %w", path, ErrNoTeamID)
	}
	if !binsign.ValidTeamID(sig.TeamID) {
		return "", fmt.Errorf("%s: codesign reported TeamIdentifier %q, which is not a Team ID", path, sig.TeamID)
	}
	return sig.TeamID, nil
}

// DeveloperID reports whether path verifies against the Developer ID
// Application requirement for teamID: an Apple-anchored chain through the
// Developer ID intermediate to a Developer ID Application leaf issued to that
// team. An Apple Development or Mac App Store signature from the same team
// fails it.
func (c CodesignTeamID) DeveloperID(ctx context.Context, path, teamID string) (bool, error) {
	req, err := binsign.DeveloperIDRequirement(teamID)
	if err != nil {
		return false, err
	}
	return c.Inspector.Satisfies(ctx, path, req)
}
