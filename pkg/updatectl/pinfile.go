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

package updatectl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Every operation on the release pin runs relative to directory descriptors,
// never through a path a less privileged user could redirect. The server work
// dir belongs to the service user, which can rename or replace the pin
// directory inside it at any moment; so the work dir is opened once, the pin
// directory is opened relative to it without following a symlink and checked
// on the opened descriptor, and every later step (the chmod, the temp file,
// the rename, the unlink) acts on that descriptor. A swap after the check can
// then only move the directory root is writing into, never redirect root's
// write elsewhere, and the writer notices the move and fails.

// pinDirChecked is called after the writer has checked the pin directory and
// before it writes the pin: a test seam for swapping the directory there.
var pinDirChecked = func() {}

// maxClearDepth bounds how deep ClearReleasePin descends into an untrusted
// directory tree.
const maxClearDepth = 16

// openWorkDir opens workDir as a directory, without following it if it is a
// symlink. A missing work dir is an error wrapping fs.ErrNotExist.
func openWorkDir(workDir string) (int, error) {
	fd, err := unix.Open(workDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, fmt.Errorf("open the work dir %s: %w", workDir, fs.ErrNotExist)
	}
	if err != nil {
		return -1, fmt.Errorf("open the work dir %s: %w", workDir, err)
	}
	return fd, nil
}

// statProblem says why st cannot be trusted as the pin directory (wantDir) or
// the pin file: the wrong type (a symlink included), an owner other than
// owner, or a mode its group or others may write. Empty means trusted.
func statProblem(st *unix.Stat_t, owner uint32, wantDir bool) string {
	switch typ := st.Mode & unix.S_IFMT; {
	case typ == unix.S_IFLNK:
		return "a symlink"
	case wantDir && typ != unix.S_IFDIR:
		return "not a directory"
	case !wantDir && typ != unix.S_IFREG:
		return "not a regular file"
	}
	if st.Uid != owner {
		return fmt.Sprintf("owned by uid %d, not uid %d", st.Uid, owner)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Sprintf("writable by its group or others (mode %#o)", st.Mode&0o7777)
	}
	return ""
}

// openPinDirAt opens the pin directory relative to the work dir descriptor
// parent, without following a symlink, and checks it on the opened
// descriptor. A missing directory is an error wrapping fs.ErrNotExist.
func openPinDirAt(parent int, workDir string, owner uint32) (int, error) {
	dir := ReleasePinDir(workDir)
	fd, err := unix.Openat(parent, releasePinDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, fmt.Errorf("open %s: %w", dir, fs.ErrNotExist)
	}
	if err != nil {
		// A symlink fails O_NOFOLLOW with ELOOP, a file O_DIRECTORY with ENOTDIR.
		return -1, fmt.Errorf("%s is not a real directory: %w", dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("stat %s: %w", dir, err)
	}
	if p := statProblem(&st, owner, true); p != "" {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%s is %s", dir, p)
	}
	return fd, nil
}

// WriteReleasePin records pin under workDir. The caller must be root: the pin
// directory is created when missing, must be a real directory owned by root
// that no one else may write, and is set to 0755; the pin is written to a new
// temp file in it (0644, fsync'ed) and renamed over the pin, and the
// directory is fsync'ed. Every step after the check acts on the checked
// directory's descriptor; if the directory was moved away meanwhile, the
// write fails and leaves nothing at the pin path.
func WriteReleasePin(workDir string, pin ReleasePin) error {
	return writeReleasePin(workDir, pin, 0)
}

func writeReleasePin(workDir string, pin ReleasePin, owner uint32) error {
	if err := pin.Validate(); err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	b, err := json.Marshal(pin)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	parent, err := openWorkDir(workDir)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Mkdirat(parent, releasePinDirName, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("write the release pin: create %s: %w", ReleasePinDir(workDir), err)
	}
	dfd, err := openPinDirAt(parent, workDir, owner)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	defer func() { _ = unix.Close(dfd) }()
	if err := unix.Fchmod(dfd, 0o755); err != nil {
		return fmt.Errorf("write the release pin: chmod %s: %w", ReleasePinDir(workDir), err)
	}
	pinDirChecked()
	if err := writePinAt(dfd, append(b, '\n')); err != nil {
		return fmt.Errorf("write the release pin %s: %w", ReleasePinPath(workDir), err)
	}
	if err := samePinDir(parent, dfd); err != nil {
		// The pin went into a directory no longer at the pin path: take it
		// back out, and fail.
		_ = unix.Unlinkat(dfd, releasePinFileName, 0)
		return fmt.Errorf("write the release pin: %s was replaced during the write: %w", ReleasePinDir(workDir), err)
	}
	return nil
}

// writePinAt writes data to a new temp file in the directory dfd, created
// exclusively and without following a symlink, chmods it 0644 and fsyncs it,
// renames it over the pin and fsyncs the directory. The temp file is removed
// on every error.
func writePinAt(dfd int, data []byte) error {
	tmp := "." + releasePinFileName + ".tmp-" + strconv.FormatUint(rand.Uint64(), 36)
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create the temp file: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	err = func() error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		if err := f.Chmod(0o644); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, releasePinFileName)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	return unix.Fsync(dfd)
}

// samePinDir reports an error unless the pin directory entry in parent is
// still the directory dfd holds.
func samePinDir(parent, dfd int) error {
	var held, now unix.Stat_t
	if err := unix.Fstat(dfd, &held); err != nil {
		return err
	}
	if err := unix.Fstatat(parent, releasePinDirName, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if held.Dev != now.Dev || held.Ino != now.Ino {
		return errors.New("the directory entry now names another file")
	}
	return nil
}

// Cleared is what ClearReleasePin removed.
type Cleared struct {
	// Path is what was removed: the pin file, or the whole pin directory
	// entry when it could not be trusted. Empty means there was nothing.
	Path string
	// Untrusted says why the pin directory entry could not be trusted, when
	// the whole entry was removed.
	Untrusted string
}

// ClearReleasePin removes the release pin under workDir, as root. A trusted
// pin directory keeps its place and loses only the pin. A pin directory entry
// that cannot be trusted (a symlink, not a directory, another owner, writable
// by its group or others) is removed whole, so a less privileged user cannot
// block every update by planting one: a symlink or a file is unlinked, a
// directory is emptied and removed, every step relative to the work dir's
// descriptor and never following a symlink. A missing work dir, directory or
// pin is not an error.
func ClearReleasePin(workDir string) (Cleared, error) {
	return clearReleasePin(workDir, 0)
}

func clearReleasePin(workDir string, owner uint32) (Cleared, error) {
	parent, err := openWorkDir(workDir)
	if errors.Is(err, fs.ErrNotExist) {
		return Cleared{}, nil
	}
	if err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: %w", err)
	}
	defer func() { _ = unix.Close(parent) }()
	var st unix.Stat_t
	err = unix.Fstatat(parent, releasePinDirName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return Cleared{}, nil
	}
	if err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: stat %s: %w", ReleasePinDir(workDir), err)
	}
	if p := statProblem(&st, owner, true); p != "" {
		if err := removeAllAt(parent, releasePinDirName, 0); err != nil {
			return Cleared{}, fmt.Errorf("clear the release pin: remove %s (%s): %w", ReleasePinDir(workDir), p, err)
		}
		if err := unix.Fsync(parent); err != nil {
			return Cleared{}, fmt.Errorf("clear the release pin: sync %s: %w", workDir, err)
		}
		return Cleared{Path: ReleasePinDir(workDir), Untrusted: p}, nil
	}
	dfd, err := openPinDirAt(parent, workDir, owner)
	if err != nil {
		// It changed since the stat; a second run sees what it is now.
		return Cleared{}, fmt.Errorf("clear the release pin: %w", err)
	}
	defer func() { _ = unix.Close(dfd) }()
	err = unix.Unlinkat(dfd, releasePinFileName, 0)
	if errors.Is(err, unix.ENOENT) {
		return Cleared{}, nil
	}
	if err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: unlink %s: %w", ReleasePinPath(workDir), err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: sync %s: %w", ReleasePinDir(workDir), err)
	}
	return Cleared{Path: ReleasePinPath(workDir)}, nil
}

// removeAllAt removes name in the directory dirfd and, when it is a
// directory, everything under it, never following a symlink: anything but a
// directory is unlinked; a directory is opened relative to dirfd with
// O_NOFOLLOW, emptied the same way through its own descriptor, and removed.
// A directory refilled while it is emptied is retried a bounded number of
// times; the depth is bounded by maxClearDepth.
func removeAllAt(dirfd int, name string, depth int) error {
	if depth > maxClearDepth {
		return fmt.Errorf("%s is nested deeper than %d directories", name, maxClearDepth)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(dirfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return nil
	}
	for range 3 {
		if err := emptyDirAt(dirfd, name, depth); err != nil {
			return err
		}
		err := unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
		if err == nil || errors.Is(err, unix.ENOENT) {
			return nil
		}
		if !errors.Is(err, unix.ENOTEMPTY) {
			return err
		}
	}
	return fmt.Errorf("%s kept being refilled while it was removed", name)
}

// emptyDirAt removes every entry of the directory name in dirfd.
func emptyDirAt(dirfd int, name string, depth int) error {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	d := os.NewFile(uintptr(fd), name)
	defer func() { _ = d.Close() }()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := removeAllAt(fd, n, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// readReleasePin reads the pin under workDir, held to the checks the pin
// needs: a real directory and a regular file, both owned by owner and writable
// by no one else. A missing work dir, directory or file is (nil, nil). The
// directory is opened relative to the work dir and the file relative to the
// directory, neither following a symlink, and both are checked on the opened
// descriptors, so neither can be swapped between the check and the read.
func readReleasePin(workDir string, owner uint32) (*ReleasePin, error) {
	parent, err := openWorkDir(workDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	dfd, err := openPinDirAt(parent, workDir, owner)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	path := ReleasePinPath(workDir)
	fd, err := unix.Openat(dfd, releasePinFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if p := statProblem(&st, owner, false); p != "" {
		return nil, fmt.Errorf("%s is %s", path, p)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxReleasePinBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) > maxReleasePinBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxReleasePinBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var pin ReleasePin
	if err := dec.Decode(&pin); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := pin.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &pin, nil
}
