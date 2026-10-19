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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/atomicfile"
)

// The release pin is a server-local record of the archive digest a release
// must have, written by root (`k3sm update apply --pin-sha256`) before it
// creates the Update. It binds a roll to bytes vouched for outside the
// release host: the controller refuses a release whose checksums file
// disagrees with the pin before any node is touched, and on a match the
// pinned digest is what the cluster CA signs into every node's payload.
//
// The pin lives at <server work dir>/update/release-pin, a root-owned 0644
// file in a root-owned 0755 directory. Only root can write it; the server
// reads it. A pin can only constrain a roll, never loosen one: it is
// consulted only for its own version, and a pin the controller cannot trust
// (a wrong owner, a group- or world-writable file or directory, a symlink, a
// malformed record) refuses the roll rather than being skipped.
const (
	// releasePinDirName is the directory under the server work dir.
	releasePinDirName = "update"
	// releasePinFileName is the pin file in that directory.
	releasePinFileName = "release-pin"
	// maxReleasePinBytes bounds the pin read; a record is under 200 bytes.
	maxReleasePinBytes = 4096
)

// The condition reasons the release pin adds.
const (
	// ReasonReleasePinMismatch is the Failed (and Resolved) condition reason
	// when the release disagrees with the release pin, or the pin cannot be
	// trusted.
	ReasonReleasePinMismatch = "ReleasePinMismatch"
	// ReasonResolvedPinned is the Resolved condition reason when the release
	// matched the release pin for its version.
	ReasonResolvedPinned = "ResolvedPinned"
)

// ErrReleasePinMismatch marks a release the release pin refuses: its
// checksums file has no entry for the archive, its digest differs from the
// pin, or the pin itself cannot be trusted. Every such error also wraps
// ErrRelease, so the roll fails definitively instead of retrying.
var ErrReleasePinMismatch = errors.New("the release does not match the release pin")

// pinError is a definitive failure carrying ErrReleasePinMismatch.
func pinError(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrRelease, ErrReleasePinMismatch, fmt.Sprintf(format, args...))
}

// ReleasePin is the pin record, stored as JSON.
type ReleasePin struct {
	// Version is the release tag the pin binds, exactly as the Update names it.
	Version string `json:"version"`
	// SHA256 is the darwin/arm64 archive's lowercase hex sha256.
	SHA256 string `json:"sha256"`
	// At is when the pin was written.
	At time.Time `json:"at"`
}

// Validate refuses a record with an unusable tag or a digest that is not 64
// lowercase hex digits.
func (p ReleasePin) Validate() error {
	if !validTag(p.Version) {
		return fmt.Errorf("the pinned version %q is not a release tag", p.Version)
	}
	if !isSHA256Hex(p.SHA256) {
		return errors.New("the pinned sha256 is not 64 lowercase hex digits")
	}
	return nil
}

// ReleasePinDir is the directory holding the release pin under workDir.
func ReleasePinDir(workDir string) string { return filepath.Join(workDir, releasePinDirName) }

// ReleasePinPath is the release pin file under workDir.
func ReleasePinPath(workDir string) string {
	return filepath.Join(ReleasePinDir(workDir), releasePinFileName)
}

// WriteReleasePin records pin under workDir. The caller must be root: the
// directory is created root-owned 0755 when missing, an existing one must be
// a real directory owned by root and writable by no one else, and the file is
// replaced through a temp file beside it (0644, fsync'ed, renamed, the
// directory fsync'ed).
func WriteReleasePin(workDir string, pin ReleasePin) error {
	return writeReleasePin(workDir, pin, 0)
}

func writeReleasePin(workDir string, pin ReleasePin, owner uint32) error {
	if err := pin.Validate(); err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	dir := ReleasePinDir(workDir)
	if err := os.Mkdir(dir, 0o755); err == nil {
		if err := os.Chmod(dir, 0o755); err != nil {
			return fmt.Errorf("write the release pin: %w", err)
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("write the release pin: %w", err)
	}
	d, err := openPinDir(dir, owner)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	_ = d.Close() // only its checks were needed
	b, err := json.Marshal(pin)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	if err := atomicfile.Replace(ReleasePinPath(workDir), append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	return nil
}

// RemoveReleasePin removes the release pin under workDir. It reports whether
// there was one. The directory must pass the same checks as for a write; a
// missing directory or file is not an error.
func RemoveReleasePin(workDir string) (bool, error) {
	return removeReleasePin(workDir, 0)
}

func removeReleasePin(workDir string, owner uint32) (bool, error) {
	d, err := openPinDir(ReleasePinDir(workDir), owner)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("remove the release pin: %w", err)
	}
	defer func() { _ = d.Close() }()
	err = unix.Unlinkat(int(d.Fd()), releasePinFileName, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("remove the release pin: unlink %s: %w", ReleasePinPath(workDir), err)
	}
	if err := d.Sync(); err != nil {
		return true, fmt.Errorf("remove the release pin: sync %s: %w", ReleasePinDir(workDir), err)
	}
	return true, nil
}

// readReleasePin reads the pin under workDir, held to the checks the pin
// needs: a real directory and a regular file, both owned by owner and writable
// by no one else. A missing directory or file is (nil, nil). The file is
// opened relative to the checked directory's descriptor, without following a
// symlink, and checked on the opened descriptor, so neither can be swapped
// between the check and the read.
func readReleasePin(workDir string, owner uint32) (*ReleasePin, error) {
	d, err := openPinDir(ReleasePinDir(workDir), owner)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	fd, err := unix.Openat(int(d.Fd()), releasePinFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", ReleasePinPath(workDir), err)
	}
	f := os.NewFile(uintptr(fd), ReleasePinPath(workDir))
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", f.Name(), err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", f.Name())
	}
	if err := trustedOwnerMode(f.Name(), fi, owner); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxReleasePinBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Name(), err)
	}
	if len(raw) > maxReleasePinBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", f.Name(), maxReleasePinBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var pin ReleasePin
	if err := dec.Decode(&pin); err != nil {
		return nil, fmt.Errorf("decode %s: %w", f.Name(), err)
	}
	if err := pin.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Name(), err)
	}
	return &pin, nil
}

// openPinDir opens dir without following a symlink and holds it to the pin's
// checks on the opened descriptor: a directory owned by owner, writable by no
// one else. A missing dir is an error wrapping fs.ErrNotExist.
func openPinDir(dir string, owner uint32) (*os.File, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, fmt.Errorf("open %s: %w", dir, fs.ErrNotExist)
	}
	if err != nil {
		// A symlink fails O_NOFOLLOW with ELOOP, a file O_DIRECTORY with ENOTDIR.
		return nil, fmt.Errorf("%s is not a real directory: %w", dir, err)
	}
	d := os.NewFile(uintptr(fd), dir)
	fi, err := d.Stat()
	if err == nil && !fi.IsDir() {
		err = fmt.Errorf("%s is not a directory", dir)
	}
	if err == nil {
		err = trustedOwnerMode(dir, fi, owner)
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// trustedOwnerMode refuses fi unless owner owns it and neither its group nor
// others may write it.
func trustedOwnerMode(path string, fi fs.FileInfo, owner uint32) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	if st.Uid != owner {
		return fmt.Errorf("%s is owned by uid %d, not uid %d", path, st.Uid, owner)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by its group or others (%v)", path, fi.Mode().Perm())
	}
	return nil
}

// PinnedResolver wraps a Resolver with the release pin under WorkDir. With no
// pin, or a pin for another version (logged), it is Resolver. With a pin for
// exactly the tag being resolved, the release's checksums digest must equal
// the pin: a match is returned with Pinned set; a mismatch, a checksums file
// with no entry for the archive, or any other definitive resolve failure is
// ErrReleasePinMismatch. A pin it cannot trust refuses every resolve until
// root fixes or removes it (`k3sm update apply --clear-pin`). A transient
// resolve error passes through, to be retried.
type PinnedResolver struct {
	// Resolver reads the release index. Required.
	Resolver Resolver
	// WorkDir is the server work dir the pin lives under. Required.
	WorkDir string
	// Log is the structured logger. nil means slog.Default().
	Log *slog.Logger
	// owner is the uid the pin and its directory must be owned by. The zero
	// value is root, the only owner outside tests.
	owner uint32
}

// AssetURL implements Resolver.
func (r PinnedResolver) AssetURL(tag string) (string, error) { return r.Resolver.AssetURL(tag) }

// Resolve implements Resolver.
func (r PinnedResolver) Resolve(ctx context.Context, tag string) (Release, error) {
	if r.Resolver == nil || r.WorkDir == "" {
		return Release{}, pinError("the pinned resolver has no resolver or work dir")
	}
	pin, err := readReleasePin(r.WorkDir, r.owner)
	if err != nil {
		return Release{}, pinError("the release pin cannot be trusted: %v", err)
	}
	if pin == nil {
		return r.Resolver.Resolve(ctx, tag)
	}
	if pin.Version != tag {
		r.log().Info("update controller: ignoring the release pin for another version",
			"pinned", pin.Version, "target", tag, "path", ReleasePinPath(r.WorkDir))
		return r.Resolver.Resolve(ctx, tag)
	}
	rel, err := r.Resolver.Resolve(ctx, tag)
	if err != nil {
		if errors.Is(err, ErrRelease) {
			return Release{}, pinError("%s is pinned to sha256:%s, and the release did not resolve: %v", tag, pin.SHA256, err)
		}
		return Release{}, err
	}
	if rel.SHA256 != pin.SHA256 {
		return Release{}, pinError("%s is pinned to sha256:%s, the release's checksums file says sha256:%s", tag, pin.SHA256, rel.SHA256)
	}
	rel.Pinned = true
	return rel, nil
}

func (r PinnedResolver) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}
