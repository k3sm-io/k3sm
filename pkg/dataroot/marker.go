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

package dataroot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// MarkerName is the file `k3sm install` writes at the top of every directory
// tree it owns outright and that a purge may later delete whole: the data root
// and the daemon log dir.
//
// It is NOT the data-volume marker (.k3sm-datavol), which says "this APFS
// volume is k3sm's" and lives on a volume whatever directory it is mounted at.
// This one says "this DIRECTORY is the k3sm tree named inside me", and is what
// `k3sm uninstall --purge` requires before it deletes a tree as root.
//
// What it is and is not: a guard against a fat-fingered or misconfigured path
// (a data root of "/" or of somebody's home), checked on top of a path deny
// list. It is not a boundary against a compromised root, which can write a
// marker anywhere it likes.
const MarkerName = ".k3sm-dataroot"

// MarkerMode is the marker's permission bits: root-written, world-readable,
// and writable by nobody but its owner.
const MarkerMode fs.FileMode = 0o644

// ErrMarker is what every marker refusal wraps. Match it with errors.Is.
var ErrMarker = errors.New("not a k3sm-marked directory")

// MarkerPath is where the marker of dir lives.
func MarkerPath(dir string) string { return filepath.Join(dir, MarkerName) }

// MarkerContent is what the marker of dir holds: the cleaned absolute path of
// the directory it marks. Binding the content to the path is what stops a
// marker copied into another directory from authorizing that directory.
func MarkerContent(dir string) []byte { return []byte(filepath.Clean(dir) + "\n") }

// WriteMarker writes dir's marker root:wheel at MarkerMode, atomically (a temp
// file in dir, then a rename). It is idempotent: an existing marker is
// replaced by an identical one. dir must already exist and must not be a
// symlink.
func WriteMarker(dir string) error { return writeMarker(dir, 0, 0) }

// writeMarker is WriteMarker with the owner explicit, so an unprivileged test
// can exercise everything but the chown to root.
func writeMarker(dir string, uid, gid int) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("write marker in %s: %w", dir, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("write marker in %s: not a real directory", dir)
	}
	tmp, err := os.CreateTemp(dir, ".k3sm-dataroot-*")
	if err != nil {
		return fmt.Errorf("create temp marker in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // a no-op once the rename succeeded
	// Owner and mode are applied to the open descriptor, before the content and
	// the rename: the file inherits the directory's group on macOS, and the log
	// dir's group is not wheel.
	if err := tmp.Chown(uid, gid); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chown temp marker %s: %w", name, err)
	}
	if err := tmp.Chmod(MarkerMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp marker %s: %w", name, err)
	}
	if _, err := tmp.Write(MarkerContent(dir)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp marker %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp marker %s: %w", name, err)
	}
	if err := os.Rename(name, MarkerPath(dir)); err != nil {
		return fmt.Errorf("install marker %s: %w", MarkerPath(dir), err)
	}
	return nil
}

// MarkerFacts is what ReadMarker observed, all of it off one open descriptor.
type MarkerFacts struct {
	// Regular reports a regular file (a symlink is never opened at all).
	Regular bool
	// UID is the owner.
	UID uint32
	// Mode is the permission bits.
	Mode fs.FileMode
	// Content is the file's bytes, read up to a small bound.
	Content []byte
}

// markerMaxBytes bounds how much of a marker is read: a path and a newline.
const markerMaxBytes = 4096

// ReadMarker opens dir's marker O_NOFOLLOW|O_RDONLY and reports its type,
// owner, mode and content from that one descriptor, so nothing can be swapped
// between the check and the read. A missing marker has os.ReadFile's contract
// (an error satisfying errors.Is(err, fs.ErrNotExist)); a symlink in its place
// is an error wrapping ErrMarker.
func ReadMarker(dir string) (MarkerFacts, error) {
	path := MarkerPath(dir)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return MarkerFacts{}, fmt.Errorf("%s is a symlink: %w", path, ErrMarker)
		}
		return MarkerFacts{}, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return MarkerFacts{}, fmt.Errorf("stat %s: %w", path, err)
	}
	facts := MarkerFacts{
		Regular: st.Mode&unix.S_IFMT == unix.S_IFREG,
		UID:     st.Uid,
		Mode:    fs.FileMode(st.Mode) & fs.ModePerm,
	}
	if !facts.Regular {
		return facts, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, markerMaxBytes))
	if err != nil {
		return MarkerFacts{}, fmt.Errorf("read %s: %w", path, err)
	}
	facts.Content = data
	return facts, nil
}

// CheckMarker judges facts read from dir's marker: a regular file, owned by
// root, writable by nobody else, whose content names dir itself. It is pure,
// so every refusal is testable without privilege.
func CheckMarker(dir string, facts MarkerFacts) error {
	path := MarkerPath(dir)
	switch {
	case !facts.Regular:
		return fmt.Errorf("%s is not a regular file: %w", path, ErrMarker)
	case facts.UID != 0:
		return fmt.Errorf("%s is owned by uid %d, not root: %w", path, facts.UID, ErrMarker)
	case facts.Mode&0o022 != 0:
		return fmt.Errorf("%s is group- or world-writable (%#o): %w", path, facts.Mode, ErrMarker)
	case !bytes.Equal(bytes.TrimRight(facts.Content, "\n"), bytes.TrimRight(MarkerContent(dir), "\n")):
		return fmt.Errorf("%s names %q, not %s: %w", path, bytes.TrimSpace(facts.Content), filepath.Clean(dir), ErrMarker)
	}
	return nil
}

// VerifyMarker is ReadMarker then CheckMarker: nil only when dir carries a
// marker k3sm wrote for exactly dir.
func VerifyMarker(dir string) error {
	facts, err := ReadMarker(dir)
	if err != nil {
		return err
	}
	return CheckMarker(dir, facts)
}
