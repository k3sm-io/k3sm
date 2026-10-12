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

package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrUnsafeDir reports a target directory a less privileged user could write to,
// where InstallReader refuses to stage: such a writer could swap the temp file
// between its signing and its rename and have the swapped bytes installed.
var ErrUnsafeDir = errors.New("atomicfile: target directory is writable by others")

// geteuid and lchown are seams so the owner-preserving and directory checks are
// testable without root.
var (
	geteuid = os.Geteuid
	lchown  = os.Lchown
)

// tempInfix is the one definition of the temp-file naming: a temp for target name is
// "." + name + tempInfix + the digits os.CreateTemp appends.
const tempInfix = ".tmp-"

// tempPrefix returns the temp-file name prefix for the target named name.
func tempPrefix(name string) string { return "." + name + tempInfix }

// WriteNew installs data at path with mode. The bytes go to a temp file in path's
// directory (created 0600, so secret material is never readable mid-write), which is
// chmod'ed to mode, fsync'ed and hard-linked to path; the directory is then fsync'ed so
// the new name is durable. link(2) fails with EEXIST when path exists, so the
// no-overwrite check and the install are one kernel step: an existing path yields an
// error wrapping fs.ErrExist and is left untouched. The temp file is removed on every
// return, success or error.
func WriteNew(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tempPrefix(filepath.Base(path)))
	if err != nil {
		return fmt.Errorf("atomicfile: create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := writeAndSync(tmp, data, mode); err != nil {
		return fmt.Errorf("atomicfile: write temp for %s: %w", path, err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		return fmt.Errorf("atomicfile: install %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("atomicfile: sync directory of %s: %w", path, err)
	}
	return nil
}

// Replace installs data at path with mode, replacing whatever is there. The bytes go
// to a temp file in path's directory (created 0600), which is chmod'ed to mode,
// fsync'ed and renamed over path; the directory is then fsync'ed. rename(2) replaces
// the directory entry itself, so an existing symlink at path is replaced, never
// followed, and a pre-existing file's wider mode does not survive: the result is
// always a fresh regular file with exactly mode. For material re-issued on every
// start (a component leaf); a file that must never be overwritten uses WriteNew.
// The temp file is removed on every error return.
func Replace(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tempPrefix(filepath.Base(path)))
	if err != nil {
		return fmt.Errorf("atomicfile: create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	if err := writeAndSync(tmp, data, mode); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomicfile: write temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomicfile: install %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("atomicfile: sync directory of %s: %w", path, err)
	}
	return nil
}

// InstallFile installs a copy of the file at src at dst with mode, on a NEW inode. It
// is InstallReader over src's bytes; src may equal dst, which is how a live file is
// rewritten (re-signed) without ever being written in place.
func InstallFile(src, dst string, mode os.FileMode, prepare func(tmpPath string) error) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("atomicfile: open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	return InstallReader(in, dst, mode, prepare)
}

// InstallReader streams r to a temp file in dst's directory (created 0600), chmods it
// to mode, runs prepare on the temp's path (nil for none), fsyncs it and renames it
// over dst; the directory is then fsync'ed. The temp file is removed on every error
// return, and an error from prepare leaves dst untouched.
//
// It is the ONE way k3sm writes an executable or a dylib. macOS caches a Mach-O's
// code signature per vnode: rewriting a signed file in place (an O_TRUNC write, a
// copy onto it, or `codesign -f` on it) while any process has it mapped leaves the
// kernel holding the old signature, and every process that maps the file afterwards
// is killed (SIGKILL, Code Signature Invalid). rename(2) instead puts the new bytes
// on a new inode and leaves the old one, and every mapping of it, intact. So any
// change to a binary's bytes, its signature included, happens on the temp inside
// prepare (that is where signing goes), and the finished file appears at dst in one
// step: dst never names an unsigned or half-written binary.
//
// Like Replace, an existing symlink at dst is replaced, never followed. Running as
// root, the new file keeps the owner and group of the regular file it replaces; a
// first install is owned by the euid. A target directory that is group- or
// world-writable is refused with ErrUnsafeDir, unless it is sticky and owned by the
// euid (then no one else can rename or remove the temp).
func InstallReader(r io.Reader, dst string, mode os.FileMode, prepare func(tmpPath string) error) error {
	dir := filepath.Dir(dst)
	if err := checkDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tempPrefix(filepath.Base(dst)))
	if err != nil {
		return fmt.Errorf("atomicfile: create temp for %s: %w", dst, err)
	}
	tmpPath := tmp.Name()
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: write temp for %s: %w", dst, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: chmod temp for %s: %w", dst, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close temp for %s: %w", dst, err)
	}
	if prepare != nil {
		if err := prepare(tmpPath); err != nil {
			return fmt.Errorf("atomicfile: prepare %s: %w", dst, err)
		}
	}
	if err := keepOwner(tmpPath, dst); err != nil {
		return fmt.Errorf("atomicfile: keep the owner of %s: %w", dst, err)
	}
	// Synced after prepare, which may have rewritten the temp (a signature).
	if err := syncFile(tmpPath); err != nil {
		return fmt.Errorf("atomicfile: sync temp for %s: %w", dst, err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("atomicfile: install %s: %w", dst, err)
	}
	installed = true
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("atomicfile: sync directory of %s: %w", dst, err)
	}
	return nil
}

// ReapOrphans removes the temp files a killed WriteNew of dir/name may have left: the
// regular files in dir named ".<name>.tmp-<digits>". Nothing else is touched, and an
// absent dir is not an error. It must not run concurrently with a WriteNew of the same
// target, whose temp it would remove.
func ReapOrphans(dir, name string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("atomicfile: read %s: %w", dir, err)
	}
	prefix := tempPrefix(name)
	for _, e := range entries {
		if !isTempOf(e.Name(), prefix) || !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("atomicfile: remove orphan temp %s: %w", p, err)
		}
	}
	return nil
}

// isTempOf reports whether entry is prefix followed by one or more digits.
func isTempOf(entry, prefix string) bool {
	rest, ok := strings.CutPrefix(entry, prefix)
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// writeAndSync sets f's mode, writes data, fsyncs and closes f. f is closed on every
// path.
func writeAndSync(f *os.File, data []byte, mode os.FileMode) error {
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// checkDir refuses a directory others can write to (see ErrUnsafeDir).
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("atomicfile: stat %s: %w", dir, err)
	}
	if fi.Mode().Perm()&0o022 == 0 {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if fi.Mode()&os.ModeSticky != 0 && ok && int(st.Uid) == geteuid() {
		return nil
	}
	return fmt.Errorf("%w: %s is %v", ErrUnsafeDir, dir, fi.Mode())
}

// keepOwner gives tmp the owner and group of the regular file at dst when running
// as root, so replacing a binary never changes who owns it. Without root a file
// cannot be given away, and with no file at dst the euid owns the new one.
func keepOwner(tmp, dst string) error {
	if geteuid() != 0 {
		return nil
	}
	fi, err := os.Lstat(dst)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return lchown(tmp, int(st.Uid), int(st.Gid))
}

// syncFile fsyncs the file at path.
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// syncDir fsyncs the directory dir so a link made in it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}
