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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSappndMeasuredFacts is U195, root-run: it pins the 2026-11-23 probe
// table the swap rests on (docs/design/keystore.md § "SF_APPEND, as
// measured"). On an SF_APPEND file root's fchown, fchmod, rename, link,
// unlink and O_TRUNC open each fail with EPERM; a file handed to the
// service user and then flagged takes both, and root's fchown back is then
// EPERM; a descriptor opened without O_APPEND before the flag can neither
// pwrite nor ftruncate once it is set, and the bytes stay; the service
// user's link(2) of a root-owned 0600 unflagged file into its own
// directory succeeds, and of a flagged file fails. Only root can set the
// flag, so it skips unless root.
func TestSappndMeasuredFacts(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run (U195): run as root through hack/acceptance/keystore.sh --root")
	}
	svcUID, svcGID := serviceIDs(t)
	// The service user must reach the source files for the link probes
	// below: a t.TempDir() sits under root's 0700 directories, where its
	// link fails with EACCES for the path, not the flag. So the files live
	// in a root-created 0755 directory under the sticky, world-searchable
	// /private/tmp, and each link lands in a directory the service user
	// owns.
	dir, err := os.MkdirTemp("/private/tmp", "k3sm-sappnd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink == 0 {
				_ = unix.Chflags(p, 0)
			}
			return nil
		})
		_ = os.RemoveAll(dir) // the flags are clear, so every name goes
	})
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	n := 0
	// file creates a root-owned 0600 file holding "x\n", flagged when flag,
	// and returns its path and a read-only descriptor on it.
	file := func(flag bool) (string, *os.File) {
		t.Helper()
		n++
		p := filepath.Join(dir, fmt.Sprintf("f%d", n))
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if flag {
			if err := unix.Chflags(p, sfAppend); err != nil {
				t.Fatalf("chflags sappnd: %v", err)
			}
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return p, f
	}
	wantErrno := func(op string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", op, err, want)
		}
	}
	unchanged := func(op, p string) {
		t.Helper()
		var st unix.Stat_t
		b, err := os.ReadFile(p)
		if err != nil || string(b) != "x\n" || unix.Lstat(p, &st) != nil || st.Nlink != 1 {
			t.Errorf("%s changed %s: %q nlink %d (%v)", op, p, b, st.Nlink, err)
		}
	}

	p, f := file(true)
	wantErrno("root fchown of a flagged file", unix.Fchown(int(f.Fd()), int(svcUID), int(svcGID)), unix.EPERM)
	wantErrno("root fchmod of a flagged file", unix.Fchmod(int(f.Fd()), 0o644), unix.EPERM)
	wantErrno("root rename of a flagged file", unix.Rename(p, p+".renamed"), unix.EPERM)
	wantErrno("root link of a flagged file", unix.Link(p, p+".link"), unix.EPERM)
	wantErrno("root unlink of a flagged file", unix.Unlink(p), unix.EPERM)
	fd, err := unix.Open(p, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	wantErrno("root open(O_WRONLY|O_TRUNC) of a flagged file", err, unix.EPERM)
	unchanged("root's operations on a flagged file", p)
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Uid != 0 || st.Mode&0o7777 != 0o600 || st.Flags != sfAppend {
		t.Errorf("the flagged file is uid %d mode %04o flags %#x (%v); want root's 0600, SF_APPEND", st.Uid, st.Mode&0o7777, st.Flags, err)
	}

	_, f = file(false)
	if err := unix.Fchown(int(f.Fd()), int(svcUID), int(svcGID)); err != nil {
		t.Errorf("fchown to the service user of an unflagged file: %v", err)
	}
	if err := unix.Fchflags(int(f.Fd()), sfAppend); err != nil {
		t.Errorf("fchflags sappnd after the fchown: %v", err)
	}
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Uid != svcUID || st.Flags != sfAppend {
		t.Errorf("chown then flag left uid %d flags %#x (%v); want the service user's, SF_APPEND", st.Uid, st.Flags, err)
	}
	wantErrno("root fchown back to root while flagged", unix.Fchown(int(f.Fd()), 0, 0), unix.EPERM)

	p, _ = file(false)
	rw, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rw.Close() }()
	if err := unix.Chflags(p, sfAppend); err != nil {
		t.Fatalf("chflags sappnd: %v", err)
	}
	_, err = unix.Pwrite(int(rw.Fd()), []byte("Y"), 0)
	wantErrno("pwrite at 0 through a non-append descriptor opened before the flag", err, unix.EPERM)
	wantErrno("ftruncate through that descriptor", unix.Ftruncate(int(rw.Fd()), 0), unix.EPERM)
	unchanged("the pre-flag descriptor's pwrite and ftruncate", p)

	own := filepath.Join(dir, "service-own")
	if err := os.Mkdir(own, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(own, int(svcUID), int(svcGID)); err != nil {
		t.Fatal(err)
	}
	asService := func(f func() error) error {
		errc := make(chan error, 1)
		go func() {
			runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
			if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(svcUID), uintptr(svcGID), 0); errno != 0 {
				errc <- fmt.Errorf("settid: %w", errno)
				return
			}
			errc <- f()
		}()
		return <-errc
	}
	p, _ = file(false)
	if err := asService(func() error { return unix.Link(p, filepath.Join(own, "alias-unflagged")) }); err != nil {
		t.Errorf("the service user's link of a root-owned 0600 unflagged file: %v, want success", err)
	}
	if err := unix.Lstat(p, &st); err != nil || st.Nlink != 2 {
		t.Errorf("after the service user's link the unflagged file has nlink %d (%v), want 2", st.Nlink, err)
	}
	p, _ = file(true)
	err = asService(func() error { return unix.Link(p, filepath.Join(own, "alias-flagged")) })
	t.Logf("the service user's link of a flagged file: %v", err)
	wantErrno("the service user's link of a flagged file (the flag, not the path, must refuse it)", err, unix.EPERM)
	if err := unix.Lstat(p, &st); err != nil || st.Nlink != 1 {
		t.Errorf("after the service user's link the flagged file has nlink %d (%v), want 1", st.Nlink, err)
	}
}

// TestSappndDirectorySwap is U195's second table, root-run: it pins the
// 2026-11-23 directory-swap probe (docs/design/keystore.md § "SF_APPEND,
// as measured"). A live directory, root's 0755, holds the service user's
// 0600 flagged log; a root-only 0700 staging directory holds a replacement
// directory with its own flagged log. The service user holds, from before
// the swap, an O_WRONLY|O_APPEND descriptor on the old log and one on the
// live directory. Root renames a directory holding a flagged file and
// swaps the two directories with RENAME_SWAP (the canonical path reads the
// new log at once), then clears the retired log's flag. Through its held
// descriptors the service user can then clear O_APPEND, pwrite and
// ftruncate the retired log, and openat it for write; by path it cannot
// open the new canonical log without O_APPEND (EPERM) or with O_TRUNC
// (EPERM), it can append to it, and it cannot list staging (EACCES). The
// canonical log ends holding its content and the one append, flags exactly
// SF_APPEND, one link.
func TestSappndDirectorySwap(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run (U195): run as root through hack/acceptance/keystore.sh --root")
	}
	svcUID, svcGID := serviceIDs(t)
	// As in TestSappndMeasuredFacts: the service user must reach the tree,
	// so it lives in a root 0755 directory under /private/tmp.
	base, err := os.MkdirTemp("/private/tmp", "k3sm-swap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink == 0 {
				_ = unix.Chflags(p, 0)
			}
			return nil
		})
		_ = os.RemoveAll(base)
	})
	mkdir := func(p string, mode uint32) {
		t.Helper()
		if err := os.Mkdir(p, os.FileMode(mode)); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		if err := os.Chmod(p, os.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
	}
	flaggedLog := func(p, data string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, int(svcUID), int(svcGID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := unix.Chflags(p, sfAppend); err != nil {
			t.Fatal(err)
		}
	}
	mkdir(base, 0o755)
	live := filepath.Join(base, "live")
	staging := filepath.Join(base, "staging")
	repl := filepath.Join(staging, "live.new")
	mkdir(live, 0o755)
	mkdir(staging, 0o700)
	mkdir(repl, 0o755)
	flaggedLog(filepath.Join(live, "log"), "old\n")
	flaggedLog(filepath.Join(repl, "log"), "new\n")

	asService := func(f func() error) error {
		errc := make(chan error, 1)
		go func() {
			runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
			if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(svcUID), uintptr(svcGID), 0); errno != 0 {
				errc <- fmt.Errorf("settid: %w", errno)
				return
			}
			errc <- f()
		}()
		return <-errc
	}
	heldLog, heldDir := -1, -1
	if err := asService(func() error {
		var err error
		if heldDir, err = unix.Open(live, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
			return err
		}
		heldLog, err = unix.Openat(heldDir, "log", unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC, 0)
		return err
	}); err != nil {
		t.Fatalf("the service user's descriptors before the swap: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(heldLog); _ = unix.Close(heldDir) })

	row := func(op string, err error, want unix.Errno) {
		t.Helper()
		var got unix.Errno
		switch {
		case err == nil && want == 0:
		case err == nil:
			t.Errorf("%s: succeeded, want errno %d (%v)", op, int(want), want)
		case !errors.As(err, &got):
			t.Errorf("%s: %v, not an errno; want %d (%v)", op, err, int(want), want)
		case got != want:
			t.Errorf("%s: errno %d (%v), want %d (%v)", op, int(got), got, int(want), want)
		}
	}

	row("root rename of a directory holding a flagged file", os.Rename(repl, repl+".moved"), 0)
	row("root rename of it back", os.Rename(repl+".moved", repl), 0)
	row("root renameatx_np(RENAME_SWAP) of two directories, each holding a flagged file", unix.RenamexNp(repl, live, unix.RENAME_SWAP), 0)
	if b, err := os.ReadFile(filepath.Join(live, "log")); err != nil || string(b) != "new\n" {
		t.Errorf("the canonical path after the swap reads %q (%v), want the new log", b, err)
	}
	retired := filepath.Join(repl, "log")
	row("root clears the flag on the retired log, now in staging", unix.Chflags(retired, 0), 0)
	row("the service user's held descriptor on the retired log: F_SETFL clearing O_APPEND", asService(func() error {
		fl, err := unix.FcntlInt(uintptr(heldLog), unix.F_GETFL, 0)
		if err != nil {
			return err
		}
		_, err = unix.FcntlInt(uintptr(heldLog), unix.F_SETFL, fl&^unix.O_APPEND)
		return err
	}), 0)
	row("the same descriptor: pwrite at offset 0", asService(func() error {
		_, err := unix.Pwrite(heldLog, []byte("XX"), 0)
		return err
	}), 0)
	row("the same descriptor: ftruncate", asService(func() error { return unix.Ftruncate(heldLog, 0) }), 0)
	var st unix.Stat_t
	if err := unix.Stat(retired, &st); err != nil || st.Size != 0 {
		t.Errorf("the retired log is size %d (%v), want emptied", st.Size, err)
	}
	row("the service user's held directory descriptor: openat the retired log for write", asService(func() error {
		fd, err := unix.Openat(heldDir, "log", unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}), 0)
	canonical := filepath.Join(live, "log")
	open := func(flag int) func() error {
		return func() error {
			fd, err := unix.Open(canonical, flag|unix.O_CLOEXEC, 0)
			if err == nil {
				_ = unix.Close(fd)
			}
			return err
		}
	}
	row("the service user, by path: open the new canonical log O_WRONLY without O_APPEND", asService(open(unix.O_WRONLY)), unix.EPERM)
	row("the service user, by path: open the new canonical log O_WRONLY|O_TRUNC", asService(open(unix.O_WRONLY|unix.O_TRUNC)), unix.EPERM)
	row("the service user, by path: O_APPEND write to the new canonical log", asService(func() error {
		fd, err := unix.Open(canonical, unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		_, err = unix.Write(fd, []byte("appended\n"))
		return err
	}), 0)
	row("the service user: list the staging directory", asService(func() error {
		fd, err := unix.Open(staging, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}), unix.EACCES)
	b, err := os.ReadFile(canonical)
	if err != nil || string(b) != "new\nappended\n" {
		t.Errorf("the canonical log holds %q (%v), want %q", b, err, "new\nappended\n")
	}
	if err := unix.Lstat(canonical, &st); err != nil || st.Flags != sfAppend || st.Nlink != 1 {
		t.Errorf("the canonical log is flags %#x nlink %d (%v), want SF_APPEND alone and one link", st.Flags, st.Nlink, err)
	}
}
