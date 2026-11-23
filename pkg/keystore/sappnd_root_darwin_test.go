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
	dir := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink == 0 {
				_ = unix.Chflags(p, 0)
			}
			return nil
		})
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
	if err := os.Mkdir(own, 0o700); err != nil {
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
	if err == nil {
		t.Errorf("the service user's link of a flagged file succeeded, want a failure")
	} else {
		t.Logf("the service user's link of a flagged file: %v", err)
	}
	if err := unix.Lstat(p, &st); err != nil || st.Nlink != 1 {
		t.Errorf("after the service user's link the flagged file has nlink %d (%v), want 1", st.Nlink, err)
	}
}
