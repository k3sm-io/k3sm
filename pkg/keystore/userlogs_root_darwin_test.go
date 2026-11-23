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
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fpunchhole is struct fpunchhole (<sys/fcntl.h>), F_PUNCHHOLE's argument,
// which x/sys does not define.
type fpunchhole struct {
	flags, reserved uint32
	offset, length  int64
}

// TestAppendOnlyFlagHoldsAsRoot sets the real SF_APPEND flag (chflags
// sappnd) on a log the service user owns at 0600, and proves what the
// flag variant of the user-scope floor rests on: an O_APPEND write lands,
// while every attempt of the defeat list (docs/design/keystore.md § "The
// user-scope floor") fails with EPERM exactly and leaves every byte in
// place. The store's own check, through the real flag source, admits the
// flagged file and refuses it as errLogNotAppendOnly once the flag is
// cleared. Only root can set SF_APPEND, so it skips unless root.
func TestAppendOnlyFlagHoldsAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-only: SF_APPEND can only be set by root")
	}
	s, _ := newTestStore(t)
	p := filepath.Join(s.dataRoot, logsDirName, userFloorLogName)
	if err := os.WriteFile(p, []byte("first\n"), logMode); err != nil {
		t.Fatal(err)
	}
	giveToService(t, p)
	if err := unix.Chflags(p, sfAppend); err != nil {
		t.Fatalf("chflags sappnd: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chflags(p, 0) }) // so TempDir can remove it

	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open O_APPEND on a flagged file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte("second\n")); err != nil {
		t.Fatalf("append to a flagged file: %v", err)
	}
	want := "first\nsecond\n"

	other := filepath.Join(s.dataRoot, "other")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.dataRoot, logsDirName, "floor-link")
	// rw is the O_RDWR|O_APPEND descriptor, when the open is allowed: the
	// pwrite, mmap and punch-hole attempts go through it.
	rw := -1
	t.Cleanup(func() {
		if rw >= 0 {
			_ = unix.Close(rw)
		}
	})
	openRW := func() error {
		fd, err := unix.Open(p, unix.O_RDWR|unix.O_APPEND, 0)
		if err != nil {
			return err
		}
		rw = fd
		return nil
	}
	needRW := func(t *testing.T) {
		if rw < 0 {
			if err := openRW(); err != nil {
				t.Skipf("the O_RDWR|O_APPEND open was refused (%v), so there is no descriptor to attempt this through", err)
			}
		}
	}
	for _, a := range []struct {
		name    string
		attempt func(t *testing.T) error
	}{
		{"ftruncate on the O_APPEND descriptor", func(*testing.T) error { return unix.Ftruncate(int(f.Fd()), 0) }},
		{"truncate by path", func(*testing.T) error { return unix.Truncate(p, 0) }},
		{"O_RDWR open", func(*testing.T) error {
			fd, err := unix.Open(p, unix.O_RDWR, 0)
			if err == nil {
				_ = unix.Close(fd) // the open itself is the failure
			}
			return err
		}},
		{"pwrite at offset 0 through O_RDWR|O_APPEND", func(t *testing.T) error {
			if err := openRW(); err != nil {
				return err
			}
			_, err := unix.Pwrite(rw, []byte("XXXXX"), 0)
			return err
		}},
		{"F_SETFL clearing O_APPEND", func(t *testing.T) error {
			needRW(t)
			fl, err := unix.FcntlInt(uintptr(rw), unix.F_GETFL, 0)
			if err != nil {
				return err
			}
			_, err = unix.FcntlInt(uintptr(rw), unix.F_SETFL, fl&^unix.O_APPEND)
			return err
		}},
		{"pwrite at offset 0 after the F_SETFL attempt", func(t *testing.T) error {
			needRW(t)
			_, err := unix.Pwrite(rw, []byte("XXXXX"), 0)
			return err
		}},
		{"pwrite at offset 3 through O_RDWR|O_APPEND", func(t *testing.T) error {
			needRW(t)
			_, err := unix.Pwrite(rw, []byte("XXXXX"), 3)
			return err
		}},
		{"mmap MAP_SHARED|PROT_WRITE", func(t *testing.T) error {
			needRW(t)
			b, err := unix.Mmap(rw, 0, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
			if err == nil {
				_ = unix.Munmap(b) // the mapping itself is the failure
			}
			return err
		}},
		{"F_PUNCHHOLE", func(t *testing.T) error {
			needRW(t)
			ph := fpunchhole{offset: 0, length: int64(len(want))}
			_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(rw), unix.F_PUNCHHOLE, uintptr(unsafe.Pointer(&ph)))
			if errno != 0 {
				return errno
			}
			return nil
		}},
		{"renamex_np RENAME_SWAP", func(*testing.T) error { return unix.RenamexNp(other, p, unix.RENAME_SWAP) }},
		{"exchangedata", func(*testing.T) error { return unix.Exchangedata(other, p, 0) }},
		{"link", func(*testing.T) error { return unix.Link(p, link) }},
		{"unlink after the link attempt", func(*testing.T) error { return unix.Unlink(p) }},
		{"rename over", func(*testing.T) error { return unix.Rename(other, p) }},
		{"O_TRUNC open", func(*testing.T) error {
			fd, err := unix.Open(p, unix.O_WRONLY|unix.O_TRUNC, 0)
			if err == nil {
				_ = unix.Close(fd) // the open itself is the failure
			}
			return err
		}},
		{"unlink", func(*testing.T) error { return unix.Unlink(p) }},
	} {
		t.Run(a.name, func(t *testing.T) {
			if err := a.attempt(t); !errors.Is(err, unix.EPERM) {
				t.Errorf("%s of a flagged file: %v, want EPERM", a.name, err)
			}
			if b, err := os.ReadFile(p); err != nil || string(b) != want {
				t.Fatalf("after the %s attempt the file holds %q (%v), want %q", a.name, b, err, want)
			}
		})
	}

	s.logFlags = fileFlags
	l := newFileFloorLog(s).log
	g, _, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatalf("the store refused the flagged log: %v", err)
	}
	defer func() { _ = g.Close() }() // read-only
	if err := unix.Chflags(p, 0); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := s.judgeLog(g, &st); !errors.Is(err, errLogNotAppendOnly) {
		t.Fatalf("judgeLog with the flag cleared: %v, want errLogNotAppendOnly", err)
	}
}
