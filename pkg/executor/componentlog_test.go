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

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/internal/atomicfile"
)

// The rotation and the log open run as root in the server work dir, so none of
// them may write through a symlink planted at a path they create or open. Each
// row plants one beside kine.log pointing at a file outside the work dir and
// checks the outside file is never written and the call refuses or replaces
// the link itself. Temp dirs only: no privilege is needed to show the refusal.
func TestComponentLogRotationRefusesSymlinks(t *testing.T) {
	t.Parallel()
	const secret = "outside file, must not change"
	tests := []struct {
		name string
		// link is the path, relative to the log path, the symlink sits at.
		link string
		run  func(logPath string) error
		// wantErr: the call must refuse. Otherwise it must succeed by replacing
		// the link, never writing through it.
		wantErr bool
	}{
		{"the log being rotated", "", func(p string) error { return rotateComponentLog(p, true) }, true},
		{"the log being rotated with no live failure", "", func(p string) error { return rotateComponentLog(p, false) }, true},
		{"the child's log open", "", func(p string) error {
			f, err := openComponentLog(p)
			if err == nil {
				_ = f.Close()
			}
			return err
		}, true},
		{"the pin marker", componentLogPinSuffix, func(p string) error { return createExclusive(p + componentLogPinSuffix) }, true},
		{"the tail copy's temp file", componentLogTmpSuffix, func(p string) error {
			if err := os.WriteFile(p, []byte("headhead-TAIL"), 0o600); err != nil {
				return err
			}
			return keepLogTail(p, p+".2", 4)
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, outside := t.TempDir(), filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(outside, []byte(secret), 0o600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "kine.log")
			if err := os.Symlink(outside, logPath+tc.link); err != nil {
				t.Fatal(err)
			}
			err := tc.run(logPath)
			if tc.wantErr && err == nil {
				t.Fatalf("followed or accepted a symlink at %s", logPath+tc.link)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want the link replaced, got %v", err)
			}
			if got, rerr := os.ReadFile(outside); rerr != nil || string(got) != secret {
				t.Fatalf("the symlink's target was written: %q, %v", got, rerr)
			}
			if _, err := os.Lstat(logPath + ".1"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a symlink was rotated into .1: %v", err)
			}
			if !tc.wantErr {
				if got, err := os.ReadFile(logPath + ".2"); err != nil || string(got) != "TAIL" {
					t.Fatalf(".log.2 = %q, %v; want the tail", got, err)
				}
				if _, err := os.Lstat(logPath + componentLogTmpSuffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("temp left behind: %v", err)
				}
			}
		})
	}
}

// A log path holding something other than a regular file is refused after the
// open (Fstat), never rotated, copied or blocked on: a FIFO is opened
// non-blocking, so a planted one cannot hang a spawn.
func TestComponentLogRotationRefusesNonRegular(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		plant func(path string) error
		run   func(logPath string) error
	}{
		{"a FIFO being rotated", func(p string) error { return syscall.Mkfifo(p, 0o600) },
			func(p string) error { return rotateComponentLog(p, true) }},
		{"a directory being rotated", func(p string) error { return os.Mkdir(p, 0o700) },
			func(p string) error { return rotateComponentLog(p, false) }},
		{"a FIFO kept as the latest lap", func(p string) error { return syscall.Mkfifo(p, 0o600) },
			func(p string) error { return keepLogTail(p, p+".2", 4) }},
		{"a directory opened as the child's log", func(p string) error { return os.Mkdir(p, 0o700) },
			func(p string) error {
				f, err := openComponentLog(p)
				if err == nil {
					_ = f.Close()
				}
				return err
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logPath := filepath.Join(t.TempDir(), "kine.log")
			if err := tc.plant(logPath); err != nil {
				t.Fatal(err)
			}
			if err := tc.run(logPath); err == nil {
				t.Fatal("a non-regular log path was accepted")
			}
			for _, kept := range []string{".1", ".2"} {
				if _, err := os.Lstat(logPath + kept); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a non-regular file was kept as %s: %v", kept, err)
				}
			}
			if fi, err := os.Lstat(logPath); err != nil || fi.Mode().IsRegular() {
				t.Fatalf("the planted file was moved or replaced: %v %v", fi, err)
			}
		})
	}
}

// A work dir another user could write is not rotated at all: the files the
// rotation creates and renames there could otherwise be raced from outside.
func TestComponentLogRotationRefusesAnUntrustedDir(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o770, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			logPath := filepath.Join(dir, "kine.log")
			if err := os.WriteFile(logPath, []byte("run"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			err := rotateComponentLog(logPath, true)
			if !errors.Is(err, atomicfile.ErrUnsafeDir) {
				t.Fatalf("err = %v, want ErrUnsafeDir", err)
			}
			if _, err := os.Lstat(logPath + ".1"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rotated in an untrusted dir: %v", err)
			}
			if _, err := os.Lstat(logPath + componentLogPinSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pinned in an untrusted dir: %v", err)
			}
		})
	}
	// The trusted case still rotates, so the refusal above is the check's.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "kine.log")
	if err := os.WriteFile(logPath, []byte("run"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rotateComponentLog(logPath, true); err != nil {
		t.Fatalf("a 0700 dir this process owns must rotate: %v", err)
	}
	if got, err := os.ReadFile(logPath + ".1"); err != nil || !strings.Contains(string(got), "run") {
		t.Fatalf(".1 = %q, %v", got, err)
	}
}

// The child's log is opened without truncating or blocking and checked through
// the descriptor before it is truncated: a hardlink to another file is refused
// with that file's bytes intact, a FIFO is refused without hanging the open, and
// a plain file is truncated and left writable for the child.
func TestOpenComponentLogChecksBeforeTruncating(t *testing.T) {
	t.Parallel()
	const other = "another name for this inode, must keep its bytes"
	tests := []struct {
		name    string
		plant   func(t *testing.T, logPath string)
		wantErr bool
	}{
		{"a hardlinked log", func(t *testing.T, p string) {
			elsewhere := filepath.Join(filepath.Dir(p), "elsewhere")
			if err := os.WriteFile(elsewhere, []byte(other), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(elsewhere, p); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a FIFO at the log path", func(t *testing.T, p string) {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a previous run's regular log", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("previous run"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"no log yet", func(*testing.T, string) {}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logPath := filepath.Join(t.TempDir(), "kine.log")
			tc.plant(t, logPath)
			type result struct {
				f   *os.File
				err error
			}
			done := make(chan result, 1)
			go func() {
				f, err := openComponentLog(logPath)
				done <- result{f, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("openComponentLog blocked")
			}
			if tc.wantErr {
				if r.err == nil {
					_ = r.f.Close()
					t.Fatal("accepted a log path that is not a single-link regular file")
				}
				elsewhere := filepath.Join(filepath.Dir(logPath), "elsewhere")
				if got, err := os.ReadFile(elsewhere); err == nil && string(got) != other {
					t.Fatalf("the hardlink's other name was truncated: %q", got)
				}
				return
			}
			if r.err != nil {
				t.Fatalf("openComponentLog: %v", r.err)
			}
			if _, err := r.f.WriteString("this run"); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := r.f.Close(); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(logPath); err != nil || string(got) != "this run" {
				t.Fatalf("log = %q, %v; want only this run's bytes", got, err)
			}
			if fi, err := os.Stat(logPath); err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("log mode = %v, %v; want 0600", fi, err)
			}
		})
	}
}

// The temp file keepLogTail writes the .2 tail into is one uninstall removes:
// a crash mid-copy must not leave a file ComponentLogKeptPaths does not list.
func TestKeepLogTailTempIsAKeptPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kept := ComponentLogKeptPaths(dir)
	for _, n := range componentLogNames {
		logPath := filepath.Join(dir, n+".log")
		tmp := logTailTmp(logPath + ".2")
		if !slices.Contains(kept, tmp) {
			t.Errorf("keepLogTail's temp %s is not in ComponentLogKeptPaths", tmp)
		}
	}
	// keepLogTail writes through logTailTmp: a non-empty dir planted at that
	// name cannot be removed, so the copy must fail on exactly that path.
	logPath := filepath.Join(dir, kineBinaryName+".log")
	if err := os.WriteFile(logPath, []byte("headhead-TAIL"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := logTailTmp(logPath + ".2")
	if err := os.MkdirAll(filepath.Join(tmp, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := keepLogTail(logPath, logPath+".2", 4); err == nil || !strings.Contains(err.Error(), tmp) {
		t.Fatalf("keepLogTail err = %v, want one naming %s", err, tmp)
	}
}
