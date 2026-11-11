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
	"strings"
	"syscall"
	"testing"

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
