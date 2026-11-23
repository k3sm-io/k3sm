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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// panicFileAttrWriter is TestMain's file-attribute writer: every call
// panics, naming the primitive.
type panicFileAttrWriter struct{}

func (panicFileAttrWriter) Fchown(int, int, int) error {
	panic("a unit test reached fchown: inject a fake file-attribute writer")
}

func (panicFileAttrWriter) Fchmod(int, uint32) error {
	panic("a unit test reached fchmod: inject a fake file-attribute writer")
}

func (panicFileAttrWriter) Fchflags(int, int) error {
	panic("a unit test reached chflags: inject a fake file-attribute writer")
}

// setSeam sets *p to v for the test and restores the previous value with
// t.Cleanup, so no fake outlives its test.
func setSeam[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// attrRecorder records each file-attribute call, in order, with the name
// of the file its descriptor holds, and changes nothing on disk. failOn
// fails the first call whose record has that prefix.
type attrRecorder struct {
	calls  []string
	failOn string
}

func (r *attrRecorder) record(call string) error {
	r.calls = append(r.calls, call)
	if r.failOn != "" && strings.HasPrefix(call, r.failOn) {
		r.failOn = ""
		return errors.New("injected")
	}
	return nil
}

func (r *attrRecorder) Fchown(fd, uid, gid int) error {
	return r.record(fmt.Sprintf("chown:%s:%d:%d", fdName(fd), uid, gid))
}

func (r *attrRecorder) Fchmod(fd int, mode uint32) error {
	return r.record(fmt.Sprintf("chmod:%s:%#o", fdName(fd), mode))
}

func (r *attrRecorder) Fchflags(fd, flags int) error {
	return r.record(fmt.Sprintf("chflags:%s:%#x", fdName(fd), flags))
}

// fdName is the base name of the file open at fd (fcntl F_GETPATH).
func fdName(fd int) string {
	buf := make([]byte, unix.PathMax)
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "?"
	}
	return filepath.Base(unix.ByteSliceToString(buf))
}

// U21 (install's half): the keystore step creates keystore-run/ and both
// logs, each log created root-owned 0600 with nothing written, flagged
// SF_APPEND on the held descriptor and only then handed to the service
// user; a rerun finishes a root-owned log the same way; it refuses without
// root, over a symlink, over a log at another mode, and over a missing
// floor while user scopes exist, changing nothing.
func TestKeystoreAppendOnlyFilesAtInstall(t *testing.T) {
	const svcUID, svcGID = 271, 20
	me := os.Getuid()
	floor, audit := keystore.UserFloorLogName, keystore.AuditLogName
	run := keystore.RunDirName
	want := []string{
		"chmod:" + run + ":0700", "chown:" + run + ":271:20",
		"chmod:" + floor + ":0600", "chflags:" + floor + ":0x40000", "chown:" + floor + ":271:20",
		"chmod:" + audit + ":0600", "chflags:" + audit + ":0x40000", "chown:" + audit + ":271:20",
	}
	setup := func(t *testing.T) (string, *attrRecorder) {
		t.Helper()
		root := t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		rec := &attrRecorder{}
		setSeam(t, &euidSeam, func() int { return 0 })
		setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
		return root, rec
	}
	t.Run("fresh", func(t *testing.T) {
		root, rec := setup(t)
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(rec.calls, want) {
			t.Fatalf("file-attribute calls:\n got %q\nwant %q", rec.calls, want)
		}
		for _, n := range []string{floor, audit} {
			fi, err := os.Lstat(filepath.Join(root, n))
			if err != nil {
				t.Fatal(err)
			}
			if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || fi.Size() != 0 {
				t.Fatalf("%s: %v size %d, want an empty 0600 regular file", n, fi.Mode(), fi.Size())
			}
		}
		if fi, err := os.Lstat(filepath.Join(root, run)); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v, %v, want a 0700 directory", run, fi, err)
		}
		// A rerun finds both logs still root's (the recorder changed no
		// owner): an install that stopped before its chown, finished in the
		// same order, flag first.
		rec.calls = nil
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); err != nil {
			t.Fatal(err)
		}
		rerun := []string{
			"chmod:" + run + ":0700", "chown:" + run + ":271:20",
			"chflags:" + floor + ":0x40000", "chown:" + floor + ":271:20",
			"chflags:" + audit + ":0x40000", "chown:" + audit + ":271:20",
		}
		if !slices.Equal(rec.calls, rerun) {
			t.Fatalf("rerun calls:\n got %q\nwant %q", rec.calls, rerun)
		}
	})
	t.Run("flag fails, no chown", func(t *testing.T) {
		root, rec := setup(t)
		rec.failOn = "chflags:" + floor
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); err == nil {
			t.Fatal("a failed chflags was not an error")
		}
		if slices.Contains(rec.calls, "chown:"+floor+":271:20") {
			t.Fatalf("the floor was handed over without its flag: %q", rec.calls)
		}
	})
	t.Run("not root", func(t *testing.T) {
		root, rec := setup(t)
		setSeam(t, &euidSeam, func() int { return 501 })
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); !errors.Is(err, errKeystoreFilesNotRoot) {
			t.Fatalf("got %v, want errKeystoreFilesNotRoot", err)
		}
		assertEmptyDir(t, root)
		if len(rec.calls) != 0 {
			t.Fatalf("calls without root: %q", rec.calls)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root, rec := setup(t)
		target := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.Symlink(target, filepath.Join(root, audit)); err != nil {
			t.Fatal(err)
		}
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); !errors.Is(err, errKeystoreFileUntrusted) {
			t.Fatalf("got %v, want errKeystoreFileUntrusted", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the symlink was followed")
		}
		if slices.ContainsFunc(rec.calls, func(c string) bool { return strings.Contains(c, audit) }) {
			t.Fatalf("an attribute was written through the symlink: %q", rec.calls)
		}
	})
	t.Run("wrong mode", func(t *testing.T) {
		root, _ := setup(t)
		if err := os.WriteFile(filepath.Join(root, floor), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); !errors.Is(err, errKeystoreFileUntrusted) {
			t.Fatalf("got %v, want errKeystoreFileUntrusted", err)
		}
	})
	t.Run("floor missing with user scopes", func(t *testing.T) {
		root, rec := setup(t)
		if err := os.MkdirAll(filepath.Join(root, "server", "keystore", keystore.UserScopesDirName), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); !errors.Is(err, errKeystoreFloorWithScopes) {
			t.Fatalf("got %v, want errKeystoreFloorWithScopes", err)
		}
		if _, err := os.Lstat(filepath.Join(root, floor)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a floor was created while user scopes exist")
		}
		if slices.ContainsFunc(rec.calls, func(c string) bool { return strings.Contains(c, floor) }) {
			t.Fatalf("calls on the floor: %q", rec.calls)
		}
	})
}

// TestRealPrimitivesUnreachable proves TestMain's stubs are in place: each
// seam, called without a fake, panics naming its primitive (U61).
func TestRealPrimitivesUnreachable(t *testing.T) {
	for _, tt := range []struct {
		primitive string
		call      func()
	}{
		{"geteuid", func() { _ = euidSeam() }},
		{"fchown", func() { _ = fileAttrSeam.Fchown(-1, 0, 0) }},
		{"fchmod", func() { _ = fileAttrSeam.Fchmod(-1, 0) }},
		{"chflags", func() { _ = fileAttrSeam.Fchflags(-1, 0) }},
	} {
		t.Run(tt.primitive, func(t *testing.T) {
			defer func() {
				r := recover()
				if s, _ := r.(string); !strings.Contains(s, tt.primitive) {
					t.Fatalf("the seam for %s did not panic naming it: %v", tt.primitive, r)
				}
			}()
			tt.call()
		})
	}
}

// The keystore step refuses while the maintenance marker stands in the data
// root, naming the verbs to rerun: it changes nothing, so it never flags or
// hands over a log a stopped floor --rebuild or audit --rotate left
// root-owned. Once the marker is gone it runs as usual.
func TestKeystoreFilesRefuseDuringMaintenance(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &attrRecorder{}
	setSeam(t, &euidSeam, func() int { return 0 })
	setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
	// A stopped rotate's state: the root-owned new log, unflagged.
	log := filepath.Join(root, keystore.AuditLogName)
	if err := os.WriteFile(log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, keystore.MaintenanceMarkerName)
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := ensureKeystoreFiles(root, 271, 20, os.Getuid())
	if !errors.Is(err, errKeystoreMaintenance) || !strings.Contains(err.Error(), "floor --rebuild") || !strings.Contains(err.Error(), "audit --rotate") {
		t.Fatalf("install while the marker stands: %v, want errKeystoreMaintenance naming both verbs", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("install made file-attribute calls while the marker stands: %q", rec.calls)
	}
	for _, n := range []string{keystore.UserFloorLogName, keystore.RunDirName} {
		if _, err := os.Lstat(filepath.Join(root, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("install created %s while the marker stands: %v", n, err)
		}
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := ensureKeystoreFiles(root, 271, 20, os.Getuid()); err != nil {
		t.Fatalf("install once the marker is gone: %v", err)
	}
}

// The keystore step judges the data root's flags and ACL as the keystore
// does (keystore.JudgeDirFlagsACL): a data root carrying a file flag beside
// SF_APPEND is refused, changing nothing.
func TestKeystoreFilesJudgeDataRootFlags(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &attrRecorder{}
	setSeam(t, &euidSeam, func() int { return 0 })
	setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
	if err := unix.Chflags(root, unix.UF_HIDDEN); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(root, 0) })
	err := ensureKeystoreFiles(root, 271, 20, os.Getuid())
	if !errors.Is(err, errKeystoreFileUntrusted) {
		t.Fatalf("install over a flagged data root: %v, want errKeystoreFileUntrusted", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("install made file-attribute calls over a flagged data root: %q", rec.calls)
	}
}
