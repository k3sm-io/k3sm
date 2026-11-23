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

// fakeStat is keystoreFstatSeam for a test whose recorder changes nothing
// on disk: a file the recorder chowned reads as the service user's, and
// one it flagged reads with SF_APPEND.
func (r *attrRecorder) fakeStat(svcUID int) func(int, *unix.Stat_t) error {
	return func(fd int, st *unix.Stat_t) error {
		if err := unix.Fstat(fd, st); err != nil {
			return err
		}
		n := fdName(fd)
		for _, c := range r.calls {
			if strings.HasPrefix(c, "chown:"+n+":") {
				st.Uid = uint32(svcUID)
			}
			if c == "chflags:"+n+":0x40000" {
				st.Flags = unix.SF_APPEND
			}
		}
		return nil
	}
}

// U21 (install's half): the keystore step creates keystore-run/,
// keystore-logs/ and both logs, each built with its own directory in
// keystore-staging/: the log created root's 0600 with nothing written,
// handed to the service user, set to 0600 and flagged SF_APPEND on the held
// descriptor and judged, all before the directory is placed in
// keystore-logs/ with RENAME_EXCL; a rerun leaves judged logs alone; a
// failed flag places nothing, and the rerun builds the directory again;
// it refuses an unflagged log, without root, over a symlink, over a log at
// another mode, over a log at an old location and over a missing floor
// while user scopes exist, changing nothing.
func TestKeystoreAppendOnlyFilesAtInstall(t *testing.T) {
	const svcUID, svcGID = 271, 20
	me := os.Getuid()
	floor, audit := keystore.UserFloorLogName, keystore.AuditLogName
	run, logs := keystore.RunDirName, keystore.LogsDirName
	swap := func(n string) []string {
		return []string{"chown:" + n + ":271:20", "chmod:" + n + ":0600", "chflags:" + n + ":0x40000"}
	}
	logPath := func(root, n string) string { return filepath.Join(root, logs, keystore.LogDirOf(n), n) }
	want := append(append([]string{"chown:" + run + ":271:20"}, swap(floor)...), swap(audit)...)
	setup := func(t *testing.T) (string, *attrRecorder) {
		t.Helper()
		root := t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		rec := &attrRecorder{}
		setSeam(t, &euidSeam, func() int { return 0 })
		setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
		setSeam(t, &keystoreFstatSeam, rec.fakeStat(svcUID))
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
			if fi, err := os.Lstat(filepath.Dir(logPath(root, n))); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
				t.Fatalf("%s's directory: %v, %v, want a 0755 directory", n, fi, err)
			}
			fi, err := os.Lstat(logPath(root, n))
			if err != nil {
				t.Fatal(err)
			}
			if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || fi.Size() != 0 {
				t.Fatalf("%s: %v size %d, want an empty 0600 regular file", n, fi.Mode(), fi.Size())
			}
		}
		if fi, err := os.Lstat(filepath.Join(root, logs)); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v, %v, want a 0755 directory", logs, fi, err)
		}
		if _, err := os.Lstat(filepath.Join(root, keystore.StagingDirName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left behind: %v", keystore.StagingDirName, err)
		}
		// A rerun finds both logs judged and leaves them alone.
		rec.calls = rec.calls[:len(rec.calls):len(rec.calls)]
		before := len(rec.calls)
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); err != nil {
			t.Fatal(err)
		}
		rerun := []string{"chown:" + run + ":271:20"}
		if got := rec.calls[before:]; !slices.Equal(got, rerun) {
			t.Fatalf("rerun calls:\n got %q\nwant %q", got, rerun)
		}
	})
	t.Run("flag fails, rerun builds again", func(t *testing.T) {
		root, rec := setup(t)
		rec.failOn = "chflags:" + floor
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); err == nil {
			t.Fatal("a failed chflags was not an error")
		}
		if _, err := os.Lstat(filepath.Join(root, logs, keystore.FloorDirName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a floor directory was placed after a failed flag: %v", err)
		}
		rec.failOn = ""
		before := len(rec.calls)
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); err != nil {
			t.Fatal(err)
		}
		got := rec.calls[before:]
		wantRerun := append(append([]string{"chown:" + run + ":271:20"}, swap(floor)...), swap(audit)...)
		if !slices.Equal(got, wantRerun) {
			t.Fatalf("rerun calls:\n got %q\nwant %q", got, wantRerun)
		}
	})
	t.Run("unflagged is refused", func(t *testing.T) {
		root, _ := setup(t)
		if err := os.MkdirAll(filepath.Dir(logPath(root, floor)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logPath(root, floor), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		setSeam(t, &keystoreFstatSeam, func(fd int, st *unix.Stat_t) error {
			err := unix.Fstat(fd, st)
			st.Uid = svcUID
			return err
		})
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); !errors.Is(err, errKeystoreFileUntrusted) {
			t.Fatalf("got %v, want errKeystoreFileUntrusted", err)
		}
	})
	t.Run("old location", func(t *testing.T) {
		root, rec := setup(t)
		if err := os.WriteFile(filepath.Join(root, audit), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); !errors.Is(err, errKeystoreFileUntrusted) || !strings.Contains(err.Error(), "sudo k3sm install") {
			t.Fatalf("got %v, want errKeystoreFileUntrusted naming install", err)
		}
		if len(rec.calls) != 0 {
			t.Fatalf("calls over a log at the old location: %q", rec.calls)
		}
	})
	t.Run("old location in keystore-logs", func(t *testing.T) {
		root, rec := setup(t)
		if err := os.Mkdir(filepath.Join(root, logs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, logs, floor), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ensureKeystoreFiles(root, svcUID, svcGID, me); !errors.Is(err, errKeystoreFileUntrusted) || !strings.Contains(err.Error(), "sudo k3sm install") {
			t.Fatalf("got %v, want errKeystoreFileUntrusted naming install", err)
		}
		if slices.ContainsFunc(rec.calls, func(c string) bool { return strings.Contains(c, ".log") }) {
			t.Fatalf("log calls over a log at the old location: %q", rec.calls)
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
		if err := os.MkdirAll(filepath.Dir(logPath(root, audit)), 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.Symlink(target, logPath(root, audit)); err != nil {
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
		if err := os.MkdirAll(filepath.Dir(logPath(root, floor)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logPath(root, floor), []byte("x\n"), 0o644); err != nil {
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
		if _, err := os.Lstat(logPath(root, floor)); !errors.Is(err, os.ErrNotExist) {
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

// The keystore step refuses while a maintenance verb runs (the marker
// stands and keystore-lock is held), changing nothing. With the marker
// stale (no lock held) it cleans keystore-staging/, ensures the live set
// and removes the marker.
func TestKeystoreFilesRefuseDuringMaintenance(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &attrRecorder{}
	setSeam(t, &euidSeam, func() int { return 0 })
	setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
	setSeam(t, &keystoreFstatSeam, rec.fakeStat(271))
	marker := filepath.Join(root, keystore.MaintenanceMarkerName)
	if err := os.WriteFile(marker, []byte("verb=floor-rebuild\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(root, keystore.FloorLockName), os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	err = ensureKeystoreFiles(root, 271, 20, os.Getuid())
	if !errors.Is(err, errKeystoreMaintenance) {
		t.Fatalf("install while a verb holds the lock: %v, want errKeystoreMaintenance", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("install made file-attribute calls while a verb runs: %q", rec.calls)
	}
	if _, err := os.Lstat(filepath.Join(root, keystore.RunDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("install created %s while a verb runs: %v", keystore.RunDirName, err)
	}
	_ = lock.Close() // releases the flock
	// A crashed verb's leftovers in staging are removed, never read.
	left := filepath.Join(root, keystore.StagingDirName, keystore.FloorDirName+".new")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(left, keystore.UserFloorLogName), []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureKeystoreFiles(root, 271, 20, os.Getuid()); err != nil {
		t.Fatalf("install with a stale marker: %v", err)
	}
	for _, p := range []string{marker, filepath.Join(root, keystore.StagingDirName)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after install with a stale marker: %v", p, err)
		}
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
