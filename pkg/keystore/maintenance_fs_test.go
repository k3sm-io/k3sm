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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The maintenance verbs' filesystem safety (docs/design/keystore.md § "Root
// maintenance verbs"), as far as a non-root test reaches: the attribute
// writer records each call and changes nothing, and the flag source reports
// SF_APPEND. The root-run halves are cmd/k3sm's U68, U90 and U118.

// inoCall is one attribute call and the inode its descriptor held.
type inoCall struct {
	ino  uint64
	call string
}

// inoRecorder records each attribute call with its inode; before, when
// set, runs ahead of each call.
type inoRecorder struct {
	calls  []inoCall
	before func(fd int, call string)
}

func (r *inoRecorder) record(fd int, call string) error {
	if r.before != nil {
		r.before(fd, call)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	r.calls = append(r.calls, inoCall{st.Ino, call})
	return nil
}

func (r *inoRecorder) Fchown(fd, uid, gid int) error {
	if err := r.record(fd, fmt.Sprintf("fchown %d", uid)); err != nil {
		return err
	}
	return ownAsRoot(fd, uid, gid)
}

func (r *inoRecorder) Fchmod(fd int, mode uint32) error {
	if err := r.record(fd, fmt.Sprintf("fchmod %o", mode)); err != nil {
		return err
	}
	return modeAsRoot(fd, mode)
}

func (r *inoRecorder) Fchflags(fd, flags int) error {
	return r.record(fd, fmt.Sprintf("fchflags %#x", flags))
}

// of is the calls on inode ino, in order.
func (r *inoRecorder) of(ino uint64) []string {
	var out []string
	for _, c := range r.calls {
		if c.ino == ino {
			out = append(out, c.call)
		}
	}
	return out
}

func inoOf(t *testing.T, p string) (uint64, uint16) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino, st.Nlink
}

// placeArchive writes the audit archive n, root's (the data root's owner's)
// 0600, as rotate leaves it.
func placeArchive(t *testing.T, s *FileStore, n int, data string) string {
	t.Helper()
	p := filepath.Join(s.dataRoot, auditArchiveName(n))
	if err := os.WriteFile(p, []byte(data), logMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, logMode); err != nil {
		t.Fatal(err)
	}
	return p
}

// maintVerb runs one maintenance verb with attrs.
type maintVerb struct {
	name, log string
	run       func(s *FileStore, attrs FileAttrWriter) error
}

var maintVerbs = []maintVerb{
	{"floor --rebuild", userFloorLogName, func(s *FileStore, a FileAttrWriter) error {
		_, err := s.RebuildFloor(context.Background(), a)
		return err
	}},
	{"audit --rotate", auditLogName, func(s *FileStore, a FileAttrWriter) error {
		_, err := s.RotateAudit(context.Background(), a, false)
		return err
	}},
}

// TestMaintenanceOwnsBeforeUnflag (U118's order): the old log, and each
// archive rotate shifts, has its flag cleared and is made root's 0600 in
// the next two calls on its own descriptor, with no other call between. The
// flag refuses a change of owner, so the clear comes first.
func TestMaintenanceOwnsBeforeUnflag(t *testing.T) {
	for _, v := range maintVerbs {
		t.Run(v.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			watched := map[uint64]string{}
			ino, _ := inoOf(t, filepath.Join(s.dataRoot, v.log))
			watched[ino] = "the old " + v.log
			if v.log == auditLogName {
				for n := 1; n <= 3; n++ {
					ino, _ := inoOf(t, placeArchive(t, s, n, fmt.Sprintf("archive %d\n", n)))
					watched[ino] = auditArchiveName(n)
				}
			}
			rec := &inoRecorder{}
			if err := v.run(s, rec); err != nil {
				t.Fatal(err)
			}
			root := fmt.Sprintf("fchown %d", s.floorUID)
			for ino, what := range watched {
				got := rec.of(ino)
				if len(got) < 3 || got[0] != "fchflags 0x0" || got[1] != root || got[2] != "fchmod 600" {
					t.Errorf("%s's first calls are %q, want the flag clear, then root's ownership and 0600", what, got)
				}
			}
			for i, c := range rec.calls {
				if c.call == "fchflags 0x0" && watched[c.ino] != "" && (i+2 >= len(rec.calls) || rec.calls[i+1].ino != c.ino || rec.calls[i+2].ino != c.ino) {
					t.Errorf("another call came between %s's chown, chmod and flag clear", watched[c.ino])
				}
			}
			assertNoMaintenanceLeft(t, s)
		})
	}
}

// TestMaintenanceRepairsHardLinkedLog: a hard link planted on a log makes
// the steady-state check refuse it, naming the verb that repairs it; that
// verb takes the linked log as input and succeeds, and the new canonical
// log is a fresh inode with one link. For rotate the old inode is .1,
// root's 0600, and a second rotate shifts the still-linked .1 with a Warn.
func TestMaintenanceRepairsHardLinkedLog(t *testing.T) {
	for _, v := range maintVerbs {
		t.Run(v.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			p := filepath.Join(s.dataRoot, v.log)
			link := filepath.Join(s.dataRoot, "keystore-planted-link")
			if err := os.Link(p, link); err != nil {
				t.Fatal(err)
			}
			err := s.CheckLogFlags(context.Background())
			if !errors.Is(err, errLogUntrusted) {
				t.Fatalf("the check over a linked %s: %v, want errLogUntrusted", v.log, err)
			}
			verb, ok := LinkedLogRepair(err)
			if want := repairVerb(v.log); !ok || verb != want || !strings.Contains(err.Error(), want) {
				t.Fatalf("the check's error %q names %q (%v), want %q", err, verb, ok, want)
			}
			oldIno, _ := inoOf(t, p)
			if err := v.run(s, &inoRecorder{}); err != nil {
				t.Fatalf("%s over a linked log: %v, want it to repair it", v.name, err)
			}
			newIno, nlink := inoOf(t, p)
			if newIno == oldIno || nlink != 1 {
				t.Fatalf("the new %s is inode %d with %d links, want a fresh inode (not %d) with one", v.log, newIno, nlink, oldIno)
			}
			if err := s.CheckLogFlags(context.Background()); err != nil {
				t.Fatalf("the check after the repair: %v", err)
			}
			if v.log != auditLogName {
				return
			}
			one := filepath.Join(s.dataRoot, auditArchiveName(1))
			if ino, nl := inoOf(t, one); ino != oldIno || nl != 2 {
				t.Fatalf(".1 is inode %d with %d links, want the old log (%d), still linked", ino, nl, oldIno)
			}
			if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
				t.Fatalf("rotate over a linked root 0600 archive: %v, want a Warn only", err)
			}
			if ino, _ := inoOf(t, filepath.Join(s.dataRoot, auditArchiveName(2))); ino != oldIno {
				t.Fatal("the linked archive was not shifted to .2")
			}
		})
	}
}

// TestMaintenanceStagingDirIsRootOnly: the staging file is created in
// keystore-staging/, a directory of the data root's owner at 0700, never at
// a name in the data root, and the directory is gone after the run. A
// staging directory at another mode, or a symlink at its name, refuses the
// verb, changing nothing and leaving no marker.
func TestMaintenanceStagingDirIsRootOnly(t *testing.T) {
	for _, v := range maintVerbs {
		t.Run(v.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			dir := filepath.Join(s.dataRoot, stagingDirName)
			checked := false
			rec := &inoRecorder{before: func(fd int, _ string) {
				if checked {
					return
				}
				checked = true
				var st unix.Stat_t
				if err := unix.Lstat(dir, &st); err != nil {
					t.Fatalf("the staging directory during the run: %v", err)
				}
				if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != stagingDirMode || int(st.Uid) != s.floorUID {
					t.Errorf("the staging directory is mode %#o uid %d, want a directory, 0700, uid %d", st.Mode, st.Uid, s.floorUID)
				}
				buf := make([]byte, unix.PathMax)
				if err := fcntlGetPath(fd, buf); err != nil {
					t.Fatal(err)
				}
				if got := filepath.Dir(unix.ByteSliceToString(buf)); filepath.Base(got) != stagingDirName {
					t.Errorf("the first file the verb touches is in %s, want the staging directory", got)
				}
			}}
			if err := v.run(s, rec); err != nil {
				t.Fatal(err)
			}
			if !checked {
				t.Fatal("the verb made no attribute call")
			}
			assertNoMaintenanceLeft(t, s)

			for _, plant := range []struct {
				name string
				do   func() error
			}{
				{"a staging directory at 0755", func() error { return os.Mkdir(dir, 0o755) }},
				{"a symlink at the staging directory", func() error { return os.Symlink(t.TempDir(), dir) }},
			} {
				if err := plant.do(); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o755); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				before := readLog(t, s, v.log)
				err := v.run(s, &inoRecorder{})
				if !errors.Is(err, errLogUntrusted) {
					t.Errorf("%s: %v, want refused as untrusted", plant.name, err)
				}
				if string(readLog(t, s, v.log)) != string(before) {
					t.Errorf("%s: the refused verb changed %s", plant.name, v.log)
				}
				if _, err := os.Lstat(filepath.Join(s.dataRoot, maintenanceMarkerName)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s: the refused verb left the marker: %v", plant.name, err)
				}
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// fcntlGetPath fills buf with the path of the file open at fd (fcntl
// F_GETPATH).
func fcntlGetPath(fd int, buf []byte) error {
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return errno
	}
	return nil
}

// TestMaintenanceJudgesMarkerAndStale: a marker with a second link, or a
// staging file a crash left with a second link, refuses the verb; an
// archive that is not 0600 refuses rotate, and one with a second link does
// not.
func TestMaintenanceJudgesMarkerAndStale(t *testing.T) {
	t.Run("marker with two links", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		m := filepath.Join(s.dataRoot, maintenanceMarkerName)
		if err := os.WriteFile(m, nil, markerMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(m, m+".alias"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RebuildFloor(context.Background(), &inoRecorder{}); !errors.Is(err, errLogUntrusted) {
			t.Fatalf("rebuild over a linked marker: %v, want untrusted", err)
		}
		if _, err := os.Lstat(m); err != nil {
			t.Fatalf("the refused verb removed a marker it did not write: %v", err)
		}
	})
	t.Run("stale staging file with two links", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		dir := filepath.Join(s.dataRoot, stagingDirName)
		if err := os.Mkdir(dir, stagingDirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, stagingDirMode); err != nil {
			t.Fatal(err)
		}
		stale := filepath.Join(dir, floorStagingName)
		if err := os.WriteFile(stale, []byte("stale"), logMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(stale, filepath.Join(dir, "alias")); err != nil {
			t.Fatal(err)
		}
		before := readLog(t, s, userFloorLogName)
		if _, err := s.RebuildFloor(context.Background(), &inoRecorder{}); !errors.Is(err, errRebuildRefused) || !errors.Is(err, errLogUntrusted) {
			t.Fatalf("rebuild over a linked stale staging file: %v, want refused as untrusted", err)
		}
		if string(readLog(t, s, userFloorLogName)) != string(before) {
			t.Fatal("the refused rebuild changed the floor")
		}
	})
	t.Run("archives", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		p := placeArchive(t, s, 1, "a\n")
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); !errors.Is(err, errRotateRefused) {
			t.Fatalf("rotate over a 0644 archive: %v, want refused", err)
		}
		if err := os.Chmod(p, logMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(p, filepath.Join(s.dataRoot, "keystore-archive-alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
			t.Fatalf("rotate over a linked root 0600 archive: %v, want a Warn only", err)
		}
	})
}

// TestRotateFinishesAfterCrashBeforeNewLog: a crash after the old audit
// log was renamed to .1 and before the new log was renamed in leaves the
// marker, no canonical log and .1; the rerun writes, flags and hands over a
// fresh log, flags .1 and removes the marker. Without the marker a missing
// audit log refuses, as before.
func TestRotateFinishesAfterCrashBeforeNewLog(t *testing.T) {
	crash := func(t *testing.T, s *FileStore, marker bool) uint64 {
		t.Helper()
		p := filepath.Join(s.dataRoot, auditLogName)
		if err := os.WriteFile(p, []byte("old line\n"), logMode); err != nil {
			t.Fatal(err)
		}
		// The crash left the old log root's 0600, as .1.
		if err := os.Chown(p, s.floorUID, s.floorGID); err != nil {
			t.Fatal(err)
		}
		ino, _ := inoOf(t, p)
		if err := os.Rename(p, filepath.Join(s.dataRoot, auditArchiveName(1))); err != nil {
			t.Fatal(err)
		}
		if marker {
			if err := os.WriteFile(filepath.Join(s.dataRoot, maintenanceMarkerName), nil, markerMode); err != nil {
				t.Fatal(err)
			}
		}
		return ino
	}
	t.Run("with the marker", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		oneIno := crash(t, s, true)
		rec := &inoRecorder{}
		rep, err := s.RotateAudit(context.Background(), rec, false)
		if err != nil {
			t.Fatalf("the rerun after the crash: %v, want it to finish", err)
		}
		if rep.Archives != 1 {
			t.Errorf("kept %d archives, want 1", rep.Archives)
		}
		newIno, nlink := inoOf(t, filepath.Join(s.dataRoot, auditLogName))
		if newIno == oneIno || nlink != 1 {
			t.Fatalf("the canonical log after the rerun is inode %d with %d links", newIno, nlink)
		}
		svc := fmt.Sprintf("fchown %d", s.uid)
		if got := rec.of(newIno); len(got) < 2 || got[len(got)-2] != fmt.Sprintf("fchflags %#x", sfAppend) || got[len(got)-1] != svc {
			t.Errorf("the new log's calls %q, want it flagged and then handed over", got)
		}
		if got := rec.of(oneIno); len(got) != 1 || got[0] != fmt.Sprintf("fchflags %#x", sfAppend) {
			t.Errorf(".1's calls %q, want its flag set", got)
		}
		if b, err := os.ReadFile(filepath.Join(s.dataRoot, auditArchiveName(1))); err != nil || string(b) != "old line\n" {
			t.Errorf(".1 holds %q, %v; want the old log", b, err)
		}
		assertNoMaintenanceLeft(t, s)
		if err := s.CheckLogFlags(context.Background()); err != nil {
			t.Fatalf("the check after the rerun: %v", err)
		}
	})
	t.Run("without the marker", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		crash(t, s, false)
		if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); !errors.Is(err, errRotateRefused) {
			t.Fatalf("rotate with no audit log and no marker: %v, want refused", err)
		}
		if _, err := os.Lstat(filepath.Join(s.dataRoot, auditLogName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused rotate made an audit log: %v", err)
		}
		assertNoMaintenanceLeft(t, s)
	})
}

// TestAuditRootRefusesMissingLogInMaintenance: with no user scopes a
// missing audit log is Phase A and AuditRoot writes nothing; while the
// maintenance marker stands it is a rotate stopped part-way, and AuditRoot
// says so instead of skipping the line.
func TestAuditRootRefusesMissingLogInMaintenance(t *testing.T) {
	s, _ := newMasteredStore(t)
	withFileLogs(t, s)
	if err := os.Remove(filepath.Join(s.dataRoot, auditLogName)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.AuditRoot(ctx, "list", "", "ok"); err != nil {
		t.Fatalf("AuditRoot with no audit log and no marker: %v, want nil", err)
	}
	if err := os.WriteFile(filepath.Join(s.dataRoot, maintenanceMarkerName), nil, markerMode); err != nil {
		t.Fatal(err)
	}
	err := s.AuditRoot(ctx, "list", "", "ok")
	if !errors.Is(err, errAuditMissingInMaintenance) || !strings.Contains(err.Error(), "audit --rotate") {
		t.Fatalf("AuditRoot with no audit log while the marker stands: %v, want the rerun named", err)
	}
}

// TestMaintenanceMarkerBeforeLocks (the design's order): the verb writes
// the marker before it waits for the locks, so it stands while the verb
// waits for a held store lock; once the lock is free the verb finishes and
// removes it. Past the 30 s wait the verb refuses, naming the service-user
// holder and k3sm stop, and removes the marker it wrote, but keeps one an
// earlier run left.
func TestMaintenanceMarkerBeforeLocks(t *testing.T) {
	hold := func(t *testing.T, s *FileStore) *os.File {
		t.Helper()
		f, err := os.Open(filepath.Join(s.dir, lockName))
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		return f
	}
	marker := func(s *FileStore) error {
		_, err := os.Lstat(filepath.Join(s.dataRoot, maintenanceMarkerName))
		return err
	}
	synctest.Test(t, func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		held := hold(t, s)
		done := make(chan error, 1)
		go func() {
			_, err := s.RotateAudit(context.Background(), &inoRecorder{}, false)
			done <- err
		}()
		synctest.Wait()
		if err := marker(s); err != nil {
			t.Fatalf("the marker while the verb waits for the store lock: %v, want it written first", err)
		}
		if err := held.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("rotate once the lock is free: %v", err)
		}
		if err := marker(s); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the marker after the run: %v", err)
		}
	})
	for _, left := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			if left {
				if err := os.WriteFile(filepath.Join(s.dataRoot, maintenanceMarkerName), nil, markerMode); err != nil {
					t.Fatal(err)
				}
			}
			held := hold(t, s)
			defer func() { _ = held.Close() }()
			_, err := s.RebuildFloor(context.Background(), &inoRecorder{})
			if !errors.Is(err, errStoreLockHeld) || !strings.Contains(err.Error(), "k3sm stop") || !strings.Contains(err.Error(), "service user") {
				t.Fatalf("rebuild past the 30 s wait: %v, want the service-user holder and k3sm stop named", err)
			}
			err = marker(s)
			if left && err != nil {
				t.Errorf("the timed-out verb removed a marker an earlier run left: %v", err)
			}
			if !left && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the timed-out verb left its own marker: %v", err)
			}
		})
	}
}

// TestRemoveScopeWalksJudgedRoot: rm-scope's tree walk starts from the
// keystore root it judged, so a decoy tree swapped in at the keystore's
// path afterwards is never walked or removed.
func TestRemoveScopeWalksJudgedRoot(t *testing.T) {
	s, _, _ := fileLogScope(t)
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	real := s.dir + ".real"
	if err := os.Rename(s.dir, real); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(s.dir, userScopesName, "1001")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(decoy, scopeKeyName)
	if err := os.WriteFile(keep, []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeScopeTree(root, "1001"); err != nil {
		t.Fatalf("removeScopeTree: %v", err)
	}
	if _, err := os.Lstat(keep); err != nil {
		t.Fatalf("the decoy tree at the keystore's path was walked: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(real, userScopesName, "1001")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the judged keystore's scope is still there: %v", err)
	}
}
