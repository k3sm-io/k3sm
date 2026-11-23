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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	p := filepath.Join(s.dataRoot, logsDirName, auditDirName, archivesDirName, auditArchiveName(n))
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

// TestSwapCallOrder (U118's order): each verb hands the new log to the
// service user, sets its mode and flags it, in that order, while it is in
// keystore-staging/, and those are the verb's only calls on a reachable or
// new file: the old log takes none while reachable (its flag is cleared
// only once it is retired into staging, and these non-root tests' logs
// carry no flag, so it takes none at all), no archive takes any, and the
// logs directory is never chmod'd (there is no gate).
func TestSwapCallOrder(t *testing.T) {
	for _, v := range maintVerbs {
		t.Run(v.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			p := filepath.Join(s.dataRoot, logsDirName, logDirOf(v.log), v.log)
			oldIno, _ := inoOf(t, p)
			var archives []uint64
			if v.log == auditLogName {
				for n := 1; n <= 3; n++ {
					ino, _ := inoOf(t, placeArchive(t, s, n, fmt.Sprintf("archive %d\n", n)))
					archives = append(archives, ino)
				}
			}
			rec := &inoRecorder{}
			if err := v.run(s, rec); err != nil {
				t.Fatal(err)
			}
			newIno, nlink := inoOf(t, p)
			if newIno == oldIno || nlink != 1 {
				t.Fatalf("the new log is inode %d with %d links, want a fresh inode with one", newIno, nlink)
			}
			svc := fmt.Sprintf("fchown %d", s.uid)
			flag := fmt.Sprintf("fchflags %#x", sfAppend)
			if got, want := rec.of(newIno), []string{svc, "fchmod 600", flag}; !slices.Equal(got, want) {
				t.Errorf("the new log's calls %q, want %q", got, want)
			}
			if got := rec.of(oldIno); len(got) != 0 {
				t.Errorf("the old log's calls %q, want none", got)
			}
			for _, a := range archives {
				if got := rec.of(a); len(got) != 0 {
					t.Errorf("an archive took calls %q", got)
				}
			}
			if len(rec.calls) != 3 {
				t.Errorf("calls %v, want the new log's three alone", rec.calls)
			}
			assertNoMaintenanceLeft(t, s)
		})
	}
}

// TestMaintenanceRepairsHardLinkedLog: a hard link planted on a log makes
// the steady-state check refuse it, naming the verb that repairs it; that
// verb takes the linked log as input and succeeds, and the new canonical
// log is a fresh inode with one link. For rotate .1 is a fresh root 0600
// copy of the old log, and the planted link keeps only the retired inode.
func TestMaintenanceRepairsHardLinkedLog(t *testing.T) {
	for _, v := range maintVerbs {
		t.Run(v.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			p := filepath.Join(s.dataRoot, logsDirName, logDirOf(v.log), v.log)
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
			one := filepath.Join(s.dataRoot, logsDirName, auditDirName, archivesDirName, auditArchiveName(1))
			if ino, nl := inoOf(t, one); ino == oldIno || nl != 1 {
				t.Fatalf(".1 is inode %d with %d links, want a fresh copy, not the old log (%d)", ino, nl, oldIno)
			}
			if ino, nl := inoOf(t, link); ino != oldIno || nl != 1 {
				t.Fatalf("the planted link is inode %d with %d links, want the retired old log alone", ino, nl)
			}
		})
	}
}

// TestMaintenanceStagingDirIsRootOnly: the replacement directory is built in
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
				if got := unix.ByteSliceToString(buf); !strings.Contains(got, "/"+stagingDirName+"/") {
					t.Errorf("the first file the verb touches is %s, want one in the staging directory", got)
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

// TestMaintenanceJudgesMarkerAndStale: a root marker with a second link is
// read, with a Warn; a staging file a crash left is cleaned; an
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
		if _, err := s.RebuildFloor(context.Background(), &inoRecorder{}); err != nil {
			t.Fatalf("rebuild over a linked root marker: %v, want it read (a second link is a Warn)", err)
		}
	})
	t.Run("stale staging left by a crash is cleaned", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		dir := filepath.Join(s.dataRoot, stagingDirName)
		left := filepath.Join(dir, newDirName(userFloorLogName))
		if err := os.MkdirAll(left, stagingDirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, stagingDirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(left, userFloorLogName), []byte("forged\n"), logMode); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RebuildFloor(context.Background(), &inoRecorder{}); err != nil {
			t.Fatalf("rebuild over stale staging: %v, want it cleaned", err)
		}
		if bytes.Contains(readLog(t, s, userFloorLogName), []byte("forged")) {
			t.Fatal("the rebuild read what a crash left in staging")
		}
		assertNoMaintenanceLeft(t, s)
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
		if err := os.Link(p, filepath.Join(s.dataRoot, logsDirName, auditDirName, "keystore-archive-alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
			t.Fatalf("rotate over a linked root 0600 archive: %v, want a Warn only", err)
		}
		archives := filepath.Join(s.dataRoot, logsDirName, auditDirName, archivesDirName)
		var st unix.Stat_t
		if err := unix.Lstat(archives, &st); err != nil || st.Mode&0o7777 != archivesDirMode {
			t.Fatalf("the rotated %s is at mode %04o (%v), want 0700", archivesDirName, st.Mode&0o7777, err)
		}
		if _, err := os.Stat(filepath.Join(archives, auditArchiveName(2))); err != nil {
			t.Fatalf("the old .1 is not .2 in %s: %v", archivesDirName, err)
		}
		if err := os.Chmod(archives, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); !errors.Is(err, errRotateRefused) || !errors.Is(err, errLogUntrusted) {
			t.Fatalf("rotate over a 0755 %s: %v, want refused as untrusted", archivesDirName, err)
		}
	})
}

// stepCrash fails the step seam at one step, and counts the steps seen.
type stepCrash struct {
	inoRecorder
	at   string
	seen []string
}

func (c *stepCrash) BeforeSwapStep(step string) error {
	c.seen = append(c.seen, step)
	if step == c.at {
		return fmt.Errorf("crash before %s", step)
	}
	return nil
}

// TestSwapRerunFromEachStep: a verb stopped before each step leaves the
// canonical log either the complete old one or the complete new one,
// judged with one link; the rerun leaves a valid set and no marker. Past
// the report (step 4) and the swap, the rerun prints the crashed run's
// report and does not run again: a rotate does not archive the new empty
// log, and a rebuild that dropped lines still reports them. Running the
// other verb after the crash harms nothing.
func TestSwapRerunFromEachStep(t *testing.T) {
	for _, v := range maintVerbs {
		for _, at := range SwapSteps {
			for _, other := range []bool{false, true} {
				name := v.name + "/" + at
				if other {
					name += "/other verb first"
				}
				t.Run(name, func(t *testing.T) {
					s, _, _ := fileLogScope(t)
					p := filepath.Join(s.dataRoot, logsDirName, logDirOf(v.log), v.log)
					if v.log == userFloorLogName {
						appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
					} else {
						appendLogBytes(t, s, auditLogName, []byte("old audit line\n"))
					}
					old := readLog(t, s, v.log)
					c := &stepCrash{at: at}
					err := v.run(s, c)
					if err == nil {
						t.Fatalf("the verb did not fail at %s", at)
					}
					got := readLog(t, s, v.log)
					committed := slices.Index(SwapSteps, at) > slices.Index(SwapSteps, swapStepSwap)
					if Committed(err) != committed {
						t.Fatalf("a failure at %s: Committed %v, want %v (%v)", at, Committed(err), committed, err)
					}
					if committed == bytes.Equal(got, old) {
						t.Fatalf("after a crash at %s the log holds %q (old %q), want the %s set", at, got, old, map[bool]string{true: "new", false: "old"}[committed])
					}
					if _, nl := inoOf(t, p); nl != 1 {
						t.Fatalf("the log has %d links after the crash", nl)
					}
					if other {
						o := maintVerbs[0]
						if o.log == v.log {
							o = maintVerbs[1]
						}
						if err := o.run(s, &inoRecorder{}); err != nil {
							t.Fatalf("%s after a crashed %s: %v", o.name, v.name, err)
						}
						again := readLog(t, s, v.log)
						if committed && v.log == auditLogName {
							// The rebuild reported the committed rotate with
							// one audit line, before it replaced the marker.
							line := []byte(`"op":"` + verbRotate + `","via":"root","scope":"system","name":"-","namespace":"","result":"committed"}` + "\n")
							i := bytes.LastIndexByte(again[:len(again)-1], '\n')
							if i < 0 || !bytes.HasSuffix(again, line) {
								t.Fatalf("%s after a committed %s: no committed audit line ending %q", o.name, v.name, again)
							}
							again = again[:i]
						}
						if !bytes.Equal(again, got) {
							t.Fatalf("%s changed %s: %q, was %q", o.name, v.log, again, got)
						}
					}
					var rerr error
					var rb RebuildReport
					if v.log == userFloorLogName {
						rb, rerr = s.RebuildFloor(context.Background(), &inoRecorder{})
					} else {
						_, rerr = s.RotateAudit(context.Background(), &inoRecorder{}, false)
					}
					if rerr != nil {
						t.Fatalf("the rerun after a crash at %s: %v", at, rerr)
					}
					if v.log == userFloorLogName && !other && rb.Dropped != 1 {
						t.Errorf("the rerun reports %d dropped lines, want the crashed run's 1", rb.Dropped)
					}
					if v.log == auditLogName && !other {
						one, err := os.ReadFile(filepath.Join(s.dataRoot, logsDirName, auditDirName, archivesDirName, auditArchiveName(1)))
						if err != nil || !bytes.Equal(one, old) {
							t.Errorf(".1 after the rerun holds %q, %v; want the old log %q", one, err, old)
						}
					}
					if err := s.CheckLogFlags(context.Background()); err != nil {
						t.Fatalf("the check after the rerun: %v", err)
					}
					assertNoMaintenanceLeft(t, s)
				})
			}
		}
	}
}

// TestOldLogUnflaggedServiceOwnedRefused: an old log whose SF_APPEND flag
// is clear is taken as input only when root owns it; owned by the service
// user it could have been rewritten, and the verb refuses. A flagged old
// log is taken, and so is one with more than one link.
func TestOldLogUnflaggedServiceOwnedRefused(t *testing.T) {
	s := &FileStore{uid: 501, floorUID: 0}
	for _, tt := range []struct {
		name  string
		owner uint32
		flags uint32
		nlink uint16
		want  error
	}{
		{"flagged, the service user's", 501, sfAppend, 1, nil},
		{"flagged, two links", 501, sfAppend, 2, nil},
		{"unflagged, root's (a restore)", 0, 0, 1, nil},
		{"unflagged, the service user's", 501, 0, 1, errOldLogUnflagged},
		{"unflagged, another user's", 777, 0, 1, errOldLogUnflagged},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := unix.Stat_t{Mode: unix.S_IFREG | logMode, Uid: tt.owner, Nlink: tt.nlink}
			err := s.judgeOldLog(userFloorLogName, &st, tt.flags)
			if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

// TestAuditRootRefusesMissingLogInMaintenance: with no user scopes a
// missing audit log is Phase A and AuditRoot writes nothing; while the
// maintenance marker stands it was removed (the swap never leaves it
// missing), and AuditRoot says so, naming install, instead of skipping the
// line.
func TestAuditRootRefusesMissingLogInMaintenance(t *testing.T) {
	s, _ := newMasteredStore(t)
	withFileLogs(t, s)
	if err := os.Remove(filepath.Join(s.dataRoot, logsDirName, auditDirName, auditLogName)); err != nil {
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
	if !errors.Is(err, errAuditMissingInMaintenance) || !strings.Contains(err.Error(), "sudo k3sm install") || strings.Contains(err.Error(), "audit --rotate") {
		t.Fatalf("AuditRoot with no audit log while the marker stands: %v, want install named", err)
	}
}

// TestMaintenanceLocksBeforeMarker (the design's order): the verb takes
// the locks, then writes the marker, so no marker stands while it waits for
// a held store lock; once the lock is free the verb finishes and removes
// it. Past the 30 s wait the verb refuses, naming the service-user holder
// and k3sm stop, and leaves a marker an earlier run left as it was.
func TestMaintenanceLocksBeforeMarker(t *testing.T) {
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
		if err := marker(s); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the marker while the verb waits for the store lock: %v, want none yet", err)
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
				t.Errorf("the timed-out verb left a marker: %v", err)
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
	if err := removeScopeTree(root, s.dir, "1001", s.uid); err != nil {
		t.Fatalf("removeScopeTree: %v", err)
	}
	if _, err := os.Lstat(keep); err != nil {
		t.Fatalf("the decoy tree at the keystore's path was walked: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(real, userScopesName, "1001")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the judged keystore's scope is still there: %v", err)
	}
}
