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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// addInheritableACL puts a real extended ACL entry on p with chmod +a, granted with
// the test user's own rights: everyone may add a subdirectory, which is
// also inherited by directories created in p.
func addInheritableACL(t *testing.T, p string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow add_subdirectory,directory_inherit", p).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v: %s", err, out)
	}
}

// pathHasACL reports whether p carries an extended ACL entry, read on a
// descriptor through hasExtendedACL.
func pathHasACL(t *testing.T, p string) bool {
	t.Helper()
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	acl, err := hasExtendedACL(fd)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

// A directory mkdirAt creates under a parent carrying an inheritable ACL
// entry carries none: a plain mkdir beside it inherits the entry (the
// setup is real), the one mkdirAt made has it removed before the handover.
func TestMkdirAtStripsInheritedACL(t *testing.T) {
	s, _, _ := fileLogScope(t)
	parent := t.TempDir()
	addInheritableACL(t, parent)
	control := filepath.Join(parent, "plain")
	if err := os.Mkdir(control, 0o700); err != nil {
		t.Fatal(err)
	}
	if !pathHasACL(t, control) {
		t.Fatal("a plain mkdir under the parent inherited no ACL entry: the setup does not test anything")
	}
	pr, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	if _, err := s.mkdirAt(pr, "made"); err != nil {
		t.Fatalf("mkdirAt: %v", err)
	}
	if pathHasACL(t, filepath.Join(parent, "made")) {
		t.Fatal("the directory mkdirAt made carries the parent's inherited ACL entry")
	}
}

// A root-owned 0700 directory at the name that carries an extended ACL is
// finished, its ACL removed first, but never as proven: its key was listed
// by an earlier run that stopped at the take (it would prove the removal
// without the ACL), and the rerun removes it, keeps the key listed, and is
// committed, saying the leftover carried an ACL and that rm-scope cannot
// confirm it was the uid's live scope.
func TestRemoveScopeRootLeftoverWithACLIsUnproven(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	saved := rmTakeDir
	rmTakeDir = func(int) error { return unix.EIO }
	_, err := s.RemoveScope(t.Context(), 1001)
	rmTakeDir = saved
	if !Committed(err) {
		t.Fatalf("run 1, stopped at the take after listing: %v, want committed", err)
	}
	addInheritableACL(t, dir)
	asTakenRerun(t, s, dir)
	res, err := s.RemoveScope(t.Context(), 1001)
	if !Committed(err) || res.Recorded {
		t.Fatalf("the rerun over a root-owned leftover with an ACL: %v, recorded %v; want committed, not exit 0", err, res.Recorded)
	}
	for _, want := range []string{"root-owned leftover", "extended ACL", "cannot confirm it was the live scope of user/1001"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the leftover is still there: %v", err)
	}
	if !readRecord(t, s).listed(1001) {
		t.Fatal("the key the earlier run listed is no longer listed")
	}
}

// A root-owned 0700 directory at the name whose scope.key opens as this
// uid's but is not in the record before the run (the ACL hole: the service
// user moved a root-owned directory there and put a fresh key in it) is
// removed and its key listed, but the result is committed, never exit 0:
// rm-scope cannot confirm it was the uid's live scope.
func TestRemoveScopeRootLeftoverUnlistedKeyIsNotExitZero(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	asTakenRerun(t, s, dir)
	res, err := s.RemoveScope(t.Context(), 1001)
	if err == nil || !Committed(err) || res.Recorded {
		t.Fatalf("rm-scope over a root-owned leftover holding an unlisted key: %v, recorded %v; want committed", err, res.Recorded)
	}
	for _, want := range []string{"root-owned leftover", "was not listed before this run", "cannot confirm it was the live scope of user/1001", "delivery record was not checked"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not say %q", err, want)
		}
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the leftover is still there: %v", err)
	}
	if !readRecord(t, s).listed(1001) {
		t.Fatal("the leftover's key is not listed")
	}
}

// A take stopped before any of its steps (through the seam: the first
// fchmod, the fchown, the second fchmod, the ACL removal, the final fstat),
// over a scope directory carrying a real extended ACL whose mode the
// service user widened after the judge, leaves a directory a rerun
// finishes, and run 1's text offers the rerun line. Stopped at the first
// fchmod, it is the service user's at the widened mode with its ACL: the
// judge reads through the mode, so the rerun judges it and finishes,
// listed (exit 0). Stopped before the fchown, it is the service user's at
// 0700 (the first fchmod ran) with its ACL: the same.
// Stopped after the fchown and before the ACL removal, it is root's (the
// service-uid seam: the test's own uid stands for root) with the ACL: the
// rerun removes the ACL and finishes, committed, unproven. Stopped after
// the ACL removal, it is a plain taken leftover whose key the first run
// listed: exit 0.
func TestRemoveScopeTakeStopAtEachStepRerunFinishes(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root")
	}
	for step := 0; step < len(rmTakeSteps); step++ {
		t.Run(strconv.Itoa(step), func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			addInheritableACL(t, dir)
			// After the judge, the service user widens its directory's mode.
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Chmod(dir, 0o750); err != nil {
					t.Fatal(err)
				}
			})
			setSeam(t, &rmTakeStep, func(at int) error {
				if at == step {
					return unix.EIO
				}
				return nil
			})
			_, err := s.RemoveScope(t.Context(), 1001)
			if !errors.Is(err, unix.EIO) || !Committed(err) {
				t.Fatalf("run 1, the take stopped at step %d: %v, want committed EIO", step, err)
			}
			if !strings.Contains(err.Error(), rmRerunLine) {
				t.Errorf("run 1, the take stopped at step %d: %q offers no rerun, and a rerun finishes", step, err)
			}
			rmTakeStep, rmBeforeTree = nil, nil
			var st unix.Stat_t
			if err := unix.Lstat(dir, &st); err != nil {
				t.Fatal(err)
			}
			if want := map[bool]uint32{true: 0o750, false: 0o700}[step == 0]; uint32(st.Mode&0o7777) != want {
				t.Fatalf("after run 1 the scope directory is at %#o, want %#o", st.Mode&0o7777, want)
			}
			acl := pathHasACL(t, dir)
			if wantACL := step <= 3; acl != wantACL {
				t.Fatalf("after run 1 the scope directory carries an ACL: %v, want %v", acl, wantACL)
			}
			if step >= 2 {
				// The fchown ran: the directory is root's.
				asTakenRerun(t, s, dir)
			}
			res, err := s.RemoveScope(t.Context(), 1001)
			if step == 2 || step == 3 {
				if !Committed(err) || res.Recorded || !strings.Contains(err.Error(), "extended ACL") {
					t.Fatalf("the rerun over root's directory with an ACL: %v, recorded %v; want committed, unproven", err, res.Recorded)
				}
			} else if err != nil || !res.Recorded {
				t.Fatalf("the rerun: %v, recorded %v; want removed and listed", err, res.Recorded)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
			if !readRecord(t, s).listed(1001) {
				t.Fatal("the scope is not listed")
			}
		})
	}
}

// A root-owned leftover whose ACL rm-scope removed, followed by a record
// write that fails before its rename, is committed (the ACL removal
// stands), never "nothing was changed".
func TestRemoveScopeACLStrippedThenStopIsCommitted(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	addInheritableACL(t, dir)
	asTakenRerun(t, s, dir)
	// A non-empty directory at the record's temporary name fails the write
	// before its rename.
	block := filepath.Join(s.dataRoot, removedScopesTemp)
	if err := os.MkdirAll(filepath.Join(block, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := s.RemoveScope(t.Context(), 1001)
	if err == nil || !Committed(err) {
		t.Fatalf("rm-scope stopped after stripping the ACL: %v, want committed", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "removed the extended ACL") || strings.Contains(msg, "nothing was changed") {
		t.Errorf("the error %q does not say the ACL was removed, or says nothing was changed", msg)
	}
	if pathHasACL(t, dir) {
		t.Fatal("the leftover still carries its ACL")
	}
}
