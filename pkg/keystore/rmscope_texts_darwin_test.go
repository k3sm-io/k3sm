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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// rmRerunLine is the one command rm-scope ever prints for uid 1001: its
// own rerun, built from the integer uid.
const rmRerunLine = "rerun sudo k3sm keys rm-scope user/1001 --yes"

// checkRmScopeText checks a stop's text at the layer the operator reads:
// no by-hand action (no rm, no "remove it as root", no flag to clear, no
// delete), the rerun line present exactly when rerun is set, and no command
// but sudo k3sm keys rm-scope user/1001 --yes, nor the word rerun at all
// where a rerun cannot help.
func checkRmScopeText(t *testing.T, msg string, rerun bool) {
	t.Helper()
	for _, bad := range []string{"rm -", "remove it as root", "clear the flag", "Root may", "its owner may", "by hand", "administrator", "chflags", "delete", "k3sm doctor"} {
		if strings.Contains(msg, bad) {
			t.Errorf("the error %q offers %q, an action by hand", msg, bad)
		}
	}
	if got := strings.Contains(msg, rmRerunLine); got != rerun {
		t.Errorf("the error %q holds the rerun line: %v, want %v", msg, got, rerun)
	}
	if !rerun && strings.Contains(strings.ToLower(msg), "rerun") {
		t.Errorf("the error %q says rerun, and a rerun cannot help", msg)
	}
	for rest := msg; ; {
		i := strings.Index(rest, "sudo")
		if i < 0 {
			break
		}
		if !strings.HasPrefix(rest[i:], "sudo k3sm keys rm-scope user/1001 --yes") {
			t.Errorf("the error %q holds a command other than sudo k3sm keys rm-scope user/1001 --yes", msg)
			break
		}
		rest = rest[i+len("sudo"):]
	}
}

// Every stop of RemoveScope returns text, at the layer the operator reads,
// that names what it left for reading and offers no action by hand, and
// holds the rerun line exactly where a rerun can help (rmRerunCannotHelp)
// and nowhere else. Each case drives RemoveScope into one stop through its
// seams. A rerun cannot help: the emptied scope directory moved away
// before its rmdir, a symlink planted at the scope's name, another user's
// flag on .user (the seam stands for its owner), another scope's directory
// at the name, a directory on another device in the tree, a tree nested
// too deep, a twice-linked flagged FIFO rm-scope does not clear, and a
// final rmdir whose probe fails. A rerun can help: a take that stops, a
// flag set again on scope.key after rm-scope cleared it, and a record
// whose data-root fsync fails after its rename. A system flag cannot be
// set without root; its text is pinned at the flagKept layer
// (TestRmScopeOffersNoCommand).
func TestRmScopeErrorTextsOfferNoCommand(t *testing.T) {
	if asRoot() {
		t.Skip("the cases set the test user's own flags and own its tree; the root cases are in the root-run tests")
	}
	for _, tc := range []struct {
		name  string
		want  error
		rerun bool
		setup func(t *testing.T, s *FileStore, server, dir string)
	}{
		{"moved before its rmdir", errScopeDirMoved, false, func(t *testing.T, _ *FileStore, _, dir string) {
			done := false
			setSeam(t, &rmBeforeScopeRmdir, func(step rmdirStep) {
				if done || step != rmdirBeforeStat {
					return
				}
				done = true
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"planted at the scope's name", errPlanted, false, func(t *testing.T, _ *FileStore, _, dir string) {
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+".away", dir); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"another user's flag on .user", errSharedDirFlag, false, func(t *testing.T, s *FileStore, _, dir string) {
			shared := filepath.Dir(dir)
			t.Cleanup(func() { _ = unix.Chflags(shared, 0) })
			setScopeFlags(t, shared, unix.UF_IMMUTABLE, false)
			setSeam(t, &rmSharedOwner, func(*unix.Stat_t) uint32 { return s.uid + 1 })
		}},
		{"another scope at the name", errNotJudgedScope, false, func(t *testing.T, s *FileStore, server, dir string) {
			userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(scopeDir(server, "1002"), dir); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"a directory on another device", errScopeForeignDir, false, func(t *testing.T, _ *FileStore, _, dir string) {
			mount := filepath.Join(dir, scopeEntriesName, "mounted")
			if err := os.Mkdir(mount, 0o700); err != nil {
				t.Fatal(err)
			}
			ino, _ := inoOf(t, mount)
			otherDeviceFor(t, ino)
		}},
		{"nested too deep", errScopeTreeDeep, false, func(t *testing.T, _ *FileStore, _, dir string) {
			p := filepath.Join(dir, scopeEntriesName)
			for i := 0; i <= maxScopeTreeDepth; i++ {
				p = filepath.Join(p, fmt.Sprintf("c%d", i))
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"a twice-linked flagged FIFO", errFlagLeft, false, func(t *testing.T, _ *FileStore, _, dir string) {
			t.Cleanup(func() { unflagScopeTree(dir) })
			fifo := filepath.Join(dir, "planted-fifo")
			if err := unix.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(fifo, filepath.Join(dir, scopeEntriesName, "fifo-alias")); err != nil {
				t.Fatal(err)
			}
			setScopeFlagsByPath(t, fifo, unix.UF_IMMUTABLE)
		}},
		{"the rmdir's probe fails", errScopeRmdirUnconfirmed, false, func(t *testing.T, _ *FileStore, _, _ string) {
			setSeam(t, &rmProbeMkdir, func(int, string, uint32) error { return unix.EIO })
		}},
		{"a take that stops", unix.EIO, true, func(t *testing.T, _ *FileStore, _, _ string) {
			setSeam(t, &rmTakeDir, func(int) error { return unix.EIO })
		}},
		{"a flag set again on scope.key", unix.EPERM, true, func(t *testing.T, _ *FileStore, _, dir string) {
			t.Cleanup(func() { unflagScopeTree(dir) })
			ino := setScopeFlags(t, filepath.Join(dir, scopeKeyName), unix.UF_IMMUTABLE, false)
			saved := scopeFchflags
			setSeam(t, &scopeFchflags, func(fd, flags int) error {
				if err := saved(fd, flags); err != nil {
					return err
				}
				var st unix.Stat_t
				if err := unix.Fstat(fd, &st); err != nil || st.Ino != ino {
					return err
				}
				return unix.Fchflags(fd, flags|unix.UF_IMMUTABLE)
			})
		}},
		{"the record's fsync fails after its rename", errCommitted, true, func(t *testing.T, _ *FileStore, _, _ string) {
			setSeam(t, &removedScopesFsync, func(int) error { return unix.EIO })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			tc.setup(t, s, server, dir)
			_, err := s.RemoveScope(t.Context(), 1001)
			if !errors.Is(err, tc.want) {
				t.Fatalf("rm-scope: %v, want %v", err, tc.want)
			}
			// The record's own errors and errNotJudgedScope are not rmStopped's
			// to judge; every other stop follows the cannot-help list.
			if tc.want != errCommitted && tc.want != errNotJudgedScope && rmRerunCannotHelp(err) == tc.rerun {
				t.Errorf("rmRerunCannotHelp(%v) = %v, and the case says a rerun helps: %v", err, !tc.rerun, tc.rerun)
			}
			checkRmScopeText(t, err.Error(), tc.rerun)
		})
	}
	// A scope directory that is gone when the walk comes to open it was not
	// removed by this run, and nothing was written: a refusal saying it was
	// found absent, never that it was removed.
	t.Run("absent at the open", func(t *testing.T) {
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		if err := os.Remove(filepath.Join(dir, scopeKeyName)); err != nil {
			t.Fatal(err)
		}
		setSeam(t, &rmBeforeTree, func() {
			if err := os.Rename(dir, dir+".away"); err != nil {
				t.Fatal(err)
			}
		})
		_, err := s.RemoveScope(t.Context(), 1001)
		if err == nil || Committed(err) {
			t.Fatalf("rm-scope of a keyless scope found absent: %v, want a refusal", err)
		}
		msg := err.Error()
		checkRmScopeText(t, msg, false)
		if !strings.Contains(msg, "absent at its name") || strings.Contains(msg, "removed user/1001") || strings.Contains(msg, "removed the directory") {
			t.Errorf("the report %q does not say the scope was found absent, or says it was removed", msg)
		}
	})
}
