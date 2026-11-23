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
// delete, nothing to restore), the rerun line present exactly when rerun is set, and no command
// but sudo k3sm keys rm-scope user/1001 --yes, nor the word rerun at all
// where a rerun cannot help.
func checkRmScopeText(t *testing.T, msg string, rerun bool) {
	t.Helper()
	checkRmScopeCommands(t, msg)
	for _, bad := range []string{"rm -", "remove it as root", "clear the flag", "Root may", "its owner may", "by hand", "administrator", "chflags", "delete", "k3sm doctor", "restore it"} {
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

// Every text rm-scope builds, at the layer the operator reads, names what
// it found or left for reading and offers no action by hand, and holds
// the rerun line exactly where a rerun can help (rmRerunCannotHelp) and
// nowhere else. Each case drives RemoveScope into one stop or committed
// result through its seams.
//
// Before the walk: the scope directory absent (found absent, no advice),
// a regular file at the scope's name and a scope directory another user
// owns (named for reading, no command), and the floor's size that does
// not read. In the walk, a rerun cannot help: the emptied scope directory
// moved away before its rmdir, a symlink planted at the scope's name,
// another user's flag on .user (the seam stands for its owner), a system
// flag on .user (the seam reports it), another scope's directory at the
// name, a directory on another device in the tree, a tree nested too
// deep, a twice-linked flagged FIFO rm-scope does not clear, a final rmdir
// whose probe fails, and the directory absent at the walk's open with the
// fsync of .user failing. A rerun can help: a take that stops (at its
// first fchmod, or as a whole), a flag set again on scope.key after
// rm-scope cleared it, and a record whose data-root fsync fails after its
// rename. The committed results of a root-owned leftover (one with an
// ACL, one holding an unlisted key, one met on the judged path with or
// without a key) and of a
// judged key not read again as the same after the take offer no rerun.
//
// A system flag on an entry cannot be set without root; its text is
// pinned at the flagKept layer (TestRmScopeOffersNoCommand). Only the
// cases needing a non-root user (the service-uid seam, the test user's
// own flags and ACLs) skip under root, and the scope directory another
// user owns needs root to chown it.
func TestRmScopeErrorTextsOfferNoCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		// want is the error the stop wraps; nil checks only its class.
		want      error
		committed bool
		rerun     bool
		nonRoot   bool
		rootOnly  bool
		says      []string
		setup     func(t *testing.T, s *FileStore, server, dir string)
	}{
		{name: "the scope directory absent", says: []string{"absent"}, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a file at the scope's name", want: ErrCorrupt, says: []string{"not a directory", "named for reading"}, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "another user owns the scope directory", want: ErrCorrupt, rootOnly: true, says: []string{"owned by uid 4242", "named for reading"}, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			if err := os.Chown(dir, 4242, 4242); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the floor's size does not read", nonRoot: true, says: []string{"nothing was changed"}, setup: func(t *testing.T, s *FileStore, _, _ string) {
			if err := os.Chmod(filepath.Join(s.dataRoot, logsDirName), 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "moved before its rmdir", want: errScopeDirMoved, committed: true, setup: func(t *testing.T, _ *FileStore, _, dir string) {
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
		{name: "planted at the scope's name", want: errPlanted, committed: true, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+".away", dir); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{name: "another user's flag on .user", want: errSharedDirFlag, committed: true, nonRoot: true, setup: func(t *testing.T, s *FileStore, _, dir string) {
			shared := filepath.Dir(dir)
			t.Cleanup(func() { _ = unix.Chflags(shared, 0) })
			setScopeFlags(t, shared, unix.UF_IMMUTABLE, false)
			setSeam(t, &rmSharedOwner, func(*unix.Stat_t) uint32 { return s.uid + 1 })
		}},
		{name: "a system flag on .user", want: errFlagLeft, committed: true, nonRoot: true, says: []string{"system flag"}, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			shared := filepath.Dir(dir)
			t.Cleanup(func() { _ = unix.Chflags(shared, 0) })
			setScopeFlags(t, shared, unix.UF_IMMUTABLE, false)
			setSeam(t, &rmSharedFlags, func(st *unix.Stat_t) uint32 { return statFlags(st) | unix.SF_IMMUTABLE })
		}},
		{name: "another scope at the name", want: errNotJudgedScope, committed: true, setup: func(t *testing.T, s *FileStore, server, dir string) {
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
		{name: "a directory on another device", want: errScopeForeignDir, committed: true, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			mount := filepath.Join(dir, scopeEntriesName, "mounted")
			if err := os.Mkdir(mount, 0o700); err != nil {
				t.Fatal(err)
			}
			ino, _ := inoOf(t, mount)
			otherDeviceFor(t, ino)
		}},
		{name: "nested too deep", want: errScopeTreeDeep, committed: true, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			p := filepath.Join(dir, scopeEntriesName)
			for i := 0; i <= maxScopeTreeDepth; i++ {
				p = filepath.Join(p, fmt.Sprintf("c%d", i))
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "a twice-linked flagged FIFO", want: errFlagLeft, committed: true, nonRoot: true, setup: func(t *testing.T, _ *FileStore, _, dir string) {
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
		{name: "the rmdir's probe fails", want: errScopeRmdirUnconfirmed, committed: true, setup: func(t *testing.T, _ *FileStore, _, _ string) {
			setSeam(t, &rmProbeMkdir, func(int, string, uint32) error { return unix.EIO })
		}},
		{name: "absent at the open, .user's fsync fails", says: []string{"absent at its name", "fsync of the shared directory .user"}, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			if err := os.Remove(filepath.Join(dir, scopeKeyName)); err != nil {
				t.Fatal(err)
			}
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
			})
			setSeam(t, &rmSyncShared, func(int) error { return unix.EIO })
		}},
		{name: "a take that stops", want: unix.EIO, committed: true, rerun: true, setup: func(t *testing.T, _ *FileStore, _, _ string) {
			setSeam(t, &rmTakeDir, func(int) error { return unix.EIO })
		}},
		{name: "a take that stops at its first fchmod", want: unix.EIO, committed: true, rerun: true, setup: func(t *testing.T, _ *FileStore, _, dir string) {
			if err := os.Chmod(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			setSeam(t, &rmTakeStep, func(step int) error {
				if step == 0 {
					return unix.EIO
				}
				return nil
			})
		}},
		{name: "a flag set again on scope.key", want: unix.EPERM, committed: true, rerun: true, nonRoot: true, setup: func(t *testing.T, _ *FileStore, _, dir string) {
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
		{name: "the record's fsync fails after its rename", want: errCommitted, committed: true, rerun: true, setup: func(t *testing.T, _ *FileStore, _, _ string) {
			setSeam(t, &removedScopesFsync, func(int) error { return unix.EIO })
		}},
		{name: "a root leftover with an ACL", want: errCommitted, committed: true, nonRoot: true, says: []string{"root-owned leftover", "extended ACL"}, setup: func(t *testing.T, s *FileStore, _, dir string) {
			saved := rmTakeDir
			rmTakeDir = func(int) error { return unix.EIO }
			_, err := s.RemoveScope(t.Context(), 1001)
			rmTakeDir = saved
			if !Committed(err) {
				t.Fatalf("run 1, stopped at the take: %v, want committed", err)
			}
			addInheritableACL(t, dir)
			asTakenRerun(t, s, dir)
		}},
		{name: "an unlisted key in a root leftover", want: errCommitted, committed: true, nonRoot: true, says: []string{"root-owned leftover", "was not listed before this run"}, setup: func(t *testing.T, s *FileStore, _, dir string) {
			asTakenRerun(t, s, dir)
		}},
		{name: "a root leftover on the judged path", want: errCommitted, committed: true, nonRoot: true, says: []string{"root-owned leftover", "the directory rm-scope judged was not at its name"}, setup: func(t *testing.T, s *FileStore, server, dir string) {
			saved := rmTakeDir
			rmTakeDir = func(int) error { return unix.EIO }
			_, err := s.RemoveScope(t.Context(), 1001)
			rmTakeDir = saved
			if !Committed(err) {
				t.Fatalf("run 1, stopped at the take: %v, want committed", err)
			}
			spare := filepath.Join(server, "spare")
			if err := os.Rename(dir, spare); err != nil {
				t.Fatal(err)
			}
			takeLeftover(t, spare)
			userPut(t, userScope(t, s, 1001), "user/1001/y", "y")
			fillRecord(t, s)
			if err := os.Chmod(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			setSeam(t, &rmServiceUID, func(*FileStore) uint32 { return s.uid + 1 })
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(spare, dir); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{name: "a keyless root leftover on the judged path", want: errCommitted, committed: true, nonRoot: true, says: []string{"root-owned leftover", "the directory rm-scope judged was not at its name"}, setup: func(t *testing.T, s *FileStore, server, dir string) {
			spare := filepath.Join(server, "spare")
			if err := os.Rename(dir, spare); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(spare, scopeKeyName)); err != nil {
				t.Fatal(err)
			}
			takeLeftover(t, spare)
			userPut(t, userScope(t, s, 1001), "user/1001/y", "y")
			if err := os.Chmod(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			setSeam(t, &rmServiceUID, func(*FileStore) uint32 { return s.uid + 1 })
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(spare, dir); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{name: "the judged key not read again as the same", want: errCommitted, committed: true, says: []string{"read again after rm-scope took the directory"}, setup: func(t *testing.T, s *FileStore, server, dir string) {
			other := filepath.Join(server, "other.key")
			if err := os.Rename(filepath.Join(dir, scopeKeyName), other); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			userPut(t, userScope(t, s, 1001), "user/1001/y", "y")
			saved := rmTakeDir
			once := false
			setSeam(t, &rmTakeDir, func(fd int) error {
				if !once {
					once = true
					if err := os.Rename(other, filepath.Join(dir, scopeKeyName)); err != nil {
						t.Fatal(err)
					}
				}
				return saved(fd)
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.nonRoot && asRoot() {
				t.Skip("the case needs a non-root user: the service-uid seam, or the test user's own flags or ACLs")
			}
			if tc.rootOnly && !asRoot() {
				t.Skip("the case chowns the scope directory to another user, which needs root")
			}
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			tc.setup(t, s, server, dir)
			_, err := s.RemoveScope(t.Context(), 1001)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || Committed(err) != tc.committed {
				t.Fatalf("rm-scope: %v, want %v, committed %v", err, tc.want, tc.committed)
			}
			// The record's own errors, errNotJudgedScope and the results
			// outside the walk are not rmStopped's to judge; every other
			// stop follows the cannot-help list.
			if tc.want != nil && tc.want != errCommitted && tc.want != errNotJudgedScope && tc.want != ErrCorrupt && rmRerunCannotHelp(err) == tc.rerun {
				t.Errorf("rmRerunCannotHelp(%v) = %v, and the case says a rerun helps: %v", err, !tc.rerun, tc.rerun)
			}
			msg := err.Error()
			checkRmScopeText(t, msg, tc.rerun)
			for _, want := range tc.says {
				if !strings.Contains(msg, want) {
					t.Errorf("the error %q does not say %q", msg, want)
				}
			}
			for _, bad := range []string{"partly or wholly present", "removed the directory of user/1001", "removed user/1001"} {
				if (tc.want == nil || tc.want == ErrCorrupt || strings.Contains(tc.name, "judged path")) && strings.Contains(msg, bad) {
					t.Errorf("the error %q says %q, and the scope's directory was not removed", msg, bad)
				}
			}
		})
	}
}

// The errors about the root-owned removed-scopes record in the data root
// come from the shared readers (readRemovedScopes, rootfile.go's
// judgeRootFile and rootFileFlagRepair) and keep their wording, repair
// advice included: they are outside checkRmScopeText's rule. rm-scope
// adds only that nothing was changed, and no name from the service user's
// tree. The cases: a record that does not read (through the seam), and a
// record carrying a user flag (its repair names chflags on the record's
// own root-owned path).
func TestRmScopeRecordErrorsNameNoServiceUserPath(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *FileStore)
	}{
		{"the record does not read", func(t *testing.T, _ *FileStore) {
			setSeam(t, &rmReadRemovedScopes, func(*FileStore, int) (*removedScopes, error) {
				return nil, fmt.Errorf("%w: read: %w", errRemovedScopesBad, unix.EIO)
			})
		}},
		{"the record carries a flag", func(t *testing.T, s *FileStore) {
			userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
			if _, err := s.RemoveScope(t.Context(), 1002); err != nil {
				t.Fatal(err)
			}
			rec := removedRecordPath(s)
			if err := unix.Chflags(rec, unix.UF_NODUMP); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Chflags(rec, 0) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			tc.setup(t, s)
			_, err := s.RemoveScope(t.Context(), 1001)
			if !errors.Is(err, errRemovedScopesBad) || Committed(err) || !strings.Contains(err.Error(), "nothing was changed") {
				t.Fatalf("rm-scope over a bad record: %v, want a refusal of errRemovedScopesBad saying nothing was changed", err)
			}
			checkRmScopeCommands(t, err.Error())
			for _, bad := range []string{s.dir, userScopesName, "user/1001", "user/1002"} {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("the error %q names %q, from the service user's tree", err, bad)
				}
			}
		})
	}
}
