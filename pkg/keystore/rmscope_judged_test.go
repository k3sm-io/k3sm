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
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// rmScopeOf is uid's scope as RemoveScope builds it: a removed key opens.
func rmScopeOf(s *FileStore, uid uint32) *UserScope {
	return &UserScope{s: s, uid: uid, scope: userScopeOf(uid), allowRemoved: true}
}

// The service user owns .user and can rename another of its scope
// directories onto the judged one's name after RemoveScope judged and
// listed it (the seam does, just before the tree is removed): the
// directory now at the name holds another scope's scope.key, so nothing of
// it is taken or removed, its key is not listed, and the error names the
// directory as not the judged scope, with no command and no rerun.
func TestRemoveScopeRefusesSwappedScope(t *testing.T) {
	s, server, _ := fileLogScope(t)
	userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
	dir, other := scopeDir(server, "1001"), scopeDir(server, "1002")
	away := filepath.Join(filepath.Dir(dir), "away")
	before := treeNames(t, other)
	var mode os.FileMode
	ran := false
	setSeam(t, &rmBeforeTree, func() {
		ran = true
		if err := os.Rename(dir, away); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, dir); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		mode = fi.Mode()
	})
	takes := countTakes(t)
	_, err := s.RemoveScope(t.Context(), 1001)
	if !ran {
		t.Fatal("the seam never ran")
	}
	if !errors.Is(err, errNotJudgedScope) {
		t.Fatalf("rm-scope over a swapped-in scope directory: %v, want errNotJudgedScope", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, quoteName(dir)+" (named for reading, not for pasting)") || !strings.Contains(msg, "took nothing, changed nothing and removed nothing in it") {
		t.Errorf("the error %q does not name the directory as untouched", msg)
	}
	for _, bad := range []string{"sudo", "rm -", "rerun"} {
		if strings.Contains(msg, bad) {
			t.Errorf("the error %q offers %q, which cannot help", msg, bad)
		}
	}
	if *takes != 0 {
		t.Errorf("rmTakeDir ran %d times, want none", *takes)
	}
	if after := treeNames(t, dir); !slices.Equal(before, after) {
		t.Fatalf("the swapped-in directory holds %v, want %v untouched", after, before)
	}
	if fi, err := os.Lstat(dir); err != nil || fi.Mode() != mode {
		t.Fatalf("the swapped-in directory: %v (%v), want mode %v", fi, err, mode)
	}
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dfd) }()
	for _, uid := range []uint32{1001, 1002} {
		hk, err := rmScopeOf(s, uid).scopeKeyAt(dfd, k)
		if err != nil {
			t.Fatal(err)
		}
		if hk.id != "" && readRecord(t, s).has(uid, hk.id) {
			t.Fatalf("the swapped-in scope's key is listed for uid %d", uid)
		}
	}
}

// rerunTree runs removeScopeTree over keystore/.user/1001 with the check
// of a rerun path; through the seam the service user is another uid, so
// the test's own 0700 directories are root's, as an earlier run left them.
func rerunTree(t *testing.T, s *FileStore, path rmPath) error {
	t.Helper()
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dfd) }()
	removed, err := s.readRemovedScopes(dfd)
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	svc := s.uid + 1
	_, err = removeScopeTree(root, s.dir, "1001", svc, rmTreeOpts{check: (&rmRun{s: s, u: rmScopeOf(s, 1001), k: k, removed: removed, dfd: dfd, svc: svc, name: "1001", path: path}).check})
	return err
}

// takeLeftover makes uid 1001's scope directory look as an earlier run
// left it after its take: every directory in it at 0700.
func takeLeftover(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return os.Chmod(p, 0o700)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A rerun finishes what an interrupted rm-scope left: a taken directory
// (root's at 0700) holding no scope.key, or holding the scope.key the
// record lists for the uid, is removed.
func TestRemoveScopeRerunAcceptsOwnLeftover(t *testing.T) {
	t.Run("taken, no scope.key", func(t *testing.T) {
		if asRoot() {
			t.Skip("the seam's other service uid makes the store's own directories foreign as root")
		}
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		if err := os.Remove(filepath.Join(dir, scopeKeyName)); err != nil {
			t.Fatal(err)
		}
		takeLeftover(t, dir)
		if err := rerunTree(t, s, rmPathTaken); err != nil {
			t.Fatalf("the rerun over a taken directory without scope.key: %v", err)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the scope directory is still there: %v", err)
		}
	})
	t.Run("taken, listed scope.key", func(t *testing.T) {
		if asRoot() {
			t.Skip("the seam's other service uid makes the store's own directories foreign as root")
		}
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		saved := rmTakeDir
		setSeam(t, &rmTakeDir, func(int) error { return unix.EIO })
		if _, err := s.RemoveScope(t.Context(), 1001); !Committed(err) {
			t.Fatalf("run 1, stopped at the take after listing: %v, want committed", err)
		}
		rmTakeDir = saved
		takeLeftover(t, dir)
		if err := rerunTree(t, s, rmPathTaken); err != nil {
			t.Fatalf("the rerun over a taken directory whose scope.key is listed: %v", err)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the scope directory is still there: %v", err)
		}
	})
}

// asTakenRerun makes the next RemoveScope see uid 1001's directory as an
// earlier run's take left it: every directory in it at 0700, and, through
// the seam, the service user another uid, so the test's own 0700
// directories are root's.
func asTakenRerun(t *testing.T, s *FileStore, dir string) {
	t.Helper()
	takeLeftover(t, dir)
	setSeam(t, &rmServiceUID, func(*FileStore) uint32 { return s.uid + 1 })
}

// A root-owned 0700 directory at the name is always finished, whatever
// scope.key it holds: the service user can place none there but another
// uid's taken leftover, which no open serves. A key that opens as this
// scope's is listed first, so the removal is listed (exit 0); one that is
// absent or cannot be trusted is removed, committed (exit 4). A stop
// between the take and the first unlink leaves a directory the rerun
// finishes.
func TestRemoveScopeRerunFinishesAnyTakenLeftover(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root")
	}
	for _, tc := range []struct {
		name   string
		setup  func(t *testing.T, s *FileStore, dir string)
		listed bool
	}{
		{"no key", func(t *testing.T, _ *FileStore, dir string) {
			if err := os.Remove(filepath.Join(dir, scopeKeyName)); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"listed key", func(t *testing.T, s *FileStore, _ string) {
			saved := rmTakeDir
			rmTakeDir = func(int) error { return unix.EIO }
			defer func() { rmTakeDir = saved }()
			if _, err := s.RemoveScope(t.Context(), 1001); !Committed(err) {
				t.Fatalf("run 1, stopped at the take after listing: %v, want committed", err)
			}
		}, true},
		{"valid unlisted key", func(*testing.T, *FileStore, string) {}, true},
		{"untrusted key", func(t *testing.T, _ *FileStore, dir string) {
			if err := os.WriteFile(filepath.Join(dir, scopeKeyName), []byte("not a key record"), fileMode); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"stop between the take and the first unlink", func(t *testing.T, s *FileStore, dir string) {
			if err := os.WriteFile(filepath.Join(dir, scopeKeyName), []byte("not a key record"), fileMode); err != nil {
				t.Fatal(err)
			}
			saved := rmTakeDir
			rmTakeDir = func(fd int) error {
				if err := saved(fd); err != nil {
					return err
				}
				return unix.EIO // taken; stop before anything in it is unlinked
			}
			defer func() { rmTakeDir = saved }()
			if _, err := s.RemoveScope(t.Context(), 1001); !errors.Is(err, unix.EIO) {
				t.Fatalf("run 1, stopped after the take: %v, want EIO", err)
			}
			if _, err := os.Lstat(filepath.Join(dir, scopeKeyName)); err != nil {
				t.Fatalf("scope.key after run 1: %v, want it left for the rerun", err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			tc.setup(t, s, dir)
			asTakenRerun(t, s, dir)
			res, err := s.RemoveScope(t.Context(), 1001)
			if tc.listed {
				if err != nil || !res.Recorded {
					t.Fatalf("the rerun: %v, recorded %v; want removed and listed", err, res.Recorded)
				}
			} else if !Committed(err) || res.Recorded {
				t.Fatalf("the rerun: %v, recorded %v; want removed, committed, unconfirmed", err, res.Recorded)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
		})
	}
}

// A path without a judged key identity accepts no service user's
// directory that holds what it was not judged to hold: on the no-key path
// a valid, unlisted scope.key put back after the judge is refused, with
// nothing taken, changed or removed, and no command or rerun offered.
func TestRemoveScopeRerunRefusesServiceUserLeftover(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	key := filepath.Join(dir, scopeKeyName)
	hidden := filepath.Join(server, "scope.key.saved")
	if err := os.Rename(key, hidden); err != nil {
		t.Fatal(err)
	}
	var before []string
	setSeam(t, &rmBeforeTree, func() {
		if err := os.Rename(hidden, key); err != nil {
			t.Fatal(err)
		}
		before = treeNames(t, dir)
	})
	takes := countTakes(t)
	_, err := s.RemoveScope(t.Context(), 1001)
	if !errors.Is(err, errNotJudgedScope) {
		t.Fatalf("the rerun over a put-back key: %v, want errNotJudgedScope", err)
	}
	for _, bad := range []string{"sudo", "rm -", "rerun"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("the error %q offers %q", err, bad)
		}
	}
	if after := treeNames(t, dir); !slices.Equal(before, after) {
		t.Fatalf("the directory holds %v, want %v untouched", after, before)
	}
	if Committed(err) || *takes != 0 {
		t.Errorf("the refusal is committed (%v) or took %d directories", Committed(err), *takes)
	}
	if readRecord(t, s).listed(1001) {
		t.Error("the scope was listed")
	}
}

// A uid with an earlier listed key (K1) whose re-created scope's key (K2)
// is missing or garbled is removed, but not as listed: the record's other
// key proves nothing of this directory, so the result is committed and
// says how many keys the record lists for the uid.
func TestRmScopeListedNeedsThisKey(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, p string){
		"missing": func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		},
		"garbled": func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("not a key record"), fileMode); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			if res, err := s.RemoveScope(t.Context(), 1001); err != nil || !res.Recorded {
				t.Fatalf("the first removal (K1): %v, recorded %v", err, res.Recorded)
			}
			userPut(t, userScope(t, s, 1001), "user/1001/y", "y")
			damage(t, filepath.Join(scopeDir(server, "1001"), scopeKeyName))
			res, err := s.RemoveScope(t.Context(), 1001)
			if err == nil || !Committed(err) || res.Recorded {
				t.Fatalf("rm-scope of K2 with its key %s: %v, recorded %v; want committed, not listed", name, err, res.Recorded)
			}
			for _, want := range []string{"removed the directory of user/1001", "could not confirm that its key is listed", "which lists 1 keys for this uid"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error %q does not say %q", err, want)
				}
			}
			if _, err := os.Lstat(scopeDir(server, "1001")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
		})
	}
}

// A directory gone from its name when the walk opens it (the seam renames
// it away after the judge) is never reported removed: the judged path that
// wrote the record, and a listed rerun that made it durable again, are
// committed, saying it was found absent; a path that changed and wrote
// nothing refuses.
func TestRmScopeAbsentAtOpenIsNotRemoved(t *testing.T) {
	for _, tc := range []struct {
		name      string
		setup     func(t *testing.T, s *FileStore, dir string)
		committed bool
		want      string
	}{
		{"judged, written", func(*testing.T, *FileStore, string) {}, true, "rm-scope listed user/1001"},
		{"judged, listed rerun", func(t *testing.T, s *FileStore, _ string) {
			saved := rmTakeDir
			rmTakeDir = func(int) error { return unix.EIO }
			defer func() { rmTakeDir = saved }()
			if _, err := s.RemoveScope(t.Context(), 1001); !Committed(err) {
				t.Fatalf("run 1: %v, want committed", err)
			}
		}, true, "user/1001 is listed"},
		{"no key", func(t *testing.T, _ *FileStore, dir string) {
			if err := os.Remove(filepath.Join(dir, scopeKeyName)); err != nil {
				t.Fatal(err)
			}
		}, false, "absent at its name"},
		{"untrusted key", func(t *testing.T, _ *FileStore, dir string) {
			if err := os.WriteFile(filepath.Join(dir, scopeKeyName), []byte("not a key record"), fileMode); err != nil {
				t.Fatal(err)
			}
		}, false, "absent at its name"},
		{"taken", func(t *testing.T, s *FileStore, dir string) {
			if asRoot() {
				t.Skip("the seam's other service uid makes the store's own directories foreign as root")
			}
			asTakenRerun(t, s, dir)
		}, false, "absent at its name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			tc.setup(t, s, dir)
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
			})
			_, err := s.RemoveScope(t.Context(), 1001)
			if err == nil || Committed(err) != tc.committed {
				t.Fatalf("rm-scope with the directory gone at the open: %v, want committed %v", err, tc.committed)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.want) || !strings.Contains(msg, "absent") || strings.Contains(msg, "removed user/1001") || strings.Contains(msg, "removed the directory") {
				t.Errorf("the error %q does not say %q and found absent, or says removed", msg, tc.want)
			}
		})
	}
}
