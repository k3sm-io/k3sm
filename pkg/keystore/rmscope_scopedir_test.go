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

// treeNames lists every path below dir, relative to it, sorted.
func treeNames(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		names = append(names, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	return names
}

// otherDeviceFor makes rmDev report another device for the inode ino.
func otherDeviceFor(t *testing.T, ino uint64) {
	t.Helper()
	saved := rmDev
	setSeam(t, &rmDev, func(st *unix.Stat_t) uint64 {
		if uint64(st.Ino) == ino {
			return saved(st) + 1
		}
		return saved(st)
	})
}

// countTakes counts rmTakeDir's calls, still taking.
func countTakes(t *testing.T) *int {
	t.Helper()
	n := new(int)
	saved := rmTakeDir
	setSeam(t, &rmTakeDir, func(fd int) error {
		*n++
		return saved(fd)
	})
	return n
}

// checkScopeDirRefused checks err is the refusal of the scope directory
// itself, naming it for reading only, saying why, and offering no command.
func checkScopeDirRefused(t *testing.T, err error, s *FileStore, why string) {
	t.Helper()
	if !errors.Is(err, errScopeForeignDir) {
		t.Fatalf("removeScopeTree over a scope directory that is not the scope's: %v, want errScopeForeignDir", err)
	}
	msg := err.Error()
	for _, want := range []string{
		"the scope directory " + quoteName(filepath.Join(s.dir, userScopesName, "1001")) + " (named for reading, not for pasting)",
		why,
		"it is not the scope's, so rm-scope took nothing, changed nothing and removed nothing in it",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error %q does not say %q", msg, want)
		}
	}
	if strings.Contains(msg, "sudo") || strings.Contains(msg, "rm -") {
		t.Errorf("the error %q offers a command", msg)
	}
}

// The service user owns .user/ and can rename another directory in at
// .user/<uid> after the by-path judgement: a scope directory that is
// neither the service user's nor root's at 0700 (through the seam the
// service user is another uid, and the test's uid stands for root, so the
// test's own 0755 directory is neither) is not taken, and its mode and
// every name in it are untouched.
func TestRemoveScopeRefusesForeignScopeDir(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root; TestRemoveScopeRefusesForeignScopeDirAsRoot is the root case")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	before := treeNames(t, dir)
	takes := countTakes(t)
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = removeScopeTree(root, s.dir, "1001", s.uid+1, rmTreeOpts{listed: true})
	checkScopeDirRefused(t, err, s, "neither the service user's")
	if *takes != 0 {
		t.Errorf("rmTakeDir ran %d times, want none", *takes)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil || st.Mode&0o7777 != 0o755 || st.Uid != s.uid {
		t.Fatalf("the scope directory: mode %#o uid %d (%v), want it untouched", st.Mode&0o7777, st.Uid, err)
	}
	if after := treeNames(t, dir); !slices.Equal(before, after) {
		t.Fatalf("the scope directory holds %v, want %v untouched", after, before)
	}
}

// A scope directory on another device than .user (through the seam), even
// one the service user owns, is not taken, and its mode and every name in
// it are untouched: .user's device, not the unchecked directory's, is the
// walk's baseline.
func TestRemoveScopeRefusesOtherDeviceScopeDir(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	var was unix.Stat_t
	if err := unix.Lstat(dir, &was); err != nil {
		t.Fatal(err)
	}
	before := treeNames(t, dir)
	otherDeviceFor(t, uint64(was.Ino))
	takes := countTakes(t)
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
	why := "on another device than .user"
	if asRoot() {
		why = ""
	}
	checkScopeDirRefused(t, err, s, why)
	if *takes != 0 {
		t.Errorf("rmTakeDir ran %d times, want none", *takes)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil || st.Mode != was.Mode || st.Uid != was.Uid {
		t.Fatalf("the scope directory: mode %#o uid %d (%v), want %#o uid %d", st.Mode, st.Uid, err, was.Mode, was.Uid)
	}
	if after := treeNames(t, dir); !slices.Equal(before, after) {
		t.Fatalf("the scope directory holds %v, want %v untouched", after, before)
	}
}

// A subdirectory the service user owns but on another device than the
// scope directory (through the seam) is left in place with what it holds,
// and the removal fails naming it for reading only and saying why, with no
// command; the rest of the tree goes.
func TestRemoveScopeLeavesOtherDeviceDir(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	mount := filepath.Join(dir, scopeEntriesName, "mounted")
	if err := os.Mkdir(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(mount, "theirs")
	if err := os.WriteFile(kept, []byte("another volume's"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, mount, kept)
	ino, _ := inoOf(t, mount)
	otherDeviceFor(t, ino)
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
	if !errors.Is(err, errScopeForeignDir) {
		t.Fatalf("removeScopeTree over another device's directory: %v, want errScopeForeignDir", err)
	}
	msg := err.Error()
	for _, want := range []string{
		quoteName(filepath.Join(s.dir, userScopesName, "1001", scopeEntriesName, "mounted")) + " (named for reading, not for pasting)",
		"it is on another device than the scope directory",
		"left it and everything in it in place",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error %q does not say %q", msg, want)
		}
	}
	if strings.Contains(msg, "sudo") || strings.Contains(msg, "rm -") {
		t.Errorf("the error %q offers a command", msg)
	}
	if b, err := os.ReadFile(kept); err != nil || string(b) != "another volume's" {
		t.Fatalf("the file on the other device: %q, %v; want it untouched", b, err)
	}
	names, err := os.ReadDir(filepath.Join(dir, scopeEntriesName))
	if err != nil || len(names) != 1 || names[0].Name() != "mounted" {
		t.Fatalf("entries/ holds %v (%v), want only the other device's directory", names, err)
	}
}

// .user is the service user's, so the emptied scope directory's name can be
// renamed away, or another directory put at it, just before rm-scope
// removes it: before its stat, or between the stat and the unlinkat (the
// seam does one of them once). None is reported removed: each is
// errScopeDirMoved, never success, the directory moved away is still
// there and empty, and the error offers no rerun. A swapped-in directory
// survives when it holds a name (ENOTEMPTY, said as a non-empty directory
// now at the name); an empty one swapped in after the stat is what the
// unlinkat removes, and the error says another directory was removed at
// the name and the emptied one remains.
func TestRemoveScopeDirMovedBeforeRmdir(t *testing.T) {
	for _, tc := range []struct {
		name     string
		step     rmdirStep
		swapIn   bool
		nonEmpty bool
		want     string
	}{
		{"moved away", rmdirBeforeStat, false, false, "moved away from its name"},
		{"another directory at the name", rmdirBeforeStat, true, false, "is no longer the directory rm-scope emptied"},
		{"moved away after the stat", rmdirBeforeUnlink, false, false, "moved away from its name"},
		{"an empty directory at the name after the stat", rmdirBeforeUnlink, true, false, "another directory was removed at the name"},
		{"a non-empty directory at the name after the stat", rmdirBeforeUnlink, true, true, "a non-empty directory is now at the name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			away := filepath.Join(filepath.Dir(dir), "away")
			var swapped uint64
			setSeam(t, &rmBeforeScopeRmdir, func(step rmdirStep) {
				if swapped != 0 || step != tc.step {
					return
				}
				if err := os.Rename(dir, away); err != nil {
					t.Fatal(err)
				}
				swapped = 1
				if tc.swapIn {
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if tc.nonEmpty {
						if err := os.WriteFile(filepath.Join(dir, "theirs"), nil, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					swapped, _ = inoOf(t, dir)
				}
			})
			root, err := s.openDir(s.dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			_, err = removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
			if swapped == 0 {
				t.Fatal("the seam never ran")
			}
			if !errors.Is(err, errScopeDirMoved) {
				t.Fatalf("removeScopeTree with the name swapped before its rmdir: %v, want errScopeDirMoved", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, quoteName(dir)+" (named for reading, not for pasting)") || !strings.Contains(msg, tc.want) {
				t.Errorf("the error %q does not name the scope directory for reading and say %q", msg, tc.want)
			}
			if strings.Contains(msg, "which only root can now do") {
				t.Errorf("the error %q says only root can change the names", msg)
			}
			if names, err := os.ReadDir(away); err != nil || len(names) != 0 {
				t.Fatalf("the emptied directory moved away: %v (%v), want it present and empty", names, err)
			}
			_, lerr := os.Lstat(dir)
			switch {
			case tc.swapIn && (tc.step == rmdirBeforeStat || tc.nonEmpty):
				if ino, _ := inoOf(t, dir); ino != swapped {
					t.Fatalf("the directory at the name is inode %d, want the swapped-in %d", ino, swapped)
				}
			case !errors.Is(lerr, os.ErrNotExist):
				t.Fatalf("the name after the stop: %v, want nothing at it", lerr)
			}
		})
	}
}
