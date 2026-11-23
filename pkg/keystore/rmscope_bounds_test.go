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

// watchWalk records the inode of every directory rm-scope takes or lists,
// through the take and listing seams, still doing both.
func watchWalk(t *testing.T) map[uint64]bool {
	t.Helper()
	seen := map[uint64]bool{}
	note := func(fd int) {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Errorf("fstat a directory rm-scope holds: %v", err)
			return
		}
		seen[uint64(st.Ino)] = true
	}
	take := rmTakeDir
	setSeam(t, &rmTakeDir, func(fd int) error {
		note(fd)
		return take(fd)
	})
	list := rmReadBatch
	setSeam(t, &rmReadBatch, func(dfd, n int, skip map[string]bool) ([]string, error) {
		note(dfd)
		return list(dfd, n, skip)
	})
	return seen
}

// More directories that are not the scope's than maxForeignDirs (through
// the device seam, each on another device) stop the walk once it has left
// maxForeignDirs of them: the error is errScopeForeignDir naming exactly
// that many, and no foreign directory is taken or listed, so each keeps
// its file.
func TestRemoveScopeForeignDirCap(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	const n = maxForeignDirs + 4
	foreign := map[uint64]bool{}
	var kept []string
	for i := range n {
		d := filepath.Join(dir, scopeEntriesName, fmt.Sprintf("mounted%02d", i))
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(d, "theirs")
		if err := os.WriteFile(f, []byte("another volume's"), 0o600); err != nil {
			t.Fatal(err)
		}
		giveToService(t, d, f)
		ino, _ := inoOf(t, d)
		foreign[ino] = true
		kept = append(kept, f)
	}
	saved := rmDev
	setSeam(t, &rmDev, func(st *unix.Stat_t) uint64 {
		if foreign[uint64(st.Ino)] {
			return saved(st) + 1
		}
		return saved(st)
	})
	seen := watchWalk(t)
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
	if !errors.Is(err, errScopeForeignDir) {
		t.Fatalf("removeScopeTree over %d foreign directories: %v, want errScopeForeignDir", n, err)
	}
	if got := strings.Count(err.Error(), errScopeForeignDir.Error()); got != maxForeignDirs {
		t.Errorf("the error names %d foreign directories, want the cap, %d", got, maxForeignDirs)
	}
	for ino := range foreign {
		if seen[ino] {
			t.Errorf("rm-scope took or listed the foreign directory inode %d", ino)
		}
	}
	for _, f := range kept {
		if b, err := os.ReadFile(f); err != nil || string(b) != "another volume's" {
			t.Fatalf("the file %s in a foreign directory: %q, %v; want it untouched", f, b, err)
		}
	}
}

// A chain of directories nested deeper than maxScopeTreeDepth below the
// scope directory stops the walk at the first directory past the limit:
// the error is errScopeTreeDeep naming that directory relative to the
// scope directory, for reading only, saying nothing below it was removed,
// with no command; that directory is neither taken nor listed, and it and
// what it holds are untouched.
func TestRemoveScopeDepthLimit(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	var chain []string
	for i := 0; i <= maxScopeTreeDepth+1; i++ {
		chain = append(chain, fmt.Sprintf("c%d", i))
	}
	p := dir
	var paths []string
	for _, c := range chain {
		p = filepath.Join(p, c)
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	bottom := filepath.Join(p, "f")
	if err := os.WriteFile(bottom, []byte("deep"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, append(paths, bottom)...)
	// chain[maxScopeTreeDepth] is the first directory past the limit.
	past := paths[maxScopeTreeDepth]
	pastIno, _ := inoOf(t, past)
	seen := watchWalk(t)
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
	if !errors.Is(err, errScopeTreeDeep) {
		t.Fatalf("removeScopeTree over a chain past the limit: %v, want errScopeTreeDeep", err)
	}
	rel := filepath.Join(chain[:maxScopeTreeDepth+1]...)
	msg := err.Error()
	for _, want := range []string{
		"the directory " + quoteName(rel) + " below the scope directory (named for reading, not for pasting)",
		fmt.Sprintf("nested more than %d directories deep", maxScopeTreeDepth),
		"rm-scope removed nothing below it",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error %q does not say %q", msg, want)
		}
	}
	for _, bad := range []string{"sudo", "remove it as root", "rerun"} {
		if strings.Contains(msg, bad) {
			t.Errorf("the error %q offers a command (%q)", msg, bad)
		}
	}
	if seen[pastIno] {
		t.Error("rm-scope took or listed the directory past the limit")
	}
	var st unix.Stat_t
	if err := unix.Lstat(past, &st); err != nil || st.Mode&0o7777 != 0o755 {
		t.Fatalf("the directory past the limit: mode %#o (%v), want it untouched at 0755", st.Mode&0o7777, err)
	}
	if b, err := os.ReadFile(bottom); err != nil || string(b) != "deep" {
		t.Fatalf("the file below the limit: %q, %v; want it untouched", b, err)
	}
}
