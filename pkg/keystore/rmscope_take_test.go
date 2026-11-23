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

// rm-scope takes every directory of the scope tree, the scope directory
// first: through the take seam, each directory, a planted 0755 one and the
// one below it included, is handed to root at 0700 (to the test's own uid,
// non-root) before the walk goes on, and the tree is then removed.
func TestRemoveScopeTakesEachDirBeforeListing(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	if err := os.MkdirAll(filepath.Join(dir, "sub", "deeper"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "deeper", "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, filepath.Join(dir, "sub"), filepath.Join(dir, "sub", "deeper"), filepath.Join(dir, "sub", "deeper", "f"))
	// The planted directories are the service user's: the test's uid.
	type takeRec struct {
		ino  uint64
		mode uint32
	}
	var takes []takeRec
	saved := rmTakeDir
	setSeam(t, &rmTakeDir, func(fd int) error {
		err := saved(fd)
		var st unix.Stat_t
		if serr := unix.Fstat(fd, &st); serr != nil {
			return serr
		}
		takes = append(takes, takeRec{st.Ino, uint32(st.Mode & 0o7777)})
		if int(st.Uid) != rmRootUID {
			t.Errorf("a taken directory is uid %d's, want %d", st.Uid, rmRootUID)
		}
		return err
	})
	var want []uint64
	for _, d := range []string{dir, filepath.Join(dir, "sub"), filepath.Join(dir, "sub", "deeper")} {
		var st unix.Stat_t
		if err := unix.Lstat(d, &st); err != nil {
			t.Fatal(err)
		}
		want = append(want, st.Ino)
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true}); err != nil {
		t.Fatalf("removeScopeTree: %v", err)
	}
	got := map[uint64]uint32{}
	for _, r := range takes {
		got[r.ino] = r.mode
	}
	for i, ino := range want {
		if m, ok := got[ino]; !ok || m != 0o700 {
			t.Errorf("directory %d was not taken at 0700 (mode %#o, taken %v)", i, m, ok)
		}
	}
	if len(takes) == 0 || takes[0].ino != want[0] {
		t.Errorf("the scope directory was not the first taken: %+v", takes)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
}

// rm-scope never descends into a directory that is not the scope's.
// Through the seam the service user is another uid than the test's, so a
// directory the test owns at 0755 is neither the service user's nor root's
// at 0700 (the test's uid stands for root, non-root): it is left in place
// with the file inside it, and the removal fails naming it for reading
// only, saying who owns it, with no command. Everything else is removed.
func TestRemoveScopeLeavesForeignDir(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root; TestRemoveScopeLeavesForeignOwnedDirAsRoot is the root case")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	foreign := filepath.Join(dir, scopeEntriesName, "foreign\x1b[31m")
	if err := os.Mkdir(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(foreign, "theirs")
	if err := os.WriteFile(kept, []byte("another user's"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = removeScopeTree(root, s.dir, "1001", s.uid+1, rmTreeOpts{listed: true})
	if !errors.Is(err, errScopeForeignDir) {
		t.Fatalf("removeScopeTree over a foreign directory: %v, want errScopeForeignDir", err)
	}
	msg := err.Error()
	for _, want := range []string{quoteName(filepath.Join(s.dir, userScopesName, "1001", scopeEntriesName, "foreign\x1b[31m")) + " (named for reading, not for pasting)", fmt.Sprintf("uid %d owns it", s.uid), "left it and everything in it in place"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error %q does not say %q", msg, want)
		}
	}
	if strings.ContainsAny(msg, "\x1b") || strings.Contains(msg, "sudo") || strings.Contains(msg, "rm -") {
		t.Errorf("the error %q carries a control byte or offers a command", msg)
	}
	if b, err := os.ReadFile(kept); err != nil || string(b) != "another user's" {
		t.Fatalf("the file in the foreign directory: %q, %v; want it untouched", b, err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(foreign, &st); err != nil || st.Mode&0o7777 != 0o755 || st.Uid != s.uid {
		t.Fatalf("the foreign directory: mode %#o uid %d (%v), want it untouched", st.Mode&0o7777, st.Uid, err)
	}
	// The rest of entries/ is gone; only the foreign directory is left
	// beside scope.key.
	names, err := os.ReadDir(filepath.Join(dir, scopeEntriesName))
	if err != nil || len(names) != 1 {
		t.Fatalf("entries/ holds %v (%v), want only the foreign directory", names, err)
	}
}

// A directory holding more names than one batch is emptied batch by batch,
// each read from the start: with a batch of 3 the walk never holds more
// than 3 names of a listing (every listing it makes, through the seam, asks
// for at most 3 and gets at most 3), and the scope directory, its
// subdirectory of 40 files and its own 12 names are all removed, with no
// count refused.
func TestRemoveScopeBatchesHugeDir(t *testing.T) {
	setSeam(t, &rmDirBatch, 3)
	var listings, most int
	saved := rmReadBatch
	setSeam(t, &rmReadBatch, func(dfd, n int, skip map[string]bool) ([]string, error) {
		names, err := saved(dfd, n, skip)
		listings++
		if n > rmDirBatch || len(names) > rmDirBatch {
			t.Errorf("a listing asked for %d names and got %d, past the batch of %d", n, len(names), rmDirBatch)
		}
		most = max(most, len(names))
		return names, err
	})
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	big := filepath.Join(dir, "big")
	if err := os.Mkdir(big, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("f%02d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 12 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("top%02d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true}); err != nil {
		t.Fatalf("removeScopeTree over more names than a batch: %v", err)
	}
	// 52 names in batches of at most 3 take at least 18 listings; a full
	// batch shows the bound was reached, not just respected.
	if listings < 18 || most != rmDirBatch {
		t.Errorf("the walk made %d listings, the largest of %d names; want at least 18, the largest %d", listings, most, rmDirBatch)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
}

// readBatch reads at most n names from the start of the directory, none in
// skip, and an empty directory but for skipped names reads as none.
func TestReadBatchBounded(t *testing.T) {
	d := t.TempDir()
	for i := range 7 {
		if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("n%d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Open(d, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	skip := map[string]bool{"n0": true, "n1": true}
	got, err := readBatch(fd, 3, skip)
	if err != nil || len(got) != 3 {
		t.Fatalf("readBatch(3): %v, %v; want 3 names", got, err)
	}
	for _, n := range got {
		if skip[n] {
			t.Errorf("readBatch returned the skipped name %q", n)
		}
	}
	all, err := readBatch(fd, 100, skip)
	if err != nil || len(all) != 5 {
		t.Fatalf("readBatch(100): %v, %v; want the 5 unskipped names", all, err)
	}
	for i := 2; i < 7; i++ {
		skip[fmt.Sprintf("n%d", i)] = true
	}
	if none, err := readBatch(fd, 3, skip); err != nil || len(none) != 0 {
		t.Fatalf("readBatch with every name skipped: %v, %v; want none", none, err)
	}
}
