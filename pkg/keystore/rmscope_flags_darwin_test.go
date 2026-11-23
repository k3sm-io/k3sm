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
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// rmFlagCall is one call of rm-scope's flag write: the inode of the
// descriptor it was made on and the flags it set.
type rmFlagCall struct {
	ino   uint64
	flags int
}

// recordScopeFlags replaces scopeFchflags with the real call that records
// each call's descriptor inode, for the test's life.
func recordScopeFlags(t *testing.T) *[]rmFlagCall {
	t.Helper()
	var calls []rmFlagCall
	saved := scopeFchflags
	scopeFchflags = func(fd, flags int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Errorf("fstat the descriptor rm-scope flags: %v", err)
		}
		calls = append(calls, rmFlagCall{ino: st.Ino, flags: flags})
		return unix.Fchflags(fd, flags)
	}
	t.Cleanup(func() { scopeFchflags = saved })
	return &calls
}

// unflagScopeTree clears every flag under dir, links included, so TempDir can
// remove it.
func unflagScopeTree(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if fd, err := unix.Open(p, unix.O_RDONLY|unix.O_SYMLINK, 0); err == nil {
				_ = unix.Fchflags(fd, 0)
				_ = unix.Close(fd)
			}
			return nil
		}
		_ = unix.Chflags(p, 0)
		return nil
	})
}

// giveScopeTree hands every name under dir, symlinks themselves included,
// to the service user, as root (giveToService): rm-scope clears only the
// service user's flags, and the names the test plants are root's when it
// runs as root. Non-root the test user is the service user already.
func giveScopeTree(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		giveToService(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// setScopeFlags sets flags on p, a symlink itself when link.
func setScopeFlags(t *testing.T, p string, flags int, link bool) uint64 {
	t.Helper()
	open := unix.O_RDONLY | unix.O_NONBLOCK
	if link {
		open |= unix.O_SYMLINK
	}
	fd, err := unix.Open(p, open, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchflags(fd, flags); err != nil {
		t.Fatalf("set flags %#x on %s: %v", flags, p, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// TestRemoveScopeClearsUserFlags: the service user can set a user flag
// (uchg, uappnd, uunlnk) on its own files, which makes unlinkat fail with
// EPERM, root's included. rm-scope's tree removal clears such a flag on a
// descriptor of the entry (the flag write seam sees the entry's own inode,
// a symlink's included) and removes the tree: a uchg scope.key, entry
// directory and version file, a uappnd delivery record, a uunlnk FIFO and
// a uchg symlink, and a uchg regular file with two links both in the tree.
// A flagged file with a link outside the tree is never cleared: the
// removal fails naming the outside link, and the outside file keeps its
// flag. Non-root, the test user is the service user and sets the flags
// itself; as root, the tree and the outside file are handed to the
// service user first, and root sets the flags.
func TestRemoveScopeClearsUserFlags(t *testing.T) {
	const ufNoUnlinkFlag = 0x10
	t.Run("flags in the tree", func(t *testing.T) {
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		t.Cleanup(func() { unflagScopeTree(dir) })
		entry := filepath.Join(dir, scopeEntriesName, "token")
		fifo := filepath.Join(dir, "planted-fifo")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "planted-link")
		if err := os.Symlink(filepath.Join(t.TempDir(), "target"), link); err != nil {
			t.Fatal(err)
		}
		twin := filepath.Join(dir, "twin")
		if err := os.WriteFile(twin, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(twin, filepath.Join(dir, scopeEntriesName, "twin-alias")); err != nil {
			t.Fatal(err)
		}
		giveScopeTree(t, dir)
		want := map[uint64]string{}
		names, err := os.ReadDir(entry)
		if err != nil || len(names) == 0 {
			t.Fatalf("read %s: %v", entry, err)
		}
		for _, n := range names {
			if !n.IsDir() {
				want[setScopeFlags(t, filepath.Join(entry, n.Name()), unix.UF_IMMUTABLE, false)] = n.Name()
				break
			}
		}
		want[setScopeFlags(t, entry, unix.UF_IMMUTABLE, false)] = "the entry directory"
		want[setScopeFlags(t, filepath.Join(dir, deliveriesName), unix.UF_APPEND, false)] = deliveriesName
		want[setScopeFlags(t, fifo, ufNoUnlinkFlag, false)] = "the FIFO"
		want[setScopeFlags(t, link, unix.UF_IMMUTABLE, true)] = "the symlink"
		want[setScopeFlags(t, twin, unix.UF_IMMUTABLE, false)] = "the twice-linked file"
		want[setScopeFlags(t, filepath.Join(dir, scopeKeyName), unix.UF_IMMUTABLE, false)] = scopeKeyName
		calls := recordScopeFlags(t)
		root, err := s.openDir(s.dir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := removeScopeTree(root, "1001", s.uid); err != nil {
			t.Fatalf("removeScopeTree over user flags: %v", err)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the scope directory is still there: %v", err)
		}
		got := map[uint64]bool{}
		for _, c := range *calls {
			got[c.ino] = true
			if c.flags&userLockingFlags != 0 {
				t.Errorf("a flag write left a user locking flag: %#x", c.flags)
			}
		}
		for ino, what := range want {
			if !got[ino] {
				t.Errorf("%s's flag was not cleared through its own descriptor (calls %+v)", what, *calls)
			}
		}
	})
	t.Run("a link outside the tree", func(t *testing.T) {
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		outside := filepath.Join(t.TempDir(), "outside")
		t.Cleanup(func() { unflagScopeTree(dir); unflagScopeTree(filepath.Dir(outside)) })
		if err := os.WriteFile(outside, []byte("not the scope's"), 0o600); err != nil {
			t.Fatal(err)
		}
		in := filepath.Join(dir, "linked-in")
		if err := os.Link(outside, in); err != nil {
			t.Skipf("the temp dir is on another volume than the data root: %v", err)
		}
		giveToService(t, outside)
		ino := setScopeFlags(t, outside, unix.UF_IMMUTABLE, false)
		calls := recordScopeFlags(t)
		root, err := s.openDir(s.dir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := removeScopeTree(root, "1001", s.uid); !errors.Is(err, errScopeFlagLinked) {
			t.Fatalf("removeScopeTree over a flagged file linked outside: %v, want errScopeFlagLinked", err)
		}
		for _, c := range *calls {
			if c.ino == ino {
				t.Errorf("rm-scope cleared the flag of a file linked outside the tree: %+v", c)
			}
		}
		var st unix.Stat_t
		if err := unix.Lstat(outside, &st); err != nil || st.Flags&unix.UF_IMMUTABLE == 0 {
			t.Errorf("the outside file's flags are %#x (%v); want uchg kept", st.Flags, err)
		}
	})
}
