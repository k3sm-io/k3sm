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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
// (uchg, uappnd, uunlnk) on its own entries, which makes unlinkat fail with
// EPERM, root's included. rm-scope's tree removal clears such a flag on a
// descriptor of the entry (the flag write seam sees the entry's own inode,
// a symlink's included) and removes the tree: a uchg scope.key, entry
// directory and version file, a uappnd delivery record, a uchg symlink, a
// uchg regular file with two links in the tree, and a uchg file whose
// other link is outside the tree (the owner could clear that flag itself,
// so leaving it would only stall the removal). A uchg FIFO and a uchg
// socket are not opened, since an open has side effects or is refused:
// their flags are cleared by directory descriptor and name
// (setattrlistat), and the tree is removed.
// Non-root, the test user is the service user and sets the flags itself;
// as root, the tree and the outside file are handed to the service user
// first, and root sets the flags.
func TestRemoveScopeClearsUserFlags(t *testing.T) {
	t.Run("flags in the tree", func(t *testing.T) {
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		t.Cleanup(func() { unflagScopeTree(dir) })
		entry := filepath.Join(dir, scopeEntriesName, "token")
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
		outside := filepath.Join(filepath.Dir(server), "outside")
		t.Cleanup(func() { unflagScopeTree(outside) })
		if err := os.WriteFile(outside, []byte("the service user's"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, filepath.Join(dir, "linked-in")); err != nil {
			t.Fatal(err)
		}
		giveScopeTree(t, dir)
		giveToService(t, outside)
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
		want[setScopeFlags(t, link, unix.UF_IMMUTABLE, true)] = "the symlink"
		want[setScopeFlags(t, twin, unix.UF_IMMUTABLE, false)] = "the twice-linked file"
		want[setScopeFlags(t, outside, unix.UF_IMMUTABLE, false)] = "the file linked outside the tree"
		want[setScopeFlags(t, filepath.Join(dir, scopeKeyName), unix.UF_IMMUTABLE, false)] = scopeKeyName
		calls := recordScopeFlags(t)
		root, err := s.openDir(s.dir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := removeScopeTree(root, s.dir, "1001", s.uid, true); err != nil {
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
	t.Run("a flagged FIFO", func(t *testing.T) {
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		t.Cleanup(func() { unflagScopeTree(dir) })
		fifo := filepath.Join(dir, "planted-fifo")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		giveScopeTree(t, dir)
		inos := map[uint64]string{
			setScopeFlagsByPath(t, fifo, unix.UF_IMMUTABLE|unix.UF_NODUMP): "the FIFO",
		}
		calls := recordScopeFlags(t)
		named := recordSetFlagsAt(t)
		root, err := s.openDir(s.dir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := removeScopeTree(root, s.dir, "1001", s.uid, true); err != nil {
			t.Fatalf("removeScopeTree over a uchg FIFO: %v", err)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the scope directory is still there: %v", err)
		}
		for _, c := range *calls {
			if what, ok := inos[c.ino]; ok {
				t.Errorf("rm-scope opened %s to clear its flag: %+v", what, c)
			}
		}
		got := map[uint64]bool{}
		for _, c := range *named {
			got[c.ino] = true
			if c.flags != 0 {
				t.Errorf("a flag write by name wrote %#x, want exactly 0", c.flags)
			}
		}
		for ino, what := range inos {
			if !got[ino] {
				t.Errorf("%s's flag was not cleared by name (calls %+v)", what, *named)
			}
		}
	})
}

// A socket takes clearUnopened's path as a FIFO does: rm-scope never
// opens it (macOS refuses with EOPNOTSUPP) and writes 0 by name. No real
// socket is needed to drive it: the entry's fstatat result is all the walk
// reads of its type, so a flagged FIFO's stat with its type set to
// S_IFSOCK drives clearScopeFlags down the socket branch. No descriptor
// flag write is made, the write by name is exactly 0, and the entry's
// flags are clear afterwards.
func TestClearScopeFlagsSocketTypeUnopened(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "sock")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(p, 0) })
	setScopeFlagsByPath(t, p, unix.UF_IMMUTABLE|unix.UF_APPEND)
	dfd, err := unix.Open(d, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, "sock", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	st.Mode = st.Mode&^unix.S_IFMT | unix.S_IFSOCK
	calls := recordScopeFlags(t)
	named := recordSetFlagsAt(t)
	w := &rmWalk{svc: st.Uid, base: d, scope: "user/1001"}
	leave, err := w.clearScopeFlags(dfd, "sock", "sock", &st)
	if err != nil || leave {
		t.Fatalf("clearScopeFlags of a socket-typed entry: leave %v, %v", leave, err)
	}
	if len(*calls) != 0 {
		t.Errorf("rm-scope opened the socket-typed entry to clear its flag: %+v", *calls)
	}
	if len(*named) != 1 || (*named)[0].flags != 0 || (*named)[0].ino != st.Ino {
		t.Errorf("the writes by name were %+v, want one write of 0 to inode %d", *named, st.Ino)
	}
	if err := unix.Lstat(p, &st); err != nil || st.Flags != 0 {
		t.Errorf("the entry has flags %#x (%v), want none", st.Flags, err)
	}
}

// setScopeFlagsByPath sets flags on p by path (chflags never opens it), as
// the service user would on its own FIFO or socket, and returns its inode.
func setScopeFlagsByPath(t *testing.T, p string, flags int) uint64 {
	t.Helper()
	if err := unix.Chflags(p, flags); err != nil {
		t.Fatalf("set flags %#x on %s: %v", flags, p, err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// recordSetFlagsAt replaces setFlagsAt with the real call that records
// each call's inode (by fstatat of the name, not followed), for the
// test's life.
func recordSetFlagsAt(t *testing.T) *[]rmFlagCall {
	t.Helper()
	var calls []rmFlagCall
	saved := setFlagsAt
	setFlagsAt = func(dirfd int, name string, flags uint32) error {
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Errorf("fstatat the name rm-scope flags: %v", err)
		}
		calls = append(calls, rmFlagCall{ino: st.Ino, flags: int(flags)})
		return saved(dirfd, name, flags)
	}
	t.Cleanup(func() { setFlagsAt = saved })
	return &calls
}

// rm-scope clears a locking flag whoever owns the entry, when it has one
// link and no system flag: a flagged file cannot be hard-linked, so it is
// debris of the tree being removed. Through the seam, the service user is
// another uid than the files' owner: a uchg file with one link and a
// uchg,nodump FIFO are cleared and the scope removed. A uchg file another
// user owns with two links (linked before it was flagged) is left: the
// removal fails with EPERM, the error says it has 2 links and offers no
// command, and its flag is kept.
func TestRemoveScopeClearsForeignFlags(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(fmt.Sprintf("second link %v", linked), func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			t.Cleanup(func() { unflagScopeTree(dir) })
			plant := filepath.Join(dir, scopeEntriesName, "foreign")
			if err := os.WriteFile(plant, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if linked {
				if err := os.Link(plant, filepath.Join(dir, "foreign-alias")); err != nil {
					t.Fatal(err)
				}
			}
			fifo := filepath.Join(dir, "foreign-fifo")
			if err := unix.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			giveScopeTree(t, dir)
			setScopeFlags(t, plant, unix.UF_IMMUTABLE, false)
			setScopeFlagsByPath(t, fifo, unix.UF_IMMUTABLE|unix.UF_NODUMP)
			root, err := s.openDir(s.dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = removeScopeTree(root, s.dir, "1001", s.uid+1, true)
			if linked {
				var st unix.Stat_t
				if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "has 2 links") || strings.Contains(err.Error(), "sudo") || strings.Contains(err.Error(), "chflags") {
					t.Fatalf("removeScopeTree over another user's twice-linked uchg file: %v, want EPERM saying it has 2 links, with no command", err)
				}
				if serr := unix.Lstat(plant, &st); serr != nil || st.Flags&unix.UF_IMMUTABLE == 0 {
					t.Errorf("the twice-linked file has flags %#x (%v); want uchg kept", st.Flags, serr)
				}
				return
			}
			if err != nil {
				t.Fatalf("removeScopeTree over another user's one-link uchg file and FIFO: %v", err)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
		})
	}
}

// rm-scope's write by name never sets a flag: when the FIFO it stat'ed is
// swapped, between that fstatat and the setattrlistat, for a hard link to
// an unflagged file outside the tree (the seam does the swap), the write
// is exactly 0, so the outside file's flags stay 0 (a write of the FIFO's
// flags less the locking ones would set nodump on it). The re-stat sees
// another file, so the name counts as not cleared and the next pass
// unlinks the link; the outside file survives.
func TestRemoveScopeSwappedNameGetsZero(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	t.Cleanup(func() { unflagScopeTree(dir) })
	fifo := filepath.Join(dir, "planted-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(server), "outside")
	if err := os.WriteFile(outside, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveScopeTree(t, dir)
	giveToService(t, outside)
	setScopeFlagsByPath(t, fifo, unix.UF_APPEND|unix.UF_NODUMP)
	saved := setFlagsAt
	swapped := false
	setFlagsAt = func(dirfd int, name string, flags uint32) error {
		if !swapped && name == "planted-fifo" {
			swapped = true
			if err := unix.Chflags(fifo, 0); err != nil {
				t.Errorf("clear the FIFO's flags: %v", err)
			}
			if err := unix.Unlinkat(dirfd, name, 0); err != nil {
				t.Errorf("unlink the FIFO: %v", err)
			}
			if err := os.Link(outside, fifo); err != nil {
				t.Errorf("link the outside file in: %v", err)
			}
		}
		return saved(dirfd, name, flags)
	}
	t.Cleanup(func() { setFlagsAt = saved })
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := removeScopeTree(root, s.dir, "1001", s.uid, true); err != nil {
		t.Fatalf("removeScopeTree over a swapped name: %v", err)
	}
	if !swapped {
		t.Fatal("the FIFO was never written by name")
	}
	var st unix.Stat_t
	if err := unix.Lstat(outside, &st); err != nil || st.Flags != 0 || st.Nlink != 1 {
		t.Fatalf("the outside file has flags %#x nlink %d (%v), want 0 and its one link", st.Flags, st.Nlink, err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
}
