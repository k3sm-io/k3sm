//go:build darwin

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

package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// realRemoveTree is a fakeSystem whose ownership answers are the model's, so
// an unprivileged test passes the root-owner check, and whose RemoveTree is
// the real one, on a real tree.
type realRemoveTree struct{ *fakeSystem }

func (realRemoveTree) RemoveTree(path string) error { return (darwinSystem{}).RemoveTree(path) }

// setFlags sets the file flags on path itself, never on what a symlink at path
// points at.
func setFlags(t *testing.T, path string, flags int) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_SYMLINK|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s to set its flags: %v", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchflags(fd, flags); err != nil {
		t.Fatalf("set flags %#x on %s: %v", flags, path, err)
	}
}

// flagsOf reads the file flags of path itself.
func flagsOf(t *testing.T, path string) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return st.Flags
}

// clearFlagsOnCleanup makes root removable again when the test ends, whatever
// the code under test left behind, so t.TempDir's own removal cannot fail.
// t.Cleanup runs last-registered first, so call it after t.TempDir.
func clearFlagsOnCleanup(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_SYMLINK|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return nil
			}
			defer func() { _ = unix.Close(fd) }()
			_ = unix.Fchflags(fd, 0)
			return nil
		})
	})
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("leftover\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// sweepOneTree runs the real sweep over cfg's staging root and pins that the
// tree goes and that a second sweep has nothing to report.
func sweepOneTree(t *testing.T, cfg Config) {
	t.Helper()
	f := &fakeSystem{}
	f.putOwned(cfg.stagingRoot(), 0, 0, fs.ModeDir|0o755, EntryDir)
	sys := realRemoveTree{f}
	if err := sweepStaging(sys, cfg); err != nil {
		t.Fatalf("sweepStaging = %v", err)
	}
	if _, err := os.Lstat(cfg.stagingRoot()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the staging root is still there after the sweep: lstat = %v", err)
	}
	if err := sweepStaging(sys, cfg); err != nil {
		t.Fatalf("a re-run of the sweep = %v", err)
	}
}

// TestSweepStagingClearsLockingFlags pins the wedge: a leftover carrying a user
// locking flag, or deeper than the process may hold descriptors, made uninstall
// fail with a staging sweep error after the teardown had finished, and fail
// again on every re-run. It is not parallel because one case lowers the
// process's descriptor limit; a parallel test does not run beside a serial one.
func TestSweepStagingClearsLockingFlags(t *testing.T) {
	newCfg := func(t *testing.T) (Config, string) {
		t.Helper()
		tmp := t.TempDir()
		clearFlagsOnCleanup(t, tmp)
		root := filepath.Join(tmp, "k3sm.staging")
		cfg := Config{InstallDir: filepath.Join(tmp, "k3sm"), StagingOptions: StagingOptions{StagingRoot: root}}.withDefaults()
		return cfg, tmp
	}

	t.Run("flagged files, directories and a symlink go", func(t *testing.T) {
		cfg, _ := newCfg(t)
		root := cfg.stagingRoot()
		mustWriteFile(t, filepath.Join(root, "app/immutable"))
		setFlags(t, filepath.Join(root, "app/immutable"), unix.UF_IMMUTABLE)
		mustWriteFile(t, filepath.Join(root, "app/append-only"))
		setFlags(t, filepath.Join(root, "app/append-only"), unix.UF_APPEND)
		mustWriteFile(t, filepath.Join(root, "locked/inner/file"))
		setFlags(t, filepath.Join(root, "locked/inner"), unix.UF_IMMUTABLE)
		setFlags(t, filepath.Join(root, "locked"), unix.UF_APPEND)
		if err := os.Symlink("immutable", filepath.Join(root, "app/link")); err != nil {
			t.Fatal(err)
		}
		setFlags(t, filepath.Join(root, "app/link"), unix.UF_IMMUTABLE)
		if err := unix.Mkfifo(filepath.Join(root, "app/fifo"), 0o644); err != nil {
			t.Fatal(err)
		}
		setFlags(t, filepath.Join(root, "app/fifo"), unix.UF_IMMUTABLE)
		setFlags(t, filepath.Join(root, "app"), unix.UF_IMMUTABLE)
		setFlags(t, root, unix.UF_IMMUTABLE)
		sweepOneTree(t, cfg)
	})

	t.Run("nothing outside the tree changes", func(t *testing.T) {
		cfg, tmp := newCfg(t)
		root := cfg.stagingRoot()
		// A symlink to a flagged file is not followed.
		pointedAt := filepath.Join(tmp, "pointed-at")
		mustWriteFile(t, pointedAt)
		mustWriteFile(t, filepath.Join(root, "app/file"))
		if err := os.Symlink(pointedAt, filepath.Join(root, "app/link")); err != nil {
			t.Fatal(err)
		}
		setFlags(t, filepath.Join(root, "app/link"), unix.UF_IMMUTABLE)
		setFlags(t, pointedAt, unix.UF_IMMUTABLE)
		// A hard link with no flag on it goes, and its other name stays.
		plain := filepath.Join(tmp, "plain")
		mustWriteFile(t, plain)
		if err := os.Link(plain, filepath.Join(root, "app/plain-link")); err != nil {
			t.Fatal(err)
		}
		sweepOneTree(t, cfg)
		if got := flagsOf(t, pointedAt); got&unix.UF_IMMUTABLE == 0 {
			t.Errorf("%s lost its immutable flag (flags %#x)", pointedAt, got)
		}
		if _, err := os.Lstat(plain); err != nil {
			t.Errorf("the other name of a hard link went: %v", err)
		}
	})

	t.Run("a hard-linked file with a locking flag is refused and named", func(t *testing.T) {
		cfg, tmp := newCfg(t)
		root := cfg.stagingRoot()
		// The flag belongs to the file, so it is on the name outside the tree
		// too. Clearing it here, even for a moment, puts that flag at the mercy
		// of a kill, so it is never cleared.
		outside := filepath.Join(tmp, "outside")
		mustWriteFile(t, outside)
		inTree := filepath.Join(root, "app/second-name")
		if err := os.MkdirAll(filepath.Dir(inTree), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, inTree); err != nil {
			t.Fatal(err)
		}
		setFlags(t, outside, unix.UF_IMMUTABLE)
		mustWriteFile(t, filepath.Join(root, "other/file"))
		var before unix.Stat_t
		if err := unix.Lstat(outside, &before); err != nil {
			t.Fatal(err)
		}

		f := &fakeSystem{}
		f.putOwned(root, 0, 0, fs.ModeDir|0o755, EntryDir)
		err := sweepStaging(realRemoveTree{f}, cfg)
		for _, want := range []string{"hard-linked file with a locking flag", "second-name"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("sweepStaging = %v, want it to name %q", err, want)
			}
		}

		var after unix.Stat_t
		if err := unix.Lstat(outside, &after); err != nil {
			t.Fatal(err)
		}
		if after.Flags&unix.UF_IMMUTABLE == 0 {
			t.Errorf("the outside name lost its immutable flag (flags %#x)", after.Flags)
		}
		// A clear and a restore leave the flag as it was, but not the change
		// time, which is what shows the flag was never touched.
		if after.Ctim != before.Ctim {
			t.Errorf("the file's change time moved from %v to %v: its flags were written", before.Ctim, after.Ctim)
		}
		if after.Nlink != 2 {
			t.Errorf("the file has %d links, want 2: the name in the tree stays for the operator", after.Nlink)
		}
		if _, err := os.Lstat(filepath.Join(root, "other")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the refusal stopped the rest of the sweep: lstat other = %v", err)
		}
	})

	t.Run("a tree deeper than the descriptor limit goes", func(t *testing.T) {
		cfg, _ := newCfg(t)
		root := cfg.stagingRoot()
		const depth, limit = 300, 64
		deepest := filepath.Join(root, strings.Repeat("d/", depth)+"file")
		mustWriteFile(t, deepest)
		setFlags(t, deepest, unix.UF_IMMUTABLE)
		// The walk meets the limit somewhere in this band, so a directory it
		// has to move there carries a flag too.
		dir := root
		for level := 1; level <= 100; level++ {
			dir = filepath.Join(dir, "d")
			if level >= 20 {
				setFlags(t, dir, unix.UF_IMMUTABLE)
			}
		}

		var saved unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &saved); err != nil {
			t.Fatal(err)
		}
		lowered := saved
		lowered.Cur = limit
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lowered); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &saved); err != nil {
				t.Fatalf("restore the descriptor limit: %v", err)
			}
		}()
		var held []int
		for len(held) < depth {
			fd, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				if !errors.Is(err, unix.EMFILE) {
					t.Fatalf("probe the descriptor limit: %v", err)
				}
				break
			}
			held = append(held, fd)
		}
		for _, fd := range held {
			_ = unix.Close(fd)
		}
		if len(held) >= depth {
			t.Fatalf("the limit let %d descriptors open; the tree must be deeper than the limit", len(held))
		}
		sweepOneTree(t, cfg)
	})
}

// TestRemoveTreeStopsAtMountPoint models a volume mounted inside the tree, and
// on the tree's root, by reporting another device for that directory: a real
// mount needs a disk image. Nothing on the far side is touched, and everything
// else in the tree still goes.
func TestRemoveTreeStopsAtMountPoint(t *testing.T) {
	t.Parallel()
	inodeOf := func(t *testing.T, path string) uint64 {
		t.Helper()
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	otherVolume := func(ino uint64) func(int, *unix.Stat_t) error {
		return func(fd int, st *unix.Stat_t) error {
			if err := unix.Fstat(fd, st); err != nil {
				return err
			}
			if st.Ino == ino {
				st.Dev++
			}
			return nil
		}
	}

	t.Run("inside the tree", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		clearFlagsOnCleanup(t, tmp)
		root := filepath.Join(tmp, "tree")
		kept := filepath.Join(root, "sub/mnt/kept")
		mustWriteFile(t, kept)
		setFlags(t, kept, unix.UF_IMMUTABLE)
		gone := []string{"a/file", "sub/b/file", "sub/z/file", "z/file"}
		for _, name := range gone {
			mustWriteFile(t, filepath.Join(root, name))
		}
		r := newTreeRemover()
		r.fstat = otherVolume(inodeOf(t, filepath.Dir(kept)))
		if err := r.remove(root); !errors.Is(err, errCrossesMount) {
			t.Fatalf("remove = %v, want errCrossesMount", err)
		}
		if got := flagsOf(t, kept); got&unix.UF_IMMUTABLE == 0 {
			t.Errorf("the flag across the mount point was cleared (flags %#x)", got)
		}
		for _, name := range []string{"a", "sub/b", "sub/z", "z"} {
			if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s survived beside the mount point: lstat = %v", name, err)
			}
		}
	})

	t.Run("on the tree's root", func(t *testing.T) {
		t.Parallel()
		root := filepath.Join(t.TempDir(), "tree")
		kept := filepath.Join(root, "kept")
		mustWriteFile(t, kept)
		r := newTreeRemover()
		r.fstat = otherVolume(inodeOf(t, root))
		if err := r.remove(root); !errors.Is(err, errCrossesMount) {
			t.Fatalf("remove = %v, want errCrossesMount", err)
		}
		if _, err := os.Lstat(kept); err != nil {
			t.Errorf("a file on the mounted volume went: %v", err)
		}
	})
}

// TestRemoveTreeLeavesFlagsAboveTheTree pins the edge of the walk: the directory
// holding the tree is not the removal's to change, so its flag stays and the
// EPERM it causes is the error.
func TestRemoveTreeLeavesFlagsAboveTheTree(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	clearFlagsOnCleanup(t, tmp)
	holder := filepath.Join(tmp, "holder")
	root := filepath.Join(holder, "tree")
	mustWriteFile(t, filepath.Join(root, "file"))
	setFlags(t, holder, unix.UF_IMMUTABLE)
	err := (darwinSystem{}).RemoveTree(root)
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("RemoveTree = %v, want EPERM", err)
	}
	if got := flagsOf(t, holder); got&unix.UF_IMMUTABLE == 0 {
		t.Errorf("the flag on the directory above the tree was cleared (flags %#x)", got)
	}
}

// TestRemoveTreeOfASymlinkOrNothing pins the two top-level cases os.RemoveAll
// also answered: a symlink at path is unlinked and its target kept, and an
// absent path is success.
func TestRemoveTreeOfASymlinkOrNothing(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target/file")
	mustWriteFile(t, target)
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(filepath.Dir(target), link); err != nil {
		t.Fatal(err)
	}
	if err := (darwinSystem{}).RemoveTree(link); err != nil {
		t.Fatalf("RemoveTree(symlink) = %v", err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the symlink survived: lstat = %v", err)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("the symlink's target went: %v", err)
	}
	for _, absent := range []string{filepath.Join(tmp, "absent"), filepath.Join(tmp, "absent/deeper")} {
		if err := (darwinSystem{}).RemoveTree(absent); err != nil {
			t.Errorf("RemoveTree(%s) = %v", absent, err)
		}
	}
}
