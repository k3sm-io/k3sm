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
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// The tests for the floor's own lock: docs/design/keystore.md §
// "Concurrency". They take a real flock on a t.TempDir() data root.

// putFloorFile replaces the floor file under server's data root with fl, as
// a writer the store does not serialize with would: one under a swapped
// .lock, which the data-root lock is there to stop.
func putFloorFile(t *testing.T, server string, fl floor) {
	t.Helper()
	b, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	tmp := floorPath(server) + ".test"
	if err := os.WriteFile(tmp, b, floorFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, floorPath(server)); err != nil {
		t.Fatal(err)
	}
}

// TestFloorWriteRereads: each floor write applies its own operation to the
// floor it reads under the lock, never a copy it read earlier, so a floor
// changed since the verb began is neither lowered nor emptied.
func TestFloorWriteRereads(t *testing.T) {
	t.Run("a stale floor held in memory cannot lower an entry's seq", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("one"))
		mustPut(t, s, "b", KindOpaque, []byte("one"))
		start := floorOf(t, server)
		// Between the Rotate's start and its floor write, the floor moves on:
		// b to sequence 9, and a itself past the sequence the Rotate commits.
		s.step = func(name string) error {
			if name == "write "+currentName {
				moved := floor{
					"a": {Generation: start["a"].Generation, Seq: 7},
					"b": {Generation: start["b"].Generation, Seq: 9},
				}
				putFloorFile(t, server, moved)
			}
			return nil
		}
		mustRotate(t, s, "a", "two")
		got := floorOf(t, server)
		if got["b"].Seq != 9 || got["b"].Generation != start["b"].Generation {
			t.Fatalf("floor b after the Rotate = %+v, want sequence 9 kept", got["b"])
		}
		if got["a"].Seq != 7 {
			t.Fatalf("floor a after the Rotate = %+v, want sequence 7 kept (the higher of 7 and 2)", got["a"])
		}
	})

	// The floor records k live at a generation the Delete never read: the
	// Delete buries the floor's own live generation, root's record, rather
	// than trust the directory it read, so whatever stands under the name
	// at that generation is refused, never accepted.
	t.Run("a Delete buries the floor's live generation, not the directory's", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		mustPut(t, s, "other", KindOpaque, []byte("one"))
		start := floorOf(t, server)
		newer := floorEntry{Generation: strings.Repeat("11", generationSize), Seq: 1}
		// After the Delete removed the pointer, a Put of a new generation of
		// k records its floor.
		s.step = func(name string) error {
			if name == "delete k" {
				putFloorFile(t, server, floor{"k": newer, "other": start["other"]})
			}
			return nil
		}
		if err := s.Delete(t.Context(), "k"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got := floorOf(t, server)
		if got["k"].live() || !got["k"].buries(newer.Generation) || len(got["k"].burials()) != 1 {
			t.Fatalf("floor k after the Delete = %+v, want the floor's live %s buried", got["k"], newer.Generation)
		}
		if got["other"] != start["other"] {
			t.Fatalf("floor other after the Delete = %+v, want %+v", got["other"], start["other"])
		}

		// The Delete of the generation the floor records still removes it.
		mustPut(t, s, "gone", KindOpaque, []byte("one"))
		if err := s.Delete(t.Context(), "gone"); err != nil {
			t.Fatalf("Delete gone: %v", err)
		}
		if f := floorOf(t, server)["gone"]; len(f.burials()) == 0 {
			t.Fatalf("the Delete left its own generation's floor entry live: %+v, want a tombstone", f)
		}
	})
}

// holdFloorLock takes an exclusive flock on s's keystore-lock, creating it
// if no verb has yet, and holds it until the test ends.
func holdFloorLock(t *testing.T, s *FileStore) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(s.dataRoot, floorLockName), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, floorLockMode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
}

// holdDataRootFlock takes an exclusive flock on s's data-root directory
// itself, as any local process able to open it could, and holds it until
// the test ends.
func holdDataRootFlock(t *testing.T, s *FileStore) {
	t.Helper()
	f, err := os.Open(s.dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
}

// floorVerbs returns each verb that writes the floor, bound to ctx and s,
// over an entry a that exists and a name b that does not.
func floorVerbs(ctx context.Context, s *FileStore) map[string]func() error {
	return map[string]func() error{
		"Put":        func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err },
		"Rotate":     func() error { _, err := s.Rotate(ctx, "a", []byte("b")); return err },
		"Delete":     func() error { return s.Delete(ctx, "a") },
		"RaiseFloor": func() error { return s.RaiseFloor(ctx) },
		"Rewrap":     func() error { return s.Rewrap(ctx, rewrapKey(9)) },
	}
}

// TestFloorLockBoundedWait: a held keystore-lock gives a timeout error
// within the bound to every verb that writes the floor, never a hang, and a
// cancelled context ends the wait. Readers do not take it. It runs in a
// synctest bubble, as TestLockBoundedWait does, so the production bound
// passes at once on the bubble's clock and no wall clock is read.
func TestFloorLockBoundedWait(t *testing.T) {
	t.Run("held", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := t.Context()
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			if s.lockWait != lockTimeout {
				t.Fatalf("lockWait = %v, want the production bound %v", s.lockWait, lockTimeout)
			}
			before := floorOf(t, server)
			holdFloorLock(t, s)
			for op, fn := range floorVerbs(ctx, s) {
				start := time.Now()
				err := fn()
				if took := time.Since(start); !errors.Is(err, errLockTimeout) || took < s.lockWait || took > s.lockWait+time.Second {
					t.Fatalf("%s under a held keystore-lock: %v after %v of bubble time, want errLockTimeout after %v", op, err, took, s.lockWait)
				}
			}
			mustCurrent(t, s, "a", "a")
			if _, err := os.Lstat(filepath.Join(server, "keystore", "b")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the timed-out Put left b: %v", err)
			}
			if after := floorOf(t, server); after["a"] != before["a"] || len(after) != len(before) {
				t.Fatalf("floor after the timed-out verbs = %+v, was %+v", after, before)
			}
		})
	})
	t.Run("a cancelled context ends the wait", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, _ := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			holdFloorLock(t, s)
			s.lockWait = time.Minute
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			if _, err := s.Rotate(ctx, "a", []byte("b")); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Rotate: %v, want the context's error", err)
			}
			if took := time.Since(start); took >= s.lockWait {
				t.Fatalf("Rotate waited %v of bubble time, want the context's 50ms", took)
			}
		})
	})
}

// TestDataRootFlockBlocksNoFloorWrite: a flock held on the data-root
// directory itself, which any local process able to open the 0755 data root
// can take, no longer blocks a verb that writes the floor. It runs in a
// synctest bubble, so a verb that did wait on it would fail with
// errLockTimeout at once rather than after the wall-clock bound.
func TestDataRootFlockBlocksNoFloorWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		holdDataRootFlock(t, s)
		for _, op := range []string{"Put", "Rotate", "RaiseFloor", "Rewrap", "Delete"} {
			if err := floorVerbs(ctx, s)[op](); err != nil {
				t.Fatalf("%s under a flock held on the data-root directory: %v, want success", op, err)
			}
		}
		fl := floorOf(t, server)
		if len(fl["a"].burials()) == 0 {
			t.Fatalf("floor after the Delete still records a live: %+v, want a tombstone", fl)
		}
		if fl["b"].Seq != 1 {
			t.Fatalf("floor b after the Put = %+v, want sequence 1", fl["b"])
		}
	})
}

// TestFloorLockFileUntrustedRefused: keystore-lock is judged on the
// descriptor the lock is taken on, and a verb that writes the floor refuses
// one that is not a regular file, not owned by root (the floor's owner), or
// group- or other-accessible, and changes nothing.
func TestFloorLockFileUntrustedRefused(t *testing.T) {
	ctx := context.Background()
	lockPath := func(s *FileStore) string { return filepath.Join(s.dataRoot, floorLockName) }
	cases := []struct {
		name   string
		damage func(t *testing.T, s *FileStore)
	}{
		{"group-readable", func(t *testing.T, s *FileStore) { chmod(t, lockPath(s), 0o640) }},
		{"other-readable", func(t *testing.T, s *FileStore) { chmod(t, lockPath(s), 0o604) }},
		{"group-writable", func(t *testing.T, s *FileStore) { chmod(t, lockPath(s), 0o620) }},
		{"not owned by root", func(t *testing.T, s *FileStore) {
			// Non-root, the data root and the lock file have one owner, the
			// running user, and no other can be made.
			if !asRoot() {
				t.Skip("needs root to give the file to another user")
			}
			if err := os.Lchown(lockPath(s), int(otherUID(t)), 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"a symlink", func(t *testing.T, s *FileStore) {
			copyFile(t, lockPath(s), lockPath(s)+".real")
			replaceWithSymlink(t, lockPath(s), floorLockName+".real")
		}},
		{"a dangling symlink", func(t *testing.T, s *FileStore) { replaceWithSymlink(t, lockPath(s), "nowhere") }},
		{"a FIFO", func(t *testing.T, s *FileStore) { replaceWithFIFO(t, lockPath(s)) }},
		{"a directory", func(t *testing.T, s *FileStore) {
			if err := os.Remove(lockPath(s)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(lockPath(s), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			if _, err := os.Lstat(lockPath(s)); err != nil {
				t.Fatalf("the first Put left no %s: %v", floorLockName, err)
			}
			before := floorOf(t, server)
			tc.damage(t, s)
			for op, fn := range floorVerbs(ctx, s) {
				err := fn()
				if !errors.Is(err, errFloorUntrusted) || !strings.Contains(err.Error(), floorLockName) {
					t.Fatalf("%s over a %s %s: %v, want errFloorUntrusted naming it", op, tc.name, floorLockName, err)
				}
			}
			if after := floorOf(t, server); !maps.Equal(after, before) {
				t.Fatalf("floor after the refused verbs = %+v, was %+v", after, before)
			}
			if _, err := os.Lstat(filepath.Join(server, "keystore", "b")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the refused Put left b: %v", err)
			}
		})
	}
}

// TestFloorLockFileRecheckedAfterFlock: once keystore-lock is flocked, it is
// Lstat'd again through the data root it was opened in, and the verb refuses
// (errFloorUntrusted) a name that no longer holds the locked file, which
// would let two writers lock different files. Its link count is not judged:
// macOS lets any local user hard-link a file it cannot read, so a refusal of
// a second link would hand every user a lasting block on the floor verbs,
// and a second link is the same inode, so it changes nothing about the lock.
func TestFloorLockFileRecheckedAfterFlock(t *testing.T) {
	ctx := context.Background()
	lockPath := func(s *FileStore) string { return filepath.Join(s.dataRoot, floorLockName) }
	t.Run("a hard link outside the data root blocks nothing", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		// t.TempDir is on the data root's volume, as the data root is
		// another t.TempDir.
		if err := os.Link(lockPath(s), filepath.Join(t.TempDir(), "held")); err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"Put", "Rotate", "RaiseFloor", "Rewrap", "Delete"} {
			if err := floorVerbs(ctx, s)[op](); err != nil {
				t.Fatalf("%s with a second link to %s: %v, want success", op, floorLockName, err)
			}
		}
		if fl := floorOf(t, server); fl["b"].Seq != 1 {
			t.Fatalf("floor b after the Put = %+v, want sequence 1", fl["b"])
		}
	})
	t.Run("replaced after the open", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		before := floorOf(t, server)
		replaced := 0
		// The hook runs after the flock, before the re-check: a new file of
		// the same owner and mode is renamed over the name.
		s.dataRootLocked = func() {
			replaced++
			tmp := lockPath(s) + ".new"
			if err := os.WriteFile(tmp, nil, floorLockMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, lockPath(s)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.Rotate(ctx, "a", []byte("b")); !errors.Is(err, errFloorUntrusted) || !strings.Contains(err.Error(), floorLockName) {
			t.Fatalf("Rotate over a %s replaced after its open: %v, want errFloorUntrusted naming it", floorLockName, err)
		}
		if replaced != 1 {
			t.Fatalf("the lock file was replaced %d times, want 1", replaced)
		}
		if after := floorOf(t, server); !maps.Equal(after, before) {
			t.Fatalf("floor after the refused Rotate = %+v, was %+v", after, before)
		}
		mustCurrent(t, s, "a", "a")
	})
}

// TestFloorLockFileCreated: the first verb that writes the floor creates
// keystore-lock in the data root, a regular file owned by the floor's owner
// (root in production) and mode 0600.
func TestFloorLockFileCreated(t *testing.T) {
	s, _ := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	fi, err := os.Lstat(filepath.Join(s.dataRoot, floorLockName))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || int(st.Uid) != s.floorUID || int(st.Gid) != s.floorGID {
		t.Fatalf("%s is %s owned by %d:%d, want a regular file 0600 owned by %d:%d", floorLockName, fi.Mode(), st.Uid, st.Gid, s.floorUID, s.floorGID)
	}
}

// TestFloorNotWritableChangesNothing: a verb that cannot write the floor
// finds out before it changes anything, so it leaves no master, no entry
// directory and no half-written version behind.
func TestFloorNotWritableChangesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a mode-0555 directory")
	}
	ctx := context.Background()
	readOnly := func(t *testing.T, s *FileStore) {
		t.Helper()
		if err := os.Chmod(s.dataRoot, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(s.dataRoot, 0o755) })
	}

	t.Run("first Put", func(t *testing.T) {
		s, server := newTestStore(t)
		readOnly(t, s)
		if _, err := s.Put(ctx, "a", KindOpaque, []byte("a")); !errors.Is(err, errFloorNotWritable) {
			t.Fatalf("Put: %v, want errFloorNotWritable", err)
		}
		if names, _ := os.ReadDir(server); len(names) != 0 {
			t.Fatalf("the refused Put created %v (a master or the entries' directory)", names)
		}
	})

	t.Run("Put, Rotate and Delete over an entry", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		before := dirContents(t, filepath.Join(server, "keystore", "a"))
		readOnly(t, s)
		for op, fn := range map[string]func() error{
			"Put":        func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err },
			"Rotate":     func() error { _, err := s.Rotate(ctx, "a", []byte("b")); return err },
			"Delete":     func() error { return s.Delete(ctx, "a") },
			"RaiseFloor": func() error { return s.RaiseFloor(ctx) },
		} {
			if err := fn(); !errors.Is(err, errFloorNotWritable) {
				t.Fatalf("%s: %v, want errFloorNotWritable", op, err)
			}
		}
		if after := dirContents(t, filepath.Join(server, "keystore", "a")); !maps.Equal(after, before) {
			t.Fatalf("the refused verbs changed the entry: %q, was %q", after, before)
		}
		if _, err := os.Lstat(filepath.Join(server, "keystore", "b")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused Put left b: %v", err)
		}
		mustCurrent(t, s, "a", "a")
	})
}

// TestDataRootSwapRefused: the data root a floor-writing verb locks is
// opened without following a symlink, and the directory the floor is then
// read and written through must be the one it locked, so neither a symlink
// at the data root nor a directory swapped in after the flock is written.
func TestDataRootSwapRefused(t *testing.T) {
	ctx := context.Background()
	t.Run("a symlink", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		before := floorOf(t, server)
		link := filepath.Join(t.TempDir(), "data")
		if err := os.Symlink(s.dataRoot, link); err != nil {
			t.Fatal(err)
		}
		s.dataRoot = link
		for op, fn := range map[string]func() error{
			"Put":        func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err },
			"Rotate":     func() error { _, err := s.Rotate(ctx, "k", []byte("two")); return err },
			"Delete":     func() error { return s.Delete(ctx, "k") },
			"RaiseFloor": func() error { return s.RaiseFloor(ctx) },
		} {
			if err := fn(); !errors.Is(err, errFloorUntrusted) {
				t.Errorf("%s through a symlinked data root: %v, want errFloorUntrusted", op, err)
			}
		}
		if after := floorOf(t, server); !maps.Equal(after, before) {
			t.Fatalf("floor after the refused verbs = %+v, was %+v", after, before)
		}
	})
	t.Run("swapped between the flock and the open", func(t *testing.T) {
		s, _ := newTestStore(t)
		// A data root apart from the server tree, so that swapping it moves
		// only the floor.
		s.dataRoot = filepath.Join(t.TempDir(), "data")
		if err := os.Mkdir(s.dataRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		swapped := false
		s.dataRootLocked = func() {
			if swapped {
				return
			}
			swapped = true
			if err := os.Rename(s.dataRoot, s.dataRoot+".locked"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(s.dataRoot, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.Rotate(ctx, "k", []byte("two")); !errors.Is(err, errFloorUntrusted) {
			t.Fatalf("Rotate over a data root swapped after its flock: %v, want errFloorUntrusted", err)
		}
		if !swapped {
			t.Fatal("the data root was never swapped")
		}
		if _, err := os.Lstat(filepath.Join(s.dataRoot, floorName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused Rotate wrote a floor into the swapped-in directory: %v", err)
		}
		mustCurrent(t, s, "k", "one")
	})
}

// TestLoopsStopOnContext: syncFloor and discardOrphans, which open or remove
// a file per name in a directory of up to maxDirNames names, stop with the
// context's error once it is done, and syncFloor then writes nothing.
func TestLoopsStopOnContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	s, server := newTestStore(t)
	// loopCtx checks at the first iteration, so two entries are enough.
	for i := range 2 {
		mustPut(t, s, fmt.Sprintf("k%d", i), KindOpaque, []byte("v"))
	}
	mustRotate(t, s, "k0", "two")
	// k0's floor one behind its pointer, so syncFloor has a raise to write.
	fl := floorOf(t, server)
	lagging := fl["k0"]
	lagging.Seq = 1
	fl["k0"] = lagging
	putFloorFile(t, server, fl)
	// An orphan above k0's current version, for discardOrphans to remove.
	orphan := entryPath(server, "k0", versionName(3))
	copyFile(t, entryPath(server, "k0", versionName(2)), orphan)

	root, done, err := s.openLocked(context.Background(), false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	l, read, err := s.lockFloor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer l.unlock()
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.syncFloor(cancelled, root, l, read, k); !errors.Is(err, context.Canceled) {
		t.Fatalf("syncFloor under a cancelled context: %v, want context.Canceled", err)
	}
	if got := floorOf(t, server)["k0"]; got != lagging {
		t.Fatalf("the stopped syncFloor wrote k0's floor %+v, want %+v left", got, lagging)
	}
	e, err := openEntry(root, "k0", read)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	if err := discardOrphans(cancelled, e, 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("discardOrphans under a cancelled context: %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(orphan); err != nil {
		t.Fatalf("the stopped discardOrphans removed the orphan: %v", err)
	}
	if err := discardOrphans(context.Background(), e, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discardOrphans left the orphan: %v", err)
	}
}
