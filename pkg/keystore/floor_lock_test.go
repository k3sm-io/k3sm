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
	"encoding/json"
	"errors"
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
	b, err := json.Marshal(floorFile{Version: floorFormat, Entries: fl})
	if err != nil {
		t.Fatal(err)
	}
	tmp := floorPath(server) + ".test"
	if err := os.WriteFile(tmp, append(b, '\n'), floorFileMode); err != nil {
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

	t.Run("a stale Delete cannot erase a newer Put's floor entry", func(t *testing.T) {
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
		if got["k"] != newer {
			t.Fatalf("floor k after the Delete = %+v, want the newer Put's %+v kept", got["k"], newer)
		}
		if got["other"] != start["other"] {
			t.Fatalf("floor other after the Delete = %+v, want %+v", got["other"], start["other"])
		}

		// The Delete of the generation the floor records still removes it.
		mustPut(t, s, "gone", KindOpaque, []byte("one"))
		if err := s.Delete(t.Context(), "gone"); err != nil {
			t.Fatalf("Delete gone: %v", err)
		}
		if _, ok := floorOf(t, server)["gone"]; ok {
			t.Fatal("the Delete left its own generation's floor entry")
		}
	})
}

// TestFloorLockBoundedWait: a held data-root lock gives a timeout error
// within the bound to every verb that writes the floor, never a hang, and a
// cancelled context ends the wait. Readers do not take it. It runs in a
// synctest bubble, as TestLockBoundedWait does, so the production bound
// passes at once.
func TestFloorLockBoundedWait(t *testing.T) {
	hold := func(t *testing.T, s *FileStore) {
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
	t.Run("held", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := t.Context()
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			if s.lockWait != lockTimeout {
				t.Fatalf("lockWait = %v, want the production bound %v", s.lockWait, lockTimeout)
			}
			before := floorOf(t, server)
			hold(t, s)
			for op, fn := range map[string]func() error{
				"Put":        func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err },
				"Rotate":     func() error { _, err := s.Rotate(ctx, "a", []byte("b")); return err },
				"Delete":     func() error { return s.Delete(ctx, "a") },
				"RaiseFloor": func() error { return s.RaiseFloor(ctx) },
			} {
				start := time.Now()
				err := fn()
				if took := time.Since(start); !errors.Is(err, errLockTimeout) || took < s.lockWait || took > s.lockWait+time.Second {
					t.Fatalf("%s under a held data-root lock: %v after %v of bubble time, want errLockTimeout after %v", op, err, took, s.lockWait)
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
			hold(t, s)
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
