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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The tests for Delete burying before the steps the service user controls:
// keystore/.lock and the judgment of keystore/ (docs/design/keystore.md §
// "Concurrency", gate row G23).

// TestDeleteBuriesUnderHeldEntryLock (G23): with keystore/.lock held by
// another descriptor, Delete times out on it, but only after the burial: the
// error says the entry is already deleted and its tree not removed, the copy
// is refused, and a retry once the lock is free removes the tree.
func TestDeleteBuriesUnderHeldEntryLock(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	gen := generationOf(t, server, "k")
	s.lockWait = 200 * time.Millisecond
	held, err := os.Open(filepath.Join(server, "keystore", lockName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	err = s.Delete(ctx, "k")
	if !errors.Is(err, errLockTimeout) || !strings.Contains(err.Error(), "already deleted") || !strings.Contains(err.Error(), "rerun") {
		t.Fatalf("Delete under a held .lock: %v, want the lock timeout saying the entry is already deleted", err)
	}
	if ts := tombstonesOf(t, server); len(ts["k"]) != 1 || ts["k"][0].Generation != gen {
		t.Fatalf("tombstones after the timeout = %+v, want k's generation %s", ts, gen)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of the entry left behind", err)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete once the lock is free: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry directory after the retry: %v, want it gone", err)
	}
}

// TestDeleteBuriesUnderReplacedEntryLock (G23): keystore/.lock replaced by a
// directory fails the entry-tree lock, but the burial still lands.
func TestDeleteBuriesUnderReplacedEntryLock(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	gen := generationOf(t, server, "k")
	lock := filepath.Join(server, "keystore", lockName)
	remove(t, lock)
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	err := s.Delete(ctx, "k")
	if err == nil || !strings.Contains(err.Error(), "already deleted") {
		t.Fatalf("Delete under a .lock directory: %v, want an error saying the entry is already deleted", err)
	}
	if ts := tombstonesOf(t, server); len(ts["k"]) != 1 || ts["k"][0].Generation != gen {
		t.Fatalf("tombstones = %+v, want k's generation %s", ts, gen)
	}
}
