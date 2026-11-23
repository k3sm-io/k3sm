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
	"syscall"
	"testing"
	"testing/synctest"
)

// TestMaintenanceTakesFloorLockFirst (G7): the maintenance verbs (floor
// --rebuild, audit --rotate and rm-scope, through lockMaintenance) take
// keystore-lock before keystore/.lock, the order Put, Rotate, Delete and
// Rewrap keep, so no two verbs wait on each other's lock. With .lock held,
// the verb is caught waiting for it while it already holds keystore-lock;
// once .lock is free it takes both, and releases both.
func TestMaintenanceTakesFloorLockFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		held, err := os.Open(filepath.Join(server, "keystore", lockName))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = held.Close() }()
		if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		root, err := s.openDir(s.dir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		done := make(chan error, 1)
		go func() {
			fl, unlock, err := s.lockMaintenance(ctx, root)
			if err == nil {
				unlock()
				fl.unlock()
			}
			done <- err
		}()
		synctest.Wait()
		probe, err := os.Open(filepath.Join(s.dataRoot, floorLockName))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = probe.Close() }()
		if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatalf("keystore-lock while the maintenance verb waits for .lock: flock = %v, want it held (EWOULDBLOCK)", err)
		}
		if err := held.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("lockMaintenance once .lock is free: %v", err)
		}
		if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("keystore-lock after the verb released it: %v", err)
		}
	})
}
