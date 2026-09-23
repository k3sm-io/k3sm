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

package podlogs

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// TestPodDirLockKeyMatchesGC pins the fact DirLocks' own doc comment states but
// nothing previously checked: podDirOfContainerLog — the function Clean and
// processContainer actually call to build their DirLocks key — must return a
// value byte-identical to what gc.go builds via BuildPodLogsDirectory, since
// they share one *DirLocks and any mismatch silently drops all mutual exclusion
// between rotation and GC. Calls the real production function, not a
// reimplementation of its formula. Found during the 2026-09-23 A1 audit.
func TestPodDirLockKeyMatchesGC(t *testing.T) {
	const podLogsDir = "/var/log/pods"
	logPath := BuildContainerLogsPath(podLogsDir, "default", "nginx", "abc-123", "nginx", 0)

	rotatorKey := podDirOfContainerLog(logPath)
	gcKey := BuildPodLogsDirectory(podLogsDir, "default", "nginx", "abc-123")

	if rotatorKey != gcKey {
		t.Fatalf("rotator lock key %q != GC lock key %q — DirLocks gives these two different mutexes, so they no longer exclude each other", rotatorKey, gcKey)
	}
}

// TestCleanLocksOnThePodDirectoryGCUses drives the REAL Clean method (not a
// reimplementation of its key formula) and checks, via the shared *DirLocks'
// own map, that it acquired the exact same mutex a real GC sharing that
// DirLocks would use for the same pod. This is deterministic (no timing/sleep
// races): pre-seed the lock map with only the pod-directory key, call Clean,
// then assert the map still has exactly one entry — if Clean had locked on a
// different (e.g. container-directory) key, DirLocks would have minted a
// second mutex and the map would have grown to two entries.
//
// Before the fix, this test fails: Clean locked on filepath.Dir(logPath) (the
// container directory), a different string from BuildPodLogsDirectory's
// result, so the map grew to 2 and GC's os.RemoveAll(podDir) ran under a
// completely different, unshared mutex than Clean's os.Remove calls in the
// same tree — no exclusion at all. Found during the 2026-09-23 A1 audit.
func TestCleanLocksOnThePodDirectoryGCUses(t *testing.T) {
	locks := NewDirLocks()
	const podLogsDir = "/var/log/pods"
	containerLogPath := BuildContainerLogsPath(podLogsDir, "default", "nginx", "abc-123", "nginx", 0)
	gcKey := BuildPodLogsDirectory(podLogsDir, "default", "nginx", "abc-123")

	// Simulates a real GC (gc.go) having already taken this pod's lock once —
	// exactly the key a concurrent GC pass on this pod would use.
	locks.Get(gcKey)
	if got := len(locks.locks); got != 1 {
		t.Fatalf("setup: lock map has %d entries after seeding the GC key, want 1", got)
	}

	mgr, err := NewContainerLogManager(&fakeRotateRuntime{}, DefaultContainerLogMaxSize, DefaultContainerLogMaxFiles, 1, time.Second, locks, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewContainerLogManager: %v", err)
	}
	// No files match containerLogPath+"*" here — Clean's glob is empty and it
	// returns immediately. That's fine: this test is about WHICH lock it took,
	// not what it did while holding it.
	if err := mgr.Clean(context.Background(), containerLogPath); err != nil {
		t.Fatalf("Clean: %v", err)
	}

	if got := len(locks.locks); got != 1 {
		t.Fatalf("lock map has %d entries after Clean, want 1 (Clean must reuse GC's pod-directory key, not mint its own)", got)
	}
}
