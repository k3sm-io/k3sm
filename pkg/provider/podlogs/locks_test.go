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
	"os"
	"path/filepath"
	"sync"
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

// sharedLockRotator builds a real containerLogManager over rt that shares locks
// with whatever GC the test builds, which is the production wiring (runtimed.go
// hands one *DirLocks to both NewContainerLogManager and NewGC).
func sharedLockRotator(t *testing.T, rt Runtime, locks *DirLocks) *containerLogManager {
	t.Helper()
	m, err := NewContainerLogManager(rt, "10", 3, 1, time.Second, locks, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewContainerLogManager: %v", err)
	}
	c, ok := m.(*containerLogManager)
	if !ok {
		t.Fatalf("NewContainerLogManager returned %T, want the real manager", m)
	}
	return c
}

// oversizedContainerLog creates <root>/default_nginx_abc-123/nginx/0.log with
// content over the 10-byte limit sharedLockRotator uses, and returns the log
// path plus the pod directory the GC keys its lock on.
func oversizedContainerLog(t *testing.T, root string) (logPath, podDir string) {
	t.Helper()
	logPath = BuildContainerLogsPath(root, "default", "nginx", "abc-123", "nginx", 0)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write(t, logPath, "longer than 10 bytes")
	return logPath, BuildPodLogsDirectory(root, "default", "nginx", "abc-123")
}

// rotatedSiblings counts the timestamped files rotation left next to logPath.
func rotatedSiblings(t *testing.T, logPath string) int {
	t.Helper()
	m, err := filepath.Glob(logPath + ".*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return len(m)
}

// TestProcessContainerLocksOnThePodDirectoryGCUses is the rotation-path twin of
// TestCleanLocksOnThePodDirectoryGCUses: it drives the REAL processContainer
// through an actual rotation and asserts, via the shared *DirLocks' map, that
// the rotation took the pod-directory mutex a GC pass would take rather than
// minting a second one. The rotation is asserted to have happened, so the lock
// was genuinely reached and the one-entry map is not vacuous.
func TestProcessContainerLocksOnThePodDirectoryGCUses(t *testing.T) {
	root := t.TempDir()
	logPath, gcKey := oversizedContainerLog(t, root)
	locks := NewDirLocks()
	locks.Get(gcKey)

	f := &fakeRotateRuntime{
		refs:    map[string]ContainerLogRef{"c": {ID: "c", Path: logPath}},
		running: map[string]bool{"c": true},
	}
	c := sharedLockRotator(t, f, locks)
	if err := c.rotateLogs(context.Background()); err != nil {
		t.Fatalf("rotateLogs: %v", err)
	}
	drainQueue(t, c)

	if got := rotatedSiblings(t, logPath); got != 1 {
		t.Fatalf("rotation left %d rotated files, want 1 (the rotation must actually run for this test to mean anything)", got)
	}
	if got := len(locks.locks); got != 1 {
		t.Fatalf("lock map has %d entries after rotation, want 1 (processContainer must reuse GC's pod-directory key, not mint its own)", got)
	}
}

// blockingReopenRuntime stalls ReopenContainerLog, which rotateLatestLog calls
// INSIDE the pod lock, until release is closed. entered is closed on the first
// call, so a test knows the rotation is holding the lock.
type blockingReopenRuntime struct {
	*fakeRotateRuntime
	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
}

func (b *blockingReopenRuntime) ReopenContainerLog(ctx context.Context, id string) error {
	b.enteredOnce.Do(func() { close(b.entered) })
	<-b.release
	return b.fakeRotateRuntime.ReopenContainerLog(ctx, id)
}

// blockedFor is how long a path must stay parked on the other's lock before the
// test accepts that it is excluded rather than merely slow to schedule.
const blockedFor = 100 * time.Millisecond

// TestRotationAndGCSerializeOnSharedPodLock is the concurrent reproduction the
// key-derivation tests stand in for: the rotator and the GC sweep run on
// separate goroutines against one pod's directory with one shared *DirLocks, and
// each must wait for the other. Before podDirOfContainerLog the rotator keyed on
// the container directory, so both subtests failed: each path ran straight
// through while the other held what it thought was the same lock.
func TestRotationAndGCSerializeOnSharedPodLock(t *testing.T) {
	t.Run("a GC-held pod lock blocks rotation until release", func(t *testing.T) {
		root := t.TempDir()
		logPath, podDir := oversizedContainerLog(t, root)
		locks := NewDirLocks()
		f := &fakeRotateRuntime{
			refs:    map[string]ContainerLogRef{"c": {ID: "c", Path: logPath}},
			running: map[string]bool{"c": true},
		}
		c := sharedLockRotator(t, f, locks)
		if err := c.rotateLogs(context.Background()); err != nil {
			t.Fatalf("rotateLogs: %v", err)
		}

		// Take the pod lock exactly as GC.RunOnce does for this pod.
		gcLock := locks.Get(podDir)
		gcLock.Lock()
		unlock := sync.OnceFunc(gcLock.Unlock)
		t.Cleanup(unlock)

		done := make(chan struct{})
		go func() {
			defer close(done)
			c.processContainer(context.Background(), 1)
		}()

		select {
		case <-done:
			t.Fatal("rotation completed while the GC held the pod lock: the two paths do not share a mutex")
		case <-time.After(blockedFor):
		}
		if got := rotatedSiblings(t, logPath); got != 0 {
			t.Fatalf("rotation renamed %d files under a GC-held pod lock, want 0", got)
		}

		unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("rotation did not finish after the GC released the pod lock")
		}
		if got := rotatedSiblings(t, logPath); got != 1 {
			t.Fatalf("rotation left %d rotated files after the lock was released, want 1", got)
		}
	})

	t.Run("a stalled rotation blocks the GC sweep until it finishes", func(t *testing.T) {
		root := t.TempDir()
		logPath, _ := oversizedContainerLog(t, root)
		locks := NewDirLocks()
		rt := &blockingReopenRuntime{
			fakeRotateRuntime: &fakeRotateRuntime{
				refs:    map[string]ContainerLogRef{"c": {ID: "c", Path: logPath}},
				running: map[string]bool{"c": true},
			},
			entered: make(chan struct{}),
			release: make(chan struct{}),
		}
		release := sync.OnceFunc(func() { close(rt.release) })
		t.Cleanup(release)
		c := sharedLockRotator(t, rt, locks)
		if err := c.rotateLogs(context.Background()); err != nil {
			t.Fatalf("rotateLogs: %v", err)
		}
		g := NewGC(root, "", fakePodState{uids: map[string]struct{}{"abc-123": {}}, synced: true}, locks, nil)

		rotated := make(chan struct{})
		go func() {
			defer close(rotated)
			c.processContainer(context.Background(), 1)
		}()
		select {
		case <-rt.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("rotation never reached the reopen step")
		}

		swept := make(chan struct{})
		go func() {
			defer close(swept)
			g.RunOnce(context.Background())
		}()
		select {
		case <-swept:
			t.Fatal("the GC sweep completed while a rotation held the pod lock: the two paths do not share a mutex")
		case <-time.After(blockedFor):
		}

		release()
		for name, ch := range map[string]chan struct{}{"rotation": rotated, "sweep": swept} {
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s did not finish after the reopen was released", name)
			}
		}
		if got := rotatedSiblings(t, logPath); got != 1 {
			t.Fatalf("rotation left %d rotated files, want 1", got)
		}
	})
}
