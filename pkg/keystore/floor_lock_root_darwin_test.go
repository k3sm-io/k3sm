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
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestNonRootDataRootFlockBlocksNoRootVerb is U119 (docs/design/keystore.md
// § "Acceptance gate", open requirement 2), a root-run row: run as root in
// the deployment's shape (hack/acceptance/keystore.sh --root), a process
// running as the service user opens the root:wheel 0755 data root itself and
// holds an exclusive flock on it, and every root verb that writes the floor
// still succeeds, since the floor lock is keystore-lock, which that user
// cannot open at all. Non-root it skips; the root-run row fails on a SKIP.
//
// It proves only that a flock on the data-root directory no longer blocks a
// root verb; TestDataRootFlockBlocksNoFloorWrite is the non-root control that
// failed before the lock moved. The service user still owns keystore/.lock,
// which every root write verb takes first, and can hold it to keep Delete
// and Rotate failing with the lock timeout for as long as it holds it: that
// accepted residual (docs/design/keystore.md § "Concurrency") is out of this
// test's scope.
func TestNonRootDataRootFlockBlocksNoRootVerb(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run (U119): run as root through hack/acceptance/keystore.sh --root")
	}
	svcUID, svcGID := serviceIDs(t)
	ctx := t.Context()
	s, server := newTestStore(t)
	// The deployment's data root: root:wheel 0755, which any local user can
	// open.
	chmod(t, s.dataRoot, 0o755)
	mustPut(t, s, "a", KindOpaque, []byte("a"))

	dataRoot, err := os.Open(s.dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dataRoot.Close() }()
	held := make(chan error, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The thread takes the service user's identity (settid, the call
		// under pthread_setugid_np) and is never handed back: a goroutine
		// that exits locked to its thread takes the thread with it, so no
		// other goroutine runs as the service user.
		runtime.LockOSThread()
		if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(svcUID), uintptr(svcGID), 0); errno != 0 {
			held <- fmt.Errorf("settid to the service user %d:%d: %w", svcUID, svcGID, errno)
			return
		}
		// keystore-lock is root's alone.
		for _, flag := range []int{unix.O_RDONLY, unix.O_RDWR} {
			if fd, err := unix.Openat(int(dataRoot.Fd()), floorLockName, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); !errors.Is(err, unix.EACCES) {
				if err == nil {
					_ = unix.Close(fd)
				}
				held <- fmt.Errorf("the service user's open of %s (flags %#x): %v, want EACCES", floorLockName, flag, err)
				return
			}
		}
		// The data root is not: the service user opens it, on its own
		// permission, and holds the old lock.
		fd, err := unix.Openat(int(dataRoot.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			held <- fmt.Errorf("the service user's open of the data root: %w", err)
			return
		}
		defer func() { _ = unix.Close(fd) }() // releases the flock
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			held <- fmt.Errorf("the service user's flock of the data root: %w", err)
			return
		}
		held <- nil
		<-release
	}()
	defer func() { close(release); <-done }()
	if err := <-held; err != nil {
		t.Fatal(err)
	}

	// A verb that waited on the held flock would fail with errLockTimeout.
	s.lockWait = time.Second
	for _, op := range []string{"Put", "Rotate", "RaiseFloor", "Rewrap", "Delete"} {
		if err := floorVerbs(ctx, s)[op](); err != nil {
			t.Fatalf("%s as root under the service user's flock on the data root: %v, want success", op, err)
		}
	}
	fl := floorOf(t, server)
	if len(fl["a"].burials()) == 0 {
		t.Fatalf("floor after the Delete still records a live: %+v, want a tombstone", fl)
	}
	if fl["b"].Seq != 1 {
		t.Fatalf("floor b after the Put = %+v, want sequence 1", fl["b"])
	}
}
