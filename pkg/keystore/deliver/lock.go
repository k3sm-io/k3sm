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

package deliver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// LockName is the writers' lock beside the declaration in the data root. It
// is its own root-owned file: the data root directory itself is never
// flocked.
const LockName = ".keystore-delivery.lock"

// lockMode is the lock file's mode: root's, closed to group and others.
const lockMode os.FileMode = 0o600

// Bounds on the wait for the lock: lockAttempts tries, DefaultLockBusy apart,
// about ten seconds in all, the keystore lock's own bound.
const (
	lockAttempts  = 200
	lockRetryWait = 50 * time.Millisecond
)

// ErrLockBusy reports that another writer held the lock for the whole bounded
// wait.
var ErrLockBusy = errors.New("another k3sm keys deliver or undeliver holds the delivery declaration's lock; try again")

// DefaultLockBusy is the production wait between attempts at a held lock.
func DefaultLockBusy() <-chan time.Time { return time.After(lockRetryWait) }

// Lock takes the writers' exclusive lock at path (the data root's LockName),
// serializing every read-modify-write of the declaration. The file is
// created 0600 if absent, opened with O_NOFOLLOW so a symlink there is
// refused, and judged with check on the opened descriptor (production:
// RootCheck) before it is locked. A held lock is retried lockAttempts times,
// waiting on busy (nil is DefaultLockBusy) between attempts, or until ctx is
// done. The returned function releases it.
func Lock(ctx context.Context, path string, check FileCheck, busy func() <-chan time.Time) (unlock func(), err error) {
	if busy == nil {
		busy = DefaultLockBusy
	}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, lockMode)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%w: the lock is a symlink", ErrRefused)
	}
	if err != nil {
		return nil, fmt.Errorf("open the delivery lock: %w", err)
	}
	defer func() {
		if err != nil {
			_ = f.Close() // abandoned; nothing was written
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat the delivery lock: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: the lock is not a regular file", ErrRefused)
	}
	if err := check(fi); err != nil {
		return nil, fmt.Errorf("%w: the lock: %w", ErrRefused, err)
	}
	for range lockAttempts {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // the close releases it regardless
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("lock the delivery lock: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-busy():
		}
	}
	return nil, ErrLockBusy
}
