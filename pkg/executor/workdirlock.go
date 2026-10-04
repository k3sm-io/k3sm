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

package executor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// workDirLockName is the advisory lock file a server holds in its work dir while an
// etcd member runs there. ClusterReset takes the same lock, so a reset can never start
// a second member over a data dir the daemon's member is serving.
const workDirLockName = "server.lock"

// ErrWorkDirLocked reports that another process (a running server, or a reset in
// progress) holds the work dir's lock.
var ErrWorkDirLocked = errors.New("executor: the work dir is locked by a running k3sm server (stop it first)")

// WorkDirLockPath is the lock file's path for a work dir.
func WorkDirLockPath(workDir string) string { return filepath.Join(workDir, workDirLockName) }

// lockWorkDir takes an exclusive, non-blocking flock(2) on the work dir's lock file
// and returns the release func. A flock rather than an O_EXCL sentinel: the kernel
// drops it when the holder dies, so a crashed server never leaves the work dir locked
// for a human to clean up. The lock is per open file description, so a second
// lockWorkDir in the same process is refused exactly like one from another process.
func lockWorkDir(workDir string) (func() error, error) {
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("create work dir %s: %w", workDir, err)
	}
	path := WorkDirLockPath(workDir)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open work-dir lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrWorkDirLocked, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() error {
		err := unix.Flock(int(f.Fd()), unix.LOCK_UN)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}, nil
}
