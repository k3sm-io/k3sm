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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRemoveScopeClearsServiceUserFlagsAsRoot is rm-scope's user-flag
// case, root-run: the service user sets uchg on its own scope.key and
// uunlnk on its entry directory, which makes root's unlinkat fail with
// EPERM; rm-scope's tree removal, as root, clears them through descriptors
// and removes the scope. A uchg file root owns, planted in the tree, is
// not the service user's, so its flag is not cleared: the removal fails
// with EPERM, naming it, and the file keeps its flag.
func TestRemoveScopeClearsServiceUserFlagsAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run: run as root through hack/acceptance/keystore.sh --root")
	}
	svcUID, svcGID := serviceIDs(t)
	asService := func(f func() error) error {
		errc := make(chan error, 1)
		go func() {
			runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
			if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(svcUID), uintptr(svcGID), 0); errno != 0 {
				errc <- fmt.Errorf("settid: %w", errno)
				return
			}
			errc <- f()
		}()
		return <-errc
	}
	for _, rootPlant := range []bool{false, true} {
		t.Run(fmt.Sprintf("root-owned plant %v", rootPlant), func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			t.Cleanup(func() { unflagScopeTree(dir) })
			_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
				if err == nil {
					_ = os.Lchown(p, int(svcUID), int(svcGID))
				}
				return nil
			})
			entry := filepath.Join(dir, scopeEntriesName, "token")
			for _, f := range []struct {
				p     string
				flags int
			}{{filepath.Join(dir, scopeKeyName), unix.UF_IMMUTABLE}, {entry, 0x10}} {
				if err := asService(func() error {
					fd, err := unix.Open(f.p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
					if err != nil {
						return err
					}
					defer func() { _ = unix.Close(fd) }()
					return unix.Fchflags(fd, f.flags)
				}); err != nil {
					t.Fatalf("the service user's fchflags %#x of %s: %v", f.flags, f.p, err)
				}
			}
			planted := filepath.Join(dir, "root-planted")
			if rootPlant {
				if err := os.WriteFile(planted, []byte("root's"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chflags(planted, unix.UF_IMMUTABLE); err != nil {
					t.Fatal(err)
				}
			}
			root, err := s.openDir(s.dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = removeScopeTree(root, "1001", s.uid)
			if rootPlant {
				var st unix.Stat_t
				if !errors.Is(err, unix.EPERM) {
					t.Errorf("removeScopeTree over a root-owned uchg file: %v, want EPERM", err)
				}
				if serr := unix.Lstat(planted, &st); serr != nil || st.Flags&unix.UF_IMMUTABLE == 0 {
					t.Errorf("the root-owned plant has flags %#x (%v); want uchg kept", st.Flags, serr)
				}
				return
			}
			if err != nil {
				t.Fatalf("removeScopeTree over the service user's flags, as root: %v", err)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
		})
	}
}
