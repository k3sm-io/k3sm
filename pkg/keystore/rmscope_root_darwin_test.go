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
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRemoveScopeClearsServiceUserFlagsAsRoot is rm-scope's user-flag
// case, root-run: the service user sets uchg on its own scope.key and
// uunlnk on its entry directory, which makes root's unlinkat fail with
// EPERM; rm-scope's tree removal, as root, clears them through descriptors
// and removes the scope. A uchg file root owns, planted in the tree with
// one link, is debris of the tree being removed: its flag is cleared too
// and the scope removed. A file root planted with a system flag (sappnd)
// is left: the removal fails with EPERM, the error names it for reading
// only, says a system flag is set and offers no command, and the file
// keeps its flag.
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
	for _, plant := range []int{0, unix.UF_IMMUTABLE, sfAppend} {
		t.Run(fmt.Sprintf("root-owned plant flags %#x", plant), func(t *testing.T) {
			// The service user sets its flags by path below, so it must
			// search every parent of the scope directory: a t.TempDir()
			// under the run's TMPDIR sits below directories it cannot
			// search. The store is built under a root-made 0755 directory
			// in the sticky, world-searchable /private/tmp instead, as the
			// link probe's files are (TestSappndMeasuredFacts).
			base, err := os.MkdirTemp("/private/tmp", "k3sm-rmscope-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(base) }) // emptied by TempDir's own cleanup first
			if err := os.Chmod(base, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", base)
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			t.Cleanup(func() { unflagScopeTree(dir) })
			// The data root is root's 0755, as deployed, and so is the
			// test's temp directory above it.
			data := filepath.Dir(server)
			for _, d := range []string{filepath.Dir(data), data} {
				if err := os.Chmod(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
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
			if plant != 0 {
				if err := os.WriteFile(planted, []byte("root's"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chflags(planted, plant); err != nil {
					t.Fatal(err)
				}
			}
			root, err := s.openDir(s.dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = removeScopeTree(root, s.dir, "1001", s.uid)
			if plant == sfAppend {
				var st unix.Stat_t
				if !errors.Is(err, unix.EPERM) {
					t.Errorf("removeScopeTree over a root-owned sappnd file: %v, want EPERM", err)
				} else if msg := err.Error(); !strings.Contains(msg, quoteName(planted)+" (named for reading, not for pasting)") || !strings.Contains(msg, "a system flag is set") || strings.Contains(msg, "sudo") || strings.Contains(msg, "chflags") {
					t.Errorf("the error %q does not name the plant for reading only, say a system flag is set, and offer no command", msg)
				}
				if serr := unix.Lstat(planted, &st); serr != nil || st.Flags&sfAppend == 0 {
					t.Errorf("the root-owned plant has flags %#x (%v); want sappnd kept", st.Flags, serr)
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

// TestRemoveScopeClearsServiceUserFIFOAndSocketAsRoot is rm-scope's
// unopened case, root-run: the service user sets uchg on a FIFO and
// uchg,uappnd on a socket in its own scope tree, by path, which makes
// root's unlinkat fail with EPERM; rm-scope, as root, clears both by
// directory descriptor and name (setattrlistat, never opening them) and
// removes the scope with no error and so no hint.
func TestRemoveScopeClearsServiceUserFIFOAndSocketAsRoot(t *testing.T) {
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
	// As in TestRemoveScopeClearsServiceUserFlagsAsRoot: the service user
	// must search every parent of the scope directory.
	base, err := os.MkdirTemp("/private/tmp", "k3sm-rmscope-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", base)
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	t.Cleanup(func() { unflagScopeTree(dir) })
	data := filepath.Dir(server)
	for _, d := range []string{filepath.Dir(data), data} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fifo := filepath.Join(dir, "planted-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, scopeEntriesName, "planted-socket")
	plantSocket(t, sock)
	_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			_ = os.Lchown(p, int(svcUID), int(svcGID))
		}
		return nil
	})
	for _, f := range []struct {
		p     string
		flags int
	}{{fifo, unix.UF_IMMUTABLE}, {sock, unix.UF_IMMUTABLE | unix.UF_APPEND}} {
		if err := asService(func() error { return unix.Chflags(f.p, f.flags) }); err != nil {
			t.Fatalf("the service user's chflags %#x of %s: %v", f.flags, f.p, err)
		}
	}
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := removeScopeTree(root, s.dir, "1001", s.uid); err != nil {
		t.Fatalf("removeScopeTree over the service user's flagged FIFO and socket, as root: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
}

// TestRemoveScopeNameSwapAsRoot is clearUnopened's swap case, root-run:
// while rm-scope removes a scope tree, a service-user process, in a tight
// loop, makes a FIFO flagged uappnd,nodump in it, clears and unlinks it,
// and puts a hard link to a root-owned unflagged file at the same name.
// rm-scope's write by name, which may land on the link, writes 0, so the
// root-owned file's flags are 0 after every one of a bounded number of
// iterations (an earlier write of the FIFO's flags less the locking ones
// would have set nodump on it).
func TestRemoveScopeNameSwapAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run: run as root through hack/acceptance/keystore.sh --root")
	}
	svcUID, svcGID := serviceIDs(t)
	base, err := os.MkdirTemp("/private/tmp", "k3sm-rmswap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		unflagScopeTree(base)
		_ = os.RemoveAll(base)
	})
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(base, "victim")
	if err := os.WriteFile(victim, []byte("root's"), 0o600); err != nil {
		t.Fatal(err)
	}
	const iterations = 150
	calls := 0
	saved := setFlagsAt
	setFlagsAt = func(dirfd int, name string, flags uint32) error {
		calls++
		return saved(dirfd, name, flags)
	}
	t.Cleanup(func() { setFlagsAt = saved })
	for i := range iterations {
		ks := filepath.Join(base, fmt.Sprintf("ks%d", i))
		d := filepath.Join(ks, userScopesName, "1001", "d")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{filepath.Dir(d), d} {
			if err := os.Chown(p, int(svcUID), int(svcGID)); err != nil {
				t.Fatal(err)
			}
		}
		stop := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
			if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(svcUID), uintptr(svcGID), 0); errno != 0 {
				done <- fmt.Errorf("settid: %w", errno)
				return
			}
			f := filepath.Join(d, "f")
			for {
				select {
				case <-stop:
					done <- nil
					return
				default:
				}
				if unix.Mkfifo(f, 0o600) == nil {
					_ = unix.Chflags(f, unix.UF_APPEND|unix.UF_NODUMP)
					_ = unix.Chflags(f, 0)
					_ = unix.Unlink(f)
				}
				if unix.Link(victim, f) == nil {
					_ = unix.Unlink(f)
				}
			}
		}()
		root, err := os.OpenRoot(ks)
		if err != nil {
			t.Fatal(err)
		}
		for range 5 {
			_ = removeScopeTree(root, ks, "1001", svcUID) // the race may leave it busy
		}
		close(stop)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_ = removeScopeTree(root, ks, "1001", svcUID)
		_ = root.Close()
		var st unix.Stat_t
		if err := unix.Lstat(victim, &st); err != nil || st.Flags != 0 {
			t.Fatalf("iteration %d: the root-owned file has flags %#x (%v), want 0", i, st.Flags, err)
		}
	}
	t.Logf("%d iterations, %d writes by name", iterations, calls)
}
