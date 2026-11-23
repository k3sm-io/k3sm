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
	"slices"
	"strings"
	"sync/atomic"
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
			_, err = removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
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
	if _, err := removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true}); err != nil {
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
			_, _ = removeScopeTree(root, ks, "1001", svcUID, rmTreeOpts{listed: true}) // the race may leave it busy
		}
		close(stop)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_, _ = removeScopeTree(root, ks, "1001", svcUID, rmTreeOpts{listed: true})
		_ = root.Close()
		var st unix.Stat_t
		if err := unix.Lstat(victim, &st); err != nil || st.Flags != 0 {
			t.Fatalf("iteration %d: the root-owned file has flags %#x (%v), want 0", i, st.Flags, err)
		}
	}
	t.Logf("%d iterations, %d writes by name", iterations, calls)
}

// rootRmScopeBase makes the scope tree reachable for the service user, as
// TestRemoveScopeClearsServiceUserFlagsAsRoot does: the store is built under
// a root-made 0755 directory in /private/tmp, and the data root and its
// parent are 0755.
func rootRmScopeBase(t *testing.T) (*FileStore, string) {
	t.Helper()
	base, err := os.MkdirTemp("/private/tmp", "k3sm-rmtake-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", base)
	s, server, _ := fileLogScope(t)
	data := filepath.Dir(server)
	for _, d := range []string{filepath.Dir(data), data} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return s, server
}

// TestRemoveScopeTakesDirsFromServiceUserAsRoot is rm-scope's take,
// root-run: while it removes a scope, a service-user process tries, in a
// loop, to create a file in, rename a file into and rename a file out of
// the scope directory and a subdirectory. Once root has taken a directory
// (the seam marks it, and holds each take until the loop has met it a
// fixed number of times), every attempt there fails with EACCES, or with ENOENT once the directory
// is gone; none succeeds. The removal completes.
func TestRemoveScopeTakesDirsFromServiceUserAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run: run as root through hack/acceptance/keystore.sh --root")
	}
	svcUID, svcGID := serviceIDs(t)
	s, server := rootRmScopeBase(t)
	dir := scopeDir(server, "1001")
	sub := filepath.Join(dir, "sub")
	outside := filepath.Join(filepath.Dir(server), "svc-outside")
	for _, d := range []string{sub, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		giveToService(t, d)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	targets := []string{dir, sub}
	var inos [2]uint64
	for i, d := range targets {
		var st unix.Stat_t
		if err := unix.Lstat(d, &st); err != nil {
			t.Fatal(err)
		}
		inos[i] = st.Ino
	}
	// The loop and the removal meet through channels, never a clock: the
	// loop closes warm after warmIters passes over both directories, met[i]
	// after metAttempts attempts on directory i once it was taken, and after
	// after afterIters passes that began once removeScopeTree returned. It
	// closes exited when it returns, so no wait outlives a failed check.
	const warmIters, metAttempts, afterIters = 20, 9, 20
	var (
		taken   [2]atomic.Bool
		removed atomic.Bool
		warm    = make(chan struct{})
		met     = [2]chan struct{}{make(chan struct{}), make(chan struct{})}
		after   = make(chan struct{})
		exited  = make(chan struct{})
	)
	wait := func(ch <-chan struct{}) {
		select {
		case <-ch:
		case <-exited:
		}
	}
	saved := rmTakeDir
	setSeam(t, &rmTakeDir, func(fd int) error {
		err := saved(fd)
		var st unix.Stat_t
		if err == nil && unix.Fstat(fd, &st) == nil {
			for i, ino := range inos {
				if st.Ino == ino {
					taken[i].Store(true)
					wait(met[i]) // let the loop meet the taken directory
				}
			}
		}
		return err
	})
	stop := make(chan struct{})
	type tally struct{ eacces, enoent, before int }
	done := make(chan error, 1)
	var got tally
	go func() {
		defer close(exited)
		runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
		if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(svcUID), uintptr(svcGID), 0); errno != 0 {
			done <- fmt.Errorf("settid: %w", errno)
			return
		}
		var metN [2]int
		check := func(i int, was bool, what string, err error) error {
			if !was {
				got.before++
				return nil
			}
			if metN[i]++; metN[i] == metAttempts {
				defer close(met[i])
			}
			switch {
			case err == nil:
				return fmt.Errorf("the service user's %s in %s succeeded after root took it", what, targets[i])
			case errors.Is(err, unix.EACCES):
				got.eacces++
			case errors.Is(err, unix.ENOENT):
				if _, serr := os.Lstat(targets[i]); !errors.Is(serr, os.ErrNotExist) {
					return fmt.Errorf("the service user's %s in %s: ENOENT while the directory is there (%v)", what, targets[i], serr)
				}
				got.enoent++
			default:
				return fmt.Errorf("the service user's %s in %s: %v, want EACCES", what, targets[i], err)
			}
			return nil
		}
		afterN := 0
		for n := 0; ; n++ {
			if n == warmIters {
				close(warm)
			}
			if afterN == afterIters {
				close(after)
			}
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if removed.Load() {
				afterN++
			}
			for i, d := range targets {
				was := taken[i].Load()
				fd, err := unix.Open(filepath.Join(d, fmt.Sprintf("c%d", n)), unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW, 0o600)
				if err == nil {
					_ = unix.Close(fd)
				}
				if cerr := check(i, was, "create", err); cerr != nil {
					done <- cerr
					return
				}
				src := filepath.Join(outside, fmt.Sprintf("r%d-%d", i, n))
				if err := os.WriteFile(src, nil, 0o600); err != nil {
					done <- err
					return
				}
				was = taken[i].Load()
				err = unix.Rename(src, filepath.Join(d, fmt.Sprintf("in%d", n)))
				if cerr := check(i, was, "rename into", err); cerr != nil {
					done <- cerr
					return
				}
				_ = os.Remove(src)
				was = taken[i].Load()
				err = unix.Rename(filepath.Join(d, fmt.Sprintf("c%d", n)), filepath.Join(outside, fmt.Sprintf("o%d-%d", i, n)))
				if cerr := check(i, was, "rename out of", err); cerr != nil {
					done <- cerr
					return
				}
			}
		}
	}()
	wait(warm) // the loop runs before the take
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, rerr := removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
	removed.Store(true)
	wait(after) // and after the removal
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if rerr != nil {
		t.Fatalf("removeScopeTree while the service user writes: %v", rerr)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there: %v", err)
	}
	if got.eacces == 0 {
		t.Fatalf("no attempt met a taken directory (%+v): the test proved nothing", got)
	}
	t.Logf("attempts: %d before the take, %d EACCES after it, %d ENOENT once gone", got.before, got.eacces, got.enoent)
}

// TestRemoveScopeRerunAfterTakeAsRoot is rm-scope's crash case, root-run:
// an rm-scope that stopped after it took the scope directory and entries/
// (the seam fails the take of the entry directory) leaves them root's at
// 0700, which no open of the scope accepts. The rerun finds the scope
// directory root's at 0700, its own earlier work, descends the taken
// directories and removes the scope, listed, with no error.
func TestRemoveScopeRerunAfterTakeAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run: run as root through hack/acceptance/keystore.sh --root")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	entry := filepath.Join(dir, scopeEntriesName, "token")
	var est unix.Stat_t
	if err := unix.Lstat(entry, &est); err != nil {
		t.Fatal(err)
	}
	saved := rmTakeDir
	setSeam(t, &rmTakeDir, func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Ino == est.Ino && st.Dev == est.Dev {
			return unix.EIO
		}
		return saved(fd)
	})
	ctx := t.Context()
	if _, err := s.RemoveScope(ctx, 1001); err == nil || !strings.Contains(err.Error(), "is listed as removed") {
		t.Fatalf("the stopped rm-scope: %v, want the listed, partly present state", err)
	}
	for _, d := range []string{dir, filepath.Join(dir, scopeEntriesName)} {
		var st unix.Stat_t
		if err := unix.Lstat(d, &st); err != nil || st.Uid != 0 || st.Mode&0o7777 != 0o700 {
			t.Fatalf("%s after the stop: uid %d mode %#o (%v), want root's at 0700", d, st.Uid, st.Mode&0o7777, err)
		}
	}
	rmTakeDir = saved
	if res, err := s.RemoveScope(ctx, 1001); err != nil || !res.Recorded {
		t.Fatalf("the rerun over root-owned directories: %v, recorded %v", err, res.Recorded)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope directory is still there after the rerun: %v", err)
	}
}

// TestRemoveScopeLeavesForeignOwnedDirAsRoot is the foreign-directory
// case, root-run: a directory another user owns, with a file inside, in
// the scope's entries/ (as if renamed in from a shared parent), is left
// untouched with its file, and rm-scope fails naming it for reading only,
// saying who owns it, with no command; the scope stays listed.
func TestRemoveScopeLeavesForeignOwnedDirAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run: run as root through hack/acceptance/keystore.sh --root")
	}
	// No service-user process reaches the tree here, so rootRmScopeBase's reachable base is not needed.
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	other := otherUID(t)
	foreign := filepath.Join(dir, scopeEntriesName, "theirs")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(foreign, "file")
	if err := os.WriteFile(kept, []byte("another user's"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{kept, foreign} {
		if err := os.Lchown(p, int(other), int(other)); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.RemoveScope(t.Context(), 1001)
	recorded := res.Recorded
	if !recorded || !errors.Is(err, errScopeForeignDir) {
		t.Fatalf("rm-scope over another user's directory: %v, recorded %v; want errScopeForeignDir, listed", err, recorded)
	}
	msg := err.Error()
	if !strings.Contains(msg, "(named for reading, not for pasting)") || !strings.Contains(msg, fmt.Sprintf("uid %d owns it", other)) || !strings.Contains(msg, "is listed as removed") {
		t.Errorf("the error %q does not name the directory for reading, its owner and the listed state", msg)
	}
	if strings.Contains(msg, "rm -") || strings.Contains(msg, "chown") {
		t.Errorf("the error %q offers a command on the directory", msg)
	}
	if b, err := os.ReadFile(kept); err != nil || string(b) != "another user's" {
		t.Fatalf("the file in the foreign directory: %q, %v; want it untouched", b, err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(foreign, &st); err != nil || st.Uid != other || st.Mode&0o7777 != 0o700 {
		t.Fatalf("the foreign directory: uid %d mode %#o (%v), want it untouched", st.Uid, st.Mode&0o7777, err)
	}
}

// TestRemoveScopeRefusesForeignScopeDirAsRoot is the foreign scope
// directory, root-run: .user/<uid> is a directory another user owns at
// 0700, as if renamed in at the name after the by-path judgement. Its tree
// removal takes nothing: the directory keeps its owner and mode and every
// name in it, and the error names it for reading only and offers no
// command.
func TestRemoveScopeRefusesForeignScopeDirAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-run: run as root through hack/acceptance/keystore.sh --root")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	other := otherUID(t)
	if err := os.Lchown(dir, int(other), int(other)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	before := treeNames(t, dir)
	takes := countTakes(t)
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = removeScopeTree(root, s.dir, "1001", s.uid, rmTreeOpts{listed: true})
	checkScopeDirRefused(t, err, s, fmt.Sprintf("uid %d owns it", other))
	if *takes != 0 {
		t.Errorf("rmTakeDir ran %d times, want none", *takes)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil || st.Uid != other || st.Mode&0o7777 != 0o700 {
		t.Fatalf("the scope directory: uid %d mode %#o (%v), want it untouched", st.Uid, st.Mode&0o7777, err)
	}
	if after := treeNames(t, dir); !slices.Equal(before, after) {
		t.Fatalf("the scope directory holds %v, want %v untouched", after, before)
	}
}
