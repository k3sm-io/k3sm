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

package socket

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeActivator hands out fds, or err, and counts its calls.
type fakeActivator struct {
	fds   func(t *testing.T) []int
	err   error
	calls int
	t     *testing.T
	// handed is set once a call returned descriptors; locked once a call
	// ran with syscall.ForkLock held.
	handed, locked bool
}

// Activate answers EALREADY after a call that handed descriptors over, as
// launch_activate_socket does, and records whether syscall.ForkLock was
// read-held during the call.
func (a *fakeActivator) Activate(string) ([]int, error) {
	a.calls++
	if syscall.ForkLock.TryLock() {
		syscall.ForkLock.Unlock()
	} else {
		a.locked = true
	}
	if a.handed {
		return nil, unix.EALREADY
	}
	var fds []int
	if a.fds != nil {
		fds = a.fds(a.t)
	}
	a.handed = a.handed || len(fds) > 0
	return fds, a.err
}

// sockDir is a short temp dir for socket paths.
func sockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ksact")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// rawSocket makes a unix socket of typ bound at path, listening when
// listen is set, with FD_CLOEXEC set when cloexec is, and returns the raw
// descriptor, as launchd would hand it over.
func rawSocket(t *testing.T, typ int, path string, listen, cloexec bool) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, typ, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if listen {
		if err := unix.Listen(fd, 8); err != nil {
			t.Fatal(err)
		}
	}
	if cloexec {
		unix.CloseOnExec(fd)
	}
	return fd
}

func listenerFD(t *testing.T, ln net.Listener) int {
	t.Helper()
	al, ok := ln.(heldListener)
	if !ok {
		t.Fatalf("listener is %T", ln)
	}
	rc, err := al.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := rc.Control(func(p uintptr) { fd = int(p) }); err != nil {
		t.Fatal(err)
	}
	return fd
}

func closed(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return errors.Is(err, unix.EBADF)
}

// passPath is a path check that passes.
func passPath(string) error { return nil }

// U120 (the server's half): the activation calls launchd outside
// syscall.ForkLock and confirms FD_CLOEXEC under it, never binds, closes the original, and
// serves a close-on-exec duplicate that an exec'd child does not hold. It
// activates once per process: a Close leaves the socket open and serving,
// every later call returns the same listener without asking launchd, and a
// second activation in the process gets EALREADY, terminal as
// OffAlreadyActivated.
func TestActivatedListenerIsCloseOnExecAndHeld(t *testing.T) {
	dir := sockDir(t)
	path := filepath.Join(dir, "keys.sock")
	var orig []int
	a := &fakeActivator{t: t, fds: func(t *testing.T) []int {
		fd := rawSocket(t, unix.SOCK_STREAM, path, true, true)
		orig = append(orig, fd)
		return []int{fd}
	}}
	confirmLocked := false
	onConfirmLocked = func() {
		if syscall.ForkLock.TryLock() {
			syscall.ForkLock.Unlock()
		} else {
			confirmLocked = true
		}
	}
	t.Cleanup(func() { onConfirmLocked = nil })
	src := NewActivation("keys", path, a, passPath).Source()
	ln, err := src(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.locked {
		t.Fatal("launch_activate_socket ran with syscall.ForkLock held")
	}
	if !confirmLocked {
		t.Fatal("the FD_CLOEXEC confirm ran without syscall.ForkLock read-held")
	}
	if !closed(orig[0]) {
		t.Fatal("launchd's original descriptor is still open")
	}
	fd := listenerFD(t, ln)
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || fl&unix.FD_CLOEXEC == 0 {
		t.Fatalf("the listener's descriptor %d: flags %#x, %v, want FD_CLOEXEC", fd, fl, err)
	}
	out, err := exec.Command("/bin/sh", "-c", "if [ -e /dev/fd/"+strconv.Itoa(fd)+" ]; then echo inherited; else echo absent; fi").Output()
	if err != nil || string(out) != "absent\n" {
		t.Fatalf("an exec'd child sees descriptor %d: %q, %v", fd, out, err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := src(context.Background())
	if err != nil || again != ln || a.calls != 1 {
		t.Fatalf("after a Close: %v, same %v, %d activations; want the same listener and one activation", err, again == ln, a.calls)
	}
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
		}
	}()
	c, err := again.Accept()
	if err != nil {
		t.Fatalf("accept after a Close: %v", err)
	}
	_ = c.Close()
	_, err = NewActivation("keys", path, a, passPath).Source()(context.Background())
	var ae *ActivationError
	if !errors.As(err, &ae) || ae.Reason != OffAlreadyActivated || !errors.Is(err, unix.EALREADY) {
		t.Fatalf("a second activation: %v, want OffAlreadyActivated over EALREADY", err)
	}
	_ = listenerFDClose(t, again)
}

// listenerFDClose closes the held listener's descriptor for the test's
// cleanup (Close does not).
func listenerFDClose(t *testing.T, ln net.Listener) error {
	t.Helper()
	return ln.(heldListener).UnixListener.Close()
}

// launchd binds an activated socket under /var/run/com.apple.launchd.<random>/
// and renames it into place, so the descriptor's address reads that name
// (measured); it is accepted for the entry's own name only.
func TestLaunchdBindName(t *testing.T) {
	for p, want := range map[string]bool{
		"/var/run/com.apple.launchd.IIQ24YBjg6/keys":      true,
		"/var/run/com.apple.launchd.IIQ24YBjg6/other":     false,
		"/var/run/com.apple.launchd./keys":                false,
		"/var/run/com.apple.launchd.a/b/keys":             false,
		"/var/run/com.apple.launchd.../keys":              false,
		"/tmp/com.apple.launchd.IIQ24YBjg6/keys":          false,
		"/var/run/com.apple.launchd.IIQ24YBjg6/keys.sock": false,
	} {
		if got := launchdBindName(p, "keys"); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}

// Each refusal is an ActivationError with its terminal reason: ESRCH is
// OffNotActivated, ENOENT OffSocketParentMissing, a descriptor without
// FD_CLOEXEC OffActivatedInheritable, and anything that is not exactly
// one listening stream socket at the keystore path ErrActivatedWrong
// (OffListenerUnavailable). Every descriptor handed over is closed.
func TestActivatedListenerRefusals(t *testing.T) {
	dir := sockDir(t)
	path := filepath.Join(dir, "keys.sock")
	var handed []int
	n := 0
	fresh := func() string { n++; return filepath.Join(dir, "s"+strconv.Itoa(n)) }
	give := func(make func(t *testing.T) []int) func(t *testing.T) []int {
		return func(t *testing.T) []int {
			fds := make(t)
			handed = append(handed, fds...)
			return fds
		}
	}
	atPath := func(typ int, listen, cloexec bool) func(t *testing.T) []int {
		return give(func(t *testing.T) []int {
			_ = os.Remove(path)
			return []int{rawSocket(t, typ, path, listen, cloexec)}
		})
	}
	for _, tt := range []struct {
		name  string
		a     *fakeActivator
		is    error
		want  string
		r     OffReason
		check func(string) error
	}{
		{"not the launchd job", &fakeActivator{err: unix.ESRCH}, ErrNotActivated, "not the server's launchd job", OffNotActivated, nil},
		{"the parent path is missing", &fakeActivator{err: unix.ENOENT}, ErrNotActivated, "parent path is missing", OffSocketParentMissing, nil},
		{"already activated", &fakeActivator{err: unix.EALREADY}, unix.EALREADY, "already handed", OffAlreadyActivated, nil},
		{"another launchd error", &fakeActivator{err: unix.EINVAL, fds: atPath(unix.SOCK_STREAM, true, true)}, unix.EINVAL, "did not activate", OffListenerUnavailable, nil},
		{"no descriptor", &fakeActivator{}, ErrActivatedWrong, "no descriptor", OffActivatedWrong, nil},
		{"two descriptors", &fakeActivator{fds: give(func(t *testing.T) []int {
			return []int{rawSocket(t, unix.SOCK_STREAM, fresh(), true, true), rawSocket(t, unix.SOCK_STREAM, fresh(), true, true)}
		})}, ErrActivatedWrong, "more than one descriptor", OffActivatedWrong, nil},
		{"without FD_CLOEXEC", &fakeActivator{fds: atPath(unix.SOCK_STREAM, true, false)}, ErrActivatedInheritable, "FD_CLOEXEC", OffActivatedInheritable, nil},
		{"a datagram socket", &fakeActivator{fds: atPath(unix.SOCK_DGRAM, false, true)}, ErrActivatedWrong, "not a stream socket", OffActivatedWrong, nil},
		{"bound, not listening", &fakeActivator{fds: atPath(unix.SOCK_STREAM, false, true)}, ErrActivatedWrong, "not listening", OffActivatedWrong, nil},
		{"listening at another path", &fakeActivator{fds: give(func(t *testing.T) []int {
			return []int{rawSocket(t, unix.SOCK_STREAM, fresh(), true, true)}
		})}, ErrActivatedWrong, "not " + path, OffActivatedWrong, nil},
		{"the clients' path is missing", &fakeActivator{fds: atPath(unix.SOCK_STREAM, true, true)}, ErrActivatedWrong, "nothing is at the path", OffActivatedWrong, func(string) error { return errors.New("nothing is at the path") }},
		{"the clients' path has another owner", &fakeActivator{fds: atPath(unix.SOCK_STREAM, true, true)}, ErrActivatedWrong, "owned by uid 501", OffActivatedWrong, func(string) error { return errors.New("the socket is owned by uid 501") }},
		{"the clients' path is a regular file", &fakeActivator{fds: atPath(unix.SOCK_STREAM, true, true)}, ErrActivatedWrong, "not a socket", OffActivatedWrong, func(string) error { return errors.New("the path is not a socket") }},
		{"not a socket", &fakeActivator{fds: give(func(t *testing.T) []int {
			var p [2]int
			if err := unix.Pipe(p[:]); err != nil {
				t.Fatal(err)
			}
			_ = unix.Close(p[1])
			unix.CloseOnExec(p[0])
			return p[:1]
		})}, ErrActivatedWrong, "SO_TYPE", OffActivatedWrong, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handed = nil
			tt.a.t = t
			check := passPath
			if tt.check != nil {
				check = tt.check
			}
			ln, err := NewActivation("keys", path, tt.a, check).Source()(context.Background())
			var ae *ActivationError
			if ln != nil || !errors.Is(err, tt.is) || !errors.As(err, &ae) || ae.Reason != tt.r {
				t.Fatalf("got %v, %v; want %v as %q", ln, err, tt.is, tt.r)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not say %q", err, tt.want)
			}
			for _, fd := range handed {
				if !closed(fd) {
					t.Errorf("descriptor %d left open", fd)
				}
			}
		})
	}
	if _, err := NewActivation("keys", path, nil, passPath).Source()(context.Background()); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("nil activator: %v", err)
	}
}
