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
	"testing"

	"golang.org/x/sys/unix"
)

// fakeActivator hands out fds, or err, and counts its calls.
type fakeActivator struct {
	fds   func(t *testing.T) []int
	err   error
	calls int
	t     *testing.T
}

func (a *fakeActivator) Activate(string) ([]int, error) {
	a.calls++
	var fds []int
	if a.fds != nil {
		fds = a.fds(a.t)
	}
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
	al, ok := ln.(activatedListener)
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

// U120 (the server's half): the listener source takes launchd's
// descriptor, never binds, closes the original, and serves a close-on-exec
// duplicate that an exec'd child does not hold; the same listener is
// handed back until it is closed, and then launchd is asked again.
func TestActivatedListenerIsCloseOnExecAndReused(t *testing.T) {
	dir := sockDir(t)
	path := filepath.Join(dir, "keys.sock")
	var orig []int
	a := &fakeActivator{t: t, fds: func(t *testing.T) []int {
		_ = os.Remove(path)
		fd := rawSocket(t, unix.SOCK_STREAM, path, true, true)
		orig = append(orig, fd)
		return []int{fd}
	}}
	src := ActivatedListener("keys", path, a)
	ln, err := src(context.Background())
	if err != nil {
		t.Fatal(err)
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
	again, err := src(context.Background())
	if err != nil || again != ln || a.calls != 1 {
		t.Fatalf("second call: %v, same %v, %d activations; want the same listener and one activation", err, again == ln, a.calls)
	}
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept on the activated listener: %v", err)
	}
	_ = c.Close()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := src(context.Background())
	if err != nil || third == ln || a.calls != 2 {
		t.Fatalf("after close: %v, same %v, %d activations; want a fresh activation", err, third == ln, a.calls)
	}
	_ = third.Close()
}

// No activated socket is ErrNotActivated (the supervisor's terminal off);
// a descriptor without FD_CLOEXEC is ErrActivatedInheritable; anything
// that is not exactly one listening stream socket at the keystore path is
// ErrActivatedWrong. Every descriptor handed over is closed.
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
		name string
		a    *fakeActivator
		is   error
		want string
	}{
		{"not the launchd job", &fakeActivator{err: unix.ESRCH}, ErrNotActivated, "not the server's launchd job"},
		{"no such entry or path", &fakeActivator{err: unix.ENOENT}, ErrNotActivated, "could not create its path"},
		{"another launchd error", &fakeActivator{err: unix.EINVAL, fds: atPath(unix.SOCK_STREAM, true, true)}, unix.EINVAL, "did not activate"},
		{"no descriptor", &fakeActivator{}, ErrActivatedWrong, "no descriptor"},
		{"two descriptors", &fakeActivator{fds: give(func(t *testing.T) []int {
			return []int{rawSocket(t, unix.SOCK_STREAM, fresh(), true, true), rawSocket(t, unix.SOCK_STREAM, fresh(), true, true)}
		})}, ErrActivatedWrong, "more than one descriptor"},
		{"without FD_CLOEXEC", &fakeActivator{fds: atPath(unix.SOCK_STREAM, true, false)}, ErrActivatedInheritable, "FD_CLOEXEC"},
		{"a datagram socket", &fakeActivator{fds: atPath(unix.SOCK_DGRAM, false, true)}, ErrActivatedWrong, "not a stream socket"},
		{"bound, not listening", &fakeActivator{fds: atPath(unix.SOCK_STREAM, false, true)}, ErrActivatedWrong, "not listening"},
		{"listening at another path", &fakeActivator{fds: give(func(t *testing.T) []int {
			return []int{rawSocket(t, unix.SOCK_STREAM, fresh(), true, true)}
		})}, ErrActivatedWrong, "not " + path},
		{"not a socket", &fakeActivator{fds: give(func(t *testing.T) []int {
			var p [2]int
			if err := unix.Pipe(p[:]); err != nil {
				t.Fatal(err)
			}
			_ = unix.Close(p[1])
			unix.CloseOnExec(p[0])
			return p[:1]
		})}, ErrActivatedWrong, "SO_TYPE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handed = nil
			tt.a.t = t
			ln, err := ActivatedListener("keys", path, tt.a)(context.Background())
			if ln != nil || !errors.Is(err, tt.is) {
				t.Fatalf("got %v, %v; want %v", ln, err, tt.is)
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
	if _, err := ActivatedListener("keys", path, nil)(context.Background()); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("nil activator: %v", err)
	}
}
