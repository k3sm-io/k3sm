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

// listeningFD binds and listens on a unix socket in a short temp dir and
// returns the raw descriptor, deliberately without FD_CLOEXEC, as a
// launchd that dropped the flag would hand it over.
func listeningFD(t *testing.T) int {
	t.Helper()
	dir, err := os.MkdirTemp("", "ksact")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, "keys.sock")}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		t.Fatal(err)
	}
	if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || fl&unix.FD_CLOEXEC != 0 {
		t.Fatalf("the fixture's descriptor: flags %#x, %v, want FD_CLOEXEC clear", fl, err)
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

// U120 (the server's half): the listener source takes launchd's
// descriptor, never binds, closes the original, and serves a close-on-exec
// duplicate that an exec'd child does not hold; the same listener is
// handed back until it is closed, and then launchd is asked again.
func TestActivatedListenerIsCloseOnExecAndReused(t *testing.T) {
	var orig []int
	a := &fakeActivator{t: t, fds: func(t *testing.T) []int {
		fd := listeningFD(t)
		orig = append(orig, fd)
		return []int{fd}
	}}
	src := ActivatedListener("keys", a)
	ln, err := src(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(orig[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("launchd's original descriptor is still open: %v", err)
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
		if c, err := net.Dial("unix", ln.Addr().String()); err == nil {
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

// No activated socket keeps the user scope off with a named reason, and
// whatever launchd handed over that is not one listening unix socket is
// closed, never served.
func TestActivatedListenerRefusals(t *testing.T) {
	var handed []int
	pipe := func(t *testing.T) []int {
		var p [2]int
		if err := unix.Pipe(p[:]); err != nil {
			t.Fatal(err)
		}
		handed = append(handed, p[0], p[1])
		return p[:]
	}
	two := func(t *testing.T) []int {
		fds := []int{listeningFD(t), listeningFD(t)}
		handed = append(handed, fds...)
		return fds
	}
	one := func(t *testing.T) []int {
		var p [2]int
		if err := unix.Pipe(p[:]); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(p[1])
		handed = append(handed, p[0])
		return p[:1]
	}
	for _, tt := range []struct {
		name string
		a    *fakeActivator
		want string
	}{
		{"not the launchd job", &fakeActivator{err: unix.ESRCH}, "not the server's launchd job"},
		{"no such entry", &fakeActivator{err: unix.ENOENT}, "Sockets entry \"keys\""},
		{"error with descriptors", &fakeActivator{err: unix.EINVAL, fds: pipe}, "Sockets entry"},
		{"two descriptors", &fakeActivator{fds: two}, "more than one descriptor"},
		{"no descriptor", &fakeActivator{}, "no descriptor"},
		{"not a socket", &fakeActivator{fds: one}, "not a listening socket"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handed = nil
			tt.a.t = t
			ln, err := ActivatedListener("keys", tt.a)(context.Background())
			if ln != nil || !errors.Is(err, ErrNotActivated) {
				t.Fatalf("got %v, %v; want ErrNotActivated", ln, err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not say %q", err, tt.want)
			}
			for _, fd := range handed {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					t.Errorf("descriptor %d left open: %v", fd, err)
				}
			}
		})
	}
	if _, err := ActivatedListener("keys", nil)(context.Background()); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("nil activator: %v", err)
	}
}
