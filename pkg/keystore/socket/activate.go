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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ErrNotActivated is launchd answering that this process has no socket for
// the Sockets entry: ESRCH (the process is not the server's launchd job, a
// rootless or hand-started server) or ENOENT (the job has no such entry,
// or launchd could not create the socket's path, such as a data root on a
// volume that is not mounted). launchd fixed the job's definition at its
// bootstrap, so neither changes for the life of the process: the
// supervisor stays off as OffNotActivated and does not retry. The server
// never binds keys.sock itself (docs/design/keystore.md § "The socket's
// directory is root's").
var ErrNotActivated = errors.New("no socket activated by launchd")

// ErrActivatedInheritable is a descriptor launchd handed over without
// FD_CLOEXEC. A fork between its arrival and the check could have
// inherited it, so it is closed and refused (OffActivatedInheritable).
var ErrActivatedInheritable = errors.New("launchd handed over the socket without FD_CLOEXEC")

// ErrActivatedWrong is an activated descriptor this server will not serve:
// other than exactly one, not a listening stream socket, or bound at
// another path than the keystore socket's.
var ErrActivatedWrong = errors.New("the activated socket is not the keystore's listening socket")

// Activator asks launchd for the descriptors of one Sockets entry of the
// calling process's job. LaunchdActivator is production's.
type Activator interface {
	// Activate returns the descriptors launchd activated for the entry
	// name, each now owned by the caller, or an error (ESRCH when the
	// process is not that job's, ENOENT when the job has no such entry).
	Activate(name string) ([]int, error)
}

// activatedListener is the listener ActivatedListener hands out: launchd's
// descriptor as a *net.UnixListener, whose Close is noted so a source that
// handed it out once activates again rather than return a closed one.
type activatedListener struct {
	*net.UnixListener
	closed *bool
	mu     *sync.Mutex
}

// Close closes the listener and notes it.
func (l activatedListener) Close() error {
	l.mu.Lock()
	*l.closed = true
	l.mu.Unlock()
	return l.UnixListener.Close()
}

// ActivatedListener is the server's ListenerSource: the socket launchd
// activated for the Sockets entry name of the server's job, taken with a,
// never a socket this process binds. The first call activates it and later
// calls return the same listener, so the supervisor pauses and reuses it;
// once the supervisor has closed it, the next call activates again.
//
// What it checks, closing every descriptor and refusing on any failure:
// that launchd answered (else ErrNotActivated or the error, wrapped); that
// it returned exactly one descriptor; that the descriptor already carries
// FD_CLOEXEC, checked and set under syscall.ForkLock (else
// ErrActivatedInheritable); and that it is a SOCK_STREAM socket in the
// listening state (SO_TYPE, and SO_ACCEPTCONN read with proc_pidfdinfo) whose bound path is path (else
// ErrActivatedWrong). The served listener is a close-on-exec duplicate and
// the original is closed.
//
// What that guarantees about children: a Go fork (os/exec, which takes
// ForkLock) sees the descriptor only with FD_CLOEXEC set, since the flag is
// confirmed under the lock before the descriptor is used, and one that
// arrived without it is refused. A fork made outside Go's lock (a cgo
// spawn) relies on launchd's own flag, which it sets (measured), and Pods
// are spawned with POSIX_SPAWN_CLOEXEC_DEFAULT.
func ActivatedListener(name, path string, a Activator) ListenerSource {
	var (
		mu     sync.Mutex // guards cur and closed
		cur    *net.UnixListener
		closed bool
	)
	return func(context.Context) (net.Listener, error) {
		mu.Lock()
		defer mu.Unlock()
		if cur != nil && !closed {
			return activatedListener{UnixListener: cur, closed: &closed, mu: &mu}, nil
		}
		ln, err := activate(name, path, a)
		if err != nil {
			return nil, err
		}
		cur, closed = ln, false
		return activatedListener{UnixListener: cur, closed: &closed, mu: &mu}, nil
	}
}

// activate takes the entry's descriptors and makes the one listener.
func activate(name, path string, a Activator) (*net.UnixListener, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: no activator", ErrNotActivated)
	}
	fds, err := a.Activate(name) // launchd IPC, outside ForkLock
	if ferr := confirmCloseOnExec(fds); ferr != nil {
		closeAll(fds)
		return nil, fmt.Errorf("%w (Sockets entry %q)", ferr, name)
	}
	if err != nil {
		closeAll(fds)
		if errors.Is(err, unix.ESRCH) {
			return nil, fmt.Errorf("%w for the Sockets entry %q: this process is not the server's launchd job: %w", ErrNotActivated, name, err)
		}
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w for the Sockets entry %q: the job has no such entry, or launchd could not create its path: %w", ErrNotActivated, name, err)
		}
		return nil, fmt.Errorf("launchd did not activate the Sockets entry %q: %w", name, err)
	}
	switch {
	case len(fds) == 0:
		return nil, fmt.Errorf("%w: launchd returned no descriptor for the Sockets entry %q", ErrActivatedWrong, name)
	case len(fds) > 1:
		closeAll(fds)
		return nil, fmt.Errorf("%w: launchd returned more than one descriptor for the Sockets entry %q, want one", ErrActivatedWrong, name)
	}
	if err := checkListening(fds[0], path); err != nil {
		closeAll(fds)
		return nil, fmt.Errorf("%w: the Sockets entry %q: %w", ErrActivatedWrong, name, err)
	}
	f := os.NewFile(uintptr(fds[0]), name)
	fl, err := net.FileListener(f) // a close-on-exec duplicate
	_ = f.Close()                  // the duplicate is the listener; the original goes
	if err != nil {
		return nil, fmt.Errorf("%w: the Sockets entry %q: %w", ErrActivatedWrong, name, err)
	}
	ln, ok := fl.(*net.UnixListener)
	if !ok {
		_ = fl.Close() // not ours to serve
		return nil, fmt.Errorf("%w: the Sockets entry %q is not a unix socket", ErrActivatedWrong, name)
	}
	return ln, nil
}

// confirmCloseOnExec, under syscall.ForkLock, reads each descriptor's
// flags and sets FD_CLOEXEC on it; any that arrived without the flag (or
// whose flags cannot be read) makes it return ErrActivatedInheritable.
func confirmCloseOnExec(fds []int) error {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	var bad error
	for _, fd := range fds {
		fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			bad = fmt.Errorf("%w: read the descriptor's flags: %w", ErrActivatedInheritable, err)
			continue
		}
		if fl&unix.FD_CLOEXEC == 0 {
			unix.CloseOnExec(fd)
			bad = ErrActivatedInheritable
		}
	}
	return bad
}

// checkListening refuses fd unless it is a SOCK_STREAM socket in the
// listening state bound at path.
func checkListening(fd int, path string) error {
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return fmt.Errorf("read SO_TYPE: %w", err)
	}
	if typ != unix.SOCK_STREAM {
		return errors.New("not a stream socket")
	}
	acc, err := socketAccepting(fd)
	if err != nil {
		return fmt.Errorf("read SO_ACCEPTCONN: %w", err)
	}
	if !acc {
		return errors.New("not listening")
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("read its address: %w", err)
	}
	ua, ok := sa.(*unix.SockaddrUnix)
	if !ok {
		return errors.New("not a unix socket")
	}
	if filepath.Clean(ua.Name) != filepath.Clean(path) {
		return fmt.Errorf("bound at %s, not %s", ua.Name, path)
	}
	return nil
}

// closeAll closes descriptors this process will not use.
func closeAll(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd) // never served
	}
}
