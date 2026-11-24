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
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ErrNotActivated is a listener source that found no socket launchd
// activated for this process: the server was not started by its launchd
// job (a rootless or hand-started server), the job's plist predates the
// Sockets entry, or launchd answered with an error. The user scope stays
// off; the server never binds keys.sock itself (docs/design/keystore.md §
// "The socket's directory is root's").
var ErrNotActivated = errors.New("no socket activated by launchd")

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
// once the supervisor has closed it, the next call activates again. Each
// descriptor enters the process inside syscall.ForkLock and is marked
// FD_CLOEXEC there, then is duplicated close-on-exec into the listener and
// the original closed, so no child the server starts, at any moment,
// inherits it (Open requirement 3). No socket, more than one, or one that
// is not a listening unix socket is an error wrapping ErrNotActivated,
// which the supervisor reports as OffListenerUnavailable.
func ActivatedListener(name string, a Activator) ListenerSource {
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
		ln, err := activate(name, a)
		if err != nil {
			return nil, err
		}
		cur, closed = ln, false
		return activatedListener{UnixListener: cur, closed: &closed, mu: &mu}, nil
	}
}

// activate takes the entry's descriptors and makes the one listener.
func activate(name string, a Activator) (*net.UnixListener, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: no activator", ErrNotActivated)
	}
	syscall.ForkLock.RLock()
	fds, err := a.Activate(name)
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		closeAll(fds)
		if errors.Is(err, unix.ESRCH) {
			return nil, fmt.Errorf("%w for the Sockets entry %q: this process is not the server's launchd job: %w", ErrNotActivated, name, err)
		}
		return nil, fmt.Errorf("%w for the Sockets entry %q: %w", ErrNotActivated, name, err)
	}
	switch {
	case len(fds) == 0:
		return nil, fmt.Errorf("%w: launchd returned no descriptor for the Sockets entry %q", ErrNotActivated, name)
	case len(fds) > 1:
		closeAll(fds)
		return nil, fmt.Errorf("%w: launchd returned more than one descriptor for the Sockets entry %q, want one", ErrNotActivated, name)
	}
	f := os.NewFile(uintptr(fds[0]), name)
	fl, err := net.FileListener(f) // a close-on-exec duplicate
	_ = f.Close()                  // the duplicate is the listener; the original goes
	if err != nil {
		return nil, fmt.Errorf("%w: the Sockets entry %q is not a listening socket: %w", ErrNotActivated, name, err)
	}
	ln, ok := fl.(*net.UnixListener)
	if !ok {
		_ = fl.Close() // not ours to serve
		return nil, fmt.Errorf("%w: the Sockets entry %q is not a unix socket", ErrNotActivated, name)
	}
	return ln, nil
}

// closeAll closes descriptors this process will not use.
func closeAll(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd) // never served
	}
}
