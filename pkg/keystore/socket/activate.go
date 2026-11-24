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
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ErrNotActivated is launchd answering that it has no socket for this
// process: ESRCH (the process is not the server's launchd job: a rootless
// or hand-started server, or a job whose plist has no such Sockets entry)
// or ENOENT (launchd binds the socket at the job's activation call, and
// the socket's parent path is missing now, as for a data root on a volume
// that is not mounted). The server never binds keys.sock itself
// (docs/design/keystore.md § "The socket's directory is root's").
var ErrNotActivated = errors.New("no socket activated by launchd")

// ErrActivatedInheritable is a descriptor launchd handed over without
// FD_CLOEXEC. It is refused for the life of the process.
var ErrActivatedInheritable = errors.New("launchd handed over the socket without FD_CLOEXEC")

// ErrActivatedWrong is an activated descriptor this server will not serve:
// other than exactly one, not a listening stream socket, or bound at a
// path that is neither the keystore socket's nor launchd's bind name for
// the entry.
var ErrActivatedWrong = errors.New("the activated socket is not the keystore's listening socket")

// ActivationError is the one outcome of the process's activation that is
// not a listener. Reason is the supervisor's off reason; every one is
// terminal, since launchd hands a job's socket over once
// (launch_activate_socket answers EALREADY to a second call).
type ActivationError struct {
	Reason OffReason
	Err    error
}

func (e *ActivationError) Error() string { return e.Err.Error() }

// Unwrap returns the cause.
func (e *ActivationError) Unwrap() error { return e.Err }

// Activator asks launchd for the descriptors of one Sockets entry of the
// calling process's job. LaunchdActivator is production's.
type Activator interface {
	// Activate returns the descriptors launchd activated for the entry
	// name, each now owned by the caller, or an error (ESRCH, ENOENT, or
	// EALREADY when this process has already activated the entry).
	Activate(name string) ([]int, error)
}

// heldListener is the listener an Activation hands out. Its Close does not
// close the descriptor: the activated socket lives as long as the process,
// because launchd will not hand it over again, so a paused, stopped or
// re-run supervisor gets the same one back.
type heldListener struct {
	*net.UnixListener
}

// Close leaves the activated socket open for the next run.
func (heldListener) Close() error { return nil }

// Activation is the process's one activation of the keystore socket. The
// first Source call activates; the listener, or the error, is the answer
// to every later call, and nothing asks launchd again. Only process exit
// closes the socket.
type Activation struct {
	name, path string
	a          Activator

	mu   sync.Mutex // guards done, ln and err
	done bool
	ln   *net.UnixListener
	err  error
}

// NewActivation is the activation of the Sockets entry name, whose socket
// must be bound at path (or at launchd's bind name for name), taken with a.
func NewActivation(name, path string, a Activator) *Activation {
	return &Activation{name: name, path: path, a: a}
}

// Source is the supervisor's ListenerSource over the activation.
//
// What it checks, refusing on any failure for the life of the process and
// closing every descriptor it holds: that launchd answered (ESRCH and
// ENOENT are OffNotActivated and OffSocketParentMissing, EALREADY is
// OffAlreadyActivated, any other error OffListenerUnavailable); that it
// returned exactly one descriptor; that each descriptor carries
// FD_CLOEXEC (else OffActivatedInheritable); and that it is a SOCK_STREAM
// socket in the listening state (SO_TYPE, and SO_ACCEPTCONN read with
// proc_pidfdinfo) bound at path or at launchd's bind name for the entry
// (/var/run/com.apple.launchd.<random>/<name>, as measured; launchd binds
// there and renames the socket into place). The served listener is a
// close-on-exec duplicate and the original is closed.
//
// The fork lock: syscall.ForkLock is read-held across the
// launch_activate_socket call and the FD_CLOEXEC confirm, released with
// defer, the pattern Go uses for its own descriptor-creating calls, so no
// Go fork (os/exec) runs while a descriptor may lack the flag. The cost is
// that a launchd that hangs stalls every Go fork for that long; it happens
// once per process, and is accepted. A fork made outside Go's lock (a cgo
// spawn) relies on launchd's own flag, which it sets (measured), and Pods
// are spawned with POSIX_SPAWN_CLOEXEC_DEFAULT.
func (v *Activation) Source() ListenerSource {
	return func(context.Context) (net.Listener, error) {
		v.mu.Lock()
		defer v.mu.Unlock()
		if !v.done {
			v.ln, v.err = activate(v.name, v.path, v.a)
			v.done = true
		}
		if v.err != nil {
			return nil, v.err
		}
		return heldListener{v.ln}, nil
	}
}

// activate takes the entry's descriptors and makes the one listener.
func activate(name, path string, a Activator) (*net.UnixListener, error) {
	refuse := func(r OffReason, err error) (*net.UnixListener, error) {
		return nil, &ActivationError{Reason: r, Err: err}
	}
	if a == nil {
		return refuse(OffNotActivated, fmt.Errorf("%w: no activator", ErrNotActivated))
	}
	fds, err, ferr := activateLocked(a, name)
	if ferr != nil {
		return refuse(OffActivatedInheritable, fmt.Errorf("%w (Sockets entry %q)", ferr, name))
	}
	if err != nil {
		closeAll(fds)
		switch {
		case errors.Is(err, unix.ESRCH):
			return refuse(OffNotActivated, fmt.Errorf("%w for the Sockets entry %q: this process is not the server's launchd job, or its plist has no such entry: %w", ErrNotActivated, name, err))
		case errors.Is(err, unix.ENOENT):
			return refuse(OffSocketParentMissing, fmt.Errorf("%w for the Sockets entry %q: the socket's parent path is missing: %w", ErrNotActivated, name, err))
		case errors.Is(err, unix.EALREADY):
			return refuse(OffAlreadyActivated, fmt.Errorf("launchd already handed this process the Sockets entry %q: %w", name, err))
		}
		return refuse(OffListenerUnavailable, fmt.Errorf("launchd did not activate the Sockets entry %q: %w", name, err))
	}
	switch {
	case len(fds) == 0:
		return refuse(OffListenerUnavailable, fmt.Errorf("%w: launchd returned no descriptor for the Sockets entry %q", ErrActivatedWrong, name))
	case len(fds) > 1:
		closeAll(fds)
		return refuse(OffListenerUnavailable, fmt.Errorf("%w: launchd returned more than one descriptor for the Sockets entry %q, want one", ErrActivatedWrong, name))
	}
	if err := checkListening(fds[0], name, path); err != nil {
		closeAll(fds)
		return refuse(OffListenerUnavailable, fmt.Errorf("%w: the Sockets entry %q: %w", ErrActivatedWrong, name, err))
	}
	f := os.NewFile(uintptr(fds[0]), name)
	fl, err := net.FileListener(f) // a close-on-exec duplicate
	_ = f.Close()                  // the duplicate is the listener; the original goes
	if err != nil {
		return refuse(OffListenerUnavailable, fmt.Errorf("%w: the Sockets entry %q: %w", ErrActivatedWrong, name, err))
	}
	ln, ok := fl.(*net.UnixListener)
	if !ok {
		_ = fl.Close() // not ours to serve
		return refuse(OffListenerUnavailable, fmt.Errorf("%w: the Sockets entry %q is not a unix socket", ErrActivatedWrong, name))
	}
	return ln, nil
}

// activateLocked calls a.Activate and confirms FD_CLOEXEC on what it
// returned, with syscall.ForkLock read-held across both. ferr is the
// confirm's refusal; when it is set, every descriptor this process still
// holds has been closed.
func activateLocked(a Activator, name string) (fds []int, err, ferr error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err = a.Activate(name)
	if ferr = confirmCloseOnExec(fds); ferr != nil {
		return nil, err, ferr
	}
	return fds, err, nil
}

// confirmCloseOnExec reads each descriptor's flags; any without FD_CLOEXEC
// makes it close every descriptor it holds and return
// ErrActivatedInheritable. A number whose flags read EBADF is not this
// process's descriptor, so it is never closed; it fails the confirm too.
// The caller holds syscall.ForkLock.
func confirmCloseOnExec(fds []int) error {
	var bad error
	held := make([]int, 0, len(fds))
	for _, fd := range fds {
		fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			bad = fmt.Errorf("%w: read the descriptor's flags: %w", ErrActivatedInheritable, err)
			if !errors.Is(err, unix.EBADF) {
				held = append(held, fd)
			}
			continue
		}
		held = append(held, fd)
		if fl&unix.FD_CLOEXEC == 0 {
			bad = ErrActivatedInheritable
		}
	}
	if bad != nil {
		closeAll(held)
	}
	return bad
}

// launchdBindDir is the directory prefix launchd binds an activated socket
// under before renaming it into place (measured: the activated
// descriptor's address reads /var/run/com.apple.launchd.<random>/<name>).
const launchdBindDir = "/var/run/com.apple.launchd."

// checkListening refuses fd unless it is a SOCK_STREAM socket in the
// listening state bound at path or at launchd's bind name for name.
func checkListening(fd int, name, path string) error {
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
	got := filepath.Clean(ua.Name)
	if got == filepath.Clean(path) || launchdBindName(got, name) {
		return nil
	}
	return fmt.Errorf("bound at %s, not %s", ua.Name, path)
}

// launchdBindName reports whether p is launchd's bind name for the entry
// name: /var/run/com.apple.launchd.<random>/<name>, one level, no dots.
func launchdBindName(p, name string) bool {
	dir, base := filepath.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	rnd, ok := strings.CutPrefix(dir, launchdBindDir)
	return ok && base == name && rnd != "" && !strings.ContainsAny(rnd, "/.")
}

// closeAll closes descriptors this process will not use.
func closeAll(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd) // never served
	}
}
