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

package builder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// A running `k3sm build` is a process of its own, and `k3sm build cancel` is
// another. They meet at a unix socket beside the build's ledger record: the
// build listens on it for as long as it runs, and a cancel request is one line
// written to it. The socket sits in the ledger directory, which is 0700 and
// owned by the user who builds, so only that user (and root) can reach it.
//
// The build process does the stopping, because it holds the job: cancelling
// its context interrupts buildx (RunBuildxTo sends SIGINT), buildx cancels its
// solve, and buildkitd cancels the build's job when the solve's session ends.
// The build then records itself cancelled and only then answers, so a cancel
// that returns has seen the record written.
const (
	cancelRequest = "cancel"
	cancelReply   = "stopped"
)

// cancelReadTimeout bounds how long the build waits for a connected peer to
// send its request line.
const cancelReadTimeout = 5 * time.Second

// ErrCancelled is returned by RunCancellable when a cancel request stopped the
// job.
var ErrCancelled = errors.New("build cancelled")

// ErrNoBuildProcess is returned by RequestCancel when nothing listens at the
// socket: the build that owned the record has already exited.
var ErrNoBuildProcess = errors.New("no running build process answered")

// RunCancellable runs job under a context a cancel request at path can cancel.
//
// When job returns, finish is called with whether a cancel request stopped it
// and the job's error, and every waiting requester is answered only after
// finish returns. A cancel that arrives after job succeeded does not turn the
// success into a cancellation. The returned error wraps ErrCancelled when the
// job was cancelled, and is job's error otherwise.
//
// A socket that cannot be opened does not stop the build: it runs without a
// cancel channel and the reason is logged, the same posture the ledger takes.
func RunCancellable(ctx context.Context, path string, job func(context.Context) error, finish func(cancelled bool, jobErr error)) error {
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var requested atomic.Bool
	done := make(chan struct{})
	ln, err := listenCancel(path)
	if err != nil {
		slog.Warn("build cancel channel unavailable; `k3sm build cancel` cannot stop this build", "path", path, "err", err)
	}
	var wg sync.WaitGroup
	if ln != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveCancel(ln, done, func() {
				requested.Store(true)
				cancel()
			})
		}()
	}

	jobErr := job(jctx)
	cancelled := requested.Load() && jobErr != nil
	if finish != nil {
		finish(cancelled, jobErr)
	}
	close(done)
	if ln != nil {
		_ = ln.Close() // removes the socket file: net.Listen sockets unlink on Close
		wg.Wait()
	}
	if cancelled {
		return fmt.Errorf("%w: %v", ErrCancelled, jobErr)
	}
	return jobErr
}

// listenCancel opens the cancel socket at path, replacing a stale socket a
// killed build left behind, and narrows it to 0600.
func listenCancel(path string) (*net.UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale cancel socket: %w", err)
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("restrict cancel socket: %w", err)
	}
	return ln, nil
}

// serveCancel accepts until ln closes. A connection that sends the cancel
// request triggers stop and is answered once done closes; any other
// connection (a liveness probe, junk) is closed unanswered.
func serveCancel(ln *net.UnixListener, done <-chan struct{}, stop func()) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(cancelReadTimeout))
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || strings.TrimSpace(line) != cancelRequest {
				return
			}
			stop()
			<-done
			_, _ = conn.Write([]byte(cancelReply + "\n"))
		}()
	}
}

// RequestCancel asks the build listening at path to stop and waits until it
// has stopped and recorded itself, or ctx ends. Nothing listening is
// ErrNoBuildProcess.
func RequestCancel(ctx context.Context, path string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		if isNoListener(err) {
			return ErrNoBuildProcess
		}
		return fmt.Errorf("reach the build: %w", err)
	}
	defer conn.Close()
	stopWatch := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopWatch()
	if _, err := conn.Write([]byte(cancelRequest + "\n")); err != nil {
		return fmt.Errorf("send the cancel request: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("the build did not stop in time: %w", ctx.Err())
		}
		return fmt.Errorf("wait for the build to stop: %w", err)
	}
	if strings.TrimSpace(line) != cancelReply {
		return fmt.Errorf("unexpected answer from the build: %q", strings.TrimSpace(line))
	}
	return nil
}

// BuildAlive reports whether a build process is listening at path. It connects
// and hangs up without a request, which the build ignores.
func BuildAlive(ctx context.Context, path string) bool {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// isNoListener is whether a dial failed because nothing listens: no socket
// file, or a socket file with no process behind it.
func isNoListener(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}
