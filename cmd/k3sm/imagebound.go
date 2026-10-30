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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// The verbs that move image content (load, import, push, pull, save) carry no
// overall deadline unless --timeout sets one. A fixed deadline is wrong both
// ways: a multi-GB push over a slow link outlives it while still sending, and a
// connection that stopped moving bytes waits all of it out. Each request is
// bounded instead by how long it may go WITHOUT progress, and Ctrl-C cancels
// the whole command.
const (
	// requestIdleTimeout is how long one registry request, or the daemon's
	// export stream, may go without moving a byte before it is abandoned. The
	// window restarts on every byte sent or received, so a slow transfer that
	// keeps moving is never cut.
	requestIdleTimeout = 2 * time.Minute
	// daemonPullCeiling bounds one PullImage call. The daemon does that
	// transfer itself and reports no progress over the unary RPC, so the CLI
	// has nothing to restart an idle window with; it bounds the call alone.
	daemonPullCeiling = 30 * time.Minute
)

// defaultRegistryTransport is the transport a boundRequests(nil) wraps:
// go-containerregistry's default. A test swaps it for an in-process one.
var defaultRegistryTransport = remote.DefaultTransport

// errNoProgress is the cause a request carries when its idle window passed
// with no byte moved.
var errNoProgress = errors.New("no progress")

// requestIdleKey carries the idle window of the requests made under a context.
type requestIdleKey struct{}

// withRequestIdle returns a context under which every registry request through
// a boundRequests transport, and the daemon's export stream, is abandoned
// after idle without progress. A zero or negative idle means no bound.
func withRequestIdle(ctx context.Context, idle time.Duration) context.Context {
	return context.WithValue(ctx, requestIdleKey{}, idle)
}

// requestIdle reports the idle window ctx carries, zero when it carries none.
func requestIdle(ctx context.Context) time.Duration {
	d, _ := ctx.Value(requestIdleKey{}).(time.Duration)
	return d
}

// stallWatch cancels its context, with errNoProgress as the cause, once touch
// has not been called for its idle window. touch and stop may be called from
// any goroutine: the transport reads a request body while the caller reads the
// response.
type stallWatch struct {
	idle    time.Duration
	cancel  context.CancelCauseFunc
	mu      sync.Mutex // guards timer and stopped
	timer   *time.Timer
	stopped bool
}

// watchStall derives a context from parent that is cancelled once idle passes
// with no touch. The caller must call stop when the request is done.
func watchStall(parent context.Context, idle time.Duration) (context.Context, *stallWatch) {
	ctx, cancel := context.WithCancelCause(parent)
	w := &stallWatch{idle: idle, cancel: cancel}
	w.timer = time.AfterFunc(idle, func() { cancel(errNoProgress) })
	return ctx, w
}

// touch records progress, restarting the idle window.
func (w *stallWatch) touch() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		w.timer.Reset(w.idle)
	}
}

// stop ends the watch and releases its context.
func (w *stallWatch) stop() {
	w.mu.Lock()
	w.stopped = true
	w.timer.Stop()
	w.mu.Unlock()
	w.cancel(context.Canceled)
}

// stalled reports whether ctx was cancelled by its idle window rather than by
// its parent (Ctrl-C, an explicit --timeout) or by stop.
func stalled(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errNoProgress)
}

// boundRequests wraps base so that each request made under a withRequestIdle
// context is abandoned once its body upload and response download together go
// idle for the window. A request under a context with no window passes through
// untouched. A nil base is defaultRegistryTransport.
func boundRequests(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = defaultRegistryTransport
	}
	return idleBoundTransport{base: base}
}

type idleBoundTransport struct{ base http.RoundTripper }

// RoundTrip implements http.RoundTripper.
func (t idleBoundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	idle := requestIdle(req.Context())
	if idle <= 0 {
		return t.base.RoundTrip(req)
	}
	ctx, w := watchStall(req.Context(), idle)
	bounded := req.WithContext(ctx)
	if req.Body != nil && req.Body != http.NoBody {
		bounded.Body = &progressBody{ReadCloser: req.Body, ctx: ctx, w: w, req: req}
	}
	resp, err := t.base.RoundTrip(bounded)
	if err != nil {
		stallErr := stalledError(ctx, idle, req, err)
		w.stop()
		return nil, stallErr
	}
	resp.Body = &progressBody{ReadCloser: resp.Body, ctx: ctx, w: w, req: req, done: true}
	return resp, nil
}

// progressBody restarts the idle window on every byte it passes, and names the
// stall when a read fails because the window passed. The response body (done
// set) also ends the watch when it is closed.
type progressBody struct {
	io.ReadCloser
	ctx  context.Context
	w    *stallWatch
	req  *http.Request
	done bool
}

func (b *progressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.w.touch()
	}
	if err != nil && !errors.Is(err, io.EOF) {
		err = stalledError(b.ctx, b.w.idle, b.req, err)
	}
	return n, err
}

func (b *progressBody) Close() error {
	err := b.ReadCloser.Close()
	if b.done {
		b.w.stop()
	}
	return err
}

// stalledError names the idle window when ctx was cancelled by it, and returns
// err unchanged otherwise.
func stalledError(ctx context.Context, idle time.Duration, req *http.Request, err error) error {
	if !stalled(ctx) {
		return err
	}
	return fmt.Errorf("%s %s: %w for %s (the request is abandoned when no byte moves for that long): %w",
		req.Method, req.URL.Redacted(), errNoProgress, idle, err)
}
