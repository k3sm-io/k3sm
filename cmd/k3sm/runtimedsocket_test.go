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
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/provider"
)

// fakeControlListener is a net.Listener that accepts nothing and records its
// closes. run never reads from a listener — it hands it straight to serve — so
// Accept only has to be non-blocking and honest.
type fakeControlListener struct {
	mu     sync.Mutex
	closes int
}

func (l *fakeControlListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *fakeControlListener) Addr() net.Addr            { return &net.UnixAddr{Name: "fake", Net: "unix"} }

func (l *fakeControlListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closes++
	return nil
}

func (l *fakeControlListener) closeCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closes
}

// controlSocketProbe is the recording seam pair the tests drive runtimedControlSocket
// through: it counts bind attempts, hands out a listener per successful bind, and
// records the order of the serve/close calls so the shutdown ORDERING — not just
// the fact of a close — is assertable.
type controlSocketProbe struct {
	mu        sync.Mutex
	binds     int
	listeners []*fakeControlListener
	// bindErrs[i] is the error the (i+1)-th bind returns; a short slice means
	// every later bind succeeds.
	bindErrs []error
	// serveFn is the serve behaviour; nil serves until ctx is done, then nil.
	serveFn func(ctx context.Context, lis net.Listener) error
	// events records "serve"/"close" in call order.
	events []string
}

func (p *controlSocketProbe) listen(string) (net.Listener, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.binds
	p.binds++
	if i < len(p.bindErrs) && p.bindErrs[i] != nil {
		return nil, p.bindErrs[i]
	}
	l := &fakeControlListener{}
	p.listeners = append(p.listeners, l)
	return l, nil
}

func (p *controlSocketProbe) serve(ctx context.Context, lis net.Listener) error {
	p.record("serve")
	if p.serveFn != nil {
		return p.serveFn(ctx, lis)
	}
	<-ctx.Done()
	return nil
}

func (p *controlSocketProbe) record(ev string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, ev)
}

func (p *controlSocketProbe) snapshot() (binds int, listeners []*fakeControlListener, events []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.binds, append([]*fakeControlListener(nil), p.listeners...), append([]string(nil), p.events...)
}

// socketUnder builds a runtimedControlSocket over the probe with the production
// budget and no backoff, so a bounded-retry test costs no wall-clock time.
func socketUnder(p *controlSocketProbe) runtimedControlSocket {
	return runtimedControlSocket{
		path:     "/tmp/k3sm-test/run/runtimed.sock",
		listen:   p.listen,
		serve:    p.serve,
		attempts: runtimedSocketBindAttempts,
		backoff:  0,
		log:      slog.New(slog.DiscardHandler),
	}
}

// TestRuntimedControlSocketRunIsNeverFatal is the central contract: every failure
// mode of the control socket ends in a plain return, bounded by the attempt
// budget. A node that cannot serve `k3sm image` must still run pods, so run has
// no error to propagate and must not spin.
func TestRuntimedControlSocketRunIsNeverFatal(t *testing.T) {
	permanent := errors.New("permission denied")

	tests := []struct {
		name string
		// bindErrs are the per-attempt bind results.
		bindErrs []error
		// serveFn, when set, replaces the ctx-blocking default.
		serveFn func(ctx context.Context, lis net.Listener) error
		// wantBinds is the exact number of bind attempts run must make.
		wantBinds int
		// wantServes is the number of serve sessions entered.
		wantServes int
	}{
		{
			// A permanent bind failure (a run dir the daemon cannot write) must
			// stop at the budget, not retry for the life of the node.
			name:       "a permanent bind failure stops at the budget",
			bindErrs:   []error{permanent, permanent, permanent, permanent, permanent, permanent, permanent},
			wantBinds:  runtimedSocketBindAttempts,
			wantServes: 0,
		},
		{
			// The transient case the retry exists for: a stale socket node from a
			// process that has not finished dying, gone by the third attempt.
			name:       "a transient bind failure is retried and then serves",
			bindErrs:   []error{errors.New("address already in use"), errors.New("address already in use")},
			wantBinds:  3,
			wantServes: 1,
		},
		{
			// A serve that fails after a successful bind rebinds — and is charged
			// against the SAME budget, so it cannot become a hot loop.
			name:      "a failing serve is bounded by the same budget",
			serveFn:   func(context.Context, net.Listener) error { return errors.New("grpc serve: bad file descriptor") },
			wantBinds: runtimedSocketBindAttempts,
			// The final attempt serves too; only its retry is refused.
			wantServes: runtimedSocketBindAttempts,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &controlSocketProbe{bindErrs: tc.bindErrs, serveFn: tc.serveFn}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := make(chan struct{})
			go func() {
				defer close(done)
				socketUnder(p).run(ctx)
			}()

			if tc.wantServes > 0 && tc.serveFn == nil {
				// The default serve blocks on ctx; end it the way node teardown does.
				time.AfterFunc(50*time.Millisecond, cancel)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("run did not return; the retry is unbounded")
			}

			binds, listeners, events := p.snapshot()
			if binds != tc.wantBinds {
				t.Errorf("bind attempts = %d, want %d", binds, tc.wantBinds)
			}
			var serves int
			for _, ev := range events {
				if ev == "serve" {
					serves++
				}
			}
			if serves != tc.wantServes {
				t.Errorf("serve sessions = %d, want %d", serves, tc.wantServes)
			}
			// EVERY listener run took ownership of is closed by the time it
			// returns — the ordering the node's teardown depends on, and the thing
			// that unlinks the socket node so the next start binds cleanly.
			for i, l := range listeners {
				if got := l.closeCount(); got != 1 {
					t.Errorf("listener %d closed %d times, want exactly 1", i, got)
				}
			}
		})
	}
}

// TestRuntimedControlSocketClosesListenerBeforeReturning pins the shutdown
// ORDER, not merely the fact of a close: on ctx cancellation the serve session
// ends, then the listener closes, and only then does run return. Node teardown
// relies on that — startNode's deferred stop must leave no bound socket behind
// for the runtime teardown (or the next start) to trip over.
func TestRuntimedControlSocketClosesListenerBeforeReturning(t *testing.T) {
	p := &controlSocketProbe{}
	serving := make(chan struct{})
	p.serveFn = func(ctx context.Context, lis net.Listener) error {
		close(serving)
		<-ctx.Done()
		// The listener MUST still be open while serve runs: closing it first
		// would drop in-flight RPCs instead of letting the server drain them.
		if lis.(*fakeControlListener).closeCount() != 0 {
			t.Error("listener was closed while serve was still running")
		}
		p.record("close-check")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		socketUnder(p).run(ctx)
	}()

	select {
	case <-serving:
	case <-time.After(10 * time.Second):
		t.Fatal("serve was never entered")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after cancellation")
	}

	_, listeners, events := p.snapshot()
	if len(listeners) != 1 {
		t.Fatalf("listeners = %d, want 1", len(listeners))
	}
	if got := listeners[0].closeCount(); got != 1 {
		t.Fatalf("listener closed %d times after run returned, want 1", got)
	}
	want := []string{"serve", "close-check"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

// TestRuntimedControlSocketRespectsCancellationDuringBackoff pins that a node
// shutting down mid-retry stops immediately instead of sleeping out its backoff
// budget: `launchctl kickstart -k` must not wait seconds on a socket that never
// bound.
func TestRuntimedControlSocketRespectsCancellationDuringBackoff(t *testing.T) {
	p := &controlSocketProbe{bindErrs: []error{errors.New("no such file or directory")}}
	s := socketUnder(p)
	s.backoff = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx)
	}()
	// Give run time to reach the backoff, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run slept through cancellation instead of returning")
	}
	if binds, _, _ := p.snapshot(); binds != 1 {
		t.Errorf("bind attempts = %d, want 1 (cancelled during the first backoff)", binds)
	}
}

// TestStartRuntimedControlSocketWithoutARuntimeIsANoop pins the HostProcess
// posture: that runtime backs no runtime/v1 service, so the node binds nothing
// and the teardown closure is still safe to defer unconditionally.
func TestStartRuntimedControlSocketWithoutARuntimeIsANoop(t *testing.T) {
	prov := provider.NewHostProcess("n", t.TempDir(), "127.0.0.1", nil)
	if rt := servableRuntime(prov); rt != nil {
		t.Fatalf("servableRuntime(HostProcess) = %v, want nil", rt)
	}
	stop := startRuntimedControlSocket(context.Background(), prov, t.TempDir(), slog.New(slog.DiscardHandler))
	if stop == nil {
		t.Fatal("startRuntimedControlSocket returned a nil teardown; the caller defers it unconditionally")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		stop()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the no-op teardown blocked")
	}
}
