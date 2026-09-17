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
	"slices"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// closeSpyProvider is a provider that exposes the embeddedRuntimeCloser seam
// directly. The embedded nil vkadapter.Provider supplies the rest of the (large)
// Virtual Kubelet method set and is never called: the teardown path only ever
// type-asserts the provider, and the production provider reaches the same seam by
// handing back its concrete *runtimed.Runtime, which a unit test cannot boot.
type closeSpyProvider struct {
	vkadapter.Provider

	mu      sync.Mutex
	calls   int
	err     error
	onClose func()
}

func (s *closeSpyProvider) Close() error {
	s.mu.Lock()
	s.calls++
	onClose := s.onClose
	err := s.err
	s.mu.Unlock()
	if onClose != nil {
		onClose()
	}
	return err
}

func (s *closeSpyProvider) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// errRunLoop stands in for the Virtual Kubelet run loop failing under a node that
// is otherwise still up — the second of startNode's two exit paths.
var errRunLoop = errors.New("virtual kubelet run loop failed")

// TestNodeExitClosesTheEmbeddedRuntime is B253's gate: a node that exits must stop
// the runtime it embedded, on BOTH exit paths, BEFORE its control socket comes
// down.
//
// What was wrong: startNode built the runtime through provider.NewRuntimed and
// drove it by direct RPC — never through runtime.Server.Serve — so the Close the
// standalone k3sm-runtimed daemon runs after Serve returns had no counterpart
// here, and nothing ever called it. A `launchctl bootout system/io.k3sm.server`
// therefore left every vm pod's k3sm-vmhost running, holding the data root open
// (the plist's WorkingDirectory) and dissenting the next `diskutil unmount`.
//
// The cases are the two ways startNode's wait ends. Each asserts the close on
// awaitNodeExit's RETURN — not after the teardown stack below it — so a stop that
// only ever happened because the test itself deferred it would read red. The
// ordering claim (the vm stop must not queue its 35-second bound behind the
// socket's shutdown grace inside launchd's 45-second ExitTimeOut) follows from
// that: the wait closes the runtime before it returns, and the control socket
// comes down later, when startNode returns to its defers. That the defers in
// production are REGISTERED in the order LIFO needs is the one fact this test
// mirrors rather than executes — startNode needs a live apiserver — and
// hack/acceptance/B253.sh pins it structurally, in the source.
func TestNodeExitClosesTheEmbeddedRuntime(t *testing.T) {
	cases := []struct {
		name    string
		exit    func(cancel context.CancelFunc, errc chan error)
		wantErr error
	}{
		{
			name: "the node context is cancelled (launchctl bootout / SIGTERM)",
			exit: func(cancel context.CancelFunc, _ chan error) { cancel() },
		},
		{
			name:    "the virtual kubelet run loop returns an error",
			exit:    func(_ context.CancelFunc, errc chan error) { errc <- errRunLoop },
			wantErr: errRunLoop,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var order []string
			record := func(event string) {
				mu.Lock()
				defer mu.Unlock()
				order = append(order, event)
			}

			spy := &closeSpyProvider{onClose: func() { record("runtime-close") }}
			stopRuntime := stopEmbeddedRuntime(spy, slog.New(slog.DiscardHandler))
			stopControlSocket := func() { record("control-socket-close") }

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			errc := make(chan error, 1)
			tc.exit(cancel, errc)

			done := make(chan error, 1)
			go func() { done <- awaitNodeExit(ctx, errc, stopRuntime) }()

			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the node exit path never returned")
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("awaitNodeExit = %v, want %v", err, tc.wantErr)
			}
			// The load-bearing assertion, and it is made HERE — on awaitNodeExit's
			// return, before anything below runs — because that is the whole claim:
			// the runtime is stopped by the wait itself, so it is already stopped by
			// the time startNode returns and its deferred teardown stack unwinds.
			if got := spy.closeCount(); got != 1 {
				t.Fatalf("the embedded runtime was closed %d times by awaitNodeExit alone, want exactly 1", got)
			}

			// Now the rest of startNode's teardown stack, in the order LIFO runs it:
			// the control socket comes down after the runtime, and the deferred
			// runtime stop (which covers the paths that return before the node is
			// ever ready) must be a no-op by now.
			stopControlSocket()
			stopRuntime()
			if got := spy.closeCount(); got != 1 {
				t.Fatalf("the embedded runtime was closed %d times after the deferred stop also ran, want exactly 1 (the closure must be idempotent)", got)
			}
			mu.Lock()
			got := slices.Clone(order)
			mu.Unlock()
			want := []string{"runtime-close", "control-socket-close"}
			if !slices.Equal(got, want) {
				t.Fatalf("teardown order = %v, want %v (the vm stop must not queue behind the socket's shutdown grace)", got, want)
			}
		})
	}
}

// TestNodeExitReportsAFailedRuntimeClose pins that a Close that reports stuck
// supervision or an unstopped helper is logged and swallowed, never propagated:
// the node is exiting either way, and masking the run loop's own error with a
// teardown error would hide the reason it exited.
func TestNodeExitReportsAFailedRuntimeClose(t *testing.T) {
	spy := &closeSpyProvider{err: errors.New("supervision did not stop before the close deadline")}
	stop := stopEmbeddedRuntime(spy, slog.New(slog.DiscardHandler))

	errc := make(chan error, 1)
	errc <- errRunLoop
	if err := awaitNodeExit(context.Background(), errc, stop); !errors.Is(err, errRunLoop) {
		t.Fatalf("awaitNodeExit = %v, want the run loop's own error %v", err, errRunLoop)
	}
	if got := spy.closeCount(); got != 1 {
		t.Fatalf("the embedded runtime was closed %d times, want exactly 1", got)
	}
}

// TestStopEmbeddedRuntimeWithoutARuntimeIsANoop pins the HostProcess posture: it
// embeds no runtimed runtime, so there is nothing to close — and the closure is
// still non-nil, because startNode defers it unconditionally.
func TestStopEmbeddedRuntimeWithoutARuntimeIsANoop(t *testing.T) {
	prov := provider.NewHostProcess("n", t.TempDir(), "127.0.0.1", nil)
	if rt := embeddedRuntime(prov); rt != nil {
		t.Fatalf("embeddedRuntime(HostProcess) = %v, want nil", rt)
	}
	stop := stopEmbeddedRuntime(prov, slog.New(slog.DiscardHandler))
	if stop == nil {
		t.Fatal("stopEmbeddedRuntime returned a nil teardown; startNode defers it unconditionally")
	}
	stop()
	stop()
}
