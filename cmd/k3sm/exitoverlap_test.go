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
	"strings"
	"sync"
	"testing"
	"time"
)

// stageSpy records when a fake teardown stage ran, which is the only thing these
// cases assert about the stages themselves.
type stageSpy struct {
	mu    sync.Mutex
	calls int
	start time.Time
	end   time.Time
}

func (s *stageSpy) run(d time.Duration) {
	s.mu.Lock()
	s.calls++
	s.start = time.Now()
	s.mu.Unlock()
	time.Sleep(d)
	s.mu.Lock()
	s.end = time.Now()
	s.mu.Unlock()
}

func (s *stageSpy) window() (int, time.Time, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.start, s.end
}

// TestDaemonExitStopsTheRuntimeAndTheControlPlaneConcurrently is B320's gate.
//
// A stopping `k3sm server` runs its two longest teardown stages — the embedded
// runtime's close (every vm host helper) and the control-plane stop (kine, the
// apiserver, the scheduler, the controller-manager) — and they used to run
// strictly serially, because startNode deferred the first and runServer deferred
// the second, on opposite sides of a function boundary. launchd's single
// ExitTimeOut therefore had to cover their SUM, and a blown ExitTimeOut is answered
// with a SIGKILL of the daemon that orphans exactly the children the teardown is
// reaping. The stages share no resource but the mounted data root, which neither
// unmounts.
//
// The cases below drive the same two seams production wires together — the node's
// teardown composition and the server's stopper — with fakes in place of the two
// stages, because a real one needs a booted runtime and four control-plane
// children.
func TestDaemonExitStopsTheRuntimeAndTheControlPlaneConcurrently(t *testing.T) {
	// Long enough that an overlapped exit is unmistakably distinct from a serial
	// one (one stage vs two), short enough to stay a unit test.
	const stage = 400 * time.Millisecond
	// Scheduling slack on a loaded Mac. It sits well below stage, so the "not the
	// sum" assertion still separates 1×stage from 2×stage.
	const slack = 250 * time.Millisecond

	t.Run("the runtime close and the control-plane stop overlap", func(t *testing.T) {
		var closeStage, stopStage stageSpy
		stopper := &controlPlaneStopper{
			stop: func(context.Context) error {
				stopStage.run(stage)
				return nil
			},
			base:      context.Background(),
			bound:     time.Minute, // not what this case is about
			waitBound: time.Minute,
			log:       slog.New(slog.DiscardHandler),
		}
		teardown := teardownWithConcurrentExit(stopper.begin, func() { closeStage.run(stage) })

		start := time.Now()
		teardown()              // startNode's teardown: begin the stop, then close the runtime
		err := stopper.finish() // runServer's defer: wait for what the node began
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("finish = %v, want nil", err)
		}
		closeCalls, _, closeEnd := closeStage.window()
		stopCalls, stopStart, _ := stopStage.window()
		if closeCalls != 1 || stopCalls != 1 {
			t.Fatalf("stages ran %d runtime closes and %d control-plane stops, want exactly one of each", closeCalls, stopCalls)
		}
		// The load-bearing assertion: the second stage was already running while
		// the first still was. Stated as an ordering of recorded instants rather
		// than as a duration, so it cannot be satisfied by a fast machine.
		if !stopStart.Before(closeEnd) {
			t.Errorf("the control-plane stop started %s after the runtime close finished — the two stages are still serial",
				stopStart.Sub(closeEnd))
		}
		// And the consequence the plist's ExitTimeOut is derived from: the exit
		// costs the LARGER stage, not the sum of both.
		if elapsed >= stage+slack {
			t.Errorf("the exit took %s for two %s stages — that is their sum, not their overlap", elapsed, stage)
		}
	})

	t.Run("a control-plane stop that never returns is cut off by the outer bound", func(t *testing.T) {
		// Released on the way out so the fake stop's goroutine ends with the test.
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		const waitBound = 200 * time.Millisecond
		var closeStage stageSpy
		stopper := &controlPlaneStopper{
			stop: func(context.Context) error {
				<-release
				return nil
			},
			base: context.Background(),
			// Deliberately larger than the outer bound: the point is that the wait
			// is bounded INDEPENDENTLY of whatever the stop promises about itself.
			bound:     time.Minute,
			waitBound: waitBound,
			log:       slog.New(slog.DiscardHandler),
		}
		teardown := teardownWithConcurrentExit(stopper.begin, func() { closeStage.run(0) })

		teardown()
		start := time.Now()
		err := stopper.finish()
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("finish = nil for a control-plane stop that never returned; the daemon would park here until launchd SIGKILLed it")
		}
		if !strings.Contains(err.Error(), "control-plane stop") {
			t.Errorf("finish = %q, want it to name the stage still running", err)
		}
		if elapsed > waitBound+5*time.Second {
			t.Errorf("finish returned after %s, want it back by its %s outer bound", elapsed, waitBound)
		}
		// The other stage is unaffected: a wedged control-plane stop must not stop
		// the node from closing its runtime.
		if calls, _, _ := closeStage.window(); calls != 1 {
			t.Errorf("the runtime close ran %d times, want 1 — it must not be held up by the control-plane stop", calls)
		}
	})

	t.Run("a stop that never began is run by the wait itself", func(t *testing.T) {
		// The bring-up that failed before startNode's teardown could fire the hook:
		// runServer's defer must still stop the control plane it started, exactly as
		// it did before the overlap existed.
		wantErr := errors.New("kine would not drain")
		var ran stageSpy
		stopper := &controlPlaneStopper{
			stop: func(ctx context.Context) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("the inline stop got a context with no deadline; it must run under its own budget")
				}
				ran.run(0)
				return wantErr
			},
			base:      context.Background(),
			bound:     time.Minute,
			waitBound: time.Minute,
			log:       slog.New(slog.DiscardHandler),
		}

		if err := stopper.finish(); !errors.Is(err, wantErr) {
			t.Fatalf("finish = %v, want the stop's own error %v", err, wantErr)
		}
		if calls, _, _ := ran.window(); calls != 1 {
			t.Fatalf("the control plane was stopped %d times, want exactly 1", calls)
		}
	})

	t.Run("the hook fires once however often the teardown runs", func(t *testing.T) {
		// startNode both defers the teardown and runs it from awaitNodeExit, so the
		// composition has to be as idempotent as the close it wraps.
		var begins, closes int
		teardown := teardownWithConcurrentExit(func() { begins++ }, func() { closes++ })
		teardown()
		teardown()
		if begins != 1 {
			t.Errorf("the exit hook fired %d times, want exactly 1", begins)
		}
		if closes != 2 {
			t.Errorf("the wrapped close ran %d times, want 2 — the wrapper must not add an idempotence the close owns itself", closes)
		}
	})

	t.Run("a bring-up with no hook keeps the close it was given", func(t *testing.T) {
		// `k3sm agent`, `k3sm dev` and the standalone `k3sm node` pass nil.
		var closes int
		closeRuntime := func() { closes++ }
		if got := teardownWithConcurrentExit(nil, closeRuntime); got == nil {
			t.Fatal("teardownWithConcurrentExit(nil, close) = nil; startNode defers the result unconditionally")
		} else {
			got()
		}
		if closes != 1 {
			t.Errorf("the runtime close ran %d times, want 1", closes)
		}
	})
}
