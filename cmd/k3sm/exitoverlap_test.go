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
	"bytes"
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
	fired chan struct{}
	start time.Time
	end   time.Time
}

func newStageSpy() *stageSpy { return &stageSpy{fired: make(chan struct{}, 4)} }

func (s *stageSpy) run(d time.Duration) {
	s.mu.Lock()
	s.calls++
	s.start = time.Now()
	s.mu.Unlock()
	s.fired <- struct{}{}
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

// logSpy is a concurrency-safe slog handler: the exit hook logs from its own
// goroutine while the wait logs from the caller's, so a test that reads the lines
// needs the writes serialized.
type logSpy struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	text slog.Handler
}

func newLogSpy() *logSpy {
	s := &logSpy{}
	s.text = slog.NewTextHandler(&s.buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return s
}

func (s *logSpy) Enabled(context.Context, slog.Level) bool { return true }

func (s *logSpy) Handle(ctx context.Context, r slog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.text.Handle(ctx, r)
}

func (s *logSpy) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s *logSpy) WithGroup(string) slog.Handler      { return s }
func (s *logSpy) logger() *slog.Logger               { return slog.New(s) }

// line returns the first logged line containing want, or "".
func (s *logSpy) line(want string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range strings.Split(s.buf.String(), "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	return ""
}

// closedChan is a node-exit signal that is already drained.
func closedChan() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// TestDaemonExitStopsTheRuntimeAndTheControlPlaneConcurrently is B320's gate.
//
// A stopping `k3sm server` runs its two longest teardown stages — the embedded
// runtime's close (every vm host helper) and the control-plane stop (kine, the
// apiserver, the scheduler, the controller-manager) — and they used to run
// strictly serially, because startNode deferred the first and runServer deferred
// the second, on opposite sides of a function boundary. launchd's single ExitTimeOut
// therefore had to cover their SUM, and a blown ExitTimeOut is answered with a
// SIGKILL of the daemon that orphans exactly the children the teardown is reaping.
// The stages share no resource but the mounted data root, which neither unmounts.
//
// What the overlap must not do is take the apiserver away from a node still writing
// to it, so the stop begins only once the node's own loops have returned or
// nodeDrainGrace has passed — the two rows in the middle below.
//
// The cases drive the same two seams production wires together — the node's
// teardown composition and the server's stopper — with fakes in place of the two
// stages, because a real one needs a booted runtime and four control-plane children.
func TestDaemonExitStopsTheRuntimeAndTheControlPlaneConcurrently(t *testing.T) {
	// Long enough that an overlapped exit is unmistakably distinct from a serial
	// one (one stage vs two), short enough to stay a unit test.
	const stage = 400 * time.Millisecond
	// Scheduling slack on a loaded Mac. It sits well below stage, so the "not the
	// sum" assertion still separates 1×stage from 2×stage.
	const slack = 250 * time.Millisecond
	// A grace no row reaches except the one testing it.
	const noDrainWait = time.Minute

	// newStopper builds the stopper under test with a fake stop; the bounds are the
	// row's to choose, since production's (executor.StopBound and the margin) are
	// minutes of wall clock.
	newStopper := func(stop func(context.Context) error, waitBound time.Duration, log *slog.Logger) *controlPlaneStopper {
		return &controlPlaneStopper{
			stop:      stop,
			base:      context.Background(),
			bound:     time.Minute,
			waitBound: waitBound,
			log:       log,
		}
	}

	t.Run("the runtime close and the control-plane stop overlap", func(t *testing.T) {
		closeStage, stopStage := newStageSpy(), newStageSpy()
		stopper := newStopper(func(context.Context) error {
			stopStage.run(stage)
			return nil
		}, time.Minute, slog.New(slog.DiscardHandler))
		teardown := teardownWithConcurrentExit(stopper.begin, closedChan, noDrainWait, func() { closeStage.run(stage) })

		start := time.Now()
		teardown() // startNode's teardown: begin the stop, then close the runtime
		// Test-only synchronisation: the hook fires on its own goroutine, and in
		// production finish is reached 37 seconds later (after the runtime close),
		// so nothing has to order them there. Here they would race, and a finish
		// that won would run the stop inline and measure the serial path.
		<-stopStage.fired
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

	t.Run("the control-plane stop waits for the node's loops to return", func(t *testing.T) {
		// The hazard the drain closes: on a SIGTERM awaitNodeExit returns on
		// ctx.Done without waiting for the run loop, so an unguarded hook SIGTERMs
		// the apiserver while the node is still publishing its last status.
		const loopExit = 100 * time.Millisecond
		nodeExited := make(chan struct{})
		loopDone := make(chan time.Time, 1)
		go func() {
			time.Sleep(loopExit)
			loopDone <- time.Now()
			close(nodeExited)
		}()

		closeStage, stopStage := newStageSpy(), newStageSpy()
		stopper := newStopper(func(context.Context) error {
			stopStage.run(0)
			return nil
		}, time.Minute, slog.New(slog.DiscardHandler))
		teardown := teardownWithConcurrentExit(stopper.begin, func() <-chan struct{} { return nodeExited }, noDrainWait, func() { closeStage.run(stage) })

		teardown()
		<-stopStage.fired // see the first row: ordering the hook against finish is a test artifact
		if err := stopper.finish(); err != nil {
			t.Fatalf("finish = %v, want nil", err)
		}
		exitedAt := <-loopDone
		_, _, closeEnd := closeStage.window()
		_, stopStart, _ := stopStage.window()

		if stopStart.Before(exitedAt) {
			t.Errorf("the control-plane stop started %s BEFORE the node's loops returned — the apiserver goes away under a node still writing to it",
				exitedAt.Sub(stopStart))
		}
		// Still overlapped: waiting for the loops costs 100ms of a 400ms close, not
		// the whole close.
		if !stopStart.Before(closeEnd) {
			t.Errorf("the control-plane stop started %s after the runtime close finished — the drain wait swallowed the overlap",
				stopStart.Sub(closeEnd))
		}
	})

	t.Run("a node whose loops never return is bounded by the drain grace", func(t *testing.T) {
		const grace = 150 * time.Millisecond
		wedged := make(chan struct{}) // never closed: the run loop that will not come back

		closeStage, stopStage := newStageSpy(), newStageSpy()
		stopper := newStopper(func(context.Context) error {
			stopStage.run(0)
			return nil
		}, time.Minute, slog.New(slog.DiscardHandler))
		teardown := teardownWithConcurrentExit(stopper.begin, func() <-chan struct{} { return wedged }, grace, func() { closeStage.run(stage) })

		start := time.Now()
		teardown()
		<-stopStage.fired // see the first row: ordering the hook against finish is a test artifact
		if err := stopper.finish(); err != nil {
			t.Fatalf("finish = %v, want nil", err)
		}
		_, _, closeEnd := closeStage.window()
		_, stopStart, _ := stopStage.window()

		if waited := stopStart.Sub(start); waited < grace {
			t.Errorf("the control-plane stop started %s in, before the %s drain grace — a node that never drains must still get its grace", waited, grace)
		}
		if !stopStart.Before(closeEnd) {
			t.Errorf("the control-plane stop started %s after the runtime close finished — a wedged run loop must not cost the whole overlap",
				stopStart.Sub(closeEnd))
		}
	})

	t.Run("a control-plane stop that never returns is cut off by the outer bound", func(t *testing.T) {
		// Released on the way out so the fake stop's goroutine ends with the test.
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		const waitBound = 200 * time.Millisecond
		logs := newLogSpy()
		closeStage := newStageSpy()
		started := make(chan struct{})
		stopper := newStopper(func(context.Context) error {
			close(started)
			<-release
			return nil
		}, waitBound, logs.logger())
		// Deliberately: bound (a minute) is larger than the outer waitBound, because
		// the point is that the wait is bounded INDEPENDENTLY of what the stop
		// promises about itself.
		teardown := teardownWithConcurrentExit(stopper.begin, closedChan, noDrainWait, func() { closeStage.run(0) })

		teardown()
		<-started // the hook has fired and the stop is running; now wait for it
		start := time.Now()
		err := stopper.finish()
		elapsed := time.Since(start)

		if !errors.Is(err, errControlPlaneStopTimeout) {
			t.Fatalf("finish = %v, want an error wrapping errControlPlaneStopTimeout; the daemon would otherwise park here until launchd SIGKILLed it", err)
		}
		if !strings.Contains(err.Error(), "control-plane stop") {
			t.Errorf("finish = %q, want it to name the stage still running", err)
		}
		if elapsed > waitBound+5*time.Second {
			t.Errorf("finish returned after %s, want it back by its %s outer bound", elapsed, waitBound)
		}
		// The timeout reports itself, with the stage and the reason the remainder is
		// somebody else's problem — the daemon's own log is where an operator learns
		// which stage launchd's ExitTimeOut is about to cut off.
		line := logs.line("stage=control-plane-stop")
		switch {
		case line == "":
			t.Errorf("the expired wait logged no line carrying stage=control-plane-stop; logged:\n%s", logs.line(""))
		case !strings.Contains(line, "level=ERROR"):
			t.Errorf("the expired wait logged %q, want it at ERROR", line)
		case !strings.Contains(line, "still_running=true"):
			t.Errorf("the expired wait logged %q, want still_running=true", line)
		case !strings.Contains(line, "ExitTimeOut"):
			t.Errorf("the expired wait logged %q, want it to say launchd's ExitTimeOut reaps the remainder", line)
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
		ran := newStageSpy()
		stopper := newStopper(func(ctx context.Context) error {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("the inline stop got a context with no deadline; it must run under its own budget")
			}
			ran.run(0)
			return wantErr
		}, time.Minute, slog.New(slog.DiscardHandler))

		if err := stopper.finish(); !errors.Is(err, wantErr) {
			t.Fatalf("finish = %v, want the stop's own error %v", err, wantErr)
		}
		if calls, _, _ := ran.window(); calls != 1 {
			t.Fatalf("the control plane was stopped %d times, want exactly 1", calls)
		}
		// A hook still inside its drain wait when the inline stop ran must not start
		// a second one behind it.
		stopper.begin()
		time.Sleep(50 * time.Millisecond)
		if calls, _, _ := ran.window(); calls != 1 {
			t.Errorf("the control plane was stopped %d times once the late hook fired, want still 1", calls)
		}
	})

	t.Run("the hook fires once however often the teardown runs", func(t *testing.T) {
		// startNode both defers the teardown and runs it from awaitNodeExit, so the
		// composition has to be as idempotent as the close it wraps.
		hook, closes := newStageSpy(), newStageSpy()
		teardown := teardownWithConcurrentExit(func() { hook.run(0) }, closedChan, noDrainWait, func() { closes.run(0) })
		teardown()
		teardown()
		select {
		case <-hook.fired:
		case <-time.After(5 * time.Second):
			t.Fatal("the exit hook never fired")
		}
		time.Sleep(100 * time.Millisecond) // a second firing would land by now
		if calls, _, _ := hook.window(); calls != 1 {
			t.Errorf("the exit hook fired %d times, want exactly 1", calls)
		}
		if calls, _, _ := closes.window(); calls != 2 {
			t.Errorf("the wrapped close ran %d times, want 2 — the wrapper must not add an idempotence the close owns itself", calls)
		}
	})

	t.Run("a bring-up with no hook keeps the close it was given", func(t *testing.T) {
		// `k3sm agent`, `k3sm dev` and the standalone `k3sm node` pass nil.
		var closes int
		closeRuntime := func() { closes++ }
		got := teardownWithConcurrentExit(nil, closedChan, noDrainWait, closeRuntime)
		if got == nil {
			t.Fatal("teardownWithConcurrentExit(nil, …) = nil; startNode defers the result unconditionally")
		}
		got()
		if closes != 1 {
			t.Errorf("the runtime close ran %d times, want 1", closes)
		}
	})

	t.Run("a node whose loops never started has nothing to drain", func(t *testing.T) {
		// startNode's early returns: the hook must fire at once rather than paying a
		// grace for loops that do not exist.
		hook := newStageSpy()
		teardown := teardownWithConcurrentExit(func() { hook.run(0) }, func() <-chan struct{} { return nil }, time.Minute, func() {})
		teardown()
		select {
		case <-hook.fired:
		case <-time.After(5 * time.Second):
			t.Fatal("the exit hook never fired for a node with no loops; it is waiting on a drain that can never happen")
		}
	})
}
