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
	"go/ast"
	"log/slog"
	"testing"
	"time"
)

// TestRunServerStopsTheRegistryBeforeTheRuntimeClose is the wiring gate for the
// ingest registry's early teardown, read off runServer's trace.
//
// The registry's teardown used to be one of runServer's own defers, so it ran
// only after startNode returned, behind the node's whole teardown (the runtime
// close first). A teardown that overran launchd's ExitTimeOut was SIGKILLed
// before it ran, and the registry child, in its own process group, kept serving
// under launchd. It now runs on the control-plane stop's lane, which the node
// fires at the start of its teardown, before its runtime close returns. That
// needs three things of runServer, each pinned here:
//
//  1. the registry stop is handed to the stopper (cpStop.precede, inside
//     startServerRegistry) after the registry starts and BEFORE startNode, whose teardown holds the runtime
//     close and fires the lane; a precede registered after startNode returned
//     would run nothing early;
//  2. the stopper's begin is the node's exit hook (onExitBegin), so the lane
//     starts with the node's teardown and not at runServer's defer;
//  3. the stop is shared (newSharedStage) and still deferred, the backstop for
//     an exit that never reaches the node's teardown, which after an early run
//     waits for it within its bound.
//
// TestRegistryTeardownRunsOnTheControlPlaneLane proves the stopper runs the
// stage during the runtime close and before the control-plane stop.
func TestRunServerStopsTheRegistryBeforeTheRuntimeClose(t *testing.T) {
	tr := runServerTrace(t)
	first := tr.firstCalls()

	precede, ok := first["cpStop.precede"]
	if !ok {
		t.Fatal("runServer never hands a stage to cpStop.precede; the ingest registry's teardown runs last, after the runtime close, where a SIGKILL skips it")
	}
	if args := precede.call.Args; len(args) != 2 || !isIdent(args[0], "stop") || !isIdent(args[1], "registryTeardownBound") {
		t.Errorf("cpStop.precede at %s is not handed (stop, registryTeardownBound)", tr.where(precede.call))
	}
	start, ok := first["startIngestRegistry"]
	if !ok {
		t.Fatal("runServer's trace never calls startIngestRegistry; this test no longer reads what it thinks it does")
	}
	node, ok := first["startNode"]
	if !ok {
		t.Fatal("runServer never calls startNode; this test no longer reads what it thinks it does")
	}
	if precede.pos < start.pos {
		t.Errorf("cpStop.precede at %s comes before startIngestRegistry at %s; it would be handed a stop that does not exist yet", tr.where(precede.call), tr.where(start.call))
	}
	if precede.pos > node.pos {
		t.Errorf("cpStop.precede at %s comes after startNode at %s, whose teardown runs the runtime close; the registry would be stopped after it", tr.where(precede.call), tr.where(node.call))
	}

	// (2) The node's exit hook is the stopper's begin.
	hooked := false
	tr.inspect(func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok || !isIdent(kv.Key, "onExitBegin") {
			return true
		}
		if sel, ok := kv.Value.(*ast.SelectorExpr); ok && sel.Sel.Name == "begin" {
			if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "cpStop" {
				hooked = true
			}
		}
		return true
	})
	if !hooked {
		t.Error("the node's onExitBegin is not the control-plane stopper's begin; the lane the registry teardown rides would start only at runServer's defer")
	}

	// (3) Shared between the two callers before it is handed over, and still deferred.
	if shared, ok := first["newSharedStage"]; !ok || shared.pos > precede.pos || shared.pos < start.pos {
		t.Error("the registry stop is not wrapped in newSharedStage between startIngestRegistry and cpStop.precede; the deferred backstop would run the teardown a second time, or not wait for the first")
	}
	if deferPos(tr.decl.Body, "stopRegistry") == 0 {
		t.Error("runServer no longer defers stopRegistry; an exit before the node's teardown would leave the registry child running")
	}
}

// isIdent reports whether e is the identifier name.
func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// TestRegistryTeardownRunsOnTheControlPlaneLane drives the stopper as the server
// wires it, with fakes for the stages: the registry's teardown starts while the
// runtime close is still running, and the control-plane stop starts only after it.
func TestRegistryTeardownRunsOnTheControlPlaneLane(t *testing.T) {
	const stage = 300 * time.Millisecond
	newStopper := func(stop func(context.Context) error, log *slog.Logger) *controlPlaneStopper {
		return &controlPlaneStopper{stop: stop, base: context.Background(), bound: time.Minute, waitBound: time.Minute, log: log}
	}

	t.Run("the registry stops during the runtime close, then the control plane", func(t *testing.T) {
		closeStage, regStage, stopStage := newStageSpy(), newStageSpy(), newStageSpy()
		stopper := newStopper(func(context.Context) error { stopStage.run(0); return nil }, slog.New(slog.DiscardHandler))
		stopper.precede(func() { regStage.run(stage / 3) }, time.Minute)
		teardown := teardownWithConcurrentExit(stopper.begin, closedChan, time.Minute, func() { closeStage.run(stage) })

		teardown()
		<-stopStage.fired // ordering the hook against finish is a test artifact; see the B320 gate
		if err := stopper.finish(); err != nil {
			t.Fatalf("finish = %v, want nil", err)
		}
		_, _, closeEnd := closeStage.window()
		regCalls, regStart, regEnd := regStage.window()
		_, stopStart, _ := stopStage.window()
		if regCalls != 1 {
			t.Fatalf("the registry teardown ran %d times, want once", regCalls)
		}
		if !regStart.Before(closeEnd) {
			t.Errorf("the registry teardown started %s after the runtime close finished; it is still queued behind it", regStart.Sub(closeEnd))
		}
		if stopStart.Before(regEnd) {
			t.Errorf("the control-plane stop started %s before the registry teardown finished; its retractions lose their apiserver", regEnd.Sub(stopStart))
		}
	})

	t.Run("a registry teardown that never returns is cut off by its bound", func(t *testing.T) {
		const bound = 100 * time.Millisecond
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		logs := newLogSpy()
		stopStage := newStageSpy()
		stopper := newStopper(func(context.Context) error { stopStage.run(0); return nil }, logs.logger())
		stopper.precede(func() { <-release }, bound)

		start := time.Now()
		stopper.begin()
		<-stopStage.fired
		if err := stopper.finish(); err != nil {
			t.Fatalf("finish = %v, want nil", err)
		}
		if _, stopStart, _ := stopStage.window(); stopStart.Sub(start) < bound {
			t.Errorf("the control-plane stop started %s in, before the %s bound on the stage ahead of it", stopStart.Sub(start), bound)
		}
		if logs.line("still running past its bound") == "" {
			t.Error("a stage cut off by its bound was not reported")
		}
	})

	t.Run("an exit that never began runs the registry first, inline", func(t *testing.T) {
		regStage, stopStage := newStageSpy(), newStageSpy()
		stopper := newStopper(func(context.Context) error { stopStage.run(0); return nil }, slog.New(slog.DiscardHandler))
		stopper.precede(func() { regStage.run(0) }, time.Minute)
		if err := stopper.finish(); err != nil {
			t.Fatalf("finish = %v, want nil", err)
		}
		_, _, regEnd := regStage.window()
		_, stopStart, _ := stopStage.window()
		if regEnd.IsZero() || stopStart.Before(regEnd) {
			t.Error("finish's inline stop did not run the registry teardown first")
		}
	})

	t.Run("the deferred backstop runs nothing twice and returns at once after a finished run", func(t *testing.T) {
		n := 0
		st := newSharedStage("test", func() { n++ }, time.Minute, slog.New(slog.DiscardHandler))
		st.run()
		start := time.Now()
		st.run()
		if n != 1 {
			t.Errorf("the shared stage ran %d times, want once", n)
		}
		if took := time.Since(start); took > 100*time.Millisecond {
			t.Errorf("the backstop took %s after a finished run", took)
		}
	})

	t.Run("the deferred backstop waits for an early run still under way", func(t *testing.T) {
		// The early run has sent its SIGTERM and is waiting to SIGKILL: an exit now
		// would leave the child without its kill. The backstop must wait it out.
		const run = 200 * time.Millisecond
		var finished time.Time
		st := newSharedStage("test", func() { time.Sleep(run); finished = time.Now() }, time.Minute, slog.New(slog.DiscardHandler))
		early := make(chan struct{})
		go func() { defer close(early); st.run() }()
		time.Sleep(run / 4) // the early run is under way
		st.run()
		returned := time.Now()
		<-early
		if finished.IsZero() || returned.Before(finished) {
			t.Error("the backstop returned while the early run was still under way")
		}
	})

	t.Run("the deferred backstop's wait ends at the stage's bound", func(t *testing.T) {
		const bound = 150 * time.Millisecond
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		logs := newLogSpy()
		st := newSharedStage("test", func() { <-release }, bound, logs.logger())
		go st.run()
		time.Sleep(bound / 3)
		start := time.Now()
		st.run()
		if took := time.Since(start); took > bound+500*time.Millisecond {
			t.Errorf("the backstop waited %s, past the %s bound measured from the early run's start", took, bound)
		}
		if logs.line("still running past its bound") == "" {
			t.Error("a backstop that stopped waiting at the bound did not say so")
		}
	})

	t.Run("a nil stopper takes no preceding stage", func(t *testing.T) {
		var s *controlPlaneStopper
		s.precede(func() {}, time.Second) // must not panic
	})
}

// TestNodeUpdateStopIsBounded is the bound on the step that held the 2026-10-16
// exit: mid-install, the update watcher is blocked on the root helper's stream,
// which ignores its context and ends only after this daemon has exited. Its stop
// must return after the grace, not wait for that.
func TestNodeUpdateStopIsBounded(t *testing.T) {
	const grace = 100 * time.Millisecond

	t.Run("a watcher that ignores its context is left after the grace", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		logs := newLogSpy()
		stop := superviseUpdateWatcher(context.Background(), func(context.Context) { <-release }, grace, logs.logger())

		start := time.Now()
		stop()
		if took := time.Since(start); took < grace || took > grace+time.Second {
			t.Errorf("stop took %s, want about the %s grace", took, grace)
		}
		if logs.line("update watcher did not return in time") == "" {
			t.Error("a watcher left after the grace was not reported")
		}
	})

	t.Run("a watcher that returns on cancellation is waited for", func(t *testing.T) {
		returned := make(chan struct{})
		stop := superviseUpdateWatcher(context.Background(), func(ctx context.Context) {
			<-ctx.Done()
			close(returned)
		}, time.Minute, slog.New(slog.DiscardHandler))

		start := time.Now()
		stop()
		select {
		case <-returned:
		default:
			t.Error("stop returned before the watcher did")
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("stop took %s for a watcher that returns at once", took)
		}
	})
}
