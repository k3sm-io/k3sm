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
	"fmt"
	"log/slog"
	"sync"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// The two longest stages of a stopping `k3sm server`, and why they now overlap.
//
// A daemon on its way out runs the embedded runtime's close (every vm host
// helper, on runtimed's own 35s+2s bound — deferred by startNode) and the
// control-plane stop (kine, the apiserver, the scheduler and the
// controller-manager, on executor.StopBound — deferred by runServer). They sat on
// opposite sides of the startNode/runServer boundary, so they ran strictly
// serially and launchd's single ExitTimeOut had to cover their SUM — the daemon
// spent 67 seconds of a 90-second budget doing two things that have nothing to say
// to each other. They touch disjoint resources: vm host helper processes on one
// side, the control-plane child processes on the other.
//
// The one thing they DO share is the mounted data root — it is the server plist's
// WorkingDirectory and both stages hold it open — and neither stage unmounts it,
// so overlapping them cannot race over it; the unmount is an operator step that
// happens after the daemon is out (see hack/acceptance/B253.sh's lab tier).
//
// The seam is additive, and deliberately so: nothing about the runtime close moves
// or is reordered (its LIFO position relative to the control socket is
// load-bearing — see startNode). startNode simply fires an optional hook at the
// very START of its teardown, before the close; `k3sm server` is the only caller
// that sets one, and its hook launches the control-plane stop so the stop is
// already draining while the vm helpers come down. runServer's own defer then
// WAITS for that stop instead of starting it.

// controlPlaneStopWaitMargin is how much longer than the stop's own budget
// runServer is willing to wait for it.
//
// It is an OUTER bound on the wait, not a second budget for the stop: the stop
// already selects on a context limited to executor.StopBound (B321), so this
// covers only the slack between that deadline and the goroutine reporting it —
// scheduling on a loaded Mac that is stopping everything at once. Its job is to
// make the wait bounded by construction, so no future regression inside Stop can
// park a daemon that launchd is holding a SIGKILL over.
const controlPlaneStopWaitMargin = 5 * time.Second

// controlPlaneStopper runs the control-plane teardown as a stage that can overlap
// the node's runtime close: begin starts it, finish waits for it.
//
// Both halves are safe to call in either order and any number of times, because
// the two exit paths reach them independently — a node that tore down normally
// fires begin from its teardown hook, while a bring-up that failed before the node
// ever ran reaches finish having never begun, and must still stop the control
// plane it started.
type controlPlaneStopper struct {
	// stop is executor.Supervised.Stop in production; a fake in tests.
	stop func(context.Context) error
	// base is the server's own context, used ONLY as the value parent: the stop
	// context is derived with context.WithoutCancel, because the commonest reason
	// to be stopping is that base has just been cancelled.
	base context.Context
	// bound is the stop's own budget (executor.StopBound) and waitBound is the
	// independent outer bound on the wait for it.
	bound     time.Duration
	waitBound time.Duration
	log       *slog.Logger

	mu   sync.Mutex
	done chan error // non-nil once begin has launched the stop
}

// newControlPlaneStopper returns the stopper `k3sm server` uses: the executor's
// own StopBound for the stop, that plus the margin for the wait.
func newControlPlaneStopper(base context.Context, stop func(context.Context) error, log *slog.Logger) *controlPlaneStopper {
	return &controlPlaneStopper{
		stop:      stop,
		base:      base,
		bound:     executor.StopBound,
		waitBound: executor.StopBound + controlPlaneStopWaitMargin,
		log:       log,
	}
}

// begin launches the control-plane stop in the background and returns
// immediately. It is the nodeOptions.onExitBegin hook `k3sm server` installs, so
// it runs at the very start of the node's teardown — before the embedded runtime
// close, which is what makes the two overlap. Calls after the first are no-ops.
func (s *controlPlaneStopper) begin() {
	s.mu.Lock()
	if s.done != nil {
		s.mu.Unlock()
		return
	}
	done := make(chan error, 1)
	s.done = done
	s.mu.Unlock()

	s.log.Info("stopping the control plane alongside the node's runtime teardown", "bound", s.bound)
	go func() { done <- s.runStop() }()
}

// finish completes the control-plane teardown: it waits for a stop begin already
// launched, or runs one inline when begin never fired (the bring-up that failed
// before the node's teardown could run — the pre-overlap behaviour, unchanged).
//
// The wait is bounded by waitBound whatever the stop does. On expiry it names the
// stage still running and returns: a daemon must not park here, because launchd
// answers a blown ExitTimeOut with a SIGKILL that orphans the children the rest of
// the teardown is still reaping.
func (s *controlPlaneStopper) finish() error {
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	if done == nil {
		return s.runStop()
	}
	select {
	case err := <-done:
		return err
	case <-time.After(s.waitBound):
		return fmt.Errorf("control-plane stop still running %s after it began; leaving it to launchd and the next start", s.waitBound)
	}
}

// runStop calls the stop under its own budget. The context is derived with
// context.WithoutCancel because the server's context is already cancelled on the
// commonest shutdown path (SIGTERM from `launchctl bootout`), and a stop handed a
// cancelled context would return instantly having reaped nothing.
func (s *controlPlaneStopper) runStop() error {
	base := s.base
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(base), s.bound)
	defer cancel()
	return s.stop(ctx)
}

// teardownWithConcurrentExit composes the node's teardown: onExitBegin first, then
// closeRuntime. The point is what onExitBegin is allowed to do — start work and
// return — so that whatever it started runs WHILE the runtime close does, instead
// of after it.
//
// It wraps the close rather than moving it: closeRuntime is the same closure
// stopEmbeddedRuntime built, still deferred in the same position, still the thing
// awaitNodeExit runs on both exit paths. A nil onExitBegin (every bring-up but
// `k3sm server`) returns closeRuntime untouched.
func teardownWithConcurrentExit(onExitBegin func(), closeRuntime func()) func() {
	if onExitBegin == nil {
		return closeRuntime
	}
	var once sync.Once
	return func() {
		once.Do(onExitBegin)
		closeRuntime()
	}
}
