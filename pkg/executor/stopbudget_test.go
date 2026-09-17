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

package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// logCapture is a concurrency-safe slog handler: the teardown logs from the
// caller's goroutine and the reapers from theirs, so a test reading the lines
// needs the writes serialized.
type logCapture struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	text slog.Handler
}

func newLogCapture() *logCapture {
	c := &logCapture{}
	c.text = slog.NewTextHandler(&c.buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return c
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(ctx context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.text.Handle(ctx, r)
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }
func (c *logCapture) logger() *slog.Logger               { return slog.New(c) }

// line returns the first logged line containing want, or "".
func (c *logCapture) line(want string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range strings.Split(c.buf.String(), "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	return ""
}

// fakeReapedComponent builds a component backed by a REAL child in its own process
// group, with the same single-reaper wiring spawnEnv gives a production component:
// one cmd.Wait, whose return closes exited.
//
// The child is a plain `sleep`, not a control-plane binary: what is under test is
// the teardown's wait discipline, and that is the same discipline whatever the
// child was executing. Its own process group is what makes stopComponent's
// group-wide kill(-pid) safe in a test binary — without Setpgid the signal would
// go to `go test`'s group, i.e. to the test runner itself.
func fakeReapedComponent(t *testing.T, name string) *component {
	t.Helper()
	c := startFakeChild(t, name)
	// The fake reaper, wired exactly as spawnEnv wires the real one.
	go func() {
		_ = c.cmd.Wait()
		close(c.exited)
	}()
	return c
}

// fakeStuckComponent builds a component whose reaper NEVER closes exited — the
// shape of the hazard this file gates: a child parked in an uninterruptible state,
// or a reaper goroutine that has not observed the exit. Stop cannot distinguish
// the two, and before B321 it waited on that channel forever after the SIGKILL.
func fakeStuckComponent(t *testing.T, name string) *component {
	t.Helper()
	return startFakeChild(t, name)
}

// startFakeChild starts the child both fakes share and owns its whole lifetime:
// the cleanup kills and reaps it on every path out of the test, including a Fatal.
func startFakeChild(t *testing.T, name string) *component {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the fake %s child: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return &component{name: name, cmd: cmd, exited: make(chan struct{})}
}

// TestStopHonoursItsContextAfterSIGKILL is B321's gate.
//
// What was wrong: Stop took a context and never read it. stopComponent waited
// drainGrace for the SIGTERM, escalated to SIGKILL, and then waited on the
// component's exited channel with NO bound at all — so a child that would not die,
// or a reaper that never observed the death, parked the whole teardown forever.
// The daemon meanwhile advertises a budget for that teardown: `k3sm server` calls
// Stop under context.WithTimeout(…, executor.StopBound), and pkg/install derives
// the plist's ExitTimeOut from that same symbol. launchd answers a blown
// ExitTimeOut with a SIGKILL of the DAEMON, which orphans exactly the children
// this stop exists to reap — so the budget has to be a deadline Stop keeps, not a
// number it hopes for.
func TestStopHonoursItsContextAfterSIGKILL(t *testing.T) {
	// Short on purpose: the assertion is that Stop returns AT its deadline, and a
	// bound in the tens of milliseconds separates that from every other wait in
	// the path (drainGrace is 5s, `go test`'s package alarm is 10 minutes — which
	// is how the unbounded wait used to surface: as a whole-package timeout with
	// no attribution).
	const budget = 200 * time.Millisecond
	// Generous enough that a loaded 8 GiB host scheduling the test goroutine late
	// cannot fail it, and still two orders of magnitude below the unbounded wait
	// it distinguishes.
	const margin = 4 * time.Second

	t.Run("a component whose reaper never observes the exit does not outlive the budget", func(t *testing.T) {
		s := NewSupervised(Config{WorkDir: t.TempDir()})
		// Start order, which is what Stop receives: kine first, apiserver second.
		// shutdownOrder then stops the apiserver first and kine last, so the
		// component that exits cleanly is reaped while the budget is still whole
		// and the stuck one is what the deadline lands on.
		clean := fakeReapedComponent(t, "apiserver")
		stuck := fakeStuckComponent(t, "kine")
		s.comps = []*component{stuck, clean}
		s.started = true

		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()

		start := time.Now()
		err := s.Stop(ctx)
		elapsed := time.Since(start)

		if !errors.Is(err, ErrStopBudgetExceeded) {
			t.Fatalf("Stop = %v, want an error wrapping ErrStopBudgetExceeded", err)
		}
		if elapsed > budget+margin {
			t.Fatalf("Stop returned after %s, want it back by its %s deadline (+%s margin) — the wait after the SIGKILL is still unbounded", elapsed, budget, margin)
		}
		if !strings.Contains(err.Error(), stuck.name) {
			t.Errorf("Stop = %q, want it to name the component it could not witness reaped (%q)", err, stuck.name)
		}
		// The other half of the claim: the budget expiring does not smear over a
		// component that DID exit. Naming everything would make the report useless
		// for finding the child that has to be reaped by hand.
		if strings.Contains(err.Error(), clean.name) {
			t.Errorf("Stop = %q, but %q exited well inside the budget and must not be named", err, clean.name)
		}
		// Stop keeps reaping what it can: the stuck component is SIGKILLed even
		// though the budget was already spent when its turn came.
		if !processGone(t, stuck.cmd.Process.Pid) {
			t.Errorf("the stuck component's child is still running; Stop stopped signalling once its budget expired")
		}
	})

	t.Run("a reaper still in flight is named at WARN", func(t *testing.T) {
		// The second way the budget can expire: every CHILD was witnessed exiting,
		// but a reaper goroutine has not finished its post-exit work (its supervision
		// decision, a crash callback). Stop must not park on it either, and the
		// give-up is reported at WARN naming components — names only, never argv or
		// a log line — because an Error here would read as a failed teardown when the
		// children are in fact all reaped.
		logs := newLogCapture()
		s := NewSupervised(Config{WorkDir: t.TempDir(), Logger: logs.logger()})
		s.comps = []*component{fakeReapedComponent(t, "kine")}
		s.started = true
		// A reaper that never finishes. Released on the way out so the goroutine
		// awaitReapers left behind ends with the test.
		s.reapers.Add(1)
		t.Cleanup(func() { s.reapers.Done() })

		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		start := time.Now()
		err := s.Stop(ctx)
		elapsed := time.Since(start)

		if !errors.Is(err, ErrStopBudgetExceeded) {
			t.Fatalf("Stop = %v, want an error wrapping ErrStopBudgetExceeded", err)
		}
		if elapsed > budget+margin {
			t.Fatalf("Stop returned after %s, want it back by its %s deadline — the reapers.Wait is still unbounded", elapsed, budget)
		}
		line := logs.line("components=")
		switch {
		case line == "":
			t.Errorf("the give-up logged no line naming the components; logged:\n%s", logs.line(""))
		case !strings.Contains(line, "level=WARN"):
			t.Errorf("the give-up logged %q, want it at WARN", line)
		case !strings.Contains(line, "components=kine"):
			t.Errorf("the give-up logged %q, want it to name kine", line)
		}
	})

	t.Run("every component reaped inside the budget is a clean stop", func(t *testing.T) {
		s := NewSupervised(Config{WorkDir: t.TempDir()})
		s.comps = []*component{fakeReapedComponent(t, "kine"), fakeReapedComponent(t, "apiserver")}
		s.started = true

		ctx, cancel := context.WithTimeout(context.Background(), StopBound)
		defer cancel()
		if err := s.Stop(ctx); err != nil {
			t.Fatalf("Stop = %v, want nil: every component exited on the SIGTERM, well inside the budget", err)
		}
	})
}

// processGone polls the kernel for a pid's departure. It polls rather than asking
// once because a SIGKILL is delivered asynchronously: the signal has been sent
// when kill() returns, not landed.
func processGone(t *testing.T, pid int) bool {
	t.Helper()
	for range 100 {
		if processExited(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
