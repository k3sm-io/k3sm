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
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// OnComponentExit is the supervision seam: before it, the per-component reapers
// were the only observers of a child's death and their only readers were
// awaitHealthy (bring-up) and stopComponent (teardown), so a control-plane
// component that died AFTER bring-up was reported to nobody. These tests pin the
// cases that decide whether the seam is safe to act on — it must fire on a crash,
// including a crash in the window where LATER components are still coming up, and
// must stay silent for both kinds of non-crash exit, because the server cancels
// its root context from this callback.

// writeChild drops an executable script into the work dir's bin dir under name.
func writeChild(t *testing.T, wd, name, script string) {
	t.Helper()
	if err := os.MkdirAll(binDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir(wd), name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// exitRecorder collects callback invocations.
type exitRecorder struct {
	mu    sync.Mutex
	calls []string
	paths []string
	tails []string
	fired chan struct{}
	once  sync.Once
}

func newExitRecorder() *exitRecorder {
	return &exitRecorder{fired: make(chan struct{})}
}

func (r *exitRecorder) fn(name string, _ error, logPath, logTail string) {
	r.mu.Lock()
	r.calls = append(r.calls, name)
	r.paths = append(r.paths, logPath)
	r.tails = append(r.tails, logTail)
	r.mu.Unlock()
	r.once.Do(func() { close(r.fired) })
}

func (r *exitRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// TestOnComponentExitFiresWhenAComponentCrashes is the case the seam exists for:
// the component came up, then its child died on its own.
func TestOnComponentExitFiresWhenAComponentCrashes(t *testing.T) {
	wd := t.TempDir()
	writeChild(t, wd, "crasher", "#!/bin/sh\necho boom-detail-line\nexit 7\n")

	rec := newExitRecorder()
	s := NewSupervised(Config{WorkDir: wd, OnComponentExit: rec.fn})

	var child *component
	stubBoot(t, func(s *Supervised, ctx context.Context) error {
		c, err := s.spawnEnv(ctx, "crasher", nil)
		if err != nil {
			return err
		}
		s.markSupervised(c) // stands in for the component's own readiness gate
		child = c
		return nil
	})

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	select {
	case <-rec.fired:
	case <-time.After(10 * time.Second):
		t.Fatal("OnComponentExit never fired for a crashed component")
	}
	<-child.exited

	rec.mu.Lock()
	name, path, tail := rec.calls[0], rec.paths[0], rec.tails[0]
	rec.mu.Unlock()
	if name != "crasher" {
		t.Errorf("callback named %q, want %q", name, "crasher")
	}
	// The tail is the operator's only evidence of WHY it died...
	if !strings.Contains(tail, "boom-detail-line") {
		t.Errorf("log tail %q does not carry the child's output", tail)
	}
	// ...and the path is where the operator gets the unredacted original, so the
	// redaction below does not cost them the diagnosis.
	if path != child.logPath {
		t.Errorf("callback got log path %q, want the component's own %q", path, child.logPath)
	}
}

// TestOnComponentExitFiresForACrashWhileALaterComponentComesUp is the window a
// single end-of-bring-up flag leaves open, and the reason supervision is marked
// per component.
//
// bringUp awaits kine -> apiserver -> scheduler -> controller-manager in
// sequence. A scheduler that dies after its own port opens, while the
// controller-manager is still coming up, is a crash — but with one global flag
// set after the whole sequence, the reaper reads false and reports it to nobody:
// the same silent wedge, in a narrower window. The later component's bring-up is
// delay-injected here to hold that window open long enough that the reaper cannot
// miss it.
func TestOnComponentExitFiresForACrashWhileALaterComponentComesUp(t *testing.T) {
	wd := t.TempDir()
	writeChild(t, wd, "early", "#!/bin/sh\necho early-boom\nexit 9\n")
	writeChild(t, wd, "late", "#!/bin/sh\nsleep 30\n")

	rec := newExitRecorder()
	s := NewSupervised(Config{WorkDir: wd, OnComponentExit: rec.fn})

	var early *component
	stubBoot(t, func(s *Supervised, ctx context.Context) error {
		c, err := s.spawnEnv(ctx, "early", nil)
		if err != nil {
			return err
		}
		early = c
		// "early" has passed its own readiness gate. Everything after this point
		// is the window under test.
		s.markSupervised(c)
		<-c.exited // it dies immediately, mid-sequence

		// The LATER component is still coming up. Bring-up has not returned, so
		// no end-of-sequence flip has happened or will happen before the crash
		// must be reported.
		if _, err := s.spawnEnv(ctx, "late", nil); err != nil {
			return err
		}
		select {
		case <-rec.fired:
		case <-time.After(10 * time.Second):
		}
		return nil
	})

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	if n := rec.count(); n == 0 {
		t.Fatal("OnComponentExit never fired for a component that crashed while a later one was still coming up — " +
			"the post-bring-up window is still open")
	}
	rec.mu.Lock()
	name, tail := rec.calls[0], rec.tails[0]
	rec.mu.Unlock()
	if name != "early" {
		t.Errorf("callback named %q, want %q", name, "early")
	}
	if !strings.Contains(tail, "early-boom") {
		t.Errorf("log tail %q does not carry the crashed component's output", tail)
	}
	<-early.exited
}

// TestStartAndAwaitListeningMarksTheComponentSupervised pins the marking on the
// production path the two late components (scheduler, controller-manager) take,
// by calling the real startAndAwaitListening.
//
// The listener is opened by the TEST, from inside the start seam — after the
// preflight has confirmed the port free, which is the order production runs in
// and the only order the preflight allows. Who binds the port is not what is
// under test; startAndAwaitListening's contract is "the port accepts a
// connection", and what is under test is that passing that gate marks the
// component.
func TestStartAndAwaitListeningMarksTheComponentSupervised(t *testing.T) {
	wd := t.TempDir()
	writeChild(t, wd, "listener", "#!/bin/sh\nsleep 30\n")

	// A port that is free NOW, so the preflight passes.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	s := NewSupervised(Config{WorkDir: wd})
	ctx := context.Background()
	defer func() { _ = s.Stop(ctx) }()

	var got *component
	start := func(ctx context.Context) (*component, error) {
		c, err := s.spawnEnv(ctx, "listener", nil)
		if err != nil {
			return nil, err
		}
		got = c
		// Satisfy the readiness gate the same way a real component would: by
		// making 127.0.0.1:port accept.
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = ln.Close() })
		return c, nil
	}

	if err := s.startAndAwaitListening(ctx, "listener", start, port); err != nil {
		t.Fatalf("startAndAwaitListening: %v", err)
	}
	if got == nil {
		t.Fatal("the start seam was never called")
	}

	s.mu.Lock()
	supervised := got.supervised
	s.mu.Unlock()
	if !supervised {
		t.Error("startAndAwaitListening returned without marking the component supervised; its crash would be reported to nobody " +
			"until the whole bring-up sequence finished")
	}
}

// TestBringUpMarksEachComponentBeforeStartingTheNext is the structural guard on
// the ORDER, read from the source because bringUp spawns real control-plane
// binaries and no unit test can call it.
//
// The invariant: within bringUp, no component start may appear while the
// previously started one is still unmarked. A refactor that moved the marks back
// to a single flip after the sequence would reopen the window and every dynamic
// test above would still pass, because they mark by hand.
//
// startAndAwaitListening counts as start-and-mark: it does both, and
// TestStartAndAwaitListeningMarksTheComponentSupervised proves the mark.
func TestBringUpMarksEachComponentBeforeStartingTheNext(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "supervised.go", nil, 0)
	if err != nil {
		t.Fatalf("parse supervised.go: %v", err)
	}
	var bringUpDecl *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv != nil && fn.Name.Name == "bringUp" {
			bringUpDecl = fn
		}
	}
	if bringUpDecl == nil {
		t.Fatal("supervised.go declares no (*Supervised).bringUp method")
	}

	// The calls that start a component, and the call that marks one. Ordered by
	// source position, which is sound here: bringUp is a straight-line sequence
	// with no loop or branch that could run them out of textual order.
	starts := map[string]bool{"startKine": true, "startAPIServer": true}
	type step struct {
		kind string // "start" | "mark" | "start+mark"
		name string
		pos  token.Pos
	}
	var steps []step
	ast.Inspect(bringUpDecl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch {
		case starts[sel.Sel.Name]:
			steps = append(steps, step{"start", sel.Sel.Name, call.Pos()})
		case sel.Sel.Name == "markSupervised":
			steps = append(steps, step{"mark", sel.Sel.Name, call.Pos()})
		case sel.Sel.Name == "startAndAwaitListening":
			steps = append(steps, step{"start+mark", sel.Sel.Name, call.Pos()})
		}
		return true
	})
	if len(steps) == 0 {
		t.Fatal("bringUp starts no components — this test no longer reads what it thinks it does")
	}

	pending := ""
	for _, st := range steps {
		switch st.kind {
		case "start":
			if pending != "" {
				t.Errorf("bringUp starts %s at %s while %s is still unmarked — a %s that crashes here is reported to nobody",
					st.name, fset.Position(st.pos), pending, pending)
			}
			pending = st.name
		case "mark":
			pending = ""
		case "start+mark":
			if pending != "" {
				t.Errorf("bringUp calls %s at %s while %s is still unmarked — a %s that crashes here is reported to nobody",
					st.name, fset.Position(st.pos), pending, pending)
			}
		}
	}
	if pending != "" {
		t.Errorf("bringUp returns with %s never marked supervised; its crash would be reported only by the end-of-bring-up backstop", pending)
	}
}

// TestOnComponentExitStaysSilentDuringStop is the false-positive case. Stop
// clears both gates under mu strictly BEFORE it signals any child, so a
// deliberate teardown must produce no callback at all — otherwise every clean
// shutdown would look like a crash and the server would cancel its own context
// while already shutting down.
func TestOnComponentExitStaysSilentDuringStop(t *testing.T) {
	wd := t.TempDir()
	writeChild(t, wd, "sleeper", "#!/bin/sh\nsleep 30\n")

	rec := newExitRecorder()
	s := NewSupervised(Config{WorkDir: wd, OnComponentExit: rec.fn})

	var comps []*component
	stubBoot(t, func(s *Supervised, ctx context.Context) error {
		for range 3 {
			c, err := s.spawnEnv(ctx, "sleeper", nil)
			if err != nil {
				return err
			}
			s.markSupervised(c) // all three are up, as after a real bring-up
			comps = append(comps, c)
		}
		return nil
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for _, c := range comps {
		<-c.exited // every reaper has run and taken its decision
	}
	// A second Stop must not resurrect the callback either.
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("OnComponentExit fired %d times during a deliberate Stop, want 0", n)
	}
}

// TestOnComponentExitStaysSilentDuringBringUp is the other false-positive case,
// and the reason supervision is a flag of its own rather than `started`. Start
// claims started BEFORE bring-up, so gating on started would fire here — and
// cancelling the boot context from under supervisedBringUp would make
// awaitHealthy's select race ctx.Done() against exited, returning a bare context
// error instead of the component name and log tail the fail-fast path exists to
// produce.
//
// A component that has NOT yet passed its own readiness gate is unmarked, which
// is exactly this case: the crash is bring-up's to report, not the callback's.
func TestOnComponentExitStaysSilentDuringBringUp(t *testing.T) {
	wd := t.TempDir()
	writeChild(t, wd, "crasher", "#!/bin/sh\nexit 3\n")

	rec := newExitRecorder()
	s := NewSupervised(Config{WorkDir: wd, OnComponentExit: rec.fn})

	var child *component
	stubBoot(t, func(s *Supervised, ctx context.Context) error {
		c, err := s.spawnEnv(ctx, "crasher", nil)
		if err != nil {
			return err
		}
		child = c
		// NO markSupervised: this component never came up. It dies while
		// bring-up is still running.
		<-c.exited
		// Hold bring-up OPEN past the reaper's decision. Waiting on the reapers
		// rather than on a clock is what makes this test discriminate AND cheap:
		// without the wait, a build that gated on `started` could pass by losing
		// the race with Start's failure path, which calls Stop and clears it.
		s.reapers.Wait()
		return context.DeadlineExceeded
	})

	if err := s.Start(context.Background()); err == nil {
		t.Fatal("Start: want the bring-up error, got nil")
	}
	<-child.exited

	if n := rec.count(); n != 0 {
		t.Fatalf("OnComponentExit fired %d times for a bring-up failure, want 0 "+
			"(supervisedBringUp already reports those, with the log tail)", n)
	}
}
