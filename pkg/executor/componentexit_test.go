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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// OnComponentExit is the supervision seam: before it, the per-component reapers
// were the only observers of a child's death and their only readers were
// awaitHealthy (bring-up) and stopComponent (teardown), so a control-plane
// component that died AFTER bring-up was reported to nobody. These tests pin the
// three cases that decide whether the seam is safe to act on — it must fire on a
// crash, and must stay silent for both kinds of non-crash exit, because the
// server cancels its root context from this callback.

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
	tails []string
	fired chan struct{}
	once  sync.Once
}

func newExitRecorder() *exitRecorder {
	return &exitRecorder{fired: make(chan struct{})}
}

func (r *exitRecorder) fn(name string, _ error, logTail string) {
	r.mu.Lock()
	r.calls = append(r.calls, name)
	r.tails = append(r.tails, logTail)
	r.mu.Unlock()
	r.once.Do(func() { close(r.fired) })
}

func (r *exitRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// stubBoot points Start's two phase seams at fn, restoring them afterwards.
func stubBoot(t *testing.T, bringUp func(*Supervised, context.Context) error) {
	t.Helper()
	origProvision, origBringUp := supervisedProvision, supervisedBringUp
	t.Cleanup(func() { supervisedProvision, supervisedBringUp = origProvision, origBringUp })
	supervisedProvision = func(*Supervised, context.Context) error { return nil }
	supervisedBringUp = bringUp
}

// TestOnComponentExitFiresWhenAComponentCrashes is the case the seam exists for:
// bring-up succeeded, then a child died on its own.
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
	name, tail := rec.calls[0], rec.tails[0]
	rec.mu.Unlock()
	if name != "crasher" {
		t.Errorf("callback named %q, want %q", name, "crasher")
	}
	// The tail is the operator's only evidence of WHY it died.
	if !strings.Contains(tail, "boom-detail-line") {
		t.Errorf("log tail %q does not carry the child's output", tail)
	}
}

// TestOnComponentExitStaysSilentDuringStop is the false-positive case. Stop
// clears supervising under mu strictly BEFORE it signals any child, so a
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
// and the reason supervising is a separate flag from started. Start claims
// started BEFORE bring-up, so gating on started would fire here — and cancelling
// the boot context from under supervisedBringUp would make awaitHealthy's select
// race ctx.Done() against exited, returning a bare context error instead of the
// component name and log tail the fail-fast path exists to produce.
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
		<-c.exited // the child dies while bring-up is still running
		// Hold bring-up OPEN after the exit. Without this the test does not
		// discriminate: Start's failure path calls Stop, which clears started,
		// and the reaper's flag read would simply lose that race — so a build
		// gating on started passes by luck. Staying here keeps started true for
		// a window the reaper cannot miss, which is precisely the production
		// window a bring-up crash occupies.
		select {
		case <-rec.fired:
			// The callback fired during bring-up. Return promptly; the
			// assertion below reports it.
		case <-time.After(2 * time.Second):
		}
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
