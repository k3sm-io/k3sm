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
	"flag"
	"go/ast"
	"os"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// The park is the give-up, and it has exactly two exits: the operator cleared
// the marker, or launchd told the process to stop. Both return nil, because under
// a bare KeepAlive any exit status is the same respawn.
func TestParkUntilClearedExitsWhenTheMarkerIsRemoved(t *testing.T) {
	path := executor.CrashLoopPath(t.TempDir())
	if err := executor.WriteCrashRecord(path, executor.CrashRecord{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- parkUntilCleared(context.Background(), path, 10*time.Millisecond, quietLogger()) }()
	select {
	case err := <-done:
		t.Fatalf("park returned %v while the marker was still present", err)
	case <-time.After(60 * time.Millisecond):
	}
	if err := executor.ClearCrashRecord(path); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("park returned %v after the clear, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("park did not notice the cleared marker")
	}
}

func TestParkUntilClearedExitsOnStop(t *testing.T) {
	path := executor.CrashLoopPath(t.TempDir())
	if err := executor.WriteCrashRecord(path, executor.CrashRecord{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- parkUntilCleared(ctx, path, time.Hour, quietLogger()) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("park returned %v on stop, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("park did not return on a cancelled context")
	}
}

// The breaker's two writers are ordered by its mutex; the healthy-window reset
// must never erase a crash that landed first, and a clean run must clear.
func TestCrashBreakerResetNeverErasesARecordedCrash(t *testing.T) {
	dir := t.TempDir()
	b := newCrashBreaker(dir, quietLogger())
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }

	if b.record("kine", "redacted tail") {
		t.Fatal("one crash tripped the breaker")
	}
	b.resetIfHealthy()
	r, err := executor.ReadCrashRecord(b.path)
	if err != nil || len(r.Crashes) != 1 {
		t.Fatalf("reset after a crash erased the record: %+v %v", r, err)
	}

	// A fresh process that saw no crash clears.
	c := newCrashBreaker(dir, quietLogger())
	c.resetIfHealthy()
	if _, err := os.Stat(c.path); !os.IsNotExist(err) {
		t.Fatal("a healthy process did not clear the record")
	}
}

func TestCrashBreakerTripsAndTheNextLoadSeesIt(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tripped := false
	for i := 0; i < executor.CrashLoopThreshold; i++ {
		b := newCrashBreaker(dir, quietLogger()) // one process per crash, as in life
		at := now.Add(time.Duration(i) * time.Minute)
		b.now = func() time.Time { return at }
		if b.record("kube-apiserver", "redacted tail") {
			if i != executor.CrashLoopThreshold-1 {
				t.Fatalf("tripped on crash %d, want %d", i+1, executor.CrashLoopThreshold)
			}
			tripped = true
		}
	}
	if !tripped {
		t.Fatal("never tripped")
	}
	next := newCrashBreaker(dir, quietLogger())
	next.now = func() time.Time { return now.Add(time.Duration(executor.CrashLoopThreshold) * time.Minute) }
	if !next.load().Tripped() {
		t.Fatal("the next start did not see the trip")
	}
}

func TestClearCrashLoopFlagIsRegistered(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var opts serverOptions
	_ = registerServerFlags(fs, &opts)
	if err := fs.Parse([]string{"--clear-crashloop", "--work-dir", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if !opts.clearCrashLoop {
		t.Fatal("--clear-crashloop did not set the option")
	}
}

// The wiring, pinned structurally the way the component-exit seam is: the park
// decision precedes the supervised executor's construction, and the crash
// callback records before it cancels.
func TestRunServerWiresTheCrashLoopBreaker(t *testing.T) {
	fset, body := runServerBody(t)
	var parkPos, newSupervisedPos, recordPos, cancelPos int
	ast.Inspect(body, func(n ast.Node) bool {
		if _, isDefer := n.(*ast.DeferStmt); isDefer {
			return false // `defer crashCancel()` is cleanup, not the crash path
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "parkUntilCleared" && parkPos == 0 {
				parkPos = fset.Position(call.Pos()).Line
			}
			if fn.Name == "crashCancel" && cancelPos == 0 {
				cancelPos = fset.Position(call.Pos()).Line
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == "NewSupervised" && newSupervisedPos == 0 {
				newSupervisedPos = fset.Position(call.Pos()).Line
			}
			if fn.Sel.Name == "record" && recordPos == 0 {
				recordPos = fset.Position(call.Pos()).Line
			}
		}
		return true
	})
	if parkPos == 0 || newSupervisedPos == 0 || parkPos > newSupervisedPos {
		t.Errorf("parkUntilCleared at line %d must precede executor.NewSupervised at line %d: a tripped breaker must never bring the control plane up", parkPos, newSupervisedPos)
	}
	if recordPos == 0 || cancelPos == 0 || recordPos > cancelPos {
		t.Errorf("breaker.record at line %d must precede the first crashCancel at line %d: the crash is counted before the process starts dying", recordPos, cancelPos)
	}
}

// TestRunServerHasOneAnswerOnFatalFaults pins the narrowing that k3sm#344
// asked for: the repo used to say, in two comments and one test, that a fatal
// return under KeepAlive is an unbounded respawn loop — the opposite of what the
// component-exit path does. There is one answer now: unsurvivable faults exit and
// the breaker bounds the loop; survivable ones continue.
func TestRunServerHasOneAnswerOnFatalFaults(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "unbounded respawn") {
		t.Error(`server.go still claims a fatal return is an "unbounded respawn" loop; the crash-loop breaker bounds it — say "unsurvivable faults exit; survivable ones continue"`)
	}
	if n := strings.Count(string(src), "UNSURVIVABLE faults exit"); n < 2 {
		t.Errorf("server.go states the one rule %d times, want it at both log-and-continue sites", n)
	}
}
