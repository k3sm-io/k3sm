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
	"go/ast"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// TestAgentTerminalRecordsBeforeItBacksOff pins the ordering the installer
// depends on.
//
// `k3sm agent` backs off for half a minute between terminal start attempts, and
// `k3sm install` waits one join budget for the node to appear. A failure
// recorded AFTER the sleep would land after the install had already given up,
// with nothing to say about why — which is the state the 2026-09-17 install was
// in when it announced a join that had not happened. So the record is written
// first, and this test reads it while the backoff is still running.
func TestAgentTerminalRecordsBeforeItBacksOff(t *testing.T) {
	dir := t.TempDir()
	b := newCrashBreaker(dir, quietLogger())
	orig := agentTerminalDelay
	agentTerminalDelay = 2 * time.Second
	t.Cleanup(func() { agentTerminalDelay = orig })

	// A start error carrying a credential, because an agent's errors are this
	// command's own text rather than something pkg/executor already redacted.
	want := errors.New("persist node-password: permission denied (token K10deadbeefdeadbeef::node:s3cr3t)")
	done := make(chan error, 1)
	go func() { done <- agentTerminal(context.Background(), b, quietLogger(), want) }()

	path := executor.CrashLoopPath(dir)
	var rec executor.CrashRecord
	deadline := time.Now().Add(time.Second)
	for {
		r, err := executor.ReadCrashRecord(path)
		if err == nil && len(r.Crashes) > 0 {
			rec = r
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing was recorded at %s while the agent was still backing off; an installer polling the record would time out with no reason to report", path)
		}
		time.Sleep(5 * time.Millisecond)
	}

	got := rec.Crashes[0]
	if got.Origin != executor.CrashOriginBringUp {
		t.Errorf("recorded origin = %q, want %q — a worker that never joined never came up; it did not crash", got.Origin, executor.CrashOriginBringUp)
	}
	if got.Component != agentComponent {
		t.Errorf("recorded component = %q, want %q", got.Component, agentComponent)
	}
	if !strings.Contains(got.Detail, "permission denied") {
		t.Errorf("recorded detail %q does not carry the reason; the installer quotes this line to the operator", got.Detail)
	}
	if strings.Contains(got.Detail, "s3cr3t") || strings.Contains(got.Detail, "K10deadbeefdeadbeef") {
		t.Errorf("the recorded detail carries the join token: %q", got.Detail)
	}
	if rec.Tripped() {
		t.Error("one start failure tripped the record; the agent counts under the same threshold the server does")
	}

	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Errorf("agentTerminal returned %v, want the error it was given", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agentTerminal never returned")
	}
}

// TestRunAgentRecordsEveryStartFailure is the structural half: runAgent cannot
// be called from a unit test (it boots a real node), but the property that
// matters is that EVERY start failure reaches the record — not only the ones
// that happen to pass through agentTerminal. The 2026-09-17 fault ("persist
// node-password: permission denied") was on one of the paths that does not.
//
// So the wiring is asserted where it lives: runAgent delegates its body to
// agentStart and records whatever comes back that has not already been counted.
func TestRunAgentRecordsEveryStartFailure(t *testing.T) {
	body := funcBodyInFile(t, "agent.go", "runAgent")
	var callsAgentStart, callsNote, guardsOnNoted bool
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			switch fn.Name {
			case "agentStart":
				callsAgentStart = true
			case "noteAgentStartFailure":
				callsNote = true
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == "noted" {
				guardsOnNoted = true
			}
		}
		return true
	})
	if !callsAgentStart {
		t.Error("runAgent does not call agentStart: without one funnel a new start-failure path is one nobody counts")
	}
	if !callsNote {
		t.Error("runAgent does not call noteAgentStartFailure: a start failure that reaches no record is invisible to `k3sm install`")
	}
	if !guardsOnNoted {
		t.Error("runAgent does not consult the breaker's noted(): a terminal failure recorded before its backoff would be counted a second time on the way out")
	}
}
