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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestBringUpFailureRecordsOnTheCrashLoopBreaker is the gate for the hole the
// breaker shipped with: it counted only what OnComponentExit reported, which is
// a component that came up and LATER died. Every other way a control plane can
// fail — kine that cannot open its database, an apiserver whose flags no longer
// parse, a provision step that cannot write — returns from executor.Start, exits
// the daemon 1, and is respawned by the server plist's bare KeepAlive, with no
// throttle and no give-up. So a persistent bring-up fault restart-looped
// forever while `k3sm install` was satisfied by any resident pid.
//
// The failure driven here is a REAL executor.Supervised Start against a work dir
// it cannot create (the parent path is a regular file): the real provision
// phase, the real BringUpError, and the real recording function runServer calls.
func TestBringUpFailureRecordsOnTheCrashLoopBreaker(t *testing.T) {
	// The breaker's record lives beside the control plane's state, so it gets a
	// work dir of its own — the failing one is deliberately unusable.
	recordDir := t.TempDir()
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	failingWorkDir := filepath.Join(blocked, "server")

	var callbackFired atomic.Int32
	// One boot: a real Start failure, recorded through the real path.
	boot := func(t *testing.T) {
		t.Helper()
		exec := executor.NewSupervised(executor.Config{
			WorkDir: failingWorkDir,
			OnComponentExit: func(string, error, string, string) {
				callbackFired.Add(1)
			},
		})
		err := exec.Start(context.Background())
		if err == nil {
			t.Fatal("Start must fail against a work dir it cannot create")
		}
		noteBringUpFailure(newCrashBreaker(recordDir, quietLogger()), quietLogger(), err)
	}

	boot(t)

	rec, err := executor.ReadCrashRecord(executor.CrashLoopPath(recordDir))
	if err != nil {
		t.Fatalf("read the record after a failed bring-up: %v", err)
	}
	if len(rec.Crashes) != 1 {
		t.Fatalf("a failed bring-up wrote %d record entries, want exactly 1: %+v", len(rec.Crashes), rec.Crashes)
	}
	last, _ := rec.Last()
	if last.Origin != executor.CrashOriginBringUp {
		t.Errorf("origin %q, want %q — a park message that calls this a crash sends the operator to the wrong part of the log",
			last.Origin, executor.CrashOriginBringUp)
	}
	if last.Component != "provision/workdirs" {
		t.Errorf("component %q, want %q — the record must name what failed, not the daemon", last.Component, "provision/workdirs")
	}
	if !strings.Contains(last.Detail, failingWorkDir) {
		t.Errorf("detail %q does not carry the bring-up error text", last.Detail)
	}
	if rec.Tripped() {
		t.Error("one bring-up failure tripped the breaker")
	}

	// The two record sites are exclusive: nothing was ever marked supervised, so
	// the component-exit callback has nothing to report and must stay silent —
	// firing it here would double-count the same failure.
	if n := callbackFired.Load(); n != 0 {
		t.Errorf("OnComponentExit fired %d times during a bring-up failure; Start already reported it", n)
	}

	// The loop: the same fault, one boot per launchd respawn, until the breaker
	// gives up.
	for i := 1; i < executor.CrashLoopThreshold; i++ {
		boot(t)
	}
	rec, err = executor.ReadCrashRecord(executor.CrashLoopPath(recordDir))
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Tripped() {
		t.Fatalf("%d identical bring-up failures did not trip the breaker: %+v", executor.CrashLoopThreshold, rec)
	}
	last, _ = rec.Last()
	msg := parkReason(last)
	if !strings.Contains(msg, "never came up") || !strings.Contains(msg, last.Component) {
		t.Errorf("park message %q must say the control plane never came up and name %q", msg, last.Component)
	}
}

// TestRunServerRecordsABringUpFailure pins the WIRING the test above exercises:
// runServer's exec.Start failure branch records on the breaker before it returns.
// Without this the recording function could sit in the package unused while the
// daemon restart-looped exactly as it did before.
func TestRunServerRecordsABringUpFailure(t *testing.T) {
	fset, body := runServerBody(t)
	var startPos, notePos, returnPos int
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || !isExecStartInit(ifStmt.Init) {
			return true
		}
		startPos = fset.Position(ifStmt.Pos()).Line
		ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.CallExpr:
				if id, isIdent := stmt.Fun.(*ast.Ident); isIdent && id.Name == "noteBringUpFailure" && notePos == 0 {
					notePos = fset.Position(stmt.Pos()).Line
				}
			case *ast.ReturnStmt:
				if returnPos == 0 {
					returnPos = fset.Position(stmt.Pos()).Line
				}
			}
			return true
		})
		return false
	})
	if startPos == 0 {
		t.Fatal("runServer no longer has an `if err := exec.Start(ctx); err != nil` branch; this gate has stopped checking anything")
	}
	if notePos == 0 {
		t.Fatalf("runServer's exec.Start failure branch at line %d does not call noteBringUpFailure: a control plane that never comes up is counted nowhere, so launchd respawns it forever", startPos)
	}
	if returnPos == 0 || notePos > returnPos {
		t.Errorf("noteBringUpFailure at line %d must run before the branch returns at line %d", notePos, returnPos)
	}
}

// isExecStartInit reports whether an if-statement's init is `err := exec.Start(...)`.
func isExecStartInit(init ast.Stmt) bool {
	assign, ok := init.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Start" {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	return ok && recv.Name == "exec"
}
