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
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestRunServerWiresTheComponentExitSeam is the WIRING gate for control-plane
// crash reporting, and it reads the source rather than running it.
//
// runServer boots a real control plane, so no unit test can call it — and this
// repo's recurring defect class is precisely a well-tested helper that bring-up
// never calls (B195, B209). pkg/executor's tests prove the seam works; nothing
// but this proves runServer still uses it. Three things are asserted, each of
// which a plausible refactor breaks while leaving every other test green:
//
//  1. cfg.OnComponentExit is assigned at all. Without it a component that dies
//     at hour six leaves this process alive, launchd's KeepAlive (a plain bool,
//     so a restart-on-EXIT policy) never fires, and the cluster stays wedged
//     while `k3sm status` reports the daemon up.
//
//  2. The assignment appears BEFORE executor.NewSupervised. Config is passed by
//     VALUE, so an assignment moved after that call mutates a dead copy: the
//     feature would be silently and completely off, with the code still reading
//     as if it were on. This is the sharp edge, which is why it is pinned to
//     NewSupervised and not merely to exec.Start.
//
//  3. runServer names its error result and defers the crash check onto it. The
//     check has to be a defer over a named return because a crash cancels the
//     root context and the error that then reaches the exit line depends on
//     where bring-up had got to — startNode returns nil on a cancelled context,
//     which is right for a signal and wrong for a crash. A refactor back to a
//     single check at the bottom would restore the bare "context canceled" exits
//     on every earlier path.
//
// Source position is a sound proxy for order here: the assignment and the
// NewSupervised call both sit in runServer's straight-line bring-up sequence,
// with no loop or branch that could execute them out of textual order.
func TestRunServerWiresTheComponentExitSeam(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	var runServerDecl *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "runServer" {
			runServerDecl = fn
		}
	}
	if runServerDecl == nil {
		t.Fatal("server.go declares no runServer function")
	}

	// (1) + (2): the assignment exists, and precedes the by-value Config copy.
	var assignPos, newSupervisedPos token.Pos
	ast.Inspect(runServerDecl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "OnComponentExit" {
					continue
				}
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "cfg" && !assignPos.IsValid() {
					assignPos = node.Pos()
				}
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewSupervised" || newSupervisedPos.IsValid() {
				return true
			}
			newSupervisedPos = node.Pos()
		}
		return true
	})

	if !assignPos.IsValid() {
		t.Fatal("runServer never assigns cfg.OnComponentExit — a control-plane child that dies after bring-up is reported to nobody, " +
			"launchd's KeepAlive never fires, and the cluster stays wedged while the daemon looks healthy")
	}
	if !newSupervisedPos.IsValid() {
		t.Fatal("runServer never calls executor.NewSupervised — this test no longer reads what it thinks it does")
	}
	if assignPos >= newSupervisedPos {
		t.Errorf("runServer assigns cfg.OnComponentExit at %s, NOT before executor.NewSupervised at %s — "+
			"Config is passed by VALUE, so this assignment mutates a copy the executor never sees and the feature is entirely off",
			fset.Position(assignPos), fset.Position(newSupervisedPos))
	}

	// (3a): the error result is named, which is what lets a defer rewrite it.
	named := false
	if res := runServerDecl.Type.Results; res != nil {
		for _, f := range res.List {
			if len(f.Names) > 0 {
				named = true
			}
		}
	}
	if !named {
		t.Error("runServer's error result is not named, so no defer can name the crashed component on it; " +
			"every crash before startNode would exit with a bare \"context canceled\"")
	}

	// (3b): a deferred closure reads crashedComponent and assigns to the result.
	deferred := false
	ast.Inspect(runServerDecl.Body, func(n ast.Node) bool {
		d, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		lit, ok := d.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		reads, writes := false, false
		ast.Inspect(lit.Body, func(m ast.Node) bool {
			switch node := m.(type) {
			case *ast.Ident:
				if node.Name == "crashedComponent" {
					reads = true
				}
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "err" {
						writes = true
					}
				}
			}
			return true
		})
		if reads && writes {
			deferred = true
		}
		return true
	})
	if !deferred {
		t.Error("runServer has no deferred closure that reads crashedComponent and rewrites err — " +
			"a crash during provisioning, or one that startNode swallows on a cancelled context, would exit 0 or unnamed")
	}
}
