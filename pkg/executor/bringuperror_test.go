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
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A bring-up failure is the ONLY failure `k3sm server` cannot attribute: a
// component that crashes after bring-up arrives at OnComponentExit with its
// name, but everything that goes wrong before the mark returns from Start as a
// wrapped string the daemon can read and not classify. BringUpError is that
// classification, and these tests pin the two properties the daemon depends on:
// errors.As recovers the component at every site, and the message an operator
// reads is byte-identical to the one the site already produced.

// deadChild writes an executable that prints one line and dies, under the bin
// dir the spawner resolves children from.
func deadChild(t *testing.T, wd, name string) {
	t.Helper()
	if err := os.MkdirAll(binDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho '" + name + " is not going to come up'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir(wd), name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestBringUpErrorNamesTheComponentAtEverySite(t *testing.T) {
	cases := []struct {
		name string
		// run drives the REAL site and returns its error; the work dir is the
		// test's own, so nothing outside it is touched.
		run           func(t *testing.T, wd string) error
		wantComponent string
		wantPhase     string
		wantText      string
	}{
		{
			name: "provision cannot make the work dirs",
			run: func(t *testing.T, wd string) error {
				// A work dir UNDER a regular file: ensureWorkDirs fails on the
				// first mkdir, which is provision's first step.
				blocked := filepath.Join(wd, "file")
				if err := os.WriteFile(blocked, []byte("not a dir"), 0o600); err != nil {
					t.Fatal(err)
				}
				s := NewSupervised(Config{WorkDir: filepath.Join(blocked, "server")})
				return s.provision(context.Background())
			},
			wantComponent: "provision/workdirs",
			wantPhase:     PhaseProvision,
		},
		{
			name: "kine will not spawn",
			run: func(t *testing.T, wd string) error {
				// No bin dir at all: the spawn of the kine child fails outright.
				s := NewSupervised(Config{WorkDir: wd, KinePort: freePort(t)})
				return s.bringUp(context.Background())
			},
			wantComponent: "kine",
			wantPhase:     PhaseBringUp,
			wantText:      "start kine: ",
		},
		{
			name: "kine dies before it listens",
			run: func(t *testing.T, wd string) error {
				deadChild(t, wd, "kine")
				s := NewSupervised(Config{WorkDir: wd, KinePort: freePort(t)})
				defer func() { _ = s.Stop(context.Background()) }()
				return s.bringUp(context.Background())
			},
			wantComponent: "kine",
			wantPhase:     PhaseBringUp,
			wantText:      "kine not listening: ",
		},
		{
			name: "a component dies between its readiness gate and its mark",
			run: func(t *testing.T, wd string) error {
				deadChild(t, wd, "crasher")
				s := NewSupervised(Config{WorkDir: wd})
				defer func() { _ = s.Stop(context.Background()) }()
				c, err := s.spawnEnv(context.Background(), "crasher", nil)
				if err != nil {
					t.Fatal(err)
				}
				<-c.exited // the window markSupervised closes
				return s.markSupervised(c)
			},
			wantComponent: "crasher",
			wantPhase:     PhaseBringUp,
			wantText:      "exited during bring-up",
		},
		{
			name: "another control plane already holds the component's port",
			run: func(t *testing.T, wd string) error {
				held, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
				port, err := strconv.Atoi(strings.TrimPrefix(held.Addr().String(), "127.0.0.1:"))
				if err != nil {
					t.Fatal(err)
				}
				s := NewSupervised(Config{WorkDir: wd})
				return s.startAndAwaitListening(context.Background(), "scheduler", s.startScheduler, port)
			},
			wantComponent: "scheduler",
			wantPhase:     PhaseBringUp,
		},
		{
			name: "the scheduler will not spawn",
			run: func(t *testing.T, wd string) error {
				s := NewSupervised(Config{WorkDir: wd})
				return s.startAndAwaitListening(context.Background(), "scheduler", s.startScheduler, freePort(t))
			},
			wantComponent: "scheduler",
			wantPhase:     PhaseBringUp,
			wantText:      "start scheduler: ",
		},
		{
			name: "the controller-manager dies before its port opens",
			run: func(t *testing.T, wd string) error {
				deadChild(t, wd, "kube-controller-manager")
				s := NewSupervised(Config{WorkDir: wd})
				defer func() { _ = s.Stop(context.Background()) }()
				return s.startAndAwaitListening(context.Background(), "controller-manager", s.startControllerManager, freePort(t))
			},
			// The component's OWN name, the one OnComponentExit would report —
			// not the short label the argv uses.
			wantComponent: "kube-controller-manager",
			wantPhase:     PhaseBringUp,
			wantText:      "kube-controller-manager not serving on 127.0.0.1:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t, t.TempDir())
			if err == nil {
				t.Fatal("the site returned nil; it must fail for this test to say anything")
			}
			var bu *BringUpError
			if !errors.As(err, &bu) {
				t.Fatalf("error %q is not a *BringUpError — the daemon cannot record WHICH component never came up", err)
			}
			if bu.Component != tc.wantComponent {
				t.Errorf("component %q, want %q", bu.Component, tc.wantComponent)
			}
			if bu.Phase != tc.wantPhase {
				t.Errorf("phase %q, want %q", bu.Phase, tc.wantPhase)
			}
			// The classification adds structure and NOTHING to the text: the
			// message is the one the site already produced, including its
			// redacted log tail.
			if bu.Error() != bu.Err.Error() {
				t.Errorf("BringUpError.Error() = %q, want the wrapped text %q unchanged", bu.Error(), bu.Err.Error())
			}
			if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error %q lost the site's own text %q", err, tc.wantText)
			}
		})
	}
}

// A nil error stays nil through the classifiers: a non-nil interface holding a
// nil *BringUpError would turn every successful step into a failure.
func TestBringUpErrIsNilForSuccess(t *testing.T) {
	if err := bringUpErr("kine", PhaseBringUp, nil); err != nil {
		t.Errorf("bringUpErr wrapped a nil error into %v", err)
	}
	if err := provisionStep("workdirs", nil); err != nil {
		t.Errorf("provisionStep wrapped a nil error into %v", err)
	}
	// And the chain survives, so errors.Is on a sentinel still works through it.
	sentinel := errors.New("boom")
	if err := bringUpErr("kine", PhaseBringUp, fmt.Errorf("start kine: %w", sentinel)); !errors.Is(err, sentinel) {
		t.Errorf("errors.Is lost the wrapped sentinel through the classification")
	}
}

// TestEveryBringUpReturnIsClassified is the structural half, and it is what
// keeps the table above from going stale: the apiserver's two sites and eight of
// provision's ten steps cannot be driven hermetically (they need a real kine, a
// real kube binary, a signing toolchain), so a new unclassified return there
// would be invisible to a behavioural test.
//
// It is deliberately FAIL-CLOSED on shapes it does not recognise. An earlier
// version keyed on two specific statement forms and silently passed everything
// else — an `err` assigned above the if, a two-statement branch, a named return —
// which is the failure mode a structural gate must not have: the shapes it
// cannot classify are exactly the ones a future edit is most likely to
// introduce. So the rule is now total over the four functions: EVERY return
// statement must be all-nil, or must mention one of the classifiers by name, or
// must be a bare `return err` whose err came from the init of an `if` calling a
// helper that classifies for itself. Anything else is named with its line and
// fails.
func TestEveryBringUpReturnIsClassified(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "supervised.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The classifiers themselves, and the two helpers that classify their own
	// errors — so a `return err` off one of those is already attributed.
	classifier := map[string]bool{"bringUpErr": true, "provisionStep": true, "BringUpError": true}
	selfClassifying := map[string]bool{
		"bringUpErr": true, "provisionStep": true,
		"markSupervised": true, "startAndAwaitListening": true,
	}
	name := func(e ast.Expr) string {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			return v.Sel.Name
		}
		return ""
	}
	scoped := map[string]bool{"provision": true, "bringUp": true, "startAndAwaitListening": true, "markSupervised": true}
	seen := map[string]bool{}
	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !scoped[fn.Name.Name] {
			continue
		}
		seen[fn.Name.Name] = true

		// Pass 1: the returns that a classifying if-init has already attributed.
		attributed := map[ast.Node]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifStmt, isIf := n.(*ast.IfStmt)
			if !isIf {
				return true
			}
			assign, isAssign := ifStmt.Init.(*ast.AssignStmt)
			if !isAssign || len(assign.Rhs) != 1 {
				return true
			}
			call, isCall := assign.Rhs[0].(*ast.CallExpr)
			if !isCall || !selfClassifying[name(call.Fun)] {
				return true
			}
			ast.Inspect(ifStmt.Body, func(inner ast.Node) bool {
				if ret, isRet := inner.(*ast.ReturnStmt); isRet {
					attributed[ret] = true
				}
				return true
			})
			return true
		})

		// Pass 2: every return, no exceptions.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ret, isRet := n.(*ast.ReturnStmt)
			if !isRet {
				return true
			}
			checked++
			line := fset.Position(ret.Pos()).Line
			allNil := len(ret.Results) > 0
			mentions := false
			for _, r := range ret.Results {
				if id, isIdent := r.(*ast.Ident); !isIdent || id.Name != "nil" {
					allNil = false
				}
				ast.Inspect(r, func(inner ast.Node) bool {
					switch v := inner.(type) {
					case *ast.Ident:
						if classifier[v.Name] {
							mentions = true
						}
					case *ast.SelectorExpr:
						if classifier[v.Sel.Name] {
							mentions = true
						}
					}
					return true
				})
			}
			if allNil || mentions {
				return true
			}
			if isBareErr(ret) && attributed[ret] {
				return true
			}
			t.Errorf("%s: the return at line %d is neither nil nor classified — wrap its error in bringUpErr/provisionStep so the daemon can name the component that failed (a bare `return err` is allowed only straight off markSupervised or startAndAwaitListening, which classify for themselves)",
				fn.Name.Name, line)
			return true
		})
	}
	for fname := range scoped {
		if !seen[fname] {
			t.Errorf("%s is no longer in supervised.go; this gate has stopped checking it", fname)
		}
	}
	// Non-vacuity: the four functions between them have well over a dozen
	// returns, so a rule that inspected none of them would be a green no-op.
	if checked < 15 {
		t.Errorf("the gate inspected only %d return statements across %v; it is not reading what it claims to", checked, scoped)
	}
}

// isBareErr reports whether a return statement is exactly `return err`.
func isBareErr(ret *ast.ReturnStmt) bool {
	if len(ret.Results) != 1 {
		return false
	}
	id, ok := ret.Results[0].(*ast.Ident)
	return ok && id.Name == "err"
}
