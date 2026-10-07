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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// runServer boots a real control plane, so no unit test can call it — and this
// repo's recurring defect class is a well-tested helper bring-up never calls
// (B195, B209), or calls in the wrong order. Its wiring is therefore asserted
// structurally, by reading the source.
//
// runServer is an orchestrator over provisioning and phase helpers declared
// beside it (serverprovision.go, serverphases.go and the rest of the non-test
// server*.go files). A pin that read only runServer's own body would go vacuous
// the moment a call moved into a helper, so every structural pin reads a TRACE
// instead: runServer's body walked in source order, with each call to a
// top-level function declared in a non-test server*.go file expanded IN PLACE —
// its arguments first, then the callee's body, transitively. Each node gets a
// monotonic trace index at its first visit, and order is compared on that index
// rather than on token.Pos, which is meaningless across files.
//
// Trace order is a sound proxy for execution order for the same reason source
// position was: every pinned call sits in a straight-line sequence (runServer's
// own, or a helper's called from it), with no loop that could execute them out
// of order. Pins about runServer's OWN shape — its defers and its named error
// result — read serverTrace.decl directly, never the expanded trace.

// serverTrace is runServer's call-ordered bring-up trace.
type serverTrace struct {
	fset *token.FileSet
	// decl is runServer itself.
	decl *ast.FuncDecl
	// files are the parsed non-test server*.go files, by name.
	files map[string]*ast.File
	// funcs are the top-level, non-method functions those files declare: the
	// helpers a call expands into.
	funcs map[string]*ast.FuncDecl
	// index is each node's trace index at its first visit.
	index map[ast.Node]int
}

// serverSourceFiles lists the non-test server*.go files of this package.
func serverSourceFiles(t *testing.T) []string {
	t.Helper()
	names, err := filepath.Glob("server*.go")
	if err != nil {
		t.Fatalf("glob server*.go: %v", err)
	}
	var out []string
	for _, n := range names {
		if !strings.HasSuffix(n, "_test.go") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no non-test server*.go files; this check would be vacuous")
	}
	return out
}

// serverSources returns the concatenated text of every non-test server*.go file:
// the scope the source-text pins read, so a comment or identifier they look for
// counts wherever the decomposition put it.
func serverSources(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, name := range serverSourceFiles(t) {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.Write(src)
		b.WriteByte('\n')
	}
	return b.String()
}

// runServerTrace parses the non-test server*.go files and returns runServer's
// trace. It fails the test if runServer is not declared.
func runServerTrace(t *testing.T) *serverTrace {
	t.Helper()
	tr := &serverTrace{
		fset:  token.NewFileSet(),
		files: map[string]*ast.File{},
		funcs: map[string]*ast.FuncDecl{},
		index: map[ast.Node]int{},
	}
	for _, name := range serverSourceFiles(t) {
		file, err := parser.ParseFile(tr.fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		tr.files[name] = file
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			tr.funcs[fn.Name.Name] = fn
		}
	}
	tr.decl = tr.funcs["runServer"]
	if tr.decl == nil {
		t.Fatal("no server*.go file declares a runServer function")
	}
	next := 0
	tr.inspect(func(n ast.Node) bool {
		if _, seen := tr.index[n]; !seen {
			tr.index[n] = next
			next++
		}
		return true
	})
	return tr
}

// inspect walks the trace with ast.Inspect semantics: f sees every node in trace
// order, and returning false prunes that node's subtree — including, for a call,
// the expansion of its callee.
//
// The trace is TEXTUAL, not temporal. Where a helper call sits decides where its
// body appears, whatever runs it and whenever:
//   - `defer helper()` expands at the defer statement, the REGISTRATION point,
//     not at function exit when the deferred call actually runs;
//   - `go helper()` expands at the go statement, though the body runs
//     concurrently;
//   - a call inside an `if` arm expands in place, and BOTH arms are walked, in
//     source order, whichever one runs.
//
// So a pin reading the trace may order a deferred, spawned or conditional call
// only where that textual position is the property it means;
// TestRunServerTraceExpandsHelpersInPlace pins each case.
func (tr *serverTrace) inspect(f func(ast.Node) bool) {
	tr.walk(tr.decl.Body, f, map[string]bool{"runServer": true})
}

func (tr *serverTrace) walk(root ast.Node, f func(ast.Node) bool, active map[string]bool) {
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil || !f(n) {
			return false
		}
		callee := tr.callee(n)
		if callee == nil || active[callee.Name.Name] {
			return true
		}
		call := n.(*ast.CallExpr)
		tr.walk(call.Fun, f, active)
		for _, arg := range call.Args {
			tr.walk(arg, f, active)
		}
		active[callee.Name.Name] = true
		tr.walk(callee.Body, f, active)
		delete(active, callee.Name.Name)
		return false
	})
}

// callee returns the helper n calls, or nil when n is not a call to a top-level
// function declared in a non-test server*.go file. A name the parser resolved to
// something other than a function (a local closure such as stop) is not one.
func (tr *serverTrace) callee(n ast.Node) *ast.FuncDecl {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok || (id.Obj != nil && id.Obj.Kind != ast.Fun) {
		return nil
	}
	return tr.funcs[id.Name]
}

// pos is n's trace index: the order pins compare on.
func (tr *serverTrace) pos(n ast.Node) int {
	i, ok := tr.index[n]
	if !ok {
		return -1
	}
	return i
}

// where renders n's source location for a failure message.
func (tr *serverTrace) where(n ast.Node) token.Position {
	return tr.fset.Position(n.Pos())
}

// traceCall is the first call of one name in the trace.
type traceCall struct {
	call *ast.CallExpr
	pos  int
}

// firstCalls maps a call name to its FIRST occurrence in the trace. It records
// both bare identifiers (enrollSelfAndBringUpMesh) and qualified selectors
// (netserve.New), because the orderings the pins depend on span both shapes.
func (tr *serverTrace) firstCalls() map[string]traceCall {
	first := map[string]traceCall{}
	note := func(name string, call *ast.CallExpr) {
		if _, seen := first[name]; !seen {
			first[name] = traceCall{call: call, pos: tr.pos(call)}
		}
	}
	tr.inspect(func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			note(fun.Name, call)
		case *ast.SelectorExpr:
			if pkg, ok := fun.X.(*ast.Ident); ok {
				note(pkg.Name+"."+fun.Sel.Name, call)
			}
		}
		return true
	})
	return first
}

// TestRunServerTraceExpandsHelpersInPlace pins the trace itself on synthetic
// source, so the structural pins that read it cannot pass by reading nothing: a
// helper's calls appear at its call site, after its arguments and before the
// caller's next statement; a local closure is not expanded; recursion stops; and
// a helper in defer, go, or if-arm position expands at its textual position (see
// serverTrace.inspect).
func TestRunServerTraceExpandsHelpersInPlace(t *testing.T) {
	for _, tc := range []struct {
		name, src, want string
	}{
		{
			name: "arguments, then the callee, then the next statement; closures and recursion stop",
			src: `package main

func runServer() {
	a()
	helper(b())
	stop := func() { never() }
	stop()
	z()
}

func helper(int) { c(); helper(0); d() }
`,
			// never() is a call inside the closure literal, visited at its textual
			// position like any other node; the closure CALL stop() is not expanded.
			want: "a helper b c helper d never stop z",
		},
		{
			name: "a deferred helper expands at the defer statement, not at exit",
			src: `package main

func runServer() {
	a()
	defer helper()
	z()
}

func helper() { inHelper() }
`,
			want: "a helper inHelper z",
		},
		{
			name: "a spawned helper expands at the go statement",
			src: `package main

func runServer() {
	a()
	go helper()
	z()
}

func helper() { inHelper() }
`,
			want: "a helper inHelper z",
		},
		{
			name: "helpers in both if arms expand in place, in source order",
			src: `package main

func runServer() {
	a()
	if cond() {
		then()
	} else {
		otherwise()
	}
	z()
}

func then()      { inThen() }
func otherwise() { inOtherwise() }
`,
			want: "a cond then inThen otherwise inOtherwise z",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := traceCallOrder(t, tc.src); got != tc.want {
				t.Errorf("trace call order = %q, want %q", got, tc.want)
			}
		})
	}

	// The index orders an expansion between its arguments and the next statement.
	tr := syntheticTrace(t, `package main

func runServer() {
	helper(b())
	z()
}

func helper(int) { c(); d() }
`)
	first := tr.firstCalls()
	if first["c"].pos <= first["b"].pos || first["d"].pos >= first["z"].pos {
		t.Errorf("trace indices do not order the expansion between its arguments and the next statement: %+v", first)
	}
}

// syntheticTrace builds a serverTrace over one in-memory source file.
func syntheticTrace(t *testing.T, src string) *serverTrace {
	t.Helper()
	tr := &serverTrace{fset: token.NewFileSet(), funcs: map[string]*ast.FuncDecl{}, index: map[ast.Node]int{}}
	file, err := parser.ParseFile(tr.fset, "server.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn := decl.(*ast.FuncDecl)
		tr.funcs[fn.Name.Name] = fn
	}
	tr.decl = tr.funcs["runServer"]
	next := 0
	tr.inspect(func(n ast.Node) bool {
		if _, seen := tr.index[n]; !seen {
			tr.index[n] = next
			next++
		}
		return true
	})
	return tr
}

// traceCallOrder renders the bare-identifier calls of src's runServer trace, in
// trace order.
func traceCallOrder(t *testing.T, src string) string {
	t.Helper()
	var order []string
	syntheticTrace(t, src).inspect(func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				order = append(order, id.Name)
			}
		}
		return true
	})
	return strings.Join(order, " ")
}
