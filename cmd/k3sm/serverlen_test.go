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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	stdmaps "maps"
	"slices"
	"sort"
	"strings"
	"testing"
)

// maxServerFuncLines is the physical-line budget for every function in the
// non-test server*.go files, runServer included: the thin-main standard keeps
// the bring-up an orchestrator over named provisioning and phase helpers.
const maxServerFuncLines = 150

// funcBodyLines maps each top-level function in src to its physical line
// count, measured as the line of its closing brace minus the line of its
// opening brace (comments and blank lines included). Methods are keyed
// "Recv.Name".
func funcBodyLines(fset *token.FileSet, file *ast.File) map[string]int {
	out := map[string]int{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			name = recvTypeName(fn.Recv.List[0].Type) + "." + name
		}
		out[name] = fset.Position(fn.Body.Rbrace).Line - fset.Position(fn.Body.Lbrace).Line
	}
	return out
}

// recvTypeName renders a method receiver's type name, dropping the pointer.
func recvTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return recvTypeName(x.X)
	}
	return "?"
}

// overBudget returns the names of every function in counts over max, sorted,
// and an error if runServer is not among them at all (the gate would otherwise
// be vacuous).
func overBudget(counts map[string]int, max int) ([]string, error) {
	if _, ok := counts["runServer"]; !ok {
		return nil, fmt.Errorf("no runServer function found")
	}
	var over []string
	for name, n := range counts {
		if n > max {
			over = append(over, name)
		}
	}
	sort.Strings(over)
	return over, nil
}

// ratchetAdvice is appended to every gate failure: the cap is a deliberate
// ratchet, and the fix for a red is a smaller function, never a larger number.
const ratchetAdvice = "this cap is a deliberate ratchet (B242's thin-main standard): extract a named helper " +
	"into serverprovision.go or serverphases.go, keeping every defer in runServer; do NOT raise maxServerFuncLines"

// TestRunServerUnder150Lines is the B242 gate: runServer is an orchestrator of
// at most maxServerFuncLines physical lines, and no function in any non-test
// server*.go file exceeds the same budget.
func TestRunServerUnder150Lines(t *testing.T) {
	fset := token.NewFileSet()
	counts := map[string]int{}
	files := map[string]string{}
	for _, name := range serverSourceFiles(t) {
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for fn, n := range funcBodyLines(fset, file) {
			counts[fn], files[fn] = n, name
		}
	}
	over, err := overBudget(counts, maxServerFuncLines)
	if err != nil {
		t.Fatalf("%v in the non-test server*.go files", err)
	}
	for _, name := range over {
		t.Errorf("%s (%s) is %d physical lines, want at most %d — %s",
			name, files[name], counts[name], maxServerFuncLines, ratchetAdvice)
	}
}

// TestFuncBodyLinesCounter pins the counter the gate uses on synthetic source,
// so the gate cannot pass by measuring nothing: a body of exactly the budget
// passes, one line over fails, and a source with no runServer is an error.
func TestFuncBodyLinesCounter(t *testing.T) {
	// body builds a function whose braces are n lines apart: the opening brace
	// on the func line, n-1 interior lines (a comment, blanks, a statement),
	// and the closing brace.
	body := func(name string, n int) string {
		var b strings.Builder
		fmt.Fprintf(&b, "func %s() {\n\t// a comment counts\n", name)
		for i := 0; i < n-3; i++ {
			b.WriteString("\n")
		}
		b.WriteString("\t_ = 0\n}\n")
		return b.String()
	}
	count := func(t *testing.T, src string) map[string]int {
		t.Helper()
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "server.go", "package main\n\n"+src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		return funcBodyLines(fset, file)
	}

	for _, tc := range []struct {
		name       string
		src        string
		wantCounts map[string]int
		wantOver   []string
		wantErr    bool
	}{
		{
			name:       "exactly the budget passes",
			src:        body("runServer", 150) + body("helper", 150),
			wantCounts: map[string]int{"runServer": 150, "helper": 150},
		},
		{
			name:       "runServer one over fails",
			src:        body("runServer", 151),
			wantCounts: map[string]int{"runServer": 151},
			wantOver:   []string{"runServer"},
		},
		{
			name:       "a helper one over fails",
			src:        body("runServer", 10) + body("helper", 151),
			wantCounts: map[string]int{"runServer": 10, "helper": 151},
			wantOver:   []string{"helper"},
		},
		{
			name:       "a method one over fails",
			src:        body("runServer", 10) + "type s struct{}\n" + strings.Replace(body("m", 151), "func m", "func (s) m", 1),
			wantCounts: map[string]int{"runServer": 10, "s.m": 151},
			wantOver:   []string{"s.m"},
		},
		{
			name:       "a missing runServer is an error",
			src:        body("helper", 10),
			wantCounts: map[string]int{"helper": 10},
			wantErr:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counts := count(t, tc.src)
			if !stdmaps.Equal(counts, tc.wantCounts) {
				t.Fatalf("counts = %v, want %v — the synthetic builder or the counter is off", counts, tc.wantCounts)
			}
			over, err := overBudget(counts, maxServerFuncLines)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !slices.Equal(over, tc.wantOver) {
				t.Errorf("over = %v, want %v", over, tc.wantOver)
			}
		})
	}
}
