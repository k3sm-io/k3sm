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

package bootstrap

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// workFactorVars are the package vars TestMain lowers. Only TestMain may write
// them: a production write would change the shipped work factor, and the pin in
// TestShippedWorkFactors would not see a write that happens after its capture.
var workFactorVars = map[string]bool{"hashCost": true, "bundleSealIters": true}

// workFactorViolations reports, as "file:line: reason", every write to a
// work-factor var (an assignment, an increment or decrement, or taking its
// address) and every bcrypt.GenerateFromPassword call whose cost argument is
// not hashCost.
func workFactorViolations(fset *token.FileSet, files []*ast.File) []string {
	var out []string
	report := func(n ast.Node, format string, args ...any) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), fmt.Sprintf(format, args...)))
	}
	isWorkFactor := func(e ast.Expr) (string, bool) {
		id, ok := ast.Unparen(e).(*ast.Ident)
		if !ok || !workFactorVars[id.Name] {
			return "", false
		}
		return id.Name, true
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if name, ok := isWorkFactor(lhs); ok {
						report(n, "assigns %s", name)
					}
				}
			case *ast.IncDecStmt:
				if name, ok := isWorkFactor(n.X); ok {
					report(n, "modifies %s", name)
				}
			case *ast.UnaryExpr:
				if name, ok := isWorkFactor(n.X); ok && n.Op == token.AND {
					report(n, "takes the address of %s", name)
				}
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "GenerateFromPassword" {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "bcrypt" {
					return true
				}
				if len(n.Args) != 2 {
					report(n, "bcrypt.GenerateFromPassword with %d arguments", len(n.Args))
					return true
				}
				if id, ok := ast.Unparen(n.Args[1]).(*ast.Ident); !ok || id.Name != "hashCost" {
					report(n, "bcrypt.GenerateFromPassword cost is not hashCost")
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// TestWorkFactorsAreSetOnlyByTests pins, at the source level, that no non-test
// file of this package writes a work-factor var and that every bcrypt hash in it
// is minted at hashCost, so the value TestShippedWorkFactors pins is the one every
// production path uses.
func TestWorkFactorsAreSetOnlyByTests(t *testing.T) {
	t.Run("package sources", func(t *testing.T) {
		names, err := filepath.Glob("*.go")
		if err != nil {
			t.Fatalf("glob package sources: %v", err)
		}
		fset := token.NewFileSet()
		var files []*ast.File
		for _, name := range names {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			files = append(files, f)
		}
		if len(files) == 0 {
			t.Fatal("found no non-test sources: the scan is not seeing the package")
		}
		calls := 0
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "GenerateFromPassword" {
						calls++
					}
				}
				return true
			})
		}
		if calls == 0 {
			t.Fatal("found no bcrypt.GenerateFromPassword call: the scan is not seeing the hashing paths")
		}
		if v := workFactorViolations(fset, files); len(v) > 0 {
			t.Errorf("work-factor discipline violated:\n%s", strings.Join(v, "\n"))
		}
	})

	// The planted rows prove the checker reds on each violation it claims to
	// catch, and stays green on the shipped shape.
	planted := []struct {
		name string
		src  string
		want string
	}{
		{"the shipped shape", `var hashCost = bcrypt.DefaultCost
func h(p []byte) { bcrypt.GenerateFromPassword(p, hashCost) }`, ""},
		{"an init lowers hashCost", `func init() { hashCost = 4 }`, "assigns hashCost"},
		{"a multi-assign lowers bundleSealIters", `func f() { a, bundleSealIters := 1, 2; _ = a }`, "assigns bundleSealIters"},
		{"a decrement", `func f() { hashCost-- }`, "modifies hashCost"},
		{"an escaping pointer", `func f() *int { return &bundleSealIters }`, "takes the address of bundleSealIters"},
		{"a hard-coded cost", `func h(p []byte) { bcrypt.GenerateFromPassword(p, bcrypt.DefaultCost) }`, "cost is not hashCost"},
		{"a literal cost", `func h(p []byte) { bcrypt.GenerateFromPassword(p, 4) }`, "cost is not hashCost"},
	}
	for _, tc := range planted {
		t.Run("planted/"+tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "planted.go", "package bootstrap\n"+tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse planted source: %v", err)
			}
			v := workFactorViolations(fset, []*ast.File{f})
			if tc.want == "" {
				if len(v) != 0 {
					t.Fatalf("clean source reported %v", v)
				}
				return
			}
			if len(v) != 1 || !strings.Contains(v[0], tc.want) {
				t.Fatalf("violations = %v, want exactly one containing %q", v, tc.want)
			}
		})
	}
}
