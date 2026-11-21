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

package keystore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// floorOwnerFields are Config's test-only fields: production leaves them 0,
// so the floor is root's.
var floorOwnerFields = map[string]bool{"FloorUID": true, "FloorGID": true}

// TestFloorOwnerUnsetOutsideTests is G6's guard on the floor's owner: no
// file of the module but a _test.go file sets Config.FloorUID or FloorGID,
// in a composite literal, an assignment, an increment or by taking its
// address. Their declaration and checkConfig only declare and read them,
// which this does not count.
func TestFloorOwnerUnsetOutsideTests(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files := 0
	var sets []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); p != root && (n == "testdata" || n == "vendor" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, pos := range floorOwnerSets(f) {
			sets = append(sets, fset.Position(pos).String())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("walked %d non-test files under %s: not the module", files, root)
	}
	if len(sets) > 0 {
		t.Fatalf("FloorUID or FloorGID is set outside a _test.go file, so a production store could trust a floor root does not own:\n%s", strings.Join(sets, "\n"))
	}
}

// TestFloorOwnerSets: the walk counts every way to set the fields, and not
// a read.
func TestFloorOwnerSets(t *testing.T) {
	for src, want := range map[string]int{
		"var c = Config{FloorUID: 1}":                      1,
		"func f(c *Config) { c.FloorGID = 1 }":             1,
		"func f(c *Config) { (c.FloorUID), x = 1, 2 }":     1,
		"func f(c *Config) { c.FloorUID++ }":               1,
		"func f(c *Config) *int { return &c.FloorGID }":    1,
		"func f(c *Config) int { return c.FloorUID }":      0,
		"func f(c *Config) bool { return c.FloorGID < 0 }": 0,
		"type Config struct{ FloorUID, FloorGID int }":     0,
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\n"+src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(floorOwnerSets(f)); got != want {
			t.Errorf("%s: %d sets, want %d", src, got, want)
		}
	}
}

// floorOwnerSets returns where f sets a floor owner field.
func floorOwnerSets(f *ast.File) []token.Pos {
	var out []token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			for _, el := range x.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok && floorOwnerFields[id.Name] {
						out = append(out, kv.Pos())
					}
				}
			}
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if isOwnerSel(l) {
					out = append(out, l.Pos())
				}
			}
		case *ast.IncDecStmt:
			if isOwnerSel(x.X) {
				out = append(out, x.Pos())
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && isOwnerSel(x.X) {
				out = append(out, x.Pos())
			}
		}
		return true
	})
	return out
}

// isOwnerSel reports whether e, parentheses removed, selects a floor owner
// field.
func isOwnerSel(e ast.Expr) bool {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	s, ok := e.(*ast.SelectorExpr)
	return ok && floorOwnerFields[s.Sel.Name]
}

// moduleRoot is the directory of the go.mod above the test's directory. A
// test binary run away from the source (the acceptance gate's root run) has
// none, and skips: the gate's --check run requires this test to pass.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("no go.mod above the test's directory: the source tree is not here")
		}
		dir = parent
	}
}
