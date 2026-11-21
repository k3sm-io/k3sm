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
// so the floor is root's. floorOwnerCopies are FileStore's copies of them,
// which only New (in store.go) writes.
var (
	floorOwnerFields = map[string]bool{"FloorUID": true, "FloorGID": true}
	floorOwnerCopies = map[string]bool{"floorUID": true, "floorGID": true}
)

// TestFloorOwnerUnsetOutsideTests is G6's guard on the floor's owner: no
// file of the module but a _test.go file sets Config.FloorUID or FloorGID,
// in a keyed or unkeyed composite literal, an assignment, a range clause,
// an increment or by taking its address; and nothing but New in store.go
// sets FileStore's floorUID or floorGID. Their declarations and checkConfig
// only declare and read them, which this does not count.
func TestFloorOwnerUnsetOutsideTests(t *testing.T) {
	root := moduleRoot(t)
	idx := configFloorIndex(t, filepath.Join(root, "pkg", "keystore", "store.go"))
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
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		for _, pos := range floorOwnerSets(f, filepath.ToSlash(rel), idx) {
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
		t.Fatalf("the floor's owner is set outside a _test.go file (or FileStore's copy outside New), so a production store could trust a floor root does not own:\n%s", strings.Join(sets, "\n"))
	}
}

// configFloorIndex is the position, from 0, of the first floor owner field
// among Config's fields as declared in path: an unkeyed Config literal with
// more elements than that sets it.
func configFloorIndex(t *testing.T, path string) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	idx := -1
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Config" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		i := 0
		for _, fl := range st.Fields.List {
			if len(fl.Names) == 0 {
				i++ // an embedded field
			}
			for _, nm := range fl.Names {
				if floorOwnerFields[nm.Name] && idx < 0 {
					idx = i
				}
				i++
			}
		}
		return false
	})
	if idx < 0 {
		t.Fatalf("no Config with a floor owner field in %s", path)
	}
	return idx
}

// TestFloorOwnerSets: the walk counts every way to set the fields, and not
// a read; FileStore's copies count outside New in store.go only.
func TestFloorOwnerSets(t *testing.T) {
	const idx = 5 // Config{Dir, MasterDir, UID, GID, DataRoot, FloorUID, FloorGID}
	for _, tc := range []struct {
		file, src string
		want      int
	}{
		{"x.go", "var c = Config{FloorUID: 1}", 1},
		{"x.go", "func f(c *Config) { c.FloorGID = 1 }", 1},
		{"x.go", "func f(c *Config) { (c.FloorUID), x = 1, 2 }", 1},
		{"x.go", "func f(c *Config) { c.FloorUID++ }", 1},
		{"x.go", "func f(c *Config) *int { return &c.FloorGID }", 1},
		{"x.go", "func f(c *Config) { for c.FloorUID = range 3 {} }", 1},
		{"x.go", "func f(c *Config) { for _, c.FloorGID = range []int{1} {} }", 1},
		{"x.go", `var c = Config{"/a", "/b", 1, 1, "/c", 7, 7}`, 1},
		{"x.go", `var c = keystore.Config{"/a", "/b", 1, 1, "/c", 7, 7}`, 1},
		{"x.go", `var c = Config{"/a", "/b", 1, 1, "/c"}`, 0},
		{"x.go", "func f(s *FileStore) { s.floorUID = 1 }", 1},
		{"pkg/keystore/store.go", "func g(s *FileStore) { s.floorGID = 1 }", 1},
		{"pkg/keystore/store.go", "func New(cfg Config) *FileStore { return &FileStore{floorUID: cfg.FloorUID} }", 0},
		{"pkg/keystore/store.go", "func New(cfg Config) *FileStore { s := &FileStore{}; s.floorGID = 1; return s }", 0},
		{"x.go", "func New(cfg Config) *FileStore { return &FileStore{floorUID: 1} }", 1},
		{"x.go", "func f(c *Config) int { return c.FloorUID }", 0},
		{"x.go", "func f(c *Config) bool { return c.FloorGID < 0 }", 0},
		{"x.go", "type Config struct{ FloorUID, FloorGID int }", 0},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\n"+tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(floorOwnerSets(f, tc.file, idx)); got != tc.want {
			t.Errorf("%s in %s: %d sets, want %d", tc.src, tc.file, got, tc.want)
		}
	}
}

// floorOwnerSets returns where f, at rel (slash-separated, from the module
// root), sets a floor owner field: Config's anywhere, given floorIdx (see
// configFloorIndex), and FileStore's copies anywhere but New in store.go.
func floorOwnerSets(f *ast.File, rel string, floorIdx int) []token.Pos {
	var out []token.Pos
	inspect := func(root ast.Node, copiesAllowed bool) {
		owner := func(e ast.Expr) bool {
			return isOwnerSel(e, floorOwnerFields) || !copiesAllowed && isOwnerSel(e, floorOwnerCopies)
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				keyed := false
				for _, el := range x.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					keyed = true
					if id, ok := kv.Key.(*ast.Ident); ok && (floorOwnerFields[id.Name] || !copiesAllowed && floorOwnerCopies[id.Name]) {
						out = append(out, kv.Pos())
					}
				}
				if !keyed && isConfigType(x.Type) && len(x.Elts) > floorIdx {
					out = append(out, x.Pos())
				}
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					if owner(l) {
						out = append(out, l.Pos())
					}
				}
			case *ast.RangeStmt:
				for _, e := range []ast.Expr{x.Key, x.Value} {
					if e != nil && owner(e) {
						out = append(out, e.Pos())
					}
				}
			case *ast.IncDecStmt:
				if owner(x.X) {
					out = append(out, x.Pos())
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && owner(x.X) {
					out = append(out, x.Pos())
				}
			}
			return true
		})
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		constructor := ok && rel == "pkg/keystore/store.go" && fd.Recv == nil && fd.Name.Name == "New"
		inspect(d, constructor)
	}
	return out
}

// isConfigType reports whether a composite literal's type is the store's
// Config: Config, or keystore.Config.
func isConfigType(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "Config"
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		return ok && id.Name == "keystore" && x.Sel.Name == "Config"
	}
	return false
}

// isOwnerSel reports whether e, parentheses removed, selects a field named
// in fields.
func isOwnerSel(e ast.Expr, fields map[string]bool) bool {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	s, ok := e.(*ast.SelectorExpr)
	return ok && fields[s.Sel.Name]
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
