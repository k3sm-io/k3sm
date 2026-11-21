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

// keystoreImportPath is the package whose Config and FileStore the guard
// follows through import names and type aliases.
const keystoreImportPath = "k3sm.io/k3sm/pkg/keystore"

// TestFloorOwnerUnsetOutsideTests is G6's guard on the floor's owner: no
// file of the module but a _test.go file sets Config.FloorUID or FloorGID,
// in a keyed or unkeyed composite literal, an assignment, a range clause,
// an increment or by taking its address; and nothing but New in store.go
// sets FileStore's floorUID or floorGID, keyed or unkeyed. A literal's type
// is followed through the name keystore is imported under and through type
// aliases declared anywhere in its package. Their declarations and
// checkConfig only declare and read them, which this does not count.
func TestFloorOwnerUnsetOutsideTests(t *testing.T) {
	root := moduleRoot(t)
	facts := newGuardFacts(t, filepath.Join(root, "pkg", "keystore", "store.go"))
	fset := token.NewFileSet()
	type parsed struct {
		f   *ast.File
		rel string
	}
	var files []parsed
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
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, parsed{f, filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 100 {
		t.Fatalf("walked %d non-test files under %s: not the module", len(files), root)
	}
	// Aliases first, since one file may alias the type another uses.
	for _, p := range files {
		facts.addAliases(p.f, p.rel)
	}
	var sets []string
	for _, p := range files {
		for _, pos := range facts.floorOwnerSets(p.f, p.rel) {
			sets = append(sets, fset.Position(pos).String())
		}
	}
	if len(sets) > 0 {
		t.Fatalf("the floor's owner is set outside a _test.go file (or FileStore's copy outside New), so a production store could trust a floor root does not own:\n%s", strings.Join(sets, "\n"))
	}
}

// guardFacts is what the guard knows of the keystore package: where the
// owner fields sit in Config and FileStore, for unkeyed literals, and the
// type aliases of either, by package directory.
type guardFacts struct {
	configIdx, storeIdx int
	aliases             map[string]map[string]string // dir -> alias -> "Config" or "FileStore"
}

func newGuardFacts(t *testing.T, storeGo string) *guardFacts {
	t.Helper()
	return &guardFacts{
		configIdx: fieldIndex(t, storeGo, "Config", floorOwnerFields),
		storeIdx:  fieldIndex(t, storeGo, "FileStore", floorOwnerCopies),
		aliases:   map[string]map[string]string{},
	}
}

// fieldIndex is the position, from 0, of the first of fields among the
// struct typeName's fields as declared in path: an unkeyed literal with more
// elements than that sets it.
func fieldIndex(t *testing.T, path, typeName string, fields map[string]bool) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	idx := -1
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != typeName {
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
				if fields[nm.Name] && idx < 0 {
					idx = i
				}
				i++
			}
		}
		return false
	})
	if idx < 0 {
		t.Fatalf("no %s with a floor owner field in %s", typeName, path)
	}
	return idx
}

// fileScope is how a file can name the keystore package's types: the names
// it imports the package under, whether it is that package or dot-imports
// it, and its package's aliases.
type fileScope struct {
	names   map[string]bool
	bare    bool
	aliases map[string]string
}

func (g *guardFacts) scope(f *ast.File, rel string) fileScope {
	dir := pathDir(rel)
	sc := fileScope{names: map[string]bool{}, bare: dir == "pkg/keystore" && f.Name.Name == "keystore", aliases: g.aliases[dir]}
	for _, im := range f.Imports {
		if strings.Trim(im.Path.Value, `"`) != keystoreImportPath {
			continue
		}
		switch {
		case im.Name == nil:
			sc.names["keystore"] = true
		case im.Name.Name == ".":
			sc.bare = true
		case im.Name.Name != "_":
			sc.names[im.Name.Name] = true
		}
	}
	return sc
}

func pathDir(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return "."
}

// keystoreType is "Config" or "FileStore" when e names that type of the
// keystore package in sc, else "".
func (sc fileScope) keystoreType(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return sc.keystoreType(x.X)
	case *ast.Ident:
		if sc.bare && (x.Name == "Config" || x.Name == "FileStore") {
			return x.Name
		}
		return sc.aliases[x.Name]
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok && sc.names[id.Name] && (x.Sel.Name == "Config" || x.Sel.Name == "FileStore") {
			return x.Sel.Name
		}
	}
	return ""
}

// addAliases records f's type aliases of Config or FileStore for its
// package, an alias of an alias included.
func (g *guardFacts) addAliases(f *ast.File, rel string) {
	dir := pathDir(rel)
	for changed := true; changed; {
		changed = false
		sc := g.scope(f, rel)
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !ts.Assign.IsValid() {
				return true
			}
			if k := sc.keystoreType(ts.Type); k != "" && g.aliases[dir][ts.Name.Name] != k {
				if g.aliases[dir] == nil {
					g.aliases[dir] = map[string]string{}
				}
				g.aliases[dir][ts.Name.Name] = k
				changed = true
			}
			return true
		})
	}
}

// TestFloorOwnerSets: the walk counts every way to set the fields, and not
// a read; FileStore's copies count outside New in store.go only; a
// literal's type is followed through import names and aliases.
func TestFloorOwnerSets(t *testing.T) {
	facts := newGuardFacts(t, "store.go")
	const imp = "import \"" + keystoreImportPath + "\"\n"
	const impAs = "import ks \"" + keystoreImportPath + "\"\n"
	unkeyedConfig := "{" + strings.Repeat("0, ", facts.configIdx+1) + "}"
	shortConfig := "{" + strings.Repeat("0, ", facts.configIdx) + "}"
	unkeyedStore := "{" + strings.Repeat("0, ", facts.storeIdx+1) + "}"
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
		{"pkg/keystore/x.go", "var c = Config" + unkeyedConfig, 1},
		{"pkg/keystore/x.go", "var c = Config" + shortConfig, 0},
		{"x.go", imp + "var c = keystore.Config" + unkeyedConfig, 1},
		{"x.go", impAs + "var c = ks.Config" + unkeyedConfig, 1},
		{"x.go", impAs + "var c = keystore.Config" + unkeyedConfig, 0},
		{"x.go", "var c = Config" + unkeyedConfig, 0}, // another package's Config
		{"x.go", impAs + "type C = ks.Config\nvar c = C" + unkeyedConfig, 1},
		{"x.go", impAs + "type C = ks.Config\ntype D = C\nvar c = D" + unkeyedConfig, 1},
		{"x.go", impAs + "type C ks.Config\nvar c = C" + unkeyedConfig, 0}, // a defined type, not the store's
		{"pkg/keystore/x.go", "var s = FileStore" + unkeyedStore, 1},
		{"pkg/keystore/store.go", "func New(cfg Config) *FileStore { return &FileStore" + unkeyedStore + " }", 0},
		{"x.go", impAs + "type S = ks.FileStore\nvar s = S" + unkeyedStore, 1},
		{"x.go", "func f(s *FileStore) { s.floorUID = 1 }", 1},
		{"pkg/keystore/store.go", "func g(s *FileStore) { s.floorGID = 1 }", 1},
		{"pkg/keystore/store.go", "func New(cfg Config) *FileStore { return &FileStore{floorUID: cfg.FloorUID} }", 0},
		{"pkg/keystore/store.go", "func New(cfg Config) *FileStore { s := &FileStore{}; s.floorGID = 1; return s }", 0},
		{"x.go", "func New(cfg Config) *FileStore { return &FileStore{floorUID: 1} }", 1},
		{"x.go", "func f(c *Config) int { return c.FloorUID }", 0},
		{"x.go", "func f(c *Config) bool { return c.FloorGID < 0 }", 0},
		{"x.go", "type Config struct{ FloorUID, FloorGID int }", 0},
	} {
		pkg := "x"
		if pathDir(tc.file) == "pkg/keystore" {
			pkg = "keystore"
		}
		f, err := parser.ParseFile(token.NewFileSet(), tc.file, "package "+pkg+"\n"+tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", tc.src, err)
		}
		g := &guardFacts{configIdx: facts.configIdx, storeIdx: facts.storeIdx, aliases: map[string]map[string]string{}}
		g.addAliases(f, tc.file)
		if got := len(g.floorOwnerSets(f, tc.file)); got != tc.want {
			t.Errorf("%s in %s: %d sets, want %d", tc.src, tc.file, got, tc.want)
		}
	}
}

// floorOwnerSets returns where f, at rel (slash-separated, from the module
// root), sets a floor owner field: Config's anywhere, and FileStore's copies
// anywhere but New in store.go, keyed or unkeyed.
func (g *guardFacts) floorOwnerSets(f *ast.File, rel string) []token.Pos {
	sc := g.scope(f, rel)
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
				if !keyed {
					switch sc.keystoreType(x.Type) {
					case "Config":
						if len(x.Elts) > g.configIdx {
							out = append(out, x.Pos())
						}
					case "FileStore":
						if !copiesAllowed && len(x.Elts) > g.storeIdx {
							out = append(out, x.Pos())
						}
					}
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
