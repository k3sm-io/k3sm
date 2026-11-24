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
	"strconv"
	"strings"
	"testing"
)

// TestUserScopeIsUnexported holds the user scope inside this package and
// pkg/keystore/socket, the socket slice's package, for which the ban on
// references is lifted (referenceAllowed): no other package outside
// pkg/keystore (its other sub-packages and cmd/k3sm included) may
// reference UserScope,
// ResolveEntry or ParseEntry, nor the delivery verbs Deliver, Withdraw and
// Delivery (which also names their parameter type). ParseEntry is held
// whole, since a reference cannot be told to use only its system form
// without types.
//
// The order is what makes the hold matter. The socket is the first
// production caller of the user scope, and it lands after the change that
// adds the delivery record (kind 0xFD). So no production scope can exist
// without its deliveries record, and no migration is needed for scopes this
// build's mint wrote without one; it also keeps the floor gap
// (userscope.go) out of reach until the user-scope floor lands.
//
// The hold is also mechanical: UserScope refuses until startUserScopes
// (CheckLogBounds, then catchUpUser) has run. And before any exported
// identifier reaches the user scope, the tests of three rows must exist,
// checked with go/ast over their packages' test files (exportPrereqs), so
// the socket slice that lifts the ban cannot land ahead of them. A test
// counts only if its body calls t.Error* or t.Fatal* on its *testing.T
// parameter outside a constant-false branch, and never Skip, SkipNow or
// Skipf. An exported identifier reaches the user scope when a file outside
// pkg/keystore references a banned name or dot-imports the package, or
// when an exported function, method, var, const or type declared in
// pkg/keystore references UserScope, startUserScopes, catchUpUser,
// ResolveEntry, ParseEntry, Deliver, Withdraw or Delivery, directly or
// through same-package calls (inPackageExports), past the reasoned
// allowlist inPackageReachAllow:
//   - U51, the per-uid byte shares, in pkg/keystore/socket:
//     TestLogSharePerUIDRefusesOnlyThatUID, TestLogShareAtMostOneSixteenthOfHardCap,
//     TestShareRefusalIsNotGlobalAppendFailure, TestReadRateLimitPerUID,
//     TestReadsChargedToShare, TestShareExhaustionIsolatedPerUID;
//   - U193, the rebuild, in pkg/keystore: TestRebuildCarriesTombstonesForward;
//   - U194, the rebuild after rm-scope, in pkg/keystore:
//     TestRebuildDropsRemovedScopeKeys.
//
// The socket slice lifts the ban on references, never the prerequisite
// check: a reference from pkg/keystore/socket is no failure, but it still
// counts as an exported identifier reaching the user scope, so the
// prerequisites are checked whenever one exists.
//
// This is a guardrail, not a proof: a syntactic scan without types can be
// walked around (a call through an interface value or a func-typed field,
// reflection, a generated file). The socket slice's mandatory security
// review is the backstop that judges what actually reaches the user scope.
func TestUserScopeIsUnexported(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the module root %s has no go.mod: %v", root, err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	files, exported := 0, false
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); p != root && (strings.HasPrefix(n, ".") || n == "testdata" || n == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || filepath.Dir(p) == self {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		rel, _ := filepath.Rel(root, p)
		for _, name := range bannedRefs(f) {
			exported = true
			if referenceAllowed(filepath.ToSlash(filepath.Dir(rel))) {
				t.Logf("%s references %s (ban lifted for its package; prerequisites checked)", rel, name)
				continue
			}
			t.Errorf("%s references %s: the user scope stays inside pkg/keystore and pkg/keystore/socket", rel, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("scanned only %d files under %s", files, root)
	}
	inPkg, err := inPackageExports(self)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range inPkg {
		exported = true
		t.Logf("pkg/keystore exports %s, whose body reaches the user scope", name)
	}
	if exported {
		missing, err := missingExportPrereqs(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range missing {
			t.Errorf("an exported identifier reaches the user scope before %s exists", m)
		}
	}
}

// referenceAllowed reports whether a file in dir, relative to the module
// root, may reference the user scope's names: pkg/keystore/socket only, the
// socket server whose store bridge opens a peer's view per request. Its
// sub-packages and every other directory stay banned.
func referenceAllowed(dir string) bool { return dir == "pkg/keystore/socket" }

// exportPrereqs are the tests that must exist, each in its package's test
// files, before any exported identifier reaches the user scope: U51's (the
// per-uid byte shares), U193's (the rebuild) and U194's (the rebuild after
// rm-scope).
var exportPrereqs = []struct {
	row, dir string
	tests    []string
}{
	{"U51", "pkg/keystore/socket", []string{
		"TestLogSharePerUIDRefusesOnlyThatUID", "TestLogShareAtMostOneSixteenthOfHardCap",
		"TestShareRefusalIsNotGlobalAppendFailure", "TestReadRateLimitPerUID",
		"TestReadsChargedToShare", "TestShareExhaustionIsolatedPerUID",
	}},
	{"U193", "pkg/keystore", []string{"TestRebuildCarriesTombstonesForward"}},
	{"U194", "pkg/keystore", []string{"TestRebuildDropsRemovedScopeKeys"}},
}

// userScopeReach are the names whose reference, in pkg/keystore, reaches
// the user scope: an exported declaration that references one, directly or
// through same-package calls, is an export of it.
var userScopeReach = map[string]bool{
	"UserScope": true, "startUserScopes": true, "catchUpUser": true, "ResolveEntry": true, "ParseEntry": true,
	"Deliver": true, "Withdraw": true, "Delivery": true,
}

// inPackageReachAllow are the exported names declared in pkg/keystore that
// already reach the user scope, keyed "<Recv>.<Name>" for a method, each
// with why it is not an export of it. Every exported method on UserScope is
// left out the same way, by its receiver: it is reachable only through a
// *UserScope, which the outside ban holds.
var inPackageReachAllow = map[string]string{
	"FileStore.UserScope":       "the user scope's own constructor, which the outside ban holds",
	"ResolveEntry":              "the entry resolver itself, which the outside ban holds",
	"FileStore.RebuildFloor":    "root's floor --rebuild: it reads every scope to write the floor's lines, all root's and charged to no uid, and gives no caller a user scope",
	"FileStore.RemoveScope":     "root's rm-scope: it removes one scope under the exclusive lock, appends no uid's line, and gives no caller a user scope",
	"FileStore.StartUserScopes": "the server's start step: it checks the logs and catches the floor up, and gives no caller a user scope; a scope is still had only through FileStore.UserScope, from pkg/keystore/socket",
}

// inPackageExports returns, as "<Recv>.<Name>" or "<Name>", in declaration
// order, each exported function, method, or package-level var, const or
// type declared in dir's non-test files that reaches a name of
// userScopeReach, past inPackageReachAllow and the methods on UserScope. It
// reaches one when its body (or, for a var, const or type, its spec)
// references one, or references a same-package function or method that
// does, transitively: a call graph built with go/ast alone, a function
// resolved by its name and a method on any package type by its selector's
// name, which over-approximates and never misses a same-package hop.
func inPackageExports(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var parsed []*ast.File
	funcs := map[string]*ast.FuncDecl{} // by key: "<Name>" or "<Recv>.<Name>"
	funcByName := map[string]string{}
	methodsByName := map[string][]string{}
	imports := map[string]bool{} // the names the files give imported packages
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, f)
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			name := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			imports[name] = true
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			key := fd.Name.Name
			if r := recvName(fd); r != "" {
				key = r + "." + key
				methodsByName[fd.Name.Name] = append(methodsByName[fd.Name.Name], key)
			} else {
				funcByName[key] = key
			}
			funcs[key] = fd
		}
	}
	// refs is what n, declared in a method whose receiver is recv of type
	// recvType ("" outside one), references: whether a userScopeReach name
	// directly, and the same-package functions it names and the methods it
	// calls. A call recv.m() is the receiver type's own m when it declares
	// one; any other method call is every package method of its selector's
	// name, unless the selector is qualified by an imported package
	// (fmt.Errorf is no method call).
	refs := func(n ast.Node, recv, recvType string) (direct bool, callees []string) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				if userScopeReach[v.Name] {
					direct = true
				}
				if k, ok := funcByName[v.Name]; ok {
					callees = append(callees, k)
				}
			case *ast.CallExpr:
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok {
					if imports[id.Name] && id.Name != recv {
						return true
					}
					if own := recvType + "." + sel.Sel.Name; recv != "" && id.Name == recv && funcs[own] != nil {
						callees = append(callees, own)
						return true
					}
				}
				callees = append(callees, methodsByName[sel.Sel.Name]...)
			}
			return true
		})
		return direct, callees
	}
	memo := map[string]bool{}
	visiting := map[string]bool{}
	var reaches func(key string) bool
	reaches = func(key string) bool {
		if r, ok := memo[key]; ok {
			return r
		}
		if visiting[key] {
			return false
		}
		visiting[key] = true
		defer delete(visiting, key)
		fd := funcs[key]
		r := false
		if fd != nil && fd.Body != nil {
			direct, callees := refs(fd.Body, recvIdent(fd), recvName(fd))
			r = direct
			for _, c := range callees {
				if r {
					break
				}
				r = reaches(c)
			}
		}
		memo[key] = r
		return r
	}
	nodeReaches := func(n ast.Node) bool {
		direct, callees := refs(n, "", "")
		if direct {
			return true
		}
		for _, c := range callees {
			if reaches(c) {
				return true
			}
		}
		return false
	}
	var out []string
	add := func(name string) {
		if _, ok := inPackageReachAllow[name]; !ok {
			out = append(out, name)
		}
	}
	for _, f := range parsed {
		for _, d := range f.Decls {
			switch v := d.(type) {
			case *ast.FuncDecl:
				if !v.Name.IsExported() || recvName(v) == "UserScope" {
					continue
				}
				key := v.Name.Name
				if r := recvName(v); r != "" {
					key = r + "." + key
				}
				if reaches(key) {
					add(key)
				}
			case *ast.GenDecl:
				for _, spec := range v.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for _, n := range sp.Names {
							if n.IsExported() && nodeReaches(sp) {
								add(n.Name)
								break
							}
						}
					case *ast.TypeSpec:
						// A type's own name is not a reference to it.
						if sp.Name.IsExported() && !userScopeReach[sp.Name.Name] && nodeReaches(sp.Type) {
							add(sp.Name.Name)
						}
					}
				}
			}
		}
	}
	return out, nil
}

// recvIdent is the receiver's name in a method, or "" for a function or an
// unnamed receiver.
func recvIdent(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 || len(fd.Recv.List[0].Names) == 0 {
		return ""
	}
	return fd.Recv.List[0].Names[0].Name
}

// recvName is the receiver's type name of a method, or "" for a function.
func recvName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	x := fd.Recv.List[0].Type
	if st, ok := x.(*ast.StarExpr); ok {
		x = st.X
	}
	switch v := x.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		if id, ok := v.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return "?"
}

// provesSomething reports whether a prerequisite test's body can fail and
// never skips: it holds a call t.Error, t.Errorf, t.Fatal or t.Fatalf on its
// *testing.T parameter t, outside any branch under a constant-false
// condition, and no call to Skip, SkipNow or Skipf on anything. A bare
// .Error selector (err.Error()) or a Fatal on another value proves nothing.
func provesSomething(fd *ast.FuncDecl) bool {
	if fd.Body == nil {
		return false
	}
	tname := testingTParam(fd)
	fails, skips := false, false
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.IfStmt:
				if constFalse(v.Cond) {
					// The body never runs; the else branch can.
					if v.Init != nil {
						walk(v.Init)
					}
					if v.Else != nil {
						walk(v.Else)
					}
					return false
				}
			case *ast.ForStmt:
				if v.Cond != nil && constFalse(v.Cond) {
					return false
				}
			case *ast.CallExpr:
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "Error", "Errorf", "Fatal", "Fatalf":
					if id, ok := sel.X.(*ast.Ident); ok && tname != "" && id.Name == tname {
						fails = true
					}
				case "Skip", "SkipNow", "Skipf":
					skips = true
				}
			}
			return true
		})
	}
	walk(fd.Body)
	return fails && !skips
}

// testingTParam is the name of fd's *testing.T parameter, or "".
func testingTParam(fd *ast.FuncDecl) string {
	if fd.Type.Params == nil {
		return ""
	}
	for _, p := range fd.Type.Params.List {
		st, ok := p.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := st.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "T" {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testing" && len(p.Names) == 1 {
			return p.Names[0].Name
		}
	}
	return ""
}

// constFalse reports whether cond is constantly false as written: false,
// !true, or either parenthesized.
func constFalse(cond ast.Expr) bool {
	switch v := cond.(type) {
	case *ast.ParenExpr:
		return constFalse(v.X)
	case *ast.Ident:
		return v.Name == "false"
	case *ast.UnaryExpr:
		if id, ok := v.X.(*ast.Ident); ok && v.Op == token.NOT {
			return id.Name == "true"
		}
	}
	return false
}

// missingExportPrereqs returns, as "<row> <dir>::<Test>", each of
// exportPrereqs that no _test.go file of its package under root declares as
// a top-level function. A package directory that does not exist declares
// none.
func missingExportPrereqs(root string) ([]string, error) {
	var missing []string
	for _, p := range exportPrereqs {
		have := map[string]bool{}
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(p.dir), "*_test.go"))
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && provesSomething(fd) {
					have[fd.Name.Name] = true
				}
			}
		}
		for _, name := range p.tests {
			if !have[name] {
				missing = append(missing, p.row+" "+p.dir+"::"+name)
			}
		}
	}
	return missing, nil
}

// missingExportPrereqs names every prerequisite test a tree lacks, reads a
// method or a test in another directory as no declaration, and names none
// once each is declared in its package's test files.
func TestExportPrereqsChecked(t *testing.T) {
	root := t.TempDir()
	missing, err := missingExportPrereqs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, p := range exportPrereqs {
		want += len(p.tests)
	}
	if len(missing) != want {
		t.Fatalf("an empty tree lacks %d prerequisites (%v), want %d", len(missing), missing, want)
	}
	write := func(dir, file, src string) {
		t.Helper()
		d := filepath.Join(root, filepath.FromSlash(dir))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, file+"_test.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("pkg/other", "x", "package other\nimport \"testing\"\nfunc TestRebuildCarriesTombstonesForward(t *testing.T) { t.Fatal(\"x\") }\n")
	write("cmd/k3sm", "x", "package main\nimport \"testing\"\ntype r struct{}\nfunc (r) TestRebuildCarriesTombstonesForward(t *testing.T) { t.Fatal(\"x\") }\n")
	if missing, err = missingExportPrereqs(root); err != nil || len(missing) != want {
		t.Fatalf("a method and a test in another package count as declared: %v, %v", missing, err)
	}
	for _, p := range exportPrereqs {
		var b strings.Builder
		b.WriteString("package p\nimport \"testing\"\n")
		for _, name := range p.tests {
			b.WriteString("func " + name + "(t *testing.T) { if t.Name() == \"\" { t.Fatal(\"x\") } }\n")
		}
		write(p.dir, p.row, b.String())
	}
	if missing, err = missingExportPrereqs(root); err != nil || len(missing) != 0 {
		t.Fatalf("every prerequisite declared: still missing %v, %v", missing, err)
	}
	// A prerequisite whose body is empty, never fails, or skips is no
	// prerequisite.
	for _, tc := range []struct{ what, body string }{
		{"an empty body", ""},
		{"a body that never fails", "_ = t.Name()"},
		{"a t.Skip", "t.Skip(\"later\"); t.Fatal(\"x\")"},
		{"a t.SkipNow", "if false { t.Error(\"x\") }; t.SkipNow()"},
		{"a t.Skipf", "t.Skipf(\"%s\", \"later\"); t.Errorf(\"x\")"},
		{"a bare Error selector", "var err error; if err != nil { _ = err.Error() }"},
		{"a Fatal on another value", "var l interface{ Fatal(...any) }; l.Fatal(\"x\")"},
		{"a t.Fatal under a constant-false condition", "if false { t.Fatal(\"x\") }"},
		{"a t.Error under a negated true", "if !true { t.Error(\"x\") }"},
	} {
		for _, p := range exportPrereqs {
			var b strings.Builder
			b.WriteString("package p\nimport \"testing\"\n")
			for _, name := range p.tests {
				b.WriteString("func " + name + "(t *testing.T) { " + tc.body + " }\n")
			}
			write(p.dir, p.row, b.String())
		}
		if missing, err = missingExportPrereqs(root); err != nil || len(missing) != want {
			t.Errorf("prerequisites with %s count as present: missing %d (%v), want %d, %v", tc.what, len(missing), missing, want, err)
		}
	}
	t.Run("an in-package wrapper", checkInPackageExports)
	t.Run("a dot-import", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\nimport . \"k3sm.io/k3sm/pkg/keystore\"\nvar _ FileStore\n", parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(bannedRefs(f), ","); got != "dot-import" {
			t.Errorf("bannedRefs of a dot-import = %q, want dot-import", got)
		}
	})
}

// checkInPackageExports: the scan of pkg/keystore itself counts an
// exported function or method whose body reaches the user scope as an
// export unless it is on inPackageReachAllow, and the package as it stands
// has none past it.
func checkInPackageExports(t *testing.T) {
	dir := t.TempDir()
	src := "package keystore\n" +
		"type FileStore struct{}\n" +
		"func (s *FileStore) UserScope(uint32) {}\n" +
		"func Wrap(s *FileStore) { s.UserScope(1001) }\n" +
		"func (s *FileStore) Start() { startUserScopes() }\n" +
		"func Parse() { _ = ParseEntry }\n" +
		"func quiet(s *FileStore) { s.UserScope(1001) }\n" +
		"func Plain() {}\n" +
		"func Through() { quiet(nil) }\n" +
		"func (s *FileStore) Deep() { s.hop() }\n" +
		"func (s *FileStore) hop() { s.hop2() }\n" +
		"func (s *FileStore) hop2() { _ = catchUpUser }\n" +
		"var Hook = quiet\n" +
		"var Direct = startUserScopes\n" +
		"type Holder struct{ u *UserScope }\n" +
		"const Fine = 1\n" +
		"type UserScope struct{}\n" +
		"func (u *UserScope) Put() { quiet(nil) }\n"
	if err := os.WriteFile(filepath.Join(dir, "w.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "w_test.go"), []byte("package keystore\nfunc Hidden(s *FileStore) { s.UserScope(1) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := inPackageExports(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := "Wrap,FileStore.Start,Parse,Through,FileStore.Deep,Hook,Direct,Holder"; strings.Join(got, ",") != want {
		t.Errorf("inPackageExports = %v, want %s", got, want)
	}
	got, err = inPackageExports(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("exported names in pkg/keystore reach the user scope past the allowlist: %v", got)
	}
}

// bannedRefs returns the banned names f references: a dot-import of the
// keystore package ("dot-import"); a .UserScope selector
// in any file; a package-qualified ResolveEntry or ParseEntry in a file
// that imports the keystore package (or any such selector there whose
// receiver is not a plain name); and, in such a file, any .Deliver,
// .Withdraw or .Delivery selector, whatever its receiver, since the verbs
// are methods on a *UserScope value that need not be named there.
func bannedRefs(f *ast.File) []string {
	banned := map[string]bool{"UserScope": true, "ResolveEntry": true, "ParseEntry": true}
	verbs := map[string]bool{"Deliver": true, "Withdraw": true, "Delivery": true}
	// The names this file gives the keystore package, if it imports it.
	var local []string
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path != "k3sm.io/k3sm/pkg/keystore" {
			continue
		}
		name := "keystore"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		local = append(local, name)
	}
	var out []string
	if contains(local, ".") {
		// A dot-import names every exported identifier bare, so no
		// selector check can see them: it is refused whole.
		out = append(out, "dot-import")
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if verbs[sel.Sel.Name] {
			if len(local) > 0 {
				out = append(out, sel.Sel.Name)
			}
			return true
		}
		if !banned[sel.Sel.Name] {
			return true
		}
		// A .UserScope selector anywhere: a *FileStore reaches a file that
		// does not import the package through another package's API, so
		// the import is no guard for it. ResolveEntry and ParseEntry only
		// package-qualified, in a file that imports the package.
		if sel.Sel.Name != "UserScope" {
			if len(local) == 0 {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && !contains(local, id.Name) {
				return true
			}
		}
		out = append(out, sel.Sel.Name)
		return true
	})
	return out
}

// TestBannedRefsFlagsUserScopeEverywhere: the gate flags a .UserScope
// selector in a file that does not import the keystore package, since a
// value of *FileStore reaches it through another package's API; and still
// flags the package-qualified names where the package is imported.
func TestBannedRefsFlagsUserScopeEverywhere(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want string
	}{
		{"package p\nfunc f(s interface{ UserScope(uint32) }) { s.UserScope(1001) }\n", "UserScope"},
		{"package p\nimport ks \"k3sm.io/k3sm/pkg/keystore\"\nvar _ = ks.ParseEntry\n", "ParseEntry"},
		{"package p\nimport \"k3sm.io/k3sm/pkg/keystore\"\nfunc f(s *keystore.FileStore) { s.UserScope(1001) }\n", "UserScope"},
		{"package p\nfunc f(e struct{ ParseEntry int }) int { return e.ParseEntry }\n", ""},
		{"package p\nimport \"k3sm.io/k3sm/pkg/keystore\"\nfunc f(u interface{ Withdraw(string) }) { u.Withdraw(\"x\") }\nvar _ keystore.Delivery\n", "Withdraw,Delivery"},
		{"package p\nimport ks \"k3sm.io/k3sm/pkg/keystore\"\nfunc f(u interface{ Deliver(ks.FileStore) }) { u.Deliver(ks.FileStore{}) }\n", "Deliver"},
		{"package p\nfunc f(u interface{ Deliver() }) { u.Deliver() }\n", ""},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(bannedRefs(f), ","); got != tc.want {
			t.Errorf("bannedRefs(%q) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestReferenceAllowedOnlySocket: the ban on references is lifted for
// pkg/keystore/socket alone, never its sub-packages, cmd/k3sm or another
// package.
func TestReferenceAllowedOnlySocket(t *testing.T) {
	for dir, want := range map[string]bool{
		"pkg/keystore/socket":      true,
		"pkg/keystore/socket/sub":  false,
		"pkg/keystore/reconcile":   false,
		"cmd/k3sm":                 false,
		"pkg/keystore/socketx":     false,
		"x/pkg/keystore/socket":    false,
		"pkg/keystore/socket/../x": false,
	} {
		if got := referenceAllowed(dir); got != want {
			t.Errorf("referenceAllowed(%q) = %v, want %v", dir, got, want)
		}
	}
}
