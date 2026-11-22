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

// TestUserScopeIsUnexported holds the user scope inside this package until
// the socket slice, which lifts this test: no package outside pkg/keystore
// (its sub-packages and cmd/k3sm included) may reference UserScope,
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
// (CheckLogBounds, then CatchUpUser) has run. And before any exported
// identifier reaches the user scope, the tests of three rows must exist,
// checked with go/ast over their packages' test files (exportPrereqs), so
// the socket slice that lifts the ban cannot land ahead of them. A test
// counts only if its body calls t.Error* or t.Fatal* and never t.Skip,
// t.SkipNow or t.Skipf. An exported identifier reaches the user scope when
// a file outside pkg/keystore references a banned name, or when an exported
// function or method declared in pkg/keystore has a body that references
// UserScope, startUserScopes, ResolveEntry, ParseEntry, Deliver, Withdraw
// or Delivery, past the reasoned allowlist inPackageReachAllow:
//   - U51, the per-uid byte shares, in pkg/keystore/socket:
//     TestLogSharePerUIDRefusesOnlyThatUID, TestLogShareAtMostOneSixteenthOfHardCap,
//     TestShareRefusalIsNotGlobalAppendFailure, TestReadRateLimitPerUID,
//     TestReadsChargedToShare, TestShareExhaustionIsolatedPerUID;
//   - U193, the rebuild, in cmd/k3sm: TestRebuildCarriesTombstonesForward;
//   - U194, the rebuild after rm-scope, in cmd/k3sm:
//     TestRebuildDropsRemovedScopeKeys.
//
// The socket slice lifts the ban on references, never the prerequisite
// check.
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
			t.Errorf("%s references %s: the user scope stays inside pkg/keystore until the socket slice", rel, name)
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
	{"U193", "cmd/k3sm", []string{"TestRebuildCarriesTombstonesForward"}},
	{"U194", "cmd/k3sm", []string{"TestRebuildDropsRemovedScopeKeys"}},
}

// userScopeReach are the names whose reference, in the body of an exported
// function or method declared in pkg/keystore, makes that name an export of
// the user scope.
var userScopeReach = map[string]bool{
	"UserScope": true, "startUserScopes": true, "ResolveEntry": true, "ParseEntry": true,
	"Deliver": true, "Withdraw": true, "Delivery": true,
}

// inPackageReachAllow are the exported names declared in pkg/keystore whose
// bodies already reach the user scope, keyed "<Recv>.<Name>" for a method,
// each with why it is not an export of it.
var inPackageReachAllow = map[string]string{
	"FileStore.UserScope": "the user scope's own constructor, which the outside ban holds",
	"ResolveEntry":        "the entry resolver itself, which the outside ban holds",
	"UserScope.Delivery":  "a method on *UserScope, reachable only through UserScope, which the outside ban holds",
}

// inPackageExports returns, as "<Recv>.<Name>" or "<Name>", each exported
// function or method declared in dir's non-test files whose body
// references a name of userScopeReach, past inPackageReachAllow.
func inPackageExports(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() || fd.Body == nil {
				continue
			}
			reaches := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && userScopeReach[id.Name] {
					reaches = true
				}
				return !reaches
			})
			if !reaches {
				continue
			}
			name := fd.Name.Name
			if r := recvName(fd); r != "" {
				name = r + "." + name
			}
			if _, ok := inPackageReachAllow[name]; !ok {
				out = append(out, name)
			}
		}
	}
	return out, nil
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
// never skips: it holds a call to a selector Error, Errorf, Fatal or Fatalf,
// and none to Skip, SkipNow or Skipf.
func provesSomething(fd *ast.FuncDecl) bool {
	if fd.Body == nil {
		return false
	}
	fails, skips := false, false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Error", "Errorf", "Fatal", "Fatalf":
			fails = true
		case "Skip", "SkipNow", "Skipf":
			skips = true
		}
		return true
	})
	return fails && !skips
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
			b.WriteString("func " + name + "(t *testing.T) { if false { t.Fatal(\"x\") } }\n")
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
		"func Plain() {}\n"
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
	if want := "Wrap,FileStore.Start,Parse"; strings.Join(got, ",") != want {
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

// bannedRefs returns the banned names f references: a .UserScope selector
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
