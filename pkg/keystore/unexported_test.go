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
// ResolveEntry or ParseEntry. ParseEntry is held whole, since a reference
// cannot be told to use only its system form without types.
//
// The order is what makes the hold matter. The socket is the first
// production caller of the user scope, and it lands after the change that
// adds the delivery record (kind 0xFD). So no production scope can exist
// without its deliveries record, and no migration is needed for scopes this
// build's mint wrote without one; it also keeps the floor gap
// (userscope.go) out of reach until the user-scope floor lands.
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
	files := 0
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
}

// bannedRefs returns the banned names f references: a .UserScope selector
// in any file, and a package-qualified ResolveEntry or ParseEntry in a file
// that imports the keystore package (or any such selector there whose
// receiver is not a plain name).
func bannedRefs(f *ast.File) []string {
	banned := map[string]bool{"UserScope": true, "ResolveEntry": true, "ParseEntry": true}
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
		if !ok || !banned[sel.Sel.Name] {
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
