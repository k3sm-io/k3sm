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
	banned := map[string]bool{"UserScope": true, "ResolveEntry": true, "ParseEntry": true}
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
		if len(local) == 0 {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !banned[sel.Sel.Name] {
				return true
			}
			// A package-qualified reference, or a method call on a value
			// (FileStore.UserScope), in a file that imports the package.
			if id, ok := sel.X.(*ast.Ident); ok && !contains(local, id.Name) && sel.Sel.Name != "UserScope" {
				return true
			}
			rel, _ := filepath.Rel(root, p)
			t.Errorf("%s references %s: the user scope stays inside pkg/keystore until the socket slice", rel, sel.Sel.Name)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("scanned only %d files under %s", files, root)
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
