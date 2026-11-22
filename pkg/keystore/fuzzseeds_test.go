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

// TestEveryFuzzTargetHasSeeds (U154): every Fuzz target in pkg/keystore and
// its sub-packages has a committed, non-empty seed directory,
// testdata/fuzz/<Target> beside it, so a plain go test replays a corpus
// that does not depend on the f.Add calls alone.
func TestEveryFuzzTargetHasSeeds(t *testing.T) {
	targets := 0
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); p != "." && (strings.HasPrefix(n, ".") || n == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
				continue
			}
			targets++
			dir := filepath.Join(filepath.Dir(p), "testdata", "fuzz", fn.Name.Name)
			if !hasRegularFile(t, dir) {
				t.Errorf("%s: %s has no committed seeds in %s", p, fn.Name.Name, dir)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if targets == 0 {
		t.Fatal("found no Fuzz target: the walk is broken")
	}
}

// hasRegularFile reports whether dir holds at least one regular file.
func hasRegularFile(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			return true
		}
	}
	return false
}
