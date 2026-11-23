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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// unbuiltVerbs are verbs the store's remedies would name but that are not
// built yet: no string the package returns may name one. floor --rebuild,
// rm-scope and audit --rotate are built, and the remedies name them; none
// is left, and a verb a later slice names in a remedy before it lands is
// added here.
var unbuiltVerbs []string

// staleWording is what a remedy said of a verb while it was not built: no
// string may still say it, now that every verb a remedy names exists.
var staleWording = []string{"not yet available", "not built yet"}

// unbuiltVerbAllow lists "file: verb" pairs allowed to name an unbuilt
// verb. It stays empty: a remedy names the matched-set restore or doctor
// until the verb lands.
var unbuiltVerbAllow = map[string]bool{}

// No string literal in the package's code names a verb that does not exist
// yet, or says a verb is not yet available; comments may, since they
// describe the design.
func TestErrorsNameNoUnbuiltVerb(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := filepath.Glob(filepath.Join("*", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range append(files, sub...) {
		if strings.HasSuffix(f, "_test.go") || strings.HasPrefix(f, "testdata"+string(os.PathSeparator)) {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: %v", fset.Position(lit.Pos()), err)
			}
			for _, w := range staleWording {
				if strings.Contains(s, w) {
					t.Errorf("%s: a string says %q of a verb, but every verb a remedy names is built: name it", fset.Position(lit.Pos()), w)
				}
			}
			for _, v := range unbuiltVerbs {
				if strings.Contains(s, v) && !unbuiltVerbAllow[f+": "+v] {
					t.Errorf("%s: a string names %q, which is not built yet: name the matched-set restore or doctor", fset.Position(lit.Pos()), v)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no source file was checked")
	}
	if len(unbuiltVerbAllow) != 0 {
		t.Fatalf("the allowlist holds %d entries, want none", len(unbuiltVerbAllow))
	}
}
