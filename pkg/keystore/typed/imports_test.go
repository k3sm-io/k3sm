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

package typed

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestImportsLeafOnly keeps the package a leaf: the standard library,
// golang.org/x/crypto/ssh (already a direct dependency) and the credential
// names in k3sm.io/apis, and nothing of Kubernetes or of pkg/keystore.
func TestImportsLeafOnly(t *testing.T) {
	allowed := map[string]bool{"golang.org/x/crypto/ssh": true, "k3sm.io/apis/keystore/credential": true}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(p, "/")
			if !strings.Contains(first, ".") || allowed[p] {
				continue
			}
			t.Errorf("%s imports %s, outside the leaf's allowed set", n, p)
		}
	}
}
