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

package provider

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// declaredFuncs returns the names of the top-level functions declared in file.
func declaredFuncs(t *testing.T, file string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string]bool{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
			out[fd.Name.Name] = true
		}
	}
	return out
}

// TestTranslateSplitLayout pins the spec/status split of the pod translator:
// translate.go holds the spec direction (toPodBox), translate_status.go the
// status direction (toPodStatus, derivePhase). The line ceiling is
// intentionally generous; it guards the split against re-merging, not size.
func TestTranslateSplitLayout(t *testing.T) {
	spec := declaredFuncs(t, "translate.go")
	status := declaredFuncs(t, "translate_status.go")

	for _, name := range []string{"toPodStatus", "derivePhase"} {
		if !status[name] {
			t.Errorf("%s must be declared in translate_status.go", name)
		}
		if spec[name] {
			t.Errorf("%s must not be declared in translate.go", name)
		}
	}
	if !spec["toPodBox"] {
		t.Error("toPodBox must be declared in translate.go")
	}
	if status["toPodBox"] {
		t.Error("toPodBox must not be declared in translate_status.go")
	}

	const maxLines = 1400
	b, err := os.ReadFile("translate.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n > maxLines {
		t.Errorf("translate.go has %d lines, ceiling %d: keep the status half in translate_status.go", n, maxLines)
	}
}
