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

package install

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// declNames returns the top-level func/method keys ("Recv.Name" or "Name") and
// every top-level declared name (funcs, types, consts, vars) of one file.
func declNames(t *testing.T, path string) (funcs []string, all map[string]bool) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	all = map[string]bool{}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			key := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) == 1 {
				expr := d.Recv.List[0].Type
				if s, ok := expr.(*ast.StarExpr); ok {
					expr = s.X
				}
				if id, ok := expr.(*ast.Ident); ok {
					key = id.Name + "." + key
				}
			}
			funcs = append(funcs, key)
			all[d.Name.Name] = true
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					all[s.Name.Name] = true
				case *ast.ValueSpec:
					for _, n := range s.Names {
						all[n.Name] = true
					}
				}
			}
		}
	}
	return funcs, all
}

// TestInstallGoHoldsOnlyOrchestration pins the by-concern split of the former
// install.go: each concern's anchors live in their own file and nowhere in
// install.go, which keeps only the orchestration.
func TestInstallGoHoldsOnlyOrchestration(t *testing.T) {
	anchors := map[string][]string{
		"plist.go":    {"NetdPlist", "renderPlist"},
		"legacy.go":   {"adoptPodLogTree", "migrateLegacyMeshKeys"},
		"meshkey.go":  {"provisionMeshKey", "readMeshKey"},
		"linkdir.go":  {"linkDirVerdict", "linkDirTrustTarget"},
		"manifest.go": {"artifactManifest", "keptArtifacts"},
	}
	files := []string{"install.go", "plist.go", "legacy.go", "meshkey.go", "linkdir.go", "manifest.go"}

	declared := map[string]map[string]bool{}
	// The compiler already rejects a duplicate top-level func/method within a
	// package; checking here makes the failure name the two files.
	seenFunc := map[string]string{}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s must exist: %v", f, err)
		}
		funcs, all := declNames(t, f)
		declared[f] = all
		for _, k := range funcs {
			if prev, dup := seenFunc[k]; dup {
				t.Errorf("%s declared in both %s and %s", k, prev, f)
			}
			seenFunc[k] = f
		}
	}

	for f, names := range anchors {
		for _, n := range names {
			if !declared[f][n] {
				t.Errorf("%s must declare %s", f, n)
			}
			if declared["install.go"][n] {
				t.Errorf("install.go must not declare %s (it lives in %s)", n, f)
			}
		}
	}

	for _, n := range []string{"Install", "Uninstall", "uninstall", "publishedWiring", "deregisterNode", "MeshKeyDir"} {
		if !declared["install.go"][n] {
			t.Errorf("install.go must declare %s", n)
		}
	}

	// Intentionally generous: this guards the split, not a precise size. It is
	// red at the pre-split 4,366 lines.
	const maxLines = 3000
	b, err := os.ReadFile("install.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n > maxLines {
		t.Errorf("install.go is %d lines, want at most %d", n, maxLines)
	}
}
