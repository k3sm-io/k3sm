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
	"path/filepath"
	"strings"
	"testing"
)

// TestGPUCapacityImportedFromItsOwnPackage pins that the node-wide GPU capacity
// rules live in pkg/gpucapacity and that this package reaches them there, not
// through pkg/mlx. It fails while any file here selects a capacity identifier
// off the mlx import, or while pkg/mlx still carries capacity.go.
func TestGPUCapacityImportedFromItsOwnPackage(t *testing.T) {
	const mlxPath = "k3sm.io/k3sm/pkg/mlx"
	const ownPath = "k3sm.io/k3sm/pkg/gpucapacity"

	if _, err := os.Stat(filepath.Join("..", "mlx", "capacity.go")); err == nil {
		t.Error("pkg/mlx/capacity.go still exists; the GPU capacity rules belong in pkg/gpucapacity")
	}
	if _, err := os.Stat(filepath.Join("..", "gpucapacity", "capacity.go")); err != nil {
		t.Errorf("pkg/gpucapacity/capacity.go: %v", err)
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	usesOwn := false
	fset := token.NewFileSet()
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		mlxName := ""
		for _, imp := range f.Imports {
			switch strings.Trim(imp.Path.Value, `"`) {
			case ownPath:
				usesOwn = true
			case mlxPath:
				mlxName = "mlx"
				if imp.Name != nil {
					mlxName = imp.Name.Name
				}
			}
		}
		if mlxName == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if ok && id.Name == mlxName && strings.Contains(sel.Sel.Name, "GPU") {
				t.Errorf("%s: %s.%s reads the GPU capacity rules through pkg/mlx; import %s", fset.Position(sel.Pos()), id.Name, sel.Sel.Name, ownPath)
			}
			return true
		})
	}
	if !usesOwn {
		t.Errorf("no file in pkg/provider imports %s", ownPath)
	}
}
