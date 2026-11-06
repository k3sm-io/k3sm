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

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestSystemToolsRunByAbsolutePath reads this package's source: a command named by
// a string literal has to be an absolute path, so PATH does not choose the program.
func TestSystemToolsRunByAbsolutePath(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || recv.Name != "exec" {
					return true
				}
				var arg ast.Expr
				switch sel.Sel.Name {
				case "Command":
					arg = call.Args[0]
				case "CommandContext":
					arg = call.Args[1]
				default:
					return true
				}
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err != nil || !strings.HasPrefix(v, "/") {
						t.Errorf("%s: exec.%s(%s), want an absolute path", fset.Position(lit.Pos()), sel.Sel.Name, lit.Value)
					}
				}
				return true
			})
		}
	}
}
