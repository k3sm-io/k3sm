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
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestDaemonLoggerSetsDefault is deliberately not t.Parallel: slog.SetDefault
// is process-global, so a parallel test would race every other logger user.
func TestDaemonLoggerSetsDefault(t *testing.T) {
	t.Run("installs the process default", func(t *testing.T) {
		prev := slog.Default()
		t.Cleanup(func() { slog.SetDefault(prev) })

		var buf bytes.Buffer
		newDaemonLogger(&buf, slog.LevelDebug)
		slog.Debug("x", "k", "v")
		slog.Default().Debug("y")

		out := buf.String()
		for _, msg := range []string{"msg=x", "msg=y"} {
			var found bool
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, msg) && strings.Contains(line, "level=DEBUG") && strings.HasPrefix(line, "time=") {
					found = true
				}
			}
			if !found {
				t.Errorf("no text-format DEBUG line for %s in %q", msg, out)
			}
		}
	})

	t.Run("no legacy log calls in daemon commands", func(t *testing.T) {
		files := []string{"agent.go", "node.go", "netd.go", "datavol.go"}
		more, err := filepath.Glob("server*.go")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range more {
			if !strings.HasSuffix(f, "_test.go") {
				files = append(files, f)
			}
		}
		for _, f := range files {
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			name := ""
			for _, imp := range af.Imports {
				if p, _ := strconv.Unquote(imp.Path.Value); p == "log" {
					name = "log"
					if imp.Name != nil {
						name = imp.Name.Name
					}
				}
			}
			if name == "" {
				continue
			}
			ast.Inspect(af, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if ok && id.Name == name && id.Obj == nil && (strings.HasPrefix(sel.Sel.Name, "Print") || strings.HasPrefix(sel.Sel.Name, "Fatal")) {
					t.Errorf("%s uses legacy log.%s; use the structured logger", f, sel.Sel.Name)
				}
				return true
			})
		}
	})
}
