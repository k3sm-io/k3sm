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

package executor

import (
	"go/ast"
	"strings"
	"testing"
)

// producedComponentNames collects the component names this package produces
// from its source: the name argument of every spawn, bringUpErr and
// provisionStep call that is a string literal or a string const (provisionStep's
// under "provision/").
func producedComponentNames(t *testing.T) map[string]bool {
	t.Helper()
	files := parsePackageFiles(t)
	consts, _ := packageStringConsts(files)
	names := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var fn string
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				fn = fun.Name
			case *ast.SelectorExpr:
				fn = fun.Sel.Name
			}
			arg, prefix := -1, ""
			switch fn {
			case "spawn":
				arg = 1
			case "bringUpErr":
				arg = 0
			case "provisionStep":
				arg, prefix = 0, "provision/"
			}
			if arg < 0 || len(call.Args) <= arg {
				return true
			}
			if v, ok := evalString(call.Args[arg], consts); ok {
				names[prefix+v] = true
			}
			return true
		})
	}
	return names
}

// TestIsComponentNameAcceptsEveryProducedName: every component name the package
// writes into BringUpError.Component or reports through OnComponentExit passes
// IsComponentName, so status never shows a real component as "unknown".
func TestIsComponentNameAcceptsEveryProducedName(t *testing.T) {
	t.Parallel()
	names := producedComponentNames(t)
	for _, want := range []string{"kine", etcdComponent, "kube-apiserver", "kube-scheduler", "kube-controller-manager"} {
		if !names[want] {
			t.Errorf("did not find the supervised child %q in the package's spawn/bringUpErr calls", want)
		}
	}
	provision := 0
	for n := range names {
		if strings.HasPrefix(n, "provision/") {
			provision++
		}
		if !IsComponentName(n) {
			t.Errorf("IsComponentName(%q) = false for a name the package produces", n)
		}
	}
	if provision < 10 {
		t.Errorf("found %d provision/<step> names, want the package's provision steps (at least 10)", provision)
	}
}

// TestIsComponentNameRefusesNonNames: empty, over-long, uppercase, spaced and
// control-byte values are refused.
func TestIsComponentNameRefusesNonNames(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", strings.Repeat("k", 65), "Kine", "kine etcd", "kine\n", "kine\x1b[2J", "kine;rm"} {
		if IsComponentName(s) {
			t.Errorf("IsComponentName(%q) = true", s)
		}
	}
}
