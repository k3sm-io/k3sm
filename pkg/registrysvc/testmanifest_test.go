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

package registrysvc

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testManifestPath lists every test this package has had since the registry child
// moved to `k3sm registry serve`, one per line: name, status, reason.
const testManifestPath = "testdata/test-manifest.txt"

// packageTestNames parses every _test.go file here, whatever its build tag, for
// the Test, Fuzz and Benchmark functions it declares.
func packageTestNames(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range files {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			for _, prefix := range []string{"Test", "Fuzz", "Benchmark"} {
				if rest, ok := strings.CutPrefix(fn.Name.Name, prefix); ok && rest != "" && fn.Name.Name != "TestMain" && strings.ToUpper(rest[:1]) == rest[:1] {
					names = append(names, fn.Name.Name)
				}
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// TestTestManifestIsComplete keeps a test from leaving silently: every test in the
// package is listed with a reason, a test listed as kept, rewritten or added
// exists, and a test listed as deleted does not.
func TestTestManifestIsComplete(t *testing.T) {
	f, err := os.Open(testManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	have := packageTestNames(t)
	listed := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) < 2 {
			t.Errorf("malformed line %q", line)
			continue
		}
		name, status := fields[0], fields[1]
		reason := ""
		if len(fields) == 3 {
			reason = strings.TrimSpace(fields[2])
		}
		if listed[name] {
			t.Errorf("%s is listed twice", name)
		}
		if reason == "" {
			t.Errorf("%s has no reason", name)
		}
		listed[name] = true
		exists := slices.Contains(have, name)
		switch status {
		case "kept", "rewritten", "added":
			if !exists {
				t.Errorf("%s is listed %s and does not exist", name, status)
			}
		case "deleted":
			if exists {
				t.Errorf("%s is listed deleted and still exists", name)
			}
		default:
			t.Errorf("%s has unknown status %q", name, status)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for _, name := range have {
		if !listed[name] {
			t.Errorf("%s is not in %s", name, testManifestPath)
		}
	}
}
