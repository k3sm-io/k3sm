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

package atomicfile

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The in-place binary write guard.
//
// k3sm must never rewrite a binary in place (see InstallReader): every executable
// or dylib write goes through InstallFile / InstallReader, and every signature
// through internal/binsign, which only signs temps. This test scans the non-test
// Go files under pkg/, cmd/ and internal/ and fails on a NEW occurrence of any of
// three shapes, each the AST of a call:
//
//   - codesign-force: a call whose literal arguments include "codesign" and "-f" or
//     "--force" (a forced re-sign, the in-place rewrite that killed every new pod);
//   - adhocsign: a call of AdHocSign (runtimed's image.AdHocSign, `codesign -f`);
//   - exec-write: os.WriteFile with a literal mode carrying an execute bit,
//     os.OpenFile with O_TRUNC and such a mode, or any function whose name contains
//     "copy" called with such a mode as its last argument (a truncating copy of a
//     binary onto a path).
//
// A finding is allowed only by a line in testdata/inplace-allow.txt naming its
// file, enclosing function and shape, with a reason. An allow line that matches
// nothing fails too, so the list cannot rot.
//
// LIMITS, stated so nobody reads more into a green than it holds: the scan is
// syntactic. It does not see a mode passed in a variable, a codesign argv built in
// a slice, an exec of cp/ditto/install, an io.Copy into a file opened elsewhere,
// or a write into a path that only becomes live later (pkg/install's staged tree,
// swapped in by one rename, is allowed by function for that reason). An allowed
// function stays allowed for any new call of the same shape inside it. It catches
// the shapes the 2026-10-12 audit found and the obvious ways to re-add them;
// review still owns the rest.

// guardFinding is one flagged call.
type guardFinding struct {
	file, fn, rule string
	pos            token.Position
}

func (f guardFinding) key() string { return f.file + " " + f.fn + " " + f.rule }

func TestNoInPlaceBinaryWrites(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var findings []guardFinding
	for _, top := range []string{"pkg", "cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			fs, err := scanFile(path, filepath.ToSlash(rel))
			findings = append(findings, fs...)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	allow := readAllowList(t, filepath.Join("testdata", "inplace-allow.txt"))
	used := map[string]bool{}
	for _, f := range findings {
		if _, ok := allow[f.key()]; ok {
			used[f.key()] = true
			continue
		}
		t.Errorf("%s: %s in %s: a binary must be written through atomicfile.InstallFile/InstallReader and signed only as a temp (binsign.EnsureSigned / binsign.Install); if this is not a binary write, allow-list %q with a reason",
			f.pos, f.rule, f.fn, f.key())
	}
	var stale []string
	for k := range allow {
		if !used[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	for _, k := range stale {
		t.Errorf("stale allow-list entry %q matches nothing; delete it", k)
	}
}

// scanFile parses path and returns its flagged calls, attributed to rel.
func scanFile(path, rel string) ([]guardFinding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var out []guardFinding
	for _, decl := range file.Decls {
		fn := "<package>"
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = funcName(fd)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if rule := classify(call); rule != "" {
				out = append(out, guardFinding{file: rel, fn: fn, rule: rule, pos: fset.Position(call.Pos())})
			}
			return true
		})
	}
	return out, nil
}

// classify returns the guard shape call matches, or "".
func classify(call *ast.CallExpr) string {
	var hasCodesign, hasForce bool
	for _, a := range call.Args {
		switch stringLit(a) {
		case "codesign":
			hasCodesign = true
		case "-f", "--force":
			hasForce = true
		}
	}
	if hasCodesign && hasForce {
		return "codesign-force"
	}
	name := calleeName(call.Fun)
	switch {
	case name == "AdHocSign":
		return "adhocsign"
	case name == "os.WriteFile" && len(call.Args) == 3 && execMode(call.Args[2]):
		return "exec-write"
	case name == "os.OpenFile" && len(call.Args) == 3 && mentions(call.Args[1], "O_TRUNC") && execMode(call.Args[2]):
		return "exec-write"
	case strings.Contains(strings.ToLower(name), "copy") && len(call.Args) > 0 && execMode(call.Args[len(call.Args)-1]):
		return "exec-write"
	}
	return ""
}

// funcName renders a FuncDecl as Name or Recv.Name.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// calleeName renders a call's function as "pkg.Name" for a selector on an
// identifier, the bare name for a selector on anything else or an identifier.
func calleeName(e ast.Expr) string {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok && id.Name == "os" {
			return "os." + f.Sel.Name
		}
		return f.Sel.Name
	}
	return ""
}

// stringLit returns e's value when it is a string literal.
func stringLit(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

// execMode reports whether e is an integer literal with an execute bit set.
func execMode(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseInt(lit.Value, 0, 64)
	return err == nil && v&0o111 != 0
}

// mentions reports whether e contains an identifier or selector named name.
func mentions(e ast.Expr, name string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// readAllowList reads "<file> <func> <rule>  # reason" lines. A line without a
// reason is refused: an exception nobody explained is one nobody can review.
func readAllowList(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	allow := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, reason, _ := strings.Cut(line, "#")
		fields := strings.Fields(entry)
		if len(fields) != 3 || strings.TrimSpace(reason) == "" {
			t.Fatalf("%s:%d: want \"<file> <func> <rule>  # reason\", got %q", path, n, line)
		}
		allow[strings.Join(fields, " ")] = strings.TrimSpace(reason)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return allow
}
