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
// these call shapes:
//
//   - codesign-force: a call whose literal arguments include "codesign" and "-f" or
//     "--force" (a forced re-sign, the in-place rewrite that killed every new pod);
//   - codesign: any call with a literal "codesign" argument outside internal/binsign
//     (read-only inspections elsewhere are allow-listed one by one);
//   - sign-call: any method call named Sign with two or more arguments outside
//     internal/binsign (the seam's
//     callers, and unrelated crypto signers, are allow-listed one by one);
//   - adhocsign: a call of AdHocSign (runtimed's image.AdHocSign, `codesign -f`);
//   - exec-write: os.WriteFile with a literal mode carrying an execute bit,
//     os.OpenFile with O_TRUNC and such a mode, or any function whose name contains
//     "copy" called with such a mode as its last argument;
//   - bin-write: os.WriteFile, or os.OpenFile with O_TRUNC, whose path argument is
//     built by a known bin-dir helper (binDir, ZotPath, HelmPath, ...), whatever the
//     mode;
//   - truncate: os.Create (which always truncates), or unix.Open / syscall.Open
//     with O_TRUNC.
//
// A finding is allowed only by a line in testdata/inplace-allow.txt naming its
// file, enclosing function and shape, with a reason. An allow line that matches
// nothing fails too, so the list cannot rot.
//
// THIS IS A REGRESSION TRIPWIRE FOR KNOWN SHAPES, NOT PROOF. It is syntactic: it
// does not see a mode or a path passed through a variable it does not recognise, a
// codesign argv built in a slice, an exec of cp/ditto/install, an io.Copy into a
// file opened elsewhere, or a write into a path that only becomes live later. An
// allowed function stays allowed for any new call of the same shape inside it. A
// green run means none of these shapes was added, nothing more; review owns the
// rest, and the behavioural tests (TestBinaryStagingNeverRewritesALiveInode and
// its siblings) own the guarantee.

// signHome is the one package allowed to invoke codesign and call Sign.
const signHome = "internal/binsign/"

// binDirHelpers are the functions and fields that name a binary directory or a
// staged binary path; a write whose path mentions one is a bin-write.
var binDirHelpers = map[string]bool{
	"binDir": true, "BinDir": true, "binPath": true, "kinePath": true, "ZotPath": true,
	"HelmPath": true, "devBinDir": true, "freshBinDir": true, "rootExecShimDir": true,
	"podShimDir": true, "stagedShadowDir": true,
}

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
			if rule := classify(call, strings.HasPrefix(rel, signHome)); rule != "" {
				out = append(out, guardFinding{file: rel, fn: fn, rule: rule, pos: fset.Position(call.Pos())})
			}
			return true
		})
	}
	return out, nil
}

// classify returns the guard shape call matches, or "". inSignHome exempts the
// sanctioned signer from the codesign and sign-call shapes (never from
// codesign-force).
func classify(call *ast.CallExpr, inSignHome bool) string {
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
	if hasCodesign && !inSignHome {
		return "codesign"
	}
	name := calleeName(call.Fun)
	// Two or more arguments: a signer takes at least a context and a path, and
	// that keeps a numeric Sign() (resource.Quantity) out of it.
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Sign" && len(call.Args) >= 2 && !inSignHome {
		return "sign-call"
	}
	nargs := len(call.Args)
	switch {
	case name == "AdHocSign":
		return "adhocsign"
	case name == "os.WriteFile" && nargs == 3 && execMode(call.Args[2]):
		return "exec-write"
	case name == "os.OpenFile" && nargs == 3 && mentions(call.Args[1], "O_TRUNC") && execMode(call.Args[2]):
		return "exec-write"
	case strings.Contains(strings.ToLower(name), "copy") && nargs > 0 && execMode(call.Args[nargs-1]):
		return "exec-write"
	case name == "os.WriteFile" && nargs == 3 && mentionsAny(call.Args[0], binDirHelpers):
		return "bin-write"
	case name == "os.OpenFile" && nargs == 3 && mentions(call.Args[1], "O_TRUNC") && mentionsAny(call.Args[0], binDirHelpers):
		return "bin-write"
	case name == "os.Create":
		return "truncate"
	case (name == "unix.Open" || name == "syscall.Open") && nargs >= 2 && mentions(call.Args[1], "O_TRUNC"):
		return "truncate"
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
		if id, ok := f.X.(*ast.Ident); ok && (id.Name == "os" || id.Name == "unix" || id.Name == "syscall") {
			return id.Name + "." + f.Sel.Name
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

// mentionsAny reports whether e contains an identifier in names.
func mentionsAny(e ast.Expr, names map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
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

// TestGuardClassifies proves every shape fires on a minimal call, and that the
// exemptions hold, so a green TestNoInPlaceBinaryWrites is not vacuous.
func TestGuardClassifies(t *testing.T) {
	tests := []struct {
		src        string
		inSignHome bool
		want       string
	}{
		{`exec.Command("codesign", "-s", "-", "-f", p)`, false, "codesign-force"},
		{`exec.Command("codesign", "-s", "-", "-f", p)`, true, "codesign-force"},
		{`exec.Command("codesign", "-dv", p)`, false, "codesign"},
		{`exec.Command("codesign", "-dv", p)`, true, ""},
		{`s.Sign(ctx, tmp, id)`, false, "sign-call"},
		{`s.Sign(ctx, tmp, id)`, true, ""},
		{`q.Sign()`, false, ""},
		{`image.AdHocSign(ctx, p)`, false, "adhocsign"},
		{`os.WriteFile(p, b, 0o755)`, false, "exec-write"},
		{`os.WriteFile(p, b, 0o644)`, false, ""},
		{`os.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0o700)`, false, "exec-write"},
		{`copyFile(a, b, 0o755)`, false, "exec-write"},
		{`os.WriteFile(filepath.Join(binDir(w), n), b, mode)`, false, "bin-write"},
		{`os.OpenFile(ZotPath(bd), os.O_WRONLY|os.O_TRUNC, m)`, false, "bin-write"},
		{`os.Create(p)`, false, "truncate"},
		{`unix.Open(p, unix.O_WRONLY|unix.O_TRUNC, 0o644)`, false, "truncate"},
		{`syscall.Open(p, syscall.O_TRUNC, 0)`, false, "truncate"},
		{`unix.Open(p, unix.O_RDONLY, 0)`, false, ""},
	}
	for _, tc := range tests {
		e, err := parser.ParseExpr(tc.src)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.src, err)
		}
		call, ok := e.(*ast.CallExpr)
		if !ok {
			t.Fatalf("%s is not a call", tc.src)
		}
		if got := classify(call, tc.inSignHome); got != tc.want {
			t.Errorf("classify(%s, signHome=%v) = %q, want %q", tc.src, tc.inSignHome, got, tc.want)
		}
	}
}
