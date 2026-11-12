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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// moduleFile is one parsed non-test .go file of the k3sm module.
type moduleFile struct {
	dir  string // slash path relative to the module root, e.g. "cmd/k3sm"
	file *ast.File
}

// parseModuleFiles parses every non-test .go file of this module, skipping
// testdata, hidden directories and nested modules.
func parseModuleFiles(t *testing.T, fset *token.FileSet) []moduleFile {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s: %v", root, err)
	}
	var out []moduleFile
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			if p != root {
				if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			return err
		}
		out = append(out, moduleFile{dir: filepath.ToSlash(rel), file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// remedySink is a place a value flows into a crash record's Remedy: an
// argument position of a named function (a parameter that reaches the field).
type remedySink struct {
	dir  string // the declaring package dir; calls of an exported name match from any dir
	name string
	arg  int
}

// remedyGuard walks every value the crash-record writer can be handed and
// checks that each one is a value IsKnownRemedy accepts.
type remedyGuard struct {
	t       *testing.T
	fset    *token.FileSet
	files   []moduleFile
	consts  map[string]string // pkg/executor's string consts
	funcs   map[string]map[string]*ast.FuncDecl
	checked map[string]int // dir -> accepted leaves
}

const executorDir = "pkg/executor"

// TestEveryRecordedRemedyIsKnown: every value that can reach a crash record's
// Remedy field, in any package of this module, is one IsKnownRemedy accepts. The
// field is reached through a Crash composite literal, an assignment to .Remedy
// in pkg/executor, or a parameter of a function that does either, followed
// transitively to every caller (RecordPermanent, then cmd/k3sm's
// recordBringUpPermanent). Each argument is then resolved through local
// variables, range-over-literal fields and same-package helpers to its leaves,
// and a leaf must be a pkg/executor string const IsKnownRemedy accepts or a
// call of EtcdSupersededError.Remedy. A string literal, a Sprintf, or a const
// defined outside pkg/executor fails here instead of being shown as the generic
// remedy at status time.
func TestEveryRecordedRemedyIsKnown(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	g := &remedyGuard{t: t, fset: fset, files: parseModuleFiles(t, fset),
		funcs: map[string]map[string]*ast.FuncDecl{}, checked: map[string]int{}}
	var execFiles []*ast.File
	for _, mf := range g.files {
		if mf.dir == executorDir {
			execFiles = append(execFiles, mf.file)
		}
		for _, d := range mf.file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if g.funcs[mf.dir] == nil {
					g.funcs[mf.dir] = map[string]*ast.FuncDecl{}
				}
				// A method and a function can share a name; the guard only needs one
				// declaration per name to follow returns, and records every Remedy
				// method below.
				if _, dup := g.funcs[mf.dir][fd.Name.Name]; !dup || fd.Recv == nil {
					g.funcs[mf.dir][fd.Name.Name] = fd
				}
			}
		}
	}
	g.consts, _ = packageStringConsts(execFiles)

	// The one Remedy() method a leaf may call is EtcdSupersededError's; a second
	// would make a `.Remedy()` leaf ambiguous without type information.
	for _, mf := range g.files {
		for _, d := range mf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "Remedy" {
				continue
			}
			if mf.dir != executorDir || recvTypeName(fd) != "EtcdSupersededError" {
				t.Errorf("%s: a Remedy method on %s; teach this guard to tell it from EtcdSupersededError.Remedy",
					g.fset.Position(fd.Pos()), recvTypeName(fd))
			}
		}
	}

	// Direct writes of the field, then every parameter that reaches one.
	var queue []remedySink
	seen := map[remedySink]bool{}
	push := func(s remedySink) {
		if !seen[s] {
			seen[s] = true
			queue = append(queue, s)
		}
	}
	for _, mf := range g.files {
		for _, d := range mf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CompositeLit:
					if !isCrashType(n.Type, mf.dir) {
						return true
					}
					for _, e := range n.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok && identName(kv.Key) == "Remedy" {
							g.resolve(mf.dir, fd, kv.Value, push)
						}
					}
				case *ast.AssignStmt:
					if mf.dir != executorDir {
						return true
					}
					for i, l := range n.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Remedy" {
							if len(n.Rhs) != len(n.Lhs) {
								g.t.Errorf("%s: a .Remedy assignment this guard cannot pair with its value", g.fset.Position(n.Pos()))
								continue
							}
							g.resolve(mf.dir, fd, n.Rhs[i], push)
						}
					}
				}
				return true
			})
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		g.callsOf(s, func(dir string, fd *ast.FuncDecl, arg ast.Expr) {
			g.resolve(dir, fd, arg, push)
		})
	}

	if g.checked[executorDir] == 0 || g.checked["cmd/k3sm"] == 0 {
		t.Errorf("accepted remedies by package = %v; expected writes from pkg/executor and cmd/k3sm, so the walk is broken", g.checked)
	}
	var names []string
	for s := range seen {
		names = append(names, s.dir+"."+s.name)
	}
	sort.Strings(names)
	t.Logf("remedy parameters followed: %v; accepted leaves by package: %v", names, g.checked)
}

// callsOf calls visit with the sink's argument at every call of the sink's
// function: from its own package by plain name or selector, and from any
// package by selector when the name is exported.
func (g *remedyGuard) callsOf(s remedySink, visit func(dir string, fd *ast.FuncDecl, arg ast.Expr)) {
	exported := ast.IsExported(s.name)
	for _, mf := range g.files {
		for _, d := range mf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				match := false
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					match = fun.Name == s.name && mf.dir == s.dir
				case *ast.SelectorExpr:
					match = fun.Sel.Name == s.name && (exported || mf.dir == s.dir)
				}
				if !match {
					return true
				}
				if s.arg >= len(call.Args) {
					g.t.Errorf("%s: a call of %s with no remedy argument %d", g.fset.Position(call.Pos()), s.name, s.arg)
					return true
				}
				visit(mf.dir, fd, call.Args[s.arg])
				return true
			})
		}
	}
}

// resolve follows e, an expression inside fd in package dir, to its leaves and
// checks each; a parameter of fd becomes a new sink.
func (g *remedyGuard) resolve(dir string, fd *ast.FuncDecl, e ast.Expr, push func(remedySink)) {
	g.resolveDepth(dir, fd, e, push, 0)
}

func (g *remedyGuard) resolveDepth(dir string, fd *ast.FuncDecl, e ast.Expr, push func(remedySink), depth int) {
	pos := g.fset.Position(e.Pos())
	if depth > 16 {
		g.t.Errorf("%s: remedy expression nests too deep to follow", pos)
		return
	}
	fail := func(why string) {
		g.t.Errorf("%s: a crash-record remedy that is %s; it must be a pkg/executor *Remedy const IsKnownRemedy accepts, or EtcdSupersededError.Remedy()",
			pos, why)
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		g.resolveDepth(dir, fd, e.X, push, depth+1)
	case *ast.Ident:
		if i := paramIndex(fd, e.Name); i >= 0 {
			push(remedySink{dir: dir, name: fd.Name.Name, arg: i})
			return
		}
		if dir == executorDir {
			if v, ok := g.consts[e.Name]; ok {
				g.accept(dir, pos, e.Name, v)
				return
			}
		}
		values, ok := localValues(fd, e.Name)
		if !ok {
			fail(fmt.Sprintf("the identifier %s, which is not a const of pkg/executor or a local this guard can follow", e.Name))
			return
		}
		for _, v := range values {
			g.resolveDepth(dir, fd, v, push, depth+1)
		}
	case *ast.SelectorExpr:
		x, ok := e.X.(*ast.Ident)
		if !ok {
			fail("a selector this guard cannot follow")
			return
		}
		if x.Name == "executor" {
			v, ok := g.consts[e.Sel.Name]
			if !ok {
				fail("executor." + e.Sel.Name + ", which is not a string const of pkg/executor")
				return
			}
			g.accept(dir, pos, e.Sel.Name, v)
			return
		}
		values, ok := rangeFieldValues(fd, x.Name, e.Sel.Name)
		if !ok {
			fail(fmt.Sprintf("the field %s.%s, which is not a field of a range over a literal", x.Name, e.Sel.Name))
			return
		}
		for _, v := range values {
			g.resolveDepth(dir, fd, v, push, depth+1)
		}
	case *ast.CallExpr:
		switch fun := e.Fun.(type) {
		case *ast.SelectorExpr:
			if fun.Sel.Name == "Remedy" && len(e.Args) == 0 {
				// The only Remedy method in the module is EtcdSupersededError's
				// (checked above), and IsSupersededRemedy owns its output.
				g.checked[dir]++
				return
			}
		case *ast.Ident:
			if callee := g.funcs[dir][fun.Name]; callee != nil && callee.Body != nil {
				returns := 0
				ast.Inspect(callee.Body, func(n ast.Node) bool {
					if _, lit := n.(*ast.FuncLit); lit {
						return false
					}
					if r, ok := n.(*ast.ReturnStmt); ok {
						returns++
						if len(r.Results) != 1 {
							g.t.Errorf("%s: %s returns a remedy this guard cannot pick out", g.fset.Position(r.Pos()), fun.Name)
							return false
						}
						g.resolveDepth(dir, callee, r.Results[0], push, depth+1)
					}
					return true
				})
				if returns == 0 {
					fail("returned by " + fun.Name + ", which has no return to follow")
				}
				return
			}
		}
		fail("built by a call this guard cannot follow")
	case *ast.BasicLit:
		fail("a literal " + e.Value)
	default:
		fail(fmt.Sprintf("a %T expression", e))
	}
}

func (g *remedyGuard) accept(dir string, pos token.Position, name, v string) {
	if !IsKnownRemedy(v) {
		g.t.Errorf("%s: the crash-record remedy %s is not accepted by IsKnownRemedy; add it to knownRemedies", pos, name)
		return
	}
	g.checked[dir]++
}

// isCrashType reports whether t names the crash record's entry type.
func isCrashType(t ast.Expr, dir string) bool {
	switch t := t.(type) {
	case *ast.Ident:
		return dir == executorDir && t.Name == "Crash"
	case *ast.SelectorExpr:
		return identName(t.X) == "executor" && t.Sel.Name == "Crash"
	}
	return false
}

func identName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func recvTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	return identName(t)
}

// paramIndex is name's position in fd's parameter list, or -1.
func paramIndex(fd *ast.FuncDecl, name string) int {
	i := 0
	for _, f := range fd.Type.Params.List {
		if len(f.Names) == 0 {
			i++
			continue
		}
		for _, n := range f.Names {
			if n.Name == name {
				return i
			}
			i++
		}
	}
	return -1
}

// localValues returns every value assigned to the local name in fd, and false
// when it is assigned in a way this guard cannot follow (+=, a multi-value
// assignment) or not at all.
func localValues(fd *ast.FuncDecl, name string) (values []ast.Expr, ok bool) {
	ok = true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				if identName(l) != name {
					continue
				}
				if (n.Tok != token.DEFINE && n.Tok != token.ASSIGN) || len(n.Rhs) != len(n.Lhs) {
					ok = false
					continue
				}
				values = append(values, n.Rhs[i])
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if id.Name != name {
					continue
				}
				if len(n.Values) != len(n.Names) {
					ok = false
					continue
				}
				values = append(values, n.Values[i])
			}
		case *ast.RangeStmt:
			if identName(n.Key) == name || identName(n.Value) == name {
				ok = false
			}
		}
		return true
	})
	return values, ok && len(values) > 0
}

// rangeFieldValues returns field's value in every element of the literal that
// a `for _, v := range <literal>` in fd ranges v over.
func rangeFieldValues(fd *ast.FuncDecl, v, field string) (values []ast.Expr, ok bool) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		r, isRange := n.(*ast.RangeStmt)
		if !isRange || identName(r.Value) != v {
			return true
		}
		lit, isLit := r.X.(*ast.CompositeLit)
		if !isLit {
			return false
		}
		arr, isArr := lit.Type.(*ast.ArrayType)
		if !isArr {
			return false
		}
		st, isStruct := arr.Elt.(*ast.StructType)
		if !isStruct {
			return false
		}
		idx, i := -1, 0
		for _, f := range st.Fields.List {
			for _, n := range f.Names {
				if n.Name == field {
					idx = i
				}
				i++
			}
		}
		if idx < 0 {
			return false
		}
		for _, el := range lit.Elts {
			cl, isCL := el.(*ast.CompositeLit)
			if !isCL {
				return false
			}
			var got ast.Expr
			for j, fe := range cl.Elts {
				if kv, isKV := fe.(*ast.KeyValueExpr); isKV {
					if identName(kv.Key) == field {
						got = kv.Value
					}
				} else if j == idx {
					got = fe
				}
			}
			if got == nil {
				return false
			}
			values = append(values, got)
		}
		ok = len(values) > 0
		return false
	})
	return values, ok
}
