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
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	modulePath  = "k3sm.io/k3sm"
	executorDir = "pkg/executor"
	execPath    = modulePath + "/" + executorDir
)

// Floors of TestEveryRecordedRemedyIsKnown: what the walk finds in today's
// tree. A walk that finds less is broken, not clean. Raise these when a remedy
// or a Crash literal is added.
const (
	minCrashLiteralSites  = 8 // Crash composite literals, typed or elided, in non-test code
	minDistinctRemedyCons = 8 // distinct pkg/executor remedy consts reaching a crash record
)

// remedyAssignAllowed lists, by file, the receiver names whose `.Remedy = ...`
// assignments are status rows or verdicts, not crash records, and whose type
// this guard cannot see from a declaration in the same function (the variable
// is the result of a call). Every other `.Remedy` assignment in the module is
// checked as a crash-record write. An entry that no assignment uses fails, so
// the list cannot outlive the code it excuses.
var remedyAssignAllowed = map[string][]string{
	"pkg/status/agent.go":  {"row"}, // the Row agentRow builds from c.daemonRow
	"pkg/status/update.go": {"r"},   // the Row UpdateRowFrom and updateRowWith return
}

// moduleFile is one parsed non-test .go file of the k3sm module.
type moduleFile struct {
	dir     string // slash path relative to the module root, e.g. "cmd/k3sm"
	path    string // slash path of the file relative to the module root
	file    *ast.File
	imports map[string]string // local qualifier -> import path
}

// parseModuleFiles parses every non-test .go file of this module, skipping
// testdata, hidden directories and nested modules.
func parseModuleFiles(t *testing.T, fset *token.FileSet) []*moduleFile {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("module root %s: %v", root, err)
	}
	if !strings.HasPrefix(string(gomod), "module "+modulePath+"\n") {
		t.Fatalf("%s/go.mod does not declare module %s", root, modulePath)
	}
	var out []*moduleFile
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
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		out = append(out, &moduleFile{dir: path.Dir(rel), path: rel, file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Each file's import table, naming module packages by their declared
	// package name and other imports by the last path element.
	pkgNames := map[string]string{}
	for _, mf := range out {
		pkgNames[modulePath+"/"+mf.dir] = mf.file.Name.Name
	}
	for _, mf := range out {
		mf.imports = map[string]string{}
		for _, is := range mf.file.Imports {
			p, err := strconv.Unquote(is.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			name := path.Base(p)
			if n, ok := pkgNames[p]; ok {
				name = n
			}
			if is.Name != nil {
				name = is.Name.Name
			}
			switch name {
			case "_":
			case ".":
				if strings.HasPrefix(p, modulePath+"/") {
					t.Errorf("%s: a dot import of %s hides which package a Crash or remedy name belongs to; import it by name",
						fset.Position(is.Pos()), p)
				}
			default:
				mf.imports[name] = p
			}
		}
	}
	return out
}

// importPath is the package a qualifier x names in mf, and false when x is not
// an import qualifier.
func (mf *moduleFile) importPath(x ast.Expr) (string, bool) {
	id, ok := x.(*ast.Ident)
	if !ok {
		return "", false
	}
	p, ok := mf.imports[id.Name]
	return p, ok
}

// remedySink is a place a value flows into a crash record's Remedy: an
// argument position of a named function or method (a parameter that reaches
// the field).
type remedySink struct {
	dir  string // the declaring package dir
	recv string // the receiver type name, "" for a function
	name string
	arg  int
}

type funcRef struct {
	mf *moduleFile
	fd *ast.FuncDecl
}

type typeRef struct {
	mf   *moduleFile
	spec *ast.TypeSpec
}

// remedyGuard walks every value the crash-record writer can be handed and
// checks that each one is a value IsKnownRemedy accepts.
type remedyGuard struct {
	t         *testing.T
	fset      *token.FileSet
	files     []*moduleFile
	consts    map[string]string // pkg/executor's string consts
	funcs     map[string]map[string]funcRef
	types     map[string]map[string]typeRef
	checked   map[string]int  // dir -> accepted leaves
	accepted  map[string]bool // distinct pkg/executor consts accepted
	crashLits int
	allowUsed map[string]bool // "file receiver" entries of remedyAssignAllowed used
}

// TestEveryRecordedRemedyIsKnown: every value that can reach a crash record's
// Remedy field, in any package of this module, is one IsKnownRemedy accepts. The
// field is reached through a Crash composite literal (typed, or with its type
// elided inside a slice, array or map literal of Crash), an assignment to
// .Remedy in any package, or a parameter of a function that does either,
// followed transitively to every caller (RecordPermanent, then cmd/k3sm's
// recordBringUpPermanent). Each argument is then resolved through local
// variables, range-over-literal fields and same-package helpers to its leaves,
// and a leaf must be a pkg/executor string const IsKnownRemedy accepts or a
// call of EtcdSupersededError.Remedy. A string literal, a Sprintf, or a const
// defined outside pkg/executor fails here instead of being shown as the generic
// remedy at status time. Shapes the walk cannot follow fail rather than pass: an
// unkeyed Crash literal, a type naming Crash, a dot import of a module package,
// and a remedy sink taken as a value instead of called.
func TestEveryRecordedRemedyIsKnown(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	g := &remedyGuard{t: t, fset: fset, files: parseModuleFiles(t, fset),
		funcs: map[string]map[string]funcRef{}, types: map[string]map[string]typeRef{},
		checked: map[string]int{}, accepted: map[string]bool{}, allowUsed: map[string]bool{}}
	var execFiles []*ast.File
	for _, mf := range g.files {
		if mf.dir == executorDir {
			execFiles = append(execFiles, mf.file)
		}
		if g.funcs[mf.dir] == nil {
			g.funcs[mf.dir] = map[string]funcRef{}
			g.types[mf.dir] = map[string]typeRef{}
		}
		for _, d := range mf.file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				// A method and a function can share a name; the guard only needs one
				// declaration per name to follow returns, and records every Remedy
				// method below.
				if _, dup := g.funcs[mf.dir][d.Name.Name]; !dup || d.Recv == nil {
					g.funcs[mf.dir][d.Name.Name] = funcRef{mf: mf, fd: d}
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if ts, ok := s.(*ast.TypeSpec); ok {
						g.types[mf.dir][ts.Name.Name] = typeRef{mf: mf, spec: ts}
						if g.isCrashType(mf, ts.Type) {
							t.Errorf("%s: the type %s names the crash record's Crash; write Crash itself so this guard sees its literals",
								fset.Position(ts.Pos()), ts.Name.Name)
						}
					}
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
		g.eachDecl(mf, func(fd *ast.FuncDecl, n ast.Node) {
			switch n := n.(type) {
			case *ast.CompositeLit:
				if n.Type != nil {
					g.visitLit(mf, fd, n, mf, n.Type, 0, push)
				}
			case *ast.AssignStmt:
				for i, l := range n.Lhs {
					sel, ok := ast.Unparen(l).(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Remedy" || g.notCrashWrite(mf, fd, sel.X) {
						continue
					}
					if (n.Tok != token.ASSIGN && n.Tok != token.DEFINE) || len(n.Rhs) != len(n.Lhs) {
						g.t.Errorf("%s: a .Remedy assignment this guard cannot pair with its value", g.fset.Position(n.Pos()))
						continue
					}
					g.resolve(mf, fd, n.Rhs[i], push)
				}
			}
		})
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		g.callsOf(s, func(mf *moduleFile, fd *ast.FuncDecl, arg ast.Expr) {
			g.resolve(mf, fd, arg, push)
		})
	}
	g.sinkValues(seen)

	for file, recvs := range remedyAssignAllowed {
		for _, r := range recvs {
			if !g.allowUsed[file+" "+r] {
				t.Errorf("remedyAssignAllowed lists %s %s, which no .Remedy assignment uses; drop the entry", file, r)
			}
		}
	}
	for _, want := range []remedySink{
		{dir: executorDir, recv: "CrashRecord", name: "RecordPermanent", arg: 4},
		{dir: "cmd/k3sm", recv: "crashBreaker", name: "recordBringUpPermanent", arg: 2},
	} {
		if !seen[want] {
			t.Errorf("the walk did not follow %s.%s.%s argument %d; it is broken", want.dir, want.recv, want.name, want.arg)
		}
	}
	if g.crashLits < minCrashLiteralSites {
		t.Errorf("found %d Crash literal sites, below the floor %d; the walk is broken", g.crashLits, minCrashLiteralSites)
	}
	if len(g.accepted) < minDistinctRemedyCons {
		t.Errorf("accepted %d distinct remedy consts, below the floor %d; the walk is broken", len(g.accepted), minDistinctRemedyCons)
	}
	if g.checked[executorDir] == 0 || g.checked["cmd/k3sm"] == 0 {
		t.Errorf("accepted remedies by package = %v; expected writes from pkg/executor and cmd/k3sm, so the walk is broken", g.checked)
	}
	var names, consts []string
	for s := range seen {
		names = append(names, s.dir+"."+s.recv+"."+s.name)
	}
	for c := range g.accepted {
		consts = append(consts, c)
	}
	sort.Strings(names)
	sort.Strings(consts)
	t.Logf("remedy parameters followed: %v; Crash literal sites: %d; accepted consts: %v; accepted leaves by package: %v",
		names, g.crashLits, consts, g.checked)
}

// eachDecl calls visit on every node of mf's declarations, with the enclosing
// function declaration or nil at package level.
func (g *remedyGuard) eachDecl(mf *moduleFile, visit func(fd *ast.FuncDecl, n ast.Node)) {
	for _, d := range mf.file.Decls {
		fd, _ := d.(*ast.FuncDecl)
		var root ast.Node = d
		if fd != nil {
			if fd.Body == nil {
				continue
			}
			root = fd.Body
		}
		ast.Inspect(root, func(n ast.Node) bool {
			if n != nil {
				visit(fd, n)
			}
			return true
		})
	}
}

// visitLit checks lit, a composite literal in mf whose type is typ (typ is
// written in typeFile: lit's own type, or the element type an enclosing literal
// elides). A Crash literal's Remedy is resolved; a slice, array or map of Crash
// is followed into its elided elements.
func (g *remedyGuard) visitLit(mf *moduleFile, fd *ast.FuncDecl, lit *ast.CompositeLit, typeFile *moduleFile, typ ast.Expr, depth int, push func(remedySink)) {
	if depth > 8 {
		g.t.Errorf("%s: a composite literal type nests too deep to follow", g.fset.Position(lit.Pos()))
		return
	}
	if s, ok := typ.(*ast.StarExpr); ok {
		typ = s.X
	}
	if g.isCrashType(typeFile, typ) {
		g.crashLits++
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				g.t.Errorf("%s: an unkeyed Crash literal; key its fields so this guard can find Remedy", g.fset.Position(lit.Pos()))
				return
			}
			if identName(kv.Key) == "Remedy" {
				g.resolve(mf, fd, kv.Value, push)
			}
		}
		return
	}
	elided := func(e ast.Expr, elt ast.Expr) {
		if cl, ok := e.(*ast.CompositeLit); ok && cl.Type == nil {
			g.visitLit(mf, fd, cl, typeFile, elt, depth+1, push)
		}
	}
	switch tt := typ.(type) {
	case *ast.ArrayType:
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				e = kv.Value
			}
			elided(e, tt.Elt)
		}
	case *ast.MapType:
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				elided(kv.Key, tt.Key)
				elided(kv.Value, tt.Value)
			}
		}
	case *ast.Ident, *ast.SelectorExpr:
		// A named slice or map type of this module: follow its definition.
		if ref, ok := g.namedType(typeFile, tt); ok {
			if _, isStruct := ref.spec.Type.(*ast.StructType); !isStruct {
				g.visitLit(mf, fd, lit, ref.mf, ref.spec.Type, depth+1, push)
			}
		}
	}
}

// namedType finds the module type declaration t names from mf.
func (g *remedyGuard) namedType(mf *moduleFile, t ast.Expr) (typeRef, bool) {
	switch t := t.(type) {
	case *ast.Ident:
		ref, ok := g.types[mf.dir][t.Name]
		return ref, ok
	case *ast.SelectorExpr:
		p, ok := mf.importPath(t.X)
		if !ok || !strings.HasPrefix(p, modulePath+"/") {
			return typeRef{}, false
		}
		ref, ok := g.types[strings.TrimPrefix(p, modulePath+"/")][t.Sel.Name]
		return ref, ok
	}
	return typeRef{}, false
}

// notCrashWrite reports whether `x.Remedy = ...` in fd provably does not write
// a crash record: x is a variable whose every declaration in fd names a type
// other than Crash, or x is on remedyAssignAllowed for mf's file.
func (g *remedyGuard) notCrashWrite(mf *moduleFile, fd *ast.FuncDecl, x ast.Expr) bool {
	id, ok := x.(*ast.Ident)
	if !ok || fd == nil {
		return false
	}
	var types []ast.Expr
	known := true
	addFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				if n.Name == id.Name {
					types = append(types, f.Type)
				}
			}
		}
	}
	addFields(fd.Recv)
	ast.Inspect(fd, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncType:
			addFields(n.Params)
			addFields(n.Results)
		case *ast.ValueSpec:
			for i, nm := range n.Names {
				if nm.Name != id.Name {
					continue
				}
				switch {
				case n.Type != nil:
					types = append(types, n.Type)
				case len(n.Values) == len(n.Names):
					types = append(types, litType(n.Values[i]))
				default:
					known = false
				}
			}
		case *ast.AssignStmt:
			if n.Tok != token.DEFINE {
				return true
			}
			for i, l := range n.Lhs {
				if identName(l) != id.Name {
					continue
				}
				if len(n.Rhs) != len(n.Lhs) {
					known = false
					continue
				}
				types = append(types, litType(n.Rhs[i]))
			}
		case *ast.RangeStmt:
			if identName(n.Key) == id.Name || identName(n.Value) == id.Name {
				known = false
			}
		}
		return true
	})
	if known && len(types) > 0 {
		for _, t := range types {
			if s, ok := t.(*ast.StarExpr); ok {
				t = s.X
			}
			if t == nil || g.isCrashType(mf, t) {
				known = false
				break
			}
			if _, named := t.(*ast.Ident); !named {
				if _, named := t.(*ast.SelectorExpr); !named {
					known = false
					break
				}
			}
		}
		if known {
			return true
		}
	}
	for _, r := range remedyAssignAllowed[mf.path] {
		if r == id.Name {
			g.allowUsed[mf.path+" "+r] = true
			return true
		}
	}
	return false
}

// litType is the type of a composite literal e or &e, or nil.
func litType(e ast.Expr) ast.Expr {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	if cl, ok := e.(*ast.CompositeLit); ok {
		return cl.Type
	}
	return nil
}

// isSink reports whether fun, an expression in mf, names the sink's function:
// a plain name in the sink's own package, a qualifier that the import table
// resolves to the sink's package, or, for a method, a selector on a value (from
// the sink's package, or from any package when the name is exported).
func (g *remedyGuard) isSink(mf *moduleFile, fun ast.Expr, s remedySink) bool {
	switch fun := fun.(type) {
	case *ast.Ident:
		return s.recv == "" && fun.Name == s.name && mf.dir == s.dir
	case *ast.SelectorExpr:
		if fun.Sel.Name != s.name {
			return false
		}
		if p, isImport := mf.importPath(fun.X); isImport {
			return s.recv == "" && p == modulePath+"/"+s.dir
		}
		return s.recv != "" && (mf.dir == s.dir || ast.IsExported(s.name))
	}
	return false
}

// callsOf calls visit with the sink's argument at every call of the sink's
// function.
func (g *remedyGuard) callsOf(s remedySink, visit func(mf *moduleFile, fd *ast.FuncDecl, arg ast.Expr)) {
	for _, mf := range g.files {
		g.eachDecl(mf, func(fd *ast.FuncDecl, n ast.Node) {
			call, ok := n.(*ast.CallExpr)
			if !ok || !g.isSink(mf, ast.Unparen(call.Fun), s) {
				return
			}
			if s.arg >= len(call.Args) {
				g.t.Errorf("%s: a call of %s with no remedy argument %d", g.fset.Position(call.Pos()), s.name, s.arg)
				return
			}
			visit(mf, fd, call.Args[s.arg])
		})
	}
}

// sinkValues fails every reference to a sink that is not the function of a
// call: a sink taken as a value (a func value, a method value or expression)
// hands its remedy parameter to callers this guard cannot see.
func (g *remedyGuard) sinkValues(sinks map[remedySink]bool) {
	for _, mf := range g.files {
		called := map[ast.Expr]bool{}
		sels := map[*ast.Ident]bool{}
		g.eachDecl(mf, func(_ *ast.FuncDecl, n ast.Node) {
			switch n := n.(type) {
			case *ast.CallExpr:
				called[ast.Unparen(n.Fun)] = true
			case *ast.SelectorExpr:
				sels[n.Sel] = true
			}
		})
		g.eachDecl(mf, func(_ *ast.FuncDecl, n ast.Node) {
			e, ok := n.(ast.Expr)
			if !ok || called[e] {
				return
			}
			if id, isID := e.(*ast.Ident); isID && sels[id] {
				return
			}
			for s := range sinks {
				if g.isSink(mf, e, s) {
					g.t.Errorf("%s: %s is used as a value, not called; its remedy argument cannot be followed, so call it directly",
						g.fset.Position(e.Pos()), s.name)
				}
			}
		})
	}
}

// resolve follows e, an expression inside fd (nil at package level) in mf, to
// its leaves and checks each; a parameter of fd becomes a new sink.
func (g *remedyGuard) resolve(mf *moduleFile, fd *ast.FuncDecl, e ast.Expr, push func(remedySink)) {
	g.resolveDepth(mf, fd, e, push, 0)
}

func (g *remedyGuard) resolveDepth(mf *moduleFile, fd *ast.FuncDecl, e ast.Expr, push func(remedySink), depth int) {
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
		g.resolveDepth(mf, fd, e.X, push, depth+1)
	case *ast.Ident:
		if fd != nil {
			if i := paramIndex(fd, e.Name); i >= 0 {
				push(remedySink{dir: mf.dir, recv: recvTypeName(fd), name: fd.Name.Name, arg: i})
				return
			}
		}
		if mf.dir == executorDir {
			if v, ok := g.consts[e.Name]; ok {
				g.accept(mf.dir, pos, e.Name, v)
				return
			}
		}
		var values []ast.Expr
		ok := false
		if fd != nil {
			values, ok = localValues(fd, e.Name)
		}
		if !ok {
			fail(fmt.Sprintf("the identifier %s, which is not a const of pkg/executor or a local this guard can follow", e.Name))
			return
		}
		for _, v := range values {
			g.resolveDepth(mf, fd, v, push, depth+1)
		}
	case *ast.SelectorExpr:
		x, ok := e.X.(*ast.Ident)
		if !ok {
			fail("a selector this guard cannot follow")
			return
		}
		if p, isImport := mf.importPath(x); isImport {
			v, ok := g.consts[e.Sel.Name]
			if p != execPath || !ok {
				fail(fmt.Sprintf("%s.%s, which is not a string const of pkg/executor", x.Name, e.Sel.Name))
				return
			}
			g.accept(mf.dir, pos, e.Sel.Name, v)
			return
		}
		var values []ast.Expr
		if fd != nil {
			values, ok = rangeFieldValues(fd, x.Name, e.Sel.Name)
		}
		if !ok {
			fail(fmt.Sprintf("the field %s.%s, which is not a field of a range over a literal", x.Name, e.Sel.Name))
			return
		}
		for _, v := range values {
			g.resolveDepth(mf, fd, v, push, depth+1)
		}
	case *ast.CallExpr:
		switch fun := e.Fun.(type) {
		case *ast.SelectorExpr:
			if _, isImport := mf.importPath(fun.X); !isImport && fun.Sel.Name == "Remedy" && len(e.Args) == 0 {
				// The only Remedy method in the module is EtcdSupersededError's
				// (checked above), and IsSupersededRemedy owns its output.
				g.checked[mf.dir]++
				return
			}
		case *ast.Ident:
			if callee := g.funcs[mf.dir][fun.Name]; callee.fd != nil && callee.fd.Body != nil {
				returns := 0
				ast.Inspect(callee.fd.Body, func(n ast.Node) bool {
					if _, lit := n.(*ast.FuncLit); lit {
						return false
					}
					if r, ok := n.(*ast.ReturnStmt); ok {
						returns++
						if len(r.Results) != 1 {
							g.t.Errorf("%s: %s returns a remedy this guard cannot pick out", g.fset.Position(r.Pos()), fun.Name)
							return false
						}
						g.resolveDepth(callee.mf, callee.fd, r.Results[0], push, depth+1)
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
	g.accepted[name] = true
}

// isCrashType reports whether t, written in mf, names the crash record's entry
// type: Crash inside pkg/executor, or a qualifier mf imports pkg/executor as.
func (g *remedyGuard) isCrashType(mf *moduleFile, t ast.Expr) bool {
	switch t := t.(type) {
	case *ast.Ident:
		return mf.dir == executorDir && t.Name == "Crash"
	case *ast.SelectorExpr:
		p, ok := mf.importPath(t.X)
		return ok && p == execPath && t.Sel.Name == "Crash"
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
