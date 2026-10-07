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

package testgate

// The real-socket detector behind TestNoUntaggedRealSocketTests
// (realsocket_gate_test.go), and its self-test. A twin of this gate lives in the
// k3sm.io/darwin-net module; the two are kept in lockstep, so a change to the
// flagged set, the exemption rule, or the allowlist grammar here is made there
// too. The tagged-tier set (realSocketExemptTags) is per-module configuration,
// not part of the rule: this module has three tagged tiers, the twin has two.
//
// What it flags, by IMPORT PATH (an aliased import is resolved to its path, and a
// dot import is matched on the bare identifier):
//
//   - net: Listen, ListenPacket, ListenTCP, ListenUDP, ListenIP, ListenUnix,
//     ListenUnixgram, ListenMulticastUDP, Dial, DialTimeout, DialTCP, DialUDP,
//     DialIP, DialUnix — any reference, so a method value is caught as well as a
//     call — and construction of net.Dialer, net.ListenConfig, or net.Resolver as
//     a composite literal, &T{}, or new(T).
//   - net/http/httptest: NewServer, NewTLSServer, NewUnstartedServer.
//   - crypto/tls: Listen, Dial, DialWithDialer.
//   - net/http: ListenAndServe, ListenAndServeTLS, Get, Post, Head, PostForm.
//   - syscall.Socket and golang.org/x/sys/unix.Socket.
//
// Unix-domain sockets count: a socket file is still a kernel socket the test
// opens. Not flagged: net.Pipe, httptest.NewRecorder, net.ParseIP and the other
// pure helpers, a local function that happens to be named Listen, and a
// *net.Dialer that only appears as a type.
//
// A file is exempt when its //go:build expression is false with none of the
// integration, e2e, or kinecompat tags set and true with at least one of them,
// every other tag evaluated against the running build (GOOS, GOARCH, unix, the
// go1.N release tags, race as compiled, cgo false). So !race, darwin, or
// !integration never exempt a file; only a constraint that genuinely moves it
// into a tagged tier does.
//
// Known limits, accepted for a syntax-only check:
//
//   - It is per call site. A file that calls a socket-opening helper defined in
//     another file is not flagged; the helper's file is. Production code reached
//     from a test (a Reconcile that binds a listener) is invisible to it.
//   - There is no type checking. A Dialer value received from elsewhere is caught
//     only at its construction site, a zero-value `var d net.Dialer` is not caught,
//     and a local variable that shadows a package name is not resolved.
//   - Only //go:build lines are read; a file-name GOOS/GOARCH suffix is not, which
//     errs toward flagging.

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// realSocketFuncs maps an import path to the package-level functions that open a
// real socket.
var realSocketFuncs = map[string][]string{
	"net": {
		"Listen", "ListenPacket", "ListenTCP", "ListenUDP", "ListenIP", "ListenUnix",
		"ListenUnixgram", "ListenMulticastUDP", "Dial", "DialTimeout", "DialTCP",
		"DialUDP", "DialIP", "DialUnix",
	},
	"net/http/httptest":     {"NewServer", "NewTLSServer", "NewUnstartedServer"},
	"crypto/tls":            {"Listen", "Dial", "DialWithDialer"},
	"net/http":              {"ListenAndServe", "ListenAndServeTLS", "Get", "Post", "Head", "PostForm"},
	"syscall":               {"Socket"},
	"golang.org/x/sys/unix": {"Socket"},
}

// realSocketTypes maps an import path to the types whose construction is a
// socket-opening capability.
var realSocketTypes = map[string][]string{
	"net": {"Dialer", "ListenConfig", "Resolver"},
}

// realSocketExemptTags are the tags that move a file into a tagged tier: this
// module's three tagged test tiers. TestRealSocketExemptTagsMatchCI holds the set
// equal to the tags hack/ci.sh vets, so a new tier cannot be added to one and not
// the other.
var realSocketExemptTags = []string{"integration", "e2e", "kinecompat"}

// realSocketNow is the gate's clock. The self-test overrides it; the gate itself
// uses the real one, so allowlist entries expire.
var realSocketNow = time.Now

// realSocketMaxHorizon is how far past now an allowlist entry may be dated, so no
// entry can be bumped to a date that never comes.
const realSocketMaxHorizon = 183 * 24 * time.Hour

// socketUse is one flagged reference: where it is and what it named.
type socketUse struct {
	line int
	what string // e.g. "net.Listen", "httptest.NewServer", "&net.Dialer{}"
}

// realSocketExempt reports whether f's //go:build constraint moves it into a
// tagged tier (see the file comment). A file with no constraint is not exempt.
func realSocketExempt(f *ast.File) (bool, error) {
	var expr constraint.Expr
	for _, cg := range f.Comments {
		if cg.Pos() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			e, err := constraint.Parse(c.Text)
			if err != nil {
				return false, fmt.Errorf("parse %q: %w", c.Text, err)
			}
			expr = e
		}
	}
	if expr == nil {
		return false, nil
	}
	evalWith := func(extra string) bool {
		return expr.Eval(func(tag string) bool { return extra != "" && tag == extra || realSocketBuildTag(tag) })
	}
	if evalWith("") {
		return false, nil
	}
	for _, tag := range realSocketExemptTags {
		if evalWith(tag) {
			return true, nil
		}
	}
	return false, nil
}

// realSocketBuildTag evaluates one non-tier build tag against the running build.
func realSocketBuildTag(tag string) bool {
	switch tag {
	case runtime.GOOS, runtime.GOARCH:
		return true
	case "unix":
		return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
	case "race":
		return raceEnabled
	case "cgo":
		return false
	}
	return slices.Contains(build.Default.ReleaseTags, tag)
}

// realSocketUses returns every flagged reference in f, in source order.
func realSocketUses(fset *token.FileSet, f *ast.File) []socketUse {
	named := map[string]string{} // local package name → import path, for flagged paths
	var dotted []string          // import paths dot-imported
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, ok := realSocketFuncs[path]; !ok {
			if _, ok := realSocketTypes[path]; !ok {
				continue
			}
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch name {
		case "_":
		case ".":
			dotted = append(dotted, path)
		default:
			named[name] = path
		}
	}
	if len(named) == 0 && len(dotted) == 0 {
		return nil
	}

	// resolve maps an expression naming a package member (pkg.Name, or Name under
	// a dot import) to its import path and member name.
	resolve := func(e ast.Expr) (path, member string, ok bool) {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			id, isID := x.X.(*ast.Ident)
			if !isID {
				return "", "", false
			}
			p, found := named[id.Name]
			return p, x.Sel.Name, found
		case *ast.Ident:
			for _, p := range dotted {
				if slices.Contains(realSocketFuncs[p], x.Name) || slices.Contains(realSocketTypes[p], x.Name) {
					return p, x.Name, true
				}
			}
		}
		return "", "", false
	}
	label := func(path, member string) string { return path[strings.LastIndex(path, "/")+1:] + "." + member }

	var uses []socketUse
	add := func(pos token.Pos, what string) {
		uses = append(uses, socketUse{line: fset.Position(pos).Line, what: what})
	}
	isFunc := func(e ast.Expr) (string, bool) {
		if p, m, ok := resolve(e); ok && slices.Contains(realSocketFuncs[p], m) {
			return label(p, m), true
		}
		return "", false
	}
	isType := func(e ast.Expr) (string, bool) {
		if p, m, ok := resolve(e); ok && slices.Contains(realSocketTypes[p], m) {
			return label(p, m), true
		}
		return "", false
	}

	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if what, ok := isFunc(x); ok {
				add(x.Pos(), what)
				return false
			}
			// Only the operand can hold a reference; the selector name is a field
			// or method, never a dot-imported function.
			ast.Inspect(x.X, visit)
			return false
		case *ast.Ident:
			if what, ok := isFunc(x); ok {
				add(x.Pos(), what)
			}
		case *ast.CompositeLit:
			if what, ok := isType(x.Type); ok {
				add(x.Pos(), what+"{}")
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				if what, ok := isType(x.Args[0]); ok {
					add(x.Pos(), "new("+what+")")
				}
			}
		case *ast.FuncDecl:
			// The declared name is not a reference; a method named Dial under a dot
			// import of net is not net.Dial.
			if x.Recv != nil {
				ast.Inspect(x.Recv, visit)
			}
			ast.Inspect(x.Type, visit)
			if x.Body != nil {
				ast.Inspect(x.Body, visit)
			}
			return false
		case *ast.Field:
			// Field, parameter, and result names are declarations, not references.
			ast.Inspect(x.Type, visit)
			return false
		case *ast.KeyValueExpr:
			// A struct-literal field key is a field name, not a reference.
			if _, isKey := x.Key.(*ast.Ident); isKey {
				ast.Inspect(x.Value, visit)
				return false
			}
		case *ast.ImportSpec:
			return false
		}
		return true
	}
	ast.Inspect(f, visit)
	sort.SliceStable(uses, func(i, j int) bool { return uses[i].line < uses[j].line })
	return uses
}

// realSocketOffender is one untagged test file that opens a real socket, with its
// first offending reference.
type realSocketOffender struct {
	path  string // module-relative, slash-separated
	first socketUse
}

// realSocketScan walks every *_test.go under root (skipping testdata, vendor, and
// dot directories) and returns its untagged offenders keyed by module-relative
// path. A file that does not parse is an error: an unreadable file cannot be
// proven clean.
func realSocketScan(root string) (map[string]realSocketOffender, error) {
	offenders := map[string]realSocketOffender{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		exempt, err := realSocketExempt(f)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if exempt {
			return nil
		}
		if uses := realSocketUses(fset, f); len(uses) > 0 {
			offenders[rel] = realSocketOffender{path: rel, first: uses[0]}
		}
		return nil
	})
	return offenders, err
}

// realSocketAllow is one allowlist entry.
type realSocketAllow struct {
	path  string
	until time.Time // a date, midnight UTC
	line  int
}

// parseRealSocketAllow parses the allowlist grammar
//
//	<module-relative path> until=YYYY-MM-DD # <non-empty why>
//
// Blank lines and lines starting with # are ignored. It returns every entry it
// could parse and a finding for every line it could not.
func parseRealSocketAllow(data string) ([]realSocketAllow, []string) {
	var (
		entries  []realSocketAllow
		findings []string
		seen     = map[string]int{}
	)
	for i, raw := range strings.Split(data, "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		spec, why, hasWhy := strings.Cut(line, "#")
		if !hasWhy || strings.TrimSpace(why) == "" {
			findings = append(findings, fmt.Sprintf("allowlist line %d: missing the `# <why>` reason: %q", n, line))
			continue
		}
		fields := strings.Fields(spec)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "until=") {
			findings = append(findings, fmt.Sprintf("allowlist line %d: want `<path> until=YYYY-MM-DD # <why>`: %q", n, line))
			continue
		}
		until, err := time.Parse(time.DateOnly, strings.TrimPrefix(fields[1], "until="))
		if err != nil {
			findings = append(findings, fmt.Sprintf("allowlist line %d: bad until date: %v", n, err))
			continue
		}
		if prev, dup := seen[fields[0]]; dup {
			findings = append(findings, fmt.Sprintf("allowlist line %d: duplicate entry for %s (first on line %d)", n, fields[0], prev))
			continue
		}
		seen[fields[0]] = n
		entries = append(entries, realSocketAllow{path: fields[0], until: until, line: n})
	}
	return entries, findings
}

// checkRealSocketAllow matches offenders against the allowlist as of now and
// returns every finding, sorted: an unlisted offender, an expired entry, an entry
// dated past the horizon, and a stale entry that names no offender.
func checkRealSocketAllow(offenders map[string]realSocketOffender, allowData string, now time.Time) []string {
	entries, findings := parseRealSocketAllow(allowData)
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)

	listed := map[string]bool{}
	for _, e := range entries {
		listed[e.path] = true
		switch {
		case e.until.Before(today):
			findings = append(findings, fmt.Sprintf("allowlist line %d: %s expired on %s: tag it //go:build integration or convert it to fakes, then delete the line", e.line, e.path, e.until.Format(time.DateOnly)))
		case e.until.Sub(today) > realSocketMaxHorizon:
			findings = append(findings, fmt.Sprintf("allowlist line %d: %s is dated %s, more than 183 days out; entries are a schedule, not a waiver", e.line, e.path, e.until.Format(time.DateOnly)))
		}
		if _, ok := offenders[e.path]; !ok {
			findings = append(findings, fmt.Sprintf("allowlist line %d: %s opens no untagged real socket (converted, tagged, or gone): delete the line so the list shrinks", e.line, e.path))
		}
	}
	for path, o := range offenders {
		if !listed[path] {
			findings = append(findings, fmt.Sprintf("%s:%d: untagged test opens a real socket (%s): fake it at a seam, or move it behind //go:build integration", path, o.first.line, o.first.what))
		}
	}
	sort.Strings(findings)
	return findings
}

// runRealSocketGate scans the module at root and checks the allowlist at
// allowPath as of now. A missing allowlist is an error, not an empty list.
func runRealSocketGate(root, allowPath string, now time.Time) ([]string, error) {
	data, err := os.ReadFile(allowPath)
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	offenders, err := realSocketScan(root)
	if err != nil {
		return nil, err
	}
	return checkRealSocketAllow(offenders, string(data), now), nil
}

// detectSource parses one source snippet and returns its uses and exemption.
func detectSource(t *testing.T, src string) (bool, []socketUse) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "snippet_test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse snippet: %v\n%s", err, src)
	}
	exempt, err := realSocketExempt(f)
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	return exempt, realSocketUses(fset, f)
}

// TestRealSocketDetector is the gate's self-test: every flagged family is caught,
// every look-alike is not, aliases and dot imports resolve, only a real tier
// constraint exempts a file, every allowlist failure mode fires, and a real
// fixture file is flagged by the walker end to end.
func TestRealSocketDetector(t *testing.T) {
	t.Parallel()

	t.Run("every flagged function is caught", func(t *testing.T) {
		for path, funcs := range realSocketFuncs {
			name := path[strings.LastIndex(path, "/")+1:]
			for _, fn := range funcs {
				src := fmt.Sprintf("package p\nimport %q\nvar _ = %s.%s\n", path, name, fn)
				if _, uses := detectSource(t, src); len(uses) != 1 || uses[0].what != name+"."+fn {
					t.Errorf("%s.%s: uses = %v, want exactly one", path, fn, uses)
				}
			}
		}
	})

	cases := []struct {
		name string
		src  string
		want []string // the flagged references, in order; nil means clean
	}{
		{"net.Listen call", "package p\nimport \"net\"\nfunc f() { net.Listen(\"tcp\", \":0\") }\n", []string{"net.Listen"}},
		{"unix-domain socket counts", "package p\nimport \"net\"\nfunc f() { net.Listen(\"unix\", \"/x.sock\") }\n", []string{"net.Listen"}},
		{"Dialer composite literal", "package p\nimport \"net\"\nvar d = net.Dialer{}\n", []string{"net.Dialer{}"}},
		{"&Dialer{}", "package p\nimport \"net\"\nvar d = &net.Dialer{Timeout: 1}\n", []string{"net.Dialer{}"}},
		{"new(ListenConfig)", "package p\nimport \"net\"\nvar c = new(net.ListenConfig)\n", []string{"new(net.ListenConfig)"}},
		{"Resolver literal", "package p\nimport \"net\"\nvar r = &net.Resolver{}\n", []string{"net.Resolver{}"}},
		{"httptest server", "package p\nimport \"net/http/httptest\"\nvar s = httptest.NewServer(nil)\n", []string{"httptest.NewServer"}},
		{"tls dial", "package p\nimport \"crypto/tls\"\nfunc f() { tls.Dial(\"tcp\", \"x:1\", nil) }\n", []string{"tls.Dial"}},
		{"http.Get", "package p\nimport \"net/http\"\nfunc f() { http.Get(\"http://x\") }\n", []string{"http.Get"}},
		{"syscall.Socket", "package p\nimport \"syscall\"\nfunc f() { syscall.Socket(1, 2, 0) }\n", []string{"syscall.Socket"}},
		{"x/sys/unix.Socket", "package p\nimport \"golang.org/x/sys/unix\"\nfunc f() { unix.Socket(1, 2, 0) }\n", []string{"unix.Socket"}},
		{"aliased import", "package p\nimport n \"net\"\nfunc f() { n.DialTimeout(\"tcp\", \"x:1\", 0) }\n", []string{"net.DialTimeout"}},
		{"aliased httptest", "package p\nimport ht \"net/http/httptest\"\nvar s = ht.NewUnstartedServer(nil)\n", []string{"httptest.NewUnstartedServer"}},
		{"dot import call", "package p\nimport . \"net\"\nfunc f() { ListenPacket(\"udp\", \":0\") }\n", []string{"net.ListenPacket"}},
		{"dot import type", "package p\nimport . \"net\"\nvar d = &Dialer{}\n", []string{"net.Dialer{}"}},
		{"method value", "package p\nimport \"net\"\nvar listen = net.Listen\n", []string{"net.Listen"}},
		{"two uses in order", "package p\nimport \"net\"\nfunc f() {\n\tnet.Dial(\"tcp\", \"x:1\")\n\tnet.ListenUDP(\"udp\", nil)\n}\n", []string{"net.Dial", "net.ListenUDP"}},

		{"net.Pipe is in-memory", "package p\nimport \"net\"\nfunc f() { net.Pipe() }\n", nil},
		{"httptest.NewRecorder is in-memory", "package p\nimport \"net/http/httptest\"\nvar r = httptest.NewRecorder()\n", nil},
		{"net.ParseIP is pure", "package p\nimport \"net\"\nvar ip = net.ParseIP(\"10.0.0.1\")\n", nil},
		{"local func named Listen", "package p\nfunc Listen() {}\nfunc f() { Listen() }\n", nil},
		{"local Listen beside a net import", "package p\nimport \"net\"\nvar _ net.Addr\nfunc Listen() {}\nfunc f() { Listen() }\n", nil},
		{"Dialer as a type only", "package p\nimport \"net\"\nfunc f(d *net.Dialer) {}\n", nil},
		{"method named Listen on a value", "package p\nimport \"net\"\ntype b struct{}\nfunc (b) Listen() {}\nvar _ net.Addr\nfunc f(x b) { x.Listen() }\n", nil},
		{"dot import, selector named Dial", "package p\nimport . \"net\"\ntype b struct{}\nfunc (b) Dial() {}\nvar _ Addr\nfunc f(x b) { x.Dial() }\n", nil},
		{"dot import, struct key named Dial", "package p\nimport . \"net\"\ntype c struct{ Dial int }\nvar _ Addr\nvar _ = c{Dial: 1}\n", nil},
		{"a string mentioning net.Listen", "package p\nvar s = \"net.Listen\"\n", nil},
		{"blank import", "package p\nimport _ \"net\"\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, uses := detectSource(t, tc.src)
			var got []string
			for _, u := range uses {
				got = append(got, u.what)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("flagged %v, want %v", got, tc.want)
			}
		})
	}

	constraints := []struct {
		build  string
		exempt bool
	}{
		{"integration", true},
		{"e2e", true},
		{"integration || e2e", true},
		{"kinecompat", true},
		{runtime.GOOS + " && integration", true},
		{"!race", false},
		{"race", false},
		{runtime.GOOS, false},
		{"!integration", false},
		{"ignore", false},
		{"integration && !integration", false},
		{"!cgo", false},
	}
	for _, tc := range constraints {
		t.Run("constraint "+tc.build, func(t *testing.T) {
			src := "//go:build " + tc.build + "\n\npackage p\n\nimport \"net\"\n\nvar _ = net.Listen\n"
			exempt, _ := detectSource(t, src)
			if exempt != tc.exempt {
				t.Fatalf("//go:build %s exempt = %v, want %v", tc.build, exempt, tc.exempt)
			}
		})
	}

	t.Run("allowlist", func(t *testing.T) {
		now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
		offenders := map[string]realSocketOffender{
			"pkg/a/a_test.go": {path: "pkg/a/a_test.go", first: socketUse{line: 7, what: "net.Listen"}},
		}
		ok := "pkg/a/a_test.go until=2026-12-31 # loopback echo backends\n"
		for _, tc := range []struct {
			name  string
			allow string
			want  []string // substrings, one per expected finding
		}{
			{"listed and in date", "# header\n\n" + ok, nil},
			{"due today is still in date", "pkg/a/a_test.go until=2026-10-02 # why\n", nil},
			{"exactly 183 days out is allowed", "pkg/a/a_test.go until=2027-04-03 # why\n", nil},
			{"unlisted offender", "", []string{"pkg/a/a_test.go:7: untagged test opens a real socket (net.Listen)"}},
			{"expired", "pkg/a/a_test.go until=2026-10-01 # why\n", []string{"expired on 2026-10-01"}},
			{"past the horizon", "pkg/a/a_test.go until=2027-04-04 # why\n", []string{"more than 183 days out"}},
			{"stale entry", ok + "pkg/b/b_test.go until=2026-12-31 # why\n", []string{"pkg/b/b_test.go opens no untagged real socket"}},
			{"missing until", "pkg/a/a_test.go # why\n", []string{"line 1: want", "untagged test opens a real socket"}},
			{"bad date", "pkg/a/a_test.go until=2026-13-01 # why\n", []string{"bad until date", "untagged test opens a real socket"}},
			{"extra field", "pkg/a/a_test.go until=2026-12-31 extra # why\n", []string{"line 1: want", "untagged test opens a real socket"}},
			{"no reason", "pkg/a/a_test.go until=2026-12-31\n", []string{"missing the `# <why>` reason", "untagged test opens a real socket"}},
			{"empty reason", "pkg/a/a_test.go until=2026-12-31 #   \n", []string{"missing the `# <why>` reason", "untagged test opens a real socket"}},
			{"duplicate", ok + ok, []string{"line 2: duplicate entry"}},
			{"all at once", "pkg/c/c_test.go until=2020-01-01 # why\npkg/d/d_test.go until=2026-12-31\n", []string{
				"pkg/c/c_test.go expired", "pkg/c/c_test.go opens no untagged", "line 2: missing the", "pkg/a/a_test.go:7",
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := checkRealSocketAllow(offenders, tc.allow, now)
				if len(got) != len(tc.want) {
					t.Fatalf("findings = %q, want %d matching %q", got, len(tc.want), tc.want)
				}
				for _, w := range tc.want {
					if !slices.ContainsFunc(got, func(g string) bool { return strings.Contains(g, w) }) {
						t.Fatalf("findings = %q, want one containing %q", got, w)
					}
				}
			})
		}
	})

	t.Run("walker flags a real fixture file", func(t *testing.T) {
		fixture, err := os.ReadFile(filepath.Join("testdata", "detector", "violation.go.txt"))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		root := t.TempDir()
		write := func(rel, data string) {
			t.Helper()
			p := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("go.mod", "module example.com/m\n")
		write("pkg/x/violation_test.go", string(fixture))
		write("pkg/x/testdata/ignored_test.go", string(fixture)) // testdata is never scanned
		write("pkg/x/tagged_integration_test.go", "//go:build integration\n\n"+string(fixture))
		write("allow", "")

		findings, err := runRealSocketGate(root, filepath.Join(root, "allow"), realSocketNow())
		if err != nil {
			t.Fatalf("gate: %v", err)
		}
		if len(findings) != 1 || !strings.HasPrefix(findings[0], "pkg/x/violation_test.go:") {
			t.Fatalf("findings = %q, want exactly the untagged fixture", findings)
		}

		if _, err := runRealSocketGate(root, filepath.Join(root, "missing.allow"), realSocketNow()); err == nil {
			t.Fatal("a missing allowlist passed the gate")
		}

		write("pkg/x/broken_test.go", "package x\nfunc {\n")
		if _, err := runRealSocketGate(root, filepath.Join(root, "allow"), realSocketNow()); err == nil {
			t.Fatal("an unparseable test file passed the gate")
		}
	})
}
