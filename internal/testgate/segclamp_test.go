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

// TestPodNetworkDialsGoThroughTheSegmentClamp keeps every TCP connection the k3sm
// process opens or accepts behind the segment clamp in
// k3sm.io/darwin-net/pkg/tcpseg. Pod IPs, Service VIPs and the node's own
// addresses are lo0 aliases, so a connection to one negotiates a loopback-sized
// TCP segment; if the alias's route later moves onto the mesh tunnel, that
// segment size reaches a link that cannot carry it. tcpseg lowers it after
// connect (the only point macOS allows), so a dial or listen that bypasses it is
// a regression.
//
// What it flags, in every non-test .go file under pkg/ and cmd/, by import path
// (an aliased import is resolved; dot imports are not used in this module):
//
//   - net.Dialer constructed as a composite literal (&net.Dialer{} included), a
//     zero-value `var x net.Dialer`, or new(net.Dialer), and a struct field of
//     type net.Dialer or *net.Dialer;
//   - net.ListenConfig constructed the same ways, when the same function calls a
//     Listen method with a network that is not a non-TCP literal;
//   - net.Dial, net.DialTimeout, net.DialTCP, net.Listen and tls.Dial, unless the
//     network argument is a string literal that does not start with "tcp" (a
//     unix socket never touches a network interface);
//   - http.Transport composite literals, http.DefaultTransport and
//     http.DefaultClient.
//
// A finding is cleared when (a) the innermost enclosing function (a declaration
// or a function literal) references tcpseg.Dialer or tcpseg.WrapListener, or
// (b) an entry in testdata/segclamp.allow names its file, enclosing declaration,
// and construct. Every entry is logged on every run, and an entry that matches
// nothing fails the gate, so the list cannot rot.
//
// Known limits of a syntax-only check: a Dialer or Transport received from
// another package is not seen (http.Client{} with a nil Transport falls back to
// http.DefaultTransport invisibly), listeners opened through a binder interface
// are seen only where a net constructor is named, and an http.Server that binds
// its own listener is not a construct listed above. kube-apiserver and the other
// control-plane components run as child processes, so their outbound transports
// (webhooks, aggregation) are out of reach of an in-process clamp; that residual
// is stated in the allowlist file, not covered by an entry.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// segClampImport is the package whose Dialer and WrapListener clear a finding.
const segClampImport = "k3sm.io/darwin-net/pkg/tcpseg"

// segClampFinding is one unclamped construct.
type segClampFinding struct {
	path   string // module-relative, slash-separated
	line   int
	anchor string // enclosing declaration: Func, Recv.Method, a type name, or "-"
	what   string // the construct, e.g. "net.Dialer{}", "net.Listen"
}

func (f segClampFinding) String() string {
	return fmt.Sprintf("%s:%d %s %s", f.path, f.line, f.anchor, f.what)
}

// segClampAllow is one allowlist entry.
type segClampAllow struct {
	path, anchor, what, why string
	line                    int
}

// TestPodNetworkDialsGoThroughTheSegmentClamp fails on every unclamped construct
// not covered by testdata/segclamp.allow and on every allowlist entry that
// covers nothing.
func TestPodNetworkDialsGoThroughTheSegmentClamp(t *testing.T) {
	t.Parallel()

	t.Run("the walker reports an unclamped dial", testSegClampDetector)

	root := realSocketModuleRoot(t)
	var findings []segClampFinding
	for _, dir := range []string{"pkg", "cmd"} {
		got, err := segClampScan(root, dir)
		if err != nil {
			t.Fatalf("scan %s: %v", dir, err)
		}
		findings = append(findings, got...)
	}
	data, err := os.ReadFile(filepath.Join(root, "internal", "testgate", "testdata", "segclamp.allow"))
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	allow, problems := parseSegClampAllow(string(data))
	for _, a := range allow {
		t.Logf("allowlisted: %s %s %s # %s", a.path, a.anchor, a.what, a.why)
	}
	problems = append(problems, checkSegClamp(findings, allow)...)
	if len(problems) > 0 {
		t.Fatalf("segment-clamp gate: %d finding(s):\n\t%s", len(problems), strings.Join(problems, "\n\t"))
	}
}

// segClampScan parses every non-test .go file under root/dir (skipping testdata,
// vendor and dot directories) and returns its unclamped constructs. A file that
// does not parse is an error: an unreadable file cannot be proven clean.
func segClampScan(root, dir string) ([]segClampFinding, error) {
	var findings []segClampFinding
	fset := token.NewFileSet()
	base := filepath.Join(root, dir)
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != base && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
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
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		findings = append(findings, segClampUses(fset, filepath.ToSlash(rel), f)...)
		return nil
	})
	return findings, err
}

// segClampUses returns the unclamped constructs in one parsed file.
func segClampUses(fset *token.FileSet, rel string, f *ast.File) []segClampFinding {
	names := map[string]string{} // import path → local name, for the paths of interest
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		switch p {
		case "net", "net/http", "crypto/tls", segClampImport:
		default:
			continue
		}
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[p] = name
	}
	if names["net"] == "" && names["net/http"] == "" && names["crypto/tls"] == "" {
		return nil
	}

	is := func(e ast.Expr, path, member string) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != member {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && names[path] != "" && id.Name == names[path]
	}
	typeOf := func(e ast.Expr) string {
		switch {
		case is(e, "net", "Dialer"):
			return "net.Dialer"
		case is(e, "net", "ListenConfig"):
			return "net.ListenConfig"
		case is(e, "net/http", "Transport"):
			return "http.Transport"
		}
		return ""
	}

	var out []segClampFinding
	// visitFunc scans one function body: its own constructs are cleared together
	// by a tcpseg reference in the same body, and each nested function literal
	// is scanned on its own.
	var visitFunc func(body ast.Node, anchor string)
	visitFunc = func(body ast.Node, anchor string) {
		type hit struct {
			pos  token.Pos
			what string
		}
		var hits []hit
		clamped, tcpListen := false, false
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				visitFunc(x.Body, anchor)
				return false
			case *ast.SelectorExpr:
				if is(x, segClampImport, "Dialer") || is(x, segClampImport, "WrapListener") {
					clamped = true
				}
				if is(x, "net/http", "DefaultTransport") || is(x, "net/http", "DefaultClient") {
					hits = append(hits, hit{x.Pos(), "http." + x.Sel.Name})
				}
			case *ast.CompositeLit:
				if t := typeOf(x.Type); t != "" {
					hits = append(hits, hit{x.Pos(), t + "{}"})
				}
			case *ast.ValueSpec:
				if t := typeOf(x.Type); t == "net.Dialer" || t == "net.ListenConfig" {
					hits = append(hits, hit{x.Pos(), "var " + t})
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
					if t := typeOf(x.Args[0]); t == "net.Dialer" || t == "net.ListenConfig" {
						hits = append(hits, hit{x.Pos(), "new(" + t + ")"})
					}
				}
				for _, fn := range []struct{ path, member, label string }{
					{"net", "Dial", "net.Dial"},
					{"net", "DialTimeout", "net.DialTimeout"},
					{"net", "DialTCP", "net.DialTCP"},
					{"net", "Listen", "net.Listen"},
					{"crypto/tls", "Dial", "tls.Dial"},
				} {
					if is(x.Fun, fn.path, fn.member) && segClampTCPArg(x.Args, 0) {
						hits = append(hits, hit{x.Pos(), fn.label})
					}
				}
				// lc.Listen(ctx, network, addr) on a ListenConfig value.
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Listen" && len(x.Args) == 3 && segClampTCPArg(x.Args, 1) {
					tcpListen = true
				}
			}
			return true
		})
		if clamped {
			return
		}
		for _, h := range hits {
			if strings.Contains(h.what, "net.ListenConfig") && !tcpListen {
				continue
			}
			out = append(out, segClampFinding{path: rel, line: fset.Position(h.pos).Line, anchor: anchor, what: h.what})
		}
	}

	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				visitFunc(d.Body, segClampAnchor(d))
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					st, ok := s.Type.(*ast.StructType)
					if !ok {
						break
					}
					for _, fld := range st.Fields.List {
						t := fld.Type
						if star, ok := t.(*ast.StarExpr); ok {
							t = star.X
						}
						if typeOf(t) == "net.Dialer" {
							out = append(out, segClampFinding{path: rel, line: fset.Position(fld.Pos()).Line, anchor: s.Name.Name, what: "field net.Dialer"})
						}
					}
				case *ast.ValueSpec:
					// Package-level vars: scanned as one "-" anchored body.
					visitFunc(s, "-")
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].line < out[j].line })
	return out
}

// segClampTCPArg reports whether args[i] may name a TCP network: anything but a
// string literal that does not start with "tcp".
func segClampTCPArg(args []ast.Expr, i int) bool {
	if i >= len(args) {
		return true
	}
	lit, ok := args[i].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return true
	}
	v, err := strconv.Unquote(lit.Value)
	return err != nil || strings.HasPrefix(v, "tcp")
}

// segClampAnchor names a function declaration: Name, or Recv.Name for a method
// (the receiver's type name, pointer and type parameters dropped).
func segClampAnchor(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	t := d.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	switch x := t.(type) {
	case *ast.IndexExpr:
		t = x.X
	case *ast.IndexListExpr:
		t = x.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + d.Name.Name
	}
	return d.Name.Name
}

// parseSegClampAllow parses the allowlist grammar
//
//	<module-relative path> <anchor> <construct> # <non-empty why>
//
// Blank lines and lines starting with # are ignored. It returns every entry it
// could parse and a problem for every line it could not, or that repeats one.
func parseSegClampAllow(data string) ([]segClampAllow, []string) {
	var entries []segClampAllow
	var problems []string
	seen := map[string]int{}
	for i, raw := range strings.Split(data, "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		body, why, ok := strings.Cut(line, "#")
		why = strings.TrimSpace(why)
		if !ok || why == "" {
			problems = append(problems, fmt.Sprintf("allowlist line %d: missing `# <why>`: %q", n, line))
			continue
		}
		// The construct may contain a space ("var net.Dialer"), so split off
		// the first two fields and keep the rest.
		fields := strings.Fields(body)
		if len(fields) < 3 {
			problems = append(problems, fmt.Sprintf("allowlist line %d: want `<path> <anchor> <construct> # <why>`: %q", n, line))
			continue
		}
		e := segClampAllow{path: fields[0], anchor: fields[1], what: strings.Join(fields[2:], " "), why: why, line: n}
		key := e.path + " " + e.anchor + " " + e.what
		if prev, dup := seen[key]; dup {
			problems = append(problems, fmt.Sprintf("allowlist line %d: duplicates line %d: %s", n, prev, key))
			continue
		}
		seen[key] = n
		entries = append(entries, e)
	}
	return entries, problems
}

// checkSegClamp reports every finding no entry covers and every entry that
// covers no finding.
func checkSegClamp(findings []segClampFinding, allow []segClampAllow) []string {
	var problems []string
	used := make([]bool, len(allow))
	for _, f := range findings {
		covered := false
		for i, a := range allow {
			if a.path == f.path && a.anchor == f.anchor && a.what == f.what {
				used[i] = true
				covered = true
			}
		}
		if !covered {
			problems = append(problems, fmt.Sprintf("%s: unclamped; dial through tcpseg.Dialer or wrap the listener with tcpseg.WrapListener, or allowlist it with a reason", f))
		}
	}
	for i, a := range allow {
		if !used[i] {
			problems = append(problems, fmt.Sprintf("allowlist line %d: stale, matches nothing: %s %s %s", a.line, a.path, a.anchor, a.what))
		}
	}
	return problems
}

// segClampDetect parses src as a file named rel and returns its findings.
func segClampDetect(t *testing.T, src string) []segClampFinding {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return segClampUses(fset, "pkg/x/x.go", f)
}

// testSegClampDetector proves the walker is not vacuous: an unclamped dial toward
// a pod address is reported, and the clamped and non-TCP shapes are not. It runs
// as a subtest of the gate, so the gate cannot pass with a blind walker.
func testSegClampDetector(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string // "anchor what"
	}{
		{
			name: "an unwrapped zero-value dialer toward a pod IP is reported",
			src: `package x
import ("context"; "net")
func probe(ctx context.Context, podIP string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", podIP)
}`,
			want: []string{"probe var net.Dialer"},
		},
		{
			name: "the same dial through tcpseg is clean",
			src: `package x
import ("context"; "net"; "k3sm.io/darwin-net/pkg/tcpseg")
func probe(ctx context.Context, podIP string) (net.Conn, error) {
	var d tcpseg.Dialer
	return d.DialContext(ctx, "tcp", podIP)
}`,
		},
		{
			name: "a tcp listen is reported, a wrapped one is clean, a unix one is ignored",
			src: `package x
import ("net"; ts "k3sm.io/darwin-net/pkg/tcpseg")
func bare(a string) (net.Listener, error) { return net.Listen("tcp", a) }
func wrapped(a string) (net.Listener, error) {
	l, err := net.Listen("tcp", a)
	if err != nil { return nil, err }
	return ts.WrapListener(l), nil
}
func sock(p string) (net.Listener, error) { return net.Listen("unix", p) }`,
			want: []string{"bare net.Listen"},
		},
		{
			name: "a clamp in the outer function does not clear a function literal",
			src: `package x
import ("context"; "net"; "net/http"; "k3sm.io/darwin-net/pkg/tcpseg")
type r struct{}
func (*r) build() (*http.Transport, func(context.Context, string) (net.Conn, error)) {
	tr := &http.Transport{DialContext: (&tcpseg.Dialer{}).DialContext}
	return tr, func(ctx context.Context, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", a)
	}
}`,
			want: []string{"r.build net.Dialer{}"},
		},
		{
			name: "default client, a dialer field and a tcp ListenConfig are reported",
			src: `package x
import ("context"; "net"; "net/http")
type holder struct{ d net.Dialer }
func get(r *http.Request) { _, _ = http.DefaultClient.Do(r) }
func tcp(ctx context.Context) { var lc net.ListenConfig; _, _ = lc.Listen(ctx, "tcp", ":1") }
func udp(ctx context.Context) { var lc net.ListenConfig; _, _ = lc.ListenPacket(ctx, "udp", ":1") }`,
			want: []string{"holder field net.Dialer", "get http.DefaultClient", "tcp var net.ListenConfig"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, f := range segClampDetect(t, tc.src) {
				got = append(got, f.anchor+" "+f.what)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("findings = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("an entry that matches nothing fails, an uncovered finding fails", func(t *testing.T) {
		findings := segClampDetect(t, `package x
import ("context"; "net")
func probe(ctx context.Context, a string) { var d net.Dialer; _, _ = d.DialContext(ctx, "tcp", a) }`)
		allow, problems := parseSegClampAllow("pkg/x/x.go other var net.Dialer # stale on purpose\n")
		if len(problems) != 0 {
			t.Fatalf("parse problems: %v", problems)
		}
		got := checkSegClamp(findings, allow)
		if len(got) != 2 || !strings.Contains(got[0], "unclamped") || !strings.Contains(got[1], "stale") {
			t.Fatalf("problems = %q, want one unclamped and one stale", got)
		}
		allow, _ = parseSegClampAllow("pkg/x/x.go probe var net.Dialer # covered\n")
		if got := checkSegClamp(findings, allow); len(got) != 0 {
			t.Fatalf("problems = %q, want none for a covering entry", got)
		}
	})
}
