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

package bootstrap_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// recordingNodePasswords is a NodePasswordStore that remembers every name it was
// asked to bind, so a test can say which names reached the store at all — the
// first-write-wins binding is keyed on exactly that string.
//
// Locking discipline: mu guards names; httptest serves each request on its own
// goroutine.
type recordingNodePasswords struct {
	inner *bootstrap.MemoryNodePasswords

	mu    sync.Mutex
	names []string
}

func (r *recordingNodePasswords) Ensure(ctx context.Context, nodeName, password string) error {
	r.mu.Lock()
	r.names = append(r.names, nodeName)
	r.mu.Unlock()
	return r.inner.Ensure(ctx, nodeName, password)
}

func (r *recordingNodePasswords) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.names)
}

// TestNodeNameCanonicalizedOnce pins one definition of "the same node name".
//
// A join used to be checked against this control plane's own name with a
// trimmed, Unicode case-folded comparison, while every later step (the
// node-password binding, the mesh write guard, the CSR checks, the enroll) used
// the raw name byte for byte. Two notions of sameness let a spelling slip
// between them: "K3sm-host" with a KELVIN SIGN folds to "k3sm-host" for one
// check and is a different string for the next. Now the name is canonicalized
// once, a request must already be canonical, and everything keys on that form.
func TestNodeNameCanonicalizedOnce(t *testing.T) {
	t.Parallel()

	t.Run("table", func(t *testing.T) {
		t.Parallel()
		label63 := strings.Repeat("a", 63)
		name253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("a", 61)
		name254 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("a", 62)
		if len(name253) != 253 || len(name254) != 254 {
			t.Fatalf("fixture lengths %d/%d, want 253/254", len(name253), len(name254))
		}
		for _, tc := range []struct {
			name, in, want string // want == "" means an error is expected
		}{
			{"already canonical", "k3sm-host", "k3sm-host"},
			{"mixed case is lowercased", "K3sm-Host", "k3sm-host"},
			{"surrounding spaces are trimmed", "  worker-1 ", "worker-1"},
			{"dotted subdomain", "worker-1.lab", "worker-1.lab"},
			{"exactly 253 bytes", name253, name253},
			{"ip-literal-looking name is a valid DNS-1123 subdomain", "10.0.0.1", "10.0.0.1"},
			{"interior space", "k3sm host", ""},
			{"tab", "k3sm\thost", ""},
			{"crlf", "k3sm-host\r\n", ""},
			{"trailing newline is refused, not trimmed", "k3sm-host\n", ""},
			{"nul", "k3sm\x00host", ""},
			{"del", "k3sm-host\x7f", ""},
			{"trailing dot", "k3sm-host.", ""},
			{"leading dot", ".k3sm-host", ""},
			{"empty label", "k3sm..host", ""},
			{"single dot", ".", ""},
			{"label starting with a hyphen", "-k3sm", ""},
			{"label ending with a hyphen", "k3sm-.host", ""},
			{"underscore", "k3sm_host", ""},
			{"254 bytes", name254, ""},
			{"64-byte label", strings.Repeat("a", 64), ""},
			{"empty", "", ""},
			{"all spaces", "   ", ""},
			{"kelvin sign", "\u212a3sm-host", ""},
			{"long s", "k3\u017fm-host", ""},
			{"dotted capital i", "\u0130nfra", ""},
			{"cyrillic o", "k3sm-h\u043est", ""},
			{"nbsp", "k3sm-host\u00a0", ""},
			{"fullwidth", "\uff4b3sm-host", ""},
		} {
			got, err := bootstrap.CanonicalNodeName(tc.in)
			if tc.want == "" {
				if err == nil {
					t.Errorf("%s: CanonicalNodeName(%q) = %q, want an error", tc.name, tc.in, got)
				} else if !errors.Is(err, bootstrap.ErrInvalidNodeName) {
					t.Errorf("%s: error %v does not wrap ErrInvalidNodeName", tc.name, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: CanonicalNodeName(%q) error %v, want %q", tc.name, tc.in, err, tc.want)
				continue
			}
			if got != tc.want {
				t.Errorf("%s: CanonicalNodeName(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
			}
			again, err := bootstrap.CanonicalNodeName(got)
			if err != nil || again != got {
				t.Errorf("%s: not idempotent: Canon(%q) = %q, %v", tc.name, got, again, err)
			}
		}
	})

	t.Run("join", func(t *testing.T) {
		t.Parallel()
		enroller := newPeerStoreEnroller("100.64.1.0/24", "100.64.1.1")
		passwords := &recordingNodePasswords{inner: bootstrap.NewMemoryNodePasswords()}
		ts, tok, client := newNodeNameJoinServer(t, enroller, passwords, "K3sm-Host")

		post := func(nodeName string) (int, string) {
			t.Helper()
			status, body, err := postJoin(client, ts.URL, bootstrap.JoinRequest{
				SchemaVersion: bootstrap.JoinSchemaVersion,
				Token:         tok,
				NodeName:      nodeName,
				NodePassword:  "attacker-node-password",
			})
			if err != nil {
				t.Fatalf("post join %q: %v", nodeName, err)
			}
			return status, body
		}

		// The canonical spelling of this server's own name: the self refusal.
		if status, body := post("k3sm-host"); status != http.StatusForbidden || !strings.Contains(body, "not available") {
			t.Errorf("own canonical name: status = %d (%s), want 403 not available", status, body)
		}

		// Non-canonical spellings: ONE fixed answer, whether or not the name they
		// spell is this server's own, so the reply is no oracle for that name.
		var notCanonical []string
		for _, n := range []string{"K3SM-HOST", " k3sm-host ", "Worker-1"} {
			status, body := post(n)
			if status != http.StatusBadRequest {
				t.Errorf("non-canonical %q: status = %d (%s), want 400", n, status, body)
			}
			if strings.Contains(strings.ToLower(body), "k3sm-host") || strings.Contains(strings.ToLower(body), "worker-1") {
				t.Errorf("non-canonical %q: the refusal %q echoes a spelling", n, body)
			}
			notCanonical = append(notCanonical, body)
		}
		for _, b := range notCanonical[1:] {
			if b != notCanonical[0] {
				t.Errorf("non-canonical refusals differ: %q vs %q", notCanonical[0], b)
			}
		}

		// Names with no canonical form at all.
		for _, n := range []string{"k3sm-host.", "\u212a3sm-host", "k3sm-host\n"} {
			if status, body := post(n); status != http.StatusBadRequest {
				t.Errorf("invalid %q: status = %d (%s), want 400", n, status, body)
			}
		}

		// No refusal above reached the store or the enroll.
		if got := passwords.seen(); len(got) != 0 {
			t.Errorf("refused joins reached the node-password store with %q", got)
		}
		if n := enroller.calls(); n != 0 {
			t.Errorf("refused joins ran the enroll %d times, want 0", n)
		}

		// A canonical worker joins, and only canonical names were ever keyed on.
		res, err := bootstrap.Join(context.Background(), bootstrap.JoinOptions{
			Server:       ts.URL,
			Token:        tok,
			NodeName:     "worker-1",
			NodePassword: "worker-node-password",
			MeshEndpoint: "192.0.2.50:51820",
			HTTPClient:   client,
		})
		if err != nil {
			t.Fatalf("a canonical worker join must be served: %v", err)
		}
		if cn := parseCertPEM(t, res.NodeClientCertPEM).Subject.CommonName; cn != "system:node:worker-1" {
			t.Errorf("issued CN = %q, want system:node:worker-1", cn)
		}
		if got := passwords.seen(); !slices.Equal(got, []string{"worker-1"}) {
			t.Errorf("node-password store saw %q, want only [worker-1]", got)
		}
		if n := enroller.calls(); n != 1 {
			t.Errorf("enroll ran %d times, want 1", n)
		}
		enroller.mu.Lock()
		for name := range enroller.peers {
			if c, err := bootstrap.CanonicalNodeName(name); err != nil || c != name {
				t.Errorf("the enroll wrote a peer under the non-canonical name %q", name)
			}
		}
		enroller.mu.Unlock()
	})

	t.Run("newserver", func(t *testing.T) {
		t.Parallel()
		for _, self := range []string{"k3sm_host", "k3sm-host.", "\u212a3sm-host", "k3sm-host\n"} {
			_, err := bootstrap.NewServer(nodeNameServerConfig(t, newPeerStoreEnroller("100.64.1.0/24", "100.64.1.1"),
				bootstrap.NewMemoryNodePasswords(), nil, self))
			if !errors.Is(err, bootstrap.ErrInvalidNodeName) {
				t.Errorf("SelfNodeName %q: NewServer error %v, want one wrapping ErrInvalidNodeName", self, err)
			}
		}
	})

	t.Run("ast", func(t *testing.T) {
		t.Parallel()
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
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", p, err)
			}
			files = append(files, f)
		}
		if violations := nodeNameDisciplineViolations(files); len(violations) > 0 {
			t.Errorf("node-name discipline violated:\n  %s", strings.Join(violations, "\n  "))
		}

		// The checker must be able to fail: a fixture that folds in
		// selfNameClaimed, canonicalizes twice in handleJoin, and never in
		// NewServer.
		const bad = `package bootstrap
import "strings"
func NewServer(cfg ServerConfig) (*Server, error) { return nil, nil }
func (s *Server) handleJoin() {
	name, _ := CanonicalNodeName(x)
	_ = selfNameClaimed(s.self, name)
	other, _ := CanonicalNodeName(y)
	_ = s.cfg.NodePasswords.Ensure(nil, other, "")
}
func selfNameClaimed(a, b string) bool { return strings.EqualFold(a, b) }
`
		f, err := parser.ParseFile(token.NewFileSet(), "bad.go", bad, 0)
		if err != nil {
			t.Fatalf("parse fixture: %v", err)
		}
		got := strings.Join(nodeNameDisciplineViolations([]*ast.File{f}), "\n")
		for _, want := range []string{
			"handleJoin calls CanonicalNodeName 2 times",
			"NewServer does not call CanonicalNodeName",
			"selfNameClaimed calls strings.EqualFold",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the checker missed %q in the violating fixture; it reported:\n%s", want, got)
			}
		}
	})
}

// nodeNameDisciplineViolations checks, over a package's parsed files, that the
// node name is canonicalized exactly once in handleJoin (as a top-level
// statement, ahead of the self-name refusal and the node-password binding),
// that NewServer canonicalizes the self name, and that none of handleJoin,
// NewServer or selfNameClaimed folds case on its own.
func nodeNameDisciplineViolations(files []*ast.File) []string {
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[fn.Name.Name] = fn
			}
		}
	}
	var out []string
	for _, name := range []string{"handleJoin", "NewServer", "selfNameClaimed"} {
		if funcs[name] == nil {
			out = append(out, name+" is not declared")
		}
	}
	if len(out) > 0 {
		return out
	}

	// No local case folding in the three functions.
	for _, name := range []string{"handleJoin", "NewServer", "selfNameClaimed"} {
		ast.Inspect(funcs[name].Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			pkg, sel := callName(call)
			switch {
			case pkg == "strings" && (sel == "EqualFold" || sel == "ToLower" || sel == "ToUpper"):
				out = append(out, fmt.Sprintf("%s calls strings.%s", name, sel))
			case pkg == "unicode":
				out = append(out, fmt.Sprintf("%s calls unicode.%s", name, sel))
			case name == "selfNameClaimed" && pkg == "strings":
				out = append(out, fmt.Sprintf("selfNameClaimed calls strings.%s; it must be plain equality", sel))
			}
			return true
		})
	}

	if countCalls(funcs["NewServer"].Body, "CanonicalNodeName") == 0 {
		out = append(out, "NewServer does not call CanonicalNodeName")
	}

	body := funcs["handleJoin"].Body
	if n := countCalls(body, "CanonicalNodeName"); n != 1 {
		out = append(out, fmt.Sprintf("handleJoin calls CanonicalNodeName %d times, want exactly 1", n))
	}
	canon := token.NoPos
	for _, stmt := range body.List {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			continue
		}
		if call, ok := as.Rhs[0].(*ast.CallExpr); ok {
			if _, sel := callName(call); sel == "CanonicalNodeName" {
				canon = call.Pos()
				break
			}
		}
	}
	if canon == token.NoPos {
		out = append(out, "handleJoin does not call CanonicalNodeName as a top-level statement")
		return out
	}
	for _, after := range []string{"selfNameClaimed", "Ensure"} {
		pos := firstCall(body, after)
		switch {
		case pos == token.NoPos:
			out = append(out, "handleJoin no longer calls "+after+"; the ordering check is vacuous")
		case pos < canon:
			out = append(out, "handleJoin calls "+after+" before CanonicalNodeName")
		}
	}
	return out
}

// callName returns a call's package-or-receiver identifier (when it is a plain
// identifier) and its function or method name.
func callName(call *ast.CallExpr) (string, string) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return "", fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok {
			return x.Name, fun.Sel.Name
		}
		return "", fun.Sel.Name
	}
	return "", ""
}

func countCalls(body *ast.BlockStmt, sel string) int {
	n := 0
	ast.Inspect(body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if _, s := callName(call); s == sel {
				n++
			}
		}
		return true
	})
	return n
}

func firstCall(body *ast.BlockStmt, sel string) token.Pos {
	pos := token.NoPos
	ast.Inspect(body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && pos == token.NoPos {
			if _, s := callName(call); s == sel {
				pos = call.Pos()
			}
		}
		return pos == token.NoPos
	})
	return pos
}

// nodeNameServerConfig is the join server's config over the given store and
// enroller; tokens may be nil when the server is never served.
func nodeNameServerConfig(t *testing.T, enroller bootstrap.Enroller, passwords bootstrap.NodePasswordStore, tokens *bootstrap.TokenStore, self string) bootstrap.ServerConfig {
	t.Helper()
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signingCA, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	if tokens == nil {
		tokens = bootstrap.NewTokenStore(nil)
	}
	return bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        tokens,
		NodePasswords: passwords,
		Enroller:      enroller,
		SelfNodeName:  self,
	}
}

// newNodeNameJoinServer serves a join server whose node-password store is the
// caller's (the shared join rig fixes a MemoryNodePasswords, and this gate
// needs to record what reached the store).
func newNodeNameJoinServer(t *testing.T, enroller bootstrap.Enroller, passwords bootstrap.NodePasswordStore, self string) (*httptest.Server, string, *http.Client) {
	t.Helper()
	tokens := bootstrap.NewTokenStore(nil)
	user, secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	cfg := nodeNameServerConfig(t, enroller, passwords, tokens, self)
	srv, err := bootstrap.NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, bootstrap.FormatToken(cfg.ClusterCA.PinHash(), user, secret), ts.Client()
}
