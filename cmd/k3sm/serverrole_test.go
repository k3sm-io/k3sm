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

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
)

// TestRunServerTraceImportPrecedesMeshPKI pins, in the expanded runServer trace, that
// the HA server-join import (and its bounded wait) runs before the mesh PKI ensure
// and before the executor starts: a joined server must hold every CA before
// anything that would load or mint one runs.
func TestRunServerTraceImportPrecedesMeshPKI(t *testing.T) {
	first := runServerTrace(t).firstCalls()
	for _, name := range []string{"importServerCABundle", "provisionMeshPKI", "exec.Start"} {
		if _, ok := first[name]; !ok {
			t.Fatalf("runServer no longer calls %s", name)
		}
	}
	imp := first["importServerCABundle"].pos
	for _, later := range []string{"provisionMeshPKI", "exec.Start"} {
		if imp >= first[later].pos {
			t.Errorf("runServer reaches %s before importServerCABundle", later)
		}
	}
}

// moduleGoFiles parses every non-test .go file of the k3sm module.
func moduleGoFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && p != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		files[p] = f
		return nil
	})
	if err != nil {
		t.Fatalf("parse the module: %v", err)
	}
	return fset, files
}

// TestEnsureCallersPassRole is the source gate on the CA mint role: every non-test
// caller of certs.EnsureHierarchy passes a role derived from --server-join (the
// serverOptions.role method, which reads the serverJoin flag, or executor
// Config.CARole, which reads the EtcdJoin member role etcdConfig sets from that
// same flag), never a literal; and certs.EnsureEtcdCAs, which always mints an
// absent pair, is called only by provisionEtcdCerts behind its own init-member guard.
func TestEnsureCallersPassRole(t *testing.T) {
	fset, files := moduleGoFiles(t)
	roleMethods := map[string]bool{"role": false, "CARole": false} // name -> reads the --server-join role
	var ensureCallers, etcdCallers []string
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, isRole := roleMethods[fn.Name.Name]; isRole && fn.Recv != nil {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok && (id.Name == "serverJoin" || id.Name == "EtcdJoin") {
						roleMethods[fn.Name.Name] = true
					}
					return true
				})
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				where := fset.Position(call.Pos()).String() + " (" + fn.Name.Name + ")"
				switch sel.Sel.Name {
				case "EnsureHierarchy":
					ensureCallers = append(ensureCallers, fn.Name.Name)
					if len(call.Args) != 3 {
						t.Errorf("%s: EnsureHierarchy takes (workDir, role, posture)", where)
						return true
					}
					var method string
					if rc, ok := call.Args[1].(*ast.CallExpr); ok {
						if rs, ok := rc.Fun.(*ast.SelectorExpr); ok {
							method = rs.Sel.Name
						}
					}
					if _, known := roleMethods[method]; !known {
						t.Errorf("%s: the role argument is not a role derived from --server-join (role/CARole)", where)
					}
				case "EnsureEtcdCAs":
					etcdCallers = append(etcdCallers, fn.Name.Name)
				}
				return true
			})
		}
	}
	if len(ensureCallers) == 0 {
		t.Fatal("no non-test EnsureHierarchy caller found; the gate would be vacuous")
	}
	for name, readsJoin := range roleMethods {
		if !readsJoin {
			t.Errorf("no %s method reads the --server-join role (serverJoin / EtcdJoin)", name)
		}
	}
	sort.Strings(etcdCallers)
	if !slices.Equal(etcdCallers, []string{"provisionEtcdCerts"}) {
		t.Errorf("EnsureEtcdCAs is called by %v, want only provisionEtcdCerts", etcdCallers)
	}
	t.Logf("EnsureHierarchy callers: %v", ensureCallers)
}

// TestServerExecutorConfigCarriesServerJoin pins that serverExecutorConfig hands the
// executor the CA role of --server-join: the executor's Config.CARole (read off the
// etcd member role) agrees with serverOptions.role for every posture, so the CLI and
// the executor cannot disagree about whether this server may mint.
func TestServerExecutorConfigCarriesServerJoin(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for _, tc := range []struct {
		name     string
		opts     serverOptions
		wantJoin bool
		wantRole executor.EtcdRole
	}{
		{"single server", serverOptions{nodeName: "s"}, false, 0},
		{"cluster-init", serverOptions{nodeName: "s", clusterInit: true, etcdPeerIP: "192.0.2.10"}, false, executor.EtcdInit},
		{"server-join", serverOptions{nodeName: "s", serverJoin: true, etcdPeerIP: "192.0.2.11"}, true, executor.EtcdJoin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := serverExecutorConfig(tc.opts, "", logger)
			wantRole := certs.RoleMintAuthority
			if tc.wantJoin {
				wantRole = certs.RoleJoined
			}
			if got := cfg.CARole(); got != wantRole || got != tc.opts.role() {
				t.Errorf("executor CARole = %v, serverOptions.role = %v, want both %v", got, tc.opts.role(), wantRole)
			}
			var role executor.EtcdRole
			if cfg.Etcd != nil {
				role = cfg.Etcd.Role
			}
			if role != tc.wantRole {
				t.Errorf("etcd role = %v, want %v", role, tc.wantRole)
			}
		})
	}
}
