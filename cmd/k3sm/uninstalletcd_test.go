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
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

type fakeSelfRemover struct {
	id        uint64
	removeErr error
	removed   []uint64
	closed    bool
}

func (f *fakeSelfRemover) LocalMemberID(context.Context) (uint64, error) { return f.id, nil }
func (f *fakeSelfRemover) MemberRemove(_ context.Context, id uint64) error {
	f.removed = append(f.removed, id)
	return f.removeErr
}
func (f *fakeSelfRemover) Close() error { f.closed = true; return nil }

func writeEtcdStatusRecord(t *testing.T, workDir, clientURL string) {
	t.Helper()
	b, err := json.Marshal(executor.EtcdStatus{ClientURL: clientURL, MemberName: "server-b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executor.EtcdStatusPath(workDir), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUninstallRemovesSelfBestEffort pins the cmd half of an HA server's uninstall:
// the closure removes THIS server's own member — the ID its loopback member reports,
// on the client port the running server recorded — through the local admin, never a
// peer; every failure comes back as an error (pkg/install logs it beside the
// --cluster-reset remedy and carries on, TestUninstallServerMemberRemoveOrder), never
// a panic or a hang; and runUninstall hands the closure to install.
func TestUninstallRemovesSelfBestEffort(t *testing.T) {
	ctx := context.Background()

	t.Run("removes its own member over loopback", func(t *testing.T) {
		wd := t.TempDir()
		writeEtcdStatusRecord(t, wd, "https://127.0.0.1:12379")
		fake := &fakeSelfRemover{id: 0xb}
		var dialedPort int
		dereg := serverMemberDeregister(wd, func(_ context.Context, workDir string, port int) (selfMemberRemover, error) {
			if workDir != wd {
				t.Errorf("dialled work dir %q, want %q", workDir, wd)
			}
			dialedPort = port
			return fake, nil
		})
		if err := dereg(ctx); err != nil {
			t.Fatalf("deregister: %v", err)
		}
		if dialedPort != 12379 || len(fake.removed) != 1 || fake.removed[0] != 0xb || !fake.closed {
			t.Errorf("port=%d removed=%x closed=%v; want port 12379, removed [b], closed", dialedPort, fake.removed, fake.closed)
		}
	})

	t.Run("a refused removal is an error naming the member", func(t *testing.T) {
		wd := t.TempDir()
		writeEtcdStatusRecord(t, wd, "https://127.0.0.1:12379")
		fake := &fakeSelfRemover{id: 0xb, removeErr: errors.New("etcdserver: no leader")}
		err := serverMemberDeregister(wd, func(context.Context, string, int) (selfMemberRemover, error) { return fake, nil })(ctx)
		if err == nil || !strings.Contains(err.Error(), "etcd member b") || !strings.Contains(err.Error(), "no leader") {
			t.Errorf("err = %v, want the member and the cause", err)
		}
		if !fake.closed {
			t.Error("the client was not closed after a failed removal")
		}
	})

	t.Run("no usable status record: an error, no dial", func(t *testing.T) {
		for _, url := range []string{"", "https://192.168.0.111:2379", "http://127.0.0.1:2379"} {
			wd := t.TempDir()
			if url != "" {
				writeEtcdStatusRecord(t, wd, url)
			}
			err := serverMemberDeregister(wd, func(context.Context, string, int) (selfMemberRemover, error) {
				t.Fatal("dialled with no usable loopback client URL")
				return nil, nil
			})(ctx)
			if !errors.Is(err, executor.ErrNoEtcdClient) {
				t.Errorf("record %q: err = %v, want ErrNoEtcdClient", url, err)
			}
		}
	})

	t.Run("runUninstall hands it to install", func(t *testing.T) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "install.go", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		wired := false
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "runUninstall" {
				return true
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
					return true
				}
				sel, ok := as.Lhs[0].(*ast.SelectorExpr)
				call, isCall := as.Rhs[0].(*ast.CallExpr)
				if ok && sel.Sel.Name == "DeregisterServer" && isCall {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "serverMemberDeregister" {
						wired = true
					}
				}
				return true
			})
			return false
		})
		if !wired {
			t.Error("runUninstall does not set cfg.DeregisterServer from serverMemberDeregister")
		}
	})
}
