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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore/socket"
)

// TestRunServerStartsKeystoreSocket pins the startup call: runServer defers
// the keystore-socket teardown step over startKeystoreSocket with the
// activated listener source (keystoreSocketListener), after the
// keystore-delivery step, so LIFO stops the listener first and both before
// the control plane.
func TestRunServerStartsKeystoreSocket(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "runServer" {
			run = fd
		}
	}
	if run == nil {
		t.Fatal("no runServer in server.go")
	}
	var steps []string
	var socketCall *ast.CallExpr
	ast.Inspect(run.Body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if id, ok := ds.Call.Fun.(*ast.Ident); !ok || id.Name != "timedTeardownStep" || len(ds.Call.Args) != 3 {
			return true
		}
		lit, ok := ds.Call.Args[1].(*ast.BasicLit)
		if !ok {
			return true
		}
		name, _ := strconv.Unquote(lit.Value)
		steps = append(steps, name)
		if name == "keystore-socket" {
			socketCall, _ = ds.Call.Args[2].(*ast.CallExpr)
		}
		return true
	})
	if socketCall == nil {
		t.Fatalf("runServer defers no keystore-socket step; steps %q", steps)
	}
	if id, ok := socketCall.Fun.(*ast.Ident); !ok || id.Name != "startKeystoreSocket" || len(socketCall.Args) != 5 {
		t.Fatal("the keystore-socket step is not startKeystoreSocket(...)")
	}
	if c, ok := socketCall.Args[3].(*ast.CallExpr); !ok || c.Fun.(*ast.Ident).Name != "keystoreSocketListener" {
		t.Fatal("startKeystoreSocket's listener is not keystoreSocketListener()")
	}
	idx := func(s string) int {
		for i, v := range steps {
			if v == s {
				return i
			}
		}
		return -1
	}
	if d, k := idx("keystore-delivery"), idx("keystore-socket"); d < 0 || k < d {
		t.Fatalf("keystore-socket (%d) is not deferred after keystore-delivery (%d)", k, d)
	}
}

// A process launchd did not start as the server's job (this test) gets no
// activated socket: the production source refuses with ErrNotActivated and
// binds nothing, which keeps the user scope off as the listening socket
// being unavailable.
func TestKeystoreSocketListenerOffOutsideLaunchd(t *testing.T) {
	ln, err := keystoreSocketListener("/var/lib/k3sm/server")(context.Background())
	if ln != nil {
		_ = ln.Close()
		t.Fatal("a listener outside the launchd job")
	}
	if !errors.Is(err, socket.ErrNotActivated) {
		t.Fatalf("got %v, want ErrNotActivated", err)
	}
}

// The path the server requires of launchd's descriptor is the one the
// server plist's Sockets entry names.
func TestKeystoreSocketPathIsThePlists(t *testing.T) {
	cfg := install.Config{}
	plist := string(install.ServerPlist(cfg))
	want := keystoreSocketPath("/var/lib/k3sm/server")
	if want != "/var/lib/k3sm/keystore-sock/keys.sock" || !strings.Contains(plist, "<string>"+want+"</string>") {
		t.Fatalf("the server requires %s; the plist names it: %v", want, strings.Contains(plist, want))
	}
}

// fixedActivator hands out one listening socket at path, then EALREADY.
type fixedActivator struct {
	t    *testing.T
	path string
	done bool
}

func (a *fixedActivator) Activate(string) ([]int, error) {
	if a.done {
		return nil, unix.EALREADY
	}
	a.done = true
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		a.t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: a.path}); err != nil {
		a.t.Fatal(err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		a.t.Fatal(err)
	}
	unix.CloseOnExec(fd)
	return []int{fd}, nil
}

// The activation's path check is doctor's rule: a socket at the clients'
// path that this (non-root) user owns, in its group, is refused as OffActivatedWrong, the
// descriptor launchd handed over notwithstanding; a missing path and a
// regular file are refused by the same rule (TestDoctorKeystoreSocketLstat).
func TestActivationRefusesClientPathNotRoots(t *testing.T) {
	dir, err := os.MkdirTemp("", "kswd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "keys.sock")
	act := socket.NewActivation(install.KeystoreSocketsEntry, path, &fixedActivator{t: t, path: path}, checkKeystoreSocketPath)
	_, err = act.Source()(context.Background())
	var ae *socket.ActivationError
	if !errors.As(err, &ae) || ae.Reason != socket.OffActivatedWrong || !errors.Is(err, errNoListeningSocket) {
		t.Fatalf("got %v, want OffActivatedWrong over doctor's no-listening-socket rule", err)
	}
	for _, p := range []string{filepath.Join(dir, "absent"), dir} {
		if err := checkKeystoreSocketPath(p); !errors.Is(err, errNoListeningSocket) {
			t.Errorf("%s: %v, want no listening socket", p, err)
		}
	}
}

// The holder records the first work dir; a source asked for another one
// refuses, terminally, and never hands out the first one's listener.
func TestKeystoreActivationHolderRefusesAnotherWorkDir(t *testing.T) {
	var h keystoreActivationHolder
	first := h.source("/var/lib/k3sm/server", &fixedActivator{t: t, path: "/nonexistent"})
	_, err := h.source("/Volumes/other/server", &fixedActivator{t: t})(context.Background())
	var ae *socket.ActivationError
	if !errors.Is(err, errActivationWorkDir) || !errors.As(err, &ae) || ae.Reason != socket.OffActivatedWrong {
		t.Fatalf("another work dir: %v, want errActivationWorkDir as OffActivatedWrong", err)
	}
	if first == nil || h.source("/var/lib/k3sm/server/", nil) == nil {
		t.Fatal("the first work dir's source")
	}
}
