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
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore/socket"
)

// TestRunServerStartsKeystoreSocket pins the startup call: runServer defers
// the keystore-socket teardown step over startKeystoreSocket with the
// runtime's posture (serverPodPosture) and the activated listener source
// (keystoreSocketListener), after the
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
	if id, ok := socketCall.Fun.(*ast.Ident); !ok || id.Name != "startKeystoreSocket" || len(socketCall.Args) != 6 {
		t.Fatal("the keystore-socket step is not startKeystoreSocket(...)")
	}
	noted := false
	ast.Inspect(run.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "notePodProfileCheckScope" {
				noted = true
			}
		}
		return true
	})
	if !noted {
		t.Fatal("runServer does not log the Pod-profile check's scope (notePodProfileCheckScope)")
	}
	if !derivesServerPodPosture(socketCall.Args[2]) {
		t.Fatal("startKeystoreSocket's posture is not func() { return serverPodPosture(...) }, the one the node's runtime renders from")
	}
	if c, ok := socketCall.Args[4].(*ast.CallExpr); !ok || c.Fun.(*ast.Ident).Name != "keystoreSocketListener" {
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

// derivesServerPodPosture reports whether e is a func literal whose one
// statement returns serverPodPosture(...).
func derivesServerPodPosture(e ast.Expr) bool {
	lit, ok := e.(*ast.FuncLit)
	if !ok || len(lit.Body.List) != 1 {
		return false
	}
	ret, ok := lit.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "serverPodPosture"
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

// The holder records the first work dir; a source asked for another one
// refuses, terminally, without asking launchd, and never hands out the
// first one's listener.
func TestKeystoreActivationHolderRefusesAnotherWorkDir(t *testing.T) {
	var h keystoreActivationHolder
	first := &countingActivator{}
	if h.source("/var/lib/k3sm/server", first) == nil {
		t.Fatal("the first work dir's source")
	}
	other := &countingActivator{}
	ln, err := h.source("/Volumes/other/server", other)(context.Background())
	var ae *socket.ActivationError
	if ln != nil || !errors.Is(err, errActivationWorkDir) || !errors.As(err, &ae) || ae.Reason != socket.OffActivatedWrong {
		t.Fatalf("another work dir: %v, %v; want errActivationWorkDir as OffActivatedWrong", ln, err)
	}
	if first.calls != 0 || other.calls != 0 {
		t.Fatalf("launchd asked %d and %d times; a refused work dir asks it nothing", first.calls, other.calls)
	}
	if _, err := h.source("/var/lib/k3sm/server/", nil)(context.Background()); errors.Is(err, errActivationWorkDir) {
		t.Fatalf("the first work dir, spelled with a trailing slash: %v", err)
	}
	if first.calls != 1 {
		t.Fatalf("the first work dir's source asked launchd %d times, want 1 (its own activator)", first.calls)
	}
}

// countingActivator counts its calls and answers ESRCH, as launchd does a
// process that is not the job.
type countingActivator struct{ calls int }

func (a *countingActivator) Activate(string) ([]int, error) {
	a.calls++
	return nil, unix.ESRCH
}
