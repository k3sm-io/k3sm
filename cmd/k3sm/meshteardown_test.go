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
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/mesh"

	"k3sm.io/k3sm/pkg/hostnet"
)

// fakeMeshDatapath stands in for darwin-net's *mesh.Mesh. Close mirrors the real
// Mesh.Close contract exactly — under a mutex, a no-op once the device is already
// down — because the teardown ordering under test depends on that idempotence: the
// caller's deferred handle and the watcher goroutine's fallback both run it.
//
// Mesh.Close is 1:1 with the device's Down (it is the only thing Close does), so
// downs below counts utun releases; closes counts every call, including the
// no-ops, which is what lets the fallback row wait deterministically.
type fakeMeshDatapath struct {
	mu      sync.Mutex
	meshIP  netip.Addr
	started bool
	downs   int
	closes  int
	// programs records the peer set of every Reconcile, in order. The RESUME
	// gate reads it: what a bring-up programs into the kernel device, and when,
	// is the whole behaviour under test there (see
	// TestAgentResumeSeedsPeersFromALiveList).
	programs [][]netv1.MeshPeerSpec
}

func (f *fakeMeshDatapath) MeshIP() netip.Addr { return f.meshIP }

func (f *fakeMeshDatapath) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = true
	return nil
}

func (f *fakeMeshDatapath) Reconcile(_ context.Context, peers []netv1.MeshPeerSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// COPY: the caller owns the slice and may reuse its backing array, so keeping
	// the header would record whatever it holds later, not what was programmed.
	f.programs = append(f.programs, append([]netv1.MeshPeerSpec(nil), peers...))
	return nil
}

// programmed returns the recorded peer sets, in reconcile order.
func (f *fakeMeshDatapath) programmed() [][]netv1.MeshPeerSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]netv1.MeshPeerSpec, len(f.programs))
	copy(out, f.programs)
	return out
}

func (f *fakeMeshDatapath) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	if !f.started {
		return nil
	}
	f.started = false
	// The device teardown is not instantaneous (route removals, a pf anchor
	// unload). The delay is deliberate: a teardown fired into a goroutine would
	// return to the caller before this count moves, so the "before it returned"
	// assertion below fails rather than passing by scheduling luck.
	time.Sleep(20 * time.Millisecond)
	f.downs++
	return nil
}

func (f *fakeMeshDatapath) counts() (downs, closes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downs, f.closes
}

// fakeMeshWatch blocks until ctx, like the real MeshPeer watcher.
type fakeMeshWatch struct{ done chan struct{} }

func (w *fakeMeshWatch) Run(ctx context.Context) error {
	defer close(w.done)
	<-ctx.Done()
	return ctx.Err()
}

// installFakeMeshSeam swaps the mesh construction seam for the duration of the
// test and returns the fake device and the watcher's exit signal.
func installFakeMeshSeam(t *testing.T) (*fakeMeshDatapath, chan struct{}) {
	t.Helper()
	dev := &fakeMeshDatapath{meshIP: netip.MustParseAddr("100.64.0.1")}
	watchDone := make(chan struct{})
	prev := activeMeshSeam
	activeMeshSeam = meshSeam{
		newMesh: func(netip.Prefix, ...mesh.Option) (meshDatapath, error) { return dev, nil },
		newWatch: func(*rest.Config, meshDatapath, *slog.Logger) (meshWatch, error) {
			return &fakeMeshWatch{done: watchDone}, nil
		},
	}
	t.Cleanup(func() { activeMeshSeam = prev })
	return dev, watchDone
}

// TestAgentMeshTeardownReleasesUtun is B245's mesh-lifecycle gate.
//
// Before it, nothing held the mesh: the only Close was the last act of the
// MeshPeer watcher goroutine, which starts running only after ctx is cancelled —
// i.e. after the signal that is about to end the process. On SIGTERM the process
// could therefore exit with the per-peer routes and the utun-scoped MSS-clamp pf
// anchor still installed, which the next start inherits.
func TestAgentMeshTeardownReleasesUtun(t *testing.T) {
	t.Run("the teardown releases the device before it returns", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		down, err := bringUpMesh(ctx, agentTeardownTestBringUp(t), hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger())
		if err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}
		if downs, _ := dev.counts(); downs != 0 {
			t.Fatalf("the device was torn down %d times during bring-up; want 0", downs)
		}
		if err := down(context.Background()); err != nil {
			t.Fatalf("mesh teardown: %v", err)
		}
		// Read IMMEDIATELY: the handle must have completed the teardown, not
		// scheduled it. A fire-and-forget implementation reads 0 here.
		if downs, _ := dev.counts(); downs != 1 {
			t.Errorf("the device came down %d times by the moment the teardown returned; want 1 — the routes and the pf anchor must be gone BEFORE the process exits", downs)
		}
	})

	t.Run("the watcher goroutine's fallback close is a no-op after it", func(t *testing.T) {
		dev, watchDone := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		down, err := bringUpMesh(ctx, agentTeardownTestBringUp(t), hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger())
		if err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}
		if err := down(context.Background()); err != nil {
			t.Fatalf("mesh teardown: %v", err)
		}
		// Now end the node ctx, as a signal would: the watcher returns and runs its
		// own fallback Close on the way out.
		cancel()
		<-watchDone
		deadline := time.Now().Add(2 * time.Second)
		for {
			_, closes := dev.counts()
			if closes >= 2 || time.Now().After(deadline) {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		downs, closes := dev.counts()
		if closes < 2 {
			t.Fatalf("the watcher goroutine never ran its fallback close (%d closes); the fallback is what covers a path that never reaches the deferred teardown", closes)
		}
		if downs != 1 {
			t.Errorf("the device came down %d times across the deferred teardown and the watcher's fallback; want exactly 1 — Close is idempotent and a second teardown must not re-run route removal", downs)
		}
	})

	t.Run("both node roles defer the teardown", func(t *testing.T) {
		// bringUpMesh returning a handle is worth nothing if no caller holds it, and
		// neither role's start can be called from a unit test (both boot a real
		// node). The wiring is asserted structurally instead, which is what the
		// well-meaning later edit that drops the defer would trip. The agent's
		// body is agentStart — runAgent is the thin wrapper that records a start
		// failure on the crash-loop record — so that is the function that must
		// hold the handle.
		for _, tc := range []struct {
			file, fn, why string
		}{
			{"agent.go", "agentStart", "a worker's mesh teardown must run after startNode returns, before the process exits"},
			{"server.go", "runServer", "the control-plane node's mesh must come down on the way out, not be left to a goroutine racing process death"},
		} {
			body := funcBodyInFile(t, tc.file, tc.fn)
			if deferPos(body, "meshDown") == token.NoPos {
				t.Errorf("%s does not defer its mesh teardown handle (meshDown) — %s", tc.fn, tc.why)
			}
		}
	})

	t.Run("the server tears its mesh down after the control plane", func(t *testing.T) {
		// Registration order IS run order, reversed. The mesh teardown must be
		// registered BEFORE exec.Stop's defer so LIFO runs it AFTER: in the mesh
		// posture the apiserver binds and advertises the mesh IP, so releasing the
		// utun and its alias first would pull the interface out from under a control
		// plane still draining its components. The agent has no such constraint —
		// its mesh teardown is simply last, after startNode returns.
		body := funcBodyInFile(t, "server.go", "runServer")
		mesh := deferPos(body, "meshDown")
		stop := deferOfSelector(body, "exec", "Stop")
		switch {
		case mesh == token.NoPos:
			t.Fatal("runServer defers no mesh teardown")
		case stop == token.NoPos:
			t.Fatal("runServer defers no exec.Stop — the ordering this row pins has no anchor")
		case mesh > stop:
			t.Error("runServer registers its mesh teardown AFTER exec.Stop's defer, so LIFO tears the mesh down FIRST — the apiserver binds the mesh IP, and pulling it out from under a draining control plane is exactly the fault this ordering exists to prevent")
		}
	})
}

// agentTeardownTestBringUp is the bring-up input both rows share: a real pod /24
// and the mesh-egress /32 it derives, pointed at a kubeconfig that parses (the
// watcher's REST config is built from it) and no refresher.
func agentTeardownTestBringUp(t *testing.T) meshBringUp {
	t.Helper()
	return meshBringUp{
		podCIDR:    "100.64.0.0/24",
		meshIP:     "100.64.0.1",
		keyRef:     meshKeyRef,
		listenPort: 51820,
		kubeconfig: writeNodeRESTKubeconfig(t, "https://127.0.0.1:6443"),
	}
}

// funcBodyInFile parses file and returns the named top-level function's body.
func funcBodyInFile(t *testing.T, file, name string) *ast.BlockStmt {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, decl := range parsed.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn.Body
		}
	}
	t.Fatalf("%s declares no %s function", file, name)
	return nil
}

// deferPos returns the position of the FIRST defer statement in body that
// mentions ident (directly or inside a deferred closure), or token.NoPos. The
// position is the registration site, which is what the LIFO order is read from.
func deferPos(body *ast.BlockStmt, ident string) token.Pos {
	return firstDefer(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		return ok && id.Name == ident
	})
}

// deferOfSelector returns the position of the first defer statement in body that
// calls pkg.sel (e.g. exec.Stop), or token.NoPos.
func deferOfSelector(body *ast.BlockStmt, x, sel string) token.Pos {
	return firstDefer(body, func(n ast.Node) bool {
		s, ok := n.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != sel {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && id.Name == x
	})
}

// firstDefer returns the position of the first defer statement in body
// containing a node match reports true for.
func firstDefer(body *ast.BlockStmt, match func(ast.Node) bool) token.Pos {
	found := token.NoPos
	ast.Inspect(body, func(n ast.Node) bool {
		def, ok := n.(*ast.DeferStmt)
		if !ok || found != token.NoPos {
			return found == token.NoPos
		}
		hit := false
		ast.Inspect(def, func(m ast.Node) bool {
			if match(m) {
				hit = true
			}
			return true
		})
		if hit {
			found = def.Pos()
		}
		return true
	})
	return found
}
