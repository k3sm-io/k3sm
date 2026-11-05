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
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"k8s.io/client-go/rest"

	"k3sm.io/darwin-net/pkg/mesh"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
)

// meshSeamCall is what one bring-up handed the mesh seam: the self prefix and
// option count of each newMesh call, and, for each newWatch call, whether the
// watch options it was given make a real mesh.Watcher write MeshPeer status.
type meshSeamCall struct {
	meshSelf  []netip.Prefix
	meshOpts  []int
	watchOpts []int
	writes    []bool
}

// installEffectRecordingMeshSeam swaps the mesh seam for one that records every
// newMesh and newWatch call. It judges the watch options by their EFFECT: it
// applies them to a real mesh.Watcher built by mesh.NewWatcher (no informer is
// started, so nothing dials) and reads WritesHandshakeStatus. Comparing the
// options' code pointers instead would pass a wrapper or a copy of the literal
// that sets nothing, and could be fooled by the linker sharing one pointer.
func installEffectRecordingMeshSeam(t *testing.T) func() meshSeamCall {
	t.Helper()
	var mu sync.Mutex
	var rec meshSeamCall
	prev := activeMeshSeam
	activeMeshSeam = meshSeam{
		newMesh: func(self netip.Prefix, opts ...mesh.Option) (meshDatapath, error) {
			mu.Lock()
			rec.meshSelf = append(rec.meshSelf, self)
			rec.meshOpts = append(rec.meshOpts, len(opts))
			mu.Unlock()
			return &fakeMeshDatapath{meshIP: netip.MustParseAddr("100.64.0.1")}, nil
		},
		newWatch: func(cfg *rest.Config, _ meshDatapath, _ *slog.Logger, opts ...mesh.WatcherOption) (meshWatch, error) {
			w, err := mesh.NewWatcher(cfg, nil, quietLogger(), opts...)
			if err != nil {
				return nil, fmt.Errorf("build a real watcher to apply the options to: %w", err)
			}
			mu.Lock()
			rec.watchOpts = append(rec.watchOpts, len(opts))
			rec.writes = append(rec.writes, w.WritesHandshakeStatus())
			mu.Unlock()
			return &fakeMeshWatch{done: make(chan struct{})}, nil
		},
	}
	t.Cleanup(func() { activeMeshSeam = prev })
	return func() meshSeamCall {
		mu.Lock()
		defer mu.Unlock()
		return meshSeamCall{
			meshSelf:  append([]netip.Prefix(nil), rec.meshSelf...),
			meshOpts:  append([]int(nil), rec.meshOpts...),
			watchOpts: append([]int(nil), rec.watchOpts...),
			writes:    append([]bool(nil), rec.writes...),
		}
	}
}

// checkMeshSeamCall fails the test unless the bring-up built exactly one mesh
// for wantSelf with at least one option, and exactly one watch with wantOpts
// options whose effect on a real watcher is wantWrites.
func checkMeshSeamCall(t *testing.T, got meshSeamCall, wantSelf netip.Prefix, wantOpts int, wantWrites bool) {
	t.Helper()
	if len(got.meshSelf) != 1 || got.meshSelf[0] != wantSelf || got.meshOpts[0] == 0 {
		t.Errorf("newMesh calls: self %v with %v options, want one call for %v with its options", got.meshSelf, got.meshOpts, wantSelf)
	}
	if len(got.writes) != 1 || got.watchOpts[0] != wantOpts || got.writes[0] != wantWrites {
		t.Errorf("newWatch calls: %v options writing status %v, want one call with %d option(s) writing status %v",
			got.watchOpts, got.writes, wantOpts, wantWrites)
	}
}

// TestServerMeshWatcherOptionAppliesStatusPatcher pins who writes MeshPeer
// status.lastHandshakeTime, by effect: the options the control-plane node's
// MeshPeer watch is built with make a real mesh.Watcher write status (its
// identity already writes MeshPeers), and a worker's watch is built with no
// option and stays read-only, so no node identity needs write authority on
// MeshPeers.
func TestServerMeshWatcherOptionAppliesStatusPatcher(t *testing.T) {
	t.Run("the server's watch writes status", func(t *testing.T) {
		seen := installEffectRecordingMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e, _ := enrollerOverStub(t)
		opts := selfEnrollOptions(t.TempDir(), "k3sm-host")
		_, down, err := enrollSelfAndBringUpMesh(ctx, e, bootstrap.NewMemoryNodePasswords(), opts, firstServerCIDR,
			hostnet.Mode{Backend: hostnet.BackendDirect}, writeNodeRESTKubeconfig(t, "https://127.0.0.1:6443"), quietLogger())
		if err != nil {
			t.Fatalf("server mesh bring-up: %v", err)
		}
		defer func() { _ = down(context.Background()) }()
		checkMeshSeamCall(t, seen(), firstServerCIDR, 1, true)
	})

	t.Run("a worker's watch stays read-only", func(t *testing.T) {
		seen := installEffectRecordingMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		in := agentTeardownTestBringUp(t)
		down, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger())
		if err != nil {
			t.Fatalf("worker mesh bring-up: %v", err)
		}
		defer func() { _ = down(context.Background()) }()
		checkMeshSeamCall(t, seen(), netip.MustParsePrefix(in.podCIDR), 0, false)
	})
}
