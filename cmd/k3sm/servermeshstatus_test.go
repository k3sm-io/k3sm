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
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"k8s.io/client-go/rest"

	"k3sm.io/darwin-net/pkg/mesh"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
)

// installOptRecordingMeshSeam swaps the mesh seam for one that records how many
// watcher options each bring-up passed.
func installOptRecordingMeshSeam(t *testing.T) func() []int {
	t.Helper()
	var mu sync.Mutex
	var seen []int
	prev := activeMeshSeam
	activeMeshSeam = meshSeam{
		newMesh: func(netip.Prefix, ...mesh.Option) (meshDatapath, error) {
			return &fakeMeshDatapath{meshIP: netip.MustParseAddr("100.64.0.1")}, nil
		},
		newWatch: func(_ *rest.Config, _ meshDatapath, _ *slog.Logger, opts ...mesh.WatcherOption) (meshWatch, error) {
			mu.Lock()
			seen = append(seen, len(opts))
			mu.Unlock()
			return &fakeMeshWatch{done: make(chan struct{})}, nil
		},
	}
	t.Cleanup(func() { activeMeshSeam = prev })
	return func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), seen...)
	}
}

// TestServerMeshWritesHandshakeStatus pins who writes MeshPeer
// status.lastHandshakeTime: the control-plane node's MeshPeer watch is built
// with mesh.WithHandshakeStatus (its identity already writes MeshPeers), and a
// worker's watch is built with no option, so no node identity needs write
// authority on MeshPeers.
func TestServerMeshWritesHandshakeStatus(t *testing.T) {
	t.Run("the server's watch writes status", func(t *testing.T) {
		seen := installOptRecordingMeshSeam(t)
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
		if got := seen(); len(got) != 1 || got[0] != 1 {
			t.Fatalf("server watch options = %v, want one watch with exactly one option (WithHandshakeStatus)", got)
		}
	})

	t.Run("a worker's watch stays read-only", func(t *testing.T) {
		seen := installOptRecordingMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		down, err := bringUpMesh(ctx, agentTeardownTestBringUp(t), hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger())
		if err != nil {
			t.Fatalf("worker mesh bring-up: %v", err)
		}
		defer func() { _ = down(context.Background()) }()
		if got := seen(); len(got) != 1 || got[0] != 0 {
			t.Fatalf("worker watch options = %v, want one watch with no option", got)
		}
	})
}
