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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/hostnet"
)

// The resume fixture. The apiserver a restarted worker targets is the SERVER's
// mesh address (workerAPIServerURL), so the seed's server peer is the one whose
// AllowedIPs cover it — and the only one a resuming node may program before it
// has asked the cluster anything.
//
// Peer A and peer B share a pod /24 on purpose: that is the live hazard, not a
// contrived one. A node removed from the cluster frees its index, and
// lowestFreeNodeIndex hands the same index to the next joiner, so a seed entry
// can name the OLD node's public key for a /24 the NEW node owns. Programming the
// seed whole encrypts that /24's traffic to a key nobody holds.
const resumeAPIServerHost = "10.42.0.1"

func resumeServerPeer() netv1.MeshPeerSpec {
	return netv1.MeshPeerSpec{
		NodeName: "server-0", PublicKey: "serverKey", Endpoint: "192.168.1.10:51820",
		PodCIDR: "10.42.0.0/24", AllowedIPs: []string{"10.42.0.0/24"}, MeshIP: resumeAPIServerHost,
	}
}

func resumePeerA() netv1.MeshPeerSpec {
	return netv1.MeshPeerSpec{
		NodeName: "worker-a", PublicKey: "aKeyRemovedFromTheCluster", Endpoint: "192.168.1.20:51820",
		PodCIDR: "10.42.2.0/24", AllowedIPs: []string{"10.42.2.0/24"}, MeshIP: "10.42.2.1",
	}
}

func resumePeerB() netv1.MeshPeerSpec {
	return netv1.MeshPeerSpec{
		NodeName: "worker-b", PublicKey: "bKeyOnTheRecycledIndex", Endpoint: "192.168.1.30:51820",
		PodCIDR: "10.42.2.0/24", AllowedIPs: []string{"10.42.2.0/24"}, MeshIP: "10.42.2.1",
	}
}

// resumeBringUp is the bring-up input the rows share: the stored seed, a
// kubeconfig pointing at the server's MESH address (which is what makes the seed's
// server peer the one that must be programmed first), and no refresher.
//
// meshIP is left empty so the device's mesh-egress assertion is out of scope —
// the fake derives a fixed address and this gate is about the peer program.
func resumeBringUp(t *testing.T, seed []netv1.MeshPeerSpec) meshBringUp {
	t.Helper()
	return meshBringUp{
		podCIDR:    "10.42.3.0/24",
		keyRef:     meshKeyRef,
		listenPort: 51820,
		kubeconfig: writeNodeRESTKubeconfig(t, "https://"+resumeAPIServerHost+":6443"),
		peers:      seed,
		resume:     true,
	}
}

// syncBuffer is a mutex-guarded log sink: bringUpMesh starts goroutines that may
// log, so an unguarded bytes.Buffer races under -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// peerNames projects the recorded programs to node names, which is what the
// assertions are about and what a failure message can be read in.
func peerNames(programs [][]netv1.MeshPeerSpec) [][]string {
	out := make([][]string, 0, len(programs))
	for _, program := range programs {
		names := make([]string, 0, len(program))
		for _, peer := range program {
			names = append(names, peer.NodeName)
		}
		out = append(out, names)
	}
	return out
}

func sameNames(got [][]string, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if len(got[i]) != len(want[i]) {
			return false
		}
		for j := range got[i] {
			if got[i][j] != want[i][j] {
				return false
			}
		}
	}
	return true
}

// TestAgentResumeSeedsPeersFromALiveList is B308's gate.
//
// Before it, the credential-resume path programmed cred.Assignment.Peers — the
// snapshot of the ORIGINAL join, which Save writes back unchanged on every start
// — into the kernel device before the MeshPeer watcher existed. A peer removed or
// re-keyed since that join was programmed for the whole window until the watcher's
// first sync, and with the free-index scan recycling a removed node's index, a
// stale entry can name the wrong key for a pod CIDR a new node now owns.
func TestAgentResumeSeedsPeersFromALiveList(t *testing.T) {
	seed := []netv1.MeshPeerSpec{resumeServerPeer(), resumePeerA()}
	live := []netv1.MeshPeerSpec{resumeServerPeer(), resumePeerB()}

	t.Run("the live list replaces the seed, and only the server peer precedes it", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		calls := 0
		in := resumeBringUp(t, seed)
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) {
			calls++
			return live, nil
		}
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger()); err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}
		// Read IMMEDIATELY on return: bringUpMesh's synchronous return is the
		// readiness gate the VK node registration follows, so the live program must
		// have happened by now, not be scheduled.
		got := peerNames(dev.programmed())
		want := [][]string{{"server-0"}, {"server-0", "worker-b"}}
		if !sameNames(got, want) {
			t.Fatalf("programmed %v; want %v — a resuming node programs the server peer alone, then the LIVE list", got, want)
		}
		for i, program := range dev.programmed() {
			for _, peer := range program {
				if peer.NodeName == "worker-a" {
					t.Errorf("reconcile %d programmed the removed peer %q (key %q) from the stored seed; the cluster no longer has it and its /24 belongs to %q", i, peer.NodeName, peer.PublicKey, "worker-b")
				}
			}
		}
		if calls != 1 {
			t.Errorf("the live MeshPeer list was fetched %d times; want 1", calls)
		}
	})

	t.Run("the seed is the fallback after the first-sync bound, and the bound is named", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		const bound = 100 * time.Millisecond
		sink := &syncBuffer{}
		logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
		in := resumeBringUp(t, seed)
		in.firstSyncTimeout = bound
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) {
			return nil, errors.New("apiserver unreachable")
		}
		start := time.Now()
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, logger); err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}
		elapsed := time.Since(start)

		got := peerNames(dev.programmed())
		want := [][]string{{"server-0"}, {"server-0", "worker-a"}}
		if !sameNames(got, want) {
			t.Fatalf("programmed %v; want %v — with no live list the seed is the fallback, because a possibly-stale peer set beats none and the watcher corrects it", got, want)
		}
		if elapsed < bound {
			t.Errorf("bringUpMesh returned after %s, before its own %s bound; the wait for the live list is what keeps the stale seed out of the kernel", elapsed, bound)
		}
		if elapsed > bound+2*time.Second {
			t.Errorf("bringUpMesh took %s for a %s bound; the bound is what a resuming node's registration waits on", elapsed, bound)
		}
		out := sink.String()
		if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "bound=100ms") {
			t.Errorf("the fallback was not reported at WARN with its bound; log was:\n%s", out)
		}
	})

	t.Run("a hung lister cannot outlast the bound", func(t *testing.T) {
		// The bound is only real if an attempt can be cut short. The agent's ctx is
		// the signal context and carries no deadline, so a lister that blocks until
		// its OWN ctx ends — an apiserver that accepts the connection and never
		// answers — held node start open indefinitely before the per-attempt timeout.
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		const bound = 300 * time.Millisecond
		in := resumeBringUp(t, seed)
		in.firstSyncTimeout = bound
		in.listPeers = func(ctx context.Context) ([]netv1.MeshPeerSpec, error) {
			<-ctx.Done() // never returns on its own
			return nil, ctx.Err()
		}
		start := time.Now()
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger()); err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}
		if elapsed := time.Since(start); elapsed > bound+time.Second {
			t.Errorf("bringUpMesh took %s against a %s bound with a hung lister; the attempt must be cut short, or node start waits on an apiserver that never answers", elapsed, bound)
		}
		got := peerNames(dev.programmed())
		want := [][]string{{"server-0"}, {"server-0", "worker-a"}}
		if !sameNames(got, want) {
			t.Fatalf("programmed %v; want %v — a hung list is the fallback case like any other failure", got, want)
		}
	})

	t.Run("an unloadable kubeconfig is reported before the bound is spent", func(t *testing.T) {
		// The resume path needs the kubeconfig for both the list and the watcher, so
		// one that will not load is a failure the bring-up already knows — waiting
		// the full first-sync bound to re-discover it only delays the same error.
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		broken := filepath.Join(t.TempDir(), "kubeconfig")
		if err := os.WriteFile(broken, []byte("{not a kubeconfig"), 0o600); err != nil {
			t.Fatalf("write kubeconfig: %v", err)
		}
		listed := false
		in := resumeBringUp(t, seed)
		in.kubeconfig = broken
		in.firstSyncTimeout = time.Minute // never reached
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) {
			listed = true
			return live, nil
		}
		start := time.Now()
		down, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger())
		if err == nil {
			t.Fatal("bringUpMesh accepted a kubeconfig that will not load; the watcher it needs cannot be built from it")
		}
		if !strings.Contains(err.Error(), "load kubeconfig for mesh watch") {
			t.Errorf("bringUpMesh reported %v; want the kubeconfig load failure", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("bringUpMesh took %s to report a kubeconfig that will not load; it must not spend the first-sync bound first", elapsed)
		}
		if listed {
			t.Error("the lister ran against a kubeconfig that will not load")
		}
		if programs := dev.programmed(); len(programs) != 0 {
			t.Errorf("programmed %v; want nothing — the bring-up failed before any peer decision", peerNames(programs))
		}
		// The device came up before the failure, so the caller gets a REAL teardown.
		if err := down(context.Background()); err != nil {
			t.Errorf("mesh teardown: %v", err)
		}
		if downs, _ := dev.counts(); downs != 1 {
			t.Errorf("the device came down %d times; want 1 — a half-built bring-up still owns a utun", downs)
		}
	})

	t.Run("a seed with no server peer programs nothing before the live list", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		in := resumeBringUp(t, []netv1.MeshPeerSpec{resumePeerA()})
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) { return live, nil }
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger()); err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}
		got := peerNames(dev.programmed())
		want := [][]string{{"server-0", "worker-b"}}
		if !sameNames(got, want) {
			t.Fatalf("programmed %v; want %v — with no peer covering the apiserver the tunnel is not the path to it, so nothing is programmed until the live list arrives", got, want)
		}
	})

	t.Run("the token-join path programs its live peers and lists nothing", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		listed := false
		in := resumeBringUp(t, seed)
		in.resume = false
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) {
			listed = true
			return live, nil
		}
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger()); err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}
		got := peerNames(dev.programmed())
		want := [][]string{{"server-0", "worker-a"}}
		if !sameNames(got, want) {
			t.Fatalf("programmed %v; want %v — a join just happened, so its peer snapshot IS live and is programmed whole", got, want)
		}
		if listed {
			t.Error("the join path fetched a live MeshPeer list; it already has one, and the extra round-trip would delay every fresh join")
		}
	})
}

// TestServerPeerFromSeed pins the selection: the peer whose mesh addresses carry
// the apiserver's address, matched structurally rather than by name or index.
func TestServerPeerFromSeed(t *testing.T) {
	noAllowedIPs := netv1.MeshPeerSpec{NodeName: "server-0", PodCIDR: "10.42.0.0/24"}
	for _, tc := range []struct {
		name  string
		peers []netv1.MeshPeerSpec
		host  string
		want  string // the selected node name, "" for no match
	}{
		{"AllowedIPs cover the apiserver", []netv1.MeshPeerSpec{resumeServerPeer(), resumePeerA()}, resumeAPIServerHost, "server-0"},
		{"the covering peer is found wherever it sits", []netv1.MeshPeerSpec{resumePeerA(), resumeServerPeer()}, resumeAPIServerHost, "server-0"},
		{"podCIDR stands in when a spec carries no AllowedIPs", []netv1.MeshPeerSpec{noAllowedIPs}, resumeAPIServerHost, "server-0"},
		{"a peer whose own mesh IP it is", []netv1.MeshPeerSpec{resumePeerA()}, "10.42.2.1", "worker-a"},
		{"no peer covers the apiserver", []netv1.MeshPeerSpec{resumePeerA()}, resumeAPIServerHost, ""},
		{"an empty seed", nil, resumeAPIServerHost, ""},
		{"a DNS name cannot be matched without the tunnel it would need", []netv1.MeshPeerSpec{resumeServerPeer()}, "apiserver.cluster.local", ""},
		{"an empty host", []netv1.MeshPeerSpec{resumeServerPeer()}, "", ""},
		{"an unparseable AllowedIPs entry is skipped, not fatal", []netv1.MeshPeerSpec{{NodeName: "junk", AllowedIPs: []string{"not-a-cidr"}}, resumeServerPeer()}, resumeAPIServerHost, "server-0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := serverPeerFromSeed(tc.peers, tc.host)
			if tc.want == "" {
				if ok {
					t.Fatalf("serverPeerFromSeed selected %q; want no match", got.NodeName)
				}
				return
			}
			if !ok {
				t.Fatalf("serverPeerFromSeed found no peer covering %s; want %q", tc.host, tc.want)
			}
			if got.NodeName != tc.want {
				t.Errorf("serverPeerFromSeed selected %q; want %q", got.NodeName, tc.want)
			}
		})
	}
}
