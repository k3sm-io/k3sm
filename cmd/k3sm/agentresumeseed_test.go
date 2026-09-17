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
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/nodecred"
)

// The seed-advance gate.
//
// B308 made a resuming node fetch the LIVE MeshPeer list before programming its
// device, but nothing kept that list: the only writer of node-assignment.json was
// Save, which a resume feeds from the credential it just loaded (joinResultFrom),
// so the stored seed was the join-time snapshot written back over itself on every
// start. The device was right and the file was frozen — and the file is exactly
// what the NEXT start's server-peer selection and its fallback are made from, so
// the fallback got staler with every restart instead of tracking the cluster.
//
// What this test decides is narrow and mechanical: the live list reaches the
// assignment file, only the assignment file, and only when there is a live list.

// seededResumeStore writes a real credential whose assignment carries seed, and
// returns the store plus the join outcome the rest of the file compares against.
func seededResumeStore(t *testing.T, seed []netv1.MeshPeerSpec) (nodeCredentialStore, *bootstrap.JoinResult) {
	t.Helper()
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	res.Peers = seed
	return savedStore(t, res), res
}

// storeArtifact is one file of the store as it stood at a moment: its bytes AND
// its modification time. Both are needed — writeStoreFile skips a write whose
// content matches, so bytes alone cannot tell "never opened" from "rewritten
// identically", and only the first is what this change promises.
type storeArtifact struct {
	path  string
	bytes []byte
	mtime time.Time
}

// snapshotFiles records the named files as they stand now.
func snapshotFiles(t *testing.T, paths ...string) []storeArtifact {
	t.Helper()
	out := make([]storeArtifact, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		out = append(out, storeArtifact{path: p, bytes: raw, mtime: fi.ModTime()})
	}
	return out
}

// assertUntouched re-reads a snapshot and fails on any difference in content or
// modification time.
func assertUntouched(t *testing.T, what string, before []storeArtifact) {
	t.Helper()
	for _, a := range before {
		raw, err := os.ReadFile(a.path)
		if err != nil {
			t.Fatalf("re-read %s: %v", a.path, err)
		}
		if !bytes.Equal(raw, a.bytes) {
			t.Errorf("%s: %s was rewritten; %s", what, filepath.Base(a.path), whyUntouchedMatters)
		}
		fi, err := os.Stat(a.path)
		if err != nil {
			t.Fatalf("re-stat %s: %v", a.path, err)
		}
		if !fi.ModTime().Equal(a.mtime) {
			t.Errorf("%s: %s was opened for writing (mtime %s → %s) even though its bytes match; %s",
				what, filepath.Base(a.path), a.mtime, fi.ModTime(), whyUntouchedMatters)
		}
	}
}

const whyUntouchedMatters = "advancing the peer seed must touch node-assignment.json and nothing else — the other four artifacts are this node's identity, and a writer that re-installs certificate material to update a peer list can tear it"

// credentialArtifacts are the four files a seed write must never open.
func credentialArtifacts(s nodeCredentialStore) []string {
	return []string{s.kubeconfigPath(), s.servingCertPath(), s.servingKeyPath(), s.clientCAPath()}
}

// wantAssignment is the assignment file exactly as it should read after the seed
// advanced: the server's original assignment for this node, with peers replaced.
func wantAssignment(t *testing.T, res *bootstrap.JoinResult, peers []netv1.MeshPeerSpec) []byte {
	t.Helper()
	blob, err := json.MarshalIndent(nodecred.Assignment{
		PodCIDR:    res.PodCIDR,
		MeshIP:     res.MeshIP,
		APIServers: res.APIServers,
		Peers:      peers,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal the expected assignment: %v", err)
	}
	return append(blob, '\n')
}

func TestAgentResumeAdvancesTheStoredSeed(t *testing.T) {
	seed := []netv1.MeshPeerSpec{resumeServerPeer(), resumePeerA()}
	live := []netv1.MeshPeerSpec{resumeServerPeer(), resumePeerB()}

	t.Run("the live list becomes the stored seed", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		store, res := seededResumeStore(t, seed)
		untouched := snapshotFiles(t, credentialArtifacts(store)...)

		in := resumeBringUp(t, seed)
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) { return live, nil }
		in.onLivePeers = store.SaveAssignmentPeers
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger()); err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}

		// Read IMMEDIATELY on return, for the same reason B308's gate does: the
		// synchronous return is what node registration follows, so the write must
		// have happened by then rather than be scheduled behind it.
		_, cred, err := nodecred.Store{Dir: store.dir}.Status(time.Now())
		if err != nil {
			t.Fatalf("load the credential back: %v", err)
		}
		if names := peerSpecNames(cred.Assignment.Peers); !equalStrings(names, []string{"server-0", "worker-b"}) {
			t.Errorf("the stored seed is %v; want the live list [server-0 worker-b] — a resume that obtained live state must leave that state behind, or the next start selects its server peer and its fallback out of the original join forever", names)
		}
		// Byte-exact, because "the peers were replaced" is only half the promise:
		// the server's assignment for this node is not re-derivable from a MeshPeer
		// list, so a writer that reconstructed the file would silently drop it.
		got, err := os.ReadFile(store.assignmentPath())
		if err != nil {
			t.Fatalf("read the assignment: %v", err)
		}
		if want := wantAssignment(t, res, live); !bytes.Equal(got, want) {
			t.Errorf("node-assignment.json is\n%s\nwant\n%s", got, want)
		}
		if fi, err := os.Stat(store.assignmentPath()); err != nil {
			t.Fatalf("stat the assignment: %v", err)
		} else if fi.Mode().Perm() != 0o644 {
			t.Errorf("node-assignment.json mode = %o, want 644 — the server's assignment is public material, and a mode change here is a writer that did not go through writeStoreFile", fi.Mode().Perm())
		}

		assertUntouched(t, "after a successful live list", untouched)

		// The device is still programmed the way B308 requires; persisting the seed
		// is an addition to that sequence, not a change to it.
		if names := peerNames(dev.programmed()); !sameNames(names, [][]string{{"server-0"}, {"server-0", "worker-b"}}) {
			t.Errorf("programmed %v; want [[server-0] [server-0 worker-b]]", names)
		}
	})

	t.Run("no live list leaves the stored seed alone", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		store, _ := seededResumeStore(t, seed)
		untouched := snapshotFiles(t, append(credentialArtifacts(store), store.assignmentPath())...)

		in := resumeBringUp(t, seed)
		in.firstSyncTimeout = 50 * time.Millisecond
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) {
			return nil, errors.New("apiserver unreachable")
		}
		in.onLivePeers = store.SaveAssignmentPeers
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger()); err != nil {
			t.Fatalf("bringUpMesh: %v", err)
		}

		// Nothing was learned, so nothing is written. Overwriting the seed with the
		// fallback that was just programmed would be a no-op at best and, if the
		// hook ever moved off the success branch, would let a degraded start erase
		// the last good snapshot this node has.
		assertUntouched(t, "after a failed live list", untouched)
		if names := peerNames(dev.programmed()); !sameNames(names, [][]string{{"server-0"}, {"server-0", "worker-a"}}) {
			t.Errorf("programmed %v; want [[server-0] [server-0 worker-a]] — the seed is still the fallback", names)
		}
	})

	t.Run("a failed write warns and does not fail the bring-up", func(t *testing.T) {
		dev, _ := installFakeMeshSeam(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sink := &syncBuffer{}
		logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
		in := resumeBringUp(t, seed)
		in.listPeers = func(context.Context) ([]netv1.MeshPeerSpec, error) { return live, nil }
		in.onLivePeers = func([]netv1.MeshPeerSpec) error { return errors.New("read-only work dir") }
		if _, err := bringUpMesh(ctx, in, hostnet.Mode{Backend: hostnet.BackendDirect}, logger); err != nil {
			t.Fatalf("bringUpMesh: %v — the device is already programmed with live state when the seed is written; a file that will not be written costs a staler fallback next start, not this node's mesh", err)
		}
		out := sink.String()
		if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "stored seed") {
			t.Errorf("a failed seed write was not reported at WARN; log was:\n%s", out)
		}
		if names := peerNames(dev.programmed()); !sameNames(names, [][]string{{"server-0"}, {"server-0", "worker-b"}}) {
			t.Errorf("programmed %v; want [[server-0] [server-0 worker-b]]", names)
		}
	})

	t.Run("a corrupt assignment is left for the operator, not synthesized", func(t *testing.T) {
		store, _ := seededResumeStore(t, seed)
		if err := os.WriteFile(store.assignmentPath(), []byte("{not json"), 0o644); err != nil {
			t.Fatalf("damage the assignment: %v", err)
		}
		untouched := snapshotFiles(t, store.assignmentPath())
		if err := store.SaveAssignmentPeers(live); err == nil {
			t.Error("SaveAssignmentPeers accepted an assignment it could not parse; rewriting it would invent a podCIDR the server assigned and this node cannot re-derive")
		}
		assertUntouched(t, "after a parse failure", untouched)
	})

	t.Run("only a resume writes back", func(t *testing.T) {
		store, _ := seededResumeStore(t, seed)
		if resumeSeedWriteback(startModeTokenJoin, store) != nil {
			t.Error("the token-join path was given a seed writer; its Save already persisted the live snapshot the join returned")
		}
		if resumeSeedWriteback(startModeReuseCredential, store) == nil {
			t.Error("the resume path was given no seed writer; it is the only path whose stored seed can go stale")
		}
	})
}

// peerSpecNames projects one peer list to node names.
func peerSpecNames(peers []netv1.MeshPeerSpec) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.NodeName)
	}
	return out
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
