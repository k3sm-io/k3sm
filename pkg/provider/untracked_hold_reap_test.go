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

package provider

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"k3sm.io/k3sm/pkg/provider/podlogs"
)

// failCreateForReap leaves x's pod in the state a failed create does: an address and
// references held, no track.
func failCreateForReap(ctx context.Context, t *testing.T, x *terminalUpdateFixture) *fakePodSource {
	t.Helper()
	src := &fakePodSource{got: map[string]*corev1.Pod{}}
	x.r.podSource = src
	failing := x.pod.DeepCopy()
	failing.Spec.Volumes = emptyDirPod("failing", "Memory").Spec.Volumes
	if err := x.r.CreatePod(ctx, failing); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
		t.Fatalf("the create = %v, want ErrEmptyDirMediumUnsupported", err)
	}
	id := string(x.pod.UID)
	if _, ok := x.ipam.allocations()[id]; !ok {
		t.Fatal("the failed create allocated no /32, so the test proves nothing")
	}
	if tr := x.r.trackByID(id); tr != nil {
		t.Fatalf("the failed create left a track (%s)", trackState(tr))
	}
	return src
}

// TestReaperReleasesHeldUIDWithNoTrack: Virtual Kubelet removes a pod whose create
// failed, with no container running, without a DeletePod, and finds no track when the
// object goes. The reaper is then the only thing that can free what the create took.
// Fails when the reaper keys on tracks alone: the /32, its alias, the slot and the
// references stay until the daemon restarts.
func TestReaperReleasesHeldUIDWithNoTrack(t *testing.T) {
	ctx := context.Background()

	t.Run("the object is gone for the threshold", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		failCreateForReap(ctx, t, x)
		for i := int32(1); i < orphanReapThreshold; i++ {
			x.r.reapOrphans(ctx)
			if _, n := p.counts(); n != 0 {
				t.Fatalf("releases after %d gone ticks = %d, want 0 below the threshold", i, n)
			}
		}
		logs := podlogs.BuildPodLogsDirectory(x.r.logGC.PodLogsDir, x.pod.Namespace, x.pod.Name, string(x.pod.UID))
		if _, err := os.Stat(logs); err != nil {
			t.Fatalf("the failed create left no log tree, so the test proves nothing: %v", err)
		}
		x.r.reapOrphans(ctx)
		x.assertForgotten(t)
		if _, err := os.Stat(logs); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the pod's log tree after the release: %v, want it gone", err)
		}
		x.r.reapOrphans(ctx)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
		x.r.orphanMu.Lock()
		gauges := len(x.r.orphanGauges)
		x.r.orphanMu.Unlock()
		if gauges != 0 {
			t.Errorf("orphan gauges = %d, want 0", gauges)
		}
	})

	t.Run("a new pod holds the name", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		src := failCreateForReap(ctx, t, x)
		successor := x.pod.DeepCopy()
		successor.UID = types.UID("successor")
		src.got[x.pod.Namespace+"/"+x.pod.Name] = successor
		for range orphanReapThreshold {
			x.r.reapOrphans(ctx)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})

	// A create retrying on its back-off keeps its address, and the retry that runs is
	// the one the "a retry that runs keeps the address" case of
	// TestFailedCreateThenRefusalHoldsNothing pins.
	t.Run("the object is still listed", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		src := failCreateForReap(ctx, t, x)
		src.listed = []corev1.Pod{*x.pod}
		for range orphanReapThreshold + 1 {
			x.r.reapOrphans(ctx)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases = %d, want 0", n)
		}
		if src.gets != 0 {
			t.Errorf("live reads = %d, want 0 for a pod the List returned", src.gets)
		}
		if _, ok := x.ipam.allocations()[string(x.pod.UID)]; !ok {
			t.Error("the pod lost its address")
		}
	})

	t.Run("the apiserver does not answer", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		src := failCreateForReap(ctx, t, x)
		src.getErr = errors.New("apiserver unreachable")
		for range orphanReapThreshold + 1 {
			x.r.reapOrphans(ctx)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases = %d, want 0 on an unknown verdict", n)
		}
	})

	// A call out owns the decision, and its outcome decides the next tick.
	t.Run("a create is in flight", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		failCreateForReap(ctx, t, x)
		for i := int32(1); i < orphanReapThreshold; i++ {
			x.r.reapOrphans(ctx)
		}
		entered, release := holdFirstAdmitted(t, x.r)
		retried := make(chan error, 1)
		failing := x.pod.DeepCopy()
		failing.Spec.Volumes = emptyDirPod("failing", "Memory").Spec.Volumes
		go func() { retried <- x.r.CreatePod(ctx, failing) }()
		awaitClosed(t, entered, "the retry to reach the admission window")
		for range orphanReapThreshold + 1 {
			x.r.reapOrphans(ctx)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases with the retry in flight = %d, want 0", n)
		}
		release()
		if err := awaitErr(t, retried, "the retry"); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
			t.Fatalf("the retry = %v, want ErrEmptyDirMediumUnsupported", err)
		}
		// The count started again: the retry's outcome is what the threshold judges.
		for i := int32(1); i < orphanReapThreshold; i++ {
			x.r.reapOrphans(ctx)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases below a new threshold = %d, want 0", n)
		}
		x.r.reapOrphans(ctx)
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})

	// The claim's own guards, for what arrives between the verdict and the claim.
	t.Run("the claim yields to a call, a release and a track", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		failCreateForReap(ctx, t, x)
		id := string(x.pod.UID)
		for name, setup := range map[string]func() (undo func()){
			"an update out": func() func() {
				x.r.updating = map[string]int{id: 1}
				return func() { x.r.updating = nil }
			},
			"a release running": func() func() {
				x.r.fenceReleasing = map[string]chan struct{}{id: make(chan struct{})}
				return func() { x.r.fenceReleasing = nil }
			},
			"a track": func() func() {
				x.r.track[id] = &podTrack{pod: x.pod}
				return func() { delete(x.r.track, id) }
			},
		} {
			x.r.mu.Lock()
			undo := setup()
			claim := x.r.claimUntrackedHoldLocked(id)
			undo()
			x.r.mu.Unlock()
			if claim != nil {
				t.Errorf("%s: the claim went ahead", name)
			}
		}
		x.r.mu.Lock()
		claim := x.r.claimUntrackedHoldLocked("nothing-held")
		x.r.mu.Unlock()
		if claim != nil {
			t.Error("a UID that holds nothing was claimed")
		}
	})

	// A stale update of the UID finds the tombstone and acquires nothing behind the
	// release.
	t.Run("an update behind the release acquires nothing", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		failCreateForReap(ctx, t, x)
		for range orphanReapThreshold {
			x.r.reapOrphans(ctx)
		}
		setups, _ := p.counts()
		if err := x.r.UpdatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("UpdatePod: %v", err)
		}
		if after, _ := p.counts(); after != setups {
			t.Errorf("pod network setups %d -> %d, want no new one", setups, after)
		}
		x.assertForgotten(t)
	})
}
