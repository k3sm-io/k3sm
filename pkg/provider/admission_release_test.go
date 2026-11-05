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
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// netProbe wraps a fixture's pod network: it counts setups and teardowns, so a
// release that ran twice or not at all shows, and onSetup, when set, runs before
// a setup allocates.
type netProbe struct {
	PodNetwork
	mu        sync.Mutex
	setups    int
	teardowns int
	onSetup   func()
}

func probeNetwork(x *terminalUpdateFixture) *netProbe {
	p := &netProbe{PodNetwork: x.r.network}
	x.r.network = p
	return p
}

func (p *netProbe) Setup(ctx context.Context, podID string) (string, error) {
	p.mu.Lock()
	p.setups++
	hook := p.onSetup
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	return p.PodNetwork.Setup(ctx, podID)
}

func (p *netProbe) Teardown(podID string) error {
	p.mu.Lock()
	p.teardowns++
	p.mu.Unlock()
	return p.PodNetwork.Teardown(podID)
}

func (p *netProbe) counts() (setups, teardowns int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.setups, p.teardowns
}

// assertForgotten fails t unless the pod holds nothing and has no track: no /32,
// no interconnect slot or alias, no reference entry.
func (x *terminalUpdateFixture) assertForgotten(t *testing.T) {
	t.Helper()
	id := string(x.pod.UID)
	if ip, ok := x.ipam.allocations()[id]; ok {
		t.Errorf("the deleted pod holds /32 %s and its lo0 alias", ip)
	}
	if rec := x.r.interconnect.record(id); rec != nil {
		t.Errorf("the deleted pod holds an interconnect attach (%+v)", rec)
	}
	if n := attachedSlots(x.r.interconnect); n != 0 {
		t.Errorf("interconnect slots held = %d, want 0", n)
	}
	if ensured, removed := x.aliases.calls(); len(ensured) != len(removed) {
		t.Errorf("interconnect aliases ensured %v, removed %v: an alias stayed", ensured, removed)
	}
	if _, registered := x.registeredRefs(); registered {
		t.Error("the deleted pod holds a reference entry")
	}
	if tr := x.r.trackByID(id); tr != nil {
		t.Errorf("the deleted pod still has a track (%s)", trackState(tr))
	}
}

// assertGoneFromAPI fails t if the pod's apiserver object is still there.
func (x *terminalUpdateFixture) assertGoneFromAPI(ctx context.Context, t *testing.T) {
	t.Helper()
	_, err := x.r.client.CoreV1().Pods(x.pod.Namespace).Get(ctx, x.pod.Name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("apiserver get after the delete = %v, want NotFound", err)
	}
}

// TestFailedCreateThenRefusalHoldsNothing: a create that fails after its admission
// window has registered the pod's references and allocated its /32, and leaves no
// track, so Virtual Kubelet's retry reaches CreatePod. If that retry is refused,
// the refused pod's delete frees nothing, so the refusal itself has to release
// what the failed create took, once. Fails when a refusal assumes the pod holds
// nothing: the /32, its alias, the slot and the references stay held for good.
func TestFailedCreateThenRefusalHoldsNothing(t *testing.T) {
	ctx := context.Background()
	runtimeClass := "no-such-runtime-class"
	for _, tc := range []struct {
		name string
		edit func(*terminalUpdateFixture)
	}{
		{"a preflight refuses the create", func(x *terminalUpdateFixture) {
			x.pod.Spec.Volumes = emptyDirPod("failing", "Memory").Spec.Volumes
		}},
		{"translation fails", func(x *terminalUpdateFixture) {
			x.pod.Spec.RuntimeClassName = &runtimeClass
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newTerminalUpdateFixture(t, compressorAt(10))
			p := probeNetwork(x)
			id := string(x.pod.UID)
			tc.edit(x)

			if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err == nil {
				t.Fatal("the create succeeded; the test needs it to fail")
			}
			if _, ok := x.ipam.allocations()[id]; !ok {
				t.Fatal("the failed create allocated no /32, so the test proves nothing")
			}
			if _, registered := x.registeredRefs(); !registered {
				t.Fatal("the failed create registered no references, so the test proves nothing")
			}
			if tr := x.r.trackByID(id); tr != nil {
				t.Fatalf("the failed create left a track (%s)", trackState(tr))
			}

			x.refuseNow(ctx, t)
			x.assertHoldsNothing(t)
			if _, n := p.counts(); n != 1 {
				t.Errorf("releases after the refusal = %d, want 1", n)
			}

			if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
				t.Fatalf("DeletePod of the refused pod: %v", err)
			}
			x.assertForgotten(t)
			if _, n := p.counts(); n != 1 {
				t.Errorf("releases after the delete = %d, want still 1", n)
			}
		})
	}

	t.Run("a refusal releases nothing no create took", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		x.refuseNow(ctx, t)
		x.assertHoldsNothing(t)
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases = %d, want 0 for a pod that acquired nothing", n)
		}
	})

	// startup re-attachment keeps a vm guest's address reserved when its helper
	// cannot be adopted (attachPod): a refusal must not hand that address on.
	t.Run("a refusal leaves an address no create took", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		id := string(x.pod.UID)
		if _, err := x.ipam.Setup(ctx, id); err != nil {
			t.Fatalf("reserve the address: %v", err)
		}
		p := probeNetwork(x)
		x.refuseNow(ctx, t)
		if _, ok := x.ipam.allocations()[id]; !ok {
			t.Error("the refusal released an address no create of this provider took")
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases = %d, want 0", n)
		}
	})

	t.Run("a retry that runs keeps the address", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		id := string(x.pod.UID)
		failing := x.pod.DeepCopy()
		failing.Spec.Volumes = emptyDirPod("failing", "Memory").Spec.Volumes
		if err := x.r.CreatePod(ctx, failing); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
			t.Fatalf("the create = %v, want ErrEmptyDirMediumUnsupported", err)
		}
		before := x.ipam.allocations()[id]
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the retry: %v", err)
		}
		if after := x.ipam.allocations()[id]; after != before {
			t.Errorf("the retry moved the pod from %s to %s", before, after)
		}
		if n := x.f.createCount(); n != 1 {
			t.Errorf("runtime CreatePod calls = %d, want 1", n)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases = %d, want 0 for a running pod", n)
		}
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases after the delete = %d, want 1", n)
		}
	})

	t.Run("a delete with no refusal frees it once", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		x.pod.Spec.Volumes = emptyDirPod("failing", "Memory").Spec.Volumes
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
			t.Fatalf("the create = %v, want ErrEmptyDirMediumUnsupported", err)
		}
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})
}

// TestDeletePodBeforeUpdateResumes: a delete landing behind an update past its
// check stops the pod and removes the apiserver object, and leaves the release and
// the track delete to the last update out, since until then an update can still
// acquire by the pod's UID. Fails when the delete forgets the track and releases
// at once: the update then acquires for a pod nothing will ever delete again.
func TestDeletePodBeforeUpdateResumes(t *testing.T) {
	ctx := context.Background()

	t.Run("a refused pod", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		id := string(x.pod.UID)
		o := overlapUpdates(t, x.r, true)

		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, o.checked, "the update to pass its check")
		x.refuseNow(ctx, t)
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if tr := x.r.trackByID(id); tr == nil || !tr.rejected {
			t.Errorf("the delete did not leave the track to the update (%s)", trackState(tr))
		}
		x.assertGoneFromAPI(ctx, t)

		o.resume()
		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a deleted pod", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
		if n := x.f.updateCount(); n != 0 {
			t.Errorf("runtime UpdatePod calls = %d, want 0", n)
		}
	})

	t.Run("a running pod", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		id := string(x.pod.UID)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		setups, _ := p.counts()
		o := overlapUpdates(t, x.r, true)

		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, o.checked, "the update to pass its check")
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if n := x.f.deleteCount(); n != 1 {
			t.Errorf("runtime DeletePod calls = %d, want 1: the delete must stop the pod at once", n)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases with the update in flight = %d, want 0", n)
		}
		if tr := x.r.trackByID(id); tr == nil {
			t.Error("the delete did not leave the track to the update")
		}
		x.assertGoneFromAPI(ctx, t)

		o.resume()
		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a deleted pod", err)
		}
		x.assertForgotten(t)
		if after, n := p.counts(); after != setups || n != 1 {
			t.Errorf("setups %d -> %d, releases %d: want no new setup and 1 release", setups, after, n)
		}
		if n := x.f.updateCount(); n != 0 {
			t.Errorf("runtime UpdatePod calls = %d, want 0", n)
		}
		if n := x.f.createCount(); n != 1 {
			t.Errorf("runtime CreatePod calls = %d, want 1", n)
		}
	})

	t.Run("two updates, the last out finishes the delete", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		id := string(x.pod.UID)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		var checkedOnce sync.Once
		firstChecked, secondChecked := make(chan struct{}), make(chan struct{})
		firstGate, secondGate := make(chan struct{}), make(chan struct{})
		releaseFirst := sync.OnceFunc(func() { close(firstGate) })
		t.Cleanup(releaseFirst)
		releaseSecond := sync.OnceFunc(func() { close(secondGate) })
		t.Cleanup(releaseSecond)
		x.r.updateCheckedHook = func(string) {
			first := false
			checkedOnce.Do(func() { first = true })
			if first {
				close(firstChecked)
				<-firstGate
				return
			}
			close(secondChecked)
			<-secondGate
		}
		updated1 := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, firstChecked, "the first update to pass its check")
		updated2 := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, secondChecked, "the second update to pass its check")
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}

		releaseFirst()
		if err := awaitErr(t, updated1, "the first update"); err != nil {
			t.Errorf("first UpdatePod = %v, want nil", err)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases with an update still in flight = %d, want 0", n)
		}
		if tr := x.r.trackByID(id); tr == nil {
			t.Error("the first update out forgot the track with another in flight")
		}
		releaseSecond()
		if err := awaitErr(t, updated2, "the second update"); err != nil {
			t.Errorf("second UpdatePod = %v, want nil", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})

	t.Run("the orphan reaper's teardown", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		id := string(x.pod.UID)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		o := overlapUpdates(t, x.r, true)
		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, o.checked, "the update to pass its check")
		x.r.reapOrphan(ctx, x.pod.DeepCopy(), x.r.trackByID(id))

		o.resume()
		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a reaped pod", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})
}

// TestUpdatePodLosesRaceWithDelete: an update that loses to a delete must not leave
// a /32 behind, wherever the delete lands. Setup is idempotent per pod, so after a
// release it allocates a fresh address that nothing owns.
func TestUpdatePodLosesRaceWithDelete(t *testing.T) {
	ctx := context.Background()

	// Past every check, inside the allocation: only a release after the update's
	// return can free what it takes. Fails when the delete releases at once.
	t.Run("the delete lands while the update allocates", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		entered, gate := make(chan struct{}), make(chan struct{})
		resume := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(resume)
		p.mu.Lock()
		p.onSetup = func() {
			close(entered)
			<-gate
		}
		p.mu.Unlock()

		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, entered, "the update to reach its allocation")
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		resume()
		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a deleted pod", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
		if n := x.f.updateCount(); n != 0 {
			t.Errorf("runtime UpdatePod calls = %d, want 0", n)
		}
	})

	// The delete has begun and not yet decided: its quiesce marked the track. The
	// update stops at its check. Fails when the check does not read the mark: the
	// update registers its spec and may allocate behind the release.
	t.Run("the update arrives once the delete has begun", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		setups, _ := p.counts()
		x.r.trackByID(string(x.pod.UID)).markDeleting()

		if err := x.r.UpdatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a pod being deleted", err)
		}
		if after, _ := p.counts(); after != setups {
			t.Errorf("pod network setups %d -> %d, want no new one", setups, after)
		}
		if n := x.f.updateCount(); n != 0 {
			t.Errorf("runtime UpdatePod calls = %d, want 0", n)
		}
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})

	// The update waits behind an admitted create, the delete lands, and the create
	// fails with no track. Fails when a waiting update does not count as in flight:
	// it wakes to an untracked pod and allocates after the delete has finished.
	t.Run("the delete lands while the update waits for a verdict", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		x.pod.Spec.Volumes = emptyDirPod("failing", "Memory").Spec.Volumes
		entered, release := holdFirstAdmitted(t, x.r)
		o := overlapUpdates(t, x.r, false)

		first := make(chan error, 1)
		go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		awaitClosed(t, entered, "the create to reach the admission window")
		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		o.awaitParked(t, x.r, updated)

		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		release()
		if err := awaitErr(t, first, "the create"); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
			t.Errorf("the create = %v, want ErrEmptyDirMediumUnsupported", err)
		}
		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a deleted pod", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
		if n := x.f.updateCount(); n != 0 {
			t.Errorf("runtime UpdatePod calls = %d, want 0", n)
		}
	})

	// The delete has returned and the update's object carries the deletion stamp.
	// Fails when an untracked update reads no stamp: it allocates for a gone pod.
	t.Run("a stamped update finds no track", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		setups, _ := p.counts()
		stamped := x.pod.DeepCopy()
		now := metav1.Now()
		stamped.DeletionTimestamp = &now
		if err := x.r.UpdatePod(ctx, stamped); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a deleted pod", err)
		}
		if after, _ := p.counts(); after != setups {
			t.Errorf("pod network setups %d -> %d, want no new one", setups, after)
		}
		x.assertForgotten(t)
	})
}

// panicOnMessage is a slog handler that panics on the first record whose message
// holds substr: the one thing that can run between a fence's claim and its release.
type panicOnMessage struct {
	substr string
	value  any
}

func (h panicOnMessage) Enabled(context.Context, slog.Level) bool { return true }
func (h panicOnMessage) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h panicOnMessage) WithGroup(string) slog.Handler            { return h }
func (h panicOnMessage) Handle(_ context.Context, rec slog.Record) error {
	if strings.Contains(rec.Message, h.substr) {
		panic(h.value)
	}
	return nil
}

// TestCreatePodFenceReleaseRunsOnPanic: a panic in CreatePod's fence must still
// release what the create took and end the wait on the release, or every later
// create and update of the pod waits on a release that never ran. The panic is not
// recovered. Fails when anything that can panic sits between the claim and the
// release: the claim stays published and the /32 stays held.
func TestCreatePodFenceReleaseRunsOnPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errFence := errors.New("fence log panicked")
	x := newTerminalUpdateFixture(t, compressorAt(10))
	id := string(x.pod.UID)
	x.r.log = slog.New(panicOnMessage{substr: "became terminal", value: errFence})
	entered, release := holdFirstAdmitted(t, x.r)

	first := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != any(errFence) {
				first <- fmt.Errorf("recovered %v, want the log's panic", p)
				return
			}
			first <- nil
		}()
		_ = x.r.CreatePod(ctx, x.pod.DeepCopy())
	}()
	awaitClosed(t, entered, "the create to reach the admission window")
	x.forgeRefusalInWindow(ctx, t)
	release()
	if err := awaitErr(t, first, "the create's panic"); err != nil {
		t.Fatal(err)
	}

	x.r.mu.Lock()
	_, waiting := x.r.fenceReleasing[id]
	x.r.mu.Unlock()
	if waiting {
		t.Error("the panic left the release's wait in place")
	}
	x.assertHoldsNothing(t)

	next := make(chan error, 1)
	go func() { next <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	if err := awaitErr(t, next, "a create after the panic"); err != nil {
		t.Errorf("a create after the panic = %v, want nil: the pod stays refused", err)
	}
	updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
	if err := awaitErr(t, updated, "an update after the panic"); err != nil {
		t.Errorf("an update after the panic = %v, want nil: the pod stays refused", err)
	}
	if tr := x.r.trackByID(id); tr == nil || !tr.rejected {
		t.Errorf("the refusal did not stand (%s)", trackState(tr))
	}
}
