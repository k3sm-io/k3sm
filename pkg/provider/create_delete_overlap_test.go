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
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// TestCreateOverlappingDeleteLeavesNoTrackOrGuest forces each order of a create of a
// UID against a delete of the same UID. Virtual Kubelet runs one call per pod key
// (TestPodControllerRunsOneCallPerPodKey in vkadapter), so its create and delete never
// overlap. What can overlap its create is the orphan reaper, off the queue, once the
// informer holds a pod the apiserver has lost; and a parked pod's retries overlap each
// other and the pod's delete. An order only an overlapping Virtual Kubelet could drive
// says so in its name: the guard that closes the reachable order closes it too.
func TestCreateOverlappingDeleteLeavesNoTrackOrGuest(t *testing.T) {
	t.Run("the reaper releases behind a create past its check, which waits at the fence", testCreateAtFenceBehindReaper)
	t.Run("the reaper has released behind a create past its check", testCreateBehindFinishedReaper)
	t.Run("a delete finishes behind a create at the fence (only an overlapping Virtual Kubelet)", testDeleteBehindCreateAtFence)
	t.Run("a create lands inside the reaper's delete, behind a refused create", testCreateInsideReaperDelete)
	t.Run("a create lands inside the delete of an untracked pod (only an overlapping Virtual Kubelet)", func(t *testing.T) {
		testCreateInsidePodDelete(t, false)
	})
	t.Run("a create lands inside the delete of a tracked pod (only an overlapping Virtual Kubelet)", func(t *testing.T) {
		testCreateInsidePodDelete(t, true)
	})
	t.Run("a same-name successor lands inside its predecessor's delete, under its own UID", testSuccessorInsidePredecessorDelete)
	t.Run("a second retry lands inside the compensating delete", testSecondRetryInsideCompensatingDelete)
	t.Run("a second retry lands after the compensating delete retired", testSecondRetryAfterCompensatingDelete)
	t.Run("nothing can land while a compensating entry is false", testNothingLandsBesideFalseEntry)
}

// holdRelease holds every fence release of r at its start, and reports
// the releases entered and the creates waiting at the fence.
func holdRelease(t *testing.T, r *runtimedRuntime) (entered, waiting <-chan struct{}, release func()) {
	t.Helper()
	in, wait, hold := make(chan struct{}, 8), make(chan struct{}, 8), make(chan struct{})
	r.fenceReleaseHook = func(string) {
		in <- struct{}{}
		<-hold
	}
	r.fenceWaitHook = func(string) { wait <- struct{}{} }
	var released bool
	release = func() {
		if !released {
			released = true
			close(hold)
		}
	}
	t.Cleanup(release)
	return in, wait, release
}

// admitResult is what a create past CreatePod's first check heard from admission.
type admitResult struct {
	refused bool
	ticket  *admitTicket
}

// assertAdmissionRefused requires the create to be told it is stale, counted nowhere.
func assertAdmissionRefused(t *testing.T, x *terminalUpdateFixture, got admitResult) {
	t.Helper()
	if !got.refused || got.ticket != nil {
		if got.ticket != nil {
			x.r.createDone(x.pod, got.ticket)
		}
		t.Errorf("admission of a create behind the release = refused %v, want refused: it builds a guest for a pod the apiserver lost", got.refused)
	}
	x.r.mu.Lock()
	n := x.r.admitting[string(x.pod.UID)]
	x.r.mu.Unlock()
	if n != 0 {
		t.Errorf("creates counted in flight = %d, want 0", n)
	}
}

// testCreateAtFenceBehindReaper: a create Virtual Kubelet retries from a stale
// informer has read createIsStale, and the reaper then decides the pod's failed create
// is gone. admitOnCreate is called directly because it is the rest of that create:
// only the first check is behind it. Fails when the wait at the fence ends in an
// admission that does not read the tombstone again.
func testCreateAtFenceBehindReaper(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	failCreateForReap(ctx, t, x)
	entered, waiting, release := holdRelease(t, x.r)
	reaped := make(chan error, 1)
	go func() {
		for range orphanReapThreshold {
			x.r.reapOrphans(ctx)
		}
		reaped <- nil
	}()
	waitRestart(t, "the reaper's release to begin", func() bool { return len(entered) == 1 })

	admitted := make(chan admitResult, 1)
	go func() {
		refused, ticket := x.r.admitOnCreate(ctx, x.pod.DeepCopy())
		admitted <- admitResult{refused, ticket}
	}()
	waitRestart(t, "the create to wait at the fence", func() bool { return len(waiting) == 1 })
	release()
	if err := awaitErr(t, reaped, "the reaper"); err != nil {
		t.Fatal(err)
	}
	assertAdmissionRefused(t, x, <-admitted)
	x.assertForgotten(t)
	if n := x.f.createCount(); n != 0 {
		t.Errorf("runtime CreatePod calls = %d, want 0", n)
	}
}

// testCreateBehindFinishedReaper is the same create reaching admission once the release
// is over, with no fence left to wait at. Fails when the tombstone is read only at the
// fence: a count published with no read beside it still lands behind the delete.
func testCreateBehindFinishedReaper(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	failCreateForReap(ctx, t, x)
	for range orphanReapThreshold {
		x.r.reapOrphans(ctx)
	}
	x.assertForgotten(t)
	refused, ticket := x.r.admitOnCreate(ctx, x.pod.DeepCopy())
	assertAdmissionRefused(t, x, admitResult{refused, ticket})
}

// testDeleteBehindCreateAtFence runs a whole CreatePod at the fence of a refused pod's
// release, with the teardown finishing behind it. The refused track's delete tears
// nothing down, so a second delete, of no track, is what does. Fails when the create
// leaves the fence without reading the tombstone: a track and a guest for a deleted pod.
func testDeleteBehindCreateAtFence(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	failCreateForReap(ctx, t, x)
	entered, waiting, release := holdRelease(t, x.r)

	x.src.set(compressorAt(85))
	refused := make(chan error, 1)
	go func() { refused <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the refused create's release to begin", func() bool { return len(entered) == 1 })
	x.src.set(compressorAt(10))

	created := make(chan error, 1)
	go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the create to wait at the fence", func() bool { return len(waiting) == 1 })
	for range 2 {
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
	}
	release()
	if err := awaitErr(t, refused, "the refused create"); err != nil {
		t.Fatalf("the refused create = %v, want nil", err)
	}
	if err := awaitErr(t, created, "the create"); err != nil {
		t.Fatalf("the create = %v, want nil", err)
	}
	if x.f.hasCreated(string(x.pod.UID)) {
		t.Error("the runtime holds a guest for the deleted pod")
	}
	x.assertForgotten(t)
}

// stopHoldingDeletes keeps only the deletes already inside the RPC held.
func stopHoldingDeletes(f *fakeRuntimeServer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteHold = nil
}

// testCreateInsideReaperDelete is the order the off-queue reaper can reach: a create
// running from a stale informer is refused while the reaper's delete is inside its
// RPC, which takes the track, so GetPod answers NotFound and Virtual Kubelet's requeue
// is a CreatePod. That one lands in the same RPC. The next ticks take the bare track.
// Fails when a landing create reads only the track for a delete that has begun: the
// guest stands with its /32 released behind it.
func testCreateInsideReaperDelete(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	id := string(x.pod.UID)
	releaseCreate := x.f.holdCreate()
	defer releaseCreate()
	first := make(chan error, 1)
	go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
	tr := x.r.trackByID(id)
	if tr == nil {
		t.Fatal("the create published no track")
	}
	x.f.pushCreate(podLevelRefusal())

	releaseDelete := x.f.holdDelete()
	defer releaseDelete()
	reaped := make(chan error, 1)
	go func() {
		x.r.reapOrphan(ctx, x.pod.DeepCopy(), tr)
		reaped <- nil
	}()
	waitRestart(t, "the reaper's delete to be entered", func() bool { return x.f.deleteCount() == 1 })
	stopHoldingDeletes(x.f)

	releaseCreate()
	if err := awaitErr(t, first, "the refused create"); err == nil {
		t.Fatal("the create succeeded; the test needs it refused")
	}
	if got, err := x.r.GetPod(ctx, x.pod.Namespace, x.pod.Name); !vkadapter.IsNotFound(err) {
		t.Fatalf("GetPod after the refusal = %v, %v, want NotFound: Virtual Kubelet would not create again", got, err)
	}
	if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
		t.Fatalf("the requeued create: %v", err)
	}

	releaseDelete()
	if err := awaitErr(t, reaped, "the reaper"); err != nil {
		t.Fatal(err)
	}
	waitRestart(t, "the compensating delete to retire", func() bool { return compensatingCount(x.r) == 0 })
	if x.f.hasCreated(id) {
		t.Error("the guest the requeued create built outlived the delete")
	}
	if late := x.r.trackByID(id); late != nil {
		x.r.reapOrphan(ctx, x.pod.DeepCopy(), late)
	}
	x.assertForgotten(t)
}

// testCreateInsidePodDelete is a create landing inside DeletePod's own RPC: runtimed
// registers a pod only when its create finishes, so that RPC stopped nothing. Fails
// when the landing create reads only the track: an untracked pod's delete marked none,
// and a re-create's track is not the one a tracked pod's delete marked.
func testCreateInsidePodDelete(t *testing.T, tracked bool) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	id := string(x.pod.UID)
	if tracked {
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
	}
	releaseDelete := x.f.holdDelete()
	defer releaseDelete()
	deleted := make(chan error, 1)
	go func() { deleted <- x.r.DeletePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the delete to be entered", func() bool { return x.f.deleteCount() == 1 })
	stopHoldingDeletes(x.f)

	if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
		t.Fatalf("the create: %v", err)
	}
	releaseDelete()
	if err := awaitErr(t, deleted, "the delete"); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	waitRestart(t, "the compensating delete to retire", func() bool { return compensatingCount(x.r) == 0 })
	if x.f.hasCreated(id) {
		t.Error("the runtime holds a guest for the deleted pod")
	}
	x.assertForgotten(t)
}

// testSuccessorInsidePredecessorDelete: a same-name re-create shares Virtual Kubelet's
// key but no state here, which is keyed by UID throughout. The reaper can overlap the
// two. Fails when a delete's RPC is read by anything but the UID: the successor's guest
// is deleted as a late create of its predecessor.
func testSuccessorInsidePredecessorDelete(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	releaseDelete := x.f.holdDelete()
	defer releaseDelete()
	reaped := make(chan error, 1)
	tr := x.r.trackByID(string(x.pod.UID))
	go func() {
		x.r.reapOrphan(ctx, x.pod.DeepCopy(), tr)
		reaped <- nil
	}()
	waitRestart(t, "the reaper's delete to be entered", func() bool { return x.f.deleteCount() == 1 })

	successor := x.pod.DeepCopy()
	successor.UID = "same-name-successor"
	successor.Annotations = nil
	if err := x.r.CreatePod(ctx, successor); err != nil {
		t.Fatalf("the successor's create: %v", err)
	}
	if n := compensatingCount(x.r); n != 0 {
		t.Errorf("compensating deletes = %d, want none for another UID", n)
	}
	releaseDelete()
	if err := awaitErr(t, reaped, "the reaper"); err != nil {
		t.Fatal(err)
	}
	x.assertForgotten(t)
	if !x.f.hasCreated(string(successor.UID)) {
		t.Error("the successor's guest is gone")
	}
	if x.r.trackByID(string(successor.UID)) == nil {
		t.Error("the successor lost its track")
	}
}

// parkedWithTwoRetries has a parked pod with two retries inside the runtime's create:
// `kubectl set image` retires the first retry's schedule, and its RPC runs on.
func parkedWithTwoRetries(t *testing.T, name string) (x *twoRetries) {
	t.Helper()
	pod := probePullPod(name)
	r, f, clk, landFirst := parkedWithHeldRetry(t, pod)
	t.Cleanup(landFirst)
	landSecond := f.holdCreate()
	t.Cleanup(landSecond)
	edited := pod.DeepCopy()
	edited.Spec.Containers[0].Image = "registry.example/web:2"
	if err := r.UpdatePod(context.Background(), edited); err != nil {
		t.Fatalf("UpdatePod on a parked pod = %v, want nil", err)
	}
	waitRestart(t, "the second retry's CreatePod to be entered", func() bool { return f.createCount() == 3 })
	return &twoRetries{pod: pod, r: r, f: f, hasWaiters: clk.HasWaiters, landFirst: landFirst, landSecond: landSecond}
}

// twoRetries is the state parkedWithTwoRetries leaves. Each land func lets one retry's
// create finish.
type twoRetries struct {
	pod        *corev1.Pod
	r          *runtimedRuntime
	f          *fakeRuntimeServer
	hasWaiters func() bool
	landFirst  func()
	landSecond func()
}

// The pod's own delete, the compensating delete of the first retry, and that of the
// second, which must be a delete of its own.
const ownThenTwoCompensating = 3

// testSecondRetryInsideCompensatingDelete: runtimed forgets the pod first thing in its
// DeletePod, so while that RPC stops the first guest, a second create registers a guest
// the RPC will not touch. Fails when the second retry only joins the running loop: the
// guest stands with nothing left to delete it.
func testSecondRetryInsideCompensatingDelete(t *testing.T) {
	ctx := context.Background()
	x := parkedWithTwoRetries(t, "second-inside")
	id := string(x.pod.UID)
	if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	releaseDelete := x.f.holdDelete()
	defer releaseDelete()

	x.landFirst()
	waitRestart(t, "the compensating delete to be entered", func() bool { return len(x.f.deleteRecords()) == 2 })
	stopHoldingDeletes(x.f)
	x.landSecond()
	waitRestart(t, "the second retry to land", func() bool { return x.f.hasCreated(id) && updatingCount(x.r, id) == 0 })
	assertTracked(t, x.r, id, "the compensating delete is the last call out")

	releaseDelete()
	waitRestart(t, "the guest the second retry built to go", func() bool { return !x.f.hasCreated(id) })
	assertNothingLeft(t, x.r, x.f, x.pod, x.hasWaiters)
	if n := len(x.f.deleteRecords()); n != ownThenTwoCompensating {
		t.Errorf("runtime DeletePod calls = %d, want %d", n, ownThenTwoCompensating)
	}
}

// testSecondRetryAfterCompensatingDelete: with a retry still out the landed delete owes
// no release, so its entry goes in the decision that says so and the second retry opens
// a delete of its own. Fails when an entry stays behind that decision, as the second
// retry can land there and join a loop that has finished.
func testSecondRetryAfterCompensatingDelete(t *testing.T) {
	ctx := context.Background()
	x := parkedWithTwoRetries(t, "second-after")
	id := string(x.pod.UID)
	if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	x.landFirst()
	waitRestart(t, "the first compensating delete to retire", func() bool {
		return len(x.f.deleteRecords()) == 2 && compensatingCount(x.r) == 0
	})
	if updatingCount(x.r, id) != 1 {
		t.Fatalf("retries out = %d, want the second", updatingCount(x.r, id))
	}
	x.landSecond()
	waitRestart(t, "the second compensating delete", func() bool { return len(x.f.deleteRecords()) == ownThenTwoCompensating })
	assertNothingLeft(t, x.r, x.f, x.pod, x.hasWaiters)
}

// testNothingLandsBesideFalseEntry pins why compensateLateCreate needs no answer to an
// entry at false: that entry stands only while a release runs, which only begins with
// every create and retry returned, and nothing new gets past the entry. Fails when a
// create or a retry can begin beside it.
func testNothingLandsBesideFalseEntry(t *testing.T) {
	ctx := context.Background()
	pod := probePullPod("false-entry")
	id := string(pod.UID)
	r, f, clk, land := parkedWithHeldRetry(t, pod)
	defer land()
	tr := r.trackByID(id)
	entered, _, release := holdRelease(t, r)
	if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	land()
	waitRestart(t, "the release to begin", func() bool { return len(entered) == 1 })

	r.mu.Lock()
	outstanding, recorded := r.compensating[id]
	counted := r.admitting[id] + r.updating[id]
	r.mu.Unlock()
	if !recorded || outstanding {
		t.Fatalf("compensating entry = %v (recorded %v), want false", outstanding, recorded)
	}
	if counted != 0 {
		t.Errorf("calls counted beside the release = %d, want 0", counted)
	}
	assertStaleCreateBuildsNothing(t, r, f, pod)
	if r.beginParkedRetry(id, tr) {
		r.updateDone(pod)
		t.Error("a retry began beside the release")
	}
	release()
	assertNothingLeft(t, r, f, pod, clk.HasWaiters)
}
