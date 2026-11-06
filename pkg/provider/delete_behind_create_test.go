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
	"os"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// podLevelRefusal is a create runtimed refuses for the whole pod, the shape that
// goes back to Virtual Kubelet as an error and is not parked.
func podLevelRefusal() *runtimev1.CreatePodResponse {
	return createRefusal(runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED, "refused")
}

// imageRefusal is a create runtimed refuses for its image, the shape that parks.
func imageRefusal() *runtimev1.CreatePodResponse {
	return createRefusal(runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
		`container c0: pull image "`+pullImage+`": unexpected status 500 Internal Server Error`)
}

// TestDeleteDuringFailedCreateHoldsNothing: a delete that lands behind an in-flight
// create leaves the release to the create's way out, so whatever the create takes
// after the delete has an owner, and the release runs once.
func TestDeleteDuringFailedCreateHoldsNothing(t *testing.T) {
	ctx := context.Background()

	// Virtual Kubelet does not issue this overlap (its queue runs one worker per pod
	// key); it pins that the provider does not rest on that. Fails when the delete
	// releases at once: the create allocates afterward and nothing owns the /32.
	t.Run("the delete lands before the create allocates", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		runtimeClass := "no-such-runtime-class"
		x.pod.Spec.RuntimeClassName = &runtimeClass
		entered, release := holdFirstAdmitted(t, x.r)

		created := make(chan error, 1)
		go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		awaitClosed(t, entered, "the create to reach the admission window")
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		x.assertGoneFromAPI(ctx, t)
		release()
		if err := awaitErr(t, created, "the create"); err == nil {
			t.Fatal("the create succeeded; the test needs it to fail")
		}

		if setups, _ := p.counts(); setups == 0 {
			t.Error("the create allocated nothing, so the test proves nothing")
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})

	// The orphan reaper keys on tracks and does not wait for a create's RPC, which an
	// image pull can hold past its threshold. Fails when the reap releases and the
	// refused create releases again.
	t.Run("the reaper lands inside a create's RPC, which is refused", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		x.f.pushCreate(podLevelRefusal())
		release := x.f.holdCreate()
		defer release()

		created := make(chan error, 1)
		go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
		tr := x.r.trackByID(string(x.pod.UID))
		if tr == nil {
			t.Fatal("the create published no track")
		}
		x.r.reapOrphan(ctx, x.pod.DeepCopy(), tr)
		x.assertGoneFromAPI(ctx, t)
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases with the create in flight = %d, want 0", n)
		}
		release()
		if err := awaitErr(t, created, "the create"); err == nil {
			t.Fatal("the create succeeded; the test needs it refused")
		}

		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})
}

// TestParkedRetryBehindDeleteHoldsNothing: a parked pod's retry allocates by the
// pod's UID, and its worker's context ending does not stop an allocation already
// past its last read of that context.
func TestParkedRetryBehindDeleteHoldsNothing(t *testing.T) {
	ctx := context.Background()

	park := func(t *testing.T) (*terminalUpdateFixture, *netProbe, *podTrack) {
		t.Helper()
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		x.f.pushCreate(imageRefusal())
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("CreatePod = %v, want the pod parked", err)
		}
		tr := x.r.trackByID(string(x.pod.UID))
		if tr == nil || tr.parkedFailure() == nil {
			t.Fatalf("the pod did not park (%s)", trackState(tr))
		}
		return x, p, tr
	}

	// Fails when the retry reads no delete mark: it allocates behind the release.
	t.Run("the retry starts once the delete has begun", func(t *testing.T) {
		x, p, tr := park(t)
		creates := x.f.createCount()
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		setups, _ := p.counts()

		reason, _, err := x.r.retryParkedCreate(ctx, x.pod.DeepCopy(), tr)
		if err != nil || reason != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND {
			t.Errorf("retry = %v, %v, want NOT_FOUND and no error: there is no pod left", reason, err)
		}
		if after, _ := p.counts(); after != setups {
			t.Errorf("pod network setups %d -> %d, want no new one", setups, after)
		}
		if n := x.f.createCount(); n != creates {
			t.Errorf("runtime CreatePod calls %d -> %d, want no new one", creates, n)
		}
		x.assertForgotten(t)
	})

	// Past the check, inside the allocation: only a release after it can free what
	// it takes. Fails when the retry is not counted in flight.
	t.Run("the delete lands while the retry allocates", func(t *testing.T) {
		x, p, tr := park(t)
		entered, gate := make(chan struct{}), make(chan struct{})
		resume := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(resume)
		p.mu.Lock()
		p.onSetup = func() {
			close(entered)
			<-gate
		}
		p.mu.Unlock()

		retried := make(chan error, 1)
		go func() {
			_, _, err := x.r.retryParkedCreate(ctx, x.pod.DeepCopy(), tr)
			retried <- err
		}()
		awaitClosed(t, entered, "the retry to reach its allocation")
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases with the retry allocating = %d, want 0", n)
		}
		resume()
		if err := awaitErr(t, retried, "the retry"); err != nil {
			t.Errorf("retry = %v, want nil", err)
		}
		waitRestart(t, "the late create's compensating delete", func() bool { return compensatingCount(x.r) == 0 })
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
	})
}

// TestRefusedCreateBesideUpdateHoldsNothing: a refused create forgets its pod while
// an update of it is in flight, which the claim worker's create can do since it runs
// off Virtual Kubelet's queue. The update can still allocate by the pod's UID, so the
// release is the last call out's. Fails when the refusal releases at once: the update
// finds no track, allocates behind the release, and nothing owns the /32.
func TestRefusedCreateBesideUpdateHoldsNothing(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	p := probeNetwork(x)
	x.f.pushCreate(podLevelRefusal())
	release := x.f.holdCreate()
	defer release()

	created := make(chan error, 1)
	go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
	o := overlapUpdates(t, x.r, true)
	updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
	awaitClosed(t, o.checked, "the update to pass its check")

	release()
	if err := awaitErr(t, created, "the create"); err == nil {
		t.Fatal("the create succeeded; the test needs it refused")
	}
	if _, n := p.counts(); n != 0 {
		t.Errorf("releases with the update in flight = %d, want 0", n)
	}

	o.resume()
	if err := awaitErr(t, updated, "the update"); err != nil {
		t.Errorf("UpdatePod = %v, want nil for a pod its create refused", err)
	}
	x.assertForgotten(t)
	if _, n := p.counts(); n != 1 {
		t.Errorf("releases = %d, want 1", n)
	}
	if n := x.f.updateCount(); n != 0 {
		t.Errorf("runtime UpdatePod calls = %d, want 0", n)
	}
}

// stopHoldingCreates leaves a create already inside the fake's RPC held, on the hold
// it took on entry, and lets later creates through.
func stopHoldingCreates(f *fakeRuntimeServer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createHold = nil
}

// TestSuccessorReachesCreateBesideDeleteOwed: a track whose delete is owed is gone from
// the cluster, and stays only for the call still out. A same-name successor reaching
// Virtual Kubelet then must find no pod of that name, since createOrUpdatePod sends
// whatever GetPod answers down UpdatePod, or nowhere when the specs match. Fails when
// the owed track still answers for the name: the successor never reaches CreatePod.
func TestSuccessorReachesCreateBesideDeleteOwed(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	p := probeNetwork(x)
	id := string(x.pod.UID)
	release := x.f.holdCreate()
	defer release()

	created := make(chan error, 1)
	go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
	stopHoldingCreates(x.f)
	tr := x.r.trackByID(id)
	if tr == nil {
		t.Fatal("the create published no track")
	}
	if got, err := x.r.GetPod(ctx, x.pod.Namespace, x.pod.Name); err != nil || got.UID != x.pod.UID {
		t.Fatalf("GetPod before the delete = %v, %v, want the pod", got, err)
	}
	x.r.reapOrphan(ctx, x.pod.DeepCopy(), tr)
	x.assertGoneFromAPI(ctx, t)

	if got, err := x.r.GetPod(ctx, x.pod.Namespace, x.pod.Name); !vkadapter.IsNotFound(err) {
		t.Fatalf("GetPod with the delete owed = %v, %v, want NotFound", got, err)
	}
	if st, err := x.r.GetPodStatus(ctx, x.pod.Namespace, x.pod.Name); !vkadapter.IsNotFound(err) {
		t.Errorf("GetPodStatus with the delete owed = %v, %v, want NotFound", st, err)
	}

	successor := x.pod.DeepCopy()
	successor.UID = types.UID("successor")
	successor.Annotations = nil
	if err := x.r.CreatePod(ctx, successor); err != nil {
		t.Fatalf("the successor's create: %v", err)
	}
	got, err := x.r.GetPod(ctx, x.pod.Namespace, x.pod.Name)
	if err != nil || got.UID != successor.UID {
		t.Fatalf("GetPod beside the successor = %v, %v, want the successor", got, err)
	}
	successorIP, ok := x.ipam.allocations()[string(successor.UID)]
	if !ok {
		t.Fatal("the successor holds no /32")
	}

	// The owed delete keeps its owner: the create's way out frees the predecessor,
	// once, and nothing of the successor's.
	x.f.pushCreate(podLevelRefusal())
	release()
	if err := awaitErr(t, created, "the create"); err == nil {
		t.Fatal("the create succeeded; the test needs it refused")
	}
	x.assertForgotten(t)
	if _, n := p.counts(); n != 1 {
		t.Errorf("releases = %d, want 1", n)
	}
	if ip, ok := x.ipam.allocations()[string(successor.UID)]; !ok || ip != successorIP {
		t.Errorf("the successor's /32 went from %s to %s (held %v)", successorIP, ip, ok)
	}
	if tr := x.r.trackByID(string(successor.UID)); tr == nil {
		t.Error("the successor lost its track")
	}
}

// TestRefusedCreateLeavesItsReplacement: a create that an idempotent re-create has
// replaced is refused by the runtime. What the UID holds is the replacement's now, so
// the refusal takes its own track's workers and nothing else. Fails when the refusal
// frees by UID: the running pod loses its /32, its alias and its log tree, or, with an
// update out, is fenced off behind a delete nobody asked for.
func TestRefusedCreateLeavesItsReplacement(t *testing.T) {
	ctx := context.Background()

	// replaced leaves a create held inside the RPC with a running replacement beside
	// it, and returns how to refuse the held one.
	replaced := func(t *testing.T, x *terminalUpdateFixture) (refuse func() error) {
		t.Helper()
		release := x.f.holdCreate()
		t.Cleanup(release)
		created := make(chan error, 1)
		go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
		stopHoldingCreates(x.f)
		first := x.r.trackByID(string(x.pod.UID))
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the re-create: %v", err)
		}
		if x.r.trackByID(string(x.pod.UID)) == first {
			t.Fatal("the re-create did not replace the track, so the test proves nothing")
		}
		return func() error {
			x.f.pushCreate(podLevelRefusal())
			release()
			return awaitErr(t, created, "the create")
		}
	}

	// assertRunning fails when anything of the replacement's went with the refusal.
	assertRunning := func(t *testing.T, x *terminalUpdateFixture, p *netProbe, want string) {
		t.Helper()
		id := string(x.pod.UID)
		if ip, ok := x.ipam.allocations()[id]; !ok || ip.String() != want {
			t.Errorf("the replacement holds /32 %v (held %v), want %s", ip, ok, want)
		}
		if _, n := p.counts(); n != 0 {
			t.Errorf("releases = %d, want 0 for a running pod", n)
		}
		if _, registered := x.registeredRefs(); !registered {
			t.Error("the replacement lost its references")
		}
		if x.r.trackByID(id) == nil {
			t.Error("the replacement lost its track")
		}
		x.r.mu.Lock()
		_, owed := x.r.deleteOwed[id]
		x.r.mu.Unlock()
		if owed {
			t.Error("the refusal owed a delete of the replacement")
		}
	}

	t.Run("no update out", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		refuse := replaced(t, x)
		want := x.ipam.allocations()[string(x.pod.UID)].String()
		logs := podlogs.BuildPodLogsDirectory(x.r.logGC.PodLogsDir, x.pod.Namespace, x.pod.Name, string(x.pod.UID))
		if err := os.MkdirAll(logs, 0o755); err != nil {
			t.Fatalf("make the pod's log tree: %v", err)
		}
		if err := refuse(); err == nil {
			t.Fatal("the create succeeded; the test needs it refused")
		}
		assertRunning(t, x, p, want)
		if _, err := os.Stat(logs); err != nil {
			t.Errorf("the replacement's log tree: %v", err)
		}
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases after the delete = %d, want 1", n)
		}
	})

	t.Run("an update out", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		refuse := replaced(t, x)
		want := x.ipam.allocations()[string(x.pod.UID)].String()
		o := overlapUpdates(t, x.r, true)
		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, o.checked, "the update to pass its check")
		if err := refuse(); err == nil {
			t.Fatal("the create succeeded; the test needs it refused")
		}
		assertRunning(t, x, p, want)
		o.resume()
		_ = awaitErr(t, updated, "the update") // the fake serves no UpdatePod; only the release matters
		assertRunning(t, x, p, want)
	})
}

// TestCreateLandingBehindDeleteIsDeletedAgain: runtimed registers a pod only when its
// create finishes, and answers a DeletePod for a pod it has not registered as a
// success that did nothing, so a delete inside a create's RPC does not stop what the
// create builds. Fails when the create's way out assumes the delete did: a guest runs
// with no track, on a /32 that can be issued again, and nothing ever deletes it.
func TestCreateLandingBehindDeleteIsDeletedAgain(t *testing.T) {
	ctx := context.Background()

	// holdThenReap has a create inside the RPC with the reaper's delete behind it.
	holdThenReap := func(t *testing.T, x *terminalUpdateFixture) (release func(), created <-chan error) {
		t.Helper()
		release = x.f.holdCreate()
		t.Cleanup(release)
		done := make(chan error, 1)
		go func() { done <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
		tr := x.r.trackByID(string(x.pod.UID))
		if tr == nil {
			t.Fatal("the create published no track")
		}
		x.r.reapOrphan(ctx, x.pod.DeepCopy(), tr)
		return release, done
	}
	deletes := func(x *terminalUpdateFixture) (calls int, built bool) {
		x.f.mu.Lock()
		defer x.f.mu.Unlock()
		_, built = x.f.created[string(x.pod.UID)]
		return x.f.deleteCalls, built
	}

	t.Run("the create lands", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		release, created := holdThenReap(t, x)
		if n, _ := deletes(x); n != 1 {
			t.Fatalf("runtime DeletePod calls before the create lands = %d, want 1", n)
		}
		release()
		if err := awaitErr(t, created, "the create"); err != nil {
			t.Fatalf("the create = %v, want nil: the delete has the pod", err)
		}
		waitRestart(t, "the guest the create built to be deleted", func() bool {
			_, built := deletes(x)
			return !built && compensatingCount(x.r) == 0
		})
		if n, _ := deletes(x); n != 2 {
			t.Errorf("runtime DeletePod calls = %d, want 2", n)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != 1 {
			t.Errorf("releases = %d, want 1", n)
		}
		x.r.mu.Lock()
		probers := len(x.r.probers)
		x.r.mu.Unlock()
		if probers != 0 {
			t.Errorf("probers = %d, want 0 for a deleted pod", probers)
		}
	})

	// A refused create built nothing, so there is nothing to delete again.
	t.Run("the create is refused", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		x.f.pushCreate(podLevelRefusal())
		release, created := holdThenReap(t, x)
		release()
		if err := awaitErr(t, created, "the create"); err == nil {
			t.Fatal("the create succeeded; the test needs it refused")
		}
		if n, _ := deletes(x); n != 1 {
			t.Errorf("runtime DeletePod calls = %d, want 1", n)
		}
		if n := compensatingCount(x.r); n != 0 {
			t.Errorf("compensating deletes = %d, want 0", n)
		}
		x.assertForgotten(t)
	})

	// A delete that begins after the create landed reaches what it built.
	t.Run("the delete follows the create", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if n, built := deletes(x); n != 1 || built {
			t.Errorf("runtime DeletePod calls = %d, guest built = %v, want 1 and false", n, built)
		}
		if n := compensatingCount(x.r); n != 0 {
			t.Errorf("compensating deletes = %d, want 0", n)
		}
	})
}

// TestCreateLandingBehindRefusalKeepsItsGuest: a re-create the runtime refuses, with
// an update out, owes the release to the last call out, and no delete has begun. A
// first create of the same UID that then lands has built the pod nothing refused.
// Fails when a landing create reads any owed entry as a delete: the guest is killed.
// Fails too when the refusal is left standing: the guest loses its /32 to the release.
func TestCreateLandingBehindRefusalKeepsItsGuest(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	p := probeNetwork(x)
	id := string(x.pod.UID)
	release := x.f.holdCreate()
	defer release()

	created := make(chan error, 1)
	go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
	stopHoldingCreates(x.f)
	first := x.r.trackByID(id)
	o := overlapUpdates(t, x.r, true)
	updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
	awaitClosed(t, o.checked, "the update to pass its check")

	x.f.pushCreate(podLevelRefusal())
	if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err == nil {
		t.Fatal("the re-create succeeded; the test needs it refused")
	}
	x.r.mu.Lock()
	del := x.r.deleteOwed[id]
	x.r.mu.Unlock()
	if del == nil {
		t.Fatal("the refusal owed nothing, so the test proves nothing")
	}
	want := x.ipam.allocations()[id]
	logs := podlogs.BuildPodLogsDirectory(x.r.logGC.PodLogsDir, x.pod.Namespace, x.pod.Name, id)

	release()
	if err := awaitErr(t, created, "the create"); err != nil {
		t.Fatalf("the create = %v, want nil", err)
	}
	o.resume()
	_ = awaitErr(t, updated, "the update") // the fake serves no UpdatePod; only the outcome below matters

	if n := compensatingCount(x.r); n != 0 {
		t.Errorf("compensating deletes = %d, want 0: nothing deleted this pod", n)
	}
	x.f.mu.Lock()
	deletes, built := x.f.deleteCalls, x.f.created[id] != nil
	x.f.mu.Unlock()
	if deletes != 0 || !built {
		t.Errorf("runtime DeletePod calls = %d, guest built = %v, want 0 and true", deletes, built)
	}
	if ip, ok := x.ipam.allocations()[id]; !ok || ip != want {
		t.Errorf("the pod holds /32 %v (held %v), want %v", ip, ok, want)
	}
	if _, n := p.counts(); n != 0 {
		t.Errorf("releases = %d, want 0 for a running pod", n)
	}
	if tr := x.r.trackByID(id); tr != first {
		t.Errorf("the pod's track = %s, want the one whose create landed", trackState(tr))
	}
	if _, err := os.Stat(logs); err != nil {
		t.Errorf("the running pod's log tree: %v", err)
	}

	if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	x.assertForgotten(t)
	if _, n := p.counts(); n != 1 {
		t.Errorf("releases after the delete = %d, want 1", n)
	}
}

// TestRefusedTrackBesideUpdateAnswersItsName: a refusal beside an update leaves its
// track in place with its object still listed, and no successor can hold the name, so
// it answers name reads as it did. Only a delete hides a track
// (TestSuccessorReachesCreateBesideDeleteOwed).
//
// Virtual Kubelet does not read GetPodStatus by name to write a status for this
// provider: syncProviderWrapper, whose NotFound marks a listed pod Failed, wraps only
// a provider that is no PodNotifier, and VKProvider is one.
func TestRefusedTrackBesideUpdateAnswersItsName(t *testing.T) {
	var _ vkadapter.PodNotifier = (*VKProvider)(nil)

	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	x.f.pushCreate(podLevelRefusal())
	release := x.f.holdCreate()
	defer release()

	created := make(chan error, 1)
	go func() { created <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	waitRestart(t, "the create's RPC to be entered", func() bool { return x.f.createCount() == 1 })
	o := overlapUpdates(t, x.r, true)
	updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
	awaitClosed(t, o.checked, "the update to pass its check")
	release()
	if err := awaitErr(t, created, "the create"); err == nil {
		t.Fatal("the create succeeded; the test needs it refused")
	}
	if got, err := x.r.GetPod(ctx, x.pod.Namespace, x.pod.Name); err != nil || got.UID != x.pod.UID {
		t.Errorf("GetPod with a refusal owed = %v, %v, want the pod", got, err)
	}
	if _, err := x.r.GetPodStatus(ctx, x.pod.Namespace, x.pod.Name); err != nil {
		t.Errorf("GetPodStatus with a refusal owed: %v", err)
	}
	o.resume()
	if err := awaitErr(t, updated, "the update"); err != nil {
		t.Errorf("the update: %v", err)
	}
	x.assertForgotten(t)
}
