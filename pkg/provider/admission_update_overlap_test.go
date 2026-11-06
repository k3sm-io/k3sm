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
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// updateOverlap steers one provider through an UpdatePod overlapping a create,
// with no ordering between the two, as Virtual Kubelet's per-pod queue would
// have given them. parked closes when an update starts to wait for a verdict and
// checked when one passes its terminal check. A checked update stays there until
// resume is called, when holdChecked is set.
type updateOverlap struct {
	parked  chan struct{}
	checked chan struct{}
	resume  func()
}

func overlapUpdates(t *testing.T, r *runtimedRuntime, holdChecked bool) *updateOverlap {
	t.Helper()
	o := &updateOverlap{parked: make(chan struct{}), checked: make(chan struct{})}
	gate := make(chan struct{})
	o.resume = sync.OnceFunc(func() { close(gate) })
	t.Cleanup(o.resume)
	var parkOnce, checkOnce sync.Once
	r.updateWaitHook = func(string) { parkOnce.Do(func() { close(o.parked) }) }
	r.updateCheckedHook = func(string) {
		checkOnce.Do(func() { close(o.checked) })
		if holdChecked {
			<-gate
		}
	}
	return o
}

// startUpdate runs an update of pod and returns its result.
func startUpdate(ctx context.Context, r *runtimedRuntime, pod *corev1.Pod) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.UpdatePod(ctx, pod) }()
	return done
}

// awaitParked waits for the update to start waiting for its verdict, and then
// that r.mu is free: a wait holding it would stall every pod on the node. An
// update that passes its check or returns first has not waited, which fails the
// test; the caller carries on so the final state is reported too.
func (o *updateOverlap) awaitParked(t *testing.T, r *runtimedRuntime, updated <-chan error) (returned bool) {
	t.Helper()
	settled := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-o.parked:
		case <-o.checked:
		case <-done:
		}
		close(settled)
	}()
	select {
	case <-settled:
	case err := <-updated:
		t.Errorf("the update ran through the admission window and returned %v instead of waiting", err)
		return true
	}
	select {
	case <-o.parked:
	default:
		t.Error("the update passed its check inside the admission window instead of waiting")
		return false
	}
	free := make(chan struct{})
	go func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		close(free)
	}()
	awaitClosed(t, free, "r.mu while an update waits for a verdict")
	return false
}

// assertHoldsNothing fails t if the pod ended holding anything: no leased /32
// (the pod's lo0 alias goes with it), no interconnect slot or alias, no
// reference entry, and no runtime call was made for it.
func (x *terminalUpdateFixture) assertHoldsNothing(t *testing.T) {
	t.Helper()
	id := string(x.pod.UID)
	if ip, ok := x.ipam.allocations()[id]; ok {
		t.Errorf("the refused pod holds /32 %s and its lo0 alias", ip)
	}
	if rec := x.r.interconnect.record(id); rec != nil {
		t.Errorf("the refused pod holds an interconnect attach (%+v)", rec)
	}
	if n := attachedSlots(x.r.interconnect); n != 0 {
		t.Errorf("interconnect slots held = %d, want 0", n)
	}
	if ensured, removed := x.aliases.calls(); len(ensured) != len(removed) {
		t.Errorf("interconnect aliases ensured %v, removed %v: an alias stayed", ensured, removed)
	}
	if _, registered := x.registeredRefs(); registered {
		t.Error("the refused pod holds a reference entry")
	}
	if n := x.f.updateCount(); n != 0 {
		t.Errorf("runtime UpdatePod calls = %d, want 0", n)
	}
	if n := x.f.createCount(); n != 0 {
		t.Errorf("runtime CreatePod calls = %d, want 0", n)
	}
	if tr := x.r.trackByID(id); tr == nil || !tr.rejected {
		t.Errorf("the refusal did not stand (%s)", trackState(tr))
	}
	x.r.mu.Lock()
	defer x.r.mu.Unlock()
	if n := x.r.admitting[id]; n != 0 {
		t.Errorf("in-flight admitted creates = %d, want 0", n)
	}
}

// refuseNow lands the refusal with a create under pressure.
func (x *terminalUpdateFixture) refuseNow(ctx context.Context, t *testing.T) {
	t.Helper()
	x.src.set(compressorAt(85))
	if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
		t.Fatalf("the create under pressure: %v", err)
	}
	if tr := x.r.trackByID(string(x.pod.UID)); tr == nil || !tr.rejected {
		t.Fatalf("the create under pressure did not refuse the pod (%s)", trackState(tr))
	}
}

// forgeRefusalInWindow drops create 1's in-flight count without ending it, then
// lands a refusal, the forged state TestAdmissionFenceStopsCreateOnForgedRefusal
// uses: admitOnCreate yields to the count, so no production path refuses inside
// an admitted create's window. The ticket's own done still ends the wait.
func (x *terminalUpdateFixture) forgeRefusalInWindow(ctx context.Context, t *testing.T) {
	t.Helper()
	x.r.mu.Lock()
	delete(x.r.admitting, string(x.pod.UID))
	x.r.mu.Unlock()
	x.refuseNow(ctx, t)
}

// TestUpdatePodDuringAdmissionAcquiresNothingOnRefusal: Virtual Kubelet orders
// calls per pod, but the provider does not rely on it. An UpdatePod overlapping
// an admission must wait for the verdict or be re-judged against it, and a
// refused pod ends holding nothing, since its delete frees nothing.
//
// "the verdict in the window is a refusal": the update waits behind the admitted
// create. Fails when UpdatePod looks only at the track: it registers, allocates
// and reaches the runtime for a pod still in its window.
//
// "a refusal lands behind an update past its check": no create was in flight when
// the update looked, so it cannot have waited; it is re-judged before the runtime
// call and releases what it took. Fails without the re-judgement (a runtime call)
// or without the release (the /32, its alias and the references stay held).
//
// "the create in the window fails, then a retry is refused": the only reachable
// order that ends a window in a refusal. The update waits, passes its check once
// the create has failed, and the retry's refusal lands behind it.
//
// "two updates, the last out releases": a release frees by the pod's UID, so it
// cannot start while another update of the pod may still allocate. Fails when
// the release ignores updates in flight.
//
// "an update leaves the release to a create in flight": the same for a create
// that has yet to acquire, on a state forged as forgeRefusalInWindow's; the create
// reaches its own fence and releases there. Fails when the release ignores
// creates in flight.
func TestUpdatePodDuringAdmissionAcquiresNothingOnRefusal(t *testing.T) {
	ctx := context.Background()

	t.Run("the verdict in the window is a refusal", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		entered, release := holdFirstAdmitted(t, x.r)
		o := overlapUpdates(t, x.r, false)

		first := make(chan error, 1)
		go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		awaitClosed(t, entered, "the create to reach the admission window")

		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		returned := o.awaitParked(t, x.r, updated)

		x.forgeRefusalInWindow(ctx, t)
		release()
		if err := awaitErr(t, first, "the create in the window"); err != nil {
			t.Fatalf("the create in the window: %v", err)
		}
		if !returned {
			if err := awaitErr(t, updated, "the update"); err != nil {
				t.Errorf("UpdatePod = %v, want nil for a refused pod", err)
			}
		}
		x.assertHoldsNothing(t)
	})

	t.Run("a refusal lands behind an update past its check", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		o := overlapUpdates(t, x.r, true)

		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, o.checked, "the update to pass its check")
		x.refuseNow(ctx, t)
		o.resume()

		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a refused pod", err)
		}
		x.assertHoldsNothing(t)
	})

	t.Run("the create in the window fails, then a retry is refused", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		x.pod.Spec.Volumes = emptyDirPod("failing", "Memory").Spec.Volumes
		entered, release := holdFirstAdmitted(t, x.r)
		o := overlapUpdates(t, x.r, true)

		first := make(chan error, 1)
		go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		awaitClosed(t, entered, "the create to reach the admission window")

		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		o.awaitParked(t, x.r, updated)

		release()
		if err := awaitErr(t, first, "the create in the window"); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
			t.Fatalf("the create in the window = %v, want ErrEmptyDirMediumUnsupported", err)
		}
		awaitClosed(t, o.checked, "the update to pass its check once the window ended")
		x.refuseNow(ctx, t)
		o.resume()

		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a refused pod", err)
		}
		x.assertHoldsNothing(t)
	})

	t.Run("two updates, the last out releases", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
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
		releases := make(chan struct{}, 2)
		x.r.fenceReleaseHook = func(string) { releases <- struct{}{} }

		// The first update's hold is left open until the second is in flight too,
		// so the order the two leave in is the one the test chose: the first update
		// returns while the second still holds its place.
		updated1 := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, firstChecked, "the first update to pass its check")
		updated2 := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, secondChecked, "the second update to pass its check")
		x.refuseNow(ctx, t)

		releaseFirst()
		if err := awaitErr(t, updated1, "the first update"); err != nil {
			t.Errorf("first UpdatePod = %v, want nil for a refused pod", err)
		}
		select {
		case <-releases:
			t.Error("the first update released with another update of the pod in flight")
		default:
		}
		releaseSecond()
		if err := awaitErr(t, updated2, "the second update"); err != nil {
			t.Errorf("second UpdatePod = %v, want nil for a refused pod", err)
		}
		x.assertHoldsNothing(t)
	})

	t.Run("an update leaves the release to a create in flight", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		id := string(x.pod.UID)
		entered, release := holdFirstAdmitted(t, x.r)
		o := overlapUpdates(t, x.r, true)
		releases := make(chan struct{}, 2)
		x.r.fenceReleaseHook = func(string) { releases <- struct{}{} }

		updated := startUpdate(ctx, x.r, x.pod.DeepCopy())
		awaitClosed(t, o.checked, "the update to pass its check")
		first := make(chan error, 1)
		go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
		awaitClosed(t, entered, "the create to reach the admission window")

		x.forgeRefusalInWindow(ctx, t)
		x.r.mu.Lock()
		x.r.admitting[id] = 1
		x.r.mu.Unlock()
		o.resume()
		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a refused pod", err)
		}
		select {
		case <-releases:
			t.Error("the update released with an admitted create of the pod in flight")
		default:
		}

		release()
		if err := awaitErr(t, first, "the create in the window"); err != nil {
			t.Fatalf("the create in the window: %v", err)
		}
		select {
		case <-releases:
		default:
			t.Error("the create's fence did not release")
		}
		x.assertHoldsNothing(t)
	})
}

// TestUpdatePodDuringAdmissionProceedsWhenAdmitted: the same overlap ending in an
// admission is an ordinary update, once the create has returned: the runtime gets
// it after the create, the tracked spec is the update's, and the pod keeps what
// it acquired. Fails when UpdatePod reaches the runtime inside the window, or when
// a waiting update never resumes.
func TestUpdatePodDuringAdmissionProceedsWhenAdmitted(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	id := string(x.pod.UID)
	entered, release := holdFirstAdmitted(t, x.r)
	o := overlapUpdates(t, x.r, false)

	first := make(chan error, 1)
	go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	awaitClosed(t, entered, "the create to reach the admission window")

	edited := x.pod.DeepCopy()
	edited.Labels = map[string]string{"edited": "yes"}
	updated := startUpdate(ctx, x.r, edited)
	if o.awaitParked(t, x.r, updated) {
		return
	}
	if n := x.f.updateCount(); n != 0 {
		t.Fatalf("runtime UpdatePod calls inside the window = %d, want 0", n)
	}

	release()
	if err := awaitErr(t, first, "the create"); err != nil {
		t.Fatalf("the create: %v", err)
	}
	// The fixture's runtime serves no UpdatePod, so the error is expected: what is
	// pinned is that the update reached it.
	_ = awaitErr(t, updated, "the update")

	if n := x.f.updateCount(); n != 1 {
		t.Errorf("runtime UpdatePod calls = %d, want 1", n)
	}
	if n := x.f.createCount(); n != 1 {
		t.Errorf("runtime CreatePod calls = %d, want 1", n)
	}
	tr := x.r.trackByID(id)
	if tr == nil || tr.rejected || tr.evictedStatus() != nil {
		t.Fatalf("the pod is not tracked as admitted (%s)", trackState(tr))
	}
	x.r.mu.Lock()
	label := tr.pod.Labels["edited"]
	x.r.mu.Unlock()
	if label != "yes" {
		t.Error("the tracked spec is not the update's")
	}
	if _, ok := x.ipam.allocations()[id]; !ok {
		t.Error("the admitted pod lost its /32")
	}
	if _, registered := x.registeredRefs(); !registered {
		t.Error("the admitted pod lost its references")
	}
}

// TestUpdatePodWaitHonoursContext: a waiting update ends with its context, having
// acquired nothing, and the create it waited on is unaffected. Fails when the wait
// reads only the verdict: the update would stay until the create returned.
func TestUpdatePodWaitHonoursContext(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	entered, release := holdFirstAdmitted(t, x.r)
	o := overlapUpdates(t, x.r, false)

	first := make(chan error, 1)
	go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	awaitClosed(t, entered, "the create to reach the admission window")

	updateCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	updated := startUpdate(updateCtx, x.r, x.pod.DeepCopy())
	if o.awaitParked(t, x.r, updated) {
		return
	}
	cancel()
	if err := awaitErr(t, updated, "the cancelled update"); !errors.Is(err, context.Canceled) {
		t.Errorf("UpdatePod = %v, want context.Canceled", err)
	}
	if _, registered := x.registeredRefs(); registered {
		t.Error("the cancelled update registered the pod's references")
	}
	if n := x.ipamSetups(); n != 0 {
		t.Errorf("pod network setups = %d, want 0", n)
	}
	if n := x.f.updateCount(); n != 0 {
		t.Errorf("runtime UpdatePod calls = %d, want 0", n)
	}

	release()
	if err := awaitErr(t, first, "the create"); err != nil {
		t.Fatalf("the create: %v", err)
	}
	if tr := x.r.trackByID(string(x.pod.UID)); tr == nil || tr.rejected {
		t.Errorf("the create did not run the pod (%s)", trackState(tr))
	}
}

// TestUpdatePodWaitsOutFenceRelease: a release at CreatePod's fence frees by the
// pod's UID, so an update arriving once the rejected track is forgotten must not
// allocate inside it, or the release takes what the update just acquired. Fails
// when the update does not look at fenceReleasing.
func TestUpdatePodWaitsOutFenceRelease(t *testing.T) {
	ctx := context.Background()
	x := newTerminalUpdateFixture(t, compressorAt(10))
	id := string(x.pod.UID)
	entered, release := holdFirstAdmitted(t, x.r)
	o := overlapUpdates(t, x.r, false)

	var updated <-chan error
	gotUpdate := make(chan struct{})
	var once sync.Once
	x.r.fenceReleaseHook = func(string) {
		once.Do(func() {
			defer close(gotUpdate)
			x.r.mu.Lock()
			delete(x.r.track, id)
			x.r.mu.Unlock()
			updated = startUpdate(ctx, x.r, x.pod.DeepCopy())
			o.awaitParked(t, x.r, updated)
		})
	}

	first := make(chan error, 1)
	go func() { first <- x.r.CreatePod(ctx, x.pod.DeepCopy()) }()
	awaitClosed(t, entered, "the create to reach the admission window")
	x.forgeRefusalInWindow(ctx, t)
	release()
	if err := awaitErr(t, first, "the create"); err != nil {
		t.Fatalf("the create: %v", err)
	}
	awaitClosed(t, gotUpdate, "the update to start inside the release")

	// The fixture's runtime serves no UpdatePod, so the error is expected: the
	// update is the untracked path, which goes on to acquire.
	_ = awaitErr(t, updated, "the update")
	if _, ok := x.ipam.allocations()[id]; !ok {
		t.Error("the release took the /32 the update acquired")
	}
	if _, registered := x.registeredRefs(); !registered {
		t.Error("the release took the references the update registered")
	}
}
