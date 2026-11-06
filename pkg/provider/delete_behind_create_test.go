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
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
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
