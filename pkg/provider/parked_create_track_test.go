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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// parkedCallsOut reports whether every call of pod id has returned: no create, update
// or parked retry is counted, no compensating delete is recorded and no release runs.
// Each of them hands over to the next under r.mu, so this is never true between a
// call's return and the release it owes.
func parkedCallsOut(r *runtimedRuntime, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, compensating := r.compensating[id]
	return r.admitting[id] == 0 && r.updating[id] == 0 && !compensating && r.fenceReleasing[id] == nil
}

// updatingCount is the number of updates and parked retries of pod id in flight.
func updatingCount(r *runtimedRuntime, id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.updating[id]
}

// deleteIsOwed reports whether the rest of pod id's delete waits for a last call out.
func deleteIsOwed(r *runtimedRuntime, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, owed := r.deleteOwed[id]
	return owed
}

// assertStaleCreateBuildsNothing replays a create of a deleted pod, which must reach
// the runtime no more and leave whatever track the id holds.
func assertStaleCreateBuildsNothing(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
	t.Helper()
	id := string(pod.UID)
	creates, before := f.createCount(), r.trackByID(id)
	// Bounded so a create that does not read the tombstone, and waits at a held
	// release instead, fails the assertions below rather than hanging the test.
	ctx, cancel := context.WithTimeout(context.Background(), admissionAwaitBound)
	defer cancel()
	if err := r.CreatePod(ctx, pod.DeepCopy()); err != nil {
		t.Fatalf("a stale CreatePod = %v, want nil", err)
	}
	if got := f.createCount(); got != creates {
		t.Errorf("CreatePod RPCs after a stale create = %d, want %d", got, creates)
	}
	if got := r.trackByID(id); got != before {
		t.Errorf("a stale create changed the track from %p to %p", before, got)
	}
}

// assertNothingLeft waits for every call of pod to return, then reads once what the
// pod's id still holds: past that wait nothing is left that could clear it.
func assertNothingLeft(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod, hasWaiters func() bool) {
	t.Helper()
	id := string(pod.UID)
	waitRestart(t, "the pod's calls to return", func() bool { return parkedCallsOut(r, id) })
	if tr := r.trackByID(id); tr != nil {
		t.Errorf("the deleted pod is still tracked with every call returned (%s)", trackState(tr))
	}
	if deleteIsOwed(r, id) {
		t.Error("a delete is still owed with every call returned, and nothing is left to run it")
	}
	if f.hasCreated(id) {
		t.Error("the runtime still holds the pod")
	}
	if n := proberCount(r); n != 0 {
		t.Errorf("probe runners = %d, want none for a deleted pod", n)
	}
	// The parked retry loop: no timer armed means no clock step can attempt again.
	waitRestart(t, "the pod's retry timers to retire", func() bool { return !hasWaiters() })
	assertStaleCreateBuildsNothing(t, r, f, pod)
	if tr := r.trackByID(id); tr != nil {
		t.Errorf("a stale create tracked the deleted pod again (%s)", trackState(tr))
	}
}

// assertTracked pins a forced window: the track is still held at this point, by the
// call named in why, so its later absence is that call's doing.
func assertTracked(t *testing.T, r *runtimedRuntime, id, why string) {
	t.Helper()
	if r.trackByID(id) == nil {
		t.Fatalf("setup: the track is gone already, so this order was not forced: %s", why)
	}
}

// TestParkedCreateLeavesNoTrackAfterCompensation forces each order of the calls that
// end a delete behind a parked pod's retry: the retry's own updateDone, the
// compensating delete's return, the release one of them runs, and the pod's own
// DeletePod. The track is held until the last of them, and gone once all have returned.
//
// The first order is the window the track read in TestParkedCreateFencedAgainstDelete
// used to land in: the fake has recorded the compensating delete, and the RPC has not
// returned. Non-vacuity: the first order fails when runCompensatingDelete stops claiming
// the release the delete owes, the second when updateDone does, the fourth and fifth when
// teardownPod stops forgetting the track, and all but the shutdown when CreatePod stops
// reading the tombstone.
func TestParkedCreateLeavesNoTrackAfterCompensation(t *testing.T) {
	ctx := context.Background()
	const lateDelete, ownDelete = 2, 1

	t.Run("the retry returns while the compensating delete is inside its RPC", func(t *testing.T) {
		pod := probePullPod("retry-first")
		id := string(pod.UID)
		r, f, clk, release := parkedWithHeldRetry(t, pod)
		defer release()
		if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		releaseDelete := f.holdDelete()
		defer releaseDelete()

		release()
		waitRestart(t, "the compensating delete to be recorded", func() bool { return len(f.deleteRecords()) == lateDelete })
		assertTracked(t, r, id, "the compensating delete is recorded and has not returned")
		waitRestart(t, "the retry to return", func() bool { return updatingCount(r, id) == 0 })
		assertTracked(t, r, id, "the retry has returned, and the compensating delete is the last call out")
		assertStaleCreateBuildsNothing(t, r, f, pod)

		releaseDelete()
		assertNothingLeft(t, r, f, pod, clk.HasWaiters)
	})

	// The retry's own updateDone has no seam of its own past its RPC, and what decides
	// here is only that the count is not zero when the compensating delete returns. An
	// update held past its check keeps the count there with the same code the retry
	// runs on its way out.
	t.Run("the compensating delete returns while a call is still counted", func(t *testing.T) {
		pod := probePullPod("compensator-first")
		id := string(pod.UID)
		r, f, clk, release := parkedWithHeldRetry(t, pod)
		defer release()
		checked := make(chan struct{}, 1)
		holdUpdate := make(chan struct{})
		r.updateCheckedHook = func(string) {
			checked <- struct{}{}
			<-holdUpdate
		}
		updated := make(chan error, 1)
		go func() { updated <- r.UpdatePod(ctx, pod.DeepCopy()) }()
		waitRestart(t, "the update to pass its check", func() bool { return len(checked) == 1 })
		if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}

		release()
		waitRestart(t, "the compensating delete to retire and only the update to be left", func() bool {
			return len(f.deleteRecords()) == lateDelete && compensatingCount(r) == 0 && updatingCount(r, id) == 1
		})
		assertTracked(t, r, id, "the update is the last call out")
		assertStaleCreateBuildsNothing(t, r, f, pod)

		close(holdUpdate)
		if err := awaitErr(t, updated, "the update"); err != nil {
			t.Fatalf("UpdatePod = %v, want nil", err)
		}
		// Synchronous: the last call out finishes the delete before it returns.
		if tr := r.trackByID(id); tr != nil {
			t.Errorf("the last call out returned and the pod is still tracked (%s)", trackState(tr))
		}
		assertNothingLeft(t, r, f, pod, clk.HasWaiters)
	})

	t.Run("the release runs while the compensating delete is still recorded", func(t *testing.T) {
		pod := probePullPod("release-held")
		id := string(pod.UID)
		r, f, clk, release := parkedWithHeldRetry(t, pod)
		defer release()
		entered := make(chan struct{}, 1)
		holdRelease := make(chan struct{})
		r.fenceReleaseHook = func(string) {
			entered <- struct{}{}
			<-holdRelease
		}
		if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		releaseDelete := f.holdDelete()
		defer releaseDelete()
		release()
		waitRestart(t, "the compensating delete to be recorded", func() bool { return len(f.deleteRecords()) == lateDelete })
		waitRestart(t, "the retry to return", func() bool { return updatingCount(r, id) == 0 })

		releaseDelete()
		waitRestart(t, "the release to begin", func() bool { return len(entered) == 1 })
		assertTracked(t, r, id, "the release forgets the track, and it is held")
		if compensatingCount(r) != 1 {
			t.Errorf("compensating entries inside the release = %d, want 1", compensatingCount(r))
		}
		assertStaleCreateBuildsNothing(t, r, f, pod)

		close(holdRelease)
		assertNothingLeft(t, r, f, pod, clk.HasWaiters)
	})

	t.Run("the compensating delete lands while the pod's own delete is inside its RPC", func(t *testing.T) {
		pod := probePullPod("own-delete-last")
		id := string(pod.UID)
		r, f, clk, release := parkedWithHeldRetry(t, pod)
		defer release()
		releaseDelete := f.holdDelete()
		defer releaseDelete()
		deleted := make(chan error, 1)
		go func() { deleted <- r.DeletePod(ctx, pod.DeepCopy()) }()
		waitRestart(t, "the pod's own delete to be entered", func() bool { return len(f.deleteRecords()) == ownDelete })
		// Only the delete already inside the RPC stays held.
		f.mu.Lock()
		f.deleteHold = nil
		f.mu.Unlock()

		release()
		waitRestart(t, "the compensating delete to retire and the retry to return", func() bool {
			return len(f.deleteRecords()) == lateDelete && compensatingCount(r) == 0 && updatingCount(r, id) == 0
		})
		assertTracked(t, r, id, "the pod's own delete has not returned, and it owes no one the rest")
		if deleteIsOwed(r, id) {
			t.Error("a delete is owed before the pod's own delete has read the count")
		}

		releaseDelete()
		if err := awaitErr(t, deleted, "the pod's own delete"); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if tr := r.trackByID(id); tr != nil {
			t.Errorf("DeletePod returned and the pod is still tracked (%s)", trackState(tr))
		}
		assertNothingLeft(t, r, f, pod, clk.HasWaiters)
	})

	// A failed delete tore nothing down and owes nothing, so the track waits for the
	// delete Virtual Kubelet requeues on the error (or the orphan reaper's).
	t.Run("the pod's own delete fails and is replayed after the compensation", func(t *testing.T) {
		pod := probePullPod("own-delete-fails")
		id := string(pod.UID)
		r, f, clk, release := parkedWithHeldRetry(t, pod)
		defer release()
		f.pushDeleteErr(errors.New("runtimed unavailable"))
		if err := r.DeletePod(ctx, pod.DeepCopy()); err == nil {
			t.Fatal("DeletePod = nil, want the runtime's error for Virtual Kubelet to requeue on")
		}

		release()
		waitRestart(t, "the compensating delete", func() bool { return len(f.deleteRecords()) == lateDelete })
		waitRestart(t, "the pod's calls to return", func() bool { return parkedCallsOut(r, id) })
		assertTracked(t, r, id, "the replay of the failed delete owns the track")

		if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
			t.Fatalf("the replayed DeletePod: %v", err)
		}
		if tr := r.trackByID(id); tr != nil {
			t.Errorf("the replayed DeletePod returned and the pod is still tracked (%s)", trackState(tr))
		}
		assertNothingLeft(t, r, f, pod, clk.HasWaiters)
	})

	t.Run("a compensating delete that fails holds the track until it lands", func(t *testing.T) {
		pod := probePullPod("compensator-retries")
		id := string(pod.UID)
		r, f, clk, release := parkedWithHeldRetry(t, pod)
		defer release()
		if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		f.pushDeleteErr(errors.New("runtimed unavailable"))

		release()
		waitRestart(t, "the retry to return", func() bool { return updatingCount(r, id) == 0 })
		waitRestart(t, "the compensating retry to arm", clk.HasWaiters)
		assertTracked(t, r, id, "the compensating delete has not landed")
		assertStaleCreateBuildsNothing(t, r, f, pod)

		clk.Step(11 * time.Second)
		waitRestart(t, "the second compensating attempt", func() bool { return len(f.deleteRecords()) == lateDelete+1 })
		assertNothingLeft(t, r, f, pod, clk.HasWaiters)
	})

	// The one order that ends with the track held: the guest was never confirmed gone, so
	// nothing is released on the way down, and the track goes with the process. The next
	// daemon start decides the guest.
	t.Run("a shutdown leaves the owed delete to the next daemon start", func(t *testing.T) {
		pod := probePullPod("shutdown")
		id := string(pod.UID)
		r, f, clk, release := parkedWithHeldRetry(t, pod)
		defer release()
		lifetime := make(chan struct{})
		r.lifetime = lifetime
		if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		f.pushDeleteErr(errors.New("runtimed unavailable"))

		release()
		waitRestart(t, "the retry to return", func() bool { return updatingCount(r, id) == 0 })
		waitRestart(t, "the compensating retry to arm", clk.HasWaiters)
		close(lifetime)
		waitRestart(t, "the pod's calls to return", func() bool { return parkedCallsOut(r, id) })
		assertTracked(t, r, id, "a shutdown releases nothing")
		if !deleteIsOwed(r, id) {
			t.Error("the owed delete was consumed by a shutdown that released nothing")
		}
	})
}
