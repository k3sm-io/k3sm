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
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// erroringCreateRuntime is the fake runtime with a FIFO of CreatePod error
// returns in front of it: the in-process runtime's refusals that come back as an
// error rather than a response. An exhausted FIFO delegates to the fake.
type erroringCreateRuntime struct {
	*fakeRuntimeServer
	mu    sync.Mutex
	errs  []error
	calls int
}

func (e *erroringCreateRuntime) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	e.mu.Lock()
	e.calls++
	var err error
	if len(e.errs) > 0 {
		err, e.errs = e.errs[0], e.errs[1:]
	}
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return e.fakeRuntimeServer.CreatePod(ctx, req)
}

func (e *erroringCreateRuntime) createCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func newBlockedCreateProvider(t *testing.T, errs ...error) (*runtimedRuntime, *erroringCreateRuntime, *testclock.FakeClock, *record.FakeRecorder) {
	t.Helper()
	ipam := newFakeIPAM(t, "100.64.0.0/24")
	e := &erroringCreateRuntime{fakeRuntimeServer: newFakeRuntimeServer(), errs: errs}
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(e, RuntimedConfig{
		NodeName: "n",
		NodeIP:   testNodeIP,
		Root:     t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: rec,
		Network:  NewPodNetAdapter(ipam, testNodeIP, nil),
	}, nil, nil)
	clk := testclock.NewFakeClock(time.Unix(10000, 0))
	r.clk = clk
	return r, e, clk, rec
}

func addressHeld(r *runtimedRuntime, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, held := r.held[id]
	return held
}

// TestCreateRefusedBesideLiveProcessesParksNotFails pins the park of a create the
// runtime refused because processes an earlier run of the pod started are still
// alive. Returning that error would leave the track installed, so the next sync
// would take the update path and never create, and a restartPolicy Never pod
// would go Failed for a condition that clears on its own.
func TestCreateRefusedBesideLiveProcessesParksNotFails(t *testing.T) {
	sentinels := []struct {
		name  string
		cause error
	}{
		{"a live process group", fmt.Errorf("create pod x: process group 4242 (record /var/lib/k3sm/pods/x/pgid): %w", runtimed.ErrPodGroupStillAlive)},
		{"a live vm host helper", fmt.Errorf("create pod x: helper pid 4343: %w", runtimed.ErrVMHelperUnadoptable)},
	}
	for _, s := range sentinels {
		t.Run(s.name+" parks the pod and creates it once the processes exit", func(t *testing.T) {
			ctx := context.Background()
			pod := pullPod("blocked")
			pod.Spec.RestartPolicy = corev1.RestartPolicyNever
			id := string(pod.UID)
			// The first create and the first retry are refused; the next one passes.
			r, e, clk, rec := newBlockedCreateProvider(t, s.cause, s.cause)

			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod = %v, want nil: the pod is parked, not failed", err)
			}
			tr := r.trackByID(id)
			if tr == nil {
				t.Fatal("the refused pod is not tracked, so nothing can retry it")
			}
			if !addressHeld(r, id) {
				t.Fatal("the parked pod's address was released")
			}
			st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
			if err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			if st.Phase != corev1.PodPending {
				t.Errorf("phase = %s, want Pending", st.Phase)
			}
			w := waitingOf(st, "c0")
			if w == nil || w.Reason != reasonContainerCreating {
				t.Fatalf("waiting = %+v, want ContainerCreating, not an image reason", w)
			}
			if !strings.Contains(w.Message, s.cause.Error()) || !strings.Contains(w.Message, "previous run's processes") {
				t.Errorf("waiting message = %q, want the wait explained with the runtime's text %q", w.Message, s.cause.Error())
			}
			events := recordedEvents(rec.Events)
			if n := countEvents(events, corev1.EventTypeWarning); n != 1 {
				t.Errorf("Warning events at the park = %d (%v), want exactly 1", n, events)
			}
			if !containsEvent(events, reasonFailedCreatePodSandBox) {
				t.Errorf("events = %v, want %s", events, reasonFailedCreatePodSandBox)
			}

			// The first resync's retry is refused again: still parked, address
			// still held, and no further Warning.
			clk.Step(resyncInterval + time.Second)
			if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			waitRestart(t, "the first retry", func() bool { return e.createCalls() == 2 })
			waitRestart(t, "the first retry to finish", func() bool {
				tr.restartMu.Lock()
				defer tr.restartMu.Unlock()
				for _, pr := range tr.pulls {
					if pr.attempt {
						return false
					}
				}
				return true
			})
			if tr.parkedFailure() == nil || !addressHeld(r, id) {
				t.Fatal("a refused retry unparked the pod or released its address")
			}
			if n := countEvents(recordedEvents(rec.Events), corev1.EventTypeWarning); n != 0 {
				t.Errorf("Warning events on a refused resync retry = %d, want 0", n)
			}

			// The processes have exited: the next resync creates the pod.
			clk.Step(resyncInterval + time.Second)
			if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			waitRestart(t, "the park to clear", func() bool { return tr.parkedFailure() == nil })
			if !e.hasCreated(id) {
				t.Error("the runtime does not hold the pod after the create passed")
			}
			if n := countEvents(recordedEvents(rec.Events), corev1.EventTypeWarning); n != 0 {
				t.Errorf("Warning events after the park = %d, want 0", n)
			}
		})

		t.Run(s.name+": a delete while parked cancels the retry and releases the address", func(t *testing.T) {
			ctx := context.Background()
			pod := pullPod("blocked-deleted")
			id := string(pod.UID)
			r, e, clk, _ := newBlockedCreateProvider(t, s.cause)
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod = %v, want nil", err)
			}
			if !addressHeld(r, id) {
				t.Fatal("the parked pod's address was released before the delete")
			}
			if err := r.DeletePod(ctx, pod); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			waitRestart(t, "the address release", func() bool { return !addressHeld(r, id) })
			waitRestart(t, "the track to go", func() bool { return r.trackByID(id) == nil })
			clk.Step(3 * resyncInterval)
			_, _ = r.GetPodStatus(ctx, pod.Namespace, pod.Name)
			if n := e.createCalls(); n != 1 {
				t.Errorf("CreatePod calls = %d, want 1: a deleted parked pod is not retried", n)
			}
			if e.hasCreated(id) {
				t.Error("the runtime holds a pod that was deleted while parked")
			}
		})
	}

	t.Run("a create in flight elsewhere is an error, not a park", func(t *testing.T) {
		ctx := context.Background()
		pod := pullPod("inflight")
		cause := fmt.Errorf("create pod x: waiting: %w: %w", runtimed.ErrPodCreateInFlight, context.Canceled)
		r, _, _, _ := newBlockedCreateProvider(t, cause)
		err := r.CreatePod(ctx, pod)
		if err == nil || !errors.Is(err, runtimed.ErrPodCreateInFlight) {
			t.Fatalf("CreatePod = %v, want the in-flight error returned", err)
		}
		if tr := r.trackByID(string(pod.UID)); tr != nil && tr.parkedFailure() != nil {
			t.Error("an in-flight wait was parked")
		}
		if isParkableCreateRefusal(cause) {
			t.Error("ErrPodCreateInFlight is in the parkable list")
		}
	})
}
