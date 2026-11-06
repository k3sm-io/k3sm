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
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/tools/record"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/gpucapacity"
)

const (
	unitsOldName = corev1.ResourceName(mlxv1alpha1.ResourceGPU)
	unitsNewName = corev1.ResourceName(runtimev1.ResourceGPU)
)

// namedGPUPod builds a pod whose one container asks for one GPU unit under each
// of the given names, in limits, the way a spec.nodeName pod reaches CreatePod:
// the scheduler never saw it, so nothing but admission counts it.
func namedGPUPod(name string, names ...corev1.ResourceName) *corev1.Pod {
	pod := gpuFitPod(name, testGiB, false)
	pod.Spec.NodeName = "n"
	for _, gpu := range names {
		pod.Spec.Containers[0].Resources.Limits[gpu] = resource.MustParse("1")
	}
	return pod
}

// requestsOnlyGPUPod asks under gpu in requests alone: counted, never granted.
func requestsOnlyGPUPod(name string, gpu corev1.ResourceName) *corev1.Pod {
	pod := gpuFitPod(name, testGiB, false)
	pod.Spec.NodeName = "n"
	pod.Spec.Containers[0].Resources.Requests = corev1.ResourceList{gpu: resource.MustParse("1")}
	return pod
}

// assertSlotRefusal pins everything a refusal by the cap owes: the sentinel, no
// RPC, no track, and an Event naming the numbers and both ways out.
func assertSlotRefusal(t *testing.T, r *runtimedRuntime, f *platformFake, rec *record.FakeRecorder, pod *corev1.Pod, wantCreates int, wantNumbers ...string) {
	t.Helper()
	err := r.CreatePod(context.Background(), pod)
	if !errors.Is(err, gpucapacity.ErrGPUSlotsFull) {
		t.Fatalf("CreatePod(%s) = %v, want gpucapacity.ErrGPUSlotsFull", pod.Name, err)
	}
	if _, creates := f.counts(); creates != wantCreates {
		t.Errorf("CreatePod RPC calls = %d, want %d: the refusal lands before the RPC", creates, wantCreates)
	}
	if r.trackByID(string(pod.UID)) != nil {
		t.Errorf("refused pod %s was tracked; it would hold a slot it never got", pod.Name)
	}
	ev := findEvent(rec.Events, reasonFailedGPUFit)
	if !strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonFailedGPUFit+" ") {
		t.Fatalf("Event = %q, want a %s %s event", ev, corev1.EventTypeWarning, reasonFailedGPUFit)
	}
	for _, want := range append([]string{string(unitsOldName), " " + string(unitsNewName)}, wantNumbers...) {
		if !strings.Contains(ev, want) {
			t.Errorf("Event %q does not name %q", ev, want)
		}
	}
}

// TestUnitsCountBothNames is the gate for counting a pod's GPU units while the
// resource has two names. The scheduler counts each name on its own and cannot do
// otherwise, and a pod with spec.nodeName skips it altogether, so CreatePod is the
// one place that holds the node to its real slot count. The assertions run on a
// real CreatePod for that reason.
func TestUnitsCountBothNames(t *testing.T) {
	t.Parallel()

	one, two, zero := resource.MustParse("1"), resource.MustParse("2"), resource.MustParse("0")

	t.Run("pod_units", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name             string
			limits, requests corev1.ResourceList
			sidecarLimits    corev1.ResourceList
			want             int64
		}{
			{name: "neither_name"},
			{name: "old_name", limits: corev1.ResourceList{unitsOldName: one}, want: 1},
			{name: "new_name", limits: corev1.ResourceList{unitsNewName: one}, want: 1},
			{name: "both_on_one_pod_counted_once", limits: corev1.ResourceList{unitsOldName: one, unitsNewName: one}, want: 1},
			{name: "both_counts_the_larger", limits: corev1.ResourceList{unitsOldName: one, unitsNewName: two}, want: 2},
			{
				name:          "each_name_on_its_own_container_counted_once",
				limits:        corev1.ResourceList{unitsOldName: one},
				sidecarLimits: corev1.ResourceList{unitsNewName: one},
				want:          1,
			},
			{name: "old_name_requests_only", requests: corev1.ResourceList{unitsOldName: one}, want: 1},
			{name: "new_name_requests_only", requests: corev1.ResourceList{unitsNewName: one}, want: 1},
			{
				name:     "a_zero_limit_wins_over_its_own_request",
				limits:   corev1.ResourceList{unitsNewName: zero},
				requests: corev1.ResourceList{unitsNewName: one},
			},
			{
				name:   "a_zero_does_not_hide_the_other_name",
				limits: corev1.ResourceList{unitsOldName: zero, unitsNewName: one},
				want:   1,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				pod := gpuFitPod("units", testGiB, false)
				c := &pod.Spec.Containers[0]
				c.Resources.Requests = tc.requests
				for k, v := range tc.limits {
					c.Resources.Limits[k] = v
				}
				if tc.sidecarLimits != nil {
					pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
						Name: "c1", Resources: corev1.ResourceRequirements{Limits: tc.sidecarLimits},
					})
				}
				if got := gpucapacity.PodUnits(pod); got != tc.want {
					t.Errorf("PodUnits = %d, want %d", got, tc.want)
				}
			})
		}
	})

	// The scheduler lets one pod per name through on a one-slot node, which is
	// the double count this cap exists for, whichever name arrives first. An
	// unknown ceiling is the case nothing else would catch: GPUFits is off there.
	t.Run("two_pods_under_different_names_exceed_the_cap", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name          string
			first, second corev1.ResourceName
		}{
			{name: "old_then_new", first: unitsOldName, second: unitsNewName},
			{name: "new_then_old", first: unitsNewName, second: unitsOldName},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				r, f, rec := gpuFitRuntime(t, 0)

				first := namedGPUPod("first", tc.first)
				if err := r.CreatePod(ctx, first); err != nil {
					t.Fatalf("CreatePod(first) = %v", err)
				}
				second := namedGPUPod("second", tc.second)
				assertSlotRefusal(t, r, f, rec, second, 1, "1 of")

				// The total is derived from the tracks, so a delete frees the slot.
				if err := r.DeletePod(ctx, first); err != nil {
					t.Fatalf("DeletePod(first) = %v", err)
				}
				if err := r.CreatePod(ctx, second); err != nil {
					t.Fatalf("CreatePod(second) after the delete = %v", err)
				}
			})
		}
	})

	// A pod with spec.nodeName and the new name skips the scheduler, so no count
	// anywhere stops the second one but this.
	t.Run("new_name_with_node_name_skips_the_scheduler", func(t *testing.T) {
		t.Parallel()
		r, f, rec := gpuFitRuntime(t, 0)
		if err := r.CreatePod(context.Background(), namedGPUPod("first", unitsNewName)); err != nil {
			t.Fatalf("CreatePod(first) = %v", err)
		}
		assertSlotRefusal(t, r, f, rec, namedGPUPod("second", unitsNewName), 1)
	})

	// With a known ceiling the memory fit often refuses first. These pods fit in
	// memory, so the cap is what refuses the third: 3 GiB holds two slots.
	t.Run("known_ceiling_cap_refuses_what_the_memory_fit_admits", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, rec := gpuFitRuntime(t, 3*testGiB)
		if err := r.CreatePod(ctx, namedGPUPod("a", unitsOldName)); err != nil {
			t.Fatalf("CreatePod(a) = %v", err)
		}
		if err := r.CreatePod(ctx, namedGPUPod("b", unitsNewName)); err != nil {
			t.Fatalf("CreatePod(b) = %v", err)
		}
		assertSlotRefusal(t, r, f, rec, namedGPUPod("c", unitsNewName), 2, "2 of")
	})

	// A pod naming both resources holds one slot, not one per name.
	t.Run("both_on_one_pod_holds_one_slot", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, rec := gpuFitRuntime(t, 3*testGiB)
		if err := r.CreatePod(ctx, namedGPUPod("both", unitsOldName, unitsNewName)); err != nil {
			t.Fatalf("CreatePod(both) = %v", err)
		}
		if err := r.CreatePod(ctx, namedGPUPod("next", unitsNewName)); err != nil {
			t.Fatalf("CreatePod(next) = %v, want the second slot free beside a pod naming both", err)
		}
		assertSlotRefusal(t, r, f, rec, namedGPUPod("over", unitsOldName), 2)
	})

	// PodUnits falls back to requests and the grant does not. So a requests-only
	// pod holds a slot and runs with no GPU access, and using the count for
	// allow_gpu would turn this into a grant.
	t.Run("requests_only_is_counted_not_granted", func(t *testing.T) {
		t.Parallel()
		for _, gpu := range []corev1.ResourceName{unitsNewName, unitsOldName} {
			t.Run(string(gpu), func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				r, f, rec := gpuFitRuntime(t, 0)

				pod := requestsOnlyGPUPod("requests", gpu)
				if err := r.CreatePod(ctx, pod); err != nil {
					t.Fatalf("CreatePod(requests) = %v", err)
				}
				f.fakeRuntimeServer.mu.Lock()
				box, ok := f.created[string(pod.UID)]
				f.fakeRuntimeServer.mu.Unlock()
				if !ok {
					t.Fatal("the requests-only pod never reached the runtime")
				}
				if box.GetSandboxProfile().GetAllowGpu() {
					t.Error("allow_gpu = true for a requests-only pod; requests never grant")
				}
				assertSlotRefusal(t, r, f, rec, namedGPUPod("limits", unitsNewName), 1, "1 of")
			})
		}

		t.Run("refused_on_a_full_node", func(t *testing.T) {
			t.Parallel()
			r, f, rec := gpuFitRuntime(t, 0)
			if err := r.CreatePod(context.Background(), namedGPUPod("holder", unitsOldName)); err != nil {
				t.Fatalf("CreatePod(holder) = %v", err)
			}
			assertSlotRefusal(t, r, f, rec, requestsOnlyGPUPod("requests", unitsNewName), 1)
		})
	})

	// A pod naming only the old name, beside pods naming only the old name, is
	// admitted as it was before the second name existed. The scheduler counts that
	// population itself.
	t.Run("old_name_alone_is_unchanged", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, rec := gpuFitRuntime(t, 0)
		for _, name := range []string{"a", "b", "c"} {
			if err := r.CreatePod(ctx, namedGPUPod(name, unitsOldName)); err != nil {
				t.Fatalf("CreatePod(%s) = %v", name, err)
			}
		}
		if _, creates := f.counts(); creates != 3 {
			t.Errorf("CreatePod RPC calls = %d, want 3", creates)
		}
		if ev := findEvent(rec.Events, reasonFailedGPUFit); ev != "" {
			t.Errorf("recorded %q, want no %s event", ev, reasonFailedGPUFit)
		}
		// One new-name pod makes it a two-name count, and the old pods are in it.
		assertSlotRefusal(t, r, f, rec, namedGPUPod("new", unitsNewName), 3, "3 of")
	})

	t.Run("idempotent_recreate_excludes_its_own_entry", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, _, _ := gpuFitRuntime(t, 0)
		pod := namedGPUPod("solo", unitsNewName)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod = %v", err)
		}
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod (repeat) = %v, want the pod's own slot not charged twice", err)
		}
	})

	// A finished pod stays tracked until the apiserver object goes, and the
	// scheduler has already released its slot. Counting it would refuse a pod the
	// scheduler rightly bound, for as long as a completed Job is kept around.
	t.Run("a_finished_pod_holds_no_slot", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, _ := gpuFitRuntime(t, 0)
		done := namedGPUPod("done", unitsNewName)
		done.Spec.RestartPolicy = corev1.RestartPolicyNever
		if err := r.CreatePod(ctx, done); err != nil {
			t.Fatalf("CreatePod(done) = %v", err)
		}
		f.fakeRuntimeServer.mu.Lock()
		if f.stopped == nil {
			f.stopped = map[string]map[string]bool{}
		}
		f.stopped[string(done.UID)] = map[string]bool{"c0": true}
		f.fakeRuntimeServer.mu.Unlock()
		if err := r.CreatePod(ctx, namedGPUPod("next", unitsNewName)); err != nil {
			t.Fatalf("CreatePod(next) = %v, want the finished pod's slot free", err)
		}
	})

	// A pod refused at admission holds nothing, and neither does an evicted one.
	t.Run("a_rejected_track_holds_no_slot", func(t *testing.T) {
		t.Parallel()
		r, _, _ := gpuFitRuntime(t, 0)
		held := namedGPUPod("rejected", unitsNewName)
		st := &corev1.PodStatus{Phase: corev1.PodFailed}
		r.mu.Lock()
		r.track[string(held.UID)] = &podTrack{pod: held, rejected: true, evicted: st}
		r.mu.Unlock()
		if err := r.CreatePod(context.Background(), namedGPUPod("next", unitsNewName)); err != nil {
			t.Fatalf("CreatePod(next) = %v, want a rejected pod to hold nothing", err)
		}
	})

	// Check and insert are one critical section, or two creates would both see a
	// free slot.
	t.Run("concurrent_creates_take_one_slot", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, _ := gpuFitRuntime(t, 0)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, pod := range []*corev1.Pod{namedGPUPod("a", unitsNewName), namedGPUPod("b", unitsOldName)} {
			wg.Go(func() { errs[i] = r.CreatePod(ctx, pod) })
		}
		wg.Wait()
		refused := 0
		for _, err := range errs {
			if errors.Is(err, gpucapacity.ErrGPUSlotsFull) {
				refused++
			} else if err != nil {
				t.Errorf("CreatePod = %v", err)
			}
		}
		if _, creates := f.counts(); refused != 1 || creates != 1 {
			t.Errorf("refused = %d, RPC calls = %d; want exactly one of each", refused, creates)
		}
	})

	// A failed probe says nothing about the slot count, and the memory fit admits
	// on it for the same reason: GPUSlots(nil) answers 1, which on a two-slot node
	// would refuse a pod the node has room for because one RPC did not answer.
	t.Run("a_failed_probe_turns_the_cap_off", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		f := &failedProbeFake{fakeRuntimeServer: newFakeRuntimeServer()}
		r := newRuntimedWith(f, RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
			Recorder: record.NewFakeRecorder(64),
		}, nil, nil)
		for _, name := range []string{"a", "b"} {
			if err := r.CreatePod(ctx, namedGPUPod(name, unitsNewName)); err != nil {
				t.Fatalf("CreatePod(%s) = %v, want it admitted on an unanswered probe", name, err)
			}
		}
	})
}

// failedProbeFake is a runtime whose GetRuntimeInfo does not answer.
type failedProbeFake struct {
	*fakeRuntimeServer
}

func (*failedProbeFake) GetRuntimeInfo(context.Context, *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	return nil, errors.New("probe unavailable")
}
