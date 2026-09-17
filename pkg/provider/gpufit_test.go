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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/mlx"
)

const testGiB = int64(1) << 30

// gpuFitPod builds a one-container pod with the given memory limit and, when
// gpu is true, one unit of the mlx.k3sm.io/gpu extended resource. The GPU ask is
// spelled in LIMITS because that is where podRequestsGPU and podMemoryLimitBytes
// both read: a requests-only ask is not a grant on this path.
func gpuFitPod(name string, memBytes int64, gpu bool) *corev1.Pod {
	c := corev1.Container{
		Name: "c0", Image: "registry/serve:1", Command: []string{"/serve"},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: *resource.NewQuantity(memBytes, resource.BinarySI),
			},
		},
	}
	if gpu {
		c.Resources.Limits[corev1.ResourceName(mlxv1alpha1.ResourceGPU)] = *resource.NewQuantity(1, resource.DecimalSI)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{c}},
	}
}

// gpuFitRuntime wires a provider over a fake runtime whose GetRuntimeInfo reports
// the given usable GPU ceiling (as the Metal recommended working set; a 0 reports
// facts with no readable ceiling, the unknown sentinel). The Event recorder is
// generously buffered because an ADMITTED pod also emits its pull-lifecycle
// events, and a full channel would drop the very event a later row asserts.
func gpuFitRuntime(t *testing.T, ceilingBytes int64) (*runtimedRuntime, *platformFake, *record.FakeRecorder) {
	t.Helper()
	f := &platformFake{
		fakeRuntimeServer: newFakeRuntimeServer(),
		info: &runtimev1.GetRuntimeInfoResponse{
			Healthy: true,
			Gpu: &runtimev1.GPUFacts{
				MetalAvailable:                true,
				SandboxGpuSupported:           true,
				ChipBrand:                     "Apple M4 Max",
				MemBytes:                      uint64(128 * testGiB),
				RecommendedMaxWorkingSetBytes: uint64(ceilingBytes),
			},
		},
	}
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
	}, nil, nil)
	return r, f, rec
}

// findEvent drains the recorder and returns the first event carrying reason, or
// "" if none did. It drains rather than peeking because an admitted pod's pull
// events sit ahead of anything a refusal recorded.
func findEvent(ch <-chan string, reason string) string {
	for {
		select {
		case ev := <-ch:
			if strings.Contains(ev, reason) {
				return ev
			}
		default:
			return ""
		}
	}
}

// TestCreatePodGPUCumulativeFit is the gate for the node's admission-time GPU
// memory fit: a pod requesting mlx.k3sm.io/gpu is admitted only if its memory
// limit still fits under this node's usable GPU ceiling BESIDE the GPU pods
// already admitted.
//
// WHY THE EXTENDED RESOURCE IS NOT ENOUGH ON ITS OWN: the advertised slot count
// is derived from the ceiling at a FIXED per-slot floor (mlx.GPUSlotFloorBytes),
// so two pods that each hold a slot can still ask for more memory between them
// than the GPU has. The scheduler counts slots and cannot see that; nothing below
// it reports the overcommit either — the second model simply fails to allocate
// mid-load, or takes the first one down with it.
//
// Every leg here is load bearing, and the admit legs are the ones that decay
// silently: a fit check exercised only on its refusal leg degrades into a
// one-GPU-pod-per-node gate, which is the behavior this whole change replaces.
func TestCreatePodGPUCumulativeFit(t *testing.T) {
	t.Parallel()

	t.Run("the_cumulative_sequence", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, rec := gpuFitRuntime(t, 4*testGiB)

		// 1. The first GPU pod takes 3 GiB of the 4 GiB ceiling.
		first := gpuFitPod("first", 3*testGiB, true)
		if err := r.CreatePod(ctx, first); err != nil {
			t.Fatalf("CreatePod(first) = %v, want it admitted under an empty node's ceiling", err)
		}
		if _, creates := f.counts(); creates != 1 {
			t.Fatalf("CreatePod RPC calls = %d, want 1 — an admitted pod must reach runtimed", creates)
		}

		// 2. A second GPU pod wanting 1.5 GiB does NOT fit beside it: 3 + 1.5 > 4.
		//    The scheduler would have bound it (the node still advertises a free
		//    slot), so this refusal is the only thing standing between the two.
		second := gpuFitPod("second", 3*testGiB/2, true)
		err := r.CreatePod(ctx, second)
		if err == nil {
			t.Fatal("CreatePod(second) = nil, want a refusal — 3GiB + 1.5GiB does not fit a 4GiB ceiling")
		}
		if !errors.Is(err, mlx.ErrGPUMemoryOverCeiling) {
			t.Errorf("CreatePod error %v does not wrap mlx.ErrGPUMemoryOverCeiling; a caller cannot tell it from a transient failure", err)
		}
		if _, creates := f.counts(); creates != 1 {
			t.Errorf("CreatePod RPC calls = %d, want 1 — the refusal must land BEFORE the RPC", creates)
		}
		if r.trackByID(string(second.UID)) != nil {
			t.Error("the refused pod was tracked; it must leave no bookkeeping behind, or it would charge the next pod for memory it never got")
		}
		ev := findEvent(rec.Events, reasonFailedGPUFit)
		if ev == "" {
			t.Fatal("no FailedGPUFit Event recorded; on a headless Mac `kubectl describe pod` is the operator's only diagnostic surface")
		}
		if !strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonFailedGPUFit+" ") {
			t.Errorf("Event = %q, want a %s %s event", ev, corev1.EventTypeWarning, reasonFailedGPUFit)
		}
		// All three numbers and both ways out: the refusal is only actionable with
		// them, since the operator has to choose between shrinking this pod and
		// removing another.
		for _, want := range []string{"1536Mi", "3Gi", "4Gi", mlxv1alpha1.ResourceGPU, "memory limit"} {
			if !strings.Contains(ev, want) {
				t.Errorf("Event %q does not name %q", ev, want)
			}
		}

		// 3. A THIRD GPU pod that does fit in the remaining 1 GiB is admitted. The
		//    node is not "full" — it is full of this much.
		third := gpuFitPod("third", testGiB, true)
		if err := r.CreatePod(ctx, third); err != nil {
			t.Fatalf("CreatePod(third) = %v, want a 1GiB pod admitted into the 1GiB that is left", err)
		}
		if _, creates := f.counts(); creates != 2 {
			t.Errorf("CreatePod RPC calls = %d, want 2", creates)
		}

		// 4. DELETING the 3 GiB pod releases its share, with no counter to drift:
		//    the admitted total is derived from the track map on every check. The
		//    1.5 GiB pod refused in step 2 now fits beside the 1 GiB survivor.
		if err := r.DeletePod(ctx, first); err != nil {
			t.Fatalf("DeletePod(first) = %v", err)
		}
		if err := r.CreatePod(ctx, second); err != nil {
			t.Fatalf("CreatePod(second) after the delete = %v, want it admitted — a deletion must release GPU memory", err)
		}
	})

	// AN UNKNOWN CEILING ADMITS EVERYTHING. A node whose Metal working set could
	// not be read (and which carries no iogpu override) has no number to refuse
	// against; refusing there would make it unschedulable for every GPU pod, which
	// is strictly worse than the overcommit the check exists to prevent.
	t.Run("unknown_ceiling_admits", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, rec := gpuFitRuntime(t, 0)

		for _, name := range []string{"a", "b", "c"} {
			if err := r.CreatePod(ctx, gpuFitPod(name, 64*testGiB, true)); err != nil {
				t.Fatalf("CreatePod(%s) = %v, want it admitted against an unknown ceiling", name, err)
			}
		}
		if _, creates := f.counts(); creates != 3 {
			t.Errorf("CreatePod RPC calls = %d, want 3", creates)
		}
		if ev := findEvent(rec.Events, reasonFailedGPUFit); ev != "" {
			t.Errorf("recorded %q against an unknown ceiling, want no %s event", ev, reasonFailedGPUFit)
		}
	})

	// NON-GPU PODS ARE NEITHER COUNTED NOR CHECKED. They use the same unified
	// memory, but they are budgeted by the node's ordinary memory Allocatable;
	// charging them here would refuse GPU pods on account of workloads that never
	// touch the GPU, and checking them would refuse ordinary pods on a node whose
	// GPU happens to be busy.
	t.Run("non_gpu_pods_are_invisible_to_the_check", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, f, rec := gpuFitRuntime(t, 4*testGiB)

		// A large NON-GPU pod first: it must not consume the GPU budget.
		if err := r.CreatePod(ctx, gpuFitPod("bulk", 64*testGiB, false)); err != nil {
			t.Fatalf("CreatePod(bulk) = %v, want a non-GPU pod admitted whatever its memory limit", err)
		}
		// ...so a GPU pod sized to the whole ceiling still fits.
		if err := r.CreatePod(ctx, gpuFitPod("gpu", 4*testGiB, true)); err != nil {
			t.Fatalf("CreatePod(gpu) = %v, want the GPU pod admitted; a non-GPU pod must not consume GPU budget", err)
		}
		// ...and a second non-GPU pod is admitted beside a GPU-saturated node,
		// because the check never runs for it.
		if err := r.CreatePod(ctx, gpuFitPod("bulk2", 64*testGiB, false)); err != nil {
			t.Fatalf("CreatePod(bulk2) = %v, want a non-GPU pod admitted on a GPU-saturated node", err)
		}
		if _, creates := f.counts(); creates != 3 {
			t.Errorf("CreatePod RPC calls = %d, want 3", creates)
		}
		if ev := findEvent(rec.Events, reasonFailedGPUFit); ev != "" {
			t.Errorf("recorded %q, want no %s event", ev, reasonFailedGPUFit)
		}
	})

	// AN IDEMPOTENT RE-CREATE IS NOT A SECOND POD. VK re-sends a CreatePod for a
	// pod the provider already tracks; measuring it against its own previous entry
	// would refuse a pod that is already running, and the pod would then be marked
	// failed for the memory it currently holds.
	t.Run("idempotent_recreate_excludes_its_own_entry", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, _, _ := gpuFitRuntime(t, 4*testGiB)

		pod := gpuFitPod("solo", 3*testGiB, true)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod = %v", err)
		}
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod (repeat) = %v, want the same pod re-admitted; it must not be charged for its own memory twice", err)
		}
	})

	// A GPU POD WITH NO ENFORCEABLE MEMORY LIMIT contributes nothing and is
	// refused by nothing: podMemoryLimitBytes reports 0 for it, the provider has
	// no number to budget with, and substituting a guess would refuse pods against
	// a total nothing measured. It is admitted, and it does not squeeze the next
	// pod out either.
	t.Run("unlimited_gpu_pod_neither_refused_nor_counted", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, _, _ := gpuFitRuntime(t, 4*testGiB)

		unlimited := gpuFitPod("unlimited", 0, true)
		unlimited.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
			corev1.ResourceName(mlxv1alpha1.ResourceGPU): *resource.NewQuantity(1, resource.DecimalSI),
		}
		if err := r.CreatePod(ctx, unlimited); err != nil {
			t.Fatalf("CreatePod(unlimited) = %v, want it admitted", err)
		}
		if err := r.CreatePod(ctx, gpuFitPod("sized", 4*testGiB, true)); err != nil {
			t.Fatalf("CreatePod(sized) = %v, want the whole ceiling still available", err)
		}
	})
}

// TestAdmittedGPUMemoryLocked pins the summing rule the CreatePod check depends
// on, at the seam rather than through five more CreatePod rows: only tracked GPU
// pods count, and the pod being admitted never counts itself.
func TestAdmittedGPUMemoryLocked(t *testing.T) {
	t.Parallel()
	r, _, _ := gpuFitRuntime(t, 4*testGiB)

	for _, p := range []*corev1.Pod{
		gpuFitPod("gpu-a", 2*testGiB, true),
		gpuFitPod("gpu-b", testGiB, true),
		gpuFitPod("plain", 32*testGiB, false),
	} {
		r.mu.Lock()
		r.track[string(p.UID)] = &podTrack{pod: p}
		r.mu.Unlock()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if got, want := r.admittedGPUMemoryLocked(""), 3*testGiB; got != want {
		t.Errorf("admittedGPUMemoryLocked(\"\") = %d, want %d — only the two GPU pods count", got, want)
	}
	if got, want := r.admittedGPUMemoryLocked("uid-gpu-a"), testGiB; got != want {
		t.Errorf("admittedGPUMemoryLocked(excluding gpu-a) = %d, want %d", got, want)
	}
	if got, want := r.admittedGPUMemoryLocked("uid-plain"), 3*testGiB; got != want {
		t.Errorf("excluding a NON-GPU pod changed the total: %d, want %d", got, want)
	}
}
