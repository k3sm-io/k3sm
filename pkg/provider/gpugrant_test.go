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

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/gpucapacity"
)

// TestGPUGrantUnderEitherName is the gate for the provider's read of a pod's GPU
// request while the resource has two names. A pod's spec is immutable and an
// install recreates native pods from it, so a reader that knew one name would run
// a pod asking for the other with allow_gpu false: a Metal failure inside a pod
// that looks healthy. So the assertion is the profile that reaches the runtime, on
// a real CreatePod, not the helper's answer.
func TestGPUGrantUnderEitherName(t *testing.T) {
	t.Parallel()

	const (
		oldName = corev1.ResourceName(mlxv1alpha1.ResourceGPU)
		newName = corev1.ResourceName(runtimev1.ResourceGPU)
	)
	one, zero := resource.MustParse("1"), resource.MustParse("0")

	t.Run("allow_gpu_at_the_runtime", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name             string
			limits, requests corev1.ResourceList
			// initLimits and sidecarLimits land on a container of their own.
			initLimits, sidecarLimits corev1.ResourceList
			want                      bool
		}{
			{name: "old_name_only", limits: corev1.ResourceList{oldName: one}, want: true},
			{name: "new_name_only", limits: corev1.ResourceList{newName: one}, want: true},
			{name: "both_names_on_one_container", limits: corev1.ResourceList{oldName: one, newName: one}, want: true},
			{name: "neither_name"},

			// A zero is no ask under its own name, and must not hide the other's.
			{name: "old_name_zero", limits: corev1.ResourceList{oldName: zero}},
			{name: "new_name_zero", limits: corev1.ResourceList{newName: zero}},
			{name: "both_names_zero", limits: corev1.ResourceList{oldName: zero, newName: zero}},
			{name: "old_zero_beside_new_one", limits: corev1.ResourceList{oldName: zero, newName: one}, want: true},
			{name: "new_zero_beside_old_one", limits: corev1.ResourceList{newName: zero, oldName: one}, want: true},

			// Limits decide under either name; requests never grant.
			{name: "old_name_requests_only", requests: corev1.ResourceList{oldName: one}},
			{name: "new_name_requests_only", requests: corev1.ResourceList{newName: one}},
			{name: "both_names_requests_only", requests: corev1.ResourceList{oldName: one, newName: one}},
			{
				name:     "old_name_requests_and_limits",
				limits:   corev1.ResourceList{oldName: one},
				requests: corev1.ResourceList{oldName: one},
				want:     true,
			},
			{
				name:     "new_name_requests_and_limits",
				limits:   corev1.ResourceList{newName: one},
				requests: corev1.ResourceList{newName: one},
				want:     true,
			},
			{
				name:     "new_name_request_beside_old_name_limit",
				limits:   corev1.ResourceList{oldName: one},
				requests: corev1.ResourceList{newName: one},
				want:     true,
			},
			{
				name:     "new_name_request_over_a_zero_limit",
				limits:   corev1.ResourceList{newName: zero},
				requests: corev1.ResourceList{newName: one},
			},

			// Every container is read for both names.
			{name: "new_name_on_an_init_container", initLimits: corev1.ResourceList{newName: one}, want: true},
			{name: "old_name_on_an_init_container", initLimits: corev1.ResourceList{oldName: one}, want: true},
			{name: "new_name_on_a_second_container", sidecarLimits: corev1.ResourceList{newName: one}, want: true},
			{
				name:          "each_name_on_its_own_container",
				limits:        corev1.ResourceList{oldName: one},
				sidecarLimits: corev1.ResourceList{newName: one},
				want:          true,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				r, f, _ := gpuFitRuntime(t, 4*testGiB)
				pod := gpuFitPod("grant", testGiB, false)
				c := &pod.Spec.Containers[0]
				c.Resources.Requests = tc.requests
				for k, v := range tc.limits {
					c.Resources.Limits[k] = v
				}
				if tc.sidecarLimits != nil {
					limits := tc.sidecarLimits.DeepCopy()
					limits[corev1.ResourceMemory] = *resource.NewQuantity(testGiB, resource.BinarySI)
					pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
						Name: "c1", Image: c.Image, Command: c.Command,
						Resources: corev1.ResourceRequirements{Limits: limits},
					})
				}
				if tc.initLimits != nil {
					pod.Spec.InitContainers = []corev1.Container{{
						Name: "init", Image: c.Image, Command: c.Command,
						Resources: corev1.ResourceRequirements{Limits: tc.initLimits},
					}}
				}

				if err := r.CreatePod(context.Background(), pod); err != nil {
					t.Fatalf("CreatePod = %v", err)
				}
				// A box that never arrived would read false through the nil-safe
				// getters and pass every row that wants no grant.
				f.fakeRuntimeServer.mu.Lock()
				box, ok := f.created[string(pod.UID)]
				f.fakeRuntimeServer.mu.Unlock()
				if !ok {
					t.Fatal("the pod never reached the runtime")
				}
				if got := box.GetSandboxProfile().GetAllowGpu(); got != tc.want {
					t.Errorf("allow_gpu at the runtime = %v, want %v", got, tc.want)
				}
			})
		}
	})

	// The fit decides from the same read, so the new name cannot be an escape from
	// the refusal of a pod no budget can measure, and the Event names the resource
	// the pod actually asked for.
	t.Run("unbounded_refusal_names_what_the_pod_asked_for", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name      string
			limits    corev1.ResourceList
			want, not corev1.ResourceName
		}{
			{name: "old_name", limits: corev1.ResourceList{oldName: one}, want: oldName, not: newName},
			{name: "new_name", limits: corev1.ResourceList{newName: one}, want: newName, not: oldName},
			{name: "both_names", limits: corev1.ResourceList{oldName: one, newName: one}, want: newName, not: oldName},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				r, f, rec := gpuFitRuntime(t, 4*testGiB)
				pod := gpuFitPod("unbounded", 0, false)
				pod.Spec.Containers[0].Resources.Limits = tc.limits

				err := r.CreatePod(context.Background(), pod)
				if !errors.Is(err, gpucapacity.ErrGPUMemoryUnbounded) {
					t.Fatalf("CreatePod = %v, want gpucapacity.ErrGPUMemoryUnbounded", err)
				}
				if _, creates := f.counts(); creates != 0 {
					t.Errorf("CreatePod RPC calls = %d, want 0", creates)
				}
				ev := findEvent(rec.Events, reasonFailedGPUFit)
				if !strings.Contains(ev, "requests "+string(tc.want)+" ") {
					t.Errorf("Event %q does not name %q as the pod's request", ev, tc.want)
				}
				// "k3sm.io/gpu" is a substring of "mlx.k3sm.io/gpu", so the absence
				// check keeps the same "requests " anchor.
				if strings.Contains(ev, "requests "+string(tc.not)+" ") {
					t.Errorf("Event %q names %q, which this row did not ask under", ev, tc.not)
				}
			})
		}
	})

	// One grant, and its memory counted once, against a total shared by both names.
	t.Run("memory_counted_once_across_both_names", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		r, _, rec := gpuFitRuntime(t, 4*testGiB)

		both := gpuFitPod("both", 3*testGiB, true)
		both.Spec.Containers[0].Resources.Limits[newName] = one
		if err := r.CreatePod(ctx, both); err != nil {
			t.Fatalf("CreatePod(both) = %v", err)
		}
		r.mu.Lock()
		admitted := r.admittedGPUMemoryLocked("")
		r.mu.Unlock()
		if admitted != 3*testGiB {
			t.Errorf("admitted = %d, want %d: a pod naming both is one pod", admitted, 3*testGiB)
		}

		// A new-name pod is fit beside it, so neither name is a separate budget.
		over := gpuFitPod("over", 2*testGiB, false)
		over.Spec.Containers[0].Resources.Limits[newName] = one
		if err := r.CreatePod(ctx, over); !errors.Is(err, gpucapacity.ErrGPUMemoryOverCeiling) {
			t.Fatalf("CreatePod(over) = %v, want gpucapacity.ErrGPUMemoryOverCeiling", err)
		}
		// The holder may be under either name, so the way out names both.
		ev := findEvent(rec.Events, reasonFailedGPUFit)
		for _, want := range []corev1.ResourceName{oldName, newName} {
			if !strings.Contains(ev, " "+string(want)) {
				t.Errorf("Event %q does not name %q", ev, want)
			}
		}

		// Both names counted twice would leave no room for this one.
		fits := gpuFitPod("fits", testGiB, false)
		fits.Spec.Containers[0].Resources.Limits[newName] = one
		if err := r.CreatePod(ctx, fits); err != nil {
			t.Fatalf("CreatePod(fits) = %v, want it admitted at exactly the ceiling", err)
		}
	})
}
