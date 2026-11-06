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

package gpucapacity

import (
	"errors"
	"math"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	oldName = corev1.ResourceName(mlxv1alpha1.ResourceGPU)
	newName = corev1.ResourceName(runtimev1.ResourceGPU)
)

func limit(gpu corev1.ResourceName, units int64) corev1.ResourceRequirements {
	return corev1.ResourceRequirements{Limits: corev1.ResourceList{gpu: *resource.NewQuantity(units, resource.DecimalSI)}}
}

func request(gpu corev1.ResourceName, units int64) corev1.ResourceRequirements {
	return corev1.ResourceRequirements{Requests: corev1.ResourceList{gpu: *resource.NewQuantity(units, resource.DecimalSI)}}
}

// TestPodUnitsSchedulerRule pins the scheduler's arithmetic under each name: a pod
// asking under only one name counts exactly what that name alone would.
func TestPodUnitsSchedulerRule(t *testing.T) {
	t.Parallel()
	sidecar := corev1.ContainerRestartPolicyAlways
	for _, gpu := range []corev1.ResourceName{oldName, newName} {
		cases := []struct {
			name string
			spec corev1.PodSpec
			want int64
		}{
			{name: "app_containers_add", spec: corev1.PodSpec{Containers: []corev1.Container{
				{Resources: limit(gpu, 1)}, {Resources: limit(gpu, 1)},
			}}, want: 2},
			{name: "init_container_runs_alone", spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Resources: limit(gpu, 2)}},
				Containers:     []corev1.Container{{Resources: limit(gpu, 1)}},
			}, want: 2},
			{name: "sidecar_runs_with_the_app", spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Resources: limit(gpu, 1), RestartPolicy: &sidecar}},
				Containers:     []corev1.Container{{Resources: limit(gpu, 1)}},
			}, want: 2},
			{name: "request_counts_when_no_limit", spec: corev1.PodSpec{Containers: []corev1.Container{
				{Resources: request(gpu, 1)},
			}}, want: 1},
			{name: "a_total_past_int64_saturates", spec: corev1.PodSpec{Containers: []corev1.Container{
				{Resources: limit(gpu, math.MaxInt64)}, {Resources: limit(gpu, 1)},
			}}, want: math.MaxInt64},
		}
		for _, tc := range cases {
			t.Run(string(gpu)+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				if got := PodUnits(&corev1.Pod{Spec: tc.spec}); got != tc.want {
					t.Errorf("PodUnits = %d, want %d", got, tc.want)
				}
			})
		}
	}
}

// TestGrantResourceReadsLimitsOnly pins the split between the count and the grant:
// PodUnits answers for a requests-only pod and GrantResource does not.
func TestGrantResourceReadsLimitsOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		res       corev1.ResourceRequirements
		wantGrant corev1.ResourceName
		wantUnits int64
		wantNew   bool
	}{
		{name: "old_limit", res: limit(oldName, 1), wantGrant: oldName, wantUnits: 1},
		{name: "new_limit", res: limit(newName, 1), wantGrant: newName, wantUnits: 1, wantNew: true},
		{name: "old_request", res: request(oldName, 1), wantUnits: 1},
		{name: "new_request", res: request(newName, 1), wantUnits: 1, wantNew: true},
		{name: "neither"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Resources: tc.res}}}}
			if got := GrantResource(pod); got != tc.wantGrant {
				t.Errorf("GrantResource = %q, want %q", got, tc.wantGrant)
			}
			if got := PodUnits(pod); got != tc.wantUnits {
				t.Errorf("PodUnits = %d, want %d", got, tc.wantUnits)
			}
			if got := PodNamesRenamedResource(pod); got != tc.wantNew {
				t.Errorf("PodNamesRenamedResource = %v, want %v", got, tc.wantNew)
			}
		})
	}
}

func TestGPUSlotsFit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		slots, held, want int64
		fits              bool
	}{
		{slots: 1, held: 0, want: 1, fits: true},
		{slots: 2, held: 1, want: 1, fits: true},
		{slots: 1, held: 1, want: 1},
		{slots: 2, held: 2, want: 1},
		{slots: 1, held: 0, want: 2},
		{slots: 2, held: math.MaxInt64, want: 1},
		{slots: 2, held: 0, want: math.MaxInt64},
	}
	for _, tc := range cases {
		t.Run(strconv.FormatInt(tc.held, 10)+"_held_"+strconv.FormatInt(tc.want, 10)+"_wanted_of_"+strconv.FormatInt(tc.slots, 10), func(t *testing.T) {
			t.Parallel()
			err := GPUSlotsFit(tc.slots, tc.held, tc.want)
			if tc.fits && err != nil {
				t.Errorf("GPUSlotsFit = %v, want nil", err)
			}
			if !tc.fits && !errors.Is(err, ErrGPUSlotsFull) {
				t.Errorf("GPUSlotsFit = %v, want ErrGPUSlotsFull", err)
			}
		})
	}
}
