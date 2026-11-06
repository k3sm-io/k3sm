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
	"fmt"
	"math"

	corev1 "k8s.io/api/core/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// units.go is the read of a pod's GPU ask while the resource has two names.
//
// There are two reads on purpose, and they answer different questions.
// GrantResource decides whether the sandbox gets GPU access and reads limits
// only. PodUnits counts what the scheduler counts, so it falls back to requests.
// Granting from PodUnits would hand the GPU to a requests-only pod.

// resourceNames are the two names a pod can ask for the GPU under, in the order
// GrantResource prefers them: runtimev1.ResourceGPU, then the engine-named
// mlxv1alpha1.ResourceGPU it replaces. A running pod's spec is immutable and an
// install recreates native pods from it, so the old name stays readable for as long
// as a pod can carry it.
var resourceNames = [...]corev1.ResourceName{
	corev1.ResourceName(runtimev1.ResourceGPU),
	corev1.ResourceName(mlxv1alpha1.ResourceGPU),
}

// ErrGPUSlotsFull is the sentinel for a GPU pod refused because the units held under
// either name plus its own would pass the node's slot count. It is errors.Is-able
// for the same reason ErrGPUMemoryOverCeiling is: another pod's deletion fixes it.
var ErrGPUSlotsFull = errors.New("pod does not fit in the node's GPU slots beside the pods already admitted")

// GrantResource returns the name the pod asks for the GPU under, or "" when it
// does not ask: the first of the two names with a nonzero quantity in a
// container's limits, not requests. That matches how podMemoryLimitBytes and
// effectiveResource already treat limits as the authoritative ceiling; a
// requests-only GPU ask is not a grant. Checked across init and regular containers:
// an init container that needs GPU access (e.g. a model-fetch step) is as real a
// request as a regular one. A pod naming both gets the first name back, so it holds
// one grant, not one per name.
func GrantResource(pod *corev1.Pod) corev1.ResourceName {
	for _, gpu := range resourceNames {
		for i := range pod.Spec.InitContainers {
			if q, ok := pod.Spec.InitContainers[i].Resources.Limits[gpu]; ok && !q.IsZero() {
				return gpu
			}
		}
		for i := range pod.Spec.Containers {
			if q, ok := pod.Spec.Containers[i].Resources.Limits[gpu]; ok && !q.IsZero() {
				return gpu
			}
		}
	}
	return ""
}

// PodUnits is how many GPU slots the pod holds, under either name, by the
// scheduler's rule: the app containers plus the restartable (sidecar) init
// containers run together, and each ordinary init container runs alone, so the pod
// needs the larger of the two. A container's limit is read first, since an extended
// resource's request defaults to (and must equal) its limit.
//
// A pod naming both resources holds the larger of its two counts, not their sum:
// it gets one grant, so it holds one set of units. The scheduler itself sees one of
// each.
//
// This is a count, not a grant, and it falls back to requests. Whether the sandbox
// gets the GPU is GrantResource's answer.
func PodUnits(pod *corev1.Pod) int64 {
	var most int64
	for _, gpu := range resourceNames {
		most = max(most, unitsUnder(pod, gpu))
	}
	return most
}

// unitsUnder is the pod's effective request under one name; see PodUnits for the
// rule. The sum saturates, because a wrapped negative would read as holding nothing.
func unitsUnder(pod *corev1.Pod, gpu corev1.ResourceName) int64 {
	units := func(c *corev1.Container) int64 {
		if q, ok := c.Resources.Limits[gpu]; ok {
			return q.Value()
		}
		q := c.Resources.Requests[gpu]
		return q.Value()
	}
	var running, initPeak int64
	for i := range pod.Spec.Containers {
		running = AddUnits(running, units(&pod.Spec.Containers[i]))
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			running = AddUnits(running, units(c))
			continue
		}
		initPeak = max(initPeak, units(c))
	}
	return max(running, initPeak)
}

// AddUnits sums two unit counts, saturating rather than wrapping: a spec is
// validated for shape and not for sanity, and a wrapped total is negative, which
// turns every later comparison into a pass.
func AddUnits(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

// GPUSlotsFit reports whether a pod wanting want units still fits under slots
// beside held units of the pods already admitted, returning nil when it does and an
// ErrGPUSlotsFull-wrapping error naming all three numbers when it does not.
//
// It is written as want <= slots-held so a saturated held total cannot overflow
// into a pass.
func GPUSlotsFit(slots, held, want int64) error {
	if want <= slots-held {
		return nil
	}
	return fmt.Errorf("%w: want %d beside %d held, slots %d", ErrGPUSlotsFull, want, held, slots)
}
