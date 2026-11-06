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
