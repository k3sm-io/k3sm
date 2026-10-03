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
	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// resolveRunAsNonRoot applies the producer rule the apis runtime.proto states on
// PodSecurityContext.run_as_non_root to an already-translated box. It runs after
// every container list (init, regular, ephemeral) has been translated, because
// the rule is a property of the whole pod.
//
// The kubelet resolves runAsNonRoot per container (DetermineEffectiveSecurityContext):
// the container's own value wins when it is set, otherwise the pod's applies. The
// wire cannot say that directly: a consumer composes the two by logical OR, and a
// proto3 bool has no presence, so a container's explicit false could never
// override a pod-level true. The producer rule closes the gap:
//
//   - whenever the pod sets a value, every container's EFFECTIVE value (its own
//     when non-nil, else the pod's) is stamped into its SecurityContext,
//     materializing the message when the container set none;
//   - PodSecurityContext.run_as_non_root carries the pod value, except that it is
//     sent false when an init or regular container explicitly opts out, so the
//     OR cannot re-impose the requirement on that container. The siblings still
//     carry true through their own stamps.
//
// Ephemeral containers are stamped against the POD SPEC's value like any other
// container, never against the derived PodSecurityContext field, which an
// opted-out sibling may have lowered to false. They never lower that field
// themselves: an ephemeral container is appended mid-life, and a pod-level box
// field must not change after create. The consequence is deliberate and fails
// closed: an ephemeral container that opts out under a pod-level true is still
// enforced, because the consumer ORs its false with the pod's true (runtimed
// composes against the create-time box regardless).
//
// A pod that sets no value is left alone: each container carries only what it
// set itself (toSecurityContext), and a container that set nothing keeps a nil
// SecurityContext, which a consumer reads as "inherit the pod defaults".
//
// Containers are paired with their spec by name, which the apiserver keeps unique
// across all three lists. A box container with no spec counterpart is stamped
// with the pod value: fail closed rather than leave it unresolved.
func resolveRunAsNonRoot(pod *corev1.Pod, box *runtimev1.PodBox) {
	var podValue *bool
	if psc := pod.Spec.SecurityContext; psc != nil {
		podValue = psc.RunAsNonRoot
	}
	if podValue == nil {
		return
	}

	own := make(map[string]*bool, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		own[c.Name] = containerRunAsNonRoot(c.SecurityContext)
	}
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		own[c.Name] = containerRunAsNonRoot(c.SecurityContext)
	}
	for i := range pod.Spec.EphemeralContainers {
		c := &pod.Spec.EphemeralContainers[i]
		own[c.Name] = containerRunAsNonRoot(c.SecurityContext)
	}

	optedOut := false
	stamp := func(list []*runtimev1.Container, lowersPod bool) {
		for _, rc := range list {
			effective := *podValue
			if v := own[rc.GetName()]; v != nil {
				effective = *v
				if !*v && lowersPod {
					optedOut = true
				}
			}
			if rc.SecurityContext == nil {
				rc.SecurityContext = &runtimev1.SecurityContext{}
			}
			rc.SecurityContext.RunAsNonRoot = effective
		}
	}
	stamp(box.GetInitContainers(), true)
	stamp(box.GetContainers(), true)
	stamp(box.GetEphemeralContainers(), false)

	if box.PodSecurityContext == nil {
		box.PodSecurityContext = &runtimev1.PodSecurityContext{}
	}
	box.PodSecurityContext.RunAsNonRoot = *podValue && !optedOut
}

// containerRunAsNonRoot returns a container's own runAsNonRoot, or nil when its
// securityContext does not set one.
func containerRunAsNonRoot(sc *corev1.SecurityContext) *bool {
	if sc == nil {
		return nil
	}
	return sc.RunAsNonRoot
}
