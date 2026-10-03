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
	apiequality "k8s.io/apimachinery/pkg/api/equality"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Ephemeral (debug) containers: corev1.PodSpec.EphemeralContainers, the
// `kubectl debug` surface.
//
// The apiserver appends them through the pods/ephemeralcontainers subresource;
// virtual-kubelet sees the grown spec and calls UpdatePod, which forwards the
// rebuilt box to runtimed. runtimed starts each appended entry once, under the
// pod's own profile, and reports it under ephemeral_container_statuses.
//
// Two shapes are refused on this side, and their refusal is DERIVED from the pod
// on every status build rather than stored, so a provider restart, a status
// replace, or a second UpdatePod can never lose or duplicate it:
//
//   - an entry that sets targetContainerName is never sent: a Darwin process has
//     no process namespace another process can join, and dropping the field
//     would silently run a debugger that cannot see the target;
//   - every entry of a vm pod: guest/v1 has no verb to start a container in a
//     booted guest. The entry is not sent either. runtimed would answer
//     FAILURE_REASON_UNSUPPORTED and keep no record of it, so a box that kept
//     listing the entry would draw the same refusal on every later update of
//     the pod and its label and annotation changes would never apply.
//
// Both render the kubelet's CreateContainerConfigError, the reason it gives a
// container whose configuration cannot be generated. A status the runtime does
// report for a name always wins over the derived one, and an entry that is
// neither reported nor refused reads Waiting ContainerCreating, the kubelet's
// shape before a container starts, so no spec entry is ever missing a status.

// msgEphemeralTargetUnsupported is the waiting message of an ephemeral container
// that sets targetContainerName.
const msgEphemeralTargetUnsupported = "k3sm: targetContainerName is not supported (Darwin processes have no shared process namespace to join); re-run kubectl debug without --target"

// msgEphemeralOnVM is the waiting message of an ephemeral container on a vm pod.
// It is runtimed's errEphemeralOnVM text, kept identical so the status, the
// Event and the daemon log read the same.
const msgEphemeralOnVM = "ephemeral containers are not supported on the vm RuntimeClass"

// toRuntimeEphemeralContainers translates the ephemeral containers runtimed is
// asked to start, through the same path as every other container. Every entry
// the node refuses (ephemeralRejections: a targetContainerName, or any entry of
// a vm pod) is left out. The fields upstream forbids on an ephemeral container
// (ports, probes, resources, lifecycle) are rejected by apiserver validation,
// and restartPolicy is never mapped for a non-init container, so nothing the
// proto forbids is produced.
func toRuntimeEphemeralContainers(pod *corev1.Pod) []*runtimev1.Container {
	ecs := pod.Spec.EphemeralContainers
	refused := map[string]bool{}
	for _, rej := range ephemeralRejections(pod) {
		refused[rej.name] = true
	}
	cs := make([]corev1.Container, 0, len(ecs))
	for i := range ecs {
		if refused[ecs[i].Name] {
			continue
		}
		// EphemeralContainerCommon mirrors corev1.Container field for field,
		// which is what makes this a conversion rather than a copy.
		cs = append(cs, corev1.Container(ecs[i].EphemeralContainerCommon))
	}
	return toRuntimeContainers(cs, false)
}

// ephemeralRejection is one ephemeral container this node will not start, with
// the message its status and Event carry.
type ephemeralRejection struct {
	name    string
	image   string
	message string
}

// ephemeralRejections returns the ephemeral containers of pod the node refuses,
// in spec order. A pod whose RuntimeClass does not resolve is not judged here:
// toPodBox refuses it outright.
func ephemeralRejections(pod *corev1.Pod) []ephemeralRejection {
	if pod == nil || len(pod.Spec.EphemeralContainers) == 0 {
		return nil
	}
	backend, err := podSandboxBackend(pod)
	vm := err == nil && backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM
	var out []ephemeralRejection
	for i := range pod.Spec.EphemeralContainers {
		ec := &pod.Spec.EphemeralContainers[i]
		switch {
		case ec.TargetContainerName != "":
			out = append(out, ephemeralRejection{ec.Name, ec.Image, msgEphemeralTargetUnsupported})
		case vm:
			out = append(out, ephemeralRejection{ec.Name, ec.Image, msgEphemeralOnVM})
		}
	}
	return out
}

// mergeEphemeralStatuses returns the pod's ephemeral container statuses: what the
// runtime reported, then, in spec order, an entry for every spec ephemeral
// container the runtime does not report. A refused one reads Waiting
// CreateContainerConfigError with its message; any other reads Waiting
// ContainerCreating (not started yet, or refused by runtimed for a cause the
// provider does not derive, which its Event explains). The runtime's entry wins
// for its name.
func mergeEphemeralStatuses(reported []corev1.ContainerStatus, pod *corev1.Pod) []corev1.ContainerStatus {
	if pod == nil || len(pod.Spec.EphemeralContainers) == 0 {
		return reported
	}
	refused := map[string]string{}
	for _, rej := range ephemeralRejections(pod) {
		refused[rej.name] = rej.message
	}
	seen := make(map[string]bool, len(reported))
	for i := range reported {
		seen[reported[i].Name] = true
	}
	out := reported
	for i := range pod.Spec.EphemeralContainers {
		ec := &pod.Spec.EphemeralContainers[i]
		if seen[ec.Name] {
			continue
		}
		waiting := &corev1.ContainerStateWaiting{Reason: reasonContainerCreating}
		if msg, ok := refused[ec.Name]; ok {
			waiting = &corev1.ContainerStateWaiting{Reason: reasonCreateContainerConfigError, Message: msg}
		}
		out = append(out, corev1.ContainerStatus{
			Name:    ec.Name,
			Image:   ec.Image,
			State:   corev1.ContainerState{Waiting: waiting},
			Started: ptr(false),
		})
	}
	return out
}

// ephemeralOnlyDelta reports whether the only spec change from previous to pod
// is ephemeral containers appended. Such an update has nothing else for runtimed
// to refuse, so any refusal concerns the append alone.
func ephemeralOnlyDelta(previous, pod *corev1.Pod) bool {
	if previous == nil || pod == nil || len(pod.Spec.EphemeralContainers) <= len(previous.Spec.EphemeralContainers) {
		return false
	}
	before, after := previous.Spec.DeepCopy(), pod.Spec.DeepCopy()
	before.EphemeralContainers, after.EphemeralContainers = nil, nil
	return apiequality.Semantic.DeepEqual(before, after)
}

// appendedEphemeralNames returns the names of the ephemeral containers pod lists
// that previous did not. A nil previous makes every entry new.
func appendedEphemeralNames(previous, pod *corev1.Pod) map[string]bool {
	had := map[string]bool{}
	if previous != nil {
		for i := range previous.Spec.EphemeralContainers {
			had[previous.Spec.EphemeralContainers[i].Name] = true
		}
	}
	out := map[string]bool{}
	for i := range pod.Spec.EphemeralContainers {
		if name := pod.Spec.EphemeralContainers[i].Name; !had[name] {
			out[name] = true
		}
	}
	return out
}

// recordEphemeralRejections records the kubelet's Failed Event for each newly
// appended ephemeral container this node refuses. It runs on the UpdatePod that
// carried the append, which is the one point that sees each append exactly once,
// so the status path needs no dedupe state. A provider restart may replay one.
//
// refusal, when non-empty, is runtimed's message for an append it refused for a
// cause the provider does not derive; it is recorded against every newly
// appended container that has no derived rejection, so the refusal is visible.
func (r *runtimedRuntime) recordEphemeralRejections(previous, pod *corev1.Pod, refusal string) {
	appended := appendedEphemeralNames(previous, pod)
	if len(appended) == 0 {
		return
	}
	id := string(pod.UID)
	derived := map[string]bool{}
	for _, rej := range ephemeralRejections(pod) {
		derived[rej.name] = true
		if appended[rej.name] {
			r.recordPodEvent(id, podEvent{corev1.EventTypeWarning, reasonFailed, msgContainerConfigError(rej.message)})
		}
	}
	if refusal == "" {
		return
	}
	for i := range pod.Spec.EphemeralContainers {
		name := pod.Spec.EphemeralContainers[i].Name
		if appended[name] && !derived[name] {
			r.recordPodEvent(id, podEvent{corev1.EventTypeWarning, reasonFailed, msgContainerConfigError(refusal)})
		}
	}
}
