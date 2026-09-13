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

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/podlogs"
)

// applyTerminationMessageOverlay fills in `terminationMessagePolicy:
// FallbackToLogsOnError` from the terminated instance's own log file.
//
// It is computed HERE, node-side, because that is where upstream computes it and
// because it is the only place that can: the policy lives in the pod SPEC (which
// runtimed never sees in corev1 form) and the message comes from a log FILE
// (which runtimed writes but never reads). The result is the last 80 lines of the
// instance's output, truncated to a 2048-byte TAIL — so `kubectl describe pod` on
// a crashed container shows what it printed on the way out without the image
// having to write a message file.
//
// It applies only to a container that TERMINATED NON-ZERO with no message of its
// own, so a container that wrote its own terminationMessagePath is never
// overwritten, and an image that could not start at all (ContainerCannotRun) keeps
// its real reason instead of an empty string read from a log that does not exist.
func (r *runtimedRuntime) applyTerminationMessageOverlay(pod *corev1.Pod, rs *runtimev1.PodStatus, st *corev1.PodStatus) {
	if rs == nil || st == nil {
		return
	}
	policies := terminationMessagePolicies(pod)
	runtimeByName := map[string]*runtimev1.ContainerStatus{}
	for _, cs := range rs.GetContainerStatuses() {
		runtimeByName[cs.GetName()] = cs
	}
	for _, cs := range rs.GetInitContainerStatuses() {
		runtimeByName[cs.GetName()] = cs
	}
	apply := func(statuses []corev1.ContainerStatus) {
		for i := range statuses {
			term := statuses[i].State.Terminated
			if term == nil {
				continue
			}
			if !podlogs.ShouldFallbackToLogs(policies[statuses[i].Name], term.ExitCode, term.Reason, term.Message) {
				continue
			}
			rcs, ok := runtimeByName[statuses[i].Name]
			if !ok {
				continue
			}
			path := rcs.GetState().GetTerminated().GetLogPath()
			if path == "" {
				path = rcs.GetLogPath()
			}
			if path == "" {
				continue
			}
			// context.Background, and honestly so: this is a bounded read of a
			// local file with Follow unset, so the reader never reaches a
			// cancellation point. buildStatus carries no context, and inventing
			// one that is never consulted would be worse than saying why.
			if msg := podlogs.TerminationMessageFromLogs(context.Background(), path, r.log); msg != "" {
				statuses[i].State.Terminated.Message = msg
			}
		}
	}
	apply(st.ContainerStatuses)
	apply(st.InitContainerStatuses)
	apply(st.EphemeralContainerStatuses)
}

// terminationMessagePolicies indexes a pod's per-container
// terminationMessagePolicy by container name, across all three container lists.
func terminationMessagePolicies(pod *corev1.Pod) map[string]corev1.TerminationMessagePolicy {
	out := map[string]corev1.TerminationMessagePolicy{}
	if pod == nil {
		return out
	}
	for _, c := range pod.Spec.Containers {
		out[c.Name] = c.TerminationMessagePolicy
	}
	for _, c := range pod.Spec.InitContainers {
		out[c.Name] = c.TerminationMessagePolicy
	}
	for _, c := range pod.Spec.EphemeralContainers {
		out[c.Name] = c.TerminationMessagePolicy
	}
	return out
}
