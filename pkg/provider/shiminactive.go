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
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// observeShimInactive turns runtimed's k3sm.io/shim-inactive pod condition
// into ONE Warning ShimInactive Event on the pod per condition reason.
//
// runtimed reads the main process's code-signing flags from the kernel right
// after the exec-shim execs it; a platform, CS_RESTRICT or hardened-runtime
// process had DYLD_INSERT_LIBRARIES dropped by dyld, so the pod shim (DNS
// precedence, single-label names, the bind/connect source discipline) is not
// loaded in it. runtimed has no API client, so the condition is the channel and
// the node records the Event. The condition's message already names both
// losses and the container, so it is the Event message, with control
// characters removed (it carries the container's own path, which is pod-spec
// text, and the Event is namespace-readable).
//
// It runs on buildStatus, the convergence point of every status path, and is
// idempotent per pod and reason: shimWarned remembers what was recorded, so a
// condition present on every resync tick fires once, and a second reason (a
// hardened-runtime container joining a restricted one) fires its own Event.
// The Event is recorded after shimMu is released.
func (r *runtimedRuntime) observeShimInactive(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus) {
	type warning struct{ reason, message string }
	var fire []warning
	t.shimMu.Lock()
	for _, c := range rs.GetConditions() {
		if c.GetType() != runtimed.ShimInactiveConditionType ||
			c.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_TRUE {
			continue
		}
		if t.shimWarned[c.GetReason()] {
			continue
		}
		if t.shimWarned == nil {
			t.shimWarned = map[string]bool{}
		}
		t.shimWarned[c.GetReason()] = true
		fire = append(fire, warning{reason: c.GetReason(), message: stripControl(c.GetMessage())})
	}
	t.shimMu.Unlock()
	for _, w := range fire {
		r.log.Warn("pod shim inactive: a restricted main process dropped DYLD_INSERT_LIBRARIES",
			"namespace", pod.Namespace, "name", pod.Name, "reason", w.reason)
		r.recorder.Event(pod, corev1.EventTypeWarning, reasonShimInactive, w.message)
	}
}

// stripControl drops every control character from s.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
