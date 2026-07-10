//go:build e2e

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

package e2e

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestTerminalPhase(t *testing.T) {
	for _, tc := range []struct {
		phase corev1.PodPhase
		want  bool
	}{
		{corev1.PodSucceeded, true},
		{corev1.PodFailed, true},
		{corev1.PodRunning, false},
		{corev1.PodPending, false},
		{corev1.PodUnknown, false},
	} {
		if got := terminalPhase(tc.phase); got != tc.want {
			t.Errorf("terminalPhase(%s) = %v, want %v", tc.phase, got, tc.want)
		}
	}
}

// TestPodFailureDetail proves the diagnostic extraction the fail-fast path relies on:
// a crashed native pod's exit code / reason must surface in the failure message
// (the kubelet-proxied logs subresource is unreliable for such pods).
func TestPodFailureDetail(t *testing.T) {
	terminated := &corev1.Pod{Status: corev1.PodStatus{
		Phase: corev1.PodFailed,
		ContainerStatuses: []corev1.ContainerStatus{{
			Name:  "app",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}},
		}},
	}}
	got := podFailureDetail(terminated)
	for _, want := range []string{"phase=Failed", `container "app" terminated`, "exitCode=1", `reason="Error"`} {
		if !strings.Contains(got, want) {
			t.Errorf("podFailureDetail terminated: %q missing %q", got, want)
		}
	}

	waiting := &corev1.Pod{Status: corev1.PodStatus{
		Phase: corev1.PodPending,
		ContainerStatuses: []corev1.ContainerStatus{{
			Name:  "app",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CreateContainerError", Message: "seatbelt exec denied"}},
		}},
	}}
	got = podFailureDetail(waiting)
	for _, want := range []string{"phase=Pending", `reason="CreateContainerError"`, "seatbelt exec denied"} {
		if !strings.Contains(got, want) {
			t.Errorf("podFailureDetail waiting: %q missing %q", got, want)
		}
	}

	if got := podFailureDetail(nil); got != "<no pod>" {
		t.Errorf("podFailureDetail(nil) = %q, want <no pod>", got)
	}
}
