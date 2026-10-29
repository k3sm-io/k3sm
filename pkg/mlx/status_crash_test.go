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

package mlx

import (
	"strings"
	"testing"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// withContainer returns p with its serving-container facts set.
func withContainer(p PodState, c ContainerState) PodState {
	p.Container = c
	return p
}

// TestStatusReportsCrashLoopingReplica pins that a replica whose serving
// container keeps failing reports why, instead of the Downloading a merely
// starting replica reports. Readiness is false in both cases; only the
// container's waiting reason and last exit tell them apart.
func TestStatusReportsCrashLoopingReplica(t *testing.T) {
	crashLoop := ContainerState{
		WaitingReason:     "CrashLoopBackOff",
		WaitingMessage:    "back-off 5m0s restarting failed container=mlx-serve pod=qwen3-0",
		Terminated:        true,
		ExitCode:          1,
		TerminatedReason:  "Error",
		TerminatedMessage: "ModuleNotFoundError: No module named 'mlx_lm'",
	}
	pending := func(name string) PodState {
		return PodState{Name: name, Phase: corev1.PodPending, Revision: testPodRevision}
	}

	cases := []struct {
		name        string
		replicas    int32
		pods        []PodState
		wantReason  string
		wantPhase   mlxv1alpha1.MLXModelPhase
		wantInMsg   []string
		wantMaxRune int
	}{
		{
			name:       "crash loop back-off reports Crashing with the exit and messages",
			replicas:   1,
			pods:       []PodState{withContainer(running("qwen3-0", ProbeUnreachable), crashLoop)},
			wantReason: ReasonCrashing,
			wantPhase:  mlxv1alpha1.MLXModelPhaseFailed,
			wantInMsg:  []string{"qwen3-0", "CrashLoopBackOff", "exit code 1", "No module named 'mlx_lm'", "back-off 5m0s", "0 of 1 replicas ready"},
		},
		{
			name:     "a crash loop with the pod between restarts still reports Crashing",
			replicas: 1,
			pods: []PodState{withContainer(PodState{Name: "qwen3-0", Phase: corev1.PodRunning, Revision: testPodRevision},
				ContainerState{Terminated: true, ExitCode: 137, TerminatedReason: "OOMKilled"})},
			wantReason: ReasonCrashing,
			wantPhase:  mlxv1alpha1.MLXModelPhaseFailed,
			wantInMsg:  []string{"qwen3-0", "exit code 137", "OOMKilled"},
		},
		{
			name:       "create container error reports Crashing",
			replicas:   1,
			pods:       []PodState{withContainer(pending("qwen3-0"), ContainerState{WaitingReason: "CreateContainerError", WaitingMessage: "exec format error"})},
			wantReason: ReasonCrashing,
			wantPhase:  mlxv1alpha1.MLXModelPhaseFailed,
			wantInMsg:  []string{"qwen3-0", "CreateContainerError", "exec format error"},
		},
		{
			name:       "image pull back-off reports ImagePullFailed",
			replicas:   1,
			pods:       []PodState{withContainer(pending("qwen3-0"), ContainerState{WaitingReason: "ImagePullBackOff", WaitingMessage: `Back-off pulling image "ghcr.io/x/mlx-serve:nope"`})},
			wantReason: ReasonImagePullFailed,
			wantPhase:  mlxv1alpha1.MLXModelPhaseFailed,
			wantInMsg:  []string{"qwen3-0", "ImagePullBackOff", "mlx-serve:nope"},
		},
		{
			name:       "err image pull reports ImagePullFailed",
			replicas:   1,
			pods:       []PodState{withContainer(pending("qwen3-0"), ContainerState{WaitingReason: "ErrImagePull", WaitingMessage: "manifest unknown"})},
			wantReason: ReasonImagePullFailed,
			wantPhase:  mlxv1alpha1.MLXModelPhaseFailed,
			wantInMsg:  []string{"qwen3-0", "ErrImagePull", "manifest unknown"},
		},
		{
			name:       "a crashing replica outranks a sibling that is merely downloading",
			replicas:   2,
			pods:       []PodState{running("qwen3-0", ProbeUnreachable), withContainer(running("qwen3-1", ProbeUnreachable), crashLoop)},
			wantReason: ReasonCrashing,
			wantPhase:  mlxv1alpha1.MLXModelPhaseFailed,
			wantInMsg:  []string{"qwen3-1", "CrashLoopBackOff", "0 of 2 replicas ready"},
		},
		{
			name:       "a starting replica with no fault is still Downloading",
			replicas:   1,
			pods:       []PodState{running("qwen3-0", ProbeUnreachable)},
			wantReason: ReasonDownloading,
			wantPhase:  mlxv1alpha1.MLXModelPhaseDownloading,
			wantInMsg:  []string{"qwen3-0"},
		},
		{
			name:       "a clean last exit is not a crash",
			replicas:   1,
			pods:       []PodState{withContainer(running("qwen3-0", ProbeUnreachable), ContainerState{Terminated: true, ExitCode: 0, TerminatedReason: "Completed"})},
			wantReason: ReasonDownloading,
			wantPhase:  mlxv1alpha1.MLXModelPhaseDownloading,
			wantInMsg:  []string{"qwen3-0"},
		},
		{
			name:       "container creating is a wait, not a fault",
			replicas:   1,
			pods:       []PodState{withContainer(pending("qwen3-0"), ContainerState{WaitingReason: "ContainerCreating"})},
			wantReason: ReasonPending,
			wantPhase:  mlxv1alpha1.MLXModelPhasePending,
			wantInMsg:  []string{"qwen3-0"},
		},
		{
			name:       "a ready replica with a past crash serves",
			replicas:   1,
			pods:       []PodState{withContainer(serving("qwen3-0"), ContainerState{Terminated: true, ExitCode: 1, TerminatedReason: "Error"})},
			wantReason: ReasonServing,
			wantPhase:  mlxv1alpha1.MLXModelPhaseReady,
		},
		{
			name:     "a long multi-line message is folded to one line and truncated",
			replicas: 1,
			pods: []PodState{withContainer(running("qwen3-0", ProbeUnreachable), ContainerState{
				WaitingReason: "CrashLoopBackOff", Terminated: true, ExitCode: 1, TerminatedReason: "Error",
				TerminatedMessage: "Traceback (most recent call last):\n" + strings.Repeat("x", 4000),
			})},
			wantReason:  ReasonCrashing,
			wantPhase:   mlxv1alpha1.MLXModelPhaseFailed,
			wantInMsg:   []string{"qwen3-0", "Traceback (most recent call last): x", "..."},
			wantMaxRune: 600,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := singleReplicaModel()
			m.Spec.Replicas = ptr.To(tc.replicas)
			got := DeriveStatus(m, Observation{Pods: tc.pods, CurrentRevision: testPodRevision}, statusOptions(), statusBase)
			c := meta.FindStatusCondition(got.Conditions, mlxv1alpha1.MLXModelConditionReady)
			if c == nil {
				t.Fatal("no Ready condition")
			}
			if c.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q (message %q)", c.Reason, tc.wantReason, c.Message)
			}
			if got.Phase != tc.wantPhase {
				t.Errorf("phase = %q, want %q", got.Phase, tc.wantPhase)
			}
			for _, w := range tc.wantInMsg {
				if !strings.Contains(c.Message, w) {
					t.Errorf("message %q does not contain %q", c.Message, w)
				}
			}
			if strings.Contains(c.Message, "\n") {
				t.Errorf("message %q spans lines", c.Message)
			}
			if tc.wantMaxRune > 0 && utf8.RuneCountInString(c.Message) > tc.wantMaxRune {
				t.Errorf("message is %d runes, want at most %d", utf8.RuneCountInString(c.Message), tc.wantMaxRune)
			}
		})
	}
}

// TestServingContainerStateReadsTheServingContainer pins the copy from a pod's
// status: the serving container's waiting reason and its current termination,
// else its last one, and nothing from a sibling container.
func TestServingContainerStateReadsTheServingContainer(t *testing.T) {
	sidecar := corev1.ContainerStatus{Name: "sidecar", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}
	cases := []struct {
		name string
		pod  *corev1.Pod
		want ContainerState
	}{
		{name: "nil pod", pod: nil, want: ContainerState{}},
		{
			name: "no status for the serving container",
			pod:  &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{sidecar}}},
			want: ContainerState{},
		},
		{
			name: "waiting with a last termination",
			pod: &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{sidecar, {
				Name:                 containerName,
				State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "back-off"}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 2, Reason: "Error", Message: "boom"}},
			}}}},
			want: ContainerState{WaitingReason: "CrashLoopBackOff", WaitingMessage: "back-off", Terminated: true, ExitCode: 2, TerminatedReason: "Error", TerminatedMessage: "boom"},
		},
		{
			name: "the current termination wins over the last one",
			pod: &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				Name:                 containerName,
				State:                corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}},
			}}}},
			want: ContainerState{Terminated: true, ExitCode: 137, TerminatedReason: "OOMKilled"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ServingContainerState(tc.pod); got != tc.want {
				t.Errorf("ServingContainerState() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
