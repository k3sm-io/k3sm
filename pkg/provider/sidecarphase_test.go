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
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPhaseWaitsForSidecarTeardown pins the upstream rule that a pod with
// native sidecars (init containers with restartPolicy: Always) is never
// published terminal while one of them still runs: when the mains finish,
// runtimed reports its mains-only terminal phase and starts the reverse-order
// sidecar teardown, and the pod stays Running until every sidecar reports
// terminated. Only then does it go Succeeded/Failed (decided by the mains), and
// that one terminal write carries every sidecar's terminated state, because
// Virtual Kubelet never writes the status of a pod already terminal in the API.
func TestPhaseWaitsForSidecarTeardown(t *testing.T) {
	never := corev1.RestartPolicyNever
	always := corev1.ContainerRestartPolicyAlways
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "default", UID: "uid-sidecar"},
		Spec: corev1.PodSpec{
			RestartPolicy: never,
			InitContainers: []corev1.Container{
				{Name: "setup"},
				{Name: "s1", RestartPolicy: &always},
				{Name: "s2", RestartPolicy: &always},
			},
			Containers: []corev1.Container{{Name: "main"}},
		},
	}

	at := func(sec int64) *timestamppb.Timestamp { return timestamppb.New(time.Unix(sec, 0)) }
	running := func(name string) *runtimev1.ContainerStatus {
		return &runtimev1.ContainerStatus{Name: name, State: &runtimev1.ContainerState{
			Running: &runtimev1.ContainerStateRunning{StartedAt: at(1000)},
		}}
	}
	exited := func(name string, code, sig int32) *runtimev1.ContainerStatus {
		return &runtimev1.ContainerStatus{Name: name, State: &runtimev1.ContainerState{
			Terminated: &runtimev1.ContainerStateTerminated{ExitCode: code, Signal: sig, StartedAt: at(1000), FinishedAt: at(1010)},
		}}
	}
	waiting := func(name, reason string, lastExit bool) *runtimev1.ContainerStatus {
		cs := &runtimev1.ContainerStatus{Name: name, State: &runtimev1.ContainerState{
			Waiting: &runtimev1.ContainerStateWaiting{Reason: reason},
		}}
		if lastExit {
			cs.LastTerminationState = &runtimev1.ContainerState{
				Terminated: &runtimev1.ContainerStateTerminated{ExitCode: 1, StartedAt: at(1000), FinishedAt: at(1005)},
			}
			cs.RestartCount = 1
		}
		return cs
	}
	setupDone := exited("setup", 0, 0)

	tests := []struct {
		name string
		rp   runtimev1.PodPhase
		init []*runtimev1.ContainerStatus
		main []*runtimev1.ContainerStatus
		want corev1.PodPhase
	}{
		{
			name: "main exited 0 with a sidecar still running stays Running",
			rp:   runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			init: []*runtimev1.ContainerStatus{setupDone, running("s1"), exited("s2", 143, 15)},
			main: []*runtimev1.ContainerStatus{exited("main", 0, 0)},
			want: corev1.PodRunning,
		},
		{
			name: "main exited 0 with both sidecars running stays Running",
			rp:   runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			init: []*runtimev1.ContainerStatus{setupDone, running("s1"), running("s2")},
			main: []*runtimev1.ContainerStatus{exited("main", 0, 0)},
			want: corev1.PodRunning,
		},
		{
			name: "every sidecar terminated after main exited 0 is Succeeded",
			rp:   runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			init: []*runtimev1.ContainerStatus{setupDone, exited("s1", 143, 15), exited("s2", 0, 0)},
			main: []*runtimev1.ContainerStatus{exited("main", 0, 0)},
			want: corev1.PodSucceeded,
		},
		{
			name: "main exited 1 under Never with a sidecar running stays Running",
			rp:   runtimev1.PodPhase_POD_PHASE_FAILED,
			init: []*runtimev1.ContainerStatus{setupDone, running("s1"), exited("s2", 143, 15)},
			main: []*runtimev1.ContainerStatus{exited("main", 1, 0)},
			want: corev1.PodRunning,
		},
		{
			name: "main exited 1 under Never with every sidecar terminated is Failed",
			rp:   runtimev1.PodPhase_POD_PHASE_FAILED,
			init: []*runtimev1.ContainerStatus{setupDone, exited("s1", 0, 9), exited("s2", 143, 15)},
			main: []*runtimev1.ContainerStatus{exited("main", 1, 0)},
			want: corev1.PodFailed,
		},
		{
			name: "a crash-looping sidecar does not hold the pod",
			rp:   runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			init: []*runtimev1.ContainerStatus{setupDone, waiting("s1", reasonCrashLoopBackOff, true), exited("s2", 0, 0)},
			main: []*runtimev1.ContainerStatus{exited("main", 0, 0)},
			want: corev1.PodSucceeded,
		},
		{
			name: "a sidecar that never started does not hold the pod",
			rp:   runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			init: []*runtimev1.ContainerStatus{setupDone, waiting("s1", "ContainerCreating", false), exited("s2", 0, 0)},
			main: []*runtimev1.ContainerStatus{exited("main", 0, 0)},
			want: corev1.PodSucceeded,
		},
		{
			name: "a non-restartable init container reported running is not considered",
			rp:   runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			init: []*runtimev1.ContainerStatus{running("setup"), exited("s1", 0, 0), exited("s2", 0, 0)},
			main: []*runtimev1.ContainerStatus{exited("main", 0, 0)},
			want: corev1.PodSucceeded,
		},
		{
			name: "a running sidecar beside a running main is Running",
			rp:   runtimev1.PodPhase_POD_PHASE_RUNNING,
			init: []*runtimev1.ContainerStatus{setupDone, running("s1"), running("s2")},
			main: []*runtimev1.ContainerStatus{running("main")},
			want: corev1.PodRunning,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := &runtimev1.PodStatus{
				PodId:                 string(pod.UID),
				Phase:                 tt.rp,
				InitContainerStatuses: tt.init,
				ContainerStatuses:     tt.main,
			}
			st := toPodStatus(pod, rs, "192.0.2.10", metav1.NewTime(time.Unix(1000, 0)), nil, transportReady)
			if st.Phase != tt.want {
				t.Fatalf("phase = %s, want %s", st.Phase, tt.want)
			}
			if st.Phase != corev1.PodSucceeded && st.Phase != corev1.PodFailed {
				return
			}
			// The terminal write is the last one Virtual Kubelet makes, so
			// every sidecar that ran must already carry its terminated state
			// in it, and no main may be published running.
			for _, cs := range st.ContainerStatuses {
				if cs.State.Running != nil {
					t.Errorf("terminal status publishes main %s running", cs.Name)
				}
			}
			for _, name := range []string{"s1", "s2"} {
				var got *corev1.ContainerStatus
				for i := range st.InitContainerStatuses {
					if st.InitContainerStatuses[i].Name == name {
						got = &st.InitContainerStatuses[i]
					}
				}
				if got == nil {
					t.Fatalf("terminal status omits sidecar %s", name)
				}
				ranAndStopped := got.State.Terminated != nil
				neverHeld := got.State.Waiting != nil
				if !ranAndStopped && !neverHeld {
					t.Errorf("terminal status carries sidecar %s as %+v, want terminated", name, got.State)
				}
			}
		})
	}
}
