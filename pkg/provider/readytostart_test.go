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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPodReadyToStartContainersCondition is the named gate for the
// PodReadyToStartContainers pod condition (GA and locked on in Kubernetes
// v1.37): True once the pod's sandbox analog is up, False while it is being
// created and after it is torn down, with a LastTransitionTime that survives
// repeated status writes.
//
// The table drives toPodStatus directly over the runtime statuses each lifecycle
// point produces; the sequence drives buildStatus, the convergence point every
// publish path goes through, because that is where the transition-time prior is
// seeded and a toPodStatus-only test could not see it reset on every resync.
func TestPodReadyToStartContainersCondition(t *testing.T) {
	const podIP, lease = "10.42.0.7", "192.168.64.5"
	running := func(pod *corev1.Pod, ip, transport string) *runtimev1.PodStatus {
		return &runtimev1.PodStatus{
			PodId:                 string(pod.UID),
			Phase:                 runtimev1.PodPhase_POD_PHASE_RUNNING,
			PodIp:                 ip,
			GuestTransportAddress: transport,
			ContainerStatuses:     []*runtimev1.ContainerStatus{rtRunning("c0")},
		}
	}
	terminal := func(pod *corev1.Pod, phase runtimev1.PodPhase, exit int32, ip, transport string) *runtimev1.PodStatus {
		return &runtimev1.PodStatus{
			PodId:                 string(pod.UID),
			Phase:                 phase,
			PodIp:                 ip,
			GuestTransportAddress: transport,
			ContainerStatuses:     []*runtimev1.ContainerStatus{rtTerminated("c0", exit, 0, time.Unix(6000, 0))},
		}
	}
	never := func(pod *corev1.Pod) *corev1.Pod {
		pod.Spec.RestartPolicy = corev1.RestartPolicyNever
		return pod
	}

	cases := []struct {
		name string
		pod  *corev1.Pod
		rs   func(*corev1.Pod) *runtimev1.PodStatus
		want corev1.ConditionStatus
	}{
		{
			name: "native pod pending before the sandbox: the create is in flight",
			pod:  runtimedPod("default", "creating"),
			rs:   creatingRuntimeStatus,
			want: corev1.ConditionFalse,
		},
		{
			name: "native pod parked on an image failure has no sandbox",
			pod:  runtimedPod("default", "parked"),
			rs: func(p *corev1.Pod) *runtimev1.PodStatus {
				return parkedRuntimeStatus(p, &createFailure{reason: runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, message: "pull failed"})
			},
			want: corev1.ConditionFalse,
		},
		{
			name: "native pod running with its pod IP bound",
			pod:  runtimedPod("default", "up"),
			rs:   func(p *corev1.Pod) *runtimev1.PodStatus { return running(p, podIP, "") },
			want: corev1.ConditionTrue,
		},
		{
			name: "native pod whose containers are still starting has its sandbox",
			pod:  runtimedPod("default", "starting"),
			rs: func(p *corev1.Pod) *runtimev1.PodStatus {
				rs := creatingRuntimeStatus(p)
				rs.PodIp = podIP
				return rs
			},
			want: corev1.ConditionTrue,
		},
		{
			name: "native pod succeeded: the sandbox is torn down",
			pod:  never(runtimedPod("default", "done")),
			rs: func(p *corev1.Pod) *runtimev1.PodStatus {
				return terminal(p, runtimev1.PodPhase_POD_PHASE_SUCCEEDED, 0, podIP, "")
			},
			want: corev1.ConditionFalse,
		},
		{
			name: "native pod failed under restartPolicy Never: the sandbox is torn down",
			pod:  never(runtimedPod("default", "failed")),
			rs: func(p *corev1.Pod) *runtimev1.PodStatus {
				return terminal(p, runtimev1.PodPhase_POD_PHASE_FAILED, 1, podIP, "")
			},
			want: corev1.ConditionFalse,
		},
		{
			name: "native pod crash-looping under restartPolicy Always keeps its sandbox",
			pod:  runtimedPod("default", "looping"),
			rs: func(p *corev1.Pod) *runtimev1.PodStatus {
				return terminal(p, runtimev1.PodPhase_POD_PHASE_FAILED, 1, podIP, "")
			},
			want: corev1.ConditionTrue,
		},
		{
			name: "native pod the runtime reports Unknown: the sandbox is lost",
			pod:  runtimedPod("default", "unknown"),
			rs: func(p *corev1.Pod) *runtimev1.PodStatus {
				rs := running(p, podIP, "")
				rs.Phase = runtimev1.PodPhase_POD_PHASE_UNKNOWN
				return rs
			},
			want: corev1.ConditionFalse,
		},
		{
			name: "vm pod booted but not yet networked (no guest lease)",
			pod:  vmPod("default", "vm-booting"),
			rs:   func(p *corev1.Pod) *runtimev1.PodStatus { return running(p, podIP, "") },
			want: corev1.ConditionFalse,
		},
		{
			name: "vm pod booted and networked",
			pod:  vmPod("default", "vm-up"),
			rs:   func(p *corev1.Pod) *runtimev1.PodStatus { return running(p, podIP, lease) },
			want: corev1.ConditionTrue,
		},
		{
			name: "vm pod whose guest failed: the sandbox is lost",
			pod:  never(vmPod("default", "vm-lost")),
			rs: func(p *corev1.Pod) *runtimev1.PodStatus {
				return terminal(p, runtimev1.PodPhase_POD_PHASE_FAILED, 137, podIP, lease)
			},
			want: corev1.ConditionFalse,
		},
		{
			name: "pod-less build with an address reads as a native sandbox",
			pod:  nil,
			rs: func(*corev1.Pod) *runtimev1.PodStatus {
				return running(runtimedPod("default", "podless"), podIP, "")
			},
			want: corev1.ConditionTrue,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := toPodStatus(tc.pod, tc.rs(tc.pod), "192.168.1.10", metav1.Now(), nil, transportReady)
			c := onlyCondition(t, st, corev1.PodReadyToStartContainers)
			if c.Status != tc.want {
				t.Fatalf("PodReadyToStartContainers = %s (phase %s), want %s", c.Status, st.Phase, tc.want)
			}
			if c.Reason != "" || c.Message != "" {
				t.Errorf("condition carries reason %q / message %q; the kubelet sets neither", c.Reason, c.Message)
			}
			if c.LastTransitionTime.IsZero() {
				t.Error("LastTransitionTime is zero; a first write is a transition")
			}
		})
	}

	t.Run("an apiserver-held copy is replaced, never duplicated", func(t *testing.T) {
		pod := runtimedPod("default", "carried")
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReadyToStartContainers, Status: corev1.ConditionFalse}}
		st := toPodStatus(pod, running(pod, podIP, ""), "192.168.1.10", metav1.Now(), nil, transportReady)
		if c := onlyCondition(t, st, corev1.PodReadyToStartContainers); c.Status != corev1.ConditionTrue {
			t.Fatalf("PodReadyToStartContainers = %s, want True", c.Status)
		}
	})

	t.Run("repeated status writes keep lastTransitionTime; a flip moves it", func(t *testing.T) {
		pod := crashPod("ltt", corev1.RestartPolicyNever)
		r, _, _, tr, _ := newCrashFake(t, pod)
		write := func(rs *runtimev1.PodStatus) corev1.PodCondition {
			t.Helper()
			st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
			return onlyCondition(t, &st, corev1.PodReadyToStartContainers)
		}
		settle := func() { time.Sleep(2 * time.Millisecond) }

		pending := write(creatingRuntimeStatus(pod))
		if pending.Status != corev1.ConditionFalse {
			t.Fatalf("pending: %s, want False", pending.Status)
		}
		settle()
		if again := write(creatingRuntimeStatus(pod)); !again.LastTransitionTime.Equal(&pending.LastTransitionTime) {
			t.Fatalf("pending rewrite moved LastTransitionTime %v -> %v", pending.LastTransitionTime, again.LastTransitionTime)
		}

		settle()
		up := write(running(pod, podIP, ""))
		if up.Status != corev1.ConditionTrue {
			t.Fatalf("running: %s, want True", up.Status)
		}
		if !up.LastTransitionTime.After(pending.LastTransitionTime.Time) {
			t.Fatalf("flip to True kept LastTransitionTime %v (pending was %v)", up.LastTransitionTime, pending.LastTransitionTime)
		}
		for i := 0; i < 3; i++ {
			settle()
			if again := write(running(pod, podIP, "")); again.Status != corev1.ConditionTrue || !again.LastTransitionTime.Equal(&up.LastTransitionTime) {
				t.Fatalf("running rewrite %d: %s at %v, want True at %v", i, again.Status, again.LastTransitionTime, up.LastTransitionTime)
			}
		}

		settle()
		down := write(terminal(pod, runtimev1.PodPhase_POD_PHASE_SUCCEEDED, 0, podIP, ""))
		if down.Status != corev1.ConditionFalse {
			t.Fatalf("torn down: %s, want False", down.Status)
		}
		if !down.LastTransitionTime.After(up.LastTransitionTime.Time) {
			t.Fatalf("flip to False kept LastTransitionTime %v (running was %v)", down.LastTransitionTime, up.LastTransitionTime)
		}
		settle()
		if again := write(terminal(pod, runtimev1.PodPhase_POD_PHASE_SUCCEEDED, 0, podIP, "")); !again.LastTransitionTime.Equal(&down.LastTransitionTime) {
			t.Fatalf("torn-down rewrite moved LastTransitionTime %v -> %v", down.LastTransitionTime, again.LastTransitionTime)
		}
	})

	t.Run("an evicted pod's sandbox reads torn down", func(t *testing.T) {
		pod := runtimedPod("default", "evicted")
		prior := toPodStatus(pod, running(pod, podIP, ""), "192.168.1.10", metav1.Now(), nil, transportReady)
		st := evictedPodStatus(*prior, "evicted for test", metav1.Now())
		if c := onlyCondition(t, st, corev1.PodReadyToStartContainers); c.Status != corev1.ConditionFalse {
			t.Fatalf("PodReadyToStartContainers = %s after eviction, want False", c.Status)
		}
	})
}

// onlyCondition returns the single condition of type ct in st, failing the test
// when it is absent or duplicated.
func onlyCondition(t *testing.T, st *corev1.PodStatus, ct corev1.PodConditionType) corev1.PodCondition {
	t.Helper()
	var found []corev1.PodCondition
	for _, c := range st.Conditions {
		if c.Type == ct {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d %s conditions in %+v, want exactly 1", len(found), ct, st.Conditions)
	}
	return found[0]
}
