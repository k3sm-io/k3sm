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
	"testing"
	"time"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// These are the M0 "Tier-1" unit tests: pure helpers plus VK-contract behavior of the
// HostProcess provider, with no privilege or network — just harmless host commands
// (`/usr/bin/true`, `/bin/sh -c …`). The runtimed gRPC client becomes a second runtime
// implementation at M2; the provider grows a small Runtime interface seam then (k3sm:M2.1).

func newPod(ns, name string, command ...string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c0", Image: "native", Command: command}},
		},
	}
}

// waitPhase polls the provider until the pod reaches want or the deadline elapses.
func waitPhase(t *testing.T, p *HostProcess, ns, name string, want corev1.PodPhase, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st, err := p.GetPodStatus(context.Background(), ns, name)
		if err == nil && st.Phase == want {
			return
		}
		if time.Now().After(deadline) {
			got := "<none>"
			if err == nil {
				got = string(st.Phase)
			}
			t.Fatalf("pod %s/%s: want phase %s, last %s", ns, name, want, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAggregatePhase(t *testing.T) {
	running := corev1.ContainerStatus{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
	ok := corev1.ContainerStatus{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}
	bad := corev1.ContainerStatus{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 3}}}

	tests := []struct {
		name string
		css  []corev1.ContainerStatus
		want corev1.PodPhase
	}{
		{"any running wins", []corev1.ContainerStatus{running, bad}, corev1.PodRunning},
		{"all succeeded", []corev1.ContainerStatus{ok, ok}, corev1.PodSucceeded},
		{"one failed", []corev1.ContainerStatus{ok, bad}, corev1.PodFailed},
		{"empty defaults succeeded", nil, corev1.PodSucceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aggregatePhase(tt.css); got != tt.want {
				t.Errorf("aggregatePhase = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSetCond(t *testing.T) {
	t.Run("updates existing", func(t *testing.T) {
		s := &corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
		setCond(s, corev1.PodReady, corev1.ConditionFalse)
		if len(s.Conditions) != 1 || s.Conditions[0].Status != corev1.ConditionFalse {
			t.Fatalf("want single PodReady=False, got %+v", s.Conditions)
		}
	})
	t.Run("appends missing", func(t *testing.T) {
		s := &corev1.PodStatus{}
		setCond(s, corev1.ContainersReady, corev1.ConditionTrue)
		if len(s.Conditions) != 1 || s.Conditions[0].Type != corev1.ContainersReady {
			t.Fatalf("want appended ContainersReady, got %+v", s.Conditions)
		}
	})
}

func TestEnvSlice(t *testing.T) {
	got := envSlice([]corev1.EnvVar{{Name: "K3SM_TEST_X", Value: "1"}})
	found := false
	for _, kv := range got {
		if kv == "K3SM_TEST_X=1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("env var not appended; got tail %v", got[len(got)-1:])
	}
	if len(got) <= 1 {
		t.Fatal("expected os.Environ() to be included")
	}
}

func TestRunningAndWaitingStatus(t *testing.T) {
	now := metav1.Now()
	c := &corev1.Container{Name: "c0", Image: "native"}
	r := runningStatus(c, now)
	if r.State.Running == nil || !r.Ready || r.Started == nil || !*r.Started {
		t.Fatalf("runningStatus malformed: %+v", r)
	}
	w := waitingStatus(c, "StartError", "boom")
	if w.State.Waiting == nil || w.State.Waiting.Reason != "StartError" {
		t.Fatalf("waitingStatus malformed: %+v", w)
	}
}

func TestPodKey(t *testing.T) {
	if got := podKey("default", "p"); got != "default/p" {
		t.Errorf("podKey = %q, want default/p", got)
	}
}

func TestCreatePodRunsToCompletion(t *testing.T) {
	p := NewHostProcess("test-node", t.TempDir(), "127.0.0.1")
	pod := newPod("default", "ok", "/usr/bin/true")
	if err := p.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	waitPhase(t, p, "default", "ok", corev1.PodSucceeded, 5*time.Second)
}

func TestCreatePodFailureExitCode(t *testing.T) {
	p := NewHostProcess("test-node", t.TempDir(), "127.0.0.1")
	pod := newPod("default", "fail", "/bin/sh", "-c", "exit 3")
	if err := p.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	waitPhase(t, p, "default", "fail", corev1.PodFailed, 5*time.Second)

	st, err := p.GetPodStatus(context.Background(), "default", "fail")
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	term := st.ContainerStatuses[0].State.Terminated
	if term == nil || term.ExitCode != 3 {
		t.Fatalf("want terminated exit code 3, got %+v", st.ContainerStatuses[0].State)
	}
}

func TestCreatePodIdempotent(t *testing.T) {
	p := NewHostProcess("test-node", t.TempDir(), "127.0.0.1")
	pod := newPod("default", "long", "/bin/sh", "-c", "sleep 60")
	t.Cleanup(func() { _ = p.DeletePod(context.Background(), pod) })

	if err := p.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod #1: %v", err)
	}
	if err := p.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod #2 (idempotent): %v", err)
	}
	pods, err := p.GetPods(context.Background())
	if err != nil {
		t.Fatalf("GetPods: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("want exactly 1 pod after double CreatePod, got %d", len(pods))
	}
}

func TestDeletePodIdempotent(t *testing.T) {
	p := NewHostProcess("test-node", t.TempDir(), "127.0.0.1")
	pod := newPod("default", "del", "/bin/sh", "-c", "sleep 60")
	if err := p.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if err := p.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod #1: %v", err)
	}
	if err := p.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod #2 (idempotent): %v", err)
	}
	if _, err := p.GetPod(context.Background(), "default", "del"); !errdefs.IsNotFound(err) {
		t.Fatalf("want NotFound after delete, got %v", err)
	}
}

func TestGetPodNotFound(t *testing.T) {
	p := NewHostProcess("test-node", t.TempDir(), "127.0.0.1")
	if _, err := p.GetPod(context.Background(), "default", "nope"); !errdefs.IsNotFound(err) {
		t.Fatalf("want NotFound, got %v", err)
	}
}

// TestNotifyPodsCallbackFires verifies the PodNotifier callback runs (asynchronously,
// outside the provider lock — the re-entrancy rule in the standards).
func TestNotifyPodsCallbackFires(t *testing.T) {
	p := NewHostProcess("test-node", t.TempDir(), "127.0.0.1")
	got := make(chan *corev1.Pod, 4)
	p.NotifyPods(context.Background(), func(pod *corev1.Pod) { got <- pod })

	pod := newPod("default", "notify", "/bin/sh", "-c", "sleep 60")
	t.Cleanup(func() { _ = p.DeletePod(context.Background(), pod) })
	if err := p.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	select {
	case n := <-got:
		if n.Name != "notify" {
			t.Fatalf("callback got pod %q, want notify", n.Name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PodNotifier callback did not fire within 2s")
	}
}
