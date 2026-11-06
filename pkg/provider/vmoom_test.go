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

/*
Copyright 2026 The k3sm Authors.

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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The two shapes one signal death reaches the provider in: the guest reports
// the signal with exit code 0, the host reaper reports it with 128+signal.
var signalDeathShapes = []struct {
	name      string
	exit, sig int32
}{
	{name: "vm shape exit 0 signal 9", exit: 0, sig: 9},
	{name: "native shape exit 137 signal 9", exit: 137, sig: 9},
}

// oomKilledStatus renders a container killed by signal sig for a memory limit.
func oomKilledStatus(name string, exit, sig int32, finishedAt time.Time) *runtimev1.ContainerStatus {
	cs := rtTerminated(name, exit, 0, finishedAt)
	cs.State.GetTerminated().Signal = sig
	cs.State.GetTerminated().Reason = oomKilledReason
	return cs
}

// publishedTermination returns the termination a container status shows, on
// the container or, once a restart has begun, as its last state.
func publishedTermination(t *testing.T, st corev1.PodStatus) *corev1.ContainerStateTerminated {
	t.Helper()
	if len(st.ContainerStatuses) != 1 {
		t.Fatalf("container statuses = %+v, want one", st.ContainerStatuses)
	}
	if term := st.ContainerStatuses[0].State.Terminated; term != nil {
		return term
	}
	return st.ContainerStatuses[0].LastTerminationState.Terminated
}

// TestVMContainerOOMKilledReportsUpstreamExitCode pins that a vm container
// killed by a signal publishes what upstream publishes, and what a native pod
// publishes for the same death: exit code 128+signal, and a failure wherever
// the status reads a failure.
func TestVMContainerOOMKilledReportsUpstreamExitCode(t *testing.T) {
	t.Run("exit code", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			exit, sig int32
			wantExit  int32
		}{
			{name: "vm SIGKILL", exit: 0, sig: 9, wantExit: 137},
			{name: "vm SIGTERM", exit: 0, sig: 15, wantExit: 143},
			{name: "native SIGKILL is unchanged", exit: 137, sig: 9, wantExit: 137},
			{name: "a clean exit stays clean", exit: 0, sig: 0, wantExit: 0},
			{name: "a process's own exit code is unchanged", exit: 3, sig: 0, wantExit: 3},
			{name: "an unknown exit status is unchanged", exit: -1, sig: 0, wantExit: -1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				term := &runtimev1.ContainerStateTerminated{ExitCode: tc.exit, Signal: tc.sig, Reason: oomKilledReason}
				state := &runtimev1.ContainerState{Terminated: term}
				got := toContainerStatuses([]*runtimev1.ContainerStatus{{
					Name: "c0", State: state, LastTerminationState: state,
				}})[0]
				for field, published := range map[string]*corev1.ContainerStateTerminated{
					"state":     got.State.Terminated,
					"lastState": got.LastTerminationState.Terminated,
				} {
					if published.ExitCode != tc.wantExit || published.Signal != tc.sig {
						t.Errorf("%s: exit %d signal %d, want exit %d signal %d", field, published.ExitCode, published.Signal, tc.wantExit, tc.sig)
					}
				}
			})
		}
	})

	t.Run("init container OOM-killed", func(t *testing.T) {
		pod := vmPod("default", "initoom")
		pod.Spec.RestartPolicy = corev1.RestartPolicyNever
		pod.Spec.InitContainers = []corev1.Container{{Name: "i0", Image: guestVMImage}}
		for _, shape := range signalDeathShapes {
			t.Run(shape.name, func(t *testing.T) {
				cs := oomKilledStatus("i0", shape.exit, shape.sig, time.Unix(20000, 0))
				got := toContainerStatuses([]*runtimev1.ContainerStatus{cs})
				if code := got[0].State.Terminated.ExitCode; code != 137 {
					t.Errorf("init container exit code = %d, want 137", code)
				}
				c := computeInitialized(pod, got)
				if c.Status != corev1.ConditionFalse || c.Reason != "ContainersNotInitialized" {
					t.Errorf("Initialized = %s (%s), want False (ContainersNotInitialized)", c.Status, c.Reason)
				}
			})
		}
		t.Run("the condition reads the signal itself", func(t *testing.T) {
			c := computeInitialized(pod, []corev1.ContainerStatus{{
				Name:  "i0",
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Signal: 9}},
			}})
			if c.Status != corev1.ConditionFalse {
				t.Errorf("Initialized = %s for exit 0 signal 9, want False", c.Status)
			}
		})
		t.Run("a clean init container still initializes the pod", func(t *testing.T) {
			got := toContainerStatuses([]*runtimev1.ContainerStatus{rtTerminated("i0", 0, 0, time.Unix(20000, 0))})
			if c := computeInitialized(pod, got); c.Status != corev1.ConditionTrue {
				t.Errorf("Initialized = %s for a clean exit, want True", c.Status)
			}
		})
	})

	t.Run("restart policies", func(t *testing.T) {
		for _, policy := range []corev1.RestartPolicy{corev1.RestartPolicyNever, corev1.RestartPolicyOnFailure, corev1.RestartPolicyAlways} {
			t.Run(string(policy), func(t *testing.T) {
				var want *corev1.ContainerStateTerminated
				for _, shape := range signalDeathShapes {
					pod := vmPod("default", "oom")
					pod.Spec.RestartPolicy = policy
					r, _, clk, tr, _ := newCrashFake(t, pod)
					defer tr.cancelRestarts()
					finished := clk.Now().Add(time.Second)
					rs := &runtimev1.PodStatus{
						PodId: string(pod.UID), Phase: runtimev1.PodPhase_POD_PHASE_FAILED,
						ContainerStatuses: []*runtimev1.ContainerStatus{oomKilledStatus("c0", shape.exit, shape.sig, finished)},
					}
					st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
					term := publishedTermination(t, st)
					if term == nil || term.ExitCode != 137 || term.Signal != 9 || term.Reason != oomKilledReason {
						t.Fatalf("%s: termination = %+v, want exit 137 signal 9 OOMKilled", shape.name, term)
					}
					wantPhase := corev1.PodRunning
					if policy == corev1.RestartPolicyNever {
						wantPhase = corev1.PodFailed
					}
					if st.Phase != wantPhase {
						t.Errorf("%s: phase = %s, want %s", shape.name, st.Phase, wantPhase)
					}
					if restart, wantRestart := shouldRestartOnExit(policy, nil, term), policy != corev1.RestartPolicyNever; restart != wantRestart {
						t.Errorf("%s: restart = %v, want %v", shape.name, restart, wantRestart)
					}
					if want == nil {
						want = term
					} else if !reflect.DeepEqual(term, want) {
						t.Errorf("native termination %+v differs from vm termination %+v", term, want)
					}
				}
			})
		}
	})

	t.Run("log fallback", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "0.log")
		if err := os.WriteFile(logPath, []byte("2026-09-13T09:00:00Z stderr F allocating the last page\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name        string
			exit, sig   int32
			wantMessage bool
		}{
			{name: "vm shape falls back", exit: 0, sig: 9, wantMessage: true},
			{name: "native shape falls back", exit: 137, sig: 9, wantMessage: true},
			{name: "a clean exit does not", exit: 0, sig: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pod := vmPod("default", "oom")
				pod.Spec.RestartPolicy = corev1.RestartPolicyNever
				pod.Spec.Containers[0].TerminationMessagePolicy = corev1.TerminationMessageFallbackToLogsOnError
				r, _, clk, tr, _ := newCrashFake(t, pod)
				cs := oomKilledStatus("c0", tc.exit, tc.sig, clk.Now().Add(time.Second))
				cs.State.GetTerminated().LogPath = logPath
				rs := &runtimev1.PodStatus{PodId: string(pod.UID), Phase: runtimev1.PodPhase_POD_PHASE_FAILED, ContainerStatuses: []*runtimev1.ContainerStatus{cs}}
				term := publishedTermination(t, r.buildStatus(pod.DeepCopy(), tr, rs, nil))
				if got := strings.Contains(term.Message, "allocating the last page"); got != tc.wantMessage {
					t.Errorf("termination message = %q, want the log tail: %v", term.Message, tc.wantMessage)
				}
			})
		}
	})

	t.Run("oomKills counted once", func(t *testing.T) {
		for _, policy := range []corev1.RestartPolicy{corev1.RestartPolicyNever, corev1.RestartPolicyOnFailure, corev1.RestartPolicyAlways} {
			for _, shape := range signalDeathShapes {
				t.Run(string(policy)+"/"+shape.name, func(t *testing.T) {
					pod := vmPod("default", "oom")
					pod.Spec.RestartPolicy = policy
					r, _, clk, tr, _ := newCrashFake(t, pod)
					defer tr.cancelRestarts()
					h := openHistory(t, filepath.Join(t.TempDir(), "server", "budget"), "fp")
					r.history = h
					rs := &runtimev1.PodStatus{
						PodId: string(pod.UID), Phase: runtimev1.PodPhase_POD_PHASE_FAILED,
						ContainerStatuses: []*runtimev1.ContainerStatus{oomKilledStatus("c0", shape.exit, shape.sig, clk.Now().Add(time.Second))},
					}
					for range 3 {
						r.buildStatus(pod.DeepCopy(), tr, rs, nil)
					}
					c := bandTotals(t, h, clk.Now(), budgetv1alpha1.BandStandard)
					if c.OOMKillsTotal != 1 || c.KernelKillsTotal != 0 {
						t.Errorf("oomKills=%d kernelKills=%d, want 1/0", c.OOMKillsTotal, c.KernelKillsTotal)
					}
				})
			}
		}
	})

	t.Run("a SIGKILL that is not an OOM kill counts as a kernel kill", func(t *testing.T) {
		for _, shape := range signalDeathShapes {
			t.Run(shape.name, func(t *testing.T) {
				pod := vmPod("default", "killed")
				pod.Spec.RestartPolicy = corev1.RestartPolicyNever
				r, _, clk, tr, _ := newCrashFake(t, pod)
				h := openHistory(t, filepath.Join(t.TempDir(), "server", "budget"), "fp")
				r.history = h
				cs := oomKilledStatus("c0", shape.exit, shape.sig, clk.Now().Add(time.Second))
				cs.State.GetTerminated().Reason = "Error"
				rs := &runtimev1.PodStatus{PodId: string(pod.UID), Phase: runtimev1.PodPhase_POD_PHASE_FAILED, ContainerStatuses: []*runtimev1.ContainerStatus{cs}}
				r.buildStatus(pod.DeepCopy(), tr, rs, nil)
				c := bandTotals(t, h, clk.Now(), budgetv1alpha1.BandStandard)
				if c.OOMKillsTotal != 0 || c.KernelKillsTotal != 1 {
					t.Errorf("oomKills=%d kernelKills=%d, want 0/1", c.OOMKillsTotal, c.KernelKillsTotal)
				}
			})
		}
	})
}
