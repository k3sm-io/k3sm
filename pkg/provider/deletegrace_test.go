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
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestCompensatingDeleteSendsResolvedGrace pins the grace of the DeletePod a
// late create's compensation sends: the pod's own budget, floored at
// minimumGracePeriodSeconds, exactly as an ordinary delete resolves it. In the
// apis contract a wire 0 is an immediate SIGKILL, which only evictPod asks for.
//
// Fails-before: runCompensatingDelete sent grace 0 and leaned on runtimed
// replacing it with the pod's terminationGracePeriodSeconds.
func TestCompensatingDeleteSendsResolvedGrace(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *int64
		want int64
	}{
		{"unset spec grace resolves to the 30s default", nil, 30},
		{"spec grace 7 is sent as is", ptr(int64(7)), 7},
		{"spec grace 0 is floored to 2", ptr(int64(0)), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := probePullPod("compensate-grace")
			pod.Spec.TerminationGracePeriodSeconds = tc.spec
			r, f, clk, _ := newPullProvider(t)
			f.pushCreate(createRefusal(runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
				`container c0: pull image "`+pullImage+`": unexpected status 500 Internal Server Error`))
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod = %v, want the pod parked rather than failed", err)
			}
			release := f.holdCreate()
			defer release()
			waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)
			clk.Step(11 * time.Second)
			waitRestart(t, "the retry's CreatePod to be entered", func() bool { return f.createCount() == 2 })

			if err := r.DeletePod(context.Background(), pod); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			release()
			waitRestart(t, "the compensating delete", func() bool { return len(f.deleteRecords()) == 2 })

			f.mu.Lock()
			graces := slices.Clone(f.graces)
			f.mu.Unlock()
			if want := []int64{tc.want, tc.want}; !slices.Equal(graces, want) {
				t.Errorf("DeletePod graces (the pod's own delete, then the compensation) = %v, want %v", graces, want)
			}
		})
	}
}

// TestEvictPodIsTheOnlyGraceZeroSender drives every provider path that sends
// runtimed a DeletePod, each against a pod whose grace budget is 0, and asserts
// that only evictPod's hard kill puts grace 0 on the wire. Every other path
// resolves the grace the kubelet way: the budget floored at
// minimumGracePeriodSeconds (2 s), so the container is sent SIGTERM and gets two
// seconds before SIGKILL.
//
// Fails-before: an ordinary delete, a preStop-carrying delete and the orphan
// reaper passed a 0 budget through, the compensating delete always sent 0, and
// the teardown after an eviction sent 0.
func TestEvictPodIsTheOnlyGraceZeroSender(t *testing.T) {
	ctx := context.Background()
	zeroSpec := func(pod *corev1.Pod) *corev1.Pod {
		pod.Spec.TerminationGracePeriodSeconds = ptr(int64(0))
		return pod
	}
	graces := func(f *fakeRuntimeServer) []int64 {
		f.mu.Lock()
		defer f.mu.Unlock()
		return slices.Clone(f.graces)
	}

	t.Run("ordinary delete, spec grace 0", func(t *testing.T) {
		r, f := newRuntimedFake(t)
		pod := zeroSpec(runtimedPod("default", "web"))
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := r.DeletePod(ctx, pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if got := graces(f); !slices.Equal(got, []int64{minimumGracePeriodSeconds}) {
			t.Errorf("DeletePod graces = %v, want [2]", got)
		}
	})

	t.Run("ordinary delete, deletion grace 0 over spec grace 30", func(t *testing.T) {
		r, f := newRuntimedFake(t)
		pod := runtimedPod("default", "web")
		pod.Spec.TerminationGracePeriodSeconds = ptr(int64(30))
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		pod.DeletionGracePeriodSeconds = ptr(int64(0))
		if err := r.DeletePod(ctx, pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if got := graces(f); !slices.Equal(got, []int64{minimumGracePeriodSeconds}) {
			t.Errorf("DeletePod graces = %v, want [2]", got)
		}
	})

	t.Run("delete with a preStop hook, spec grace 0: the hook is skipped", func(t *testing.T) {
		r, f := newRuntimedFake(t)
		rt := &fakeRoundTripper{status: 200}
		r.probeTransport = rt
		pod := zeroSpec(runtimedPod("default", "web"))
		pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}
		pod.Spec.Containers[0].Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/quit", Port: intstr.FromString("http")},
		}}
		pod.Status.PodIP = "10.0.0.5"
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := r.DeletePod(ctx, pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if rt.gotURL != "" {
			t.Errorf("the preStop hook ran with a grace budget of 0 (hit %q)", rt.gotURL)
		}
		if got := graces(f); !slices.Equal(got, []int64{minimumGracePeriodSeconds}) {
			t.Errorf("DeletePod graces = %v, want [2]", got)
		}
	})

	t.Run("orphan reap, spec grace 0", func(t *testing.T) {
		r, f := newRuntimedFake(t)
		pod := zeroSpec(runtimedPod("default", "web"))
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		r.reapOrphan(ctx, pod, r.trackByID(string(pod.UID)))
		if got := graces(f); !slices.Equal(got, []int64{minimumGracePeriodSeconds}) {
			t.Errorf("DeletePod graces = %v, want [2]", got)
		}
	})

	t.Run("compensating delete, spec grace 0", func(t *testing.T) {
		r, f := newRuntimedFake(t)
		pod := zeroSpec(runtimedPod("default", "web"))
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		r.runCompensatingDelete(pod, string(pod.UID)) // returns once the delete lands
		if got := graces(f); !slices.Equal(got, []int64{minimumGracePeriodSeconds}) {
			t.Errorf("DeletePod graces = %v, want [2]", got)
		}
	})

	t.Run("eviction sends 0, the teardown after it sends the floor", func(t *testing.T) {
		h := newEvictionHarness(t)
		pod := zeroSpec(evPod("hog", nil, "", ""))
		h.add(pod, "2Gi")
		if err := h.r.evictPod(ctx, pod, evictionNotice{signal: signalCompressor, message: "x"}); err != nil {
			t.Fatalf("evictPod: %v", err)
		}
		if err := h.r.DeletePod(ctx, pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if got := graces(h.f); !slices.Equal(got, []int64{0, minimumGracePeriodSeconds}) {
			t.Errorf("DeletePod graces (evictPod, then the delete) = %v, want [0 2]", got)
		}
	})
}
