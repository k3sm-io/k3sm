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

	corev1 "k8s.io/api/core/v1"
	testclock "k8s.io/utils/clock/testing"
)

// TestReadinessProbeDrivesReadyCondition asserts the readiness→Ready contract at
// the PROVIDER seam — CreatePod → prober → buildStatus → the published PodStatus —
// rather than at the pure toPodStatus seam TestM2_ReadinessGatesEndpoints already
// owns. The two are not redundant: this one proves the wiring CreatePod actually
// builds (startProber, the overlay ORDER inside buildStatus, and the postStart
// interaction), which is the path a live cluster exercises.
//
// The semantics are the kubelet's, stated on the API type itself (k8s.io/api
// core/v1 types.go, Container.ReadinessProbe): "Periodic probe of container service
// readiness. Container will be removed from service endpoints if the probe fails."
// — i.e. the probe RESULT is the container's Ready, and a container carrying a
// readiness probe has not passed one yet at start, so it begins NOT ready (the
// kubelet's prober seeds a readiness result of Failure at container start,
// k8s.io/kubernetes pkg/kubelet/prober/worker.go).
//
// Row 2 is the one no other test in this package covers: a readiness SUCCESS must
// not promote a container whose postStart hook is still gating it (B39). Upstream
// publishes nothing at all for a container while its postStart hook runs
// (k8s.io/api core/v1 types.go, Lifecycle.PostStart: "Other management of the
// container blocks until the hook completes"), so a probe verdict that arrived
// mid-hook cannot be allowed to leak a Ready container into a Service's endpoints.
func TestReadinessProbeDrivesReadyCondition(t *testing.T) {
	ctx := context.Background()

	t.Run("a readiness probe holds the container not-Ready until its first success", func(t *testing.T) {
		r, _ := newRuntimedFake(t)
		r.clk = testclock.NewFakeClock(time.Unix(0, 0))
		// InitialDelaySeconds parks the probe loop on the fake clock, which is never
		// stepped: no check ever runs, so every outcome below is fed deliberately.
		pod := probePod("ready", corev1.Container{
			Name:    "c0",
			Command: []string{"/web"},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler:        tcpHandler(8080),
				InitialDelaySeconds: 3600,
				SuccessThreshold:    1,
				FailureThreshold:    2,
			},
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })
		m := monitorFor(t, r, pod, "c0")

		for _, step := range []struct {
			name string
			act  func()
			want bool
		}{
			// The runtime reports c0 running AND ready (runningStatus in the shared
			// fake), so a false here can only come from the probe overlay.
			{"before the first success the container is not Ready", func() {}, false},
			{"the first success promotes it to Ready", func() { feed(m, probeReadiness, outcomeSuccess) }, true},
			{"one failure is below failureThreshold — still Ready", func() { feed(m, probeReadiness, outcomeFailure) }, true},
			{"failureThreshold consecutive failures demote it", func() { feed(m, probeReadiness, outcomeFailure) }, false},
		} {
			step.act()
			assertReadySurface(t, r, pod, step.name, step.want)
		}
	})

	t.Run("a readiness success does not promote a postStart-gated container", func(t *testing.T) {
		r, f, _ := newHookFake(t)
		r.clk = testclock.NewFakeClock(time.Unix(0, 0))
		f.release = make(chan struct{}, 1) // hold the hook mid-flight
		pod := postStartPod("gateprobe", corev1.RestartPolicyAlways)
		pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{
			ProbeHandler:        tcpHandler(8080),
			InitialDelaySeconds: 3600,
			SuccessThreshold:    1,
			FailureThreshold:    2,
		}
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })
		waitCond(t, "the postStart hook to be dispatched", func() bool { return f.execCount() == 1 })
		m := monitorFor(t, r, pod, "c0")

		assertReadySurface(t, r, pod, "both gates shut (hook pending, probe not yet succeeded)", false)

		// The load-bearing row: the probe committed success, but the postStart hook
		// has not returned — the container must stay NotReady and out of endpoints.
		feed(m, probeReadiness, outcomeSuccess)
		assertReadySurface(t, r, pod, "readiness succeeded while the postStart hook is still running", false)

		// The hook returns: NOW both gates are open and the container is Ready.
		f.release <- struct{}{}
		waitCond(t, "the postStart gate to lift", func() bool {
			return containerReady(hookStatus(t, r, pod), "c0")
		})
		assertReadySurface(t, r, pod, "the hook completed and the probe had succeeded", true)

		// And the probe still owns the demotion after the gate is gone.
		feed(m, probeReadiness, outcomeFailure)
		feed(m, probeReadiness, outcomeFailure)
		assertReadySurface(t, r, pod, "failureThreshold failures after the hook completed", false)
	})
}

// monitorFor returns the live containerMonitor the provider's prober built for a
// container, so a test can commit probe outcomes without running any check I/O.
func monitorFor(t *testing.T, r *runtimedRuntime, pod *corev1.Pod, container string) *containerMonitor {
	t.Helper()
	r.mu.Lock()
	pp := r.probers[string(pod.UID)]
	r.mu.Unlock()
	if pp == nil {
		t.Fatalf("no prober for pod %s/%s (CreatePod must start one for a probed pod)", pod.Namespace, pod.Name)
	}
	m := pp.monitors[container]
	if m == nil {
		t.Fatalf("no monitor for container %q", container)
	}
	return m
}

// assertReadySurface asserts the WHOLE readiness surface the EndpointSlice
// controller reads — the container's Ready plus the ContainersReady and PodReady
// conditions derived from it — matches want on the status the provider publishes.
func assertReadySurface(t *testing.T, r *runtimedRuntime, pod *corev1.Pod, step string, want bool) {
	t.Helper()
	st := hookStatus(t, r, pod)
	if got := containerReady(st, "c0"); got != want {
		t.Errorf("%s: container Ready = %v, want %v", step, got, want)
	}
	wantCond := corev1.ConditionFalse
	if want {
		wantCond = corev1.ConditionTrue
	}
	if got := condStatus(st, corev1.ContainersReady); got != wantCond {
		t.Errorf("%s: ContainersReady = %s, want %s", step, got, wantCond)
	}
	if got := condStatus(st, corev1.PodReady); got != wantCond {
		t.Errorf("%s: PodReady = %s, want %s", step, got, wantCond)
	}
}
