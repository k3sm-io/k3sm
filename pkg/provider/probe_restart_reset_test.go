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

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestProbeStateResetsOnAnyContainerRestart pins the kubelet's per-instance
// probe state for a restart the prober did not cause. The kubelet keeps one
// prober worker per container instance: when the container id changes, the
// startup result goes back to "not started" and the readiness result back to
// "not ready", and every probe waits initialDelaySeconds from the new
// instance's start. A container that crashed, or exited and was restarted by
// its restartPolicy, must therefore drop out of its Services until its probes
// pass again, instead of carrying the old instance's verdicts.
//
// c0 has a startup and a readiness probe; c1 has a readiness probe only, so the
// readiness reset is checked with and without the startup gate in front of it.
func TestProbeStateResetsOnAnyContainerRestart(t *testing.T) {
	const readinessDelay = 30 * time.Second

	cases := []struct {
		name          string
		restartPolicy corev1.RestartPolicy
		// exitCode is the first instance's exit, reported before the runtime
		// reports its replacement.
		exitCode int32
	}{
		{name: "crash restart", restartPolicy: corev1.RestartPolicyAlways, exitCode: 2},
		{name: "restartPolicy restart after a clean exit", restartPolicy: corev1.RestartPolicyAlways, exitCode: 0},
		{name: "OnFailure restart after a crash", restartPolicy: corev1.RestartPolicyOnFailure, exitCode: 137},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := testclock.NewFakeClock(time.Unix(100000, 0))
			ctx := context.Background()
			healthy := func(context.Context, time.Duration) error { return nil }
			pod := probePod("reset", corev1.Container{
				Name:         "c0",
				StartupProbe: &corev1.Probe{ProbeHandler: tcpHandler(8080), FailureThreshold: 30},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler:        tcpHandler(8080),
					InitialDelaySeconds: int32(readinessDelay / time.Second),
				},
			}, corev1.Container{
				Name: "c1",
				ReadinessProbe: &corev1.Probe{
					ProbeHandler:        tcpHandler(9090),
					InitialDelaySeconds: int32(readinessDelay / time.Second),
				},
			})
			pod.Spec.RestartPolicy = tc.restartPolicy
			pp := newPodProber(pod, clk, func(*corev1.Container, *corev1.Probe) checkFunc { return healthy }, nil)
			c0, c1 := pp.monitors["c0"], pp.monitors["c1"]

			// observe feeds one runtime status through the seam buildStatus uses.
			observe := func(id string, state *runtimev1.ContainerState) {
				t.Helper()
				rs := &runtimev1.PodStatus{PodId: string(pod.UID), Phase: runtimev1.PodPhase_POD_PHASE_RUNNING}
				for _, name := range []string{"c0", "c1"} {
					rs.ContainerStatuses = append(rs.ContainerStatuses, &runtimev1.ContainerStatus{
						Name: name, ContainerId: name + "-" + id, State: state,
					})
				}
				observeProbeInstances(pp, rs)
			}
			running := func(at time.Time) *runtimev1.ContainerState {
				return &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(at)}}
			}
			tickAll := func() {
				pp.tick(ctx, c0, probeStartup, c0.startup)
				pp.tick(ctx, c0, probeReadiness, c0.readiness)
				pp.tick(ctx, c1, probeReadiness, c1.readiness)
			}
			want := func(phase string, m *containerMonitor, started, ready bool) {
				t.Helper()
				v := vd(m)
				if v.started != started || v.ready != ready {
					t.Fatalf("%s: %s started=%v ready=%v, want started=%v ready=%v",
						phase, m.name, v.started, v.ready, started, ready)
				}
			}

			// The first instance has been up for an hour and passes every probe.
			observe("instance-1", running(clk.Now().Add(-time.Hour)))
			tickAll()
			want("first instance healthy", c0, true, true)
			want("first instance healthy", c1, true, true)

			// It exits, and the runtime restarts it under the restartPolicy. The
			// replacement has just started.
			observe("instance-1", &runtimev1.ContainerState{
				Terminated: &runtimev1.ContainerStateTerminated{ExitCode: tc.exitCode},
			})
			restartedAt := clk.Now()
			observe("instance-2", running(restartedAt))
			want("replacement observed", c0, false, false)
			want("replacement observed", c1, true, false)

			// Startup passes again at once; readiness waits initialDelaySeconds
			// from the replacement's start, so the container stays not ready.
			tickAll()
			want("inside the readiness delay", c0, true, false)
			want("inside the readiness delay", c1, true, false)

			// Past the delay, a readiness success makes it ready again.
			clk.SetTime(restartedAt.Add(readinessDelay))
			tickAll()
			want("past the readiness delay", c0, true, true)
			want("past the readiness delay", c1, true, true)

			// No probe-driven restart happened: the reset is per instance, not a
			// liveness reaction.
			if got := vd(c0).restarts; got != 0 {
				t.Fatalf("probe-driven restarts = %d, want 0", got)
			}
		})
	}
}
