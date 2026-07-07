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
	testclock "k8s.io/utils/clock/testing"
)

// TestRestartPolicyOnExit is item B8's gate (extended by M10.2/B26): it pins the
// pure restart-decision helpers — the effective-policy truth table (the pod-level
// RestartPolicy-on-exit rules, including the Signal check that distinguishes an
// OOMKilled/SIGKILL termination from a clean exit, plus the container-level
// KEP-753 sidecar override: Always regardless of the pod policy) and the
// CrashLoopBackOff doubling/cap/reset schedule.
func TestRestartPolicyOnExit(t *testing.T) {
	t.Run("effective policy truth table", func(t *testing.T) {
		exit0 := &corev1.ContainerStateTerminated{ExitCode: 0}
		exitNonzero := &corev1.ContainerStateTerminated{ExitCode: 1}
		// OOMKilled / SIGKILL: the runtime reports Signal=9 with ExitCode 0;
		// OnFailure must still treat this as a failure (mirrors translate.go:707).
		signalKill := &corev1.ContainerStateTerminated{ExitCode: 0, Signal: 9}
		sidecar := corev1.ContainerRestartPolicyAlways

		cases := []struct {
			name            string
			podPolicy       corev1.RestartPolicy
			containerPolicy *corev1.ContainerRestartPolicy
			terminated      *corev1.ContainerStateTerminated
			want            bool
		}{
			{"Always + exit0 restarts a completed container", corev1.RestartPolicyAlways, nil, exit0, true},
			{"Always + exit nonzero restarts", corev1.RestartPolicyAlways, nil, exitNonzero, true},
			{"Always + signal kill restarts", corev1.RestartPolicyAlways, nil, signalKill, true},

			{"OnFailure + exit0 does not restart", corev1.RestartPolicyOnFailure, nil, exit0, false},
			{"OnFailure + exit nonzero restarts", corev1.RestartPolicyOnFailure, nil, exitNonzero, true},
			{"OnFailure + signal kill restarts despite exit0", corev1.RestartPolicyOnFailure, nil, signalKill, true},

			{"Never + exit0 never restarts", corev1.RestartPolicyNever, nil, exit0, false},
			{"Never + exit nonzero never restarts", corev1.RestartPolicyNever, nil, exitNonzero, false},
			{"Never + signal kill never restarts", corev1.RestartPolicyNever, nil, signalKill, false},

			{"nil terminated never restarts", corev1.RestartPolicyAlways, nil, nil, false},

			// KEP-753 native sidecars: the container-level Always overrides the
			// pod policy — a Job pod (Never) still restarts its exited sidecar.
			{"sidecar Always overrides pod Never on exit0", corev1.RestartPolicyNever, &sidecar, exit0, true},
			{"sidecar Always overrides pod Never on failure", corev1.RestartPolicyNever, &sidecar, exitNonzero, true},
			{"sidecar Always overrides pod OnFailure on exit0", corev1.RestartPolicyOnFailure, &sidecar, exit0, true},
			{"sidecar + nil terminated never restarts", corev1.RestartPolicyNever, &sidecar, nil, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := shouldRestartOnExit(tc.podPolicy, tc.containerPolicy, tc.terminated); got != tc.want {
					t.Errorf("shouldRestartOnExit(%q, %v, %+v) = %v, want %v", tc.podPolicy, tc.containerPolicy, tc.terminated, got, tc.want)
				}
			})
		}
	})

	t.Run("backoff doubling and cap", func(t *testing.T) {
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		b := newCrashLoopBackoff(clk)
		// The clock does not advance between calls, so no stabilization reset
		// fires: the schedule doubles from base and saturates at the cap.
		want := []time.Duration{
			10 * time.Second,
			20 * time.Second,
			40 * time.Second,
			80 * time.Second,
			160 * time.Second,
			300 * time.Second, // 320 capped to 300
			300 * time.Second, // cap holds
			300 * time.Second,
		}
		for i, w := range want {
			if got := b.Next(); got != w {
				t.Errorf("Next() call %d = %s, want %s", i+1, got, w)
			}
		}
	})

	t.Run("Reset returns to base", func(t *testing.T) {
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		b := newCrashLoopBackoff(clk)
		b.Next() // 10s
		b.Next() // 20s
		if got := b.Next(); got != 40*time.Second {
			t.Fatalf("setup: third Next() = %s, want 40s", got)
		}
		b.Reset()
		if got := b.Next(); got != 10*time.Second {
			t.Errorf("after Reset(), Next() = %s, want 10s (base)", got)
		}
	})

	t.Run("stabilization window resets to base", func(t *testing.T) {
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		b := newCrashLoopBackoff(clk)
		b.Next() // 10s
		b.Next() // 20s
		if got := b.Next(); got != 40*time.Second {
			t.Fatalf("setup: third Next() = %s, want 40s", got)
		}
		// The container stays up past the stabilization window before crashing
		// again, so the next delay resets to base (B26's stable-Running reset,
		// driven here by the clock instead of an explicit Reset()).
		clk.Step(crashLoopStableWindow + time.Second)
		if got := b.Next(); got != 10*time.Second {
			t.Errorf("after staying up %s, Next() = %s, want reset to 10s", crashLoopStableWindow+time.Second, got)
		}
	})
}
