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

// TestRestartPolicyOnExit is item B8's gate: it pins the pure restart-decision
// helpers — the RestartPolicy-on-exit truth table (including the Signal check
// that distinguishes an OOMKilled/SIGKILL termination from a clean exit) and the
// CrashLoopBackOff doubling/cap/reset schedule.
func TestRestartPolicyOnExit(t *testing.T) {
	t.Run("policy truth table", func(t *testing.T) {
		exit0 := &corev1.ContainerStateTerminated{ExitCode: 0}
		exitNonzero := &corev1.ContainerStateTerminated{ExitCode: 1}
		// OOMKilled / SIGKILL: the runtime reports Signal=9 with ExitCode 0;
		// OnFailure must still treat this as a failure (mirrors translate.go:707).
		signalKill := &corev1.ContainerStateTerminated{ExitCode: 0, Signal: 9}

		cases := []struct {
			name       string
			policy     corev1.RestartPolicy
			terminated *corev1.ContainerStateTerminated
			want       bool
		}{
			{"Always + exit0 restarts a completed container", corev1.RestartPolicyAlways, exit0, true},
			{"Always + exit nonzero restarts", corev1.RestartPolicyAlways, exitNonzero, true},
			{"Always + signal kill restarts", corev1.RestartPolicyAlways, signalKill, true},

			{"OnFailure + exit0 does not restart", corev1.RestartPolicyOnFailure, exit0, false},
			{"OnFailure + exit nonzero restarts", corev1.RestartPolicyOnFailure, exitNonzero, true},
			{"OnFailure + signal kill restarts despite exit0", corev1.RestartPolicyOnFailure, signalKill, true},

			{"Never + exit0 never restarts", corev1.RestartPolicyNever, exit0, false},
			{"Never + exit nonzero never restarts", corev1.RestartPolicyNever, exitNonzero, false},
			{"Never + signal kill never restarts", corev1.RestartPolicyNever, signalKill, false},

			{"nil terminated never restarts", corev1.RestartPolicyAlways, nil, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := shouldRestartOnExit(tc.policy, tc.terminated); got != tc.want {
					t.Errorf("shouldRestartOnExit(%q, %+v) = %v, want %v", tc.policy, tc.terminated, got, tc.want)
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
