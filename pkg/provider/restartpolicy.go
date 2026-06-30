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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"
)

// Restart-decision helpers: pure, side-effect-free functions that decide
// WHETHER and WHEN a terminated regular container should be restarted under its
// Pod's RestartPolicy. They encode the upstream kubelet truth table and the
// CrashLoopBackOff schedule WITHOUT touching the live status/restart path.
//
// Currently unwired by design. The live status path (derivePhase/toPodStatus)
// still surfaces a crashed container as PodFailed; item B26 is the consumer that
// wires shouldRestartOnExit + crashLoopBackoff into the reaper to compose the
// live behavior — the phase, the Waiting{Reason: CrashLoopBackOff} state, and
// the restartCount surface. Landing the decision logic here, pure and tested,
// lets B26 add the re-exec and the status transitions atomically: flipping the
// phase to "Running while restarting" WITHOUT the actual re-exec would mask a
// permanently-dead pod as Running, a regression worse than today's honest
// PodFailed.
//
// Scope — regular containers only. Init containers are deliberately NOT routed
// through shouldRestartOnExit: a SUCCEEDED init container never restarts (even
// under RestartPolicyAlways), and a FAILED init container under Always/OnFailure
// restarts with the Pod held PENDING (Init:CrashLoopBackOff), not Running. That
// init subset is a known gap for B26 to handle on its own path; it is documented
// here, not implemented.
//
// restartCount authority — the provider owns the single exit-driven restart
// count, mirroring the probe monitor's onRestart bookkeeping (probe.go:228-241).
// Once a process has exited, the reaper is the EXCLUSIVE restart trigger, so it
// never races the liveness path on an already-dead container. B8 introduces no
// competing live counter; B26 enforces the single-authority rule at wiring time.

// shouldRestartOnExit reports whether a terminated regular container should be
// restarted under policy, applying the upstream kubelet truth table:
//
//   - RestartPolicyAlways restarts on ANY exit, including a clean exit-0 (a
//     Completed container under Always still restarts).
//   - RestartPolicyOnFailure restarts IFF the termination is a failure, where
//     failure means a non-zero exit code OR a non-zero terminating signal. The
//     Signal check mirrors the status predicate in toPodStatus (translate.go:707),
//     so an OOMKilled/SIGKILL termination (Signal=9) counts as a failure even
//     when ExitCode is reported as 0.
//   - RestartPolicyNever never restarts.
//
// A nil terminated state (the container has not terminated) yields false. Apply
// this only to regular containers; see the init-container gap documented above.
func shouldRestartOnExit(policy corev1.RestartPolicy, terminated *corev1.ContainerStateTerminated) bool {
	if terminated == nil {
		return false
	}
	switch policy {
	case corev1.RestartPolicyAlways:
		return true
	case corev1.RestartPolicyOnFailure:
		return terminated.ExitCode != 0 || terminated.Signal != 0
	case corev1.RestartPolicyNever:
		return false
	default:
		return false
	}
}

// The CrashLoopBackOff schedule, matching the upstream kubelet
// (pkg/kubelet/util/flowcontrol): a 10s base, exponential doubling capped at
// 300s, and a reset to base once a container has stayed up longer than the
// stabilization window. The window (2× the cap) deliberately exceeds the maximum
// backoff so that the wait between rapid crashes can never by itself trip a
// reset — only genuine extra run time does.
const (
	crashLoopBaseDelay    = 10 * time.Second
	crashLoopMaxDelay     = 300 * time.Second
	crashLoopStableWindow = 2 * crashLoopMaxDelay // 10m
)

// crashLoopBackoff computes the per-container CrashLoopBackOff delay schedule. It
// has no wall-clock side effects: it never sleeps; it reads the injected clock
// only to detect the stabilization reset. The zero value is not usable —
// construct it with newCrashLoopBackoff. It is not safe for concurrent use; B26
// owns one per container under the reaper's existing serialization.
type crashLoopBackoff struct {
	clk  clock.Clock
	cur  time.Duration // most recent delay returned; 0 means "reset / not yet started"
	last time.Time     // clock time of the previous Next call (≈ the previous crash)
}

// newCrashLoopBackoff returns a crashLoopBackoff that reads clk for its
// stabilization-reset check; a nil clk defaults to the real clock.
func newCrashLoopBackoff(clk clock.Clock) *crashLoopBackoff {
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &crashLoopBackoff{clk: clk}
}

// Next returns the delay to wait before the next restart attempt and advances
// the schedule. The first call returns the base delay; each subsequent rapid
// call doubles the previous delay, capped at the maximum. If more than the
// stabilization window has elapsed since the previous call — i.e. the container
// stayed up long enough to be considered stable — the schedule resets and Next
// returns the base delay again. Next does not sleep; the caller waits.
func (b *crashLoopBackoff) Next() time.Duration {
	now := b.clk.Now()
	switch {
	case b.cur == 0:
		b.cur = crashLoopBaseDelay
	case now.Sub(b.last) >= crashLoopStableWindow:
		b.cur = crashLoopBaseDelay
	default:
		b.cur *= 2
		if b.cur > crashLoopMaxDelay {
			b.cur = crashLoopMaxDelay
		}
	}
	b.last = now
	return b.cur
}

// Reset returns the schedule to its base delay, so the next Next call returns the
// base. B26 calls it when a container reaches a stable Running state — the
// explicit counterpart to Next's clock-driven stabilization reset.
func (b *crashLoopBackoff) Reset() {
	b.cur = 0
	b.last = time.Time{}
}
