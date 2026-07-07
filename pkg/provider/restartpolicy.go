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
// WHETHER and WHEN a terminated container should be restarted under its
// effective restart policy. They encode the upstream kubelet truth table and
// the CrashLoopBackOff schedule.
//
// Wired (M10.2, B26) on the RUNTIMED path only: runtimed_restart.go's
// observeExits is the single exit-driven restart authority — it consumes this
// resolver + crashLoopBackoff, schedules the re-exec via the RestartContainer
// RPC, and synthesizes the Waiting{Reason: CrashLoopBackOff} overlay while
// holding the pod phase at Running. The phase is held ONLY while a re-exec is
// actually scheduled: flipping the phase without the re-exec would mask a
// permanently-dead pod as Running, worse than an honest PodFailed.
//
// NOT wired on the HostProcess provider (the M0 opt-in runtime): a HostProcess
// pod's exited container is reaped once and never re-exec'd, whatever its
// restartPolicy — the conformance register handles that row at write-back.
//
// Scope — regular containers resolve under the POD policy; NATIVE SIDECARS
// (init containers with restartPolicy: Always, KEP-753) resolve under an
// effective per-container Always regardless of the pod policy — the sidecar
// half of the former "init containers deliberately NOT routed" gap is
// DISCHARGED. Plain init containers remain unrouted: a SUCCEEDED init
// container never restarts, and a FAILED one under Always/OnFailure would
// restart with the Pod held PENDING (Init:CrashLoopBackOff) — that subset is
// still documented, not implemented.
//
// restartCount authority — runtimed's ContainerStatus.restart_count is the
// single count (the RestartContainer RPC bumps it); the provider surfaces it
// verbatim and keeps no competing exit-driven counter.

// shouldRestartOnExit reports whether a terminated container should be
// restarted. It is the ONE effective-policy truth table: containerPolicy is
// the container-level restartPolicy (KEP-753; non-nil Always marks a native
// sidecar, whose effective policy is Always REGARDLESS of the pod policy — a
// Job pod with restartPolicy: Never still restarts its sidecar); a nil
// containerPolicy resolves under podPolicy, applying the upstream kubelet
// table:
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
// A nil terminated state (the container has not terminated) yields false. Do
// not route a PLAIN init container (nil containerPolicy) through this — see
// the scope note above.
func shouldRestartOnExit(podPolicy corev1.RestartPolicy, containerPolicy *corev1.ContainerRestartPolicy, terminated *corev1.ContainerStateTerminated) bool {
	if terminated == nil {
		return false
	}
	if containerPolicy != nil && *containerPolicy == corev1.ContainerRestartPolicyAlways {
		return true // native sidecar: effective Always regardless of the pod policy
	}
	switch podPolicy {
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
// owns one per container inside containerRestart, serialized by
// podTrack.restartMu (runtimed_restart.go).
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
// base — the explicit counterpart to Next's clock-driven stabilization reset
// (which is what the B26 trigger relies on: a container that stays up past the
// stabilization window resets on its next crash without an explicit call).
func (b *crashLoopBackoff) Reset() {
	b.cur = 0
	b.last = time.Time{}
}
