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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// B26 — the provider is the SINGLE exit-driven restart authority on the
// runtimed path. runtimed performs NO exit-driven restarts (its contract:
// apis runtime.proto Container.restart_policy); the provider observes every
// container termination via the status stream + the GetPodStatus backstop
// (both converge on buildStatus), decides via the effective-policy resolver
// (shouldRestartOnExit, restartpolicy.go) + the CrashLoopBackOff schedule,
// and re-execs the container in place through the existing RestartContainer
// RPC — the same runtime action the liveness-probe path drives.
//
// Idempotency (BINDING): the trigger is keyed per container on the
// termination's identity — terminationKey{restart_count, exit code,
// FinishedAt} — inside the podTrack, so a stream+backstop double-delivery of
// the same terminated status NEVER double-restarts. runtimed's restart_count
// is the single count authority (RestartContainer bumps it); the provider
// surfaces it verbatim and keeps no competing counter.
//
// Concurrency: podTrack.restartMu guards the per-container bookkeeping
// (t.restarts), separate from r.mu for the same reason as readyMu — buildStatus
// runs OUTSIDE r.mu (GetPods snapshots tracks under r.mu, then builds each
// unlocked). Lock order where both are held is always r.mu → restartMu
// (runRestart's trackByID), never the reverse. Each pending re-exec is one
// ctx-bounded goroutine (a pod-lifetime context, cancelled by DeletePod /
// pod-terminal / CreatePod-replace via cancelRestarts), so a backoff wait
// never blocks the watch goroutine and never leaks past the pod.

// reasonCrashLoopBackOff is the corev1 waiting reason the provider synthesizes
// while a container sits between its exit and the scheduled re-exec.
const reasonCrashLoopBackOff = "CrashLoopBackOff"

// terminationKey identifies ONE observed container termination: runtimed's
// restart_count at the time of the exit plus the termination's exit code and
// finish instant. A re-exec bumps restart_count, so the next exit of the same
// container always produces a fresh key; re-delivery of the same exit (stream
// then backstop) reproduces the same key and is dropped.
type terminationKey struct {
	restartCount int32
	exitCode     int32
	finishedAt   int64 // FinishedAt.UnixNano(); stable even when the runtime reports none
}

// containerRestart is the per-container exit-driven restart bookkeeping held in
// podTrack.restarts under restartMu. The zero value is not used — observeExits
// constructs it with a backoff bound to the provider clock.
type containerRestart struct {
	backoff *crashLoopBackoff
	// seen/seenSet record the last termination identity acted upon (the
	// idempotency latch); seenSet distinguishes "never triggered" from a
	// legitimately zero-valued key.
	seen    terminationKey
	seenSet bool
	// pending is true from the restart decision until the RestartContainer RPC
	// returns (or the pod dies); the status overlay renders CrashLoopBackOff
	// exactly while pending.
	pending bool
	// delay is the backoff wait of the in-flight (or most recent) re-exec.
	delay time.Duration
	// lastTerm is the terminated state that triggered the pending re-exec,
	// surfaced as lastState.terminated by the overlay.
	lastTerm corev1.ContainerStateTerminated
	// cancel aborts the pending re-exec goroutine (DeletePod / pod terminal).
	cancel context.CancelFunc
}

// isNativeSidecar reports whether the named container is declared in pod's
// initContainers with restartPolicy: Always — the KEP-753 native sidecar whose
// effective restart policy is Always regardless of the pod-level policy.
func isNativeSidecar(pod *corev1.Pod, name string) bool {
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if c.Name == name {
			return c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
		}
	}
	return false
}

// observeExits is the B26 trigger: called from buildStatus on EVERY runtime
// status observation (stream, backstop, direct GetPodStatus), it decides — via
// the effective-policy resolver — which terminated containers are due a
// restart and schedules each re-exec exactly once (see terminationKey).
//
// Scope: regular containers resolve under the POD policy (nil container
// policy); native sidecars (init w/ restartPolicy: Always) resolve under
// effective Always regardless of the pod policy — so a Job pod
// (restartPolicy: Never) keeps its sidecar alive while its mains run. A plain
// init container is never routed here (the documented restartpolicy.go gap:
// Init:CrashLoopBackOff under a held-Pending pod is not implemented).
//
// Terminal gate: when runtimed's mains-only phase is Succeeded/Failed AND no
// MAIN container is due a restart, the pod is genuinely terminal (the B74 Job
// contract: Never + exit≠0 → Failed, exit 0 → Succeeded) — nothing restarts,
// including sidecars (runtimed owns their reverse-order teardown), and any
// pending re-exec is cancelled. When a main IS due (Always, or OnFailure on a
// failure), the pod is restarting, not terminal; the overlay holds the phase
// at Running.
func (r *runtimedRuntime) observeExits(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus) {
	if rs == nil || pod == nil {
		return
	}
	podPolicy := pod.Spec.RestartPolicy
	if podPolicy == "" {
		podPolicy = corev1.RestartPolicyAlways // the corev1 default
	}

	type exit struct {
		name string
		key  terminationKey
		term corev1.ContainerStateTerminated
	}
	var due []exit
	anyMainRestart := false
	collect := func(cs *runtimev1.ContainerStatus, containerPolicy *corev1.ContainerRestartPolicy) bool {
		term := toContainerState(cs.GetState()).Terminated
		if term == nil || !shouldRestartOnExit(podPolicy, containerPolicy, term) {
			return false
		}
		due = append(due, exit{
			name: cs.GetName(),
			key:  terminationKey{restartCount: cs.GetRestartCount(), exitCode: term.ExitCode, finishedAt: term.FinishedAt.UnixNano()},
			term: *term,
		})
		return true
	}
	for _, cs := range rs.GetContainerStatuses() {
		if collect(cs, nil) { // regular container → the pod policy
			anyMainRestart = true
		}
	}
	always := corev1.ContainerRestartPolicyAlways
	for _, cs := range rs.GetInitContainerStatuses() {
		if !isNativeSidecar(pod, cs.GetName()) {
			continue // plain init containers are deliberately not exit-restarted
		}
		collect(cs, &always) // sidecar → effective Always regardless of pod policy
	}

	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	phase := rs.GetPhase()
	if (phase == runtimev1.PodPhase_POD_PHASE_SUCCEEDED || phase == runtimev1.PodPhase_POD_PHASE_FAILED) && !anyMainRestart {
		// Genuinely terminal on the mains: never restart into runtimed's teardown.
		t.cancelRestartsLocked()
		return
	}
	for _, e := range due {
		r.scheduleRestartLocked(t, rs.GetPodId(), e.name, e.key, e.term)
	}
}

// scheduleRestartLocked schedules one re-exec for a decided restart, under
// t.restartMu. The terminationKey latch makes it idempotent: a termination
// already pending or already acted upon is dropped, so double-delivery never
// double-restarts and never advances the backoff twice. The backoff wait runs
// in its own pod-lifetime goroutine (never on the watch goroutine).
func (r *runtimedRuntime) scheduleRestartLocked(t *podTrack, podID, name string, key terminationKey, term corev1.ContainerStateTerminated) {
	if t.restarts == nil {
		t.restarts = map[string]*containerRestart{}
	}
	cr := t.restarts[name]
	if cr == nil {
		cr = &containerRestart{backoff: newCrashLoopBackoff(r.clk)}
		t.restarts[name] = cr
	}
	if cr.pending || (cr.seenSet && cr.seen == key) {
		return // this termination is already handled (stream+backstop double-delivery)
	}
	cr.seen, cr.seenSet = key, true
	cr.pending = true
	cr.lastTerm = term
	cr.delay = cr.backoff.Next()
	// The re-exec's lifetime is the pod's, not any single RPC's — root a fresh
	// cancelable context (cancelled by cancelRestarts on DeletePod / terminal /
	// CreatePod-replace), mirroring the prober's lifetime pattern.
	ctx, cancel := context.WithCancel(context.Background())
	cr.cancel = cancel
	go r.runRestart(ctx, podID, name, cr.delay)
}

// runRestart waits out the CrashLoopBackOff delay (on the injected clock, so
// tests never sleep) and then re-execs the container via the RestartContainer
// RPC — the runtime action that bumps runtimed's restart_count, the single
// count authority. It clears the pending flag whether the RPC succeeded or
// failed: a failed re-exec leaves the container terminated, and the next
// status observation (same key) does not reschedule — the failure is logged
// and the pod surfaces its honest runtime state.
func (r *runtimedRuntime) runRestart(ctx context.Context, podID, name string, delay time.Duration) {
	select {
	case <-ctx.Done():
		return
	case <-r.clk.After(delay):
	}
	err := r.restartContainerReason(ctx, podID, name, "back-off restarting failed container")
	if t := r.trackByID(podID); t != nil {
		t.restartMu.Lock()
		if cr := t.restarts[name]; cr != nil {
			cr.pending = false
			cr.cancel = nil
		}
		t.restartMu.Unlock()
	}
	if err != nil && ctx.Err() == nil {
		r.log.Warn("exit-driven container restart", "pod", podID, "container", name, "err", err)
	}
}

// applyRestartOverlay synthesizes the CrashLoopBackOff surface for every
// container whose re-exec is pending: state becomes
// waiting.reason=CrashLoopBackOff (message carrying the backoff),
// lastState.terminated carries the triggering exit, Ready/Started drop, and
// the restartCount stays runtimed's verbatim count (never provider-bumped).
// When a MAIN container's re-exec is pending, the pod PHASE is held at Running
// — a restarting pod is Running, never terminal (flipping the phase without
// the re-exec would mask a permanently-dead pod; here the re-exec is
// scheduled by construction). A pending sidecar alone never lifts a phase:
// the mains decide it.
func (r *runtimedRuntime) applyRestartOverlay(pod *corev1.Pod, t *podTrack, st *corev1.PodStatus) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if len(t.restarts) == 0 {
		return
	}
	mainPending := overlayCrashLoop(pod, st.ContainerStatuses, t.restarts)
	overlayCrashLoop(pod, st.InitContainerStatuses, t.restarts)
	if mainPending && (st.Phase == corev1.PodFailed || st.Phase == corev1.PodSucceeded) {
		st.Phase = corev1.PodRunning
	}
}

// overlayCrashLoop rewrites the statuses of pending-restart containers to the
// CrashLoopBackOff waiting shape, reporting whether any rewrite happened.
// Caller holds t.restartMu.
func overlayCrashLoop(pod *corev1.Pod, cs []corev1.ContainerStatus, restarts map[string]*containerRestart) bool {
	pending := false
	for i := range cs {
		cr := restarts[cs[i].Name]
		if cr == nil || !cr.pending {
			continue
		}
		pending = true
		term := cr.lastTerm
		cs[i].LastTerminationState = corev1.ContainerState{Terminated: &term}
		cs[i].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: reasonCrashLoopBackOff,
			Message: fmt.Sprintf("back-off %s restarting failed container=%s pod=%s_%s(%s)",
				cr.delay, cs[i].Name, pod.Name, pod.Namespace, pod.UID),
		}}
		cs[i].Ready = false
		cs[i].Started = ptr(false)
	}
	return pending
}

// cancelRestarts aborts every pending re-exec for the track — called when the
// pod is deleted or its track is replaced by an idempotent CreatePod, so no
// re-exec goroutine outlives the pod it was scheduled for.
func (t *podTrack) cancelRestarts() {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	t.cancelRestartsLocked()
}

// cancelRestartsLocked is cancelRestarts under an already-held t.restartMu
// (the observeExits terminal gate).
func (t *podTrack) cancelRestartsLocked() {
	for _, cr := range t.restarts {
		if cr.cancel != nil {
			cr.cancel()
			cr.cancel = nil
		}
		cr.pending = false
	}
}
