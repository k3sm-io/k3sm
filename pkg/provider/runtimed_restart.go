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
	"k8s.io/utils/clock"

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

// The reasons recorded on the RestartContainer RPC, one per TRIGGER. Both
// triggers share the bookkeeping, the backoff and the count authority (B26); the
// reason is the only thing that distinguishes them, and runtimed records it in
// the replacement container's last_termination_state.
const (
	restartReasonBackOff  = "back-off restarting failed container"
	restartReasonLiveness = "liveness probe failed"
)

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

// containerRestart is the per-container restart bookkeeping held in
// podTrack.restarts under restartMu. It is the SINGLE authority for BOTH restart
// triggers (B26): the exit-driven path (observeExits) and the liveness-probe
// path (restartForLiveness) share one entry, so there is exactly one backoff
// schedule and one restart-window per container, never two competing ones.
//
// The zero value is not used — restartFor constructs it with a backoff bound to
// the provider clock.
//
// Two distinct flags, deliberately: `restarting` is the OBSERVABLE window (what
// the status overlay renders), `attempt` is the internal single-worker claim.
// They are written ONLY by the four methods below, so the state machine has one
// home rather than a flag with writers scattered across the file.
type containerRestart struct {
	backoff *crashLoopBackoff
	// seen/seenSet record the last termination identity acted upon (the
	// idempotency latch); seenSet distinguishes "never triggered" from a
	// legitimately zero-valued key.
	seen    terminationKey
	seenSet bool
	// restarting is the RESTART WINDOW: true from the instant a restart is
	// decided (an observed exit, or a committed liveness failure) until the
	// container is observed RUNNING again. It deliberately OUTLASTS the
	// RestartContainer RPC: clearing it when the RPC returned — before the
	// replacement process is up — would drop the CrashLoopBackOff surface, the
	// lastState.terminated and the Running phase hold for the length of that
	// window, so a watcher would see a non-monotone Running→Failed→Running flap
	// on every crash. The window closes on evidence (a running container), never
	// on the completion of a call.
	restarting bool
	// attempt is true while the container's SINGLE re-exec worker is in flight
	// (scheduled → the RPC finally succeeded or the pod died). It gates
	// scheduling so two workers can never race the same container; it is NOT the
	// observable window.
	attempt bool
	// delay is the backoff wait of the in-flight (or most recent) re-exec — the
	// value the CrashLoopBackOff message reports.
	delay time.Duration
	// lastTerm/hasLastTerm is the terminated state that triggered the restart,
	// surfaced as lastState.terminated by the overlay. A liveness-driven restart
	// has none at decision time (the container has not exited yet), so the
	// overlay leaves runtimed's own last_termination_state in place.
	lastTerm    corev1.ContainerStateTerminated
	hasLastTerm bool
	// cancel aborts the in-flight re-exec worker (DeletePod / pod terminal).
	cancel context.CancelFunc
}

// restartInFlight reports whether the container is inside its restart window —
// exit (or liveness kill) observed, replacement not yet observed running. It is
// the ONE predicate the status overlay and the phase hold read.
func (cr *containerRestart) restartInFlight() bool { return cr.restarting }

// beginAttempt claims the container's single re-exec worker slot and opens the
// restart window, reporting false when a worker already holds it. Caller holds
// t.restartMu.
func (cr *containerRestart) beginAttempt(cancel context.CancelFunc) bool {
	if cr.attempt {
		return false
	}
	cr.attempt = true
	cr.restarting = true
	cr.cancel = cancel
	return true
}

// endAttempt releases the worker slot once the re-exec RPC has succeeded. The
// restart WINDOW stays open — only observeRunning closes it. Caller holds
// t.restartMu.
func (cr *containerRestart) endAttempt() {
	cr.attempt = false
	cr.cancel = nil
}

// observeRunning closes the restart window: the replacement container has been
// observed RUNNING, so the synthesized CrashLoopBackOff surface must give way to
// the runtime's own state. Caller holds t.restartMu.
func (cr *containerRestart) observeRunning() {
	cr.restarting = false
	cr.hasLastTerm = false
}

// abort cancels any in-flight re-exec and closes the window — the pod is being
// deleted, replaced, or is genuinely terminal. Caller holds t.restartMu.
func (cr *containerRestart) abort() {
	if cr.cancel != nil {
		cr.cancel()
		cr.cancel = nil
	}
	cr.attempt = false
	cr.restarting = false
}

// restartFor returns the container's bookkeeping entry, creating it (with a
// backoff bound to clk) on first use. Caller holds t.restartMu.
func (t *podTrack) restartFor(name string, clk clock.Clock) *containerRestart {
	if t.restarts == nil {
		t.restarts = map[string]*containerRestart{}
	}
	cr := t.restarts[name]
	if cr == nil {
		cr = &containerRestart{backoff: newCrashLoopBackoff(clk)}
		t.restarts[name] = cr
	}
	return cr
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
	podPolicy := effectivePodRestartPolicy(pod)

	type exit struct {
		name string
		key  terminationKey
		term corev1.ContainerStateTerminated
	}
	var due []exit
	var running []string
	anyMainRestart := false
	collect := func(cs *runtimev1.ContainerStatus, containerPolicy *corev1.ContainerRestartPolicy) bool {
		state := toContainerState(cs.GetState())
		if state.Running != nil {
			// The evidence that closes an open restart window (B26): the
			// replacement process is up.
			running = append(running, cs.GetName())
			return false
		}
		term := state.Terminated
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
	// Close the window of every container observed RUNNING first, so a status
	// carrying both a recovered container and a freshly-crashed one is handled
	// correctly in one pass.
	for _, name := range running {
		if cr := t.restarts[name]; cr != nil {
			cr.observeRunning()
		}
	}
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

// scheduleRestartLocked schedules one re-exec for a decided EXIT, under
// t.restartMu. The terminationKey latch makes it idempotent: a termination
// already being acted upon or already acted upon is dropped, so double-delivery
// never double-restarts and never advances the backoff twice. The backoff wait
// runs in its own pod-lifetime goroutine (never on the watch goroutine).
//
// A container with a worker already in flight returns WITHOUT latching the key,
// so this exit is re-decided on the next status observation (the 10s backstop
// resync guarantees one) rather than being silently swallowed by the worker that
// was handling the previous death.
func (r *runtimedRuntime) scheduleRestartLocked(t *podTrack, podID, name string, key terminationKey, term corev1.ContainerStateTerminated) {
	cr := t.restartFor(name, r.clk)
	if cr.attempt || (cr.seenSet && cr.seen == key) {
		return // already in flight, or already handled (stream+backstop double-delivery)
	}
	cr.seen, cr.seenSet = key, true
	cr.lastTerm, cr.hasLastTerm = term, true
	cr.delay = cr.backoff.Next()
	r.startRestartWorkerLocked(cr, podID, name, restartReasonBackOff, cr.delay)
}

// restartForLiveness is the LIVENESS half of the single restart authority: the
// podProber's restartFunc seam (probe.go) routes here instead of calling
// RestartContainer directly, so a committed liveness failure and an observed
// exit share ONE containerRestart entry — one restart window, one backoff
// schedule, one surfaced restartCount (runtimed's, bumped by the RPC). Before
// B26 the probe path bypassed all of it, so a liveness restart was invisible to
// the exit-driven bookkeeping and could race a second RestartContainer against it.
//
// Backoff parity with the kubelet: a container that is NOT already crash-looping
// is restarted AT ONCE (upstream kills a failed-liveness container immediately;
// only a container already in the backoff window is throttled), but the shared
// schedule advances either way, so the NEXT restart of this container — from
// either trigger — is throttled correctly.
//
// ctx is the probe tick's context and is deliberately NOT propagated: the re-exec
// worker's lifetime is the POD's (cancelled by cancelRestarts), not one probe
// tick's. It returns an error only when the pod is untracked; a restart already
// in flight is a successful no-op.
func (r *runtimedRuntime) restartForLiveness(ctx context.Context, podID, container string) error {
	_ = ctx // see the doc comment: the worker is pod-scoped, not tick-scoped
	t := r.trackByID(podID)
	if t == nil {
		return fmt.Errorf("restart container %s/%s: pod is not tracked", podID, container)
	}
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	cr := t.restartFor(container, r.clk)
	if cr.attempt {
		return nil // a re-exec for this container is already in flight
	}
	hot := cr.backoff.Hot()
	cr.delay = cr.backoff.Next()
	if !hot {
		cr.delay = 0 // kubelet parity: an idle container's liveness kill is immediate
	}
	r.startRestartWorkerLocked(cr, podID, container, restartReasonLiveness, cr.delay)
	return nil
}

// startRestartWorkerLocked launches the container's single re-exec worker under
// t.restartMu — the ONE place a restart goroutine is created, shared by both
// triggers. The worker's lifetime is the pod's, not any single RPC's, so it
// roots a fresh cancelable context (cancelled by cancelRestarts on DeletePod /
// terminal / CreatePod-replace), mirroring the prober's lifetime pattern.
func (r *runtimedRuntime) startRestartWorkerLocked(cr *containerRestart, podID, name, reason string, delay time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	if !cr.beginAttempt(cancel) {
		cancel()
		return
	}
	go r.runRestart(ctx, podID, name, reason, delay)
}

// runRestart is the container's SINGLE re-exec worker. It waits out the
// CrashLoopBackOff delay (on the injected clock, so tests never sleep), records
// the kubelet's Warning BackOff Event, and re-execs the container via the
// RestartContainer RPC — the runtime action that bumps runtimed's restart_count,
// the single count authority.
//
// A FAILED RPC is RETRIED under the advanced backoff, indefinitely, until it
// succeeds or the pod goes away (B26). Returning after one failed attempt would
// abandon the container FOREVER: a failed re-exec never bumps runtimed's
// restart_count, so the next status observation reproduces the SAME
// terminationKey, the idempotency latch drops it, and nothing can ever
// reschedule. Upstream's CrashLoopBackOff is by definition an unbounded retry
// loop, so the worker — not the observer — owns the retry.
//
// It returns once the RPC succeeds; the restart WINDOW stays open until the
// container is observed running (observeExits → observeRunning), which is what
// keeps the CrashLoopBackOff surface and the Running phase hold stable across
// the swap.
func (r *runtimedRuntime) runRestart(ctx context.Context, podID, name, reason string, delay time.Duration) {
	defer r.finishAttempt(podID, name)
	for {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-r.clk.After(delay):
			}
		} else if ctx.Err() != nil {
			return
		}
		r.emitBackOff(podID, name)
		err := r.restartContainerReason(ctx, podID, name, reason)
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			return // the pod was deleted / replaced while the RPC was in flight
		}
		r.log.Warn("container re-exec failed; retrying under the CrashLoopBackOff schedule",
			"pod", podID, "container", name, "err", err)
		next, ok := r.advanceBackoff(podID, name)
		if !ok {
			return // the pod (or its bookkeeping) is gone
		}
		delay = next
	}
}

// finishAttempt releases the container's worker slot when the worker exits. The
// restart window is untouched — it closes only on the evidence that the
// container is running again.
func (r *runtimedRuntime) finishAttempt(podID, name string) {
	t := r.trackByID(podID)
	if t == nil {
		return
	}
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if cr := t.restarts[name]; cr != nil {
		cr.endAttempt()
	}
}

// advanceBackoff advances the container's SHARED CrashLoopBackOff schedule after
// a failed re-exec and publishes the new delay onto the bookkeeping the status
// overlay renders, so a retried attempt surfaces its true back-off. It reports
// false when the pod or its bookkeeping is gone (the worker then stops).
func (r *runtimedRuntime) advanceBackoff(podID, name string) (time.Duration, bool) {
	t := r.trackByID(podID)
	if t == nil {
		return 0, false
	}
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	cr := t.restarts[name]
	if cr == nil {
		return 0, false
	}
	cr.delay = cr.backoff.Next()
	return cr.delay, true
}

// emitBackOff records the kubelet's Warning BackOff Event for a throttled
// container re-exec, so `kubectl describe pod` on a crash-looping pod shows the
// crash loop in its Events table (it previously showed no evidence at all). It
// runs OUTSIDE restartMu and outside r.mu — an EventRecorder sink must never be
// driven while a provider lock is held.
func (r *runtimedRuntime) emitBackOff(podID, container string) {
	pod := r.podByID(podID)
	if pod == nil {
		return
	}
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonBackOff, msgBackOffRestarting(container, pod))
}

// podByID returns the tracked pod object for id under r.mu, or nil when the pod
// was deleted.
func (r *runtimedRuntime) podByID(id string) *corev1.Pod {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t := r.track[id]; t != nil {
		return t.pod
	}
	return nil
}

// applyRestartOverlay synthesizes the CrashLoopBackOff surface for every
// container inside its restart WINDOW (exit observed → replacement observed
// running): state becomes waiting.reason=CrashLoopBackOff (message carrying the
// backoff), lastState.terminated carries the triggering exit, Ready/Started
// drop, and the restartCount stays runtimed's verbatim count (never
// provider-bumped). When a MAIN container is restarting, the pod PHASE is held
// at Running — a restarting pod is Running, never terminal (flipping the phase
// without the re-exec would mask a permanently-dead pod; here the re-exec is
// scheduled by construction). A restarting sidecar alone never lifts a phase:
// the mains decide it.
//
// This overlay is now a BELT to derivePhase's braces, not the only guard: since
// B26 derivePhase itself honors the effective restart policy, so a restartable
// termination reports Running even on a status built before any bookkeeping
// exists. The overlay still owns the surface (Waiting/lastState) and covers the
// window where runtimed reports neither a terminated nor a running container.
func (r *runtimedRuntime) applyRestartOverlay(pod *corev1.Pod, t *podTrack, st *corev1.PodStatus) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if len(t.restarts) == 0 {
		return
	}
	mainRestarting := overlayCrashLoop(pod, st.ContainerStatuses, t.restarts)
	overlayCrashLoop(pod, st.InitContainerStatuses, t.restarts)
	if mainRestarting && (st.Phase == corev1.PodFailed || st.Phase == corev1.PodSucceeded) {
		st.Phase = corev1.PodRunning
	}
}

// overlayCrashLoop rewrites the statuses of restarting containers to the
// CrashLoopBackOff waiting shape, reporting whether any rewrite happened.
// Caller holds t.restartMu.
func overlayCrashLoop(pod *corev1.Pod, cs []corev1.ContainerStatus, restarts map[string]*containerRestart) bool {
	restarting := false
	for i := range cs {
		cr := restarts[cs[i].Name]
		if cr == nil || !cr.restartInFlight() {
			continue
		}
		restarting = true
		if cr.hasLastTerm {
			// A liveness-driven restart has no termination yet — leave runtimed's
			// own last_termination_state rather than fabricating an empty one.
			term := cr.lastTerm
			cs[i].LastTerminationState = corev1.ContainerState{Terminated: &term}
		}
		cs[i].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: reasonCrashLoopBackOff,
			Message: fmt.Sprintf("back-off %s restarting failed container=%s pod=%s_%s(%s)",
				cr.delay, cs[i].Name, pod.Name, pod.Namespace, pod.UID),
		}}
		cs[i].Ready = false
		cs[i].Started = ptr(false)
	}
	return restarting
}

// cancelRestarts aborts every in-flight re-exec for the track — called when the
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
		cr.abort()
	}
}
