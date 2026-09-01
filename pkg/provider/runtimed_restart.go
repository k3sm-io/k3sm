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

// B26 — the provider is the single exit-driven restart authority on the
// runtimed path. runtimed performs no exit-driven restarts (its contract:
// apis runtime.proto Container.restart_policy); the provider observes every
// container termination via the status stream + the GetPodStatus backstop
// (both converge on buildStatus), decides via the effective-policy resolver
// (shouldRestartOnExit, restartpolicy.go) + the CrashLoopBackOff schedule,
// and re-execs the container in place through the existing RestartContainer
// RPC — the same runtime action the liveness-probe path drives.
//
// Three triggers, one authority: an observed exit (observeExits), a committed
// liveness failure and a failed postStart hook (both via killAndRestart, B39).
//
// Idempotency (binding): the trigger is keyed per container on the
// termination's identity — terminationKey{restart_count, exit code,
// FinishedAt} — inside the podTrack, so a stream+backstop double-delivery of
// the same terminated status never double-restarts. runtimed's restart_count
// is the single count authority (RestartContainer bumps it); the provider
// surfaces it verbatim and keeps no competing counter.
//
// Concurrency: podTrack.restartMu guards the per-container bookkeeping
// (t.restarts), separate from r.mu for the same reason as readyMu — buildStatus
// runs outside r.mu (GetPods snapshots tracks under r.mu, then builds each
// unlocked). Lock order where both are held is always r.mu → restartMu, never
// the reverse. Each pending re-exec is one ctx-bounded goroutine (a pod-lifetime
// context, cancelled by DeletePod / pod-terminal / CreatePod-replace via
// cancelRestarts), so a backoff wait never blocks the watch goroutine and never
// leaks past the pod.
//
// Worker identity (binding): a re-exec worker is handed the *podTrack and
// *containerRestart it was started against, plus its claim generation — it never
// re-resolves them from podID. An idempotent CreatePod for the same pod.UID
// installs a new podTrack while a worker may be blocked inside RestartContainer,
// so a worker that looked its track up on return would mutate the replacement's
// bookkeeping and could release a claim it does not hold — reintroducing the two
// competing restart authorities B26 exists to collapse.

// reasonCrashLoopBackOff is the corev1 waiting reason the provider synthesizes
// while a container sits between its exit and the scheduled re-exec.
const reasonCrashLoopBackOff = "CrashLoopBackOff"

// The reasons recorded on the RestartContainer RPC, one per trigger. Both
// triggers share the bookkeeping, the backoff and the count authority (B26); the
// reason is the only thing that distinguishes them, and runtimed records it in
// the replacement container's last_termination_state.
const (
	restartReasonBackOff   = "back-off restarting failed container"
	restartReasonLiveness  = "liveness probe failed"
	restartReasonPostStart = "post-start hook failed"
)

// terminationKey identifies one observed container termination: runtimed's
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
// podTrack.restarts under restartMu. It is the single authority for both restart
// triggers (B26): the exit-driven path (observeExits) and the liveness-probe
// path (restartForLiveness) share one entry, so there is exactly one backoff
// schedule and one restart-window per container, never two competing ones.
//
// The zero value is not used — restartFor constructs it with a backoff bound to
// the provider clock.
//
// Two distinct flags: `restarting` is the observable window (what the status
// overlay renders), `attempt` is the internal single-worker claim. They are
// written only by the four methods below, so the state machine has one home
// rather than a flag with writers scattered across the file.
type containerRestart struct {
	backoff *crashLoopBackoff
	// seen/seenSet record the last termination identity acted upon (the
	// idempotency latch); seenSet distinguishes "never triggered" from a
	// legitimately zero-valued key.
	seen    terminationKey
	seenSet bool
	// restarting is the restart window: true from the instant a restart is
	// decided (an observed exit, or a committed liveness failure) until the
	// container is observed running again. It outlasts the
	// RestartContainer RPC on purpose: clearing it when the RPC returned — before the
	// replacement process is up — would drop the CrashLoopBackOff surface, the
	// lastState.terminated and the Running phase hold for the length of that
	// window, so a watcher would see a non-monotone Running→Failed→Running flap
	// on every crash. The window closes on evidence (a running container), never
	// on the completion of a call.
	restarting bool
	// attempt is true while the container's single re-exec worker is in flight
	// (scheduled → the RPC finally succeeded or the pod died). It gates
	// scheduling so two workers can never race the same container; it is not the
	// observable window.
	attempt bool
	// attemptGen is the monotone id of the current worker claim, minted by
	// beginAttempt and presented back by the worker that holds it. A claim can
	// therefore only ever be released by its holder: a worker whose claim was
	// aborted mid-RPC (cancelRestarts on an idempotent CreatePod / the terminal
	// gate) and then superseded by a fresh worker presents a stale generation and
	// is ignored. Without this, the stale worker's release would hand a container
	// that already has a worker back to scheduleRestartLocked, which gates solely
	// on `attempt` — two concurrent RestartContainer RPCs and two independent
	// backoff.Next() advances against one schedule, exactly the
	// two-competing-authorities condition B26 exists to eliminate.
	attemptGen uint64
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
// the one predicate the status overlay and the phase hold read.
func (cr *containerRestart) restartInFlight() bool { return cr.restarting }

// beginAttempt claims the container's single re-exec worker slot and opens the
// restart window, returning the claim's generation. It reports false when a
// worker already holds the slot. Caller holds t.restartMu.
func (cr *containerRestart) beginAttempt(cancel context.CancelFunc) (uint64, bool) {
	if cr.attempt {
		return 0, false
	}
	cr.attempt = true
	cr.restarting = true
	cr.cancel = cancel
	cr.attemptGen++
	return cr.attemptGen, true
}

// holdsAttempt reports whether the claim identified by gen is the live one — the
// worker presenting it still owns the container's re-exec slot. A worker whose
// claim was aborted (attempt cleared) or superseded by a newer one (generation
// bumped) does not hold it and must touch no shared bookkeeping. Caller holds
// t.restartMu.
func (cr *containerRestart) holdsAttempt(gen uint64) bool {
	return cr.attempt && cr.attemptGen == gen
}

// endAttempt releases the worker slot held by gen once its re-exec RPC has
// succeeded (or the worker is giving up). It is a no-op for a stale claim, so a
// worker can never release a successor's slot. The restart window stays open —
// only observeRunning closes it. Caller holds t.restartMu.
func (cr *containerRestart) endAttempt(gen uint64) {
	if !cr.holdsAttempt(gen) {
		return
	}
	cr.attempt = false
	cr.cancel = nil
}

// observeRunning closes the restart window: the replacement container has been
// observed running, so the synthesized CrashLoopBackOff surface must give way to
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

// observeExits is the B26 trigger: called from buildStatus on every runtime
// status observation (stream, backstop, direct GetPodStatus), it decides — via
// the effective-policy resolver — which terminated containers are due a
// restart and schedules each re-exec exactly once (see terminationKey).
//
// Scope: regular containers resolve under the pod policy (nil container
// policy); native sidecars (init w/ restartPolicy: Always) resolve under
// effective Always regardless of the pod policy — so a Job pod
// (restartPolicy: Never) keeps its sidecar alive while its mains run. A plain
// init container is never routed here (the documented restartpolicy.go gap:
// Init:CrashLoopBackOff under a held-Pending pod is not implemented).
//
// Terminal gate: when runtimed's mains-only phase is Succeeded/Failed and no
// main container is due a restart, the pod is genuinely terminal (the B74 Job
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
	// Close the window of every container observed running first, so a status
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

// scheduleRestartLocked schedules one re-exec for a decided exit, under
// t.restartMu. The terminationKey latch makes it idempotent: a termination
// already being acted upon or already acted upon is dropped, so double-delivery
// never double-restarts and never advances the backoff twice. The backoff wait
// runs in its own pod-lifetime goroutine (never on the watch goroutine).
//
// A container with a worker already in flight returns without latching the key,
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
	r.startRestartWorkerLocked(t, cr, podID, name, restartReasonBackOff, cr.delay)
}

// restartForLiveness is the liveness trigger of the single restart authority: the
// podProber's restartFunc seam (probe.go) routes here instead of calling
// RestartContainer directly, so a committed liveness failure and an observed
// exit share one containerRestart entry — one restart window, one backoff
// schedule, one surfaced restartCount (runtimed's, bumped by the RPC). Before
// B26 the probe path bypassed all of it, so a liveness restart was invisible to
// the exit-driven bookkeeping and could race a second RestartContainer against it.
//
// ctx is the probe tick's context and is not propagated: the re-exec
// worker's lifetime is the pod's (cancelled by cancelRestarts), not one probe
// tick's. The decision itself is killAndRestart, shared with the postStart-failure
// trigger.
func (r *runtimedRuntime) restartForLiveness(ctx context.Context, podID, container string) error {
	_ = ctx // see the doc comment: the worker is pod-scoped, not tick-scoped
	return r.killAndRestart(podID, container, restartReasonLiveness)
}

// killAndRestart is the kill-a-live-container arm of the single restart authority,
// shared by the two triggers that decide a running container must go: a committed
// liveness failure and a failed postStart hook (B39 — upstream kills the container
// and lets its restart policy restart it). Both are "terminate, then re-spawn",
// which is exactly the RestartContainer RPC, and both must share one
// containerRestart entry so there is one restart window, one backoff schedule and
// one surfaced restartCount.
//
// Backoff parity with the kubelet: a container that is not already crash-looping is
// restarted at once (upstream kills such a container immediately; only a container
// already inside the backoff window is throttled), but the shared schedule advances
// either way, so the next restart of this container — from any trigger — is
// throttled correctly.
//
// It returns an error only when the pod is untracked; a restart already in flight is
// a successful no-op.
func (r *runtimedRuntime) killAndRestart(podID, container, reason string) error {
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
		cr.delay = 0 // kubelet parity: an idle container's kill is immediate
	}
	r.startRestartWorkerLocked(t, cr, podID, container, reason, cr.delay)
	return nil
}

// startRestartWorkerLocked launches the container's single re-exec worker under
// t.restartMu — the one place a restart goroutine is created, shared by both
// triggers. The worker's lifetime is the pod's, not any single RPC's, so it
// roots a fresh cancelable context (cancelled by cancelRestarts on DeletePod /
// terminal / CreatePod-replace), mirroring the prober's lifetime pattern.
//
// The worker is handed the track and the bookkeeping entry it was started
// against, plus its claim generation — never a podID to re-resolve. An
// idempotent CreatePod for the same pod.UID installs a new podTrack
// (runtimed.go) while a worker may be blocked inside RestartContainer; a worker
// that re-resolved r.track[podID] on return would operate on the replacement
// track's bookkeeping. Identity is passed, never looked up.
func (r *runtimedRuntime) startRestartWorkerLocked(t *podTrack, cr *containerRestart, podID, name, reason string, delay time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	gen, ok := cr.beginAttempt(cancel)
	if !ok {
		cancel()
		return
	}
	go r.runRestart(ctx, t, cr, gen, podID, name, reason, delay)
}

// runRestart is the container's single re-exec worker. It waits out the
// CrashLoopBackOff delay (on the injected clock, so tests never sleep), records
// the kubelet's Warning BackOff Event, and re-execs the container via the
// RestartContainer RPC — the runtime action that bumps runtimed's restart_count,
// the single count authority.
//
// A failed RPC is retried under the advanced backoff, indefinitely, until it
// succeeds or the pod goes away (B26). Returning after one failed attempt would
// abandon the container forever: a failed re-exec never bumps runtimed's
// restart_count, so the next status observation reproduces the same
// terminationKey, the idempotency latch drops it, and nothing can ever
// reschedule. Upstream's CrashLoopBackOff is by definition an unbounded retry
// loop, so the worker — not the observer — owns the retry.
//
// It returns once the RPC succeeds — after re-dispatching the container's postStart
// hook, which upstream runs on every container start (B39). The restart window stays
// open until the container is observed running (observeExits → observeRunning),
// which is what keeps the CrashLoopBackOff surface and the Running phase hold stable
// across the swap.
//
// The Warning BackOff Event is emitted only when the attempt actually waited
// (delay > 0). A liveness kill on a container that is not already looping is
// immediate by kubelet parity (restartForLiveness), and upstream surfaces that
// as Unhealthy + Killing — it reserves BackOff for genuine throttling, so
// emitting it here would fire an operator's `reason=BackOff` alert on a single
// probe blip against a healthy container.
func (r *runtimedRuntime) runRestart(ctx context.Context, t *podTrack, cr *containerRestart, gen uint64, podID, name, reason string, delay time.Duration) {
	defer r.finishAttempt(t, cr, gen)
	for {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-r.clk.After(delay):
			}
			r.emitBackOff(podID, name)
		} else if ctx.Err() != nil {
			return
		}
		err := r.restartContainerReason(ctx, podID, name, reason)
		if err == nil {
			// The container has been started again, so its postStart hook fires
			// again (B39): upstream runs the hook inside startContainer, which is
			// the same path a restart takes.
			r.rerunPostStart(t, podID, name)
			return
		}
		if ctx.Err() != nil {
			return // the pod was deleted / replaced while the RPC was in flight
		}
		r.log.Warn("container re-exec failed; retrying under the CrashLoopBackOff schedule",
			"pod", podID, "container", name, "err", err)
		next, ok := r.advanceBackoff(t, cr, gen)
		if !ok {
			return // the claim was aborted or superseded; this worker is stale
		}
		delay = next
	}
}

// finishAttempt releases the worker slot on the bookkeeping entry the worker was
// started against, and only if it still holds claim gen — a stale worker
// releases nothing. The restart window is untouched: it closes only on the
// evidence that the container is running again.
func (r *runtimedRuntime) finishAttempt(t *podTrack, cr *containerRestart, gen uint64) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	cr.endAttempt(gen)
}

// advanceBackoff advances the container's shared CrashLoopBackOff schedule after
// a failed re-exec and publishes the new delay onto the bookkeeping the status
// overlay renders, so a retried attempt surfaces its true back-off. It reports
// false when the calling worker no longer holds the claim (aborted by DeletePod
// / the terminal gate / a CreatePod replace, or superseded) — the worker then
// stops rather than advancing a schedule it does not own.
func (r *runtimedRuntime) advanceBackoff(t *podTrack, cr *containerRestart, gen uint64) (time.Duration, bool) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if !cr.holdsAttempt(gen) {
		return 0, false
	}
	cr.delay = cr.backoff.Next()
	return cr.delay, true
}

// emitBackOff records the kubelet's Warning BackOff Event for a throttled
// container re-exec (callers gate on a non-zero back-off), so `kubectl describe
// pod` on a crash-looping pod shows the crash loop in its Events table (it
// previously showed no evidence at all). It runs outside restartMu and outside
// r.mu — an EventRecorder sink must never be driven while a provider lock is held.
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
// container inside its restart window (exit observed → replacement observed
// running): state becomes waiting.reason=CrashLoopBackOff (message carrying the
// backoff), lastState.terminated carries the triggering exit, Ready/Started
// drop, and the restartCount stays runtimed's verbatim count (never
// provider-bumped). When a main container is restarting, the pod phase is held
// at Running — a restarting pod is Running, never terminal (flipping the phase
// without the re-exec would mask a permanently-dead pod; here the re-exec is
// scheduled by construction). A restarting sidecar alone never lifts a phase:
// the mains decide it.
//
// This overlay is now a belt to derivePhase's braces, not the only guard: since
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

// overlayCrashLoop marks every restarting container not-Ready and, for a
// container that is actually being throttled (delay > 0), rewrites its state to
// the CrashLoopBackOff waiting shape. It reports whether any container was in
// its restart window (which is what holds the pod phase at Running).
//
// The delay > 0 gate is the honesty condition: a liveness kill on a container
// that is not already looping restarts it at once (kubelet parity), so there is
// no back-off to report — rendering CrashLoopBackOff there would both claim a
// crash loop that is not happening and print the self-contradicting "back-off
// 0s". Such a container keeps the runtime's own state and simply reads
// not-Ready, which is exactly upstream's surface for a container failing its
// liveness probe.
//
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
		if cr.delay > 0 {
			cs[i].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason: reasonCrashLoopBackOff,
				Message: fmt.Sprintf("back-off %s restarting failed container=%s pod=%s_%s(%s)",
					cr.delay, cs[i].Name, pod.Name, pod.Namespace, pod.UID),
			}}
		}
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
