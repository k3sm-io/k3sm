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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The provider is the image-pull RETRY authority on the runtimed path, exactly
// as it is the exit-driven restart authority next door (runtimed_restart.go).
//
// The ownership split (binding): runtimed owns the container's waiting STATE —
// it attempted the start, it recorded the typed failure_reason and the bounded
// message on ContainerStateWaiting, and it will re-attempt only when asked. The
// provider owns the SCHEDULE — when to ask again, how long to wait, and which
// kubelet waiting reason the pod reports meanwhile. Neither half guesses at the
// other's: the provider never inspects a message to classify a failure (the
// typed reason is the contract), and runtimed never runs a retry loop.
//
// The retry verb is StartContainer, never RestartContainer: a container that
// never started has no process to replace, and RestartContainer's contract is to
// bump restart_count and record a last termination. Driving a pull retry through
// it would report a growing restart count for a container that has restarted
// zero times, which upstream reads as a crash loop and a Job counts against its
// backoff limit. runtimed refuses RestartContainer on a never-started container
// for the same reason.
//
// Cadence, per upstream's own re-evaluation rules:
//
//   - IMAGE_PULL / IMAGE_PULL_CREDENTIAL / IMAGE_NO_PLATFORM_MATCH /
//     SIGNATURE_REJECTED get the exponential schedule (10s→300s, the SAME
//     crashLoopBackoff primitive the restart path uses — never a second
//     schedule), because the cause is external and may heal on its own.
//   - IMAGE_NEVER_PULL and CONTAINER_CONFIG are re-attempted once per backstop
//     resync with no exponential growth, matching the kubelet's per-sync
//     re-derivation of image presence and container config: a `k3sm image load`
//     or a fixed Secret heals the pod without touching it.
//   - INVALID_IMAGE_NAME is re-attempted only when the pod spec changes the
//     container's image, because parsing an unchanged reference is deterministic.
//
// Keying: podTrack.pulls is keyed by IMAGE REFERENCE and the track is already
// per pod UID, so the schedule is per (pod UID × image) — the kubelet's own key.
// Two containers of one pod sharing a bad image share one schedule and are
// re-attempted together.
//
// Concurrency: podTrack.pulls is guarded by the EXISTING restartMu (see the
// field doc). Both maps feed the same buildStatus overlay chain, so one lock is
// the honest shape; a second mutex would only add a lock-order rule with nothing
// to buy. Each schedule has at most one worker, holding a generation-stamped
// claim, handed the *podTrack and *imagePullRetry it was started against — never
// a podID to re-resolve — so an idempotent CreatePod that installs a fresh track
// cannot have the old worker write into the successor's bookkeeping. Events are
// recorded outside every provider lock.
//
// State is IN-MEMORY and lost on a provider restart, which starts every schedule
// again at the 10s base. The kubelet's pull backoff has the same property across
// a kubelet restart, so this is parity, not a divergence.

// pullRetryClass is the re-attempt cadence a typed failure earns.
type pullRetryClass int

const (
	// pullClassNone is "no schedule at all": a non-failure wait, or an RPC-level
	// refusal that says nothing about the container's image.
	pullClassNone pullRetryClass = iota
	// pullClassBackoff is the exponential 10s→300s schedule.
	pullClassBackoff
	// pullClassResync is one re-attempt per backstop resync, no growth.
	pullClassResync
	// pullClassSpecChange is "only a new pod spec can help".
	pullClassSpecChange
)

// pullClassFor maps a typed failure to its re-attempt cadence.
//
// The default arm mirrors waitingReasonFor's: an unknown value is an image or
// container-start failure by the proto's forward-compatibility rule, so it earns
// the retry schedule rather than being silently abandoned. NOT_FOUND and
// NOT_UPDATABLE are the two answers that are about the RPC rather than the
// container's image (the pod is gone; the container already has a process), and
// they end a schedule instead of pacing one.
func pullClassFor(fr runtimev1.FailureReason) pullRetryClass {
	switch fr {
	case runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED,
		runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
		runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE:
		return pullClassNone
	case runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME:
		return pullClassSpecChange
	case runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL,
		runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG:
		return pullClassResync
	default:
		return pullClassBackoff
	}
}

// imagePullRetry is the provider-owned retry schedule for one (pod, image)
// pair, held in podTrack.pulls under restartMu.
//
// See the file comment for the ownership split it implements: runtimed owns the
// waiting state this schedule paces re-attempts against, the provider owns the
// schedule, and the backoff itself is the crashLoopBackoff primitive shared with
// the restart authority.
//
// The zero value is not used — pullFor constructs it with a backoff bound to the
// provider clock.
type imagePullRetry struct {
	class   pullRetryClass
	backoff *crashLoopBackoff
	// reason/message are the last typed cause observed for this image, kept so a
	// re-classification (the cause changed between attempts) is visible to the
	// next observation.
	reason  runtimev1.FailureReason
	message string
	// delay is the wait of the in-flight (or most recent) attempt.
	delay time.Duration
	// sleeping is true while the worker is waiting out delay. It is the ONE
	// predicate applyPullOverlay reads: sleeping renders ImagePullBackOff, the
	// attempt window renders ErrImagePull, which is upstream's alternation.
	sleeping bool
	// lastAttempt is the clock time of the most recent re-attempt, the
	// resync-cadence gate for the classes that have no exponential schedule.
	lastAttempt time.Time
	// firstReport holds the ErrImagePull surface for exactly one published
	// status: the schedule is armed by the same observation that first sees the
	// failure, and its worker can begin sleeping before that status is even
	// rendered, which would publish ImagePullBackOff for an attempt whose own
	// failure was never reported. Upstream always shows the failed attempt
	// first, so the overlay skips its flip once and clears the flag.
	firstReport bool
	// attempt/attemptGen are the single-worker claim, with the same
	// generation discipline as containerRestart: a claim can only be released by
	// its holder, so a worker aborted mid-RPC and superseded by a fresh one
	// cannot hand a live schedule back to the scheduler.
	attempt    bool
	attemptGen uint64
	// cancel aborts the in-flight worker (DeletePod / CreatePod replace).
	cancel context.CancelFunc
}

// newImagePullRetry builds a schedule of class cls with a backoff bound to clk.
func newImagePullRetry(cls pullRetryClass, clk clock.Clock) *imagePullRetry {
	return &imagePullRetry{class: cls, backoff: newCrashLoopBackoff(clk)}
}

// beginAttempt claims the schedule's single worker slot, returning the claim's
// generation. It reports false when a worker already holds it. Caller holds
// t.restartMu.
func (pr *imagePullRetry) beginAttempt(cancel context.CancelFunc) (uint64, bool) {
	if pr.attempt {
		return 0, false
	}
	pr.attempt = true
	pr.cancel = cancel
	pr.attemptGen++
	return pr.attemptGen, true
}

// holdsAttempt reports whether gen is the live claim. Caller holds t.restartMu.
func (pr *imagePullRetry) holdsAttempt(gen uint64) bool {
	return pr.attempt && pr.attemptGen == gen
}

// endAttempt releases the worker slot held by gen; a no-op for a stale claim, so
// a superseded worker can never release its successor's slot. Caller holds
// t.restartMu.
func (pr *imagePullRetry) endAttempt(gen uint64) {
	if !pr.holdsAttempt(gen) {
		return
	}
	pr.attempt = false
	pr.sleeping = false
	pr.cancel = nil
}

// abort cancels any in-flight worker — the pod is being deleted or replaced.
// Caller holds t.restartMu.
func (pr *imagePullRetry) abort() {
	if pr.cancel != nil {
		pr.cancel()
		pr.cancel = nil
	}
	pr.attempt = false
	pr.sleeping = false
}

// pullFor returns the schedule for an image reference, creating it on first use.
// Caller holds t.restartMu.
func (t *podTrack) pullFor(image string, cls pullRetryClass, clk clock.Clock) (*imagePullRetry, bool) {
	if t.pulls == nil {
		t.pulls = map[string]*imagePullRetry{}
	}
	if pr := t.pulls[image]; pr != nil {
		return pr, false
	}
	pr := newImagePullRetry(cls, clk)
	t.pulls[image] = pr
	return pr, true
}

// cancelPulls aborts every in-flight pull retry for the track — called when the
// pod is deleted or its track is replaced by an idempotent CreatePod, so no
// retry goroutine outlives the pod it was scheduled for. It mirrors
// cancelRestarts and is called at exactly the same sites.
func (t *podTrack) cancelPulls() {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	for _, pr := range t.pulls {
		pr.abort()
	}
}

// dropPullsFor cancels and forgets the schedules of the named image references —
// the UpdatePod re-key: a container whose image changed is a different pull, so
// the old reference's schedule (and its worker) has nothing left to retry, and
// the next failure starts a fresh schedule at the 10s base.
func (t *podTrack) dropPullsFor(images []string) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	for _, image := range images {
		if pr := t.pulls[image]; pr != nil {
			pr.abort()
			delete(t.pulls, image)
		}
	}
}

// pullObservation is one container reported Waiting for a typed reason.
type pullObservation struct {
	container string
	image     string
	message   string
	reason    runtimev1.FailureReason
}

// observePulls is the pull-failure trigger, called from buildStatus on every
// runtime status observation (stream, backstop, direct GetPodStatus) beside its
// exit-driven twin. It files a retry schedule per failing image, fires the
// resync-cadence re-attempts, and drops the schedule of an image no container
// waits on any more (the pull healed, or the pod stopped declaring it).
//
// A schedule with a live worker is never dropped here: the worker owns its own
// lifetime and drops the entry itself when an attempt finally succeeds. That is
// what keeps a momentarily-stale status observation from cancelling a working
// retry loop and resetting its back-off to the base delay.
func (r *runtimedRuntime) observePulls(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus) {
	if pod == nil || rs == nil {
		return
	}
	obs := collectPullFailures(pod, rs)
	podID := rs.GetPodId()
	if podID == "" {
		podID = string(pod.UID)
	}
	var events []podEvent

	t.restartMu.Lock()
	live := make(map[string]bool, len(obs))
	for _, o := range obs {
		live[o.image] = true
		cls := pullClassFor(o.reason)
		pr, fresh := t.pullFor(o.image, cls, r.clk)
		pr.class, pr.reason, pr.message = cls, o.reason, o.message
		switch {
		case fresh:
			// The failure runtimed just reported: announce it once, and arm the
			// schedule its class earns.
			pr.lastAttempt = r.clk.Now()
			pr.firstReport = true
			events = append(events, pullEventFor(o))
			if cls == pullClassBackoff {
				r.startPullWorkerLocked(t, pr, podID, o.image)
			}
		case cls == pullClassResync && !pr.attempt && !r.clk.Now().Before(pr.lastAttempt.Add(resyncInterval)):
			// Upstream re-derives image presence and container config on every pod
			// sync; this is that sync, on the provider's own backstop cadence.
			pr.lastAttempt = r.clk.Now()
			events = append(events, pullEventFor(o))
			r.startPullOnceLocked(t, pr, podID, o.image)
		}
	}
	for ref, pr := range t.pulls {
		if live[ref] || pr.attempt {
			continue
		}
		delete(t.pulls, ref)
	}
	t.restartMu.Unlock()

	for _, e := range events {
		r.recordPodEvent(podID, e)
	}
}

// collectPullFailures extracts every container (init or main) the runtime
// reports Waiting for a typed cause that earns a schedule. A container whose
// image reference cannot be resolved at all is skipped: the schedule is keyed by
// reference, so there would be nothing to key it on.
func collectPullFailures(pod *corev1.Pod, rs *runtimev1.PodStatus) []pullObservation {
	var out []pullObservation
	collect := func(css []*runtimev1.ContainerStatus) {
		for _, cs := range css {
			w := cs.GetState().GetWaiting()
			if w == nil || pullClassFor(w.GetFailureReason()) == pullClassNone {
				continue
			}
			image := imageRefFor(pod, cs.GetName(), cs.GetImage())
			if image == "" {
				continue
			}
			out = append(out, pullObservation{
				container: cs.GetName(),
				image:     image,
				message:   w.GetMessage(),
				reason:    w.GetFailureReason(),
			})
		}
	}
	collect(rs.GetContainerStatuses())
	collect(rs.GetInitContainerStatuses())
	return out
}

// pullEventFor is the Event a freshly observed (or re-evaluated) failure
// records, one per kubelet reason class.
func pullEventFor(o pullObservation) podEvent {
	switch o.reason {
	case runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME:
		return podEvent{corev1.EventTypeWarning, reasonInspectFailed, msgInspectFailed(o.image, o.message)}
	case runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL:
		return podEvent{corev1.EventTypeWarning, reasonErrImageNeverPull, msgImageNeverPull(o.image)}
	case runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG:
		return podEvent{corev1.EventTypeWarning, reasonFailed, msgContainerConfigError(o.message)}
	default:
		return podEvent{corev1.EventTypeWarning, reasonFailed, msgFailedPullImage(o.image, o.message)}
	}
}

// recordPodEvent records one Event against the tracked pod. It runs outside
// restartMu and outside r.mu.
//
// podEvent is the buffered-Event record this package already uses on the
// HostProcess path (hostprocess.go): an Event queued while a lock is held and
// recorded after it is released, because an EventRecorder sink must never be
// driven under a provider lock.
func (r *runtimedRuntime) recordPodEvent(podID string, e podEvent) {
	pod := r.podByID(podID)
	if pod == nil {
		return
	}
	r.recorder.Event(pod, e.eventtype, e.reason, e.message)
}

// startPullWorkerLocked launches the schedule's single exponential worker under
// t.restartMu — the one place a pull-retry goroutine is created for the backoff
// class. The worker roots a fresh cancelable context (cancelled by cancelPulls
// on DeletePod / the CreatePod replace), so its lifetime is the pod's.
func (r *runtimedRuntime) startPullWorkerLocked(t *podTrack, pr *imagePullRetry, podID, image string) {
	ctx, cancel := context.WithCancel(context.Background())
	gen, ok := pr.beginAttempt(cancel)
	if !ok {
		cancel()
		return
	}
	pr.delay = pr.backoff.Next()
	go r.runPullRetry(ctx, t, pr, gen, podID, image)
}

// startPullOnceLocked launches a SINGLE re-attempt for a resync-cadence class
// under t.restartMu. It takes the same worker claim as the exponential path, so
// two resync ticks can never have two attempts in flight for one image, and
// cancelPulls aborts it exactly as it aborts a worker.
func (r *runtimedRuntime) startPullOnceLocked(t *podTrack, pr *imagePullRetry, podID, image string) {
	ctx, cancel := context.WithCancel(context.Background())
	gen, ok := pr.beginAttempt(cancel)
	if !ok {
		cancel()
		return
	}
	go r.runPullOnce(ctx, t, pr, gen, podID, image)
}

// runPullRetry is the image's single retry worker: sleep the schedule's delay on
// the injected clock (so tests never sleep), then ask runtimed to start every
// container of the pod that names this image, and repeat.
//
// An RPC-level failure is retried under the SAME schedule, indefinitely, exactly
// as the re-exec worker does (runtimed_restart.go): a transport failure says
// nothing about the image, and returning would abandon the container forever —
// nothing else re-arms a pull schedule, because a failed attempt changes no
// status the observer could act on.
//
// A typed failure whose class is no longer the exponential one (the cause
// changed under us, or the pod is gone) ends the loop instead of pacing a
// schedule that no longer fits; the next status observation files the right one.
func (r *runtimedRuntime) runPullRetry(ctx context.Context, t *podTrack, pr *imagePullRetry, gen uint64, podID, image string) {
	defer r.finishPullAttempt(t, pr, gen)
	for {
		delay, ok := r.beginPullSleep(t, pr, gen)
		if !ok {
			return // the claim was aborted or superseded; this worker is stale
		}
		r.recordPodEvent(podID, podEvent{corev1.EventTypeNormal, reasonBackOff, msgBackOffPullingImage(image)})
		select {
		case <-ctx.Done():
			return
		case <-r.clk.After(delay):
		}
		if !r.endPullSleep(t, pr, gen) {
			return
		}
		reason, message, err := r.startWaitingContainers(ctx, t, podID, image)
		if ctx.Err() != nil {
			return // the pod was deleted / replaced while the RPC was in flight
		}
		switch {
		case err != nil:
			r.log.Warn("image pull retry could not reach the runtime; retrying under the pull back-off",
				"pod", podID, "image", image, "err", err)
		case reason == runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED:
			r.dropPull(t, pr, gen, image)
			return
		case pullClassFor(reason) != pullClassBackoff:
			r.log.Warn("image pull retry failed for a cause with no exponential schedule; dropping it",
				"pod", podID, "image", image, "reason", reason.String())
			r.dropPull(t, pr, gen, image)
			return
		default:
			r.log.Warn("image pull retry failed; retrying under the pull back-off",
				"pod", podID, "image", image, "reason", reason.String(), "err", message)
			r.recordPodEvent(podID, podEvent{corev1.EventTypeWarning, reasonFailed, msgFailedPullImage(image, message)})
		}
		if !r.advancePullBackoff(t, pr, gen) {
			return
		}
	}
}

// runPullOnce is the resync-cadence re-attempt: one StartContainer round for the
// image, no schedule, no sleep. Its Event was recorded by the observer that
// decided the re-evaluation was due (upstream records one per sync that finds
// the image absent), so a failure here only logs.
func (r *runtimedRuntime) runPullOnce(ctx context.Context, t *podTrack, pr *imagePullRetry, gen uint64, podID, image string) {
	defer r.finishPullAttempt(t, pr, gen)
	reason, message, err := r.startWaitingContainers(ctx, t, podID, image)
	switch {
	case ctx.Err() != nil:
		return
	case err != nil:
		r.log.Warn("resync-cadence image re-attempt could not reach the runtime",
			"pod", podID, "image", image, "err", err)
	case reason == runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED:
		r.dropPull(t, pr, gen, image)
	default:
		r.log.Warn("resync-cadence image re-attempt failed; it is re-attempted once per resync",
			"pod", podID, "image", image, "reason", reason.String(), "err", message)
	}
}

// startWaitingContainers asks runtimed to start every container of the pod that
// names image, returning the first typed failure (UNSPECIFIED when they all
// started) and its bounded message, or a transport error.
//
// A NOT_UPDATABLE refusal is skipped rather than reported: it means the
// container already has a process (it started, or another attempt won the race),
// which is not this schedule's failure.
func (r *runtimedRuntime) startWaitingContainers(ctx context.Context, t *podTrack, podID, image string) (runtimev1.FailureReason, string, error) {
	names := containersWithImage(r.trackPod(t), image)
	failReason := runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED
	failMessage := ""
	for _, name := range names {
		resp, err := r.rt.StartContainer(ctx, &runtimev1.StartContainerRequest{PodId: podID, Container: name})
		if err != nil {
			return runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, "", err
		}
		e := resp.GetError()
		if e == nil || e.GetCode() == 0 {
			continue
		}
		if resp.GetFailureReason() == runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			continue
		}
		failReason = resp.GetFailureReason()
		failMessage = resp.GetStatus().GetState().GetWaiting().GetMessage()
		if failMessage == "" {
			failMessage = e.GetMessage()
		}
	}
	return failReason, failMessage, nil
}

// beginPullSleep opens the schedule's sleep window (the ImagePullBackOff
// surface) and returns the delay to wait. It reports false when the calling
// worker no longer holds the claim.
func (r *runtimedRuntime) beginPullSleep(t *podTrack, pr *imagePullRetry, gen uint64) (time.Duration, bool) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if !pr.holdsAttempt(gen) {
		return 0, false
	}
	pr.sleeping = true
	return pr.delay, true
}

// endPullSleep closes the sleep window: the attempt is about to run, so the
// container reads ErrImagePull again.
func (r *runtimedRuntime) endPullSleep(t *podTrack, pr *imagePullRetry, gen uint64) bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if !pr.holdsAttempt(gen) {
		return false
	}
	pr.sleeping = false
	return true
}

// advancePullBackoff advances the schedule after a failed attempt so the next
// wait — and the surface the operator reads — grows. It reports false when the
// calling worker no longer holds the claim.
func (r *runtimedRuntime) advancePullBackoff(t *podTrack, pr *imagePullRetry, gen uint64) bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if !pr.holdsAttempt(gen) {
		return false
	}
	pr.delay = pr.backoff.Next()
	pr.lastAttempt = r.clk.Now()
	return true
}

// dropPull retires the schedule its holder just satisfied (or found unfit): the
// entry is removed so the next observation of a fresh failure starts a new
// schedule at the base delay. A stale claim drops nothing.
func (r *runtimedRuntime) dropPull(t *podTrack, pr *imagePullRetry, gen uint64, image string) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if !pr.holdsAttempt(gen) {
		return
	}
	pr.endAttempt(gen)
	if t.pulls[image] == pr {
		delete(t.pulls, image)
	}
}

// finishPullAttempt releases the worker slot on the entry the worker was started
// against, and only if it still holds the claim.
func (r *runtimedRuntime) finishPullAttempt(t *podTrack, pr *imagePullRetry, gen uint64) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	pr.endAttempt(gen)
}

// applyPullOverlay renders the ErrImagePull ↔ ImagePullBackOff alternation on
// top of the translated status. translate.go stays a pure function of runtimed's
// report — it maps the typed failure to ErrImagePull — and this overlay, which
// is the only place that can see the provider's schedule, flips a container to
// ImagePullBackOff for exactly as long as its image's schedule is sleeping.
// During the attempt window the container reads ErrImagePull with runtimed's own
// message, which is the alternation `kubectl get pod` shows upstream.
//
// It runs after applyRestartOverlay (a crash-looping container's
// CrashLoopBackOff surface is a different waiting reason and is untouched here)
// and before applyPostStartOverlay, which must stay last so its readiness
// re-derivation sees every other verdict.
func (r *runtimedRuntime) applyPullOverlay(pod *corev1.Pod, t *podTrack, st *corev1.PodStatus) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if len(t.pulls) == 0 {
		return
	}
	overlayPullBackOff(pod, st.ContainerStatuses, t.pulls)
	overlayPullBackOff(pod, st.InitContainerStatuses, t.pulls)
	// The failed attempt has now been published once; from here the surface
	// follows the schedule (see imagePullRetry.firstReport).
	for _, pr := range t.pulls {
		pr.firstReport = false
	}
}

// overlayPullBackOff rewrites ErrImagePull to ImagePullBackOff for every
// container whose image is mid-sleep. Caller holds t.restartMu.
func overlayPullBackOff(pod *corev1.Pod, cs []corev1.ContainerStatus, pulls map[string]*imagePullRetry) {
	for i := range cs {
		w := cs[i].State.Waiting
		if w == nil || w.Reason != reasonErrImagePull {
			continue
		}
		image := imageRefFor(pod, cs[i].Name, cs[i].Image)
		pr := pulls[image]
		if pr == nil || !pr.sleeping || pr.firstReport {
			continue
		}
		w.Reason = reasonImagePullBackOff
		w.Message = msgBackOffPullingImage(image)
	}
}

// creatingRuntimeStatus synthesizes the status of a pod the provider tracks but
// the runtime does not know yet — the CreatePod call window, which is otherwise
// reported as NotFound and makes a pod that IS being created look like a pod
// that does not exist.
//
// Every declared container reads Waiting: init containers and the mains of an
// init-free pod are ContainerCreating; the mains of a pod that declares init
// containers are PodInitializing, because they are waiting on the init sequence
// rather than on their own creation. Both are non-failure waits, so they carry
// no failure_reason and no retry schedule is filed for them.
func creatingRuntimeStatus(pod *corev1.Pod) *runtimev1.PodStatus {
	rs := &runtimev1.PodStatus{PodId: string(pod.UID), Phase: runtimev1.PodPhase_POD_PHASE_PENDING}
	mainReason := reasonContainerCreating
	if len(pod.Spec.InitContainers) > 0 {
		mainReason = reasonPodInitializing
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		rs.InitContainerStatuses = append(rs.InitContainerStatuses, creatingContainerStatus(c, reasonContainerCreating))
	}
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		rs.ContainerStatuses = append(rs.ContainerStatuses, creatingContainerStatus(c, mainReason))
	}
	return rs
}

// creatingContainerStatus is one synthesized non-failure waiting entry.
func creatingContainerStatus(c *corev1.Container, reason string) *runtimev1.ContainerStatus {
	return &runtimev1.ContainerStatus{
		Name:  c.Name,
		Image: c.Image,
		State: &runtimev1.ContainerState{Waiting: &runtimev1.ContainerStateWaiting{Reason: reason}},
	}
}

// retryPullsForChangedImages is the UpdatePod half of the cadence rules: a
// container whose image reference changed is a different pull, so its old
// schedule is cancelled and forgotten, and the new reference is attempted at
// once. This is the ONLY thing that unsticks an InvalidImageName container,
// whose reference is deterministic and can never parse differently — the
// troubleshooting doc names `kubectl set image` for exactly this.
//
// It runs before the UpdatePod RPC: re-keying is provider-side bookkeeping and
// must not wait on the runtime to answer.
func (r *runtimedRuntime) retryPullsForChangedImages(t *podTrack, old, updated *corev1.Pod) {
	if t == nil || old == nil || updated == nil {
		return
	}
	previous := imagesByContainer(old)
	var staleRefs []string
	var changed []string
	for name, image := range imagesByContainer(updated) {
		was, ok := previous[name]
		if !ok || was == image {
			continue
		}
		staleRefs = append(staleRefs, was)
		changed = append(changed, name)
	}
	if len(changed) == 0 {
		return
	}
	t.dropPullsFor(staleRefs)
	podID := string(updated.UID)
	go func() {
		for _, name := range changed {
			resp, err := r.rt.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: podID, Container: name})
			switch {
			case err != nil:
				r.log.Warn("start container after an image change could not reach the runtime",
					"pod", podID, "container", name, "err", err)
			case resp.GetError() != nil && resp.GetError().GetCode() != 0 &&
				resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE:
				r.log.Warn("start container after an image change failed; it stays waiting",
					"pod", podID, "container", name, "reason", resp.GetFailureReason().String())
			}
		}
	}()
}

// imagesByContainer maps every declared container (init and main) to its image
// reference.
func imagesByContainer(pod *corev1.Pod) map[string]string {
	out := make(map[string]string, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	for i := range pod.Spec.InitContainers {
		out[pod.Spec.InitContainers[i].Name] = pod.Spec.InitContainers[i].Image
	}
	for i := range pod.Spec.Containers {
		out[pod.Spec.Containers[i].Name] = pod.Spec.Containers[i].Image
	}
	return out
}

// containersWithImage names every declared container of pod whose image is ref.
func containersWithImage(pod *corev1.Pod, ref string) []string {
	if pod == nil {
		return nil
	}
	var out []string
	for name, image := range imagesByContainer(pod) {
		if image == ref {
			out = append(out, name)
		}
	}
	return out
}

// imageRefFor resolves the image reference a container's schedule is keyed by:
// the runtime's own report when it has one (runtimed stamps the spec image on a
// waiting container's status), falling back to the pod spec so a status rendered
// without it still keys correctly.
func imageRefFor(pod *corev1.Pod, container, reported string) string {
	if reported != "" {
		return reported
	}
	if pod == nil {
		return ""
	}
	return imagesByContainer(pod)[container]
}

// trackPod returns the track's current desired-spec Pod under r.mu (UpdatePod
// replaces the pointer under that lock). Lock order is r.mu → restartMu, so this
// is never called with restartMu held.
func (r *runtimedRuntime) trackPod(t *podTrack) *corev1.Pod {
	r.mu.Lock()
	defer r.mu.Unlock()
	return t.pod
}
