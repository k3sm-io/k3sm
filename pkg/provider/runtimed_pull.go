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
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
	runtimed "k3sm.io/runtimed/pkg/runtime"
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
// The retry verb is StartContainer for a pod runtimed HOLDS, and CreatePod for a
// pod it refused to create at all (the parked-create path below): a pod whose
// guest was never built has no container to start, so asking it to start one is
// a NotFound forever. Never RestartContainer: a container that
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
	// The schedules go with the workers. A cancelled schedule paces nothing, and
	// leaving the entries behind would keep rendering an ImagePullBackOff overlay
	// (and, for a replaced track, a park) for a pod that is being torn down. A
	// worker still unwinding holds its own *imagePullRetry pointer, so its
	// generation-claim release is unaffected by the map being emptied.
	clear(t.pulls)
	clear(t.pulling)
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
	// Close every attempt window whose container now reports what its image
	// resolution did. This runs on EVERY observation, parked or not: the Pulled
	// event is owed as soon as an outcome exists, and the outcome is the only
	// thing that says which of the kubelet's two messages is true.
	events = append(events, r.pulledEventsLocked(t, rs)...)
	if t.parked != nil {
		// A pod runtimed never created has exactly ONE thing to retry — the
		// create — so the park owns the single schedule and the per-container
		// filing below is skipped entirely. Skipping it is not an optimisation:
		// the synthesized status stamps each container's OWN image (anything else
		// would be a lie in `kubectl get pod -o yaml`), so the loop below would
		// file one schedule per distinct image and run that many concurrent
		// CreatePod retries for one pod.
		events = append(events, r.observeParkedLocked(t, podID)...)
		t.restartMu.Unlock()
		for _, e := range events {
			r.recordPodEvent(podID, e)
		}
		return
	}
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
		reason, message, err := r.attemptPull(ctx, t, podID, image)
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
	reason, message, err := r.attemptPull(ctx, t, podID, image)
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
func (r *runtimedRuntime) startWaitingContainers(ctx context.Context, pod *corev1.Pod, podID, image string) (runtimev1.FailureReason, string, error) {
	names := containersWithImage(pod, image)
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
	// A parked pod has one schedule for the whole pod (see observePulls), so
	// every container waiting on the refusal follows it — including the ones
	// whose own image is a different reference.
	var park *imagePullRetry
	parkImage := ""
	if t.parked != nil {
		park, parkImage = t.pulls[t.parked.image], t.parked.image
	}
	overlayPullBackOff(pod, st.ContainerStatuses, t.pulls, park, parkImage)
	overlayPullBackOff(pod, st.InitContainerStatuses, t.pulls, park, parkImage)
	// The failed attempt has now been published once; from here the surface
	// follows the schedule (see imagePullRetry.firstReport).
	for _, pr := range t.pulls {
		pr.firstReport = false
	}
}

// overlayPullBackOff rewrites ErrImagePull to ImagePullBackOff for every
// container whose image is mid-sleep. park, when non-nil, is the single schedule
// of a parked pod and overrides the per-image lookup for every waiting
// container. Caller holds t.restartMu.
func overlayPullBackOff(pod *corev1.Pod, cs []corev1.ContainerStatus, pulls map[string]*imagePullRetry, park *imagePullRetry, parkImage string) {
	for i := range cs {
		w := cs[i].State.Waiting
		if w == nil || w.Reason != reasonErrImagePull {
			continue
		}
		ref := imageRefFor(pod, cs[i].Name, cs[i].Image)
		pr := pulls[ref]
		if park != nil {
			pr, ref = park, parkImage
		}
		if pr == nil || !pr.sleeping || pr.firstReport {
			continue
		}
		w.Reason = reasonImagePullBackOff
		w.Message = msgBackOffPullingImage(ref)
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

// ---------------------------------------------------------------------------
// Pull PROGRESS: the Pulling → Pulled pair
// ---------------------------------------------------------------------------

// pullAttempt is one dispatched start attempt for a container whose image has to
// be resolved: the Pulling event has been recorded, and the matching Pulled
// event is OWED until a status carries that attempt's image_pull outcome.
//
// It is per CONTAINER rather than per image because the outcome is: two
// containers naming one image are resolved separately by the runtime, and each
// gets its own answer about whether the fetch happened. Held in podTrack.pulling
// under restartMu, beside the retry schedules, so one lock covers the whole pull
// surface.
type pullAttempt struct {
	image string
	// at is the clock time the Pulling event was recorded, the base of the
	// kubelet's "(%v including waiting)" duration.
	at time.Time
}

// containerImage is a declared container and the image reference it names.
type containerImage struct {
	name  string
	image string
}

// pullableContainers names every declared container (init and main) whose image
// the runtime must RESOLVE, in start order. only, when non-empty, restricts the
// selection to the containers naming that reference.
//
// A host-binary route is excluded: runtimed's resolveBinary takes the native
// sentinel and an absolute-path reference in place, never parsing them as image
// references and never contacting a registry (pinned on the runtime side by
// runtimed's TestHostBinaryRoutesNeverReachTheReferenceParser). Announcing a
// pull for one would report work that provably does not happen.
func pullableContainers(pod *corev1.Pod, only string) []containerImage {
	if pod == nil {
		return nil
	}
	var out []containerImage
	add := func(cs []corev1.Container) {
		for i := range cs {
			c := &cs[i]
			if c.Image == "" || isHostBinaryContainer(c) {
				continue
			}
			if only != "" && c.Image != only {
				continue
			}
			out = append(out, containerImage{name: c.Name, image: c.Image})
		}
	}
	add(pod.Spec.InitContainers)
	add(pod.Spec.Containers)
	return out
}

// isHostBinaryContainer is isHostBinaryRoute's pod-spec twin, applying the same
// discriminator to the corev1 container the provider still has in hand on the
// paths that never build a PodBox (a retry, a status observation). The two must
// agree: translate.go copies Command/Args onto the box verbatim, so they read
// the same fields.
func isHostBinaryContainer(c *corev1.Container) bool {
	if c.Image == runtimed.NativeImage {
		return true
	}
	return len(c.Command) == 0 && len(c.Args) == 0 && image.IsHostPathReference(c.Image)
}

// notePullDispatch opens the attempt window for each container an imminent start
// attempt will resolve an image for, returning the Pulling Events to record
// OUTSIDE every provider lock.
//
// It is called from exactly ONE place per attempt — attemptPull, on the worker
// that is about to make the call, plus CreatePod for the first attempt of all.
// An observer that merely SCHEDULES an attempt must not call it too: upstream
// records one Pulling per trip through its image manager, and a second dispatch
// also REPLACES the attempt window, which resets the base of the
// "(… including waiting)" duration the eventual Pulled reports.
func (r *runtimedRuntime) notePullDispatch(t *podTrack, cs []containerImage) []podEvent {
	if len(cs) == 0 {
		return nil
	}
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if t.pulling == nil {
		t.pulling = map[string]*pullAttempt{}
	}
	now := r.clk.Now()
	out := make([]podEvent, 0, len(cs))
	for _, ci := range cs {
		// A re-dispatch REPLACES the window: the previous attempt's outcome never
		// arrived (it failed), and the duration the next Pulled reports must be
		// this attempt's, not the abandoned one's.
		t.pulling[ci.name] = &pullAttempt{image: ci.image, at: now}
		out = append(out, podEvent{corev1.EventTypeNormal, reasonPulling, msgPullingImage(ci.image)})
	}
	return out
}

// pulledEventsLocked closes every open attempt window whose container now
// reports an image_pull outcome, returning the Pulled Events. Emitting is
// once-per-attempt by construction: the window is deleted as it is closed, and
// only a fresh dispatch reopens one. Caller holds t.restartMu.
//
// Which of the kubelet's two messages applies is READ from runtimed's outcome,
// never inferred: "already present on machine" and "successfully pulled in %v"
// are claims about what the node did, and the container state, the resolved
// image and the image id look identical either way.
func (r *runtimedRuntime) pulledEventsLocked(t *podTrack, rs *runtimev1.PodStatus) []podEvent {
	if len(t.pulling) == 0 {
		return nil
	}
	now := r.clk.Now()
	var out []podEvent
	scan := func(css []*runtimev1.ContainerStatus) {
		for _, cs := range css {
			op := cs.GetImagePull()
			at := t.pulling[cs.GetName()]
			if op == nil || at == nil {
				continue
			}
			delete(t.pulling, cs.GetName())
			ref := at.image
			if ref == "" {
				ref = cs.GetImage()
			}
			if !op.GetPulled() {
				out = append(out, podEvent{corev1.EventTypeNormal, reasonPulled, msgImageAlreadyPresent(ref)})
				continue
			}
			out = append(out, podEvent{corev1.EventTypeNormal, reasonPulled,
				msgPulledImage(ref, op.GetDuration().AsDuration(), now.Sub(at.at))})
		}
	}
	scan(rs.GetContainerStatuses())
	scan(rs.GetInitContainerStatuses())
	return out
}

// ---------------------------------------------------------------------------
// The PARKED create: a pod whose CreatePod the runtime refused for an image
// ---------------------------------------------------------------------------

// createFailure is the provider-side record of a CreatePod runtimed refused for
// a CONTAINER-class image failure, held in podTrack.parked under restartMu.
//
// Why the record exists at all: on the vm spine the whole pod is one guest, so
// an image that cannot be resolved fails the CREATE rather than leaving a
// container Waiting inside a pod that exists (runtimed's resolveVMContainers
// returns before CreateVM). Returning that refusal to virtual-kubelet lands the
// pod ProviderFailed — a TERMINAL phase — for a condition upstream reports as a
// retryable ImagePullBackOff. The visible cost is not cosmetic: a ReplicaSet
// whose Pod goes Failed creates a replacement, so a registry outage turns into
// unbounded Pod churn against the registry that is down, and `kubectl get pod`
// shows a fresh Pending pod each time instead of one pod with a backoff. So the
// provider keeps the pod, reports the kubelet's waiting surface for it, and
// retries the create on the same schedule a started pod's failed pull gets.
//
// The record is what makes that surface possible: runtimed holds nothing for
// this pod, so every status the provider publishes for it is synthesized, and
// this is the only place the cause survives.
type createFailure struct {
	// reason/message are runtimed's typed cause and its bounded message, updated
	// by each failed retry so the surface reports the current cause.
	reason  runtimev1.FailureReason
	message string
	// image is the reference the failure is attributed to — the schedule key, so
	// the retry cadence is the same (pod UID × image) key the started-pod path
	// uses.
	image string
	// container, when set, is the single container the refusal named; the rest of
	// the pod then reports ContainerCreating. Empty means the failure is
	// attributed pod-wide and every container reports it.
	container string
}

// isContainerClassFailure reports whether a CreatePod refusal is about a
// CONTAINER's image rather than about the pod.
//
// It is a CLOSED list, deliberately, and not pullClassFor's forward-compatible
// default: parking a pod means telling virtual-kubelet the create SUCCEEDED, and
// a wrong yes hides a genuinely failed pod behind a Pending that retries
// forever. The waiting-reason path can afford to guess "probably an image"
// because the worst case there is a mislabelled reason on a pod that is already
// visibly stuck; this one cannot. A future runtimed reason is therefore an
// error return until it is added here on purpose.
func isContainerClassFailure(fr runtimev1.FailureReason) bool {
	switch fr {
	case runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME,
		runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
		runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL,
		runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH,
		runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL,
		runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG,
		runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED:
		return true
	default:
		return false
	}
}

// parkedFailure returns the track's create-refusal record, or nil for a pod the
// runtime created.
func (t *podTrack) parkedFailure() *createFailure {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.parked
}

// updateParked refreshes the record with the cause of the latest failed retry,
// keeping the schedule key: the backoff is per (pod UID × image), and the image
// being retried has not changed.
func (t *podTrack) updateParked(reason runtimev1.FailureReason, message string) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if t.parked == nil {
		return
	}
	t.parked.reason, t.parked.message = reason, message
}

// markDeleting closes the track to any further create. DeletePod sets it BEFORE
// it cancels a worker, so a create RPC already in flight cannot find the track
// live once the delete has begun. See podTrack.deleting for why cancellation
// alone is not enough.
func (t *podTrack) markDeleting() {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	t.deleting = true
}

// parkCreate records a refused create, files its retry schedule, and announces
// the failure with the same Events the started-pod path emits.
func (r *runtimedRuntime) parkCreate(pod *corev1.Pod, t *podTrack, reason runtimev1.FailureReason, message string) {
	cf := &createFailure{reason: reason, message: message}
	cf.image, cf.container = attributeCreateFailure(pod, message)
	podID := string(pod.UID)
	events := []podEvent{pullEventFor(pullObservation{
		container: cf.container, image: cf.image, message: message, reason: reason,
	})}

	t.restartMu.Lock()
	t.parked = cf
	events = append(events, r.observeParkedLocked(t, podID)...)
	t.restartMu.Unlock()

	for _, e := range events {
		r.recordPodEvent(podID, e)
	}
}

// observeParkedLocked keeps a parked pod's SINGLE schedule filed and paces the
// classes that have no exponential worker, returning any Events to record
// outside the lock. It runs on every status observation, so a schedule a worker
// retired (its class stopped fitting) is re-filed from the current cause rather
// than leaving the pod parked with nothing left to retry it.
//
// Caller holds t.restartMu and t.parked is non-nil.
func (r *runtimedRuntime) observeParkedLocked(t *podTrack, podID string) []podEvent {
	cf := t.parked
	cls := pullClassFor(cf.reason)
	pr, fresh := t.pullFor(cf.image, cls, r.clk)
	pr.class, pr.reason, pr.message = cls, cf.reason, cf.message
	// One pod, one create, one schedule: drop anything a previous life of this
	// track filed under another reference.
	for ref, other := range t.pulls {
		if ref != cf.image && !other.attempt {
			delete(t.pulls, ref)
		}
	}
	switch {
	case fresh:
		pr.lastAttempt = r.clk.Now()
		pr.firstReport = true
		if cls == pullClassBackoff {
			r.startPullWorkerLocked(t, pr, podID, cf.image)
		}
		// The refusal's own Events belong to the caller that observed it
		// (parkCreate, or the worker whose attempt failed), not to this filing.
		return nil
	case cls == pullClassResync && !pr.attempt && !r.clk.Now().Before(pr.lastAttempt.Add(resyncInterval)):
		pr.lastAttempt = r.clk.Now()
		events := []podEvent{pullEventFor(pullObservation{
			container: cf.container, image: cf.image, message: cf.message, reason: cf.reason,
		})}
		// The attempt's own Pulling belongs to the worker that makes the call
		// (attemptPull), exactly as on the started-pod resync branch above.
		r.startPullOnceLocked(t, pr, podID, cf.image)
		return events
	default:
		return nil
	}
}

// attributeCreateFailure decides which image a wholesale refusal is about, and
// whether one container owns it.
//
// runtimed's vm refusals are shaped `container <name>: pull image "<ref>": …`,
// so both facts are usually present in the bounded message. The message is read
// only to MATCH strings the pod itself declares — never parsed for content — so
// a message that says something unexpected degrades to a pod-wide attribution
// rather than mis-naming a container.
//
// A NAMED container wins, and wins first: the refusal is that container's
// failure, so only it carries the typed reason and the bounded message, and the
// rest of the pod reports ContainerCreating. That is the truth for them — they
// never started because the POD could not be created, not because of anything
// about their own images, and stamping a registry error about someone else's
// image onto every container of the pod says otherwise in `kubectl get pod`.
// The named container's own declared image keys the schedule, so the retry
// cadence stays the (pod UID × image) key the started-pod path uses.
//
// NOTHING named ⇒ the failure is the pod's and every container reports it,
// because on the vm spine no container exists and none will until the create
// succeeds; the schedule keys on the single named image when there is one, and
// otherwise on the pod's first declared image, which is the one the runtime
// resolves first.
func attributeCreateFailure(pod *corev1.Pod, message string) (string, string) {
	cs := pullableContainers(pod, "")
	var named []string
	seen := map[string]bool{}
	for _, ci := range cs {
		if seen[ci.image] || !strings.Contains(message, ci.image) {
			continue
		}
		seen[ci.image] = true
		named = append(named, ci.image)
	}
	container := ""
	for _, ci := range cs {
		if strings.Contains(message, "container "+ci.name+":") {
			container = ci.name
			break
		}
	}
	switch {
	case container != "":
		return imagesByContainer(pod)[container], container
	case len(named) > 0:
		return named[0], ""
	case len(cs) > 0:
		return cs[0].image, ""
	default:
		return "", ""
	}
}

// parkedRuntimeStatus synthesizes the runtime status of a parked pod: Pending,
// with the refusal rendered as each container's waiting entry. It carries the
// TYPED failure_reason, so translate.go maps it to the kubelet's waiting reason
// through the one table both paths use.
//
// Each container reports its OWN image, never the failing one, because
// ContainerStatus.image is what `kubectl get pod -o yaml` prints for it.
func parkedRuntimeStatus(pod *corev1.Pod, cf *createFailure) *runtimev1.PodStatus {
	rs := &runtimev1.PodStatus{PodId: string(pod.UID), Phase: runtimev1.PodPhase_POD_PHASE_PENDING}
	entry := func(c *corev1.Container) *runtimev1.ContainerStatus {
		if cf.container != "" && c.Name != cf.container {
			return creatingContainerStatus(c, reasonContainerCreating)
		}
		return &runtimev1.ContainerStatus{
			Name:  c.Name,
			Image: c.Image,
			State: &runtimev1.ContainerState{Waiting: &runtimev1.ContainerStateWaiting{
				Message:       cf.message,
				FailureReason: cf.reason,
			}},
		}
	}
	for i := range pod.Spec.InitContainers {
		rs.InitContainerStatuses = append(rs.InitContainerStatuses, entry(&pod.Spec.InitContainers[i]))
	}
	for i := range pod.Spec.Containers {
		rs.ContainerStatuses = append(rs.ContainerStatuses, entry(&pod.Spec.Containers[i]))
	}
	return rs
}

// synthesizedStatus is the provider's own answer for a tracked pod the RUNTIME
// does not report: the CreatePod call window, or a pod whose create runtimed
// refused for an image failure and the provider parked.
func (r *runtimedRuntime) synthesizedStatus(pod *corev1.Pod, t *podTrack) *runtimev1.PodStatus {
	if cf := t.parkedFailure(); cf != nil {
		return parkedRuntimeStatus(pod, cf)
	}
	return creatingRuntimeStatus(pod)
}

// attemptPull runs one re-attempt for the schedule keyed by image, announcing it
// with the kubelet's Pulling Event first.
//
// It is the ONE place the two retry verbs are chosen between: a pod runtimed
// holds is re-attempted with StartContainer for the containers naming this
// image, and a parked pod is re-attempted with the whole CreatePod, because
// nothing exists there to start.
func (r *runtimedRuntime) attemptPull(ctx context.Context, t *podTrack, podID, image string) (runtimev1.FailureReason, string, error) {
	pod := r.trackPod(t)
	parked := t.parkedFailure() != nil
	// A parked retry rebuilds the WHOLE pod, so every pullable container is part
	// of this attempt; a started pod's retry touches only this image.
	selector := image
	if parked {
		selector = ""
	}
	for _, e := range r.notePullDispatch(t, pullableContainers(pod, selector)) {
		r.recordPodEvent(podID, e)
	}
	if parked {
		return r.retryParkedCreate(ctx, pod, t)
	}
	return r.startWaitingContainers(ctx, pod, podID, image)
}

// retryParkedCreate re-runs the create for a parked pod and, on success,
// completes it exactly as CreatePod would have.
//
// It repeats CreatePod's address allocation and translation rather than sharing
// its whole body on purpose: the two refusals CreatePod makes BEFORE the RPC —
// the image-platform preflight and the Xcode-toolchain warning — are decided by
// this node's capabilities and this pod's annotations, neither of which a retry
// can have changed, and the preflight's contract is that a pod it refuses leaves
// no track at all. Re-running them here would either re-warn on every retry or
// have to un-track a pod that is already tracked.
//
// A create that SUCCEEDS is committed according to WHY it could be committed —
// commitParkedCreate returns the reason and this function acts on it. The RPC is
// the one call in this path that changes the runtime's state before the provider
// gets a say, and the provider's own cancellation does not reach into it:
// DeletePod cancels this worker's context, but a guest the runtime has already
// built stays built. So a create that raced a DELETE is undone, a create whose
// pod was taken over by an idempotent successor is left where it is, and a create
// that merely outlived its own schedule is adopted.
//
// A retry that fails for a POD-LEVEL reason cannot un-park the pod — VK is long
// past its CreatePod call and there is no error channel left — and has no
// kubelet waiting reason to render, so the STATUS keeps the last image-class
// cause while the new one is published where it is not a lie: the Warning Event
// the caller records from the returned message, and the node log.
func (r *runtimedRuntime) retryParkedCreate(ctx context.Context, pod *corev1.Pod, t *podTrack) (runtimev1.FailureReason, string, error) {
	if pod == nil {
		return runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND, "", nil
	}
	ctx = withPodIdentity(ctx, pod)
	podIP, err := r.podIP(ctx, pod)
	if err != nil {
		return runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, "",
			fmt.Errorf("allocate pod ip %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	box, err := r.buildBox(ctx, pod, podIP)
	if err != nil {
		return runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, "",
			fmt.Errorf("translate pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	resp, err := r.rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		return runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, "",
			fmt.Errorf("runtimed create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		t.updateParked(resp.GetFailureReason(), e.GetMessage())
		return resp.GetFailureReason(), e.GetMessage(), nil
	}
	switch r.commitParkedCreate(t, string(pod.UID)) {
	case commitDeleted:
		r.compensateLateCreate(pod)
		// NOT_FOUND ends the schedule (pullClassNone), which is the truth: there
		// is no pod left to retry a create for.
		return runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND, "", nil
	case commitSuperseded:
		// Nothing to undo and nothing to adopt. runtimed's CreatePod is idempotent
		// on pod id, so the successor's own create resolves to the SAME guest this
		// one just built; a compensating delete here would tear down the pod the
		// successor has already been told it owns, and the successor's create
		// would never be replayed to rebuild it.
		r.log.Info("a parked pod's create landed after an idempotent re-create took the pod over; leaving it to the successor",
			"namespace", pod.Namespace, "name", pod.Name, "pod", string(pod.UID))
		return runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND, "", nil
	}
	r.completeCreate(pod, t, resp.GetStatus())
	return runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, "", nil
}

// commitReason is WHY a create that has just landed could (or could not) be
// committed to the track that asked for it. The three answers demand three
// different actions, and collapsing them into "committed / not" is what made a
// bare cancellation look identical to a delete.
type commitReason int

const (
	// commitAdopted: the track is still the live one for this pod id and no
	// delete has begun, so the guest belongs to this pod. It has been unparked.
	commitAdopted commitReason = iota
	// commitDeleted: the pod is being (or has been) deleted, so nothing will ever
	// reference this guest again — the caller must delete it.
	commitDeleted
	// commitSuperseded: an idempotent CreatePod installed a successor track for
	// the same UID. The guest is the successor's; the caller must leave it alone.
	commitSuperseded
)

// commitParkedCreate decides how a create that has just LANDED may be committed,
// and performs the adoption in the same critical section as the decision.
//
// The GENERATION claim is deliberately NOT part of this decision, though every
// other schedule mutation checks it. A claim answers "does this worker still own
// the schedule?", and the question here is "does this pod still own the guest the
// runtime just built?" — which the schedule cannot speak to. An image re-key
// (retryPullsForChangedImages) drops the claim of a live pod's in-flight retry
// without touching the pod, so a claim-gated commit answered a routine
// `kubectl set image` by deleting a running pod. A create for a UID this provider
// still tracks, and is not deleting, is adopted whatever became of the claim: the
// live paths reconcile any drift between the adopted guest and the current spec
// from there.
//
// Order matters between the two remaining checks. DeletePod sets podTrack.deleting
// BEFORE it removes the track (runtimed.go), so a delete is visible as deleting
// whether or not the track is still installed — while the reverse reading, "the
// track is not installed", cannot tell a delete from a replace. deleting is
// therefore decisive, and the track lookup only distinguishes the other two. The
// unpark happens under the SAME restartMu deleting is read under, so a DeletePod
// cannot slip between the check and the commit: either it marks first and this
// answers commitDeleted, or it marks second and finds an ordinary tracked pod to
// tear down.
//
// Lock order is r.mu → restartMu, as everywhere else.
func (r *runtimedRuntime) commitParkedCreate(t *podTrack, podID string) commitReason {
	r.mu.Lock()
	live := r.track[podID]
	r.mu.Unlock()
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	switch {
	case t.deleting:
		return commitDeleted
	case live == t:
		t.parked = nil
		return commitAdopted
	case live != nil:
		return commitSuperseded
	default:
		// No track at all and this one was never marked: the id was deleted after
		// a successor had taken it over, so the successor's delete carried the
		// deleting flag and this track never saw it. Nothing owns the guest.
		return commitDeleted
	}
}

// compensateLateCreate deletes a pod the runtime created for a retry the
// provider can no longer adopt, retrying until the delete lands.
//
// Without it the create is a RESURRECTION: virtual-kubelet is long past its
// DeletePod, the track is gone, and runtimed's DeletePod for a pod id it does
// not know is a no-op — so the delete that raced this create can never be
// replayed against it, and the guest outlives every reference to it. The one
// process that knows the create happened is this one.
//
// Which is also why a FAILED compensating delete may not simply be logged: this
// is the last reference to the guest in the whole system, so dropping it on a
// transport error leaks exactly what the compensation exists to prevent, and
// nothing re-arms it. The retry runs on the shared crashLoopBackoff primitive
// (never a second schedule) against the provider clock, and is recorded in
// r.compensating so a second late create for the same id joins the loop already
// running instead of starting a rival one.
//
// It roots its own delete calls at context.Background: the worker's context was
// cancelled by the very delete being compensated for, and a cancelled context
// would make the compensating delete a no-op. Its LOOP is bounded by the
// provider's lifetime instead (r.lifetime), so a shutdown mid-retry ends it with
// an explicit error rather than a goroutine nobody can stop.
func (r *runtimedRuntime) compensateLateCreate(pod *corev1.Pod) {
	podID := string(pod.UID)
	r.mu.Lock()
	already := r.compensating[podID]
	if !already {
		if r.compensating == nil {
			r.compensating = map[string]bool{}
		}
		r.compensating[podID] = true
	}
	r.mu.Unlock()
	if already {
		return
	}
	r.log.Warn("a parked pod's create landed after the pod was deleted; deleting it again",
		"namespace", pod.Namespace, "name", pod.Name, "pod", podID)
	go r.runCompensatingDelete(pod, podID)
}

// runCompensatingDelete is compensateLateCreate's single retry loop for one pod
// id. It returns only when the delete has landed or the provider is shutting
// down, and clears the pod's entry in r.compensating either way.
func (r *runtimedRuntime) runCompensatingDelete(pod *corev1.Pod, podID string) {
	defer func() {
		r.mu.Lock()
		delete(r.compensating, podID)
		r.mu.Unlock()
	}()
	backoff := newCrashLoopBackoff(r.clk)
	for {
		_, err := r.rt.DeletePod(context.Background(),
			&runtimev1.DeletePodRequest{PodId: podID, GracePeriodSeconds: 0})
		if err == nil {
			return
		}
		r.log.Warn("could not delete the pod a late create left behind; retrying under the back-off",
			"namespace", pod.Namespace, "name", pod.Name, "pod", podID, "err", err)
		select {
		case <-r.lifetime:
			r.log.Error("the provider is shutting down with a compensating delete still owed; the pod will outlive its Pod object",
				"namespace", pod.Namespace, "name", pod.Name, "pod", podID)
			return
		case <-r.clk.After(backoff.Next()):
		}
	}
}

// retryPullsForChangedImages is the UpdatePod half of the cadence rules: a
// container whose image reference changed is a different pull, so its old
// schedule is cancelled and forgotten, and the new reference is attempted at
// once. This is the ONLY thing that unsticks an InvalidImageName container,
// whose reference is deterministic and can never parse differently — the
// troubleshooting doc names `kubectl set image` for exactly this.
//
// The re-attempt is filed as a schedule in t.pulls and run by the SAME
// generation-claimed worker machinery every other re-attempt uses; it is never a
// bare goroutine. That is the whole difference between "the pod's retry" and "a
// goroutine that happens to mention the pod": a tracked worker's context is
// cancelled by cancelPulls when the pod is deleted or its track replaced, and a
// goroutine rooted at context.Background is reachable by nothing — it would go
// on talking to runtimed about a pod that no longer exists, and on a node
// churning pods it accumulates one such goroutine per image edit.
//
// The fresh schedule is a RESYNC-class one-shot rather than an exponential
// worker, whatever the old reference's class was: a spec change earns exactly
// one immediate attempt, and if it fails, the next status observation carries
// runtimed's typed reason for the NEW reference and re-classifies from that.
// Inheriting the old class would pace the new image by the old one's failures.
//
// It runs before the UpdatePod RPC: re-keying is provider-side bookkeeping and
// must not wait on the runtime to answer.
func (r *runtimedRuntime) retryPullsForChangedImages(t *podTrack, old, updated *corev1.Pod) {
	if t == nil || old == nil || updated == nil {
		return
	}
	previous := imagesByContainer(old)
	var staleRefs, freshRefs []string
	seen := map[string]bool{}
	for name, ref := range imagesByContainer(updated) {
		was, ok := previous[name]
		if !ok || was == ref || seen[ref] {
			continue
		}
		seen[ref] = true
		staleRefs = append(staleRefs, was)
		freshRefs = append(freshRefs, ref)
	}
	if len(freshRefs) == 0 {
		return
	}
	podID := string(updated.UID)

	t.restartMu.Lock()
	for _, ref := range staleRefs {
		if pr := t.pulls[ref]; pr != nil {
			pr.abort()
			delete(t.pulls, ref)
		}
	}
	for _, ref := range freshRefs {
		pr, _ := t.pullFor(ref, pullClassResync, r.clk)
		pr.class = pullClassResync
		pr.lastAttempt = r.clk.Now()
		// No Pulling is announced here: the worker started below announces its own
		// (notePullDispatch), and a second dispatch would double the event and
		// reset the attempt window it opens.
		r.startPullOnceLocked(t, pr, podID, ref)
	}
	t.restartMu.Unlock()
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
