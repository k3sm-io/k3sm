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
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The kubelet's spec.activeDeadlineSeconds enforcement for a bare Pod
// (pkg/kubelet/active_deadline.go): a pod active on the node longer than its
// deadline is stopped and reported Failed with reason DeadlineExceeded. k3sm
// decides on the 10 s status backstop (resync), so the failure lands up to one
// resyncInterval late; there is no per-pod timer.

const (
	// reasonDeadlineExceeded and msgDeadlineExceeded are the kubelet's reason and
	// message for a pod failed past its active deadline.
	reasonDeadlineExceeded = "DeadlineExceeded"
	msgDeadlineExceeded    = "Pod was active on the node longer than the specified deadline"
)

// deadlineStopSlack is added to a pod's effective termination grace to bound
// one deadline stop: it covers the runtime's own post-kill steps (reaping the
// processes, tearing down the pod's mounts and network) after the grace ends.
// A variable, not a constant, so a test can shorten it.
var deadlineStopSlack = 30 * time.Second

// deadlineStopGrace is the grace a deadline stop sends to the runtime: the
// pod's own effective termination grace, floored.
func deadlineStopGrace(pod *corev1.Pod) int64 {
	return floorGrace(graceSeconds(pod))
}

// activeDeadlineExceeded reports whether a pod with the given
// spec.activeDeadlineSeconds and status.startTime has outlived its deadline at
// now. A nil deadline or a nil start time is never exceeded, as in the kubelet.
func activeDeadlineExceeded(deadline *int64, start *metav1.Time, now time.Time) bool {
	if deadline == nil || start == nil {
		return false
	}
	return now.Sub(start.Time) >= time.Duration(*deadline)*time.Second
}

// isDeadlineExceededPod reports whether the apiserver object pod is a pod this
// node (or a previous run of it) failed past its active deadline.
func isDeadlineExceededPod(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodFailed && pod.Status.Reason == reasonDeadlineExceeded
}

// enforceActiveDeadlines fails every tracked pod, running or parked, that has
// outlived its active deadline. It runs on the backstop tick only: a status read
// never stops a pod. The deadline is read from the tracked spec each time, so an
// UpdatePod that changes it is honoured on the next tick.
func (r *runtimedRuntime) enforceActiveDeadlines(ctx context.Context) {
	now := r.clk.Now()
	type tracked struct {
		pod *corev1.Pod
		t   *podTrack
	}
	r.mu.Lock()
	var due, owed []tracked
	for _, t := range r.track {
		if t == nil || t.pod == nil {
			continue
		}
		if t.unpersistedStatus() != nil {
			owed = append(owed, tracked{pod: t.pod, t: t})
			continue
		}
		start := deadlineStart(t)
		if activeDeadlineExceeded(t.pod.Spec.ActiveDeadlineSeconds, start, now) {
			due = append(due, tracked{pod: t.pod, t: t})
		}
	}
	r.mu.Unlock()
	for _, d := range owed {
		if trackDeleting(d.t) {
			continue
		}
		r.persistDeadlineStatus(ctx, d.pod, d.t, false)
	}
	for _, d := range due {
		if d.t.rejected || d.t.evictedStatus() != nil || d.t.isStopping() || trackDeleting(d.t) {
			continue
		}
		r.startDeadlineStop(ctx, d.pod, d.t)
	}
}

// startDeadlineStop takes t's stopping mark on the tick, so a later tick sees
// the mark and starts no second stop, then runs the stop itself in one
// goroutine per pod: the runtime stop can take the pod's whole termination
// grace, and several pods expiring together must not hold the tick's status
// publication behind each other. The stopping mark is not a status: readers go
// on reporting the live pod until the stop succeeds and failPastDeadline
// records Failed, so a stop that fails never shows Failed and then Running.
//
// Locking: the mark, its completion and its rollback are t.restartMu's
// (markStopping, finishStopping, clearStopping); the goroutine holds only its
// own *podTrack and takes no provider lock across the RPC. Lifetime: the
// goroutine's context keeps ctx's values but is cancelled by the provider's
// lifetime (r.lifetime, closed by shutdown), not by the tick, and is bounded by
// the stop's grace plus deadlineStopSlack (real time: lifetimeContext has no
// clock), so a runtime stop that hangs cannot hold the stopping mark, and with
// it the pod's fence, for the daemon's life; a timed-out stop is a failed stop
// and the next tick retries it. It is counted in
// r.deadlineStops, added under r.mu only while the lifetime is open, and
// shutdown waits for it. A provider already shut down starts no stop and takes
// no mark.
func (r *runtimedRuntime) startDeadlineStop(ctx context.Context, tracked *corev1.Pod, t *podTrack) {
	r.mu.Lock()
	select {
	case <-r.lifetime:
		r.mu.Unlock()
		return
	default:
	}
	r.deadlineStops.Add(1)
	r.mu.Unlock()
	prior := r.podWithStatus(ctx, tracked, t)
	// A pod that reached a terminal phase on its own (a restartPolicy Never pod
	// that Succeeded, or Failed, inside its deadline) is not active, so the
	// kubelet's deadline leaves it alone, as the eviction ranking does
	// (evictionCandidates). The check sits here, not in enforceActiveDeadlines'
	// collection loop, because the phase needs podWithStatus's runtime
	// GetPodStatus, which must not run under r.mu.
	switch prior.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		r.deadlineStops.Done()
		return
	}
	st := failedPodStatus(prior.Status, reasonDeadlineExceeded, msgDeadlineExceeded, metav1.NewTime(r.clk.Now()))
	if !t.markStopping(prior.Status.DeepCopy()) {
		r.deadlineStops.Done()
		return
	}
	go func() {
		defer r.deadlineStops.Done()
		lifeCtx, cancelLife := r.lifetimeContext(ctx)
		defer cancelLife()
		bound := time.Duration(deadlineStopGrace(tracked))*time.Second + deadlineStopSlack
		stopCtx, cancel := context.WithTimeout(lifeCtx, bound)
		defer cancel()
		err := r.failPastDeadline(stopCtx, tracked, t, st)
		timedOut := err != nil && errors.Is(stopCtx.Err(), context.DeadlineExceeded)
		// A stop that keeps failing is retried every resync: the first failure
		// of a pod logs at Warn, the repeats at Debug, until a stop succeeds.
		t.restartMu.Lock()
		repeat := t.deadlineStopFailed
		t.deadlineStopFailed = err != nil
		t.restartMu.Unlock()
		if err != nil {
			// A timeout always logs at Warn: each takes the whole bound, so its
			// repeats are already spaced out.
			log := r.log.Warn
			if repeat && !timedOut {
				log = r.log.Debug
			}
			msg := "active deadline: could not stop the pod; retrying on the next resync"
			if timedOut {
				msg = "active deadline: the pod's stop timed out; retrying on the next resync"
			}
			log(msg, "pod", podKey(tracked.Namespace, tracked.Name), "uid", string(tracked.UID),
				"timeout", bound, "err", err)
		}
	}()
}

// lifetimeContext returns a context carrying parent's values that is cancelled
// when the provider's lifetime ends (r.lifetime), or by the returned cancel.
func (r *runtimedRuntime) lifetimeContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	go func() {
		select {
		case <-r.lifetime:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// deadlineStart is the start the active deadline counts from: the earlier of the
// track's own start and the apiserver pod's status.startTime. A daemon that
// restarts after a deadline stop but before the Failed status was written sees
// the pod Running with its first life's startTime and creates it again under a
// fresh wall-clock start; the earlier time fails it again on the first resync
// instead of granting it a second full deadline. Either may be unset. Guarded by
// r.mu (t.pod).
func deadlineStart(t *podTrack) *metav1.Time {
	var start *metav1.Time
	if !t.startTime.IsZero() {
		start = &t.startTime
	}
	if api := t.pod.Status.StartTime; api != nil && !api.IsZero() && (start == nil || api.Before(start)) {
		start = api
	}
	return start
}

// unpersistedStatus returns the deadline failure status t still owes the
// apiserver, or nil.
func (t *podTrack) unpersistedStatus() *corev1.PodStatus {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.unpersisted
}

// persistDeadlineStatus writes t's owed deadline failure status to the apiserver
// (UID-checked, persistEvictedStatus) and clears the debt once the write lands,
// the pod was replaced under its name, or the pod is gone. A failure keeps the
// debt for the next resync; only the first attempt logs above Debug.
//
// The first write, from the stop's goroutine, takes persistEvictedStatus's full
// back-off. A retry from the resync tick is one attempt with no back-off: the
// next resync is the retry, and several owed pods against an apiserver that is
// down must not stall the tick behind each other's back-off.
func (r *runtimedRuntime) persistDeadlineStatus(ctx context.Context, pod *corev1.Pod, t *podTrack, first bool) {
	st := t.unpersistedStatus()
	if st == nil {
		return
	}
	write := r.persistDeadlineStatusOnce
	if first {
		write = r.persistEvictedStatus
	}
	if err := write(ctx, pod, st); err != nil && !apierrors.IsNotFound(err) {
		log := r.log.Debug
		if first {
			log = r.log.Error
		}
		log("active deadline: could not persist the failed status to the apiserver; retrying on the next resync",
			"pod", podKey(pod.Namespace, pod.Name), "uid", string(pod.UID), "err", err)
		return
	}
	t.restartMu.Lock()
	if t.unpersisted == st {
		t.unpersisted = nil
	}
	t.restartMu.Unlock()
}

// deadlineStatusWriteTimeout bounds one per-tick deadline status write so a hung apiserver call cannot stall the resync tick.
const deadlineStatusWriteTimeout = 5 * time.Second

// persistDeadlineStatusOnce is one attempt of persistEvictedStatus's write, with
// no back-off: UID-checked, and a nil client is a no-op.
func (r *runtimedRuntime) persistDeadlineStatusOnce(ctx context.Context, pod *corev1.Pod, st *corev1.PodStatus) error {
	if r.client == nil {
		return nil
	}
	// A timeout is an ordinary failed attempt: the debt stays and the next tick retries.
	ctx, cancel := context.WithTimeout(ctx, deadlineStatusWriteTimeout)
	defer cancel()
	live, err := r.client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if live.UID != pod.UID {
		r.log.Warn("active deadline: the apiserver pod was replaced; not writing the failed status",
			"pod", podKey(pod.Namespace, pod.Name), "uid", string(pod.UID), "live_uid", string(live.UID))
		return nil
	}
	live.Status = *st.DeepCopy()
	_, err = r.client.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, live, metav1.UpdateOptions{})
	return err
}

// failPastDeadline stops a pod past its active deadline in evictPod's shape and
// records it Failed, reason DeadlineExceeded, with no DisruptionTarget condition.
// The caller has taken the stopping mark (startDeadlineStop); the terminal
// status st is recorded only once the stop succeeds or the runtime answers
// not-found, and a failed stop clears the stopping mark and publishes nothing,
// so the next tick retries it; the pod's last live status stays readable until
// then, and the retry builds its Failed status from it (clearStopping). The pod's address, logs and track stay for the
// DeletePod that follows, as on an eviction. A parked pod has no runtime pod, so
// the runtime's not-found answers the stop; its pull schedules are cancelled and
// its park record cleared, and a create of it still in flight is deleted when it
// lands after st is recorded (commitParkedCreate).
//
// The stop is the pod's own grace, floored, with no preStop hook, through
// runtimed's DeletePod by pod id (wire 0 stays evictPod's alone). This runs off
// the tick.
func (r *runtimedRuntime) failPastDeadline(ctx context.Context, tracked *corev1.Pod, t *podTrack, st *corev1.PodStatus) error {
	id := string(tracked.UID)
	t.quiesceForEviction()
	intent := r.recordStopIntent(tracked, "")
	_, err := r.rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: id, GracePeriodSeconds: deadlineStopGrace(tracked)})
	if err != nil && status.Code(err) != codes.NotFound {
		if stopNotIssued(err) {
			r.history.dropIntent(intent)
		}
		t.clearStopping()
		return fmt.Errorf("runtimed delete pod %s/%s: %w", tracked.Namespace, tracked.Name, err)
	}
	if !t.finishStopping(st) {
		// An eviction made the pod terminal while this stop ran; its status
		// stands and this failure publishes nothing.
		return nil
	}
	t.restartMu.Lock()
	t.parked = nil
	t.restartMu.Unlock()
	r.stopProber(id)
	r.transport.drop(id)

	r.log.Warn("active deadline: the pod outlived its activeDeadlineSeconds; failed it",
		"pod", podKey(tracked.Namespace, tracked.Name), "uid", id,
		"active_deadline_seconds", *tracked.Spec.ActiveDeadlineSeconds)
	r.recorder.Event(tracked, corev1.EventTypeWarning, reasonDeadlineExceeded, msgDeadlineExceeded)
	// A pod deleted while its stop ran is the DeletePod's now: it owes the
	// apiserver no Failed status, and a callback would republish a pod the
	// kubelet already let go of.
	t.restartMu.Lock()
	if t.deleting {
		t.restartMu.Unlock()
		return nil
	}
	t.unpersisted = st
	t.restartMu.Unlock()
	r.persistDeadlineStatus(ctx, tracked, t, true)
	if cb := r.callback(); cb != nil {
		out := tracked.DeepCopy()
		out.Status = *st.DeepCopy()
		cb(out)
	}
	return nil
}
