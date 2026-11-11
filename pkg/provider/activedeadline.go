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
		if d.t.rejected || d.t.evictedStatus() != nil || trackDeleting(d.t) {
			continue
		}
		r.startDeadlineStop(ctx, d.pod, d.t)
	}
}

// startDeadlineStop takes t's terminal mark on the tick, so this tick's status
// read already publishes Failed and a later tick sees the mark and starts no
// second stop, then runs the stop itself in one goroutine per pod: the runtime
// stop can take the pod's whole termination grace, and several pods expiring
// together must not hold the tick's status publication behind each other.
//
// Locking: the mark and its rollback are t.restartMu's (markTerminal,
// unmarkEvicted); the goroutine holds only its own *podTrack and takes no
// provider lock across the RPC. Lifetime: the goroutine's context keeps ctx's
// values but is cancelled by the provider's lifetime (r.lifetime, closed by
// shutdown), not by the tick; it is counted in r.deadlineStops, added under r.mu
// only while the lifetime is open, and shutdown waits for it. A provider already
// shut down starts no stop and takes no mark.
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
	st := failedPodStatus(prior.Status, reasonDeadlineExceeded, msgDeadlineExceeded, metav1.NewTime(r.clk.Now()))
	if !t.markTerminal(st) {
		r.deadlineStops.Done()
		return
	}
	go func() {
		defer r.deadlineStops.Done()
		stopCtx, cancel := r.lifetimeContext(ctx)
		defer cancel()
		err := r.failPastDeadline(stopCtx, tracked, t, st)
		// A stop that keeps failing is retried every resync: the first failure
		// of a pod logs at Warn, the repeats at Debug, until a stop succeeds.
		t.restartMu.Lock()
		repeat := t.deadlineStopFailed
		t.deadlineStopFailed = err != nil
		t.restartMu.Unlock()
		if err != nil {
			log := r.log.Warn
			if repeat {
				log = r.log.Debug
			}
			log("active deadline: could not stop the pod; retrying on the next resync",
				"pod", podKey(tracked.Namespace, tracked.Name), "uid", string(tracked.UID), "err", err)
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
func (r *runtimedRuntime) persistDeadlineStatus(ctx context.Context, pod *corev1.Pod, t *podTrack, first bool) {
	st := t.unpersistedStatus()
	if st == nil {
		return
	}
	if err := r.persistEvictedStatus(ctx, pod, st); err != nil && !apierrors.IsNotFound(err) {
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

// failPastDeadline stops a pod past its active deadline in evictPod's shape and
// records it Failed, reason DeadlineExceeded, with no DisruptionTarget condition.
// The terminal mark is set before the stop (by the caller) and rolled back if the stop fails;
// the pod's address, logs and track stay for the DeletePod that follows, as on an
// eviction. A parked pod has no runtime pod, so the runtime's not-found answers
// the stop; its pull schedules are cancelled and its park record cleared, and a
// create of it still in flight is deleted when it lands (commitParkedCreate).
//
// The stop is the pod's own grace, floored, with no preStop hook, through
// runtimed's DeletePod by pod id (wire 0 stays evictPod's alone). The caller has
// taken the terminal mark st (startDeadlineStop); this runs off the tick.
func (r *runtimedRuntime) failPastDeadline(ctx context.Context, tracked *corev1.Pod, t *podTrack, st *corev1.PodStatus) error {
	id := string(tracked.UID)
	t.quiesceForEviction()
	intent := r.recordStopIntent(tracked, "")
	_, err := r.rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: id, GracePeriodSeconds: floorGrace(graceSeconds(tracked))})
	if err != nil && status.Code(err) != codes.NotFound {
		if stopNotIssued(err) {
			r.history.dropIntent(intent)
		}
		t.unmarkEvicted(st)
		return fmt.Errorf("runtimed delete pod %s/%s: %w", tracked.Namespace, tracked.Name, err)
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
	t.restartMu.Lock()
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
