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
		start := &t.startTime
		if t.startTime.IsZero() {
			start = t.pod.Status.StartTime
		}
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
		if err := r.failPastDeadline(ctx, d.pod, d.t); err != nil {
			r.log.Warn("active deadline: could not stop the pod; retrying on the next resync",
				"pod", podKey(d.pod.Namespace, d.pod.Name), "uid", string(d.pod.UID), "err", err)
		}
	}
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
// The terminal mark is set before the stop and rolled back if the stop fails;
// the pod's address, logs and track stay for the DeletePod that follows, as on an
// eviction. A parked pod has no runtime pod, so the runtime's not-found answers
// the stop; its pull schedules are cancelled and its park record cleared, and a
// create of it still in flight is deleted when it lands (commitParkedCreate).
//
// The stop is the pod's own grace, floored, with no preStop hook, through
// runtimed's DeletePod by pod id (wire 0 stays evictPod's alone).
func (r *runtimedRuntime) failPastDeadline(ctx context.Context, tracked *corev1.Pod, t *podTrack) error {
	id := string(tracked.UID)
	prior := r.podWithStatus(ctx, tracked, t)
	st := failedPodStatus(prior.Status, reasonDeadlineExceeded, msgDeadlineExceeded, metav1.NewTime(r.clk.Now()))
	if !t.markTerminal(st) {
		return nil
	}
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
