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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The runtimed provider's half of node-pressure eviction (the manager is
// eviction.go): which pods are candidates, and what an evicted pod reports.

// evictedExitCode and evictedContainerReason are what every container of an
// evicted pod reports: the SIGKILL exit (128+9) with the generic reason, the same
// tuple runtimed renders for a killed process. Never OOMKilled: the container did
// not exceed its own limit.
const (
	evictedExitCode        int32 = 137
	evictedContainerReason       = "Error"
	// podCompletedReason is the kubelet's Ready/ContainersReady reason for a pod
	// in a terminal phase (pkg/kubelet/status/generate.go).
	podCompletedReason = "PodCompleted"
)

// persistEvictedBackoff bounds the evicted-status write's retries: six attempts,
// 200 ms doubling to a 3 s cap, about 7 s in all.
var persistEvictedBackoff = wait.Backoff{Steps: 6, Duration: 200 * time.Millisecond, Factor: 2, Cap: 3 * time.Second}

// markEvicted records st as t's terminal evicted status. It returns false if t
// was already evicted (the first eviction's status stands). Guarded by
// restartMu, with the rest of the delete fence.
func (t *podTrack) markEvicted(st *corev1.PodStatus) bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if t.evicted != nil {
		return false
	}
	t.evicted = st
	return true
}

// markStopping takes the first stage of a node-side failure other than an
// eviction (the active deadline): the stop is in flight, but no terminal status
// is recorded yet. It refuses a track that is deleting, was rejected at
// admission, is already stopping, or is already terminal. finishStopping
// records the status once the stop succeeds; clearStopping rolls it back.
// live is the pod's last live status, read before the mark: the runtime forgets
// the pod as its stop begins, so the readers report live (stoppingStatus) for
// the rest of the stop, and after a failed one until the retry, instead of a
// synthesized creating status.
func (t *podTrack) markStopping(live *corev1.PodStatus) bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if t.evicted != nil || t.deleting || t.rejected || t.stopping {
		return false
	}
	t.stopping = true
	t.stoppingLive = live
	return true
}

// stoppingStatus returns a copy of the last live status markStopping recorded
// for t's active-deadline stop, or nil. It is kept while the stop is in flight
// and, after a failed stop, until a runtime read succeeds again
// (observedLive) or a stop succeeds (finishStopping).
func (t *podTrack) stoppingStatus() *corev1.PodStatus {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if t.stoppingLive == nil {
		return nil
	}
	return t.stoppingLive.DeepCopy()
}

// observedLive drops the live status a failed deadline stop kept, once the
// runtime reports the pod again: its own status is the truth from then on. A
// stop in flight keeps its status, which the runtime may yet forget.
func (t *podTrack) observedLive() {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if !t.stopping {
		t.stoppingLive = nil
	}
}

// isStopping reports whether t's active-deadline stop is in flight.
func (t *podTrack) isStopping() bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.stopping
}

// stopFenced reports whether t is fenced against new work by a node-side stop:
// it is terminal (evicted, or failed by its deadline) or its active-deadline
// stop is in flight. The fences (a repeat create, an update, a parked create, a
// restart, eviction) consult it; the status readers consult evictedStatus
// alone, because a pod being stopped has published nothing yet and must not
// read Failed.
func (t *podTrack) stopFenced() bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.evicted != nil || t.stopping
}

// finishStopping is the second stage, after the stop succeeded: it records st,
// which carries its own reason, as t's terminal mark and ends the stopping
// mark, in one critical section so no tick sees the track neither stopping nor
// terminal. It returns false, recording nothing, if t was meanwhile made
// terminal by another path (an eviction), whose status stands.
func (t *podTrack) finishStopping(st *corev1.PodStatus) bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	t.stopping = false
	t.stoppingLive = nil
	if t.evicted != nil || t.rejected {
		return false
	}
	t.evicted = st
	return true
}

// clearStopping rolls back markStopping after a failed stop, releasing the
// fence so the next tick retries it. Nothing was published, so nothing is
// withdrawn. The live status stays: the runtime may already have forgotten the
// pod, and until the retry the pod must not read as being created, nor the
// retry build its Failed status from such a read.
func (t *podTrack) clearStopping() {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	t.stopping = false
}

// unmarkEvicted rolls back markEvicted after a failed runtime teardown, so the
// pod (whose processes are still running) reports its live status again and
// stays an eviction candidate. Only the status this eviction installed is
// removed.
func (t *podTrack) unmarkEvicted(st *corev1.PodStatus) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if t.evicted == st {
		t.evicted = nil
	}
}

// quiesceForEviction cancels the provider workers that could restart or
// re-create a container (pending re-execs, pull re-attempts, postStart hooks).
// Unlike quiesce it does NOT set the delete fence: an eviction whose runtime
// teardown fails is rolled back, and a pod marked deleting would leave the
// candidate set for good.
func (t *podTrack) quiesceForEviction() {
	t.cancelPostStart()
	t.cancelRestarts()
	t.cancelPulls()
}

// evictedStatus returns a copy of t's evicted status, or nil if t was not
// evicted. Every status path consults it FIRST (buildStatus, GetPodStatus,
// podWithStatus), so an evicted pod reports the eviction and nothing the runtime
// says afterwards can overwrite it.
func (t *podTrack) evictedStatus() *corev1.PodStatus {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	if t.evicted == nil {
		return nil
	}
	return t.evicted.DeepCopy()
}

// isEvictedPod reports whether the apiserver object pod is a pod this node (or a
// previous run of it) evicted: phase Failed, reason Evicted.
func isEvictedPod(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodFailed && pod.Status.Reason == reasonEvicted
}

// evictionCandidates implements evictionTarget: every tracked pod the runtime
// reports as still active (not Succeeded or Failed, not unknown to the runtime),
// minus pods already evicted or being deleted, each with its memory stats.
//
// Stats come from ONE ListPodStats under ctx, whose deadline the manager keeps
// shorter than the fast sampling tick. A pod absent from the answer, or every
// pod when the call fails or times out, has no stats, which the ranking orders
// first (the kubelet's own rule).
func (r *runtimedRuntime) evictionCandidates(ctx context.Context) []evictionCandidate {
	r.mu.Lock()
	type tracked struct {
		id  string
		pod *corev1.Pod
		t   *podTrack
	}
	all := make([]tracked, 0, len(r.track))
	for id, t := range r.track {
		all = append(all, tracked{id: id, pod: t.pod, t: t})
	}
	r.mu.Unlock()

	var out []evictionCandidate
	// probeFailed names the candidates whose status probe errored or ran out of
	// time. They stay candidates (a slow pod is not a pod that holds nothing),
	// but with NO stats, whatever ListPodStats says later: a pod the runtime
	// could not answer for in time is ranked the way upstream ranks a pod with
	// no stats, first.
	probeFailed := map[types.UID]bool{}
	for _, tr := range all {
		if tr.t.stopFenced() || trackDeleting(tr.t) {
			continue
		}
		resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: tr.id})
		if err != nil {
			probeFailed[tr.pod.UID] = true
			out = append(out, evictionCandidate{pod: tr.pod.DeepCopy()})
			continue
		}
		if resp.GetError() != nil && resp.GetError().GetCode() != 0 {
			continue // the runtime holds nothing (parked, or mid-create): nothing to free
		}
		switch resp.GetStatus().GetPhase() {
		case runtimev1.PodPhase_POD_PHASE_SUCCEEDED, runtimev1.PodPhase_POD_PHASE_FAILED:
			continue // not active: the kubelet's activePods excludes terminal pods
		}
		out = append(out, evictionCandidate{pod: tr.pod.DeepCopy()})
	}
	if len(out) == 0 {
		return nil
	}
	resp, err := r.rt.ListPodStats(ctx, &runtimev1.ListPodStatsRequest{})
	if err != nil {
		r.log.Warn("eviction: pod stats unavailable; ranking without usage", "err", err)
		return out
	}
	byID := make(map[string]*runtimev1.PodStats, len(resp.GetPodStats()))
	for _, ps := range resp.GetPodStats() {
		if ps != nil {
			byID[ps.GetPodId()] = ps
		}
	}
	for i := range out {
		ps := byID[string(out[i].pod.UID)]
		if ps == nil || probeFailed[out[i].pod.UID] {
			continue
		}
		out[i].hasStats = true
		out[i].containerUsage = map[string]int64{}
		for _, c := range ps.GetContainers() {
			ws := int64(c.GetMemory().GetWorkingSetBytes())
			out[i].containerUsage[c.GetName()] = ws
			out[i].usage += ws
		}
		if len(ps.GetContainers()) == 0 {
			out[i].usage = int64(ps.GetMemory().GetWorkingSetBytes())
		}
	}
	return out
}

// evictedPodStatus derives the evicted pod's terminal status from its last
// status: phase Failed, reason Evicted, message msg; every container not already
// terminated becomes terminated with exit 137 and reason Error; Ready and
// ContainersReady False with the kubelet's terminal-phase reason;
// PodReadyToStartContainers False (the sandbox is gone); and the
// DisruptionTarget condition True with reason TerminationByKubelet and the same
// message (the kubelet's eviction manager sets it; Job podFailurePolicy and
// disruption accounting key off it).
func evictedPodStatus(prior corev1.PodStatus, msg string, now metav1.Time) *corev1.PodStatus {
	st := failedPodStatus(prior, reasonEvicted, msg, now)
	setPodCondition(st, corev1.PodCondition{
		Type:               corev1.DisruptionTarget,
		Status:             corev1.ConditionTrue,
		Reason:             corev1.PodReasonTerminationByKubelet,
		Message:            msg,
		LastTransitionTime: now,
	})
	return st
}

// failedPodStatus is the node-terminated half of evictedPodStatus, shared with
// the active-deadline failure: phase Failed with reason and msg, every container
// not already terminated terminated with exit 137 and reason Error, Ready and
// ContainersReady False, and PodReadyToStartContainers False. It sets no
// DisruptionTarget condition.
func failedPodStatus(prior corev1.PodStatus, reason, msg string, now metav1.Time) *corev1.PodStatus {
	st := prior.DeepCopy()
	st.Phase = corev1.PodFailed
	st.Reason = reason
	st.Message = msg
	terminate := func(list []corev1.ContainerStatus) {
		for i := range list {
			cs := &list[i]
			notStarted := false
			cs.Ready = false
			cs.Started = &notStarted
			if cs.State.Terminated != nil {
				continue
			}
			var startedAt metav1.Time
			if cs.State.Running != nil {
				startedAt = cs.State.Running.StartedAt
			}
			cs.State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode:    evictedExitCode,
				Reason:      evictedContainerReason,
				StartedAt:   startedAt,
				FinishedAt:  now,
				ContainerID: cs.ContainerID,
			}}
		}
	}
	terminate(st.ContainerStatuses)
	terminate(st.InitContainerStatuses)
	setPodCondition(st, corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: podCompletedReason, LastTransitionTime: now})
	setPodCondition(st, corev1.PodCondition{Type: corev1.ContainersReady, Status: corev1.ConditionFalse, Reason: podCompletedReason, LastTransitionTime: now})
	// The eviction tears the sandbox down. A condition already False keeps its
	// transition time.
	toStart := corev1.PodCondition{Type: corev1.PodReadyToStartContainers, Status: corev1.ConditionFalse, LastTransitionTime: now}
	if c := findPodCondition(st.Conditions, corev1.PodReadyToStartContainers); c != nil && c.Status == corev1.ConditionFalse {
		toStart.LastTransitionTime = c.LastTransitionTime
	}
	setPodCondition(st, toStart)
	return st
}

// persistEvictedStatus writes st to the apiserver Pod before the eviction is
// considered done, so the eviction survives a daemon restart (the attach pass
// only adopts Running pods, Virtual Kubelet skips syncing Failed ones, and
// CreatePod refuses an evicted pod). The write is UID-checked: a pod replaced
// under the same name since is not this pod and is left alone. A nil client
// (unit tests that build no apiserver) is a no-op.
//
// Any failure but NotFound (the pod is gone; nothing to record) is retried with
// a bounded exponential backoff (persistEvictedBackoff), and never past ctx: a
// conflict, an apiserver that is briefly unavailable under the very memory
// pressure that caused the eviction, or a timeout. It stops retrying once ctx
// ends.
func (r *runtimedRuntime) persistEvictedStatus(ctx context.Context, pod *corev1.Pod, st *corev1.PodStatus) error {
	if r.client == nil {
		return nil
	}
	retriable := func(err error) bool { return ctx.Err() == nil && !apierrors.IsNotFound(err) }
	return retry.OnError(persistEvictedBackoff, retriable, func() error {
		live, err := r.client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		if live.UID != pod.UID {
			r.log.Warn("eviction: the apiserver pod was replaced; not writing the evicted status",
				"pod", podKey(pod.Namespace, pod.Name), "uid", string(pod.UID), "live_uid", string(live.UID))
			return nil
		}
		live.Status = *st.DeepCopy()
		if _, err := r.client.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, live, metav1.UpdateOptions{}); err != nil {
			return err
		}
		return nil
	})
}
