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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	for _, tr := range all {
		if tr.t.evictedStatus() != nil || trackDeleting(tr.t) {
			continue
		}
		resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: tr.id})
		if err != nil || (resp.GetError() != nil && resp.GetError().GetCode() != 0) {
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
		if ps == nil {
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
// ContainersReady False with the kubelet's terminal-phase reason; and the
// DisruptionTarget condition True with reason TerminationByKubelet and the same
// message (the kubelet's eviction manager sets it; Job podFailurePolicy and
// disruption accounting key off it).
func evictedPodStatus(prior corev1.PodStatus, msg string, now metav1.Time) *corev1.PodStatus {
	st := prior.DeepCopy()
	st.Phase = corev1.PodFailed
	st.Reason = reasonEvicted
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
	setPodCondition(st, corev1.PodCondition{
		Type:               corev1.DisruptionTarget,
		Status:             corev1.ConditionTrue,
		Reason:             corev1.PodReasonTerminationByKubelet,
		Message:            msg,
		LastTransitionTime: now,
	})
	return st
}

// persistEvictedStatus writes st to the apiserver Pod before the eviction is
// considered done, so the eviction survives a daemon restart (the attach pass
// only adopts Running pods, Virtual Kubelet skips syncing Failed ones, and
// CreatePod refuses an evicted pod). The write is UID-checked: a pod replaced
// under the same name since is not this pod and is left alone. A nil client
// (unit tests that build no apiserver) is a no-op.
func (r *runtimedRuntime) persistEvictedStatus(ctx context.Context, pod *corev1.Pod, st *corev1.PodStatus) error {
	if r.client == nil {
		return nil
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
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
