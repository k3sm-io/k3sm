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

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

// Node-side pod admission under pressure: the kubelet eviction manager's
// admit handler (pkg/kubelet/eviction/eviction_manager.go, managerImpl.Admit,
// read at v1.36.2) and the rejection the kubelet records for a refused pod
// (pkg/kubelet/kubelet.go, Kubelet.rejectPod), plus one k3sm rule from the
// node budget.
//
// The two rules, in the order they run:
//
//  1. Under MemoryPressure, refuse a BestEffort pod, unless it is critical
//     (isCriticalPod, the kubelet's IsCriticalPod) or it tolerates the
//     node.kubernetes.io/memory-pressure:NoSchedule taint. A Burstable or
//     Guaranteed pod is admitted. MemoryPressure is memoryPressured over the
//     pressure monitor's latest snapshot: the same verdict the node condition
//     publishes and the eviction manager acts on. The rejection is upstream's:
//     reason Evicted, message "The node had condition: [MemoryPressure]. ".
//  2. At the node budget's critical level or above, refuse a batch-band pod
//     (bandOf, budgethistory.go). k3sm's own rule; upstream has no bands. A
//     critical pod is never batch, so it is never refused here.
//
// A refused pod gets the kubelet's rejectPod status: phase Failed, the reason,
// and the message prefixed "Pod was rejected: ", with its QoS class kept and a
// start time (the kubelet's status manager stamps one on every status it
// writes). Nothing runs for it: no address, no sandbox, no process. The Warning
// Event carries the reason and the unprefixed message, as upstream's does.
//
// Admission runs once, at a pod's first create, as the kubelet's runs once in
// HandlePodAdditions: a pod already tracked (an idempotent re-create, a pod held
// for its claims) was admitted and is not judged again, and a pod already in a
// terminal phase is not judged at all. A pod with a deletion timestamp is judged
// like any other: upstream's only termination guard there is
// podWorkers.IsPodTerminationRequested, which is false for a pod the kubelet
// has no worker for yet.
//
// DIVERGENCE. Upstream refuses EVERY non-critical pod while the node has any
// pressure condition other than MemoryPressure alone (DiskPressure, PIDPressure).
// k3sm acts only on memory: its DiskPressure and PIDPressure conditions are
// advertised and not acted on (nodeconditions.go), so they refuse nothing here
// either.

// The kubelet's admission literals: the eviction manager's reason and message
// (pkg/kubelet/eviction/helpers.go, v1.36.2, the message with its trailing
// space) and rejectPod's message prefix (pkg/kubelet/kubelet.go).
const (
	nodeConditionMessageFmt  = "The node had condition: %v. "
	podRejectedMessagePrefix = "Pod was rejected: "
)

// reasonNodeBudgetCritical is the reason a batch-band pod is refused with at
// the node budget's critical level. k3sm's own: no kubelet rule refuses by band.
const reasonNodeBudgetCritical = "NodeBudgetCritical"

// nodeBudgetCriticalMessageFmt is the message of that refusal; its argument is
// the budget level. It ends with a space, as the kubelet's messages do.
const nodeBudgetCriticalMessageFmt = "The node budget is at level %s; pods in the batch band are not admitted. "

// admissionPressure is the pressure source admission reads: the latest host
// snapshot, false until one exists. The pressure monitor implements it.
type admissionPressure interface {
	latest() (s hostStats, seq uint64, ok bool)
}

// podAdmitResult is one admission decision. reason and message are set only
// when admit is false; message is the kubelet's, without the rejectPod prefix.
type podAdmitResult struct {
	admit   bool
	reason  string
	message string
}

// admitPod decides whether pod may start on a node whose latest snapshot is s
// (sampled false: no snapshot yet, which admits everything, as the kubelet's
// handler does with no node conditions). It is pure over (pod, s).
func admitPod(pod *corev1.Pod, s hostStats, sampled bool) podAdmitResult {
	if !sampled {
		return podAdmitResult{admit: true}
	}
	// Critical pods are admitted under any pressure: they are what keeps the
	// node up (kubernetes/kubernetes#40573). They are never batch either.
	if isCriticalPod(pod) {
		return podAdmitResult{admit: true}
	}
	if pressured, _ := memoryPressured(s); pressured &&
		getPodQOS(pod) == corev1.PodQOSBestEffort && !toleratesMemoryPressure(pod.Spec.Tolerations) {
		return podAdmitResult{
			reason:  reasonEvicted,
			message: fmt.Sprintf(nodeConditionMessageFmt, []corev1.NodeConditionType{corev1.NodeMemoryPressure}),
		}
	}
	if bandOf(pod) == budgetv1alpha1.BandBatch {
		obs, _ := budgetOf(s, ladderOf(s))
		if obs.Level == budgetv1alpha1.LevelCritical || obs.Level == budgetv1alpha1.LevelEvicting {
			return podAdmitResult{reason: reasonNodeBudgetCritical, message: fmt.Sprintf(nodeBudgetCriticalMessageFmt, obs.Level)}
		}
	}
	return podAdmitResult{admit: true}
}

// getPodQOS is v1qos.GetPodQOS: the class the apiserver stamped, else the one
// computed from the spec.
func getPodQOS(pod *corev1.Pod) corev1.PodQOSClass {
	if pod.Status.QOSClass != "" {
		return pod.Status.QOSClass
	}
	return computePodQOS(pod)
}

// toleratesMemoryPressure reports whether any of tols tolerates the taint
// node.kubernetes.io/memory-pressure:NoSchedule, by Toleration.ToleratesTaint's
// rule: the effect is empty or NoSchedule, the key is empty or the taint's, and
// the operator is Exists, or Equal (or empty) with an empty value. The taint has
// no value, so the numeric Lt and Gt operators never match it.
func toleratesMemoryPressure(tols []corev1.Toleration) bool {
	for _, t := range tols {
		if t.Effect != "" && t.Effect != corev1.TaintEffectNoSchedule {
			continue
		}
		if t.Key != "" && t.Key != corev1.TaintNodeMemoryPressure {
			continue
		}
		switch t.Operator {
		case "", corev1.TolerationOpEqual:
			if t.Value == "" {
				return true
			}
		case corev1.TolerationOpExists:
			return true
		}
	}
	return false
}

// rejectedPodStatus is the status the kubelet's rejectPod writes for a refused
// pod, with the start time its status manager adds.
func rejectedPodStatus(pod *corev1.Pod, res podAdmitResult, now metav1.Time) *corev1.PodStatus {
	return &corev1.PodStatus{
		QOSClass:  getPodQOS(pod),
		Phase:     corev1.PodFailed,
		Reason:    res.reason,
		Message:   podRejectedMessagePrefix + res.message,
		StartTime: &now,
	}
}

// isBudgetRejectedPod reports whether the apiserver object pod is a pod this
// node refused at the budget's critical level. A pod refused under memory
// pressure carries reason Evicted and is caught by isEvictedPod.
func isBudgetRejectedPod(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodFailed && pod.Status.Reason == reasonNodeBudgetCritical
}

// setAdmissionSource installs the pressure source CreatePod admits against.
// Until it is called nothing is refused, as the kubelet admits everything
// before its eviction manager has observed the node.
func (r *runtimedRuntime) setAdmissionSource(src admissionPressure) {
	r.mu.Lock()
	r.admission = src
	r.mu.Unlock()
}

// admitOnCreate runs node-side admission for a pod CreatePod is about to start.
// It returns true when the create must not proceed: either the pod's track
// already holds a terminal node status (rejected here before, or evicted), or
// the pod is refused now. A refused pod is tracked with its terminal rejected
// status (so every status path reports it, the eviction manager skips it, and
// DeletePod finishes it the way it finishes an evicted pod), the Warning Event
// is recorded, the status is written to the apiserver and pushed through the
// watch callback, and the caller creates nothing.
func (r *runtimedRuntime) admitOnCreate(ctx context.Context, pod *corev1.Pod) bool {
	id := string(pod.UID)
	r.mu.Lock()
	src := r.admission
	prior := r.track[id]
	r.mu.Unlock()
	if prior != nil {
		// Admitted (or refused) at its first create; a refused or evicted pod
		// is terminal and is never created by a repeat call.
		return prior.evictedStatus() != nil
	}
	if src == nil || pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
		return false
	}
	s, _, ok := src.latest()
	res := admitPod(pod, s, ok)
	if res.admit {
		return false
	}
	st := rejectedPodStatus(pod, res, metav1.Now())
	t := &podTrack{pod: pod.DeepCopy(), startTime: *st.StartTime, evicted: st, rejected: true}
	r.mu.Lock()
	if existing := r.track[id]; existing != nil {
		// A concurrent create of the same pod got there first. If it refused
		// the pod too, this create is refused with it; otherwise the pod was
		// admitted and this create proceeds.
		r.mu.Unlock()
		return existing.evictedStatus() != nil
	}
	r.track[id] = t
	r.mu.Unlock()

	r.log.Warn("CreatePod: the pod was rejected at admission",
		"namespace", pod.Namespace, "name", pod.Name, "uid", id,
		"reason", res.reason, "message", res.message, "band", string(bandOf(pod)))
	r.recorder.Event(pod, corev1.EventTypeWarning, res.reason, res.message)
	if err := r.persistEvictedStatus(ctx, pod, st); err != nil {
		r.log.Error("admission: could not persist the rejected status to the apiserver",
			"pod", podKey(pod.Namespace, pod.Name), "err", err)
	}
	if cb := r.callback(); cb != nil {
		out := pod.DeepCopy()
		out.Status = *st.DeepCopy()
		cb(out)
	}
	return true
}

// forgetRejected is DeletePod for a pod refused at admission. The runtime never
// heard of it and it holds no address, references or logs, so there is no
// teardown: the track is forgotten (if it is still t) and the apiserver object
// removed, as teardownPod ends.
func (r *runtimedRuntime) forgetRejected(ctx context.Context, pod *corev1.Pod, t *podTrack) {
	id := string(pod.UID)
	r.mu.Lock()
	if r.track[id] == t {
		delete(r.track, id)
	}
	r.mu.Unlock()
	r.forceDeleteFromAPI(ctx, pod)
}
