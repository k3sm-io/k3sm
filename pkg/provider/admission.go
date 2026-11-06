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
	"sync"

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
// before its eviction manager has observed the node. A nil *pressureMonitor is
// stored as no source: as an interface value it would be non-nil, and the
// first create would call latest on it.
func (r *runtimedRuntime) setAdmissionSource(src admissionPressure) {
	if m, ok := src.(*pressureMonitor); ok && m == nil {
		src = nil
	}
	r.mu.Lock()
	r.admission = src
	r.mu.Unlock()
}

// admitOnCreate runs node-side admission for a pod CreatePod is about to start.
// refused is true when the create must not proceed: either the pod's track
// already holds a terminal node status (rejected here before, or evicted), or
// the pod is refused now. A refused pod is tracked with its terminal rejected
// status (so every status path reports it, the eviction manager skips it, and
// DeletePod finishes it the way it finishes an evicted pod), the Warning Event
// is recorded, the status is written to the apiserver and pushed through the
// watch callback, and the caller creates nothing.
//
// When refused is false the caller must end the ticket when its create returns,
// with createDone.
//
// Locking: the decision and the publication of its result happen in one r.mu
// critical section. A refusal is published as the rejected track; an admission
// is published as an in-flight count in r.admitting, held until done, and so is
// a repeat create of a pod with a live track. So of two concurrent creates of
// one pod, whichever decides second sees the first's result: a create that
// would refuse yields to an admitted create in flight, and a create that would
// admit is refused with an installed rejection.
// CreatePod's track registration refuses to replace a terminal track behind
// this. The pressure monitor's lock is a leaf, so reading it under r.mu is safe.
//
// A create of a pod whose refused create is still releasing at the fence waits
// for that release first (or refuses, if ctx ends meanwhile): every resource
// the release frees is keyed by the pod's UID, so a create admitted inside the
// release would lose its own.
//
// A refusal does not wait for an UpdatePod past its check: the update is judged
// again before its runtime call and frees what it took (UpdatePod, updateDone).
//
// A refusal does free what an earlier create or update of the pod left behind with
// no track, such as a create that failed after its window, as the refused pod's
// delete frees nothing. An address no call took (attachPod) is left alone.
func (r *runtimedRuntime) admitOnCreate(ctx context.Context, pod *corev1.Pod) (refused bool, t *admitTicket) {
	id := string(pod.UID)
	r.mu.Lock()
	for {
		ch := r.fenceReleasing[id]
		if ch == nil {
			break
		}
		r.mu.Unlock()
		if hook := r.fenceWaitHook; hook != nil {
			hook(id)
		}
		select {
		case <-ch:
		case <-ctx.Done():
			r.log.Warn("CreatePod: gave up waiting for a refused create of the pod to release",
				"namespace", pod.Namespace, "name", pod.Name, "uid", id, "err", ctx.Err())
			return true, nil
		}
		r.mu.Lock()
	}
	if prior := r.track[id]; prior != nil {
		// Admitted (or refused) at its first create; a refused or evicted pod
		// is terminal and is never created by a repeat call.
		if prior.evictedStatus() != nil {
			r.mu.Unlock()
			return true, nil
		}
		// A repeat create of a live pod is not judged again, but it is in
		// flight like a first create: it allocates the pod's address before
		// it reaches the fence, and the track it saw can be deleted meanwhile.
		// Counting it keeps a refusal from landing behind it.
		return false, r.admitLocked(id)
	}
	res := podAdmitResult{admit: true}
	if src := r.admission; src != nil && r.admitting[id] == 0 &&
		pod.Status.Phase != corev1.PodFailed && pod.Status.Phase != corev1.PodSucceeded {
		s, _, ok := src.latest()
		res = admitPod(pod, s, ok)
	}
	if res.admit {
		return false, r.admitLocked(id)
	}
	st := rejectedPodStatus(pod, res, metav1.Now())
	r.track[id] = &podTrack{pod: pod.DeepCopy(), startTime: *st.StartTime, evicted: st, rejected: true}
	claim := r.claimFenceReleaseLocked(id)
	r.mu.Unlock()
	if claim != nil {
		r.fenceRelease(pod, claim)
	}

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
	return true, nil
}

// admitTicket is one admitted create's in-flight count. It ends once, however
// often doneLocked is called.
type admitTicket struct {
	r    *runtimedRuntime
	id   string
	once sync.Once
}

// doneLocked ends the count; the caller holds r.mu.
func (t *admitTicket) doneLocked() { t.once.Do(func() { t.r.admitDoneLocked(t.id) }) }

// admitLocked publishes one admitted create of pod id as an in-flight count
// and returns its ticket. The caller holds r.mu; admitLocked releases it.
func (r *runtimedRuntime) admitLocked(id string) *admitTicket {
	if r.admitting == nil {
		r.admitting = map[string]int{}
	}
	r.admitting[id]++
	r.mu.Unlock()
	return &admitTicket{r: r, id: id}
}

// admitDoneLocked ends one admitted create of pod id. The caller holds r.mu.
func (r *runtimedRuntime) admitDoneLocked(id string) {
	if r.admitting[id] > 1 {
		r.admitting[id]--
		return
	}
	delete(r.admitting, id)
	if ch := r.admitSettled[id]; ch != nil {
		delete(r.admitSettled, id)
		close(ch)
	}
}

// awaitUpdateVerdictLocked holds an UpdatePod until the pod's admission has a
// verdict the update can read from the track. It waits while a create admission let
// through has no track yet when the update looks, and while a fence release frees
// what the pod's UID holds. A waiter is woken only when the last admitted create
// returns, not when that create publishes its track, so a slow runtime call delays
// it by the same amount. It returns ctx's error if ctx ends first. The caller holds
// r.mu on entry and on every return, a panic included; the wait itself runs with
// r.mu released.
func (r *runtimedRuntime) awaitUpdateVerdictLocked(ctx context.Context, pod *corev1.Pod) error {
	id := string(pod.UID)
	for {
		ch := r.updateWaitLocked(id)
		if ch == nil {
			return nil
		}
		if err := r.waitForUpdateVerdict(ctx, id, ch); err != nil {
			return err
		}
	}
}

// waitForUpdateVerdict waits on ch with r.mu released. The relock is deferred, so a
// panic in the wait still returns the lock to a caller that unlocks in a defer.
func (r *runtimedRuntime) waitForUpdateVerdict(ctx context.Context, id string, ch <-chan struct{}) error {
	r.mu.Unlock()
	defer r.mu.Lock()
	if hook := r.updateWaitHook; hook != nil {
		hook(id)
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// updateWaitLocked returns what an update of pod id has to wait on, nil when
// nothing. A terminal or live track is the verdict, so an update reads it with no
// wait; only an admitted create yet to publish a track leaves the verdict open.
// The caller holds r.mu.
func (r *runtimedRuntime) updateWaitLocked(id string) <-chan struct{} {
	t := r.track[id]
	if t != nil && (t.rejected || t.evictedStatus() != nil) {
		return nil
	}
	if ch := r.fenceReleasing[id]; ch != nil {
		return ch
	}
	if t != nil || r.admitting[id] == 0 {
		return nil
	}
	ch := r.admitSettled[id]
	if ch == nil {
		ch = make(chan struct{})
		if r.admitSettled == nil {
			r.admitSettled = map[string]chan struct{}{}
		}
		r.admitSettled[id] = ch
	}
	return ch
}

// noteHeldLocked records that a create or update of pod id is about to acquire.
// The caller holds r.mu.
func (r *runtimedRuntime) noteHeldLocked(id string) {
	if r.held == nil {
		r.held = map[string]struct{}{}
	}
	r.held[id] = struct{}{}
}

// updateStoppedNow reports whether an update past its check has to stop acquiring:
// the pod has been refused, or its delete has begun.
func (r *runtimedRuntime) updateStoppedNow(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, deleted := r.deleteOwed[id]; deleted {
		return true
	}
	t := r.track[id]
	return t != nil && (t.rejected || trackDeleting(t))
}

// createDone ends one admitted create. It is CreatePod's only exit once admitted,
// in a defer, so a fence, a failure and a panic all reach the same decision under
// the same r.mu section. The release runs with r.mu released and takes only its
// own leaf locks.
func (r *runtimedRuntime) createDone(pod *corev1.Pod, t *admitTicket) {
	id := string(pod.UID)
	r.mu.Lock()
	t.doneLocked()
	claim := r.claimFenceReleaseLocked(id)
	r.mu.Unlock()
	if claim != nil {
		r.fenceRelease(pod, claim)
	}
}

// updateDone ends one UpdatePod, or one parked retry's allocation (retryParkedBox).
// A refusal may have landed behind it, with no create in flight to reach CreatePod's
// fence, and a refused pod's delete frees nothing; or a delete may have, leaving the
// rest of its teardown here. So the last call out releases. The release runs with
// r.mu released and takes only its own leaf locks.
func (r *runtimedRuntime) updateDone(pod *corev1.Pod) {
	id := string(pod.UID)
	r.mu.Lock()
	if r.updating[id] <= 1 {
		delete(r.updating, id)
	} else {
		r.updating[id]--
	}
	claim := r.claimFenceReleaseLocked(id)
	r.mu.Unlock()
	if claim != nil {
		r.fenceRelease(pod, claim)
	}
}

// fenceClaim is one decided release, carried out by fenceRelease: released is
// closed when it is over, and del is set when a delete is owed with it.
type fenceClaim struct {
	released chan struct{}
	del      *owedDelete
}

// owedDelete is the rest of a teardown left to the last UpdatePod out. owned
// selects the track to forget, as in teardownPod; nil is whatever the id holds.
type owedDelete struct {
	owned *podTrack
}

// oweDeleteLocked leaves the rest of a delete to the last call out. The caller
// holds r.mu.
func (r *runtimedRuntime) oweDeleteLocked(id string, owned *podTrack) {
	if r.deleteOwed == nil {
		r.deleteOwed = map[string]*owedDelete{}
	}
	r.deleteOwed[id] = &owedDelete{owned: owned}
}

// uidTombstoneCap bounds uidTombstones. An update is stale by the time between
// Virtual Kubelet's GetPod and the update's check, a few provider calls at most,
// while this many deletes on one node take far longer than that: a node runs on the
// order of a hundred pods. At 36 bytes a UID it costs well under a megabyte.
const uidTombstoneCap = 1024

// uidTombstones is a bounded set of the UIDs of recent deletes, oldest evicted
// first. A UID is never reused, so a hit is a fact about the pod for good, and an
// eviction only returns that UID's update to the path it took before. The zero value
// is usable. The owner guards it.
type uidTombstones struct {
	seen map[string]struct{}
	ring []string
	next int
}

// add records id, evicting the oldest entry once the set is at uidTombstoneCap.
func (u *uidTombstones) add(id string) {
	if _, ok := u.seen[id]; ok {
		return
	}
	if u.seen == nil {
		u.seen = map[string]struct{}{}
	}
	u.seen[id] = struct{}{}
	if len(u.ring) < uidTombstoneCap {
		u.ring = append(u.ring, id)
		return
	}
	delete(u.seen, u.ring[u.next])
	u.ring[u.next] = id
	u.next = (u.next + 1) % uidTombstoneCap
}

// has reports whether id's delete is remembered.
func (u *uidTombstones) has(id string) bool {
	_, ok := u.seen[id]
	return ok
}

// inFlightLocked reports whether a create or an update of pod id has not returned,
// so it can still acquire by the pod's UID. The caller holds r.mu.
func (r *runtimedRuntime) inFlightLocked(id string) bool {
	return r.admitting[id] != 0 || r.updating[id] != 0
}

// claimFenceReleaseLocked decides, under r.mu, that the caller releases what pod
// id's UID holds, and returns the claim to hand fenceRelease, or nil when it does
// not. The call right after a claim is fenceRelease, with nothing between them that
// can panic, and a claim consumes held and deleteOwed in this same decision, so a
// release runs once.
//
// A release is owed by a refused pod something was acquired for, and by a delete
// that landed behind a create or an update. Everything released is keyed by the UID,
// so it waits for the last in-flight create or update of the pod: an in-flight one
// still acquires, and it reaches this decision itself when it ends. fenceReleasing,
// published here, holds every new create and update until the release is over, so a
// release in progress has none in flight beside it. The caller holds r.mu.
//
// "Once" covers what reaches this decision. Still open:
//   - A create that failed and left no track, whose pod is then deleted with no
//     container running, whether the delete came during the create or after it.
//     Virtual Kubelet runs one call per pod key, removes such a pod from the apiserver
//     without calling DeletePod (syncPodInProvider, node/podcontroller.go), and finds
//     no track when the object goes, and the orphan reaper keys on tracks. What the
//     create took stays until the daemon restarts or a refusal of the same UID.
//   - A create whose RPC succeeds behind a delete: the guest the runtime built is not
//     deleted again, unlike a parked retry's (commitParkedCreate). Its /32 is released.
//   - An untracked update with no deletion stamp that is not behind a delete of its
//     UID, or is behind one uidTombstones has evicted: it allocates as it always did,
//     and only a later create, delete or refusal of the UID frees that.
func (r *runtimedRuntime) claimFenceReleaseLocked(id string) *fenceClaim {
	if r.inFlightLocked(id) || r.fenceReleasing[id] != nil {
		return nil
	}
	t := r.track[id]
	refused := t != nil && t.rejected
	_, held := r.held[id]
	del := r.deleteOwed[id]
	switch {
	case del != nil && refused && !held:
		// Deleted, and nothing was acquired to free: only the track is owed.
		delete(r.deleteOwed, id)
		if del.owned == nil || del.owned == t {
			delete(r.track, id)
		}
		return nil
	case del != nil:
		delete(r.deleteOwed, id)
	case refused && held:
	default:
		return nil
	}
	// Consumed here, not when the release runs: a release that panics is not
	// claimed a second time.
	delete(r.held, id)
	released := make(chan struct{})
	if r.fenceReleasing == nil {
		r.fenceReleasing = map[string]chan struct{}{}
	}
	r.fenceReleasing[id] = released
	return &fenceClaim{released: released, del: del}
}

// forgetRejected is DeletePod for a pod refused at admission. The runtime never
// heard of it and it holds no address, references or logs, so there is no
// teardown: the track is forgotten (if it is still t) and the apiserver object
// removed, as teardownPod ends. With an UpdatePod in flight the track stays, so the
// update reads the refusal and stops, and the last call out frees what the update
// took and forgets it.
func (r *runtimedRuntime) forgetRejected(ctx context.Context, pod *corev1.Pod, t *podTrack) {
	id := string(pod.UID)
	r.mu.Lock()
	r.tombstones.add(id)
	switch {
	case r.updating[id] != 0:
		r.oweDeleteLocked(id, t)
	case r.track[id] == t:
		delete(r.track, id)
	}
	r.mu.Unlock()
	r.forceDeleteFromAPI(ctx, pod)
}
