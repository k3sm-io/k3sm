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
	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The container lifecycle Events of the runtimed path: Pulled for a host binary,
// Created and Started once per container INSTANCE, and Killing when the provider
// asks for a live container to stop.
//
// The kubelet records Created and Started inside startContainer, beside the CRI
// calls. This provider makes no per-container start call on the create path:
// runtimed's CreatePod starts every container, and a re-exec is one
// RestartContainer RPC. So the Events are derived from what the runtime REPORTS,
// on the same buildStatus convergence observeExits and observePulls ride: the
// first observation of an instance (Running, or already Terminated after it ran)
// records its Created and Started. Every status path (the watch stream, the 10 s
// backstop, a direct GetPodStatus, the probe publish, the status returned by an
// idempotent CreatePod replay) reaches that point, so the instance latch below is
// what makes the Events once-per-instance rather than once-per-observation.

// containerInstance is the identity of one start of a container as runtimed
// reports it, and the lifecycle state the provider has recorded for it.
//
// Identity is runtimed's container ID (a digest over the pod, the container, the
// process group and the start instant, so every exec gets a new one), its
// restart_count (bumped by every RestartContainer) and the start instant. Any
// of them may be absent from a status (an older runtimed, a vm guest still
// booting), which is why newer is a comparison over whichever are known rather
// than an equality on all three.
type containerInstance struct {
	id           string
	restartCount int32
	startedAt    int64 // UnixNano; 0 when the status carried none
	// running is the state of the instance at its latest observation: what
	// DeletePod reads to decide which containers it is stopping.
	running bool
	// killing is set once a Killing Event has been recorded for this instance,
	// so no second stop request (a repeated DeletePod, a liveness kill followed
	// by the delete) records another.
	killing bool
}

// newer reports whether obs is a later instance than seen. A lower restart count
// is a stale status (a backstop read that raced the stream), never a new
// instance; a higher one always is. At one count, a later start instant or a
// different container ID with no earlier start instant is a new start (a
// StartContainer recovery keeps the count).
func (seen *containerInstance) newer(obs containerInstance) bool {
	switch {
	case obs.restartCount < seen.restartCount:
		return false
	case obs.restartCount > seen.restartCount:
		return true
	}
	bothStarts := obs.startedAt != 0 && seen.startedAt != 0
	if bothStarts && obs.startedAt != seen.startedAt {
		return obs.startedAt > seen.startedAt
	}
	return obs.id != "" && seen.id != "" && obs.id != seen.id
}

// observedInstance reads the instance a runtime container status reports, and
// whether the container has started at all. A Waiting container (creating, an
// image failure, a pending re-exec) has no instance; a Terminated one has one
// only if it ran, which its start instant or container ID says.
func observedInstance(cs *runtimev1.ContainerStatus) (containerInstance, bool) {
	inst := containerInstance{id: cs.GetContainerId(), restartCount: cs.GetRestartCount()}
	st := cs.GetState()
	switch {
	case st.GetRunning() != nil:
		inst.running = true
		if ts := st.GetRunning().GetStartedAt(); ts != nil {
			inst.startedAt = ts.AsTime().UnixNano()
		}
		return inst, true
	case st.GetTerminated() != nil:
		if ts := st.GetTerminated().GetStartedAt(); ts != nil {
			inst.startedAt = ts.AsTime().UnixNano()
		}
		return inst, inst.startedAt != 0 || inst.id != ""
	default:
		return inst, false
	}
}

// observeLifecycle records Created and Started (preceded by the kubelet's
// "already present" Pulled for a host binary) for every container instance rs
// reports that this track has not recorded yet, and keeps each latched
// instance's running state current for DeletePod. It runs after observePulls,
// so a fetched image's Pulled precedes the Created it led to.
func (r *runtimedRuntime) observeLifecycle(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus) {
	if pod == nil || rs == nil {
		return
	}
	var events []containerEvent
	t.lifecycleMu.Lock()
	scan := func(css []*runtimev1.ContainerStatus) {
		for _, cs := range css {
			obs, ok := observedInstance(cs)
			if !ok {
				continue
			}
			name := cs.GetName()
			if !t.latchInstanceLocked(name, obs) {
				continue
			}
			if c := specContainer(pod, name); c != nil && isHostBinaryContainer(c) {
				events = append(events, pulledAlreadyPresentEvent(name, c.Image))
			}
			events = append(events, containerLifecycleEvents(name, true)...)
		}
	}
	scan(rs.GetInitContainerStatuses())
	scan(rs.GetContainerStatuses())
	scan(rs.GetEphemeralContainerStatuses())
	t.lifecycleMu.Unlock()

	for _, e := range events {
		recordContainerEvent(r.recorder, pod, e)
	}
}

// latchInstanceLocked folds one observation into the container's latch and
// reports whether it is a new instance (its Created and Started are owed). An
// observation of the latched instance refreshes its running state and fills in
// identity the earlier status lacked; a stale one changes nothing. Caller holds
// t.lifecycleMu.
func (t *podTrack) latchInstanceLocked(name string, obs containerInstance) bool {
	if t.instances == nil {
		t.instances = map[string]*containerInstance{}
	}
	seen := t.instances[name]
	if seen == nil || seen.newer(obs) {
		t.instances[name] = &obs
		return true
	}
	if obs.restartCount == seen.restartCount && (obs.id == "" || seen.id == "" || obs.id == seen.id) &&
		(obs.startedAt == 0 || seen.startedAt == 0 || obs.startedAt == seen.startedAt) {
		seen.running = obs.running
		if seen.id == "" {
			seen.id = obs.id
		}
		if seen.startedAt == 0 {
			seen.startedAt = obs.startedAt
		}
	}
	return false
}

// seedLifecycle latches every instance rs reports WITHOUT recording anything: the
// re-attach of a pod that survived a node-daemon restart (runtimed_attach.go).
// Its containers were created and started in the pod's first life, whose Events
// are already recorded, and a kubelet restarted under running containers
// records none again.
func (t *podTrack) seedLifecycle(rs *runtimev1.PodStatus) {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	for _, css := range [][]*runtimev1.ContainerStatus{
		rs.GetInitContainerStatuses(), rs.GetContainerStatuses(), rs.GetEphemeralContainerStatuses(),
	} {
		for _, cs := range css {
			if obs, ok := observedInstance(cs); ok {
				t.latchInstanceLocked(cs.GetName(), obs)
			}
		}
	}
}

// inheritLifecycle carries a replaced track's latch onto the track an idempotent
// CreatePod installs for the same pod, so the replay's status (the same
// instances runtimed already reported) records nothing again. Called before t
// is published.
func (t *podTrack) inheritLifecycle(old *podTrack) {
	old.lifecycleMu.Lock()
	defer old.lifecycleMu.Unlock()
	if len(old.instances) == 0 {
		return
	}
	t.instances = make(map[string]*containerInstance, len(old.instances))
	for name, inst := range old.instances {
		cp := *inst
		t.instances[name] = &cp
	}
}

// claimKilling marks the latched instance of container as being stopped and
// reports whether a Killing Event is owed for it. requireRunning is DeletePod's
// rule: only a container last observed running is being stopped, so an exited
// one gets none. A kill the provider decided itself (a liveness failure, a
// failed postStart hook) passes false: the container is live by that decision,
// even when no status has reported it yet.
func (t *podTrack) claimKilling(container string, requireRunning bool) bool {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	inst := t.instances[container]
	if inst == nil {
		return !requireRunning
	}
	if inst.killing || (requireRunning && !inst.running) {
		return false
	}
	inst.killing = true
	return true
}

// runningContainersToKill claims a Killing Event for every container of the
// track last observed running, in spec order (init, main, ephemeral), and
// returns their names: DeletePod's set.
func (t *podTrack) runningContainersToKill(pod *corev1.Pod) []string {
	var out []string
	visit := func(name string) {
		if t.claimKilling(name, true) {
			out = append(out, name)
		}
	}
	for i := range pod.Spec.InitContainers {
		visit(pod.Spec.InitContainers[i].Name)
	}
	for i := range pod.Spec.Containers {
		visit(pod.Spec.Containers[i].Name)
	}
	for i := range pod.Spec.EphemeralContainers {
		visit(pod.Spec.EphemeralContainers[i].Name)
	}
	return out
}

// recordKilling records the Killing Event for one container of a tracked pod,
// once per instance (claimKilling), before the stop is requested. message is
// the cause-specific text, or "" for upstream's "Stopping container <name>".
// Every runtimed-path Killing goes through here: DeletePod, the kill-and-re-exec
// of a live container, and the terminal stop of a failed postStart hook.
func (r *runtimedRuntime) recordKilling(t *podTrack, pod *corev1.Pod, container, message string) {
	if t == nil || pod == nil || !t.claimKilling(container, false) {
		return
	}
	recordContainerEvent(r.recorder, pod, killingEvent(container, message))
}

// killMessageFor is the Killing message for a re-exec trigger that kills a LIVE
// container, or "" for one whose container has already exited (the exit-driven
// back-off restart), which is not a stop and records no Killing.
func killMessageFor(reason, container string) (string, bool) {
	switch reason {
	case restartReasonLiveness:
		return msgKillingLiveness(container), true
	case restartReasonPostStart:
		return msgKillingPostStart, true
	default:
		return "", false
	}
}

// specContainer returns the declared container named name (init, main or
// ephemeral, as its common Container), or nil.
func specContainer(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return &pod.Spec.InitContainers[i]
		}
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		if pod.Spec.EphemeralContainers[i].Name == name {
			c := corev1.Container(pod.Spec.EphemeralContainers[i].EphemeralContainerCommon)
			return &c
		}
	}
	return nil
}
