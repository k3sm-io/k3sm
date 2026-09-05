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

	corev1 "k8s.io/api/core/v1"
)

// postStart hook FIDELITY — the upstream semantics the earlier dispatch-only hook
// deferred. The contract this file implements is the one stated on the API type
// itself (k8s.io/api core/v1 types.go, Lifecycle / Lifecycle.PostStart):
//
//	"For the PostStart and PreStop lifecycle handlers, management of the container
//	 blocks until the action is complete"
//	"PostStart is called immediately after a container is created. If the handler
//	 fails, the container is terminated and restarted according to its restart
//	 policy. Other management of the container blocks until the hook completes."
//
// which the kubelet implements by running the hook SYNCHRONOUSLY inside
// startContainer (upstream pkg/kubelet/kuberuntime/kuberuntime_container.go): the
// pod worker cannot publish a further status for the pod while the hook runs, and a
// failed hook is followed by killContainer + the FailedPostStartHook Warning event.
// Four consequences, each implemented here:
//
//  1. READY-GATING — a container whose postStart hook has not completed is held
//     NotReady (and, through the shared ContainersReady/PodReady derivation, so is
//     the pod). Upstream gets this for free by not publishing at all; the k3sm
//     provider publishes continuously off the runtime's status stream, so the gate
//     is explicit: applyPostStartOverlay. A hook that hangs holds the container
//     NotReady for as long as it hangs — upstream's documented behavior, not a bug.
//
//  2. FAILURE ⇒ THE CONTAINER IS KILLED, then handled by its restart policy. Under
//     an effective policy that restarts a failed container (Always/OnFailure, and a
//     native sidecar's effective Always) that kill IS a re-exec, so it routes
//     through the SINGLE restart authority (runtimed_restart.go) and inherits
//     one CrashLoopBackOff schedule and one restart window. Under Never the kill is
//     TERMINAL — and that is the one arm the provider cannot perform today; see
//     failPostStart for exactly what is done instead and why nothing is faked.
//
//  3. RE-RUN ON EVERY START — the hook fires per container START, not once per pod:
//     upstream runs it inside startContainer, which is also the restart path. So a
//     successful re-exec re-dispatches it (rerunPostStart, called from the restart
//     worker), and the container is held NotReady again until it completes.
//
//  4. POD-SCOPED CANCELABLE LIFETIME — each hook goroutine runs under a context
//     owned by the pod's track and cancelled by DeletePod (and by the idempotent
//     CreatePod that replaces the track). The earlier stopgap — context.Background() with
//     a 2-minute cap — both outlived pod teardown (up to 2m) and imposed a deadline
//     upstream does not have. Cancellation replaces the cap: the hook's bound is the
//     pod's lifetime.
//
// SCOPE: mains only (pod.Spec.Containers), matching the create-path dispatch. An init
// container's or native sidecar's postStart is not dispatched at create, so it is
// not re-run on restart either — the two halves stay consistent, and the gap is the
// pre-existing one, not a new asymmetry.

// postStartHook is one container's postStart bookkeeping, held in
// podTrack.postStart under hookMu. Both flags gate readiness; they are distinct
// because only `failed` is terminal for this container start (`pending` clears when
// the hook returns, `failed` only when the container is started again).
type postStartHook struct {
	// pending is true from the instant the hook is dispatched until it returns.
	pending bool
	// failed records that the hook returned an error. The container is NOT ready
	// and must not become ready on this start: upstream would have killed it.
	failed bool
	// cancel aborts the in-flight hook (DeletePod / an idempotent CreatePod that
	// replaces the track).
	cancel context.CancelFunc
}

// gated reports whether the container must be held NotReady on account of its
// postStart hook.
func (h *postStartHook) gated() bool { return h.pending || h.failed }

// beginPostStart claims the container's single hook slot, marks it pending and
// stores its cancel. It reports false when a hook is already in flight — an
// idempotent CreatePod for a live pod must not dispatch a second one. Any previous
// FAILED verdict is cleared: this is a new container start, and upstream's hook is
// per-start.
func (t *podTrack) beginPostStart(name string, cancel context.CancelFunc) bool {
	t.hookMu.Lock()
	defer t.hookMu.Unlock()
	if t.postStart == nil {
		t.postStart = map[string]*postStartHook{}
	}
	h := t.postStart[name]
	if h == nil {
		h = &postStartHook{}
		t.postStart[name] = h
	}
	if h.pending {
		return false
	}
	h.pending, h.failed, h.cancel = true, false, cancel
	return true
}

// finishPostStart records the hook's verdict: pending clears, and a non-nil err
// latches `failed` so the container stays NotReady until it is started again.
func (t *podTrack) finishPostStart(name string, err error) {
	t.hookMu.Lock()
	defer t.hookMu.Unlock()
	h := t.postStart[name]
	if h == nil {
		return
	}
	h.pending, h.failed, h.cancel = false, err != nil, nil
}

// cancelPostStart aborts every in-flight postStart hook for the track, so no hook
// goroutine outlives the pod it was dispatched for (semantic 4). Idempotent.
func (t *podTrack) cancelPostStart() {
	t.hookMu.Lock()
	defer t.hookMu.Unlock()
	for _, h := range t.postStart {
		if h.cancel != nil {
			h.cancel()
			h.cancel = nil
		}
		h.pending = false
	}
}

// gatedContainers snapshots the set of container names currently held NotReady by
// their postStart hook. Snapshotting under the lock keeps the overlay's mutation of
// the status slices — and any callback it feeds — outside hookMu.
func (t *podTrack) gatedContainers() map[string]struct{} {
	t.hookMu.Lock()
	defer t.hookMu.Unlock()
	var out map[string]struct{}
	for name, h := range t.postStart {
		if !h.gated() {
			continue
		}
		if out == nil {
			out = map[string]struct{}{}
		}
		out[name] = struct{}{}
	}
	return out
}

// runPostStart dispatches every main container's postStart hook after the pod's
// containers are created. podIP is the freshly bound pod IP (an httpGet hook's
// default host); it falls back to the node IP.
func (r *runtimedRuntime) runPostStart(t *podTrack, pod *corev1.Pod, podIP string) {
	if t == nil || pod == nil {
		return
	}
	if podIP == "" {
		podIP = r.nodeIP
	}
	for i := range pod.Spec.Containers {
		r.dispatchPostStart(t, pod, podIP, &pod.Spec.Containers[i])
	}
}

// dispatchPostStart runs ONE container's postStart hook in its own goroutine under
// a pod-scoped cancelable context, marking the container gated BEFORE the goroutine
// starts — so no status can be published Ready in the window between the container
// starting and the hook being registered. A container with no hook is a no-op.
//
// The handler and the port table are copied so the goroutine cannot race a later
// mutation of the caller's Pod; the pod object the completion path needs is read
// from the track at completion time, never captured.
func (r *runtimedRuntime) dispatchPostStart(t *podTrack, pod *corev1.Pod, podIP string, c *corev1.Container) {
	if c.Lifecycle == nil || c.Lifecycle.PostStart == nil {
		return
	}
	h := c.Lifecycle.PostStart.DeepCopy()
	ports := append([]corev1.ContainerPort(nil), c.Ports...)
	cname := c.Name
	id := string(pod.UID)
	key := podKey(pod.Namespace, pod.Name)

	ctx, cancel := context.WithCancel(context.Background())
	if !t.beginPostStart(cname, cancel) {
		cancel() // a hook for this container is already in flight
		return
	}
	go func() {
		defer cancel()
		// No timeout: upstream does not cap a postStart hook — ctx (the pod's
		// lifetime) is the only bound, and a hook still running at teardown is
		// cancelled with the pod rather than surviving it.
		err := r.runHook(ctx, id, podIP, cname, ports, h, 0)
		if ctx.Err() != nil {
			// The pod was deleted or replaced while the hook ran: there is nothing
			// left to gate, fail, restart or publish.
			return
		}
		r.completePostStart(ctx, t, id, key, cname, err)
	}()
}

// completePostStart applies the hook's verdict: on success the readiness gate lifts
// and the status is republished at once (upstream publishes the moment the blocked
// sync completes — waiting for the next backstop tick would leave the pod NotReady
// for up to a resync period); on failure the container is killed per its restart
// policy (failPostStart).
func (r *runtimedRuntime) completePostStart(ctx context.Context, t *podTrack, podID, key, container string, hookErr error) {
	t.finishPostStart(container, hookErr)
	pod := r.podByID(podID)
	if pod == nil {
		return // deleted while the hook ran
	}
	if hookErr != nil {
		r.failPostStart(pod, podID, key, container, hookErr)
	}
	r.publishStatusUpdate(ctx, podID)
}

// failPostStart performs the kubelet's response to a failed postStart hook: it
// records the Warning event and kills the container so its restart policy decides
// what happens next (k8s.io/api core/v1 Lifecycle.PostStart: "If the handler fails,
// the container is terminated and restarted according to its restart policy").
//
// Under an effective policy that restarts a failed container the kill IS a re-exec,
// so it routes through the single restart authority — one backoff schedule,
// one restart window, runtimed's restart_count — and the replacement re-runs the
// hook (rerunPostStart).
//
// Under Never the kill is TERMINAL, and the provider CANNOT perform it: the runtime
// contract has no verb that stops one live container without re-spawning it
// (apis/runtime/v1: DeletePod kills the whole process group, UpdatePod takes a whole
// PodBox with no container selector, RestartContainer always re-spawns). What is
// done instead is deliberately the honest subset — the container is held NotReady
// for the rest of this start, it is never restarted, the failure is on the pod's
// Events and in the node log naming the missing capability. What is deliberately NOT
// done is report the container Terminated/Failed while its process keeps running: a
// reported-vs-actual divergence is strictly worse than a degraded-but-truthful
// surface. Closing the gap needs a runtimed-side stop verb (or a suppress-respawn
// field on RestartContainerRequest) — an apis + provider↔runtimed contract change,
// out of this unit's scope.
func (r *runtimedRuntime) failPostStart(pod *corev1.Pod, podID, key, container string, hookErr error) {
	// The hook's own error text never reaches the Event: Events flow to a
	// namespace-readable sink, and a handler's output can carry whatever the
	// container printed. Upstream withholds it for the same reason ("do not record
	// the message in the event so that secrets won't leak from the server"). The
	// concrete error goes to the node log only.
	r.log.Warn("postStart hook failed", "pod", key, "container", container, "err", hookErr)
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedPostStartHook, msgFailedPostStartHook(container))

	always := corev1.ContainerRestartPolicyAlways
	var containerPolicy *corev1.ContainerRestartPolicy
	if isNativeSidecar(pod, container) {
		containerPolicy = &always
	}
	// A failed hook is a container FAILURE: OnFailure restarts it, exactly as a
	// non-zero exit would. shouldRestartOnExit is the one effective-policy truth
	// table, so this decision cannot drift from the exit-driven one.
	failed := &corev1.ContainerStateTerminated{ExitCode: 1, Reason: reasonFailedPostStartHook}
	if !shouldRestartOnExit(effectivePodRestartPolicy(pod), containerPolicy, failed) {
		// Upstream would kill the container here and leave it terminal. See the
		// doc comment: there is no verb for that, so the honest surface is a
		// running container held permanently NotReady, named in the node log.
		r.log.Error("postStart hook failed under a restart policy that does not restart the container; held NotReady, but its process cannot be terminated in place (no per-container stop verb)",
			"pod", key, "container", container)
		return
	}
	if err := r.killAndRestart(podID, container, restartReasonPostStart); err != nil {
		r.log.Warn("postStart hook failed; container re-exec could not be scheduled",
			"pod", key, "container", container, "err", err)
	}
}

// rerunPostStart re-dispatches a container's postStart hook after a successful
// re-exec: upstream runs the hook inside startContainer, which is the same path a
// restart takes, so the hook fires on EVERY container start rather than once per
// pod. A container with no hook, or one whose pod has gone away, is a no-op.
//
// The httpGet host is the pod's bound IP as last published (falling back to the node
// IP) — the same resolution runPreStop uses; a restart never re-allocates the /32,
// so it is the address the replacement is reachable on.
func (r *runtimedRuntime) rerunPostStart(t *podTrack, podID, container string) {
	pod := r.podByID(podID)
	if pod == nil {
		return
	}
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name != container {
			continue
		}
		podIP := pod.Status.PodIP
		if podIP == "" {
			podIP = r.nodeIP
		}
		r.dispatchPostStart(t, pod, podIP, c)
		return
	}
}

// applyPostStartOverlay holds every container whose postStart hook is pending or
// failed NotReady, and re-derives the readiness conditions from the result
// (semantic 1). It runs on every published status because it is applied inside
// buildStatus, the single status assembly point.
//
// Started drops with Ready: upstream publishes NOTHING for the container while the
// hook runs, so a Started=true next to a pending hook would claim progress the
// container has not made.
//
// It gates MAIN container statuses only — the dispatch scope above — and container
// names are unique across a pod's containers and initContainers, so nothing an init
// status carries could match anyway.
//
// Locking: the gate set is snapshotted under hookMu and the status mutated outside
// it, so no callback can run under the lock. hookMu is never held together with
// restartMu or r.mu.
func (r *runtimedRuntime) applyPostStartOverlay(pod *corev1.Pod, t *podTrack, st *corev1.PodStatus) {
	gated := t.gatedContainers()
	if len(gated) == 0 {
		return
	}
	for i := range st.ContainerStatuses {
		if _, ok := gated[st.ContainerStatuses[i].Name]; !ok {
			continue
		}
		st.ContainerStatuses[i].Ready = false
		st.ContainerStatuses[i].Started = ptr(false)
	}
	refreshReadinessConditions(pod, st)
}
