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
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// protoTime converts a proto timestamp to a metav1.Time, returning the zero
// value for a nil timestamp.
func protoTime(ts *timestamppb.Timestamp) metav1.Time {
	if ts == nil {
		return metav1.Time{}
	}
	return metav1.NewTime(ts.AsTime())
}

// toPodStatus translates a runtime PodStatus into the corev1.PodStatus VK
// publishes, deriving the fields runtimed's renderer omits (it is lossy):
//   - the four Pod Conditions (Initialized/Ready/ContainersReady/PodScheduled),
//   - phase Running when any container runs and none has failed,
//   - a stable StartTime (passed in from CreatePod, not the per-snapshot value
//     runtimed regenerates),
//   - per-container Started (*bool) and Ready,
//   - terminated Reason/ExitCode/Signal carried verbatim (not the HostProcess
//     "Error"
//     heuristic) — this is the path the runtimed OOMKilled reason surfaces on,
//   - the ContainerStatus mirror (volume_mounts, user),
//   - the ephemeral container statuses, which are reported but never decide
//     the phase or any condition,
//   - HostIP/HostIPs from the node IP,
//   - Status.QOSClass: toPodStatus is the single place QOSClass is set, so
//     all four publish paths (GetPodStatus, GetPods, the watch-stream cb, the
//     probe-driven cb) emit a consistent value instead of blanking it on every
//     full-status replace. The apiserver-set value is carried forward
//     (authoritative + immutable); computePodQOS derives it only when unset (the
//     Pending pre-status window) or when pod is nil (the pod-less path).
//
// probes, when non-nil, overlays the provider-served probe verdicts:
// readiness drives each container's Ready (and thus the pod Ready/ContainersReady
// conditions → Service EndpointSlice membership), startup drives Started, and the
// probe-driven restart count is added — applied before the conditions are derived
// so the readiness signal propagates. A nil probes leaves the runtime status
// untouched (a pod with no probes).
//
// transport is the caller's network-path precondition on POD-LEVEL PodReady (see
// transportGate). It is transportReady for every native pod, so their status is
// byte-identical to one built before the gate existed.
func toPodStatus(pod *corev1.Pod, rs *runtimev1.PodStatus, nodeIP string, startTime metav1.Time, probes probeState, transport transportGate) *corev1.PodStatus {
	cs := toContainerStatuses(rs.GetContainerStatuses())
	initCS := toContainerStatuses(rs.GetInitContainerStatuses())
	applyProbeOverlay(cs, probes)

	containersReady := containersReadyFrom(cs)

	phase := derivePhase(pod, rs.GetPhase(), cs)
	out := &corev1.PodStatus{
		Phase:                 phase,
		Reason:                rs.GetReason(),
		Message:               rs.GetMessage(),
		HostIP:                nodeIP,
		HostIPs:               []corev1.HostIP{{IP: nodeIP}},
		PodIP:                 rs.GetPodIp(),
		StartTime:             &startTime,
		ContainerStatuses:     cs,
		InitContainerStatuses: initCS,
	}
	if ip := rs.GetPodIp(); ip != "" {
		out.PodIPs = []corev1.PodIP{{IP: ip}}
	}
	// Ephemeral containers are reported and nothing more: they never feed the
	// phase, readiness, ContainersReady, Initialized, probes, the restart
	// authority or the pull schedules, all of which read cs/initCS above or the
	// runtime's own container lists. The refusals this node derives (see
	// ephemeral.go) are merged in for the names the runtime does not report.
	out.EphemeralContainerStatuses = mergeEphemeralStatuses(toContainerStatuses(rs.GetEphemeralContainerStatuses()), pod)

	// QOSClass is set here and nowhere else (see the func doc). Carry
	// forward the apiserver's authoritative value; fall back to the hand-rolled
	// derivation only when unset or when no pod is in scope.
	if pod != nil {
		out.QOSClass = pod.Status.QOSClass
		if out.QOSClass == "" {
			out.QOSClass = computePodQOS(pod)
		}
	}

	crStatus := corev1.ConditionFalse
	if containersReady {
		crStatus = corev1.ConditionTrue
	}
	// Merge-not-replace (mirrors the QOSClass carry-forward above): emit the four
	// provider-owned conditions — PodReady via the shared computeReadiness seam so
	// spec.readinessGates are honored — then carry forward any external condition
	// on the input pod (e.g. a readinessGate a controller patched) so it survives
	// this status write and stays observable to computeReadiness.
	out.Conditions = []corev1.PodCondition{
		computeInitialized(pod, initCS),
		computeReadiness(pod, containersReady, transport),
		{Type: corev1.ContainersReady, Status: crStatus},
		{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
	}
	out.Conditions = append(out.Conditions, runtimeConditions(rs)...)
	out.Conditions = append(out.Conditions, carryForwardExternalConditions(pod)...)
	return out
}

// runtimeConditions returns the node-owned conditions runtimed publishes on
// PodStatus.conditions that the pod status carries verbatim:
// k3sm.io/shim-inactive (a restricted main process lost the pod shim) and
// k3sm.io/log-stream-lost (the pod was re-attached after a node-daemon restart,
// so output written while the daemon was down was not captured). The
// runtime's own renderings of the four kubelet-owned types are NOT forwarded,
// because toPodStatus derives those itself. A condition with an unspecified
// status is dropped rather than published as an empty ConditionStatus.
func runtimeConditions(rs *runtimev1.PodStatus) []corev1.PodCondition {
	var out []corev1.PodCondition
	for _, c := range rs.GetConditions() {
		if !isRuntimeCondition(c.GetType()) {
			continue
		}
		st, ok := conditionStatus(c.GetStatus())
		if !ok {
			continue
		}
		out = append(out, corev1.PodCondition{
			Type:               corev1.PodConditionType(c.GetType()),
			Status:             st,
			LastProbeTime:      protoTime(c.GetLastProbeTime()),
			LastTransitionTime: protoTime(c.GetLastTransitionTime()),
			Reason:             c.GetReason(),
			// The same sanitization as the ShimInactive Event
			// (observeShimInactive): one policy for both sinks, because the
			// message carries the container's own path (pod-spec text).
			Message: stripControl(c.GetMessage()),
		})
	}
	return out
}

// isRuntimeCondition reports whether t is a node-owned condition runtimed
// publishes and the pod status forwards (runtimeConditions).
func isRuntimeCondition(t string) bool {
	return t == runtimed.ShimInactiveConditionType || t == runtimed.LogStreamLostConditionType
}

// conditionStatus maps a runtime ConditionStatus to its corev1 form; ok is
// false for UNSPECIFIED (or an unknown future value).
func conditionStatus(s runtimev1.ConditionStatus) (corev1.ConditionStatus, bool) {
	switch s {
	case runtimev1.ConditionStatus_CONDITION_STATUS_TRUE:
		return corev1.ConditionTrue, true
	case runtimev1.ConditionStatus_CONDITION_STATUS_FALSE:
		return corev1.ConditionFalse, true
	case runtimev1.ConditionStatus_CONDITION_STATUS_UNKNOWN:
		return corev1.ConditionUnknown, true
	default:
		return "", false
	}
}

// containersReadyFrom reports the ContainersReady predicate over the pod's MAIN
// container statuses: the AND of every container's Ready AND at least one running
// container — not a hardcoded True. The anyRunning term matches the kubelet's
// running-gate: a non-running container carrying a stale
// Ready=true must not publish ContainersReady=True. (HostProcess has no
// readiness probes: a container is Ready when Running; applyProbeOverlay refines
// it when a readiness probe is served — the probe-less reduction.) It gates
// PodReady via the shared computeReadiness seam, which honors spec.readinessGates.
//
// It is a shared seam, not a toPodStatus local: a status overlay applied after
// the conditions are derived (the postStart readiness gate) must re-derive
// them from the same predicate, and two copies of this AND would drift.
func containersReadyFrom(cs []corev1.ContainerStatus) bool {
	anyRunning, allReady := false, len(cs) > 0
	for i := range cs {
		if cs[i].State.Running != nil {
			anyRunning = true
		}
		if !cs[i].Ready {
			allReady = false
		}
	}
	return allReady && anyRunning
}

// refreshReadinessConditions re-derives the two readiness conditions from the
// pod's (possibly overlaid) container statuses, in place. A status overlay that
// clears a container's Ready after toPodStatus derived the conditions would
// otherwise publish ContainersReady/PodReady=True next to a not-Ready container —
// a pod that takes Service traffic while the provider itself considers it not
// ready. PodReady goes back through computeReadiness (readinessGates + the stable
// LastTransitionTime prior), so a refreshed condition is indistinguishable from
// one derived with the gate applied in the first place.
//
// transport is threaded through unchanged so the postStart gate and the guest
// transport gate COMPOSE: an overlay that re-derives readiness must not discard
// the network-path precondition toPodStatus was built with, or the first
// postStart refresh would publish PodReady=True for an undialable vm pod.
func refreshReadinessConditions(pod *corev1.Pod, st *corev1.PodStatus, transport transportGate) {
	ready := containersReadyFrom(st.ContainerStatuses)
	crStatus := corev1.ConditionFalse
	if ready {
		crStatus = corev1.ConditionTrue
	}
	for i := range st.Conditions {
		switch st.Conditions[i].Type {
		case corev1.PodReady:
			st.Conditions[i] = computeReadiness(pod, ready, transport)
		case corev1.ContainersReady:
			st.Conditions[i].Status = crStatus
		}
	}
}

// transportGate is the provider-internal NETWORK-PATH precondition on POD-LEVEL
// PodReady. It exists because a vm pod's two addresses are installed at different
// moments: the pod's containers can be running and Ready while the Service proxy
// still has no published->live override for it (transportoverride.go), so the
// EndpointSlice would list a backend nothing can dial — and a failurePolicy=Fail
// webhook behind that Service rejects every request for as long as the window
// lasts (runtimed polls the guest's lease roughly every five seconds).
//
// IT GATES THE POD-LEVEL CONDITION ONLY. ContainersReady and every container's
// Ready flag are statements ABOUT THE CONTAINERS and are left exactly as computed
// — the containers really are ready; it is the node's path to them that is not.
// It is deliberately NOT a spec.readinessGate and NOT a new condition type: the
// fact is the provider's own and no external controller patches it.
//
// A gate that was satisfied can go back to transportPending — a guest that loses
// its lease is undialable again, and an undialable backend must leave the
// EndpointSlice — so PodReady flips back to False with the same reason. That is
// correct under the two-address model, not a flap to suppress.
type transportGate bool

const (
	// transportReady is the satisfied gate: the pod is dialable at its published
	// address. Every native (host-process) pod is born this way — its published
	// /32 IS live on lo0 — as is every build path with no vm pod in scope.
	transportReady transportGate = true
	// transportPending is the withheld gate: this node provisioned a guest for the
	// pod and the Service proxy holds no override for it yet.
	transportPending transportGate = false
)

// reasonGuestTransportNotReady is the PodReady reason a vm pod carries while its
// gate is transportPending. It sits beside the two kubelet-shaped reasons
// computeReadiness emits ("ContainersNotReady", "ReadinessGatesNotReady") and is
// deliberately k3sm-specific: no upstream reason names this window, and reusing
// one would tell an operator to go look at the containers, which are fine.
const reasonGuestTransportNotReady = "GuestTransportNotReady"

// computeReadiness derives the PodReady condition, honoring spec.readinessGates. It
// is the single pure authority every status-build path (toPodStatus, and
// CreatePod/reap via hostprocess.go) routes through, so PodReady never diverges
// between the live runtimed path and the host-process path.
//
// The rule (mirrors the kubelet's GeneratePodReadyCondition):
//   - containersReady is the precondition: when the containers are not ready the
//     gates are short-circuited and PodReady is False/"ContainersNotReady" (the
//     kubelet short-circuits gates behind ContainersReady).
//   - then k3sm's own transport gate: a vm pod whose live transport address the
//     Service proxy does not hold yet is False/"GuestTransportNotReady". It is
//     ordered AFTER containersReady — when both withhold, ContainersNotReady wins,
//     because a container that has not come up is the more actionable fact and the
//     transport window is a consequence of the pod being young — and BEFORE the
//     readinessGates, because an undialable pod cannot satisfy any consumer of the
//     Service regardless of what a gate condition says. The precedence chooses the
//     REASON STRING ONLY: PodReady is False under either order whenever two of
//     these withhold, so no ordering here can leak a Ready pod.
//   - otherwise PodReady = ContainersReady AND (every readinessGate whose condition
//     is present on the pod is True): a gate present-and-True is satisfied; a gate
//     present-and-not-True (False/Unknown) blocks with "ReadinessGatesNotReady"
//     naming the gate.
//
// Anti-stall ceiling (do not change without reading this): a readinessGate whose
// condition is absent from pod.Status.Conditions does not block PodReady — it is
// treated as not-yet-observable, as-if-satisfied. The k3sm VK provider cannot
// observe an externally-patched gate condition today (VK's podsEqual ignores
// status, UpdatePod is a no-op, and VK blind-overwrites pod status), so an absent
// gate blocking PodReady would stall every pod with an external readinessGate
// NotReady forever — strictly worse than advancing a rolling update too early.
// k3sm therefore honors observable gates only; the informer feedback loop that
// would let the provider react to external gate patches is a deferred follow-up.
func computeReadiness(pod *corev1.Pod, containersReady bool, transport transportGate) corev1.PodCondition {
	cond := corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionTrue}
	switch {
	case !containersReady:
		cond.Status = corev1.ConditionFalse
		cond.Reason = "ContainersNotReady"
		cond.Message = "containers are not ready"
	case transport == transportPending:
		cond.Status = corev1.ConditionFalse
		cond.Reason = reasonGuestTransportNotReady
		// One sentence covering BOTH states the gate withholds for: a guest that
		// never reported a lease and a guest that lost one it had. A message
		// written only for start-up would read as jitter on a pod that was Ready
		// for hours, which is when it matters most.
		cond.Message = "the guest has not reported its transport address yet, or lost the lease " +
			"it had; the runtime polls the guest agent every 5 s and this pod joins its " +
			"Services as soon as a lease is reported"
	case pod != nil:
		for i := range pod.Spec.ReadinessGates {
			gate := pod.Spec.ReadinessGates[i].ConditionType
			c := findPodCondition(pod.Status.Conditions, gate)
			if c == nil {
				continue // ABSENT → not-yet-observable → do NOT block (anti-stall ceiling)
			}
			if c.Status != corev1.ConditionTrue {
				cond.Status = corev1.ConditionFalse
				cond.Reason = "ReadinessGatesNotReady"
				cond.Message = fmt.Sprintf("the status of readiness gate %q is %q, want %q",
					gate, c.Status, corev1.ConditionTrue)
				break
			}
		}
	}
	cond.LastTransitionTime = readyTransitionTime(pod, cond.Status)
	return cond
}

// findPodCondition returns a pointer to the condition of type t within conds, or nil
// when absent. The returned pointer aliases the slice element (read-only use).
func findPodCondition(conds []corev1.PodCondition, t corev1.PodConditionType) *corev1.PodCondition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

// readyTransitionTime returns the LastTransitionTime for a PodReady condition
// flipping to newStatus: the pod's existing PodReady LastTransitionTime when the
// status is unchanged, else metav1.Now() (the flip instant).
func readyTransitionTime(pod *corev1.Pod, newStatus corev1.ConditionStatus) metav1.Time {
	if pod != nil {
		if cur := findPodCondition(pod.Status.Conditions, corev1.PodReady); cur != nil && cur.Status == newStatus {
			return cur.LastTransitionTime
		}
	}
	return metav1.Now()
}

// isProviderOwnedCondition reports whether t is one of the four Pod conditions the
// provider computes on every status write (Initialized/Ready/ContainersReady/
// PodScheduled). Any OTHER condition is external (e.g. a readinessGate condition)
// and is carried forward by carryForwardExternalConditions.
func isProviderOwnedCondition(t corev1.PodConditionType) bool {
	switch t {
	case corev1.PodInitialized, corev1.PodReady, corev1.ContainersReady, corev1.PodScheduled:
		return true
	case runtimed.ShimInactiveConditionType, runtimed.LogStreamLostConditionType:
		// Node-owned: toPodStatus re-reads them from the runtime on every build
		// (runtimeConditions), so a carried-forward copy would duplicate them.
		return true
	default:
		return false
	}
}

// carryForwardExternalConditions returns the pod's existing conditions minus the
// four provider-owned types, so external/readinessGate conditions survive a provider
// status rebuild (merge-not-replace, mirroring the QOSClass carry-forward in
// toPodStatus). A nil pod yields nil.
//
// This is a safe no-op in production today: the k3sm VK provider cannot yet
// observe an externally-patched gate condition (VK's podsEqual ignores status,
// UpdatePod is a no-op, and VK blind-overwrites pod status), so the input pod
// carries no external condition to preserve. It is wired now so that when the
// external-gate feedback loop lands (an informer feeding patches back to the
// provider, with no-clobber + a kine watch-staleness review — deferred),
// present gates are already observable to computeReadiness. Not an already-live
// external-gate path.
func carryForwardExternalConditions(pod *corev1.Pod) []corev1.PodCondition {
	if pod == nil {
		return nil
	}
	var out []corev1.PodCondition
	for i := range pod.Status.Conditions {
		if !isProviderOwnedCondition(pod.Status.Conditions[i].Type) {
			out = append(out, pod.Status.Conditions[i])
		}
	}
	return out
}

// applyProbeOverlay merges the provider-served probe verdicts into the container
// statuses: for a RUNNING container, a readiness/startup probe overrides
// Ready (so a failing readiness probe removes the pod from its Service
// EndpointSlice) and a startup probe overrides Started. Non-running containers
// keep the runtime's verdict (the prober only governs a live container).
//
// RestartCount is NOT touched (single-count-authority): runtimed bumps
// ContainerStatus.restart_count on the RestartContainer RPC — the same RPC the
// probe runner's doRestart drives — so the runtime count already includes every
// liveness-driven restart; adding the monitor's tally on top would double-count.
// A nil probes is a no-op.
func applyProbeOverlay(cs []corev1.ContainerStatus, probes probeState) {
	if probes == nil {
		return
	}
	for i := range cs {
		v, ok := probes.verdict(cs[i].Name)
		if !ok {
			continue
		}
		if cs[i].State.Running == nil {
			continue
		}
		if v.hasReadiness || v.hasStartup {
			cs[i].Ready = v.ready
		}
		if v.hasStartup {
			started := v.started
			cs[i].Started = &started
		}
	}
}

// derivePhase maps the runtime phase + the main container states to a corev1
// phase, honoring the pod's effective restart policy.
//
// The policy is load-bearing, not decoration: upstream's kubelet getPhase
// branches on RestartPolicy before it can return Failed — a pod only reaches
// Failed under Never (and only once every container is terminal), while under
// Always/OnFailure a terminated-but-restartable container keeps the pod Running.
// A policy-blind (anyRunning, anyFailed) check would report Failed for a
// crash-looping restartPolicy:Always pod, and upstream would react as if it
// were dead (a ReplicaSet delete/replace, a podgc reap, a Job backoffLimit
// strike). This consumes the same effective-policy resolver the restart
// decision uses (shouldRestartOnExit), so the phase and the restart decision
// can never disagree.
//
// Rules, in order:
//   - the runtime's PENDING is authoritative (the pod has not started);
//   - any main that is WAITING and has never run (no last termination) ⇒ Pending,
//     checked BEFORE the running case, because upstream's getPhase counts waiting
//     first: a pod whose second container cannot pull its image is Pending even
//     while its first container runs. A waiting container that DOES carry a last
//     termination is a restart in progress, not a start that never happened, so
//     CrashLoopBackOff keeps its Running verdict below;
//   - any running main ⇒ Running — upstream never reports a terminal phase while
//     a container runs, whatever a sibling did;
//   - a main that will be restarted (its termination resolves restartable, or it
//     already carries the synthesized CrashLoopBackOff waiting state) ⇒ Running;
//   - otherwise the runtime's own terminal verdict stands (mains-only, per the
//     Job contract).
//
// pod may be nil (the pod-less status path): with no spec there is no policy to
// honor, so the runtime's verdict is taken as authoritative and the legacy
// any-failed derivation applies. Production callers always pass the pod.
func derivePhase(pod *corev1.Pod, rp runtimev1.PodPhase, cs []corev1.ContainerStatus) corev1.PodPhase {
	if rp == runtimev1.PodPhase_POD_PHASE_PENDING {
		return corev1.PodPending
	}
	anyRunning, anyFailed, restartable := false, false, false
	waiting := 0
	policy := effectivePodRestartPolicy(pod)
	for i := range cs {
		st := &cs[i]
		if st.State.Running != nil {
			anyRunning = true
		}
		if st.State.Waiting != nil && st.LastTerminationState.Terminated == nil {
			waiting++
		}
		if t := st.State.Terminated; t != nil {
			if t.ExitCode != 0 || t.Signal != 0 {
				anyFailed = true
			}
			if pod != nil && shouldRestartOnExit(policy, nil, t) {
				restartable = true
			}
		}
		if w := st.State.Waiting; w != nil && w.Reason == reasonCrashLoopBackOff {
			restartable = true
		}
	}
	switch {
	case waiting > 0:
		return corev1.PodPending
	case anyRunning:
		return corev1.PodRunning
	case restartable:
		return corev1.PodRunning
	case rp == runtimev1.PodPhase_POD_PHASE_FAILED:
		return corev1.PodFailed
	case rp == runtimev1.PodPhase_POD_PHASE_SUCCEEDED:
		return corev1.PodSucceeded
	case anyFailed:
		return corev1.PodFailed
	default:
		return corev1.PodPending
	}
}

// computeInitialized derives the PodInitialized condition from the init-container
// statuses, rather than the unconditional ConditionTrue the
// provider used to stamp: a pod whose native sidecar is crash-looping before it
// ever started, or whose plain init container has not yet completed, must not
// report Initialized=True — controllers and `kubectl describe` read that
// condition as "the init phase is done".
//
// The rule mirrors the kubelet:
//   - a pod with no init containers is Initialized (nothing to wait for);
//   - a plain init container satisfies it by terminating with exit code 0;
//   - a native sidecar (init container with restartPolicy: Always, KEP-753)
//     satisfies it by having started — it is long-running by design and never
//     terminates before the mains;
//   - a declared init container with no status yet does not satisfy it.
//
// A nil pod yields True: with no spec there are no declared init containers to
// verify (the pod-less status path).
func computeInitialized(pod *corev1.Pod, initCS []corev1.ContainerStatus) corev1.PodCondition {
	cond := corev1.PodCondition{Type: corev1.PodInitialized, Status: corev1.ConditionTrue}
	if pod == nil || len(pod.Spec.InitContainers) == 0 {
		return cond
	}
	byName := make(map[string]*corev1.ContainerStatus, len(initCS))
	for i := range initCS {
		byName[initCS[i].Name] = &initCS[i]
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		st := byName[c.Name]
		sidecar := c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
		switch {
		case st == nil:
			// no status yet
		case sidecar && st.Started != nil && *st.Started:
			continue
		case !sidecar && st.State.Terminated != nil && st.State.Terminated.ExitCode == 0:
			continue
		}
		cond.Status = corev1.ConditionFalse
		cond.Reason = "ContainersNotInitialized"
		cond.Message = fmt.Sprintf("containers with incomplete status: [%s]", c.Name)
		return cond
	}
	return cond
}

// qualifyContainerID renders a runtimed container id in the `<runtime>://<id>`
// form kubelet consumers expect on ContainerStatus.containerID (containerd
// reports `containerd://…`, cri-o `cri-o://…`).
//
// The scheme is `runtimed.RuntimeName` — the same implementation name the daemon
// reports on GetRuntimeInfo — taken from the constant rather than spelled here,
// because two spellings of one runtime's name is exactly how a consumer ends up
// keying on a value the node stopped using.
//
// The prefix is applied HERE and not on the runtimed wire field on purpose: which
// runtime produced a status is a k8s-PRESENTATION fact known only to the
// assembler that selected the runtime, so a daemon that also serves a non-kubelet
// consumer must not have the k8s spelling baked into its own field.
//
// An empty id stays EMPTY. A bare `runtimed.RuntimeName + "://"` would assert
// that a container has an identity while naming none — worse than the blank a
// reader can see through.
func qualifyContainerID(id string) string {
	if id == "" {
		return ""
	}
	return runtimed.RuntimeName + "://" + id
}

// toContainerStatuses maps runtime container statuses to corev1, carrying the
// terminated Reason/ExitCode/Signal verbatim (so the runtimed OOMKilled reason
// surfaces) and deriving Ready/Started, plus the mirror fields (volume_mounts
// + user) so kubectl describe / get -o yaml stays a lossless mirror.
func toContainerStatuses(rcs []*runtimev1.ContainerStatus) []corev1.ContainerStatus {
	if len(rcs) == 0 {
		return nil
	}
	out := make([]corev1.ContainerStatus, 0, len(rcs))
	for _, rc := range rcs {
		st := corev1.ContainerStatus{
			Name:  rc.GetName(),
			Image: rc.GetImage(),
			// The identity pair: image_id is the image's config digest,
			// carried verbatim because it is a content address the runtime
			// resolved and this boundary has no business rewriting; container_id
			// is scheme-qualified here (see qualifyContainerID).
			ImageID:      rc.GetImageId(),
			ContainerID:  qualifyContainerID(rc.GetContainerId()),
			RestartCount: rc.GetRestartCount(),
			Ready:        rc.GetReady(),
			State:        toContainerState(rc.GetState()),
			VolumeMounts: toVolumeMountStatuses(rc.GetVolumeMounts()),
			User:         toContainerUser(rc.GetUser()),
		}
		if ls := toContainerState(rc.GetLastTerminationState()); ls != (corev1.ContainerState{}) {
			st.LastTerminationState = ls
		}
		// Started is *bool in corev1; runtimed carries started + started_set, but
		// also flags running via the state. Treat a running container as Started.
		started := rc.GetStarted() || st.State.Running != nil
		st.Started = ptr(started)
		out = append(out, st)
	}
	return out
}

// toVolumeMountStatuses maps the runtime VolumeMountStatus mirror (subset:
// name, mountPath, readOnly) back into corev1.
func toVolumeMountStatuses(vms []*runtimev1.VolumeMountStatus) []corev1.VolumeMountStatus {
	if len(vms) == 0 {
		return nil
	}
	out := make([]corev1.VolumeMountStatus, 0, len(vms))
	for _, vm := range vms {
		out = append(out, corev1.VolumeMountStatus{
			Name:      vm.GetName(),
			MountPath: vm.GetMountPath(),
			ReadOnly:  vm.GetReadOnly(),
		})
	}
	return out
}

// toContainerUser maps the runtime ContainerUser mirror (the effective uid/gid +
// supplemental groups the privilege drop produced) back into corev1, or nil when
// the runtime reported no resolved identity.
func toContainerUser(u *runtimev1.ContainerUser) *corev1.ContainerUser {
	if u == nil || u.GetLinux() == nil {
		return nil
	}
	l := u.GetLinux()
	return &corev1.ContainerUser{
		Linux: &corev1.LinuxContainerUser{
			UID:                l.GetUid(),
			GID:                l.GetGid(),
			SupplementalGroups: l.GetSupplementalGroups(),
		},
	}
}

// toContainerState maps a runtime ContainerState to corev1, preserving the
// terminated fields exactly (ExitCode, Signal, Reason, Message, timestamps).
// waitingReasonFor renders the kubelet's waiting reason for a runtimed waiting
// entry, switching on its TYPED failure_reason rather than on any text: runtimed
// owns the cause, the provider owns the vocabulary the kubelet's consumers read
// (see the reason block in runtimed_restart.go). A non-failure wait
// (UNSPECIFIED) carries runtimed's own kubelet-verbatim reason — PodInitializing
// for a container held behind an init sequence — and is passed through.
//
// The default arm is the proto's forward-compatibility rule, not a fallback of
// convenience: every value in the failure_reason 12-16 band is an image or
// container-start failure, so a value a future runtimed adds reads as
// ErrImagePull here rather than as an empty reason that would render a container
// stuck with no explanation at all (apis runtime.proto,
// ContainerStateWaiting.failure_reason).
func waitingReasonFor(w *runtimev1.ContainerStateWaiting) string {
	switch w.GetFailureReason() {
	case runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED:
		return w.GetReason()
	case runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME:
		return reasonInvalidImageName
	case runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL:
		return reasonErrImageNeverPull
	case runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG:
		return reasonCreateContainerConfigError
	case runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
		runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL,
		runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH,
		runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED:
		return reasonErrImagePull
	default:
		return reasonErrImagePull
	}
}

func toContainerState(rstate *runtimev1.ContainerState) corev1.ContainerState {
	if rstate == nil {
		return corev1.ContainerState{}
	}
	switch {
	case rstate.GetRunning() != nil:
		return corev1.ContainerState{Running: &corev1.ContainerStateRunning{
			StartedAt: protoTime(rstate.GetRunning().GetStartedAt()),
		}}
	case rstate.GetTerminated() != nil:
		t := rstate.GetTerminated()
		return corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			ExitCode:    t.GetExitCode(),
			Signal:      t.GetSignal(),
			Reason:      t.GetReason(),
			Message:     t.GetMessage(),
			StartedAt:   protoTime(t.GetStartedAt()),
			FinishedAt:  protoTime(t.GetFinishedAt()),
			ContainerID: qualifyContainerID(t.GetContainerId()),
		}}
	case rstate.GetWaiting() != nil:
		w := rstate.GetWaiting()
		return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason:  waitingReasonFor(w),
			Message: w.GetMessage(),
		}}
	default:
		return corev1.ContainerState{}
	}
}
