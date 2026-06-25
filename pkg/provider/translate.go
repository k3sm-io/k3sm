package provider

import (
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// protoTime converts a proto timestamp to a metav1.Time, returning the zero
// value for a nil timestamp.
func protoTime(ts *timestamppb.Timestamp) metav1.Time {
	if ts == nil {
		return metav1.Time{}
	}
	return metav1.NewTime(ts.AsTime())
}

// dyldInsertAnnotation is the PodBox annotation runtimed reads to inject the
// darwin-net getaddrinfo DNS shim into each container (DYLD_INSERT_LIBRARIES).
// It matches runtimed/pkg/runtime's constant; the provider sets it when a shim
// path is configured.
const dyldInsertAnnotation = "k3sm.io/dyld-insert-libraries"

// toPodBox translates a corev1.Pod into the runtime PodBox runtimed consumes. It
// FILLS sandbox_profile and signature_policy so runtimed's fail-closed gate
// passes: an empty profile or UNSPECIFIED policy makes CreatePod refuse the pod.
//
// rootfsRoot is the per-pod-dir parent; dyldShim, when non-empty, is wired into
// the annotation runtimed copies to DYLD_INSERT_LIBRARIES (the DNS shim).
func toPodBox(pod *corev1.Pod, podIP, rootfsRoot, dyldShim string) *runtimev1.PodBox {
	box := &runtimev1.PodBox{
		PodId:       string(pod.UID),
		Namespace:   pod.Namespace,
		Name:        pod.Name,
		PodIp:       podIP,
		Labels:      pod.Labels,
		Annotations: map[string]string{},
		// SignaturePolicy: ad-hoc is the M1 posture — runtimed ad-hoc signs every
		// pulled binary on pull, so ADHOC_OK lets a freshly-signed native image run
		// while still rejecting the UNSPECIFIED fail-closed default.
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
	}
	if podIP != "" {
		box.PodIps = []string{podIP}
	}
	for k, v := range pod.Annotations {
		box.Annotations[k] = v
	}
	if dyldShim != "" {
		box.Annotations[dyldInsertAnnotation] = dyldShim
	}

	box.InitContainers = toRuntimeContainers(pod.Spec.InitContainers)
	box.Containers = toRuntimeContainers(pod.Spec.Containers)

	// data_volume_path is the only path the pod may write; default-deny otherwise.
	// allow_network is true so the pod can reach the Service proxy + CoreDNS VIP
	// (runtime scopes it to the pod IP). Seatbelt exec is the M1 backend.
	box.SandboxProfile = &runtimev1.SandboxProfile{
		Backend:        runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC,
		DataVolumePath: rootfsRoot,
		AllowNetwork:   true,
	}
	return box
}

// toRuntimeContainers maps corev1 containers to runtime containers (argv =
// command+args; env carried through; image is the pull reference or, when
// command/args are empty, the host binary path per the M0/M1 convention).
func toRuntimeContainers(cs []corev1.Container) []*runtimev1.Container {
	if len(cs) == 0 {
		return nil
	}
	out := make([]*runtimev1.Container, 0, len(cs))
	for i := range cs {
		c := &cs[i]
		rc := &runtimev1.Container{
			Name:       c.Name,
			Image:      c.Image,
			Command:    c.Command,
			Args:       c.Args,
			WorkingDir: c.WorkingDir,
			Tty:        c.TTY,
			Stdin:      c.Stdin,
		}
		for _, e := range c.Env {
			rc.Env = append(rc.Env, &runtimev1.EnvVar{Name: e.Name, Value: e.Value})
		}
		out = append(out, rc)
	}
	return out
}

// toPodStatus translates a runtime PodStatus into the corev1.PodStatus VK
// publishes, DERIVING the fields runtimed's renderer omits (it is lossy):
//   - the four Pod Conditions (Initialized/Ready/ContainersReady/PodScheduled),
//   - phase Running when any container runs and none has failed,
//   - a STABLE StartTime (passed in from CreatePod, not the per-snapshot value
//     runtimed regenerates),
//   - per-container Started (*bool) and Ready,
//   - terminated Reason/ExitCode/Signal carried VERBATIM (not the M0 "Error"
//     heuristic),
//   - HostIP/HostIPs from the node IP.
func toPodStatus(rs *runtimev1.PodStatus, nodeIP string, startTime metav1.Time) *corev1.PodStatus {
	cs := toContainerStatuses(rs.GetContainerStatuses())
	initCS := toContainerStatuses(rs.GetInitContainerStatuses())

	anyRunning, anyFailed, allReady := false, false, true
	for i := range cs {
		st := &cs[i]
		if st.State.Running != nil {
			anyRunning = true
		}
		if t := st.State.Terminated; t != nil && (t.ExitCode != 0 || t.Signal != 0) {
			anyFailed = true
		}
		if !st.Ready {
			allReady = false
		}
	}
	if len(cs) == 0 {
		allReady = false
	}

	phase := derivePhase(rs.GetPhase(), anyRunning, anyFailed)
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

	ready := corev1.ConditionFalse
	if (phase == corev1.PodRunning || phase == corev1.PodSucceeded) && allReady {
		ready = corev1.ConditionTrue
	}
	containersReady := corev1.ConditionFalse
	if allReady && anyRunning {
		containersReady = corev1.ConditionTrue
	}
	out.Conditions = []corev1.PodCondition{
		{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
		{Type: corev1.PodReady, Status: ready},
		{Type: corev1.ContainersReady, Status: containersReady},
		{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
	}
	return out
}

// derivePhase maps the runtime phase to a corev1 phase, honoring the rule "phase
// = Running when any container runs and none has failed" (the runtime's own
// phase is authoritative for terminal states).
func derivePhase(rp runtimev1.PodPhase, anyRunning, anyFailed bool) corev1.PodPhase {
	switch rp {
	case runtimev1.PodPhase_POD_PHASE_FAILED:
		return corev1.PodFailed
	case runtimev1.PodPhase_POD_PHASE_SUCCEEDED:
		return corev1.PodSucceeded
	case runtimev1.PodPhase_POD_PHASE_PENDING:
		return corev1.PodPending
	}
	switch {
	case anyRunning && !anyFailed:
		return corev1.PodRunning
	case anyFailed:
		return corev1.PodFailed
	default:
		return corev1.PodPending
	}
}

// toContainerStatuses maps runtime container statuses to corev1, carrying the
// terminated Reason/ExitCode/Signal VERBATIM and deriving Ready/Started.
func toContainerStatuses(rcs []*runtimev1.ContainerStatus) []corev1.ContainerStatus {
	if len(rcs) == 0 {
		return nil
	}
	out := make([]corev1.ContainerStatus, 0, len(rcs))
	for _, rc := range rcs {
		st := corev1.ContainerStatus{
			Name:         rc.GetName(),
			Image:        rc.GetImage(),
			ImageID:      rc.GetImageId(),
			ContainerID:  rc.GetContainerId(),
			RestartCount: rc.GetRestartCount(),
			Ready:        rc.GetReady(),
			State:        toContainerState(rc.GetState()),
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

// toContainerState maps a runtime ContainerState to corev1, preserving the
// terminated fields exactly (ExitCode, Signal, Reason, Message, timestamps).
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
			ContainerID: t.GetContainerId(),
		}}
	case rstate.GetWaiting() != nil:
		w := rstate.GetWaiting()
		return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason:  w.GetReason(),
			Message: w.GetMessage(),
		}}
	default:
		return corev1.ContainerState{}
	}
}
