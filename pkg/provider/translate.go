package provider

import (
	"strconv"

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

// memoryLimitAnnotation carries the pod's memory limit in BYTES — the interim
// seam runtimed's OOM sampler + kubectl-top metering reads until apis:M2.2 defines
// a typed PodBox memory-limit field. It matches runtimed/pkg/runtime's constant
// (exactly as the DNS shim rides dyldInsertAnnotation). The value is in
// ri_phys_footprint units, NOT RSS.
const memoryLimitAnnotation = "k3sm.io/memory-limit-bytes"

// defaultGraceSeconds is the Kubernetes default SIGTERM→SIGKILL window applied
// when a pod sets no terminationGracePeriodSeconds. proto3 int64 cannot represent
// "unset", so the provider applies the 30s default itself — runtimed treats a 0
// grace as immediate-kill, which is NOT the k8s default.
const defaultGraceSeconds int64 = 30

// toPodBox translates a corev1.Pod into the runtime PodBox runtimed consumes. It
// FILLS sandbox_profile and signature_policy so runtimed's fail-closed gate
// passes: an empty profile or UNSPECIFIED policy makes CreatePod refuse the pod.
//
// rootfsRoot is the per-pod-dir parent; dyldShim, when non-empty, is wired into
// the annotation runtimed copies to DYLD_INSERT_LIBRARIES (the DNS shim).
//
// Container env is carried STRUCTURALLY here (literal value, valueFrom, envFrom);
// resolvePodBoxEnv flattens it into literal values before the box is sent to
// runtimed, which reads only EnvVar.value (it never talks to the apiserver).
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
	// The provider is the trusted producer of the memory-limit annotation: set it
	// from the pod's resource limits AFTER copying user annotations so it wins.
	if lim := podMemoryLimitBytes(pod); lim > 0 {
		box.Annotations[memoryLimitAnnotation] = strconv.FormatInt(lim, 10)
	}

	box.InitContainers = toRuntimeContainers(pod.Spec.InitContainers)
	box.Containers = toRuntimeContainers(pod.Spec.Containers)

	box.Volumes = toVolumes(pod.Spec.Volumes)
	box.PodSecurityContext = toPodSecurityContext(pod.Spec.SecurityContext)
	box.ImagePullSecrets = toLocalRefs(pod.Spec.ImagePullSecrets)

	// termination_grace_period_seconds mirrors the spec (k8s 30s default applied
	// for "unset" since proto3 cannot carry nil); the provider derives the
	// per-deletion DeletePodRequest.grace_period_seconds separately (graceSeconds).
	box.TerminationGracePeriodSeconds = defaultGraceSeconds
	if g := pod.Spec.TerminationGracePeriodSeconds; g != nil {
		box.TerminationGracePeriodSeconds = *g
	}

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

// podMemoryLimitBytes returns the pod's effective memory limit in bytes, or 0 for
// "unlimited" (no OOM enforcement). It sums the regular containers' memory limits
// and returns 0 unless EVERY regular container sets one: a pod has no enforceable
// ceiling if any container is unbounded, and an under-counted sum would falsely
// OOM the unbounded container. Init containers run sequentially BEFORE the regular
// ones, so they add nothing to the concurrent footprint budget.
func podMemoryLimitBytes(pod *corev1.Pod) int64 {
	if len(pod.Spec.Containers) == 0 {
		return 0
	}
	var sum int64
	for i := range pod.Spec.Containers {
		q, ok := pod.Spec.Containers[i].Resources.Limits[corev1.ResourceMemory]
		if !ok {
			return 0 // an unbounded container ⇒ no enforceable pod ceiling
		}
		sum += q.Value()
	}
	return sum
}

// graceSeconds is the SIGTERM→SIGKILL window the provider passes as
// DeletePodRequest.grace_period_seconds. The apiserver stamps
// DeletionGracePeriodSeconds on the object at delete time (honoring a kubectl
// --grace-period override), so it takes precedence; otherwise the pod's
// terminationGracePeriodSeconds; otherwise the k8s 30s default. runtimed treats a
// 0 grace as immediate-kill — which is why the default is applied HERE, not left
// to the proto3 zero value.
func graceSeconds(pod *corev1.Pod) int64 {
	if g := pod.DeletionGracePeriodSeconds; g != nil {
		return *g
	}
	if g := pod.Spec.TerminationGracePeriodSeconds; g != nil {
		return *g
	}
	return defaultGraceSeconds
}

// toRuntimeContainers maps corev1 containers to runtime containers (argv =
// command+args; the M2.1 volume_mounts/ports/security_context/env_from surface;
// env carried structurally for resolvePodBoxEnv; image is the pull reference or,
// when command/args are empty, the host binary path per the M0/M1 convention).
func toRuntimeContainers(cs []corev1.Container) []*runtimev1.Container {
	if len(cs) == 0 {
		return nil
	}
	out := make([]*runtimev1.Container, 0, len(cs))
	for i := range cs {
		c := &cs[i]
		rc := &runtimev1.Container{
			Name:            c.Name,
			Image:           c.Image,
			Command:         c.Command,
			Args:            c.Args,
			WorkingDir:      c.WorkingDir,
			Tty:             c.TTY,
			Stdin:           c.Stdin,
			VolumeMounts:    toVolumeMounts(c.VolumeMounts),
			Ports:           toContainerPorts(c.Ports),
			SecurityContext: toSecurityContext(c.SecurityContext),
			EnvFrom:         toEnvFrom(c.EnvFrom),
			Env:             toEnvVars(c.Env),
		}
		out = append(out, rc)
	}
	return out
}

// toEnvVars carries corev1 env structurally: a literal value passes through; a
// valueFrom (downward-API fieldRef / configMapKeyRef / secretKeyRef) is preserved
// for resolvePodBoxEnv to flatten into a literal value before the box reaches
// runtimed.
func toEnvVars(env []corev1.EnvVar) []*runtimev1.EnvVar {
	if len(env) == 0 {
		return nil
	}
	out := make([]*runtimev1.EnvVar, 0, len(env))
	for i := range env {
		e := &env[i]
		rv := &runtimev1.EnvVar{Name: e.Name, Value: e.Value}
		if e.ValueFrom != nil {
			rv.ValueFrom = toEnvVarSource(e.ValueFrom)
		}
		out = append(out, rv)
	}
	return out
}

// toEnvVarSource maps the corev1 env value source union (M2.1 subset: fieldRef /
// configMapKeyRef / secretKeyRef; resourceFieldRef is not modeled).
func toEnvVarSource(src *corev1.EnvVarSource) *runtimev1.EnvVarSource {
	out := &runtimev1.EnvVarSource{}
	if fr := src.FieldRef; fr != nil {
		out.FieldRef = &runtimev1.ObjectFieldSelector{ApiVersion: fr.APIVersion, FieldPath: fr.FieldPath}
	}
	if ck := src.ConfigMapKeyRef; ck != nil {
		out.ConfigMapKeyRef = &runtimev1.ConfigMapKeySelector{Name: ck.Name, Key: ck.Key, Optional: derefBool(ck.Optional)}
	}
	if sk := src.SecretKeyRef; sk != nil {
		out.SecretKeyRef = &runtimev1.SecretKeySelector{Name: sk.Name, Key: sk.Key, Optional: derefBool(sk.Optional)}
	}
	return out
}

// toEnvFrom maps corev1 envFrom sources (whole ConfigMap/Secret → env, optional
// per-source prefix). resolvePodBoxEnv expands these into literal env vars.
func toEnvFrom(sources []corev1.EnvFromSource) []*runtimev1.EnvFromSource {
	if len(sources) == 0 {
		return nil
	}
	out := make([]*runtimev1.EnvFromSource, 0, len(sources))
	for i := range sources {
		s := &sources[i]
		ef := &runtimev1.EnvFromSource{Prefix: s.Prefix}
		if cm := s.ConfigMapRef; cm != nil {
			ef.ConfigMapRef = &runtimev1.ConfigMapEnvSource{Name: cm.Name, Optional: derefBool(cm.Optional)}
		}
		if sec := s.SecretRef; sec != nil {
			ef.SecretRef = &runtimev1.SecretEnvSource{Name: sec.Name, Optional: derefBool(sec.Optional)}
		}
		out = append(out, ef)
	}
	return out
}

// toVolumeMounts maps corev1 volume mounts (M2.1 subset: name, mountPath,
// readOnly, subPath).
func toVolumeMounts(mounts []corev1.VolumeMount) []*runtimev1.VolumeMount {
	if len(mounts) == 0 {
		return nil
	}
	out := make([]*runtimev1.VolumeMount, 0, len(mounts))
	for i := range mounts {
		m := &mounts[i]
		out = append(out, &runtimev1.VolumeMount{
			Name:      m.Name,
			MountPath: m.MountPath,
			ReadOnly:  m.ReadOnly,
			SubPath:   m.SubPath,
		})
	}
	return out
}

// toContainerPorts maps corev1 container ports (M2.1 subset: name, containerPort,
// protocol — the named-port table named probe ports and Service targetPorts
// resolve against; host_port/host_ip are not modeled, k3sm pods bind the pod IP).
func toContainerPorts(ports []corev1.ContainerPort) []*runtimev1.ContainerPort {
	if len(ports) == 0 {
		return nil
	}
	out := make([]*runtimev1.ContainerPort, 0, len(ports))
	for i := range ports {
		p := &ports[i]
		out = append(out, &runtimev1.ContainerPort{
			Name:          p.Name,
			ContainerPort: p.ContainerPort,
			Protocol:      string(p.Protocol),
		})
	}
	return out
}

// toSecurityContext maps the container-scoped securityContext (M2.1 subset:
// runAsUser/runAsGroup/runAsNonRoot). fsGroup is pod-scoped, not here. Returns nil
// when the corev1 context carries none of the modeled fields, so an empty box
// field signals "inherit pod defaults".
func toSecurityContext(sc *corev1.SecurityContext) *runtimev1.SecurityContext {
	if sc == nil || (sc.RunAsUser == nil && sc.RunAsGroup == nil && sc.RunAsNonRoot == nil) {
		return nil
	}
	return &runtimev1.SecurityContext{
		RunAsUser:    derefInt64(sc.RunAsUser),
		RunAsGroup:   derefInt64(sc.RunAsGroup),
		RunAsNonRoot: derefBool(sc.RunAsNonRoot),
	}
}

// toPodSecurityContext maps the pod-scoped securityContext (M2.1 subset:
// fsGroup/runAsUser/runAsGroup). fsGroup lives HERE (pod-level only). Returns nil
// when none of the modeled fields is set.
func toPodSecurityContext(sc *corev1.PodSecurityContext) *runtimev1.PodSecurityContext {
	if sc == nil || (sc.FSGroup == nil && sc.RunAsUser == nil && sc.RunAsGroup == nil) {
		return nil
	}
	return &runtimev1.PodSecurityContext{
		FsGroup:    derefInt64(sc.FSGroup),
		RunAsUser:  derefInt64(sc.RunAsUser),
		RunAsGroup: derefInt64(sc.RunAsGroup),
	}
}

// toLocalRefs maps corev1 imagePullSecret references. runtimed confines the
// resolved credential to the pull client (it never reaches the pod dir); the
// proto carries only the name.
func toLocalRefs(refs []corev1.LocalObjectReference) []*runtimev1.LocalObjectReference {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*runtimev1.LocalObjectReference, 0, len(refs))
	for i := range refs {
		out = append(out, &runtimev1.LocalObjectReference{Name: refs[i].Name})
	}
	return out
}

// toVolumes maps the M2.1 corev1 volume subset (configMap / secret / emptyDir /
// downwardAPI / projected); volumes with an unmodeled source are skipped (the
// runtime materializes only the modeled set).
func toVolumes(vols []corev1.Volume) []*runtimev1.Volume {
	if len(vols) == 0 {
		return nil
	}
	out := make([]*runtimev1.Volume, 0, len(vols))
	for i := range vols {
		v := toVolume(&vols[i])
		if v != nil {
			out = append(out, v)
		}
	}
	return out
}

// toVolume maps one corev1.Volume's modeled source, or nil if none is modeled.
func toVolume(v *corev1.Volume) *runtimev1.Volume {
	rv := &runtimev1.Volume{Name: v.Name}
	switch {
	case v.ConfigMap != nil:
		rv.ConfigMap = toConfigMapVolumeSource(v.ConfigMap)
	case v.Secret != nil:
		rv.Secret = toSecretVolumeSource(v.Secret)
	case v.EmptyDir != nil:
		rv.EmptyDir = toEmptyDirVolumeSource(v.EmptyDir)
	case v.DownwardAPI != nil:
		rv.DownwardApi = toDownwardAPIVolumeSource(v.DownwardAPI)
	case v.Projected != nil:
		rv.Projected = toProjectedVolumeSource(v.Projected)
	default:
		return nil
	}
	return rv
}

func toConfigMapVolumeSource(src *corev1.ConfigMapVolumeSource) *runtimev1.ConfigMapVolumeSource {
	return &runtimev1.ConfigMapVolumeSource{
		Name:        src.Name,
		Items:       toKeyToPaths(src.Items),
		DefaultMode: derefInt32(src.DefaultMode),
		Optional:    derefBool(src.Optional),
	}
}

func toSecretVolumeSource(src *corev1.SecretVolumeSource) *runtimev1.SecretVolumeSource {
	return &runtimev1.SecretVolumeSource{
		SecretName:  src.SecretName,
		Items:       toKeyToPaths(src.Items),
		DefaultMode: derefInt32(src.DefaultMode),
		Optional:    derefBool(src.Optional),
	}
}

func toEmptyDirVolumeSource(src *corev1.EmptyDirVolumeSource) *runtimev1.EmptyDirVolumeSource {
	out := &runtimev1.EmptyDirVolumeSource{Medium: string(src.Medium)}
	if src.SizeLimit != nil {
		out.SizeLimit = src.SizeLimit.String()
	}
	return out
}

func toDownwardAPIVolumeSource(src *corev1.DownwardAPIVolumeSource) *runtimev1.DownwardAPIVolumeSource {
	return &runtimev1.DownwardAPIVolumeSource{
		Items:       toDownwardAPIFiles(src.Items),
		DefaultMode: derefInt32(src.DefaultMode),
	}
}

// toDownwardAPIFiles maps downward-API file projections (M2.1 subset: fieldRef
// only — resourceFieldRef is not modeled, those files are skipped).
func toDownwardAPIFiles(items []corev1.DownwardAPIVolumeFile) []*runtimev1.DownwardAPIVolumeFile {
	if len(items) == 0 {
		return nil
	}
	out := make([]*runtimev1.DownwardAPIVolumeFile, 0, len(items))
	for i := range items {
		it := &items[i]
		if it.FieldRef == nil {
			continue
		}
		out = append(out, &runtimev1.DownwardAPIVolumeFile{
			Path:     it.Path,
			FieldRef: &runtimev1.ObjectFieldSelector{ApiVersion: it.FieldRef.APIVersion, FieldPath: it.FieldRef.FieldPath},
			Mode:     derefInt32(it.Mode),
		})
	}
	return out
}

func toProjectedVolumeSource(src *corev1.ProjectedVolumeSource) *runtimev1.ProjectedVolumeSource {
	out := &runtimev1.ProjectedVolumeSource{DefaultMode: derefInt32(src.DefaultMode)}
	for i := range src.Sources {
		if p := toVolumeProjection(&src.Sources[i]); p != nil {
			out.Sources = append(out.Sources, p)
		}
	}
	return out
}

// toVolumeProjection maps one projection (M2.1 subset: configMap / secret /
// downwardAPI / serviceAccountToken), or nil if none is modeled.
func toVolumeProjection(p *corev1.VolumeProjection) *runtimev1.VolumeProjection {
	out := &runtimev1.VolumeProjection{}
	switch {
	case p.ConfigMap != nil:
		out.ConfigMap = &runtimev1.ConfigMapProjection{Name: p.ConfigMap.Name, Items: toKeyToPaths(p.ConfigMap.Items), Optional: derefBool(p.ConfigMap.Optional)}
	case p.Secret != nil:
		out.Secret = &runtimev1.SecretProjection{Name: p.Secret.Name, Items: toKeyToPaths(p.Secret.Items), Optional: derefBool(p.Secret.Optional)}
	case p.DownwardAPI != nil:
		out.DownwardApi = &runtimev1.DownwardAPIProjection{Items: toDownwardAPIFiles(p.DownwardAPI.Items)}
	case p.ServiceAccountToken != nil:
		out.ServiceAccountToken = &runtimev1.ServiceAccountTokenProjection{
			Audience:          p.ServiceAccountToken.Audience,
			ExpirationSeconds: derefInt64(p.ServiceAccountToken.ExpirationSeconds),
			Path:              p.ServiceAccountToken.Path,
		}
	default:
		return nil
	}
	return out
}

func toKeyToPaths(items []corev1.KeyToPath) []*runtimev1.KeyToPath {
	if len(items) == 0 {
		return nil
	}
	out := make([]*runtimev1.KeyToPath, 0, len(items))
	for i := range items {
		out = append(out, &runtimev1.KeyToPath{Key: items[i].Key, Path: items[i].Path, Mode: derefInt32(items[i].Mode)})
	}
	return out
}

func derefBool(p *bool) bool {
	return p != nil && *p
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// toPodStatus translates a runtime PodStatus into the corev1.PodStatus VK
// publishes, DERIVING the fields runtimed's renderer omits (it is lossy):
//   - the four Pod Conditions (Initialized/Ready/ContainersReady/PodScheduled),
//   - phase Running when any container runs and none has failed,
//   - a STABLE StartTime (passed in from CreatePod, not the per-snapshot value
//     runtimed regenerates),
//   - per-container Started (*bool) and Ready,
//   - terminated Reason/ExitCode/Signal carried VERBATIM (not the M0 "Error"
//     heuristic) — this is the path the runtimed OOMKilled reason surfaces on,
//   - the M2.1 ContainerStatus mirror (volume_mounts, user),
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
// terminated Reason/ExitCode/Signal VERBATIM (so the runtimed OOMKilled reason
// surfaces) and deriving Ready/Started, plus the M2.1 mirror fields (volume_mounts
// + user) so kubectl describe / get -o yaml stays a lossless mirror.
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

// toVolumeMountStatuses maps the runtime VolumeMountStatus mirror (M2.1 subset:
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
