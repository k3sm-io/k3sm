package provider

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestToPodBoxFillsGate verifies the corev1.Pod→PodBox translation fills the
// fail-closed gate fields (SandboxProfile + a non-UNSPECIFIED SignaturePolicy)
// and carries the DNS shim annotation, so runtimed's CreatePod does not refuse
// the pod.
func TestToPodBoxFillsGate(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: types.UID("uid-web")},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "c0",
				Image:   "registry/web:latest",
				Command: []string{"/web"},
				Args:    []string{"--port", "8080"},
				Env:     []corev1.EnvVar{{Name: "FOO", Value: "bar"}},
			}},
		},
	}
	box := toPodBox(pod, "10.0.0.5", "/var/lib/k3sm/pods/uid-web", "/lib/shim.dylib")

	if box.GetPodId() != "uid-web" {
		t.Errorf("pod id = %q, want uid-web", box.GetPodId())
	}
	if box.GetSandboxProfile() == nil {
		t.Fatal("sandbox_profile must be set so runtimed's fail-closed gate passes")
	}
	if box.GetSandboxProfile().GetBackend() == runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
		t.Error("sandbox backend must not be UNSPECIFIED")
	}
	if box.GetSandboxProfile().GetDataVolumePath() == "" {
		t.Error("data_volume_path must be set (the only writable path)")
	}
	if box.GetSignaturePolicy() == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		t.Error("signature_policy must not be UNSPECIFIED (fail-closed)")
	}
	if got := box.GetAnnotations()["k3sm.io/dyld-insert-libraries"]; got != "/lib/shim.dylib" {
		t.Errorf("dyld insert annotation = %q, want /lib/shim.dylib", got)
	}
	if len(box.GetContainers()) != 1 {
		t.Fatalf("want 1 container, got %d", len(box.GetContainers()))
	}
	c := box.GetContainers()[0]
	if len(c.GetCommand()) != 1 || len(c.GetArgs()) != 2 {
		t.Errorf("argv not carried: command=%v args=%v", c.GetCommand(), c.GetArgs())
	}
	if len(c.GetEnv()) != 1 || c.GetEnv()[0].GetName() != "FOO" {
		t.Errorf("env not carried: %v", c.GetEnv())
	}
}

func runningRS(podID string, startedAt time.Time) *runtimev1.PodStatus {
	return &runtimev1.PodStatus{
		PodId: podID,
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		PodIp: "10.0.0.5",
		ContainerStatuses: []*runtimev1.ContainerStatus{{
			Name:  "c0",
			Image: "web",
			Ready: true,
			State: &runtimev1.ContainerState{
				Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(startedAt)},
			},
		}},
	}
}

// TestToPodStatusRunning checks the running translation derives the four
// Conditions, a Running phase, a STABLE StartTime (the passed-in value, NOT the
// runtime's regenerated one), HostIP, and per-container Started/Ready.
func TestToPodStatusRunning(t *testing.T) {
	stable := metav1.NewTime(time.Unix(1000, 0))
	rs := runningRS("uid-web", time.Unix(2000, 0))

	st := toPodStatus(rs, "192.168.1.10", stable, nil)

	if st.Phase != corev1.PodRunning {
		t.Errorf("phase = %s, want Running", st.Phase)
	}
	if st.StartTime == nil || !st.StartTime.Equal(&stable) {
		t.Errorf("StartTime = %v, want the stable %v (not regenerated)", st.StartTime, stable)
	}
	if st.HostIP != "192.168.1.10" {
		t.Errorf("HostIP = %q, want 192.168.1.10", st.HostIP)
	}
	if len(st.PodIPs) != 1 || st.PodIPs[0].IP != "10.0.0.5" {
		t.Errorf("PodIPs = %v, want [10.0.0.5]", st.PodIPs)
	}
	conds := map[corev1.PodConditionType]corev1.ConditionStatus{}
	for _, c := range st.Conditions {
		conds[c.Type] = c.Status
	}
	for _, want := range []corev1.PodConditionType{corev1.PodInitialized, corev1.PodReady, corev1.ContainersReady, corev1.PodScheduled} {
		if _, ok := conds[want]; !ok {
			t.Errorf("missing condition %s", want)
		}
	}
	if conds[corev1.PodReady] != corev1.ConditionTrue {
		t.Errorf("PodReady = %s, want True (container ready)", conds[corev1.PodReady])
	}
	if conds[corev1.ContainersReady] != corev1.ConditionTrue {
		t.Errorf("ContainersReady = %s, want True", conds[corev1.ContainersReady])
	}
	cs := st.ContainerStatuses[0]
	if cs.State.Running == nil {
		t.Fatal("container should be Running")
	}
	if cs.Started == nil || !*cs.Started {
		t.Error("running container Started should be true")
	}
}

// TestToPodStatusTerminatedVerbatim verifies the terminated translation carries
// ExitCode, Signal, and Reason VERBATIM (not the M0 "Error" heuristic) and
// derives a Failed phase + Ready=False.
func TestToPodStatusTerminatedVerbatim(t *testing.T) {
	rs := &runtimev1.PodStatus{
		PodId: "uid-x",
		Phase: runtimev1.PodPhase_POD_PHASE_FAILED,
		ContainerStatuses: []*runtimev1.ContainerStatus{{
			Name: "c0",
			State: &runtimev1.ContainerState{
				Terminated: &runtimev1.ContainerStateTerminated{
					ExitCode: 137,
					Signal:   9,
					Reason:   "OOMKilled",
					Message:  "killed",
				},
			},
		}},
	}
	st := toPodStatus(rs, "10.0.0.1", metav1.Now(), nil)

	if st.Phase != corev1.PodFailed {
		t.Errorf("phase = %s, want Failed", st.Phase)
	}
	term := st.ContainerStatuses[0].State.Terminated
	if term == nil {
		t.Fatal("expected terminated state")
	}
	if term.ExitCode != 137 {
		t.Errorf("ExitCode = %d, want 137 (verbatim)", term.ExitCode)
	}
	if term.Signal != 9 {
		t.Errorf("Signal = %d, want 9 (verbatim)", term.Signal)
	}
	if term.Reason != "OOMKilled" {
		t.Errorf("Reason = %q, want OOMKilled (verbatim, not the M0 Error heuristic)", term.Reason)
	}
	for _, c := range st.Conditions {
		if c.Type == corev1.PodReady && c.Status != corev1.ConditionFalse {
			t.Errorf("PodReady = %s, want False for a failed pod", c.Status)
		}
	}
}

// TestToPodBoxM2Fields is the M2.1-a1 proof that the translation carries the new
// pod-spec surface to the PodBox: configMap/secret/emptyDir/downwardAPI/projected
// volumes + volumeMounts, downward-API env (structural valueFrom) + envFrom,
// container securityContext, pod fsGroup, terminationGracePeriodSeconds, and
// imagePullSecrets.
func TestToPodBoxM2Fields(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api", UID: types.UID("uid-api")},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: ptr(int64(45)),
			ImagePullSecrets:              []corev1.LocalObjectReference{{Name: "regcred"}},
			SecurityContext:               &corev1.PodSecurityContext{FSGroup: ptr(int64(999)), RunAsUser: ptr(int64(101))},
			Volumes: []corev1.Volume{
				{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}}},
				{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "app-secret"}}},
				{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "podinfo", VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{Items: []corev1.DownwardAPIVolumeFile{{Path: "name", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}}}},
				{Name: "projected", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Audience: "api", Path: "token", ExpirationSeconds: ptr(int64(3600))}}}}}},
			},
			Containers: []corev1.Container{{
				Name:  "c0",
				Image: "registry/api:latest",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "cfg", MountPath: "/etc/config", ReadOnly: true},
					{Name: "scratch", MountPath: "/scratch"},
				},
				Ports:           []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
				SecurityContext: &corev1.SecurityContext{RunAsUser: ptr(int64(1000)), RunAsGroup: ptr(int64(2000))},
				Env: []corev1.EnvVar{
					{Name: "NODE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
				},
				EnvFrom: []corev1.EnvFromSource{
					{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "env-config"}}},
					{Prefix: "S_", SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "env-secret"}}},
				},
			}},
		},
	}
	box := toPodBox(pod, "10.0.0.7", "/var/lib/k3sm/pods/uid-api", "")

	if got := len(box.GetVolumes()); got != 5 {
		t.Fatalf("volumes = %d, want 5", got)
	}
	byName := map[string]*runtimev1.Volume{}
	for _, v := range box.GetVolumes() {
		byName[v.GetName()] = v
	}
	if byName["cfg"].GetConfigMap().GetName() != "app-config" {
		t.Error("configMap volume source not carried")
	}
	if byName["sec"].GetSecret().GetSecretName() != "app-secret" {
		t.Error("secret volume source not carried")
	}
	if byName["scratch"].GetEmptyDir() == nil {
		t.Error("emptyDir volume source not carried")
	}
	if len(byName["podinfo"].GetDownwardApi().GetItems()) != 1 {
		t.Error("downwardAPI volume source not carried")
	}
	sat := byName["projected"].GetProjected().GetSources()
	if len(sat) != 1 || sat[0].GetServiceAccountToken().GetAudience() != "api" {
		t.Error("projected serviceAccountToken not carried")
	}

	if box.GetPodSecurityContext().GetFsGroup() != 999 {
		t.Errorf("fsGroup = %d, want 999", box.GetPodSecurityContext().GetFsGroup())
	}
	if box.GetTerminationGracePeriodSeconds() != 45 {
		t.Errorf("grace = %d, want 45", box.GetTerminationGracePeriodSeconds())
	}
	if len(box.GetImagePullSecrets()) != 1 || box.GetImagePullSecrets()[0].GetName() != "regcred" {
		t.Errorf("imagePullSecrets = %v, want [regcred]", box.GetImagePullSecrets())
	}

	c := box.GetContainers()[0]
	if len(c.GetVolumeMounts()) != 2 || !c.GetVolumeMounts()[0].GetReadOnly() {
		t.Errorf("volumeMounts not carried: %v", c.GetVolumeMounts())
	}
	if len(c.GetPorts()) != 1 || c.GetPorts()[0].GetContainerPort() != 8080 {
		t.Errorf("ports not carried: %v", c.GetPorts())
	}
	if c.GetSecurityContext().GetRunAsUser() != 1000 || c.GetSecurityContext().GetRunAsGroup() != 2000 {
		t.Errorf("container securityContext not carried: %v", c.GetSecurityContext())
	}
	if len(c.GetEnvFrom()) != 2 || c.GetEnvFrom()[1].GetPrefix() != "S_" || c.GetEnvFrom()[1].GetSecretRef().GetName() != "env-secret" {
		t.Errorf("envFrom not carried: %v", c.GetEnvFrom())
	}
	if len(c.GetEnv()) != 1 || c.GetEnv()[0].GetValueFrom().GetFieldRef().GetFieldPath() != "spec.nodeName" {
		t.Errorf("downward-API env (valueFrom) not carried structurally: %v", c.GetEnv())
	}
}

// TestToPodBoxMemoryLimitAnnotation is the M2.3-a1 proof that the pod's
// resources.limits.memory drives the k3sm.io/memory-limit-bytes annotation
// (runtimed's interim OOM/metering seam): set from a bounded pod, summed across
// containers, and ABSENT when any container is unbounded (no false OOM).
func TestToPodBoxMemoryLimitAnnotation(t *testing.T) {
	mem := func(s string) corev1.ResourceList {
		return corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(s)}
	}
	tests := []struct {
		name       string
		containers []corev1.Container
		wantAnno   string // "" ⇒ annotation must be absent
	}{
		{
			name:       "single bounded container",
			containers: []corev1.Container{{Name: "c0", Resources: corev1.ResourceRequirements{Limits: mem("256Mi")}}},
			wantAnno:   "268435456",
		},
		{
			name: "summed across bounded containers",
			containers: []corev1.Container{
				{Name: "c0", Resources: corev1.ResourceRequirements{Limits: mem("256Mi")}},
				{Name: "c1", Resources: corev1.ResourceRequirements{Limits: mem("256Mi")}},
			},
			wantAnno: "536870912",
		},
		{
			name: "any unbounded container ⇒ no annotation",
			containers: []corev1.Container{
				{Name: "c0", Resources: corev1.ResourceRequirements{Limits: mem("256Mi")}},
				{Name: "c1"},
			},
			wantAnno: "",
		},
		{
			name:       "no limits ⇒ no annotation",
			containers: []corev1.Container{{Name: "c0"}},
			wantAnno:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p", UID: types.UID("uid-p")},
				Spec:       corev1.PodSpec{Containers: tt.containers},
			}
			box := toPodBox(pod, "10.0.0.1", "/var/lib/k3sm/pods/uid-p", "")
			got, present := box.GetAnnotations()["k3sm.io/memory-limit-bytes"]
			if tt.wantAnno == "" {
				if present {
					t.Errorf("memory-limit annotation = %q, want absent", got)
				}
				return
			}
			if got != tt.wantAnno {
				t.Errorf("memory-limit annotation = %q, want %q", got, tt.wantAnno)
			}
		})
	}
}

// TestToContainerStatusMirror is the M2.1-a1 proof that the new ContainerStatus
// mirror fields (volume_mounts + user) round-trip from the runtime status into
// corev1.PodStatus so kubectl describe / get -o yaml stays lossless.
func TestToContainerStatusMirror(t *testing.T) {
	rs := &runtimev1.PodStatus{
		PodId: "uid-api",
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		PodIp: "10.0.0.7",
		ContainerStatuses: []*runtimev1.ContainerStatus{{
			Name:  "c0",
			Ready: true,
			State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(time.Unix(2000, 0))}},
			VolumeMounts: []*runtimev1.VolumeMountStatus{
				{Name: "cfg", MountPath: "/etc/config", ReadOnly: true},
				{Name: "scratch", MountPath: "/scratch"},
			},
			User: &runtimev1.ContainerUser{Linux: &runtimev1.LinuxContainerUser{Uid: 1000, Gid: 2000, SupplementalGroups: []int64{999}}},
		}},
	}
	st := toPodStatus(rs, "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)

	cs := st.ContainerStatuses[0]
	if len(cs.VolumeMounts) != 2 {
		t.Fatalf("VolumeMounts = %d, want 2", len(cs.VolumeMounts))
	}
	if cs.VolumeMounts[0].Name != "cfg" || cs.VolumeMounts[0].MountPath != "/etc/config" || !cs.VolumeMounts[0].ReadOnly {
		t.Errorf("VolumeMounts[0] mirror wrong: %+v", cs.VolumeMounts[0])
	}
	if cs.User == nil || cs.User.Linux == nil {
		t.Fatal("User mirror missing")
	}
	if cs.User.Linux.UID != 1000 || cs.User.Linux.GID != 2000 {
		t.Errorf("User uid/gid = %d/%d, want 1000/2000", cs.User.Linux.UID, cs.User.Linux.GID)
	}
	if len(cs.User.Linux.SupplementalGroups) != 1 || cs.User.Linux.SupplementalGroups[0] != 999 {
		t.Errorf("supplementalGroups = %v, want [999] (fsGroup)", cs.User.Linux.SupplementalGroups)
	}
}

// TestToPodStatusOOMKilled is the M2.3-a1 proof that a runtimed OOMKilled
// terminated status surfaces as a corev1 terminated reason OOMKilled with a Failed
// phase (the userspace memory-limit kill the kubelet would report).
func TestToPodStatusOOMKilled(t *testing.T) {
	rs := &runtimev1.PodStatus{
		PodId: "uid-oom",
		Phase: runtimev1.PodPhase_POD_PHASE_FAILED,
		ContainerStatuses: []*runtimev1.ContainerStatus{{
			Name: "c0",
			State: &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
				ExitCode: 137,
				Signal:   9,
				Reason:   "OOMKilled",
			}},
		}},
	}
	st := toPodStatus(rs, "10.0.0.1", metav1.Now(), nil)

	if st.Phase != corev1.PodFailed {
		t.Errorf("phase = %s, want Failed", st.Phase)
	}
	term := st.ContainerStatuses[0].State.Terminated
	if term == nil || term.Reason != "OOMKilled" {
		t.Fatalf("terminated reason = %v, want OOMKilled", term)
	}
}

// TestDerivePhase covers the phase-derivation rule directly.
func TestDerivePhase(t *testing.T) {
	tests := []struct {
		name       string
		rp         runtimev1.PodPhase
		anyRunning bool
		anyFailed  bool
		want       corev1.PodPhase
	}{
		{"running when any runs and none failed", runtimev1.PodPhase_POD_PHASE_RUNNING, true, false, corev1.PodRunning},
		{"failed honored from runtime", runtimev1.PodPhase_POD_PHASE_FAILED, false, true, corev1.PodFailed},
		{"succeeded honored from runtime", runtimev1.PodPhase_POD_PHASE_SUCCEEDED, false, false, corev1.PodSucceeded},
		{"pending honored from runtime", runtimev1.PodPhase_POD_PHASE_PENDING, false, false, corev1.PodPending},
		{"unspecified + running derives Running", runtimev1.PodPhase_POD_PHASE_UNSPECIFIED, true, false, corev1.PodRunning},
		{"unspecified + failed derives Failed", runtimev1.PodPhase_POD_PHASE_UNSPECIFIED, false, true, corev1.PodFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := derivePhase(tt.rp, tt.anyRunning, tt.anyFailed); got != tt.want {
				t.Errorf("derivePhase = %s, want %s", got, tt.want)
			}
		})
	}
}
