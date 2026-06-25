package provider

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
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

	st := toPodStatus(rs, "192.168.1.10", stable)

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
	st := toPodStatus(rs, "10.0.0.1", metav1.Now())

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
