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
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
)

// TestM3_3_ToPodBoxAllowsClusterNetwork confirms the provider sets
// SandboxProfile.AllowNetwork=true for an ordinary pod — the precondition for
// runtimed's per-pod Seatbelt egress rules (the cluster DNS + API VIPs) to be
// emitted at all (those rules are gated on AllowNetwork). Cluster networking is
// the normal case; a no-network pod would be the exception. Maps to M3.3-a1.
func TestM3_3_ToPodBoxAllowsClusterNetwork(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: types.UID("uid-web")},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c0", Image: "registry/web:latest"}},
		},
	}
	box, err := toPodBox(pod, "10.42.0.5", "/var/lib/k3sm/pods/uid-web", "", netv1.DNSConfig{})
	if err != nil {
		t.Fatalf("toPodBox: %v", err)
	}
	if !box.GetSandboxProfile().GetAllowNetwork() {
		t.Error("AllowNetwork must be true so the cluster DNS + API-server Seatbelt egress rules are emitted (in-pod DNS + kubectl)")
	}
}

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
	box, err := toPodBox(pod, "10.0.0.5", "/var/lib/k3sm/pods/uid-web", "/lib/shim.dylib", netv1.DNSConfig{})
	if err != nil {
		t.Fatalf("toPodBox: %v", err)
	}

	if box.GetPodId() != "uid-web" {
		t.Errorf("pod id = %q, want uid-web", box.GetPodId())
	}
	if box.GetSandboxProfile() == nil {
		t.Fatal("sandbox_profile must be set so runtimed's fail-closed gate passes")
	}
	if box.GetSandboxProfile().GetBackend() != runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
		t.Errorf("default (no RuntimeClass) backend = %v, want UNSPECIFIED — runtimed's SelectBackend picks the host-process rung (TestToPodBoxDefaultBackendUnspecified covers the EXEC-mismatch fix)", box.GetSandboxProfile().GetBackend())
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

// TestToPodBoxDefaultBackendUnspecified is the M5.1 proof that a pod with NO
// runtimeClassName stamps SANDBOX_BACKEND_UNSPECIFIED — NOT the old hardcoded
// SEATBELT_EXEC(=1) rung. Stamping UNSPECIFIED lets runtimed's reworked
// SelectBackend(UNSPECIFIED,…) walk the host-OS-version-gated Seatbelt ladder and
// pick the correct rung (SEATBELT_INPROC=2 where libsandbox is present), fixing the
// EXEC-vs-INPROC mismatch the provider previously forced. The pod must still pass
// runtimed's fail-closed gate (non-nil profile + non-UNSPECIFIED signature policy),
// and a non-vm pod must carry no vm sizing.
func TestToPodBoxDefaultBackendUnspecified(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "native", UID: types.UID("uid-native")},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c0", Image: "registry/web:latest"}},
		},
	}
	box, err := toPodBox(pod, "10.0.0.5", "/var/lib/k3sm/pods/uid-native", "", netv1.DNSConfig{})
	if err != nil {
		t.Fatalf("toPodBox: %v", err)
	}
	sp := box.GetSandboxProfile()
	if got := sp.GetBackend(); got != runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
		t.Errorf("default backend = %v, want UNSPECIFIED (not the old hardcoded SEATBELT_EXEC)", got)
	}
	if sp.GetBackend() == runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC {
		t.Error("default backend must NOT be SEATBELT_EXEC — that is the architect-flagged mismatch this fixes")
	}
	if sp.GetVmVcpus() != 0 || sp.GetVmMemoryBytes() != 0 {
		t.Errorf("non-vm pod must carry no vm sizing: vcpus=%d mem=%d", sp.GetVmVcpus(), sp.GetVmMemoryBytes())
	}
	if box.GetSignaturePolicy() == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		t.Error("signature_policy must still be set (the fail-closed gate is unchanged)")
	}
}

// TestToPodBoxVMRuntimeClass is the M5.1 proof that runtimeClassName: vm resolves to
// SANDBOX_BACKEND_VM and that the guest is sized from the pod's cpu/memory: vCPUs
// rounded UP from summed milli-CPU, memory summed in bytes, each container's
// effective value being its limit when set, else its request; nothing set ⇒ 0 (the
// VZ default).
func TestToPodBoxVMRuntimeClass(t *testing.T) {
	vm := string(runtimev1.HandlerVM)
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	tests := []struct {
		name       string
		containers []corev1.Container
		wantVCPUs  uint32
		wantMem    int64
	}{
		{
			name: "limit wins over request",
			containers: []corev1.Container{{
				Name: "c0",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: q("500m"), corev1.ResourceMemory: q("512Mi")},
					Limits:   corev1.ResourceList{corev1.ResourceCPU: q("1500m"), corev1.ResourceMemory: q("1Gi")},
				},
			}},
			wantVCPUs: 2,          // ceil(1500m / 1000)
			wantMem:   1073741824, // 1Gi
		},
		{
			name: "request when no limit",
			containers: []corev1.Container{{
				Name:      "c0",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: q("2"), corev1.ResourceMemory: q("256Mi")}},
			}},
			wantVCPUs: 2,
			wantMem:   268435456,
		},
		{
			name: "summed across regular containers",
			containers: []corev1.Container{
				{Name: "c0", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceCPU: q("1"), corev1.ResourceMemory: q("256Mi")}}},
				{Name: "c1", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceCPU: q("1"), corev1.ResourceMemory: q("256Mi")}}},
			},
			wantVCPUs: 2,
			wantMem:   536870912,
		},
		{
			name:       "no resources ⇒ VZ defaults (0)",
			containers: []corev1.Container{{Name: "c0"}},
			wantVCPUs:  0,
			wantMem:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg", UID: types.UID("uid-pg")},
				Spec:       corev1.PodSpec{RuntimeClassName: &vm, Containers: tt.containers},
			}
			box, err := toPodBox(pod, "10.0.0.9", "/var/lib/k3sm/pods/uid-pg", "", netv1.DNSConfig{})
			if err != nil {
				t.Fatalf("toPodBox: %v", err)
			}
			sp := box.GetSandboxProfile()
			if sp.GetBackend() != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
				t.Errorf("backend = %v, want SANDBOX_BACKEND_VM", sp.GetBackend())
			}
			if sp.GetVmVcpus() != tt.wantVCPUs {
				t.Errorf("vm_vcpus = %d, want %d", sp.GetVmVcpus(), tt.wantVCPUs)
			}
			if sp.GetVmMemoryBytes() != tt.wantMem {
				t.Errorf("vm_memory_bytes = %d, want %d", sp.GetVmMemoryBytes(), tt.wantMem)
			}
		})
	}
}

// TestToPodBoxUnknownRuntimeClassFailsClosed is the M5.1 proof that a pod naming a
// RuntimeClass with no backend mapping is REFUSED at translation (an error wrapping
// runtimev1.ErrUnknownHandler, nil box) rather than silently running on the
// host-process path — k3sm never downgrades a pod that asked for an isolation class
// it cannot satisfy.
func TestToPodBoxUnknownRuntimeClassFailsClosed(t *testing.T) {
	unknown := "kata-qemu"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "x", UID: types.UID("uid-x")},
		Spec: corev1.PodSpec{
			RuntimeClassName: &unknown,
			Containers:       []corev1.Container{{Name: "c0", Image: "img"}},
		},
	}
	box, err := toPodBox(pod, "10.0.0.1", "/var/lib/k3sm/pods/uid-x", "", netv1.DNSConfig{})
	if err == nil {
		t.Fatal("toPodBox must FAIL CLOSED on an unknown RuntimeClass, got nil (would silently downgrade to host-process)")
	}
	if !errors.Is(err, runtimev1.ErrUnknownHandler) {
		t.Errorf("error = %v, want one wrapping runtimev1.ErrUnknownHandler", err)
	}
	if box != nil {
		t.Error("box must be nil on a fail-closed translation")
	}
}

// TestToPodBoxInjectsClusterDNSEnv is the B18 DNS-keystone gate: toPodBox injects the
// K3SM_DNS_* env the DYLD getaddrinfo shim reads (serialized by dns.ConfigToEnv) into
// EVERY container — init AND regular — for a cluster-first DNSPolicy, and injects
// NOTHING for Default/None or an unusable config. Without it the shim defers to the
// host resolver and in-pod cluster Service names never resolve. The NEGATIVE Default/
// None cases are mandatory: without them an unconditional-injection regression would
// pass green (it would inject for a Default pod that opted out of cluster DNS). The
// env references the dns.EnvDNS* consts (never bare string literals) so a rename of
// the shim ABI can't silently desync the test from the encoder.
func TestToPodBoxInjectsClusterDNSEnv(t *testing.T) {
	const (
		ns         = "ns1"
		wantServer = "10.43.0.10"
		wantDomain = "cluster.local"
		wantSearch = "ns1.svc.cluster.local svc.cluster.local cluster.local"
		wantNdots  = "5"
	)
	validCfg := dns.PodDNSConfig(wantServer, wantDomain, ns)

	// dnsPod builds a pod (namespace ns) with one init + one regular container under
	// policy. extraEnv, when set, lands on the regular container BEFORE translation —
	// used to prove infra-wins precedence.
	dnsPod := func(policy corev1.DNSPolicy, extraEnv ...corev1.EnvVar) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "web", UID: types.UID("uid-web")},
			Spec: corev1.PodSpec{
				DNSPolicy:      policy,
				InitContainers: []corev1.Container{{Name: "init0", Image: "img"}},
				Containers:     []corev1.Container{{Name: "c0", Image: "img", Env: extraEnv}},
			},
		}
	}
	assertNoClusterDNS := func(t *testing.T, c *runtimev1.Container) {
		t.Helper()
		for _, e := range c.GetEnv() {
			switch e.GetName() {
			case dns.EnvDNSServer, dns.EnvDNSDomain, dns.EnvDNSSearch, dns.EnvDNSNdots, dns.EnvDNSPort:
				t.Errorf("container %s: unexpected cluster DNS env %s=%q (host DNS must be preserved)", c.GetName(), e.GetName(), e.GetValue())
			}
		}
	}

	// Positive — cluster-first policies (incl. empty=default and ...WithHostNet, which
	// k3sm host-network pods reach) inject all four K3SM_DNS_* (and NEVER PORT) into
	// every container.
	t.Run("cluster-first policies inject into every container", func(t *testing.T) {
		for _, policy := range []corev1.DNSPolicy{"", corev1.DNSClusterFirst, corev1.DNSClusterFirstWithHostNet} {
			name := string(policy)
			if name == "" {
				name = "empty(default ClusterFirst)"
			}
			t.Run(name, func(t *testing.T) {
				box, err := toPodBox(dnsPod(policy), "10.0.0.5", "/var/lib/k3sm/pods/uid-web", "/lib/shim.dylib", validCfg)
				if err != nil {
					t.Fatalf("toPodBox: %v", err)
				}
				cs := allContainers(box)
				if len(cs) != 2 {
					t.Fatalf("want 2 containers (1 init + 1 regular), got %d", len(cs))
				}
				for _, c := range cs {
					env := containerEnv(c)
					for _, kv := range []struct{ k, want string }{
						{dns.EnvDNSServer, wantServer},
						{dns.EnvDNSDomain, wantDomain},
						{dns.EnvDNSSearch, wantSearch},
						{dns.EnvDNSNdots, wantNdots},
					} {
						if got := env[kv.k]; got != kv.want {
							t.Errorf("container %s: %s = %q, want %q", c.GetName(), kv.k, got, kv.want)
						}
					}
					if _, ok := env[dns.EnvDNSPort]; ok {
						t.Errorf("container %s: %s must NOT be injected (netv1.DNSConfig carries no port)", c.GetName(), dns.EnvDNSPort)
					}
				}
			})
		}
	})

	// Negative — Default and None opt out of cluster DNS: NO K3SM_DNS_* on any
	// container (no env ⇒ the shim falls back to the host resolver, which is correct
	// Default semantics; None custom-nameserver passthrough is deferred to B19/B20).
	t.Run("opt-out policies inject nothing", func(t *testing.T) {
		for _, policy := range []corev1.DNSPolicy{corev1.DNSDefault, corev1.DNSNone} {
			t.Run(string(policy), func(t *testing.T) {
				box, err := toPodBox(dnsPod(policy), "10.0.0.5", "/var/lib/k3sm/pods/uid-web", "/lib/shim.dylib", validCfg)
				if err != nil {
					t.Fatalf("toPodBox: %v", err)
				}
				for _, c := range allContainers(box) {
					assertNoClusterDNS(t, c)
				}
			})
		}
	})

	// Negative — an unusable cfg (no cluster DNS VIP ⇒ dns.ConfigToEnv returns nil)
	// injects nothing even under ClusterFirst; the shim defers to the host resolver
	// rather than blackholing every lookup.
	t.Run("invalid cfg injects nothing", func(t *testing.T) {
		box, err := toPodBox(dnsPod(corev1.DNSClusterFirst), "10.0.0.5", "/var/lib/k3sm/pods/uid-web", "", netv1.DNSConfig{ClusterDomain: wantDomain})
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		for _, c := range allContainers(box) {
			assertNoClusterDNS(t, c)
		}
	})

	// Precedence (infra-wins) — a workload that pre-declares its own K3SM_DNS_SERVER
	// must NOT override the cluster value (ClusterFirst means cluster DNS). Drive the
	// SAME resolve path buildBox uses (resolvePodBoxEnv, nil resolver — the env is all
	// literal) and assert the resolved value is the cluster VIP.
	t.Run("infra wins over a workload K3SM_DNS_SERVER", func(t *testing.T) {
		pod := dnsPod(corev1.DNSClusterFirst, corev1.EnvVar{Name: dns.EnvDNSServer, Value: "1.2.3.4"})
		box, err := toPodBox(pod, "10.0.0.5", "/var/lib/k3sm/pods/uid-web", "", validCfg)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		if err := resolvePodBoxEnv(context.Background(), box, "node", "10.0.0.5", nil); err != nil {
			t.Fatalf("resolvePodBoxEnv: %v", err)
		}
		if got := containerEnv(box.GetContainers()[0])[dns.EnvDNSServer]; got != wantServer {
			t.Errorf("%s = %q, want the cluster VIP %q (infra wins; the workload 1.2.3.4 must not override)", dns.EnvDNSServer, got, wantServer)
		}
	})
}

// allContainers returns the box's init + regular containers in one slice without
// aliasing either underlying array (so appending in a test can't mutate the box).
func allContainers(box *runtimev1.PodBox) []*runtimev1.Container {
	out := make([]*runtimev1.Container, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	out = append(out, box.GetInitContainers()...)
	out = append(out, box.GetContainers()...)
	return out
}

// containerEnv collapses a runtime container's env to a last-wins name→value map,
// mirroring resolveContainerEnv's upsert (the later value wins) so a test reads the
// effective value of a possibly-duplicated key.
func containerEnv(c *runtimev1.Container) map[string]string {
	m := make(map[string]string, len(c.GetEnv()))
	for _, e := range c.GetEnv() {
		m[e.GetName()] = e.GetValue()
	}
	return m
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
	box, err := toPodBox(pod, "10.0.0.7", "/var/lib/k3sm/pods/uid-api", "", netv1.DNSConfig{})
	if err != nil {
		t.Fatalf("toPodBox: %v", err)
	}

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
			box, err := toPodBox(pod, "10.0.0.1", "/var/lib/k3sm/pods/uid-p", "", netv1.DNSConfig{})
			if err != nil {
				t.Fatalf("toPodBox: %v", err)
			}
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

// TestTypedMemoryLimitWritten is the M2.2-swap proof that the translation writes
// the TYPED apis:M2.2 PodBox fields, not just the interim annotation: a pod with
// resources.limits.memory sets PodBox.memory_limit_bytes, and every pod carries the
// correct qos_class enum (Guaranteed/Burstable/BestEffort) mapped from the kubelet
// QoS classification.
func TestTypedMemoryLimitWritten(t *testing.T) {
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	tests := []struct {
		name       string
		containers []corev1.Container
		wantBytes  int64
		wantQOS    runtimev1.QOSClass
	}{
		{
			name: "guaranteed: equal cpu+memory requests and limits",
			containers: []corev1.Container{{
				Name: "c0",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: q("500m"), corev1.ResourceMemory: q("256Mi")},
					Limits:   corev1.ResourceList{corev1.ResourceCPU: q("500m"), corev1.ResourceMemory: q("256Mi")},
				},
			}},
			wantBytes: 268435456,
			wantQOS:   runtimev1.QOSClass_QOS_CLASS_GUARANTEED,
		},
		{
			name: "burstable: only a memory limit set",
			containers: []corev1.Container{{
				Name:      "c0",
				Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q("256Mi")}},
			}},
			wantBytes: 268435456,
			wantQOS:   runtimev1.QOSClass_QOS_CLASS_BURSTABLE,
		},
		{
			name:       "besteffort: no requests or limits ⇒ no memory ceiling",
			containers: []corev1.Container{{Name: "c0"}},
			wantBytes:  0,
			wantQOS:    runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT,
		},
		{
			name: "burstable with an unbounded container ⇒ no enforceable pod ceiling",
			containers: []corev1.Container{
				{Name: "c0", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q("256Mi")}}},
				{Name: "c1"},
			},
			wantBytes: 0,
			wantQOS:   runtimev1.QOSClass_QOS_CLASS_BURSTABLE,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p", UID: types.UID("uid-p")},
				Spec:       corev1.PodSpec{Containers: tt.containers},
			}
			box, err := toPodBox(pod, "10.0.0.1", "/var/lib/k3sm/pods/uid-p", "", netv1.DNSConfig{})
			if err != nil {
				t.Fatalf("toPodBox: %v", err)
			}
			if box.GetMemoryLimitBytes() != tt.wantBytes {
				t.Errorf("memory_limit_bytes = %d, want %d", box.GetMemoryLimitBytes(), tt.wantBytes)
			}
			if box.GetQosClass() != tt.wantQOS {
				t.Errorf("qos_class = %v, want %v", box.GetQosClass(), tt.wantQOS)
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
