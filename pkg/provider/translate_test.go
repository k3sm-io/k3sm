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
	"strings"
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

// TestPodVMMemoryBytesExcludesOverhead is the B45 provider-side invariant guarding the
// three-figures decoupling documented at pkg/runtimeclass vmMemoryOverhead's "THREE
// DISTINCT memory figures" doc: the vm RuntimeClass's
// host-side scheduler-ACCOUNTING Overhead (256Mi, owned by pkg/runtimeclass) must NEVER be
// folded into the GUEST RAM podVMMemoryBytes hands to VZ. The guest allocation is EXACTLY
// the regular containers' effective memory sum (limit-else-request; here limit==request so
// the rule is unambiguous), and an init container — which runs sequentially BEFORE the
// regular set — is NOT in the concurrent budget. Exact equality pins that no overhead term
// is added; pkg/provider keeps ZERO import of pkg/runtimeclass (the 256Mi literal lives in
// exactly one place — asserting != sum+256Mi here would re-encode it and be vacuous given
// the exact ==).
func TestPodVMMemoryBytesExcludesOverhead(t *testing.T) {
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	// limitEqRequest sets memory limit == request so effectiveResource's limit-else-request
	// rule resolves to one unambiguous value.
	limitEqRequest := func(mem string) corev1.ResourceRequirements {
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceMemory: q(mem)},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: q(mem)},
		}
	}
	vm := string(runtimev1.HandlerVM)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg", UID: types.UID("uid-pg")},
		Spec: corev1.PodSpec{
			RuntimeClassName: &vm,
			// A 1Gi init container — must NOT be summed into the guest RAM (it runs before
			// the regular set, so it is not part of the concurrent footprint).
			InitContainers: []corev1.Container{{Name: "init0", Resources: limitEqRequest("1Gi")}},
			Containers: []corev1.Container{
				{Name: "c0", Resources: limitEqRequest("200Mi")},
				{Name: "c1", Resources: limitEqRequest("300Mi")},
			},
		},
	}
	// The exact regular-container sum — nothing else. Computed from the fixtures so the
	// assertion can't silently desync, and so the 256Mi overhead value never appears here.
	c0Mem, c1Mem := q("200Mi"), q("300Mi")
	want := c0Mem.Value() + c1Mem.Value()
	if got := podVMMemoryBytes(pod); got != want {
		t.Errorf("podVMMemoryBytes = %d, want exactly %d (the regular-container memory sum; the host-side Overhead must NOT be folded into guest RAM, and the 1Gi init container must NOT be summed)", got, want)
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

// TestToPodBoxClusterFirstMergesDNSConfig is the B20a gate: buildBox merges a
// ClusterFirst pod's spec.dnsConfig (extra searches appended+deduped, ndots
// override) into the cluster DNS base BEFORE toPodBox injects the K3SM_DNS_* env the
// DYLD getaddrinfo shim reads — so it asserts on the LIVE box env (every container,
// init + regular), not the pure dns.MergeDNSConfig primitive. The merge is gated
// structurally in buildBox on the cluster-DNS policy, so a None/Default pod gets the
// UNMERGED base and (per B18) NO injection at all — pinning the B20a/B20b seam.
// Fails-before (buildBox ignored spec.dnsConfig → the plain cluster defaults),
// passes-after.
func TestToPodBoxClusterFirstMergesDNSConfig(t *testing.T) {
	const (
		ns       = "ns1"
		vip      = "10.43.0.10"
		domain   = "cluster.local"
		cluster0 = "ns1.svc.cluster.local"
		cluster1 = "svc.cluster.local"
		cluster2 = "cluster.local"
	)
	// newR builds a runtimed-backed provider with the cluster DNS inputs buildBox
	// feeds dns.PodDNSConfig; the fake runtime server is never driven (buildBox is a
	// pure translation that does not call the runtime).
	newR := func(t *testing.T) *runtimedRuntime {
		t.Helper()
		return newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
			NodeName:      "n",
			NodeIP:        "10.0.0.5",
			Root:          t.TempDir(),
			ResolverVIP:   vip,
			ClusterDomain: domain,
		}, nil, nil)
	}
	// dnsPod builds a pod (namespace ns, 1 init + 1 regular container) under policy
	// carrying cfg as spec.dnsConfig.
	dnsPod := func(policy corev1.DNSPolicy, cfg *corev1.PodDNSConfig) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "web", UID: types.UID("uid-web")},
			Spec: corev1.PodSpec{
				DNSPolicy:      policy,
				DNSConfig:      cfg,
				InitContainers: []corev1.Container{{Name: "init0", Image: "img"}},
				Containers:     []corev1.Container{{Name: "c0", Image: "img"}},
			},
		}
	}

	// Case 1 — ClusterFirst + dnsConfig: the pod's extra search is appended AFTER the
	// cluster three and its ndots overrides the cluster default, on EVERY container
	// (init + regular).
	t.Run("ClusterFirst appends searches and overrides ndots", func(t *testing.T) {
		pod := dnsPod(corev1.DNSClusterFirst, &corev1.PodDNSConfig{
			Searches: []string{"corp.internal"},
			Options:  []corev1.PodDNSConfigOption{{Name: "ndots", Value: ptr("2")}},
		})
		box, err := newR(t).buildBox(context.Background(), pod, "10.0.0.5")
		if err != nil {
			t.Fatalf("buildBox: %v", err)
		}
		const wantSearch = "ns1.svc.cluster.local svc.cluster.local cluster.local corp.internal"
		cs := allContainers(box)
		if len(cs) != 2 {
			t.Fatalf("want 2 containers (1 init + 1 regular), got %d", len(cs))
		}
		for _, c := range cs {
			env := containerEnv(c)
			if got := env[dns.EnvDNSSearch]; got != wantSearch {
				t.Errorf("container %s: %s = %q, want %q (cluster-first + appended pod search)", c.GetName(), dns.EnvDNSSearch, got, wantSearch)
			}
			if got := env[dns.EnvDNSNdots]; got != "2" {
				t.Errorf("container %s: %s = %q, want %q (pod ndots override)", c.GetName(), dns.EnvDNSNdots, got, "2")
			}
		}
	})

	// Case 2 — the conformance boundary: an over-cap pod search list with a cross-list
	// duplicate (a pod search == a cluster search) is deduped (cluster wins) and capped
	// at MaxSearchDomains, cluster-first. With 3 cluster + 6 pod searches (one a
	// duplicate) the merge yields the 3 cluster leads + the 5 unique pod searches = 8.
	t.Run("over-cap + cross-list duplicate dedupes and caps", func(t *testing.T) {
		pod := dnsPod(corev1.DNSClusterFirst, &corev1.PodDNSConfig{
			Searches: []string{"a", "b", "cluster.local", "c", "d", "e"},
		})
		box, err := newR(t).buildBox(context.Background(), pod, "10.0.0.5")
		if err != nil {
			t.Fatalf("buildBox: %v", err)
		}
		for _, c := range allContainers(box) {
			tokens := strings.Fields(containerEnv(c)[dns.EnvDNSSearch])
			if len(tokens) > dns.MaxSearchDomains {
				t.Errorf("container %s: search has %d tokens, want <= %d (cap)", c.GetName(), len(tokens), dns.MaxSearchDomains)
			}
			// The cluster three lead the list, in order (a pod search never preempts).
			if len(tokens) < 3 || tokens[0] != cluster0 || tokens[1] != cluster1 || tokens[2] != cluster2 {
				t.Errorf("container %s: search = %v, want the cluster three (%q %q %q) leading", c.GetName(), tokens, cluster0, cluster1, cluster2)
			}
			// cluster.local appears exactly once — the pod's cross-list duplicate dropped.
			if n := countToken(tokens, cluster2); n != 1 {
				t.Errorf("container %s: %q appears %d times, want 1 (cross-list dedupe)", c.GetName(), cluster2, n)
			}
			// Every unique pod search survived the merge (proves the merge ran at all —
			// fails-before, where the box carries only the 3 cluster defaults).
			for _, want := range []string{"a", "b", "c", "d", "e"} {
				if countToken(tokens, want) != 1 {
					t.Errorf("container %s: merged search %v missing pod search %q", c.GetName(), tokens, want)
				}
			}
		}
	})

	// Case 3 — NEGATIVE: None and Default get the UNMERGED base and NO injection at
	// all (unchanged from B18) even WITH a dnsConfig. This pins the B20a/B20b seam: a
	// None pod's own dnsConfig is NOT merged into a cluster base here — B20b owns None.
	t.Run("None and Default inject nothing even with dnsConfig", func(t *testing.T) {
		cfg := &corev1.PodDNSConfig{
			Searches: []string{"corp.internal"},
			Options:  []corev1.PodDNSConfigOption{{Name: "ndots", Value: ptr("2")}},
		}
		for _, policy := range []corev1.DNSPolicy{corev1.DNSNone, corev1.DNSDefault} {
			t.Run(string(policy), func(t *testing.T) {
				box, err := newR(t).buildBox(context.Background(), dnsPod(policy, cfg), "10.0.0.5")
				if err != nil {
					t.Fatalf("buildBox: %v", err)
				}
				for _, c := range allContainers(box) {
					for _, e := range c.GetEnv() {
						switch e.GetName() {
						case dns.EnvDNSServer, dns.EnvDNSDomain, dns.EnvDNSSearch, dns.EnvDNSNdots, dns.EnvDNSPort:
							t.Errorf("policy %s container %s: unexpected cluster DNS env %s=%q (None/Default opt out — no merge, no injection)", policy, c.GetName(), e.GetName(), e.GetValue())
						}
					}
				}
			})
		}
	})
}

// TestDNSConfigOverrideClampsNdots is the k3sm-side B47 gate: dnsConfigOverride
// clamps a pod's spec.dnsConfig ndots to [0,15] (the resolv.conf RES_MAXNDOTS
// ceiling) BEFORE the int32 narrowing, so an absurd value in the overflow band
// (>=2^31) cannot wrap negative and be silently discarded by dns.MergeDNSConfig as
// keep-base — which would mask the misconfig. The darwin-net gate covers only
// ConfigToEnv, so this is the sole gate on the k3sm pre-cast clamp. The 2147483648
// case is the regression pin: on main int32(2147483648) == -2147483648 (fails-before),
// the pre-cast clamp yields 15 (passes-after).
func TestDNSConfigOverrideClampsNdots(t *testing.T) {
	ndotsCfg := func(v string) *corev1.PodDNSConfig {
		return &corev1.PodDNSConfig{
			Options: []corev1.PodDNSConfigOption{{Name: "ndots", Value: ptr(v)}},
		}
	}
	tests := []struct {
		name string
		cfg  *corev1.PodDNSConfig
		want int32
	}{
		{name: "in-range unchanged", cfg: ndotsCfg("2"), want: 2},
		{name: "boundary 15 unchanged", cfg: ndotsCfg("15"), want: 15},
		{name: "over-ceiling clamps down", cfg: ndotsCfg("1000"), want: 15},
		{name: "overflow band clamps to 15 not negative", cfg: ndotsCfg("2147483648"), want: 15},
		{name: "negative keeps base", cfg: ndotsCfg("-1"), want: 0},
		{name: "unparseable keeps base", cfg: ndotsCfg("abc"), want: 0},
		{name: "nil config keeps base", cfg: nil, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ndots := dnsConfigOverride(tt.cfg)
			if ndots != tt.want {
				t.Errorf("dnsConfigOverride ndots = %d, want %d (pre-cast clamp to [0,15])", ndots, tt.want)
			}
		})
	}
}

// countToken counts how many times tok appears in toks (a test helper for the
// dedupe/cap assertions).
func countToken(toks []string, tok string) int {
	n := 0
	for _, t := range toks {
		if t == tok {
			n++
		}
	}
	return n
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

	st := toPodStatus(nil, rs, "192.168.1.10", stable, nil)

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
	st := toPodStatus(nil, rs, "10.0.0.1", metav1.Now(), nil)

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
	st := toPodStatus(nil, rs, "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)

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
	st := toPodStatus(nil, rs, "10.0.0.1", metav1.Now(), nil)

	if st.Phase != corev1.PodFailed {
		t.Errorf("phase = %s, want Failed", st.Phase)
	}
	term := st.ContainerStatuses[0].State.Terminated
	if term == nil || term.Reason != "OOMKilled" {
		t.Fatalf("terminated reason = %v, want OOMKilled", term)
	}
}

// TestDerivePhase covers the phase-derivation rule directly, INCLUDING the B26
// restart-policy awareness: upstream's getPhase branches on RestartPolicy before
// it can ever return Failed, so a restartable termination keeps the pod Running
// and a running container always beats a failed sibling. A nil pod (the pod-less
// status path) has no policy to honor and falls back to the runtime's verdict.
func TestDerivePhase(t *testing.T) {
	policyPod := func(p corev1.RestartPolicy) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{RestartPolicy: p}}
	}
	running := corev1.ContainerStatus{
		Name:  "c-run",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}
	exited := func(code int32) corev1.ContainerStatus {
		return corev1.ContainerStatus{
			Name:  "c-term",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code}},
		}
	}
	crashLooping := corev1.ContainerStatus{
		Name:  "c-loop",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reasonCrashLoopBackOff}},
	}

	tests := []struct {
		name string
		pod  *corev1.Pod
		rp   runtimev1.PodPhase
		cs   []corev1.ContainerStatus
		want corev1.PodPhase
	}{
		{"running when any runs", policyPod(corev1.RestartPolicyAlways), runtimev1.PodPhase_POD_PHASE_RUNNING, []corev1.ContainerStatus{running}, corev1.PodRunning},
		{"pending honored from runtime", policyPod(corev1.RestartPolicyAlways), runtimev1.PodPhase_POD_PHASE_PENDING, nil, corev1.PodPending},
		{"Never + failed is Failed", policyPod(corev1.RestartPolicyNever), runtimev1.PodPhase_POD_PHASE_FAILED, []corev1.ContainerStatus{exited(1)}, corev1.PodFailed},
		{"Never + all exit 0 is Succeeded", policyPod(corev1.RestartPolicyNever), runtimev1.PodPhase_POD_PHASE_SUCCEEDED, []corev1.ContainerStatus{exited(0)}, corev1.PodSucceeded},
		{"OnFailure + failed is Running (a retry is due)", policyPod(corev1.RestartPolicyOnFailure), runtimev1.PodPhase_POD_PHASE_FAILED, []corev1.ContainerStatus{exited(1)}, corev1.PodRunning},
		{"OnFailure + exit 0 is Succeeded (no retry due)", policyPod(corev1.RestartPolicyOnFailure), runtimev1.PodPhase_POD_PHASE_SUCCEEDED, []corev1.ContainerStatus{exited(0)}, corev1.PodSucceeded},
		{"Always + failed is Running", policyPod(corev1.RestartPolicyAlways), runtimev1.PodPhase_POD_PHASE_FAILED, []corev1.ContainerStatus{exited(1)}, corev1.PodRunning},
		{"Always + exit 0 is Running (Always restarts a clean exit too)", policyPod(corev1.RestartPolicyAlways), runtimev1.PodPhase_POD_PHASE_SUCCEEDED, []corev1.ContainerStatus{exited(0)}, corev1.PodRunning},
		{"empty policy defaults to Always", policyPod(""), runtimev1.PodPhase_POD_PHASE_FAILED, []corev1.ContainerStatus{exited(1)}, corev1.PodRunning},
		{"a running main beats a failed sibling under Never", policyPod(corev1.RestartPolicyNever), runtimev1.PodPhase_POD_PHASE_FAILED, []corev1.ContainerStatus{exited(1), running}, corev1.PodRunning},
		{"a synthesized CrashLoopBackOff holds Running", policyPod(corev1.RestartPolicyNever), runtimev1.PodPhase_POD_PHASE_FAILED, []corev1.ContainerStatus{crashLooping}, corev1.PodRunning},
		{"nil pod: runtime Failed is authoritative", nil, runtimev1.PodPhase_POD_PHASE_FAILED, []corev1.ContainerStatus{exited(1)}, corev1.PodFailed},
		{"nil pod: runtime Succeeded is authoritative", nil, runtimev1.PodPhase_POD_PHASE_SUCCEEDED, nil, corev1.PodSucceeded},
		{"nil pod: unspecified + failed derives Failed", nil, runtimev1.PodPhase_POD_PHASE_UNSPECIFIED, []corev1.ContainerStatus{exited(1)}, corev1.PodFailed},
		{"unspecified + running derives Running", nil, runtimev1.PodPhase_POD_PHASE_UNSPECIFIED, []corev1.ContainerStatus{running}, corev1.PodRunning},
		{"unspecified + nothing derives Pending", nil, runtimev1.PodPhase_POD_PHASE_UNSPECIFIED, nil, corev1.PodPending},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := derivePhase(tt.pod, tt.rp, tt.cs); got != tt.want {
				t.Errorf("derivePhase = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestPodStatusQOSClass is the B12 gate: toPodStatus is the SINGLE authority that
// sets Status.QOSClass across all four publish paths (kubelet parity). It proves
// (1) the kubelet-parity derivation Guaranteed/Burstable/BestEffort, (2) that an
// init container is counted (it can flip a Guaranteed pod to Burstable), (3) that
// the apiserver's value is carried forward verbatim and beats re-derivation, (4)
// the blank-status derive fallback, and (5) that BOTH the pod-bearing GetPods path
// and the formerly pod-less GetPodStatus path (runtimed.go:321) now emit the class.
//
// It FAILS before B12 (toPodStatus emitted no QOSClass → blank) and PASSES after.
func TestPodStatusQOSClass(t *testing.T) {
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	cpuMem := func(cpu, mem string) corev1.ResourceList {
		return corev1.ResourceList{corev1.ResourceCPU: q(cpu), corev1.ResourceMemory: q(mem)}
	}
	// guaranteedContainer sets cpu AND memory with requests == limits, both EXPLICIT
	// — the only shape that classifies Guaranteed in a unit test (there is no
	// apiserver request-from-limit defaulting here; cf. the limits-only Burstable
	// precedent at TestTypedMemoryLimitWritten).
	guaranteedContainer := func(name string) corev1.Container {
		return corev1.Container{
			Name:    name,
			Command: []string{"/app"},
			Resources: corev1.ResourceRequirements{
				Requests: cpuMem("500m", "256Mi"),
				Limits:   cpuMem("500m", "256Mi"),
			},
		}
	}
	podWith := func(name string, status corev1.PodQOSClass, init, regular []corev1.Container) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
			Spec:       corev1.PodSpec{InitContainers: init, Containers: regular},
			Status:     corev1.PodStatus{QOSClass: status},
		}
	}

	t.Run("derive Guaranteed: cpu+memory, requests==limits, both explicit", func(t *testing.T) {
		pod := podWith("g", "", nil, []corev1.Container{guaranteedContainer("c0")})
		st := toPodStatus(pod, runningRS("uid-g", time.Unix(2000, 0)), "192.168.1.10", metav1.Now(), nil)
		if st.QOSClass != corev1.PodQOSGuaranteed {
			t.Errorf("QOSClass = %q, want Guaranteed", st.QOSClass)
		}
	})

	t.Run("derive Burstable: partial/unequal resources", func(t *testing.T) {
		pod := podWith("b", "", nil, []corev1.Container{{
			Name:      "c0",
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: q("128Mi")}},
		}})
		st := toPodStatus(pod, runningRS("uid-b", time.Unix(2000, 0)), "192.168.1.10", metav1.Now(), nil)
		if st.QOSClass != corev1.PodQOSBurstable {
			t.Errorf("QOSClass = %q, want Burstable", st.QOSClass)
		}
	})

	t.Run("derive BestEffort: no resources at all", func(t *testing.T) {
		pod := podWith("be", "", nil, []corev1.Container{{Name: "c0"}})
		st := toPodStatus(pod, runningRS("uid-be", time.Unix(2000, 0)), "192.168.1.10", metav1.Now(), nil)
		if st.QOSClass != corev1.PodQOSBestEffort {
			t.Errorf("QOSClass = %q, want BestEffort", st.QOSClass)
		}
	})

	t.Run("init container flips Guaranteed to Burstable (init containers are counted)", func(t *testing.T) {
		// The regular set is Guaranteed, but an init container with only a cpu limit
		// (no memory limit) breaks the pod's Guaranteed — proving the derivation
		// counts init containers, not just the regular set.
		init := []corev1.Container{{
			Name:      "init0",
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceCPU: q("250m")}},
		}}
		pod := podWith("i", "", init, []corev1.Container{guaranteedContainer("c0")})
		st := toPodStatus(pod, runningRS("uid-i", time.Unix(2000, 0)), "192.168.1.10", metav1.Now(), nil)
		if st.QOSClass != corev1.PodQOSBurstable {
			t.Errorf("QOSClass = %q, want Burstable (the init container must count)", st.QOSClass)
		}
	})

	t.Run("carry-forward beats re-derive: apiserver value preserved verbatim", func(t *testing.T) {
		// The spec ALONE derives Burstable (limits-only, no requests), but the
		// apiserver already stamped Guaranteed — carry-forward must win.
		pod := podWith("cf", corev1.PodQOSGuaranteed, nil, []corev1.Container{{
			Name:      "c0",
			Resources: corev1.ResourceRequirements{Limits: cpuMem("500m", "256Mi")},
		}})
		// Non-vacuous: the spec really derives a DIFFERENT class, so carry-forward is
		// observably distinct from re-derivation.
		if got := computePodQOS(pod); got != corev1.PodQOSBurstable {
			t.Fatalf("precondition: spec derives %q, want Burstable (so carry-forward differs)", got)
		}
		st := toPodStatus(pod, runningRS("uid-cf", time.Unix(2000, 0)), "192.168.1.10", metav1.Now(), nil)
		if st.QOSClass != corev1.PodQOSGuaranteed {
			t.Errorf("QOSClass = %q, want Guaranteed (apiserver value carried forward, not re-derived)", st.QOSClass)
		}
	})

	t.Run("derive fallback when the apiserver value is blank", func(t *testing.T) {
		pod := podWith("fb", "", nil, []corev1.Container{guaranteedContainer("c0")})
		st := toPodStatus(pod, runningRS("uid-fb", time.Unix(2000, 0)), "192.168.1.10", metav1.Now(), nil)
		if st.QOSClass != corev1.PodQOSGuaranteed {
			t.Errorf("QOSClass = %q, want Guaranteed (derived because the apiserver value was blank)", st.QOSClass)
		}
	})

	t.Run("both publish paths emit it (GetPodStatus and GetPods cover the pod-less :321 site)", func(t *testing.T) {
		r, _ := newRuntimedFake(t)
		ctx := context.Background()
		pod := podWith("pp", "", nil, []corev1.Container{guaranteedContainer("c0")})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })

		// GetPodStatus is the path that used to lack the pod (runtimed.go:321); the
		// lookup-threaded pod must now make it emit the class.
		got, err := r.GetPodStatus(ctx, "default", "pp")
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		if got.QOSClass != corev1.PodQOSGuaranteed {
			t.Errorf("GetPodStatus QOSClass = %q, want Guaranteed (the pod-less :321 site must now carry it)", got.QOSClass)
		}

		// GetPods is the watch-shaped, pod-bearing path.
		pods, err := r.GetPods(ctx)
		if err != nil {
			t.Fatalf("GetPods: %v", err)
		}
		if len(pods) != 1 {
			t.Fatalf("GetPods returned %d pods, want 1", len(pods))
		}
		if pods[0].Status.QOSClass != corev1.PodQOSGuaranteed {
			t.Errorf("GetPods QOSClass = %q, want Guaranteed", pods[0].Status.QOSClass)
		}
	})
}

// TestRlimitSourceAndQoSClass is the B7 named gate: the provider is the SOURCE
// of PodBox.rlimits (field 102), fed exclusively by pod-scoped
// k3sm.io/rlimit-<resource> annotations. It proves:
//   - the mechanical suffix→"RLIMIT_"+ToUpper(suffix) transform, forwarded
//     VERBATIM into ResourceLimit.type (runtimed's rlimitResource map stays the
//     single semantic authority — an unknown-but-well-formed name like
//     "frobnicate" is forwarded, not filtered here);
//   - the <soft> / <soft>:<hard> / "unlimited" value grammar (single value ⇒
//     soft=hard; unlimited ⇒ ^uint64(0), runtimed's RLIM_INFINITY sentinel);
//   - fail-fast SYNTAX validation: a malformed value or soft>hard (unlimited
//     counts as max) is a toPodBox ERROR naming the exact annotation key — never
//     a silent skip (producer-skip + consumer-skip would compose into a
//     silently-unconstrained pod);
//   - deterministic output: entries sorted by type name (exact-slice equality);
//   - the no-synthesis discipline mirrored at the producer: resources.limits
//     (memory/cpu) with zero rlimit annotations ⇒ box.Rlimits EMPTY (no
//     RLIMIT_AS from memory, no RLIMIT_CPU from cpu — see runtimed's
//     resolveRlimitPlan for why synthesis is forbidden).
func TestRlimitSourceAndQoSClass(t *testing.T) {
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	unlimited := ^uint64(0)

	tests := []struct {
		name            string
		annotations     map[string]string
		containers      []corev1.Container
		wantRlimits     []*runtimev1.ResourceLimit
		wantErrContains string
	}{
		{
			name:        "single annotation single value ⇒ soft=hard",
			annotations: map[string]string{"k3sm.io/rlimit-nofile": "1024"},
			wantRlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NOFILE", Soft: 1024, Hard: 1024},
			},
		},
		{
			name:        "soft:hard form carried exactly",
			annotations: map[string]string{"k3sm.io/rlimit-nofile": "1024:4096"},
			wantRlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NOFILE", Soft: 1024, Hard: 4096},
			},
		},
		{
			name:        "unlimited single value ⇒ both positions RLIM_INFINITY sentinel",
			annotations: map[string]string{"k3sm.io/rlimit-core": "unlimited"},
			wantRlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_CORE", Soft: unlimited, Hard: unlimited},
			},
		},
		{
			name:        "numeric soft with unlimited hard",
			annotations: map[string]string{"k3sm.io/rlimit-nofile": "1024:unlimited"},
			wantRlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_NOFILE", Soft: 1024, Hard: unlimited},
			},
		},
		{
			name: "multiple annotations sorted by type name",
			annotations: map[string]string{
				"k3sm.io/rlimit-nproc":  "64",
				"k3sm.io/rlimit-core":   "0",
				"k3sm.io/rlimit-nofile": "256:512",
			},
			wantRlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_CORE", Soft: 0, Hard: 0},
				{Type: "RLIMIT_NOFILE", Soft: 256, Hard: 512},
				{Type: "RLIMIT_NPROC", Soft: 64, Hard: 64},
			},
		},
		{
			name:            "malformed value errors naming the annotation key",
			annotations:     map[string]string{"k3sm.io/rlimit-nofile": "banana"},
			wantErrContains: "k3sm.io/rlimit-nofile",
		},
		{
			name:            "soft greater than hard errors",
			annotations:     map[string]string{"k3sm.io/rlimit-nofile": "4096:1024"},
			wantErrContains: "k3sm.io/rlimit-nofile",
		},
		{
			name:            "unlimited soft with numeric hard errors (unlimited counts as max)",
			annotations:     map[string]string{"k3sm.io/rlimit-nproc": "unlimited:64"},
			wantErrContains: "k3sm.io/rlimit-nproc",
		},
		{
			name:        "unknown-but-well-formed resource name forwarded verbatim",
			annotations: map[string]string{"k3sm.io/rlimit-frobnicate": "7"},
			wantRlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_FROBNICATE", Soft: 7, Hard: 7},
			},
		},
		{
			// 2^63-1 is the largest expressible magnitude (== darwin RLIM_INFINITY's
			// bit pattern, which runtimed collapses to RLIM_INFINITY — identical).
			name:        "2^63-1 maximum magnitude accepted",
			annotations: map[string]string{"k3sm.io/rlimit-fsize": "9223372036854775807"},
			wantRlimits: []*runtimev1.ResourceLimit{
				{Type: "RLIMIT_FSIZE", Soft: 9223372036854775807, Hard: 9223372036854775807},
			},
		},
		{
			// The sentinel-seam guard: a magnitude in (2^63-1, 2^64-1) would pass a
			// naive uint64 check here but runtimed's rlimitValue collapses only true
			// sentinels to RLIM_INFINITY (=2^63-1), so setrlimit would see Cur > Max
			// → an EINVAL launch abort naming no annotation. Reject it at the source.
			name:            "2^63 rejected naming the key (above-RLIM_INFINITY seam)",
			annotations:     map[string]string{"k3sm.io/rlimit-fsize": "9223372036854775808"},
			wantErrContains: "k3sm.io/rlimit-fsize",
		},
		{
			name:            "huge soft with unlimited hard rejected (would EINVAL as Cur>Max)",
			annotations:     map[string]string{"k3sm.io/rlimit-fsize": "9223372036854775808:unlimited"},
			wantErrContains: "k3sm.io/rlimit-fsize",
		},
		{
			// The no-synthesis discipline, producer side: k8s resources.limits
			// NEVER synthesize an rlimit (no RLIMIT_AS from memory, no RLIMIT_CPU
			// from cpu) — memory is enforced by runtimed's footprint sampler and
			// RLIMIT_CPU is cumulative seconds, not a rate.
			name: "no synthesis: resources.limits alone yield zero rlimits",
			containers: []corev1.Container{{
				Name: "c0",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{corev1.ResourceCPU: q("500m"), corev1.ResourceMemory: q("256Mi")},
				},
			}},
			wantRlimits: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			containers := tt.containers
			if containers == nil {
				containers = []corev1.Container{{Name: "c0", Image: "registry/app:1"}}
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "default",
					Name:        "p",
					UID:         types.UID("uid-p"),
					Annotations: tt.annotations,
				},
				Spec: corev1.PodSpec{Containers: containers},
			}
			box, err := toPodBox(pod, "10.0.0.1", "/var/lib/k3sm/pods/uid-p", "", netv1.DNSConfig{})
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("toPodBox = nil error, want an error naming annotation %q (fail-fast reject, not silent skip)", tt.wantErrContains)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("toPodBox error %q does not name the annotation key %q", err, tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("toPodBox: %v", err)
			}
			got := box.GetRlimits()
			if len(got) != len(tt.wantRlimits) {
				t.Fatalf("rlimits = %v (len %d), want %v (len %d)", got, len(got), tt.wantRlimits, len(tt.wantRlimits))
			}
			// Exact-slice equality IN ORDER: the sorted order is part of the
			// contract (deterministic proto slice + deterministic apply order).
			for i := range got {
				g, w := got[i], tt.wantRlimits[i]
				if g.GetType() != w.GetType() || g.GetSoft() != w.GetSoft() || g.GetHard() != w.GetHard() {
					t.Errorf("rlimits[%d] = {%s %d %d}, want {%s %d %d}",
						i, g.GetType(), g.GetSoft(), g.GetHard(), w.GetType(), w.GetSoft(), w.GetHard())
				}
			}
		})
	}

	// REGRESSION GUARD (not new B7 behavior): qos_class translation already ships
	// green on main (translate.go podQOSClass; TestTypedMemoryLimitWritten). These
	// subtests only pin that the rlimit source does not disturb it — qos
	// APPLICATION evidence lives in runtimed's slices, not here.
	qosTests := []struct {
		name       string
		containers []corev1.Container
		want       runtimev1.QOSClass
	}{
		{
			name:       "qos regression guard: besteffort",
			containers: []corev1.Container{{Name: "c0"}},
			want:       runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT,
		},
		{
			name: "qos regression guard: burstable",
			containers: []corev1.Container{{
				Name:      "c0",
				Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q("128Mi")}},
			}},
			want: runtimev1.QOSClass_QOS_CLASS_BURSTABLE,
		},
		{
			name: "qos regression guard: guaranteed",
			containers: []corev1.Container{{
				Name: "c0",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: q("1"), corev1.ResourceMemory: q("128Mi")},
					Limits:   corev1.ResourceList{corev1.ResourceCPU: q("1"), corev1.ResourceMemory: q("128Mi")},
				},
			}},
			want: runtimev1.QOSClass_QOS_CLASS_GUARANTEED,
		},
	}
	for _, tt := range qosTests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p", UID: types.UID("uid-p")},
				Spec:       corev1.PodSpec{Containers: tt.containers},
			}
			box, err := toPodBox(pod, "10.0.0.1", "/var/lib/k3sm/pods/uid-p", "", netv1.DNSConfig{})
			if err != nil {
				t.Fatalf("toPodBox: %v", err)
			}
			if box.GetQosClass() != tt.want {
				t.Errorf("qos_class = %v, want %v", box.GetQosClass(), tt.want)
			}
		})
	}
}

// TestComputeInitialized pins the B26 conformance fix: PodInitialized was
// stamped ConditionTrue unconditionally, so a pod whose native sidecar was
// crash-looping before it ever started still reported "the init phase is done".
// The condition is now derived from the init-container statuses, with the
// kubelet's two satisfaction rules — a PLAIN init container completes (exit 0), a
// NATIVE SIDECAR merely has to have STARTED (it is long-running by design).
func TestComputeInitialized(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	initPod := func(specs ...corev1.Container) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{InitContainers: specs}}
	}
	plain := corev1.Container{Name: "setup"}
	sidecar := corev1.Container{Name: "proxy", RestartPolicy: &always}

	terminated := func(name string, code int32) corev1.ContainerStatus {
		return corev1.ContainerStatus{
			Name:  name,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code}},
		}
	}
	started := func(name string, up bool) corev1.ContainerStatus {
		return corev1.ContainerStatus{
			Name:    name,
			Started: &up,
			State:   corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}
	}
	crashLooping := func(name string) corev1.ContainerStatus {
		return corev1.ContainerStatus{
			Name:  name,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reasonCrashLoopBackOff}},
		}
	}

	tests := []struct {
		name   string
		pod    *corev1.Pod
		initCS []corev1.ContainerStatus
		want   corev1.ConditionStatus
	}{
		{"nil pod is Initialized", nil, nil, corev1.ConditionTrue},
		{"no init containers is Initialized", initPod(), nil, corev1.ConditionTrue},
		{"completed plain init container", initPod(plain), []corev1.ContainerStatus{terminated("setup", 0)}, corev1.ConditionTrue},
		{"failed plain init container", initPod(plain), []corev1.ContainerStatus{terminated("setup", 1)}, corev1.ConditionFalse},
		{"plain init container still running", initPod(plain), []corev1.ContainerStatus{started("setup", true)}, corev1.ConditionFalse},
		{"declared init container with no status yet", initPod(plain), nil, corev1.ConditionFalse},
		{"started sidecar satisfies it", initPod(sidecar), []corev1.ContainerStatus{started("proxy", true)}, corev1.ConditionTrue},
		{"sidecar not yet started", initPod(sidecar), []corev1.ContainerStatus{started("proxy", false)}, corev1.ConditionFalse},
		{"sidecar crash-looping before it ever started", initPod(sidecar), []corev1.ContainerStatus{crashLooping("proxy")}, corev1.ConditionFalse},
		{
			"all of a mixed init set satisfied",
			initPod(plain, sidecar),
			[]corev1.ContainerStatus{terminated("setup", 0), started("proxy", true)},
			corev1.ConditionTrue,
		},
		{
			"one unsatisfied member blocks the whole set",
			initPod(plain, sidecar),
			[]corev1.ContainerStatus{terminated("setup", 0), crashLooping("proxy")},
			corev1.ConditionFalse,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeInitialized(tt.pod, tt.initCS)
			if got.Type != corev1.PodInitialized {
				t.Fatalf("condition type = %s, want PodInitialized", got.Type)
			}
			if got.Status != tt.want {
				t.Errorf("PodInitialized = %s, want %s", got.Status, tt.want)
			}
			if tt.want == corev1.ConditionFalse && got.Reason != "ContainersNotInitialized" {
				t.Errorf("reason = %q, want ContainersNotInitialized", got.Reason)
			}
		})
	}
}

// TestToPodBoxPersistentVolumeClaimVolume pins the durable PVC source through
// translation. It is a regression test with a specific history: the source existed in
// the proto (persistent_volume_claim, M3.1) and runtimed already materialized it, but
// toVolume had no case for it — so the volume was silently dropped and every
// StatefulSet with a volumeClaimTemplate failed at admission with "volume_mount
// \"data\" references undefined volume", a message that names the mount and never the
// missing source. The mount is asserted alongside the volume because the dropped
// volume only becomes observable through the dangling mount.
func TestToPodBoxPersistentVolumeClaimVolume(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db-0", UID: types.UID("uid-db-0")},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-db-0"}}},
				{Name: "ro", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "shared", ReadOnly: true}}},
			},
			Containers: []corev1.Container{{
				Name:         "app",
				Image:        "native",
				VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/var/data"}},
			}},
		},
	}

	box, err := toPodBox(pod, "10.0.0.7", "/var/lib/k3sm/pods/uid-db-0", "", netv1.DNSConfig{})
	if err != nil {
		t.Fatalf("toPodBox: %v", err)
	}

	byName := map[string]*runtimev1.Volume{}
	for _, v := range box.GetVolumes() {
		byName[v.GetName()] = v
	}
	if len(byName) != 2 {
		t.Fatalf("want 2 volumes carried through, got %d (%v) — an unmodeled source is silently dropped", len(byName), byName)
	}

	data := byName["data"].GetPersistentVolumeClaim()
	if data == nil {
		t.Fatal(`volume "data" lost its persistent_volume_claim source`)
	}
	if got := data.GetClaimName(); got != "data-db-0" {
		t.Errorf("claim_name = %q, want %q", got, "data-db-0")
	}
	if data.GetReadOnly() {
		t.Error("read_only = true, want false (the claim is read-write)")
	}
	if ro := byName["ro"].GetPersistentVolumeClaim(); ro == nil || !ro.GetReadOnly() {
		t.Errorf("read-only claim did not carry read_only=true: %+v", ro)
	}

	// The dangling-mount failure mode: every mount must resolve to a carried volume.
	for _, c := range box.GetContainers() {
		for _, m := range c.GetVolumeMounts() {
			if _, ok := byName[m.GetName()]; !ok {
				t.Errorf("container %s mounts %q but no such volume was carried — this is the exact shape runtimed rejects", c.GetName(), m.GetName())
			}
		}
	}
}
