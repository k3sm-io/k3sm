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
	"log/slog"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/runtimed/pkg/image"
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

// dyldInsertAnnotation is the PodBox annotation runtimed reads to inject the
// darwin-net getaddrinfo DNS shim into each container (DYLD_INSERT_LIBRARIES).
// It matches runtimed/pkg/runtime's constant; the provider sets it when a shim
// path is configured.
const dyldInsertAnnotation = "k3sm.io/dyld-insert-libraries"

// memoryLimitAnnotation carries the pod's memory limit in BYTES. apis:M2.2 now
// defines the typed PodBox.memory_limit_bytes field (which toPodBox sets and
// runtimed reads first); this annotation is kept as a transitional fallback
// runtimed bridges when the typed field is unset. It matches runtimed/pkg/runtime's
// constant (exactly as the DNS shim rides dyldInsertAnnotation). The value is in
// ri_phys_footprint units, NOT RSS.
const memoryLimitAnnotation = "k3sm.io/memory-limit-bytes"

// rlimitAnnotationPrefix prefixes the pod annotations that source
// PodBox.rlimits[] (field 102): `k3sm.io/rlimit-<resource>` (e.g.
// k3sm.io/rlimit-nofile, k3sm.io/rlimit-nproc), value `<soft>` or
// `<soft>:<hard>`, each a decimal integer up to 2^63-1 or "unlimited" (a
// single value means soft=hard; see parseRlimitMagnitude for the ceiling).
// The suffix maps to ResourceLimit.type as "RLIMIT_"+strings.ToUpper(suffix)
// with no name allowlist — runtimed's rlimitResource map is the semantic
// authority; the provider validates syntax only and fails CreatePod naming
// the bad key, so a producer-side skip can't compose with a consumer-side one
// into an unconstrained pod.
//
// PodBox.rlimits is pod-level (like memoryLimitAnnotation), so these limits
// apply to init/sidecar/main containers alike; per-container rlimits would
// need an apis change (out of B7 scope). Darwin semantics live with the
// consumer: runtimed clamps an unlimited RLIMIT_NOFILE to the kernel ceiling
// and counts RLIMIT_NPROC per-uid (the shared _k3sm user) — see
// runtimed/docs/resources.md.
const rlimitAnnotationPrefix = "k3sm.io/rlimit-"

// rlimitUnlimited is the annotation value token for "no limit". It is encoded
// as all-ones (^uint64(0)), the sentinel runtimed's rlimitValue maps to
// unix.RLIM_INFINITY.
const rlimitUnlimited = "unlimited"

// defaultGraceSeconds is the Kubernetes default SIGTERM→SIGKILL window applied
// when a pod sets no terminationGracePeriodSeconds. proto3 int64 cannot represent
// "unset", so the provider applies the 30s default itself — runtimed treats a 0
// grace as immediate-kill, which is NOT the k8s default.
const defaultGraceSeconds int64 = 30

// toPodBox translates a corev1.Pod into the runtime PodBox runtimed consumes. It
// fills sandbox_profile and signature_policy so runtimed's fail-closed gate
// passes: a nil profile or an unset signature policy makes CreatePod refuse the
// pod (the sandbox backend itself may be unspecified — that is the host-process
// default; see podSandboxBackend).
//
// It fails closed when the pod names a RuntimeClass with no backend mapping
// (runtimev1.ErrUnknownHandler — refused rather than silently downgraded), and
// when its k3sm.io/image-platform annotation is malformed (podImagePlatform).
//
// rootfsRoot is the per-pod-dir parent; dyldShim, when non-empty, is wired into
// the annotation runtimed copies to DYLD_INSERT_LIBRARIES (the DNS shim).
//
// Container env is carried structurally (literal value, valueFrom, envFrom);
// resolvePodBoxEnv flattens it into literal values before the box reaches
// runtimed, which reads only EnvVar.value and never talks to the apiserver.
//
// dnsCfg is the pod's cluster DNS configuration. For a cluster-first DNSPolicy,
// toPodBox injects the K3SM_DNS_* env the DYLD getaddrinfo shim reads (via
// dns.ConfigToEnv) into every container so in-pod Service names resolve against
// the cluster DNS VIP (B18, see injectClusterDNSEnv) — without this env the shim
// only loads and falls back to the host resolver.
//
// B20a additively merges a cluster-first pod's spec.dnsConfig into the cluster
// base (extra search domains appended+deduped, ndots override) before this
// injection; a None/Default pod keeps the unmerged base. Still deferred to B20b:
// dnsPolicy: None's own nameservers, an explicit ndots: 0 (indistinguishable
// from unset in this int32 path), spec.dnsConfig.nameservers under ClusterFirst
// (the shim ABI carries one server), and non-ndots options.
//
// nodeIP discriminates the bind-discipline env: a pod with a distinct /32
// (podIP != nodeIP) gets K3SM_POD_IP injected so the DYLD bind() interpose
// rewrites its wildcard binds onto that /32 (B217); hostNetwork/vm/no-network
// pods (podIP == nodeIP) get nothing. log, when non-nil, receives the M0
// host-binary-route warn — see injectBindDisciplineEnv.
func toPodBox(pod *corev1.Pod, podIP, nodeIP, rootfsRoot, dyldShim string, dnsCfg netv1.DNSConfig, log *slog.Logger) (*runtimev1.PodBox, error) {
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
	// Set the typed apis:M2.2 PodBox fields: memory_limit_bytes (the OOM ceiling
	// runtimed compares ri_phys_footprint against) and qos_class (runtimed's
	// best-effort CPU policy). The k3sm.io/memory-limit-bytes annotation is also
	// written after the user annotations as a transitional fallback runtimed
	// bridges when the typed field is unset; the typed field is authoritative.
	if lim := podMemoryLimitBytes(pod); lim > 0 {
		box.MemoryLimitBytes = lim
		box.Annotations[memoryLimitAnnotation] = strconv.FormatInt(lim, 10)
	}
	box.QosClass = podQOSClass(pod)

	// The rlimit source (B7) is explicit k3sm.io/rlimit-* annotations only —
	// mirroring runtimed's no-synthesis discipline (no RLIMIT_AS from
	// resources.limits.memory, no RLIMIT_CPU from cpu; see resolveRlimitPlan). A
	// malformed annotation fails the pod here.
	rlimits, err := podRlimits(pod)
	if err != nil {
		return nil, err
	}
	box.Rlimits = rlimits

	box.InitContainers = toRuntimeContainers(pod.Spec.InitContainers, true)
	box.Containers = toRuntimeContainers(pod.Spec.Containers, false)

	// The k3sm.io/image-platform override (M11.4) is parsed once here — the
	// annotation is pod-level — and stamped onto every container as the typed
	// Platform message, so nothing downstream re-parses a user string. A
	// malformed value fails the pod here (same fail-closed posture as rlimits):
	// silently defaulting the platform would run the wrong binaries unnoticed.
	imagePlatform, err := podImagePlatform(pod)
	if err != nil {
		return nil, err
	}
	stampImagePlatform(box, imagePlatform)

	// Inject cluster DNS env for the DYLD shim, gated on DNSPolicy — see
	// injectClusterDNSEnv (B18).
	injectClusterDNSEnv(box, pod.Spec.DNSPolicy, dnsCfg)

	// Inject K3SM_POD_IP for the DYLD bind() interpose, gated on a distinct /32
	// (B217) — see injectBindDisciplineEnv.
	injectBindDisciplineEnv(box, podIP, nodeIP, clusterCIDRs(dnsCfg.ClusterDNSIP), log)

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

	// Resolve the pod's RuntimeClass to its isolation backend (M5.1) — see
	// podSandboxBackend for the fail-closed contract.
	backend, err := podSandboxBackend(pod)
	if err != nil {
		return nil, err
	}
	// data_volume_path is the only path the pod may write; default-deny otherwise.
	// allow_network is true so the pod can reach the Service proxy + CoreDNS VIP
	// (runtime scopes it to the pod IP).
	box.SandboxProfile = &runtimev1.SandboxProfile{
		Backend:        backend,
		DataVolumePath: rootfsRoot,
		AllowNetwork:   true,
	}
	// GPU + internet-egress intent (M8.3-d2) — see applyGPUAndEgress for the
	// egress⇒network pairing.
	applyGPUAndEgress(box.SandboxProfile, pod)
	// For a vm pod, size the guest from the pod's cpu/memory (the VZ vCPU count +
	// RAM; 0 leaves the runtimed/VZ default). The Seatbelt rungs ignore these.
	if backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		box.SandboxProfile.VmVcpus = podVMVCPUs(pod)
		box.SandboxProfile.VmMemoryBytes = podVMMemoryBytes(pod)
	}
	return box, nil
}

// podRequestsGPU reports whether the pod requests the mlx.k3sm.io/gpu extended
// resource (mlxv1alpha1.ResourceGPU) via a container's limits, not requests —
// matching how podMemoryLimitBytes and effectiveResource already treat limits
// as the authoritative ceiling; a requests-only GPU ask is not a grant. Checked
// across init and regular containers: an init container that needs GPU access
// (e.g. a model-fetch step) is as real a request as a regular one.
func podRequestsGPU(pod *corev1.Pod) bool {
	gpu := corev1.ResourceName(mlxv1alpha1.ResourceGPU)
	for i := range pod.Spec.InitContainers {
		if q, ok := pod.Spec.InitContainers[i].Resources.Limits[gpu]; ok && !q.IsZero() {
			return true
		}
	}
	for i := range pod.Spec.Containers {
		if q, ok := pod.Spec.Containers[i].Resources.Limits[gpu]; ok && !q.IsZero() {
			return true
		}
	}
	return false
}

// podRequestsInternetEgress reports whether the pod carries the
// runtimev1.AnnotationInternetEgress annotation (k3sm.io/internet-egress), by
// presence, not a parsed boolean. The annotation is operator-stamped plumbing
// under the single-trust-domain model; a hand-set use on a non-operator pod is
// not rejected here (that is the M8.3-d3 Warn VAP's job), so any value on the
// key opts the pod in.
func podRequestsInternetEgress(pod *corev1.Pod) bool {
	_, ok := pod.Annotations[runtimev1.AnnotationInternetEgress]
	return ok
}

// applyGPUAndEgress sets SandboxProfile.AllowGpu/AllowInternetEgress from the
// pod's GPU-limit and egress-annotation intent, then enforces the
// AllowInternetEgress ⇒ AllowNetwork pairing: a pod that opts into internet
// egress must still carry AllowNetwork, or it loses the cluster DNS-VIP route
// Seatbelt only emits under AllowNetwork — it would be unable to resolve names
// before reaching the network it asked for. AllowNetwork is otherwise left as
// the caller set it (toPodBox hardcodes it true for every pod today), but the
// pairing holds regardless of that caller's choice.
func applyGPUAndEgress(profile *runtimev1.SandboxProfile, pod *corev1.Pod) {
	profile.AllowGpu = podRequestsGPU(pod)
	profile.AllowInternetEgress = podRequestsInternetEgress(pod)
	if profile.AllowInternetEgress {
		profile.AllowNetwork = true
	}
}

// injectClusterDNSEnv appends the K3SM_DNS_* environment the DYLD getaddrinfo shim
// reads (serialized by the single pinned dns.ConfigToEnv encoder, never
// hand-rolled here — a wrong separator would break in-pod cluster DNS) to every
// container so a pod's unqualified Service lookups expand against the cluster
// DNS VIP.
//
// DNSPolicy-gated to the cluster-first policies (clusterDNSPolicy): Default and
// None inject nothing, falling back to the host resolver — Default semantics for
// a Default pod; for None (custom spec.dnsConfig nameservers) this is deferred
// to B20b.
//
// Scope parity: appended to both InitContainers and Containers, matching the
// box-wide DYLD shim annotation.
//
// Precedence (infra-wins): appended after each container's user env, so
// resolveContainerEnv's later-wins upsert makes the cluster value authoritative
// — a workload cannot override cluster DNS under ClusterFirst. Keys are sorted
// for deterministic output.
//
// When dnsCfg is not usable (no cluster DNS VIP / invalid), dns.ConfigToEnv
// returns nil and nothing is injected.
func injectClusterDNSEnv(box *runtimev1.PodBox, policy corev1.DNSPolicy, dnsCfg netv1.DNSConfig) {
	if !clusterDNSPolicy(policy) {
		return
	}
	env := dns.ConfigToEnv(dnsCfg)
	if env == nil {
		return
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	appendEnv := func(c *runtimev1.Container) {
		for _, k := range keys {
			c.Env = append(c.Env, &runtimev1.EnvVar{Name: k, Value: env[k]})
		}
	}
	for _, c := range box.GetInitContainers() {
		appendEnv(c)
	}
	for _, c := range box.GetContainers() {
		appendEnv(c)
	}
}

// clusterCIDRs returns the B218 connect() rung's destination scope: the cluster pod
// CIDR (podnet.ClusterPodCIDR, the lo0-alias /10 every pod /32 is allocated from) and,
// when derivable, the cluster Service CIDR — the two ranges whose destinations may be
// source-pinned to a pod's own /32 on an unbound dial.
//
// dnsVIP is dnsCfg.ClusterDNSIP, the cluster DNS Service VIP already threaded into
// toPodBox. It is the only Service-network-shaped value reaching this assembly
// point — k3sm's server/agent commands carry no --service-cidr flag (only `k3sm
// netd`'s proxy path does) — so the Service CIDR is derived by masking the
// configured VIP to a /16, the range k3sm always allocates Service VIPs from
// (10.43.0.10 -> 10.43.0.0/16, matching install.DefaultServiceCIDR). An empty or
// unparseable/non-IPv4 VIP (e.g. a standalone `k3sm node` with no cluster DNS)
// yields no Service CIDR entry; the pod CIDR is still returned as a fixed constant.
func clusterCIDRs(dnsVIP string) []netip.Prefix {
	cidrs := []netip.Prefix{podnet.ClusterPodCIDR}
	if dnsVIP == "" {
		return cidrs
	}
	addr, err := netip.ParseAddr(dnsVIP)
	if err != nil || !addr.Is4() {
		return cidrs
	}
	return append(cidrs, netip.PrefixFrom(addr, 16).Masked())
}

// injectBindDisciplineEnv appends the K3SM_POD_IP environment the DYLD bind() interpose
// (shim/getaddrinfo_shim.c) reads to rewrite a pod's wildcard binds onto its own /32,
// giving same-node pods separate per-IP port spaces (two pods can both hold :8080 —
// ≥1024 TCP+UDP, the B215-measured carve). It is the B217 keystone: the DYLD shim
// annotation only loads the dylib; without this env the interpose passes every bind
// through unchanged and the same-node EADDRINUSE collision class stands.
//
// cidrs (B218) is the connect() rung's destination scope — the cluster pod CIDR and
// the cluster Service CIDR (see clusterCIDRs) — passed through verbatim to
// podnet.BindDisciplineEnvWithCIDRs, which additionally emits K3SM_CLUSTER_CIDRS so
// an unbound dial from this pod to another in-cluster address is source-pinned to the
// pod's own /32 too, not just an inbound bind. A nil/empty cidrs list degrades to the
// pre-B218 BindDisciplineEnv output — the connect rung stays off.
//
// Gated on the pod having a distinct /32 (podIP != nodeIP). A hostNetwork pod
// (MarkHostNetwork → podIP == nodeIP, zero allocation), a vm pod, and --network none
// all resolve podIP to the node IP and get nothing: hostNetwork's shipped semantic
// (a pod shares the node's addresses) must not be narrowed by rewriting its wildcard
// binds onto the node IP. Value serialization and IPv4/unspecified rejection are
// podnet.BindDisciplineEnvWithCIDRs's (the single pinned encoder of the shim ABI); a
// nil return injects nothing, and an unparseable podIP is likewise a no-op — the
// discipline stays off rather than mis-binds.
//
// Precedence (infra-wins) mirrors injectClusterDNSEnv: appended after each
// container's user env to both init and regular containers, so a workload cannot
// override the allocated /32.
//
// On an M0 host-binary route (the native sentinel, or an absolute-path image with no
// command/args) the pod binary is never ad-hoc re-signed, so AMFI drops the DYLD
// insert and the interpose never loads — the pod binds wildcard regardless of this
// env. The warn log naming the pod is the only breadcrumb an operator debugging a
// host-binary EADDRINUSE gets, since the insert drop is otherwise invisible.
func injectBindDisciplineEnv(box *runtimev1.PodBox, podIP, nodeIP string, cidrs []netip.Prefix, log *slog.Logger) {
	if podIP == "" || podIP == nodeIP {
		return
	}
	addr, err := netip.ParseAddr(podIP)
	if err != nil {
		return
	}
	env := podnet.BindDisciplineEnvWithCIDRs(addr, cidrs)
	if env == nil {
		return
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	appendEnv := func(c *runtimev1.Container) {
		for _, k := range keys {
			c.Env = append(c.Env, &runtimev1.EnvVar{Name: k, Value: env[k]})
		}
	}
	for _, c := range box.GetInitContainers() {
		appendEnv(c)
	}
	for _, c := range box.GetContainers() {
		appendEnv(c)
	}
	if log == nil {
		return
	}
	warn := func(c *runtimev1.Container) {
		if !isHostBinaryRoute(c) {
			return
		}
		log.Warn("bind-discipline env injected on an M0 host-binary route: the host binary is never ad-hoc re-signed, so AMFI drops the DYLD insert and the interpose never loads — this container binds wildcard, and its per-IP port space is NOT enforced (a same-node EADDRINUSE will name the wrong pod)",
			"namespace", box.GetNamespace(), "pod", box.GetName(), "container", c.GetName(), "pod_ip", podIP)
	}
	for _, c := range box.GetInitContainers() {
		warn(c)
	}
	for _, c := range box.GetContainers() {
		warn(c)
	}
}

// isHostBinaryRoute reports whether c runs on the M0 host-binary route runtimed's
// resolveBinary takes without a pull — the native sentinel (runtimed.NativeImage), or
// an absolute-path image reference with no command/args (image.IsHostPathReference).
// Such a binary is executed in place and NEVER ad-hoc re-signed, so a DYLD insert on it
// is silently dropped by AMFI. It mirrors runtimed/pkg/runtime.resolveBinary's
// discriminator so the provider warns on exactly the routes the shim cannot reach.
func isHostBinaryRoute(c *runtimev1.Container) bool {
	if c.GetImage() == runtimed.NativeImage {
		return true
	}
	return len(c.GetCommand()) == 0 && len(c.GetArgs()) == 0 && image.IsHostPathReference(c.GetImage())
}

// clusterDNSPolicy reports whether the pod's DNSPolicy selects cluster DNS. An empty
// policy is the upstream default (ClusterFirst). ClusterFirstWithHostNet MUST match
// too: k3sm pods share the host network by construction, so that value is reachable —
// matching only DNSClusterFirst would silently drop cluster DNS for those pods.
// Default and None do NOT select cluster DNS (no injection).
func clusterDNSPolicy(policy corev1.DNSPolicy) bool {
	return policy == "" ||
		policy == corev1.DNSClusterFirst ||
		policy == corev1.DNSClusterFirstWithHostNet
}

// dnsConfigOverride reduces a pod's corev1 spec.dnsConfig to the DISCRETE
// search/ndots inputs darwin-net's netv1-only dns.MergeDNSConfig consumes. k3sm is
// the corev1-aware layer, so this corev1→params extraction lives HERE (never in
// darwin-net/pkg/dns). buildBox calls it for a ClusterFirst pod and feeds the result
// to dns.MergeDNSConfig, which can only ADD to the cluster search list / override
// ndots — never preempt the cluster server VIP.
//
// A nil c yields (nil, 0): no extra searches, "keep the cluster base ndots". searches
// is the pod's spec.dnsConfig.searches verbatim. ndots scans c.Options for the first
// "ndots" entry: a non-negative integer value (strconv.Atoi) becomes the override,
// clamped to [0, dns.MaxNDots] (the resolv.conf RES_MAXNDOTS ceiling) before the int32
// narrowing so an absurd value (>=2^31) cannot wrap negative and be silently dropped as
// keep-base; anything else — absent, nil/empty, unparseable, or negative — yields 0,
// which dns.MergeDNSConfig reads as "keep base".
//
// DEFERRED to B20b (the apis wave): c.Nameservers (the single-server shim ABI carries
// exactly one server — the cluster VIP), an explicit `ndots: 0` (the int32 path cannot
// distinguish it from unset), and every non-"ndots" option (no shim consumer). They
// are intentionally dropped so a ClusterFirst pod can only ADD to its cluster
// search/ndots, never repoint the cluster resolver.
func dnsConfigOverride(c *corev1.PodDNSConfig) (searches []string, ndots int32) {
	if c == nil {
		return nil, 0
	}
	searches = c.Searches
	for i := range c.Options {
		if c.Options[i].Name != "ndots" {
			continue
		}
		// The first "ndots" option decides (see the func doc for the deferral and
		// the keep-base fallback).
		if v := c.Options[i].Value; v != nil {
			if n, err := strconv.Atoi(*v); err == nil && n >= 0 {
				// dns.MaxNDots is untyped, so it compares directly against n with no
				// cast; strconv.Atoi already returns ErrRange beyond int64.
				if n > dns.MaxNDots {
					n = dns.MaxNDots
				}
				ndots = int32(n)
			}
		}
		break
	}
	return searches, ndots
}

// podSandboxBackend resolves the pod's RuntimeClass (spec.runtimeClassName) to the
// SandboxBackend runtimed must confine it with, via the apis built-in
// handler→backend table (runtimev1.DefaultHandlerConfig). The empty/absent
// RuntimeClass resolves to SANDBOX_BACKEND_UNSPECIFIED — the host-process default
// that defers the rung choice to runtimed's host-OS-version-gated SelectBackend —
// and "vm" resolves to SANDBOX_BACKEND_VM. A non-empty handler with no mapping
// returns an error wrapping runtimev1.ErrUnknownHandler: k3sm fails closed (the
// pod's CreatePod is refused) rather than running a pod that requested stronger
// isolation on a weaker backend.
func podSandboxBackend(pod *corev1.Pod) (runtimev1.SandboxBackend, error) {
	var handler runtimev1.HandlerName
	if pod.Spec.RuntimeClassName != nil {
		handler = runtimev1.HandlerName(*pod.Spec.RuntimeClassName)
	}
	backend, err := runtimev1.DefaultHandlerConfig().Backend(handler)
	if err != nil {
		return runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			fmt.Errorf("resolve runtimeClassName %q: %w", handler, err)
	}
	return backend, nil
}

// podVMMemoryBytes returns the RAM (bytes) to provision a vm-RuntimeClass pod's
// guest with, summed across the regular containers: each container's effective
// memory is its limit when set, else its request (the "requests-or-limits" sizing).
// Init containers run sequentially BEFORE the regular set, so they add nothing to
// the concurrent guest budget. 0 ("nothing set") leaves runtimed/VZ to pick a
// default. This is the VM's RAM allocation, NOT an OOM ceiling (that is
// memory_limit_bytes, which the host-process path enforces).
func podVMMemoryBytes(pod *corev1.Pod) int64 {
	var sum int64
	for i := range pod.Spec.Containers {
		sum += effectiveResource(&pod.Spec.Containers[i], corev1.ResourceMemory)
	}
	return sum
}

// podVMVCPUs returns the vCPU count to provision a vm-RuntimeClass pod's guest with:
// the regular containers' effective CPU (limit when set, else request) summed in
// milli-CPU and rounded UP to whole vCPUs (a fractional CPU still gets one vCPU). 0
// ("no cpu set") leaves runtimed/VZ to pick a default.
func podVMVCPUs(pod *corev1.Pod) uint32 {
	var milli int64
	for i := range pod.Spec.Containers {
		milli += effectiveResource(&pod.Spec.Containers[i], corev1.ResourceCPU)
	}
	if milli <= 0 {
		return 0
	}
	return uint32((milli + 999) / 1000) // ceil to whole cores
}

// effectiveResource returns container c's effective quantity for resource name in
// its canonical scalar unit (bytes for memory, milli-CPU for cpu): the limit when
// set, otherwise the request, otherwise 0. It is the per-container input to the vm
// guest sizing (podVMVCPUs / podVMMemoryBytes).
func effectiveResource(c *corev1.Container, name corev1.ResourceName) int64 {
	if q, ok := c.Resources.Limits[name]; ok {
		return scalarQuantity(name, q)
	}
	if q, ok := c.Resources.Requests[name]; ok {
		return scalarQuantity(name, q)
	}
	return 0
}

// scalarQuantity reduces a resource.Quantity to the int64 scalar the vm sizing
// uses: MilliValue for cpu (so 500m → 500, 2 → 2000) and Value (bytes) for memory.
func scalarQuantity(name corev1.ResourceName, q resource.Quantity) int64 {
	if name == corev1.ResourceCPU {
		return q.MilliValue()
	}
	return q.Value()
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

// podRlimits builds PodBox.rlimits[] from the pod's k3sm.io/rlimit-<resource>
// annotations (see rlimitAnnotationPrefix for the grammar and the pod-scoped
// contract). The annotation suffix becomes ResourceLimit.type mechanically
// ("RLIMIT_"+ToUpper), with no name allowlist — semantic validity is runtimed's
// (rlimitResource). Validation here is syntax only, and it fails fast naming
// the offending annotation key: unparseable values, soft>hard (unlimited counts
// as max), and two keys colliding onto one type (their apply order would be
// map-iteration random) all reject the pod. The result is sorted by type name
// so the proto slice — and the daemon's apply order — is deterministic.
func podRlimits(pod *corev1.Pod) ([]*runtimev1.ResourceLimit, error) {
	var keys []string
	for k := range pod.Annotations {
		if strings.HasPrefix(k, rlimitAnnotationPrefix) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	sort.Strings(keys) // deterministic parse order ⇒ deterministic first error
	out := make([]*runtimev1.ResourceLimit, 0, len(keys))
	byType := make(map[string]string, len(keys)) // type → source annotation key
	for _, k := range keys {
		typ := "RLIMIT_" + strings.ToUpper(strings.TrimPrefix(k, rlimitAnnotationPrefix))
		// The duplicate-type reject (here) and the soft≤hard reject
		// (parseRlimitValue) are value/shape checks, not name semantics — they
		// need no rlimit-name knowledge. Keep them; they are not scope creep.
		if prev, dup := byType[typ]; dup {
			return nil, fmt.Errorf("rlimit annotations %s and %s both map to type %s", prev, k, typ)
		}
		byType[typ] = k
		soft, hard, err := parseRlimitValue(pod.Annotations[k])
		if err != nil {
			return nil, fmt.Errorf("rlimit annotation %s: %w", k, err)
		}
		out = append(out, &runtimev1.ResourceLimit{Type: typ, Soft: soft, Hard: hard})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out, nil
}

// parseRlimitValue parses one rlimit annotation value: `<soft>` or
// `<soft>:<hard>`, each a decimal integer up to 2^63-1 or the "unlimited"
// token; a single value means soft=hard. soft must not exceed hard, with
// unlimited counting as the maximum (its ^uint64(0) encoding makes that a
// plain compare). The soft≤hard reject is a value-shape check, not name
// semantics — see podRlimits.
func parseRlimitValue(v string) (soft, hard uint64, err error) {
	softStr, hardStr, hasHard := strings.Cut(v, ":")
	soft, err = parseRlimitMagnitude(softStr)
	if err != nil {
		return 0, 0, err
	}
	hard = soft
	if hasHard {
		hard, err = parseRlimitMagnitude(hardStr)
		if err != nil {
			return 0, 0, err
		}
	}
	if soft > hard {
		return 0, 0, fmt.Errorf("soft limit %s exceeds hard limit %s", softStr, hardStr)
	}
	return soft, hard, nil
}

// parseRlimitMagnitude parses one limit magnitude: a decimal integer up to
// 2^63-1 (math.MaxInt64), or the "unlimited" token encoded as ^uint64(0) (the
// all-ones sentinel runtimed's rlimitValue maps to unix.RLIM_INFINITY).
//
// Magnitudes above 2^63-1 are rejected, not carried: darwin's RLIM_INFINITY is
// 2^63-1, and runtimed collapses only the true sentinels (^uint64(0) /
// RLIM_INFINITY's own bit pattern) — a value in (2^63-1, 2^64-1) would ride
// through verbatim and make setrlimit see Cur > Max (e.g. huge soft with an
// unlimited hard), an EINVAL launch abort that names no annotation. Fail-fast
// here instead, where the error can name the key.
func parseRlimitMagnitude(s string) (uint64, error) {
	if s == rlimitUnlimited {
		return ^uint64(0), nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("limit %q is not a decimal integer or %q", s, rlimitUnlimited)
	}
	if n > math.MaxInt64 {
		return 0, fmt.Errorf("limit %q exceeds the 2^63-1 maximum (darwin RLIM_INFINITY); use %q for no limit", s, rlimitUnlimited)
	}
	return n, nil
}

// podQOSClass computes the pod's Quality-of-Service class and maps it to the apis
// runtime QOSClass enum runtimed uses for best-effort CPU scheduling policy (k3sm
// has no CFS millicore enforcement). The VK provider replaces the kubelet, which
// is where Status.QOSClass is normally derived, so the provider computes it from
// the spec here rather than trusting a possibly-unset status field.
func podQOSClass(pod *corev1.Pod) runtimev1.QOSClass {
	switch computePodQOS(pod) {
	case corev1.PodQOSGuaranteed:
		return runtimev1.QOSClass_QOS_CLASS_GUARANTEED
	case corev1.PodQOSBurstable:
		return runtimev1.QOSClass_QOS_CLASS_BURSTABLE
	case corev1.PodQOSBestEffort:
		return runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT
	default:
		return runtimev1.QOSClass_QOS_CLASS_UNSPECIFIED
	}
}

// computePodQOS reproduces the kubelet's v1qos.GetPodQOS classification over the
// pod's init + regular containers, considering only the CPU and memory resources:
//   - Guaranteed: every container sets non-zero CPU AND memory limits, and every
//     resource's summed request equals its summed limit;
//   - BestEffort: no container sets any CPU/memory request or limit;
//   - Burstable: anything in between.
//
// This is a hand reproduction of a server-side computation and must track upstream
// k8s.io/component-helpers/scheduling/corev1/v1qos.GetPodQOS — k3sm replaces the
// kubelet, so when the apiserver has not yet stamped Status.QOSClass this is the
// only source of the class. It is the fallback only: toPodStatus carries forward
// the apiserver's value when present (immune to any drift here);
// TestPodStatusQOSClass pins this reproduction.
func computePodQOS(pod *corev1.Pod) corev1.PodQOSClass {
	requests := corev1.ResourceList{}
	limits := corev1.ResourceList{}
	isGuaranteed := true

	accumulate := func(c *corev1.Container) {
		for name, q := range c.Resources.Requests {
			if !isQOSComputeResource(name) || q.CmpInt64(0) <= 0 {
				continue
			}
			delta := q.DeepCopy()
			if existing, ok := requests[name]; ok {
				delta.Add(existing)
			}
			requests[name] = delta
		}
		limitedResources := 0
		for name, q := range c.Resources.Limits {
			if !isQOSComputeResource(name) || q.CmpInt64(0) <= 0 {
				continue
			}
			limitedResources++
			delta := q.DeepCopy()
			if existing, ok := limits[name]; ok {
				delta.Add(existing)
			}
			limits[name] = delta
		}
		// Guaranteed requires BOTH cpu and memory to carry a non-zero limit on
		// every container; fewer than the two compute resources breaks it.
		if limitedResources < 2 {
			isGuaranteed = false
		}
	}
	for i := range pod.Spec.InitContainers {
		accumulate(&pod.Spec.InitContainers[i])
	}
	for i := range pod.Spec.Containers {
		accumulate(&pod.Spec.Containers[i])
	}

	if len(requests) == 0 && len(limits) == 0 {
		return corev1.PodQOSBestEffort
	}
	if isGuaranteed {
		for name, req := range requests {
			lim, ok := limits[name]
			if !ok || lim.Cmp(req) != 0 {
				isGuaranteed = false
				break
			}
		}
	}
	if isGuaranteed && len(requests) == len(limits) {
		return corev1.PodQOSGuaranteed
	}
	return corev1.PodQOSBurstable
}

// isQOSComputeResource reports whether name participates in QoS classification —
// only CPU and memory, matching the kubelet's supported QoS-compute resources.
func isQOSComputeResource(name corev1.ResourceName) bool {
	return name == corev1.ResourceCPU || name == corev1.ResourceMemory
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
//
// imagePullPolicy is carried verbatim (M12.1) — see toImagePullPolicy.
//
// init selects the M10.2 restart_policy mapping: on an init container,
// restartPolicy: Always (KEP-753) maps to CONTAINER_RESTART_POLICY_ALWAYS — the
// proto marker runtimed reads to run it as a native sidecar (spawned-not-waited,
// tracked long-lived, torn down in reverse after the mains). Regular containers
// always carry UNSPECIFIED: per-container policy on regular containers is out of
// scope, and the proto field is meaningful only on init containers today (see
// apis runtime.proto Container.restart_policy).
func toRuntimeContainers(cs []corev1.Container, init bool) []*runtimev1.Container {
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
			ImagePullPolicy: toImagePullPolicy(c.ImagePullPolicy),
		}
		if init && c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			rc.RestartPolicy = runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
		}
		out = append(out, rc)
	}
	return out
}

// toImagePullPolicy maps the container's stamped corev1 imagePullPolicy onto the
// proto enum, verbatim (M12.1).
//
// Defaulting is the embedded apiserver's: it stamps the corev1 default onto the
// pod spec before scheduling (a `:latest`/untagged reference defaults to Always,
// anything else to IfNotPresent). This function reads only the stamped value and
// never looks at the image reference; runtimed does not re-derive it either — a
// second derivation point could disagree with the stamped spec, and `kubectl get
// pod -o yaml` would stop describing what the node actually did.
//
// An empty value maps to UNSPECIFIED, which runtimed reads as the legacy
// pull-through — the skew contract's zero value, never an implicit Never. An
// unrecognised value maps there too: corev1's set is closed and apiserver
// validation rejects anything else, so this arm is unreachable in practice, and
// failing to a pull attempt is the safe direction.
func toImagePullPolicy(p corev1.PullPolicy) runtimev1.ImagePullPolicy {
	switch p {
	case corev1.PullAlways:
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS
	case corev1.PullIfNotPresent:
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT
	case corev1.PullNever:
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER
	default:
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED
	}
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

// toVolumes maps the modeled corev1 volume subset (configMap / secret / emptyDir /
// downwardAPI / projected / persistentVolumeClaim); volumes with an unmodeled
// source are skipped (the
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
	case v.PersistentVolumeClaim != nil:
		rv.PersistentVolumeClaim = toPersistentVolumeClaimVolumeSource(v.PersistentVolumeClaim)
	default:
		return nil
	}
	return rv
}

// toPersistentVolumeClaimVolumeSource maps the durable PVC source (M3.1). Only the
// claim reference crosses the wire: runtimed derives the bound directory from
// (namespace, claim_name) through the shared storage contract, so the provider must
// NOT resolve a path here.
//
// Dropping this case is not a benign omission. An unmodeled source returns nil and
// the volume is silently skipped, so a container that mounts it fails downstream
// with "volume_mount %q references undefined volume" — naming the MOUNT, never the
// missing source. That is what made every StatefulSet with a volumeClaimTemplate
// unschedulable while the PVC itself bound correctly.
func toPersistentVolumeClaimVolumeSource(src *corev1.PersistentVolumeClaimVolumeSource) *runtimev1.PersistentVolumeClaimVolumeSource {
	return &runtimev1.PersistentVolumeClaimVolumeSource{
		ClaimName: src.ClaimName,
		ReadOnly:  src.ReadOnly,
	}
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
// publishes, deriving the fields runtimed's renderer omits (it is lossy):
//   - the four Pod Conditions (Initialized/Ready/ContainersReady/PodScheduled),
//   - phase Running when any container runs and none has failed,
//   - a stable StartTime (passed in from CreatePod, not the per-snapshot value
//     runtimed regenerates),
//   - per-container Started (*bool) and Ready,
//   - terminated Reason/ExitCode/Signal carried verbatim (not the M0 "Error"
//     heuristic) — this is the path the runtimed OOMKilled reason surfaces on,
//   - the M2.1 ContainerStatus mirror (volume_mounts, user),
//   - HostIP/HostIPs from the node IP,
//   - Status.QOSClass (B12): toPodStatus is the single place QOSClass is set, so
//     all four publish paths (GetPodStatus, GetPods, the watch-stream cb, the
//     probe-driven cb) emit a consistent value instead of blanking it on every
//     full-status replace. The apiserver-set value is carried forward
//     (authoritative + immutable); computePodQOS derives it only when unset (the
//     Pending pre-status window) or when pod is nil (the pod-less path).
//
// probes, when non-nil, overlays the provider-served probe verdicts (M2.2):
// readiness drives each container's Ready (and thus the pod Ready/ContainersReady
// conditions → Service EndpointSlice membership), startup drives Started, and the
// probe-driven restart count is added — applied before the conditions are derived
// so the readiness signal propagates. A nil probes leaves the runtime status
// untouched (a pod with no probes).
func toPodStatus(pod *corev1.Pod, rs *runtimev1.PodStatus, nodeIP string, startTime metav1.Time, probes probeState) *corev1.PodStatus {
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

	// QOSClass is set here and nowhere else (B12 — see the func doc). Carry
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
		computeReadiness(pod, containersReady),
		{Type: corev1.ContainersReady, Status: crStatus},
		{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
	}
	out.Conditions = append(out.Conditions, carryForwardExternalConditions(pod)...)
	return out
}

// containersReadyFrom reports the ContainersReady predicate over the pod's MAIN
// container statuses: the AND of every container's Ready AND at least one running
// container — not a hardcoded True. The anyRunning term matches the kubelet's
// running-gate and the pre-B79 behavior: a non-running container carrying a stale
// Ready=true must not publish ContainersReady=True. (M0/HostProcess has no
// readiness probes: a container is Ready when Running; applyProbeOverlay refines
// it when a readiness probe is served — the probe-less reduction.) It gates
// PodReady via the shared computeReadiness seam, which honors spec.readinessGates.
//
// It is a shared seam, not a toPodStatus local: a status overlay applied after
// the conditions are derived (the B39 postStart readiness gate) must re-derive
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
func refreshReadinessConditions(pod *corev1.Pod, st *corev1.PodStatus) {
	ready := containersReadyFrom(st.ContainerStatuses)
	crStatus := corev1.ConditionFalse
	if ready {
		crStatus = corev1.ConditionTrue
	}
	for i := range st.Conditions {
		switch st.Conditions[i].Type {
		case corev1.PodReady:
			st.Conditions[i] = computeReadiness(pod, ready)
		case corev1.ContainersReady:
			st.Conditions[i].Status = crStatus
		}
	}
}

// computeReadiness derives the PodReady condition, honoring spec.readinessGates. It
// is the single pure authority every status-build path (toPodStatus, and
// CreatePod/reap via hostprocess.go) routes through, so PodReady never diverges
// between the live runtimed path and the M0 host-process path.
//
// The rule (mirrors the kubelet's GeneratePodReadyCondition):
//   - containersReady is the precondition: when the containers are not ready the
//     gates are short-circuited and PodReady is False/"ContainersNotReady" (the
//     kubelet short-circuits gates behind ContainersReady).
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
func computeReadiness(pod *corev1.Pod, containersReady bool) corev1.PodCondition {
	cond := corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionTrue}
	switch {
	case !containersReady:
		cond.Status = corev1.ConditionFalse
		cond.Reason = "ContainersNotReady"
		cond.Message = "containers are not ready"
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
// provider, with no-clobber + a kine watch-staleness review — deferred B79),
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
// statuses (M2.2): for a RUNNING container, a readiness/startup probe overrides
// Ready (so a failing readiness probe removes the pod from its Service
// EndpointSlice) and a startup probe overrides Started. Non-running containers
// keep the runtime's verdict (the prober only governs a live container).
//
// RestartCount is NOT touched (M10.2/B26 single-count-authority): runtimed bumps
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
// phase, honoring the pod's effective restart policy (B26).
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
//   - any running main ⇒ Running — upstream never reports a terminal phase while
//     a container runs, whatever a sibling did;
//   - a main that will be restarted (its termination resolves restartable, or it
//     already carries the synthesized CrashLoopBackOff waiting state) ⇒ Running;
//   - otherwise the runtime's own terminal verdict stands (mains-only, per the
//     B74 Job contract).
//
// pod may be nil (the pod-less status path): with no spec there is no policy to
// honor, so the runtime's verdict is taken as authoritative and the legacy
// any-failed derivation applies. Production callers always pass the pod.
func derivePhase(pod *corev1.Pod, rp runtimev1.PodPhase, cs []corev1.ContainerStatus) corev1.PodPhase {
	if rp == runtimev1.PodPhase_POD_PHASE_PENDING {
		return corev1.PodPending
	}
	anyRunning, anyFailed, restartable := false, false, false
	policy := effectivePodRestartPolicy(pod)
	for i := range cs {
		st := &cs[i]
		if st.State.Running != nil {
			anyRunning = true
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
// statuses (B26 conformance fix), rather than the unconditional ConditionTrue the
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
// surfaces) and deriving Ready/Started, plus the M2.1 mirror fields (volume_mounts
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
			// The identity pair (B132): image_id is the image's config digest,
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
			ContainerID: qualifyContainerID(t.GetContainerId()),
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
