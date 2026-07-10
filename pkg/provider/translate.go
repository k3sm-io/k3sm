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
	"sort"
	"strconv"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
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

// defaultGraceSeconds is the Kubernetes default SIGTERM→SIGKILL window applied
// when a pod sets no terminationGracePeriodSeconds. proto3 int64 cannot represent
// "unset", so the provider applies the 30s default itself — runtimed treats a 0
// grace as immediate-kill, which is NOT the k8s default.
const defaultGraceSeconds int64 = 30

// toPodBox translates a corev1.Pod into the runtime PodBox runtimed consumes. It
// FILLS sandbox_profile and signature_policy so runtimed's fail-closed gate
// passes: a nil profile or an UNSPECIFIED signature policy makes CreatePod refuse
// the pod. (The sandbox BACKEND may be UNSPECIFIED — that is the host-process
// default; see podSandboxBackend.)
//
// It returns an error — failing closed — when the pod names a RuntimeClass with no
// backend mapping (runtimev1.ErrUnknownHandler), so a pod that asked for an
// isolation class k3sm cannot satisfy is refused rather than silently downgraded.
//
// rootfsRoot is the per-pod-dir parent; dyldShim, when non-empty, is wired into
// the annotation runtimed copies to DYLD_INSERT_LIBRARIES (the DNS shim).
//
// Container env is carried STRUCTURALLY here (literal value, valueFrom, envFrom);
// resolvePodBoxEnv flattens it into literal values before the box is sent to
// runtimed, which reads only EnvVar.value (it never talks to the apiserver).
//
// dnsCfg is the pod's cluster DNS configuration; when the pod uses a cluster-first
// DNSPolicy, toPodBox injects the K3SM_DNS_* env the DYLD getaddrinfo shim reads
// (via dns.ConfigToEnv) into every container so in-pod cluster Service names
// resolve against the cluster DNS VIP — see injectClusterDNSEnv (B18). The
// injection is the keystone for in-pod cluster DNS: the shim annotation alone only
// loads the shim, which then defers every lookup to the host resolver until these
// env are present.
//
// B20a augments the ClusterFirst path: a cluster-first pod's spec.dnsConfig is
// additively merged into the cluster base (extra search domains appended+deduped,
// ndots override) by buildBox before this injection — the merge is gated on the
// cluster-DNS policy there, so a None/Default pod keeps the UNMERGED base. Still
// DEFERRED to B20b (the apis wave): dnsPolicy: None (a pod's own spec.dnsConfig
// nameservers — a None pod falls back to the host resolver, not its declared
// nameservers), an explicit ndots: 0 (the int32 path cannot tell it from unset),
// spec.dnsConfig.nameservers under ClusterFirst (the single-server shim ABI), and
// non-ndots options.
func toPodBox(pod *corev1.Pod, podIP, rootfsRoot, dyldShim string, dnsCfg netv1.DNSConfig) (*runtimev1.PodBox, error) {
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
	// The provider is the trusted producer of the resource-limit inputs. Set the
	// TYPED apis:M2.2 PodBox fields: memory_limit_bytes (the OOM ceiling runtimed
	// compares ri_phys_footprint against) and qos_class (runtimed's best-effort CPU
	// policy). The k3sm.io/memory-limit-bytes annotation is also written AFTER the
	// user annotations as a transitional fallback (runtimed bridges it when the
	// typed field is unset); the typed field is authoritative.
	if lim := podMemoryLimitBytes(pod); lim > 0 {
		box.MemoryLimitBytes = lim
		box.Annotations[memoryLimitAnnotation] = strconv.FormatInt(lim, 10)
	}
	box.QosClass = podQOSClass(pod)

	box.InitContainers = toRuntimeContainers(pod.Spec.InitContainers, true)
	box.Containers = toRuntimeContainers(pod.Spec.Containers, false)

	// Inject the cluster DNS env the DYLD getaddrinfo shim reads, gated on the pod's
	// DNSPolicy. Appended AFTER the user env (infra-wins) and to BOTH the init and
	// regular containers — see injectClusterDNSEnv. This is the B18 DNS keystone: the
	// shim annotation only loads the shim; without these env in-pod cluster Service
	// names do not resolve (the shim defers to the host resolver).
	injectClusterDNSEnv(box, pod.Spec.DNSPolicy, dnsCfg)

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

	// Resolve the pod's RuntimeClass to its isolation backend (M5.1). A pod with no
	// runtimeClassName resolves to SANDBOX_BACKEND_UNSPECIFIED — NOT a hardcoded
	// Seatbelt rung — so runtimed's SelectBackend(UNSPECIFIED,…) walks the
	// host-OS-version-gated Seatbelt ladder and picks the correct rung for the host
	// (SEATBELT_INPROC where libsandbox is present); runtimeClassName: vm resolves to
	// SANDBOX_BACKEND_VM (the Virtualization.framework micro-VM); an unknown handler
	// FAILS CLOSED here rather than downgrading a pod that requested stronger
	// isolation onto the host-process path.
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
	// For a vm pod, size the guest from the pod's cpu/memory (the VZ vCPU count +
	// RAM; 0 leaves the runtimed/VZ default). The Seatbelt rungs ignore these.
	if backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		box.SandboxProfile.VmVcpus = podVMVCPUs(pod)
		box.SandboxProfile.VmMemoryBytes = podVMMemoryBytes(pod)
	}
	return box, nil
}

// injectClusterDNSEnv appends the K3SM_DNS_* environment the DYLD getaddrinfo shim
// reads (serialized by the single pinned dns.ConfigToEnv encoder — NEVER hand-rolled
// here, a wrong separator would silently break ALL in-pod cluster DNS) to every
// container so a pod's unqualified Service lookups expand against the cluster DNS VIP.
//
// It is DNSPolicy-gated to the cluster-first policies (clusterDNSPolicy): Default and
// None inject NOTHING. A Default pod opted out of cluster DNS, and injecting no env
// makes the shim fall back to the host resolver — exactly Default semantics; None
// (custom spec.dnsConfig nameservers) is deferred to B20b and likewise falls back
// to the host for now rather than its declared nameservers.
//
// Scope parity: the env is appended to BOTH InitContainers and Containers, matching
// the box-wide DYLD shim annotation — an init container that resolves a Service needs
// cluster DNS too.
//
// Precedence (infra-wins): the env is appended AFTER each container's user env, so
// resolveContainerEnv's later-wins upsert makes the cluster value authoritative — a
// workload that set its own K3SM_DNS_SERVER cannot override cluster DNS (ClusterFirst
// means cluster DNS). The keys are sorted for deterministic output.
//
// When dnsCfg is not usable (no cluster DNS VIP / invalid), dns.ConfigToEnv returns
// nil and nothing is injected — the shim then defers to the host resolver.
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
// CLAMPED to [0, dns.MaxNDots] (the resolv.conf RES_MAXNDOTS ceiling) BEFORE the int32
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
		// The first "ndots" option decides: a non-negative integer overrides the
		// cluster ndots; a nil/unparseable/negative value keeps base (0). An explicit
		// `ndots: 0` is indistinguishable from unset in this int32 path — deferred to B20b.
		if v := c.Options[i].Value; v != nil {
			if n, err := strconv.Atoi(*v); err == nil && n >= 0 {
				// Clamp to the shared resolv.conf ndots ceiling (dns.MaxNDots ==
				// RES_MAXNDOTS) BEFORE the int32 narrowing: an absurd value (>=2^31)
				// would otherwise wrap negative and be silently dropped by
				// MergeDNSConfig as keep-base, masking the misconfig. Clamping the int
				// first fails predictably (→ dns.MaxNDots). dns.MaxNDots is untyped so it
				// compares against int n with no cast. strconv.Atoi already returns
				// ErrRange for values beyond int64, so those keep base.
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

// podQOSClass computes the pod's Quality-of-Service class and maps it to the apis
// runtime QOSClass enum runtimed uses for best-effort CPU scheduling policy (k3sm
// has no CFS millicore enforcement). The
// VK provider REPLACES the kubelet, which is where Status.QOSClass is normally
// derived, so the provider computes it from the spec here rather than trusting a
// possibly-unset status field.
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
// This is a HAND REPRODUCTION of a server-side computation and MUST track upstream
// k8s.io/component-helpers/scheduling/corev1/v1qos.GetPodQOS — k3sm replaces the
// kubelet, so when the apiserver has not yet stamped Status.QOSClass this is the
// only source of the class. It is the FALLBACK only: toPodStatus carries forward
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
// init selects the M10.2 restart_policy mapping: on an INIT container,
// restartPolicy: Always (KEP-753) maps to
// CONTAINER_RESTART_POLICY_ALWAYS — the proto marker runtimed reads to run it
// as a NATIVE SIDECAR (spawned-not-waited, tracked long-lived, torn down in
// reverse after the mains). Regular containers always carry UNSPECIFIED:
// per-container policy on regular containers is out of scope, and the proto
// field is meaningful only on init containers today (see
// apis runtime.proto Container.restart_policy — the contract).
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
		}
		if init && c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			rc.RestartPolicy = runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
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
//   - HostIP/HostIPs from the node IP,
//   - Status.QOSClass (B12): toPodStatus is the SINGLE place QOSClass is set, so
//     all four publish paths (GetPodStatus, GetPods, the watch-stream cb, the
//     probe-driven cb) emit a consistent value instead of blanking it on every
//     full-status replace. The apiserver-set value is carried forward
//     (authoritative + immutable); computePodQOS derives it only when unset (the
//     Pending pre-status window) or when pod is nil (the pod-less path).
//
// probes, when non-nil, overlays the provider-served probe verdicts (M2.2):
// readiness drives each container's Ready (and thus the pod Ready/ContainersReady
// conditions → Service EndpointSlice membership), startup drives Started, and the
// probe-driven restart count is added — applied BEFORE the conditions are derived
// so the readiness signal propagates. A nil probes leaves the runtime status
// untouched (a pod with no probes).
func toPodStatus(pod *corev1.Pod, rs *runtimev1.PodStatus, nodeIP string, startTime metav1.Time, probes probeState) *corev1.PodStatus {
	cs := toContainerStatuses(rs.GetContainerStatuses())
	initCS := toContainerStatuses(rs.GetInitContainerStatuses())
	applyProbeOverlay(cs, probes)

	anyRunning, anyFailed, allReady := false, false, len(cs) > 0
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
	// containersReady is the AND of every container's Ready AND at least one running
	// container — NOT a hardcoded True. The anyRunning term matches the kubelet's
	// running-gate and the pre-B79 behavior: a non-running container carrying a stale
	// Ready=true must not publish ContainersReady=True. (M0/HostProcess has no
	// readiness probes: a container is Ready when Running; applyProbeOverlay refines
	// it when a readiness probe is served — the probe-less reduction.) It gates
	// PodReady via the shared computeReadiness seam, which honors spec.readinessGates.
	containersReady := allReady && anyRunning

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

	// QOSClass is set HERE and nowhere else (B12): every publish path does a full
	// pod.Status = *toPodStatus(...) replace, so deriving it elsewhere would let the
	// field flap blank vs real across reconcile-vs-probe ticks. Carry forward the
	// apiserver's authoritative value (immutable, and immune to any drift between
	// computePodQOS and upstream GetPodQOS); fall back to the hand-rolled derivation
	// only when the apiserver has not stamped it yet, or when no pod is in scope.
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
	// spec.readinessGates are honored — then carry FORWARD any external condition on
	// the input pod (e.g. a readinessGate condition a controller patched) so it
	// survives this status write and stays observable to computeReadiness.
	out.Conditions = []corev1.PodCondition{
		{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
		computeReadiness(pod, containersReady),
		{Type: corev1.ContainersReady, Status: crStatus},
		{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
	}
	out.Conditions = append(out.Conditions, carryForwardExternalConditions(pod)...)
	return out
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
//     is PRESENT on the pod is True): a gate present-and-True is satisfied; a gate
//     present-and-not-True (False/Unknown) blocks with "ReadinessGatesNotReady"
//     naming the gate.
//
// CEILING — the absent-gate anti-stall safety rule (do NOT change without reading
// this): a readinessGate whose condition is ABSENT from pod.Status.Conditions does
// NOT block PodReady — it is treated as not-yet-observable, as-if-satisfied. This is
// deliberate and load-bearing. The k3sm VK provider CANNOT observe an
// externally-patched gate condition today (VK's podsEqual ignores status, UpdatePod
// is a no-op, and VK blind-overwrites pod status), so if an ABSENT gate blocked
// PodReady, every pod carrying an external readinessGate would stall NotReady FOREVER
// — strictly worse than advancing a rolling update too early. k3sm therefore honors
// OBSERVABLE gates only; the informer feedback loop that would let the provider react
// to external gate patches is a DEFERRED follow-up, not shipped here.
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

// carryForwardExternalConditions returns the pod's existing conditions MINUS the
// four provider-owned types, so external/readinessGate conditions survive a provider
// status rebuild (merge-not-replace, mirroring the QOSClass carry-forward in
// toPodStatus). A nil pod yields nil.
//
// DEFERRED: this carry-forward is a safe no-op in PRODUCTION today — the k3sm VK
// provider cannot yet OBSERVE an externally-patched gate condition (VK's podsEqual
// ignores status, UpdatePod is a no-op, and VK blind-overwrites pod status), so the
// input pod carries no external condition to preserve. It is wired now so that when
// the external-gate feedback loop lands (an informer feeding external gate patches
// back to the provider, with no-clobber + a kine watch-staleness review — the
// deferred B79 follow-up), present gates are already observable to computeReadiness.
// Do NOT mistake this for an already-live external-gate path.
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
