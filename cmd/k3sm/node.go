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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"

	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/policy"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// The pod runtime selector values (`--runtime`).
const (
	// runtimeHostProcess is the M0 native-process runtime: rootless dev, no
	// image pull, no Seatbelt isolation, podIP ≈ nodeIP (its documented shape).
	runtimeHostProcess = "hostprocess"
	// runtimeRuntimed is the image runtime (OCI pull → clonefile → ad-hoc-sign →
	// Seatbelt confine) with per-pod /32 pod IPs via the podnet adapter.
	runtimeRuntimed = "runtimed"
)

// defaultRuntime is the pod runtime every k3sm command selects when --runtime
// is not given: runtimed — THE M10.1 default-runtime flip (the HostProcess
// os/exec path is rejected for per-pod IP: no bind discipline, two same-node
// pods collide on shared lo0). It requires the runtimed posture (root, or the
// one-time `sudo k3sm install` netd helper); a posture miss REFUSES to start
// (runtimePreflight) — never a silent degrade. `--runtime hostprocess` is the
// explicit rootless-dev opt-out.
const defaultRuntime = runtimeRuntimed

// addRuntimeFlag registers the shared --runtime flag: the ONE place the default
// pod runtime is declared, used by `k3sm node`, `k3sm agent`, and `k3sm server`.
func addRuntimeFlag(fs *flag.FlagSet, p *string) {
	fs.StringVar(p, "runtime", defaultRuntime,
		"pod runtime: runtimed (image runtime; the default — needs root or the one-time 'sudo k3sm install' netd helper) or hostprocess (explicit rootless-dev opt-out: native processes, podIP≈nodeIP)")
}

// resolveRuntime maps an empty --runtime to the shared default.
func resolveRuntime(name string) string {
	if name == "" {
		return defaultRuntime
	}
	return name
}

// compile-time check that the VK adapter satisfies the full VK provider contract.
var _ vkadapter.Provider = (*provider.VKProvider)(nil)

// nodeOptions configures a Virtual Kubelet node bring-up. It is shared by the
// standalone `k3sm node` command and the in-process node `k3sm server` runs.
type nodeOptions struct {
	kubeconfig string
	nodeName   string
	listen     string
	podRoot    string
	nodeIP     string
	runtime    string // "runtimed" (default) or "hostprocess" — see defaultRuntime
	dnsShim    string // getaddrinfo DNS shim dylib path (runtimed only)
	dnsVIP     string // cluster DNS VIP the per-pod Seatbelt egress is scoped to (runtimed)
	domain     string // cluster DNS domain the in-pod shim search list is built from (runtimed)
	serveTLS   bool   // serve the kubelet HTTP API over TLS (M1.2: logs/exec over the proxy)

	// podCIDR is this node's pod /24 the runtimed podnet adapter allocates /32s
	// from — the SAME CIDR the mesh AllowedIPs carry: an enrolled worker's
	// assigned res.PodCIDR, the reserved index-0 /24 on the control-plane/
	// single node (defaultNodePodCIDR). Never a second IPAM source.
	podCIDR string
	// netMode is the resolved host-network backend the podnet adapter's lo0
	// alias plumbing and the runtimed preflight follow (helper vs direct vs
	// none). The zero value is BackendNone (no datapath — no adapter, podIP ≈
	// nodeIP); the commands always set it from their resolved --network mode.
	netMode hostnet.Mode
}

// runNode registers this Mac as a Virtual Kubelet node and runs pods via the
// selected runtime (M0 walking skeleton + M1 runtimed image runtime).
func runNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	opts := nodeOptions{}
	fs.StringVar(&opts.kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "path to a kubeconfig for the cluster")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.listen, "listen", "127.0.0.1:10250", "address for the kubelet HTTP API (logs/exec)")
	fs.StringVar(&opts.podRoot, "pod-root", filepath.Join(os.TempDir(), "k3sm-pods"), "directory for per-pod logs/state")
	fs.StringVar(&opts.nodeIP, "node-ip", "127.0.0.1", "node/pod IP to advertise")
	addRuntimeFlag(fs, &opts.runtime)
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.StringVar(&opts.dnsVIP, "dns-vip", dns.DefaultDNSVIP, "cluster DNS VIP the per-pod Seatbelt egress is scoped to (runtimed runtime only)")
	fs.StringVar(&opts.domain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain the in-pod getaddrinfo shim search list is built from (runtimed runtime only)")
	fs.BoolVar(&opts.serveTLS, "serve-tls", false, "serve the kubelet HTTP API over TLS so kubectl logs/exec work via the apiserver proxy")
	_ = fs.Parse(args)

	if opts.kubeconfig == "" {
		return fmt.Errorf("--kubeconfig (or $KUBECONFIG) is required")
	}

	// The standalone node has no --network flag: resolve the auto posture (root
	// → direct lo0 ops, unprivileged → the netd helper). Whether that posture is
	// actually usable is checked by the runtimed preflight in startNode — an
	// unprivileged dev box without the helper is told to `sudo k3sm install` or
	// pass --runtime hostprocess.
	mode, err := hostnet.Resolve(hostnet.NetworkAuto)
	if err != nil {
		return err
	}
	opts.netMode = mode
	// Single/standalone node: the reserved index-0 /24 (the same value the mesh
	// enroller reserves for the control-plane node).
	opts.podCIDR = defaultNodePodCIDR()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return startNode(ctx, opts)
}

// defaultNodePodCIDR is the control-plane/single-node pod /24: node index 0 of
// the cluster pod CIDR (100.64.0.0/24) — the SAME derivation the mesh enroller
// uses (enroll.go reserves index 0 for the control-plane node; workers get
// index 1+) and the same value netserve's routing-table locality defaults to.
// An enrolled worker overrides it with its assigned res.PodCIDR; there is
// deliberately no second IPAM source.
func defaultNodePodCIDR() string {
	cidr, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 0)
	if err != nil {
		// Unreachable with the pinned package constants; returning "" makes the
		// adapter construction fail fast rather than inventing a literal here.
		return ""
	}
	return cidr.String()
}

// errRuntimedPosture is the NAMED refuse-to-start error of the M10.1
// default-runtime flip: the runtimed runtime's pod network needs root or the
// netd helper, and neither is present. k3sm never silently degrades to
// hostprocess — the operator either installs the posture or opts out.
var errRuntimedPosture = errors.New("runtimed runtime posture missing")

// probeNetdHelper is the runtimed-preflight probe seam (the same reachability
// probe `--network auto` uses: a bounded dial of the netd helper socket when
// the helper backend is selected; a no-op for direct/root). A package var so
// the preflight is unit-tested with a fake.
var probeNetdHelper = func(ctx context.Context, mode hostnet.Mode) error { return mode.Probe(ctx) }

// runtimePreflight fail-fasts BEFORE the node registers when the selected
// runtime is runtimed but the posture its pod network needs is absent — an
// unprivileged process with no reachable netd helper. It NEVER auto-degrades:
// the named error tells the operator to run `sudo k3sm install` or pass
// `--runtime hostprocess` (the explicit rootless-dev opt-out). hostprocess
// bypasses it entirely; `--network none` (an explicit control-plane-only/CI
// backend) needs no helper — the runtimed runtime then runs without a per-pod
// datapath (podIP ≈ nodeIP).
func runtimePreflight(ctx context.Context, opts nodeOptions) error {
	if resolveRuntime(opts.runtime) != runtimeRuntimed {
		return nil
	}
	if !opts.netMode.DataPath() {
		return nil
	}
	if err := probeNetdHelper(ctx, opts.netMode); err != nil {
		return fmt.Errorf("%w: %v — run 'sudo k3sm install' (the one-time privileged step that lays down the io.k3sm.netd helper), or pass --runtime hostprocess for an explicit rootless dev node", errRuntimedPosture, err)
	}
	return nil
}

// startNode builds the client, selects the runtime, registers the VK node, and
// blocks until ctx ends or the node exits. The server calls it directly with an
// already-built kubeconfig.
func startNode(ctx context.Context, opts nodeOptions) error {
	// M10.1 flip guard: refuse to start (named error, actionable message) when
	// the default runtimed runtime's posture is missing — BEFORE anything
	// registers against the cluster. Never a silent hostprocess fallback.
	if err := runtimePreflight(ctx, opts); err != nil {
		return err
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	// Event sink for node-emitted pod lifecycle Events (Pulled/Created/Started/
	// Killing) so `kubectl describe pod` shows them. The broadcaster starts a
	// goroutine that drains to the apiserver Events API; defer its Shutdown to node
	// teardown so it does not leak.
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: cs.CoreV1().Events("")})
	defer eventBroadcaster.Shutdown()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "k3sm", Host: opts.nodeName})

	prov, runtimeLabel, err := buildProvider(opts, cs, recorder)
	if err != nil {
		return err
	}

	var servingTLS *tls.Config
	if opts.serveTLS {
		servingTLS, err = kubeletServingTLS(opts.nodeName, opts.nodeIP)
		if err != nil {
			return fmt.Errorf("kubelet serving tls: %w", err)
		}
	}

	// Build the VK node through the adapter: it encapsulates the kubelet HTTP API
	// wiring (logs/exec only serve when BOTH a TLS config and a handler are set, so
	// the apiserver→node proxy reaches /containerLogs — M1.2) and the
	// nil-NodeProvider → NaiveNodeProvider (auto-Ready + lease heartbeat) path.
	n, err := vkadapter.NewNode(opts.nodeName, vkadapter.NodeConfig{
		Client:         cs,
		Provider:       prov,
		HTTPListenAddr: opts.listen,
		NumWorkers:     4,
		TLSConfig:      servingTLS, // nil = plain HTTP (M0 path); set = kubelet-serving TLS
		ConfigureNode:  func(nd *corev1.Node) { configureNode(nd, opts.nodeName, opts.nodeIP) },
	})
	if err != nil {
		return fmt.Errorf("new node: %w", err)
	}

	errc := make(chan error, 1)
	go func() { errc <- n.Run(ctx) }()

	select {
	case <-n.Ready():
		log.Printf("k3sm node %q ready (runtime=%s listen=%s pod-root=%s)", opts.nodeName, runtimeLabel, opts.listen, opts.podRoot)
	case err := <-errc:
		return fmt.Errorf("node exited during startup: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// buildProvider selects and constructs the VK provider for the requested
// runtime. runtimed is the default (defaultRuntime — the M1 image runtime: OCI
// pull → clonefile → ad-hoc-sign → Seatbelt confine, per-pod /32 pod IPs via
// the injected podnet adapter), wrapped in the VK adapter; hostprocess is the
// explicit rootless-dev opt-out (M0 native processes, no isolation, podIP ≈
// nodeIP — its documented shape, untouched by M10.1). cs is the apiserver
// client the runtimed provider resolves volumes/env/imagePullSecrets with
// (M2.1/M2.6). recorder is the EventRecorder the HostProcess provider emits pod
// lifecycle Events to (the runtimed VK-provider-path emit is a deferred
// follow-up).
func buildProvider(opts nodeOptions, cs kubernetes.Interface, recorder record.EventRecorder) (vkadapter.Provider, string, error) {
	switch resolveRuntime(opts.runtime) {
	case runtimeHostProcess:
		return provider.NewHostProcess(opts.nodeName, opts.podRoot, opts.nodeIP, recorder), runtimeHostProcess, nil
	case runtimeRuntimed:
		cfg := runtimedConfig(opts, cs)
		adapter, err := buildPodNetAdapter(opts)
		if err != nil {
			return nil, "", err
		}
		if adapter != nil {
			cfg.Network = adapter
		}
		rt, err := provider.NewRuntimed(cfg)
		if err != nil {
			return nil, "", fmt.Errorf("build runtimed provider: %w", err)
		}
		return provider.NewVKProvider(rt, opts.nodeName), runtimeRuntimed, nil
	default:
		return nil, "", fmt.Errorf("unknown --runtime %q (want %s or %s)", opts.runtime, runtimeRuntimed, runtimeHostProcess)
	}
}

// buildPodNetAdapter constructs the node's ONE podnet.Network (darwin-net stays
// the sole node-/24 allocator) and wraps it in the provider adapter that
// bridges it into runtimed's PodNetwork + startup-reconcile seams (M10.1). The
// lo0 alias plumbing follows the resolved host-network backend: the netd helper
// when unprivileged, the direct root-gated manager otherwise. It returns nil
// (no adapter — runtimed keeps podIP ≈ nodeIP) only for the EXPLICIT
// no-datapath backend (`--network none`, control-plane-only/CI); a missing
// podCIDR with a datapath is a fail-fast error, never a fallback.
func buildPodNetAdapter(opts nodeOptions) (*provider.PodNetAdapter, error) {
	if !opts.netMode.DataPath() {
		return nil, nil
	}
	if opts.podCIDR == "" {
		return nil, fmt.Errorf("runtimed pod network needs the node podCIDR (the enrolled /24) and none was configured")
	}
	prefix, err := netip.ParsePrefix(opts.podCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse node podCIDR %q: %w", opts.podCIDR, err)
	}
	var popts []podnet.Option
	if opts.netMode.UsesHelper() {
		popts = append(popts, podnet.WithNetdHelper(opts.netMode.Socket))
	}
	nw, err := podnet.New(prefix, popts...)
	if err != nil {
		return nil, fmt.Errorf("build pod network for %s: %w", opts.podCIDR, err)
	}
	return provider.NewPodNetAdapter(nw, opts.nodeIP, slog.Default()), nil
}

// runtimedConfig builds the runtimed runtime configuration from the node options:
// the on-disk root, the DNS shim, the apiserver client, the helper-socket deny,
// and the per-pod Seatbelt egress VIPs. ResolverVIP is the cluster DNS VIP (the
// --dns-vip flag, defaulting to the cluster DNS VIP — never runtimed's legacy
// 10.96.0.10) and APIServerVIP is the kubernetes Service ClusterIP derived from
// the cluster service CIDR; runtimed threads both into its per-pod sandbox.Posture
// so a confined pod's DNS + in-pod client-go reach the node-local resolver / API
// VIP (M3.3). ClusterDomain (the --cluster-domain flag) is the in-pod shim search
// suffix the provider injects as K3SM_DNS_* env so cluster Service names resolve
// (B18); it MUST match the resolver's served zone. It is pure (no I/O) so the VIP +
// domain wiring is unit-tested directly.
func runtimedConfig(opts nodeOptions, cs kubernetes.Interface) provider.RuntimedConfig {
	resolverVIP := opts.dnsVIP
	if resolverVIP == "" {
		resolverVIP = dns.DefaultDNSVIP
	}
	// Cluster DNS domain the in-pod shim search list is built from. PREFER the
	// threaded --cluster-domain (the SAME value the per-node resolver's CoreDNS
	// serves) so a custom domain's unqualified Service lookups are not NXDOMAIN;
	// fall back to the canonical default only when unset.
	clusterDomain := opts.domain
	if clusterDomain == "" {
		clusterDomain = dns.DefaultClusterDomain
	}
	return provider.RuntimedConfig{
		NodeName:      opts.nodeName,
		NodeIP:        opts.nodeIP,
		Root:          opts.podRoot,
		DyldShim:      opts.dnsShim,
		ResolverVIP:   resolverVIP,
		ClusterDomain: clusterDomain,
		APIServerVIP:  apiServerVIP(),
		Client:        cs,
		// Fence every pod off the root helper socket at the sandbox: pods share the
		// _k3sm uid with the legitimate helper client, so the SBPL must deny
		// connect() to the privileged daemon. Denied regardless of run-as-root vs
		// helper mode (a pod must never drive netd).
		DeniedUnixSocketPaths: []string{netd.DefaultSocketPath},
	}
}

// apiServerVIP returns the in-cluster kubernetes Service ClusterIP — the FIRST
// host of the cluster service CIDR (10.43.0.1 for 10.43.0.0/16), which the
// apiserver assigns to the default/kubernetes Service (it serves
// --service-cluster-ip-range over that CIDR). A confined pod's in-cluster
// client-go dials it, so the per-pod Seatbelt egress must allow it. Derived from
// the single service-CIDR const, falling back to the documented VIP if it ever
// fails to parse.
func apiServerVIP() string {
	if p, err := netip.ParsePrefix(install.DefaultServiceCIDR); err == nil {
		return p.Masked().Addr().Next().String()
	}
	return "10.43.0.1"
}

// defaultMemBytes is the memory capacity advertised when the host memory read
// fails or returns an implausible value. It preserves the prior hardcoded 8 GiB
// so the node still registers on a sysctl hiccup: a failed HOST-FACT read falls
// back, it does not fail the node (a logged fallback, not a missing-config abort).
const defaultMemBytes uint64 = 8 * 1024 * 1024 * 1024

// hostMemBytes reports the host's total physical RAM in bytes from the hw.memsize
// sysctl (a uint64 — the full physical memory size, NOT the 32-bit-truncated
// hw.physmem nor the carveout-subtracted hw.memsize_usable). It is a package var
// so tests inject a fake host value without hitting a real syscall, keeping
// nodeCapacity hermetic; production reads the live sysctl via golang.org/x/sys/unix.
var hostMemBytes = func() (uint64, error) { return unix.SysctlUint64("hw.memsize") }

// nodeCapacity builds the node Capacity ResourceList from real host facts: numCPU
// logical CPUs, memBytes total physical RAM (hw.memsize), and maxPods. It is pure
// and side-effect-free (no syscall) so it is unit-tested directly. Memory uses
// BinarySI so it renders as e.g. "64Gi". The caller validates memBytes (rejecting
// an implausible 0 or > math.MaxInt64 read, which would convert to a negative
// quantity) and supplies the documented fallback before calling.
func nodeCapacity(numCPU int, memBytes uint64, maxPods int64) corev1.ResourceList {
	return corev1.ResourceList{
		corev1.ResourceCPU:    *resource.NewQuantity(int64(numCPU), resource.DecimalSI),
		corev1.ResourceMemory: *resource.NewQuantity(int64(memBytes), resource.BinarySI),
		corev1.ResourcePods:   *resource.NewQuantity(maxPods, resource.DecimalSI),
	}
}

// defaultMemReserveBytes is the FLOOR of the node memory hold-back: 2Gi of
// system-reserved headroom for the CO-LOCATED control plane. apiserver, scheduler,
// KCM, kine/SQLite, runtimed, and the node-agent all run in the single io.k3sm.server
// launchd job, with a combined real working set of roughly 1.2-2.3Gi — so 2Gi is a
// conservative, lab-refinable floor (the M5 lab measures the true RSS). It DOMINATES
// the 10% term on small/8Gi hosts (10% of 8Gi = 800Mi < 2Gi); the 10% term scales the
// apiserver watch-cache up on larger Macs. See memReserveBytes.
const defaultMemReserveBytes int64 = 2 * 1024 * 1024 * 1024

// minAllocatableMemBytes is the positive floor nodeAllocatable clamps post-reserve
// memory to. On a pathologically tiny host a reserve >= capacity would otherwise
// advertise a zero/negative Allocatable, stranding every pod Pending forever; clamping
// to 512Mi keeps the node schedulable. The carve-out is a best-effort SCHEDULING
// hold-back, not a hard guarantee, so flooring (rather than refusing to register) is
// the correct degradation.
const minAllocatableMemBytes int64 = 512 * 1024 * 1024

// memReserveBytes sizes the node memory system-reserved hold-back as
// max(defaultMemReserveBytes, 10% of capacity): a 2Gi floor that dominates on small/
// 8Gi hosts, scaling to 10% of capacity on larger Macs (where the apiserver watch-cache
// grows). The reserve is what nodeAllocatable holds back from Allocatable so the
// scheduler cannot commit 100% of RAM to pod requests and starve the co-located control
// plane. It is pure (no I/O) so it is unit-tested directly.
func memReserveBytes(capacityMemBytes int64) int64 {
	return max(defaultMemReserveBytes, capacityMemBytes/10)
}

// nodeAllocatable derives the node Allocatable ResourceList from capacity by holding
// back memReserveBytes of MEMORY for the co-located control plane; cpu and pods pass
// through unchanged (the reserve is memory-only — CPU is best-effort QoS on darwin, not
// CFS millicores). It DeepCopies capacity first and is NOT an alias: corev1.ResourceList
// is a Go map (a reference), so out := capacity would share the backing map and the
// out[memory] write below — like any resource.Quantity mutation — would shrink the
// caller's n.Status.Capacity too. Post-reserve memory is clamped to minAllocatableMemBytes
// so a reserve >= capacity on a tiny host never advertises a zero/negative Allocatable
// (which would strand every pod Pending). It is pure and side-effect-free (the input
// capacity is left unmodified) so it is unit-tested directly.
func nodeAllocatable(capacity corev1.ResourceList, memReserveBytes int64) corev1.ResourceList {
	out := capacity.DeepCopy()
	allocMem := capacity.Memory().Value() - memReserveBytes
	if allocMem < minAllocatableMemBytes {
		allocMem = minAllocatableMemBytes
	}
	out[corev1.ResourceMemory] = *resource.NewQuantity(allocMem, resource.BinarySI)
	return out
}

// configureNode stamps the registering Node object with darwin identity,
// capacity (real host CPU count and hw.memsize memory, with a documented
// fallback), and the provider taint (the load-bearing placement guard) so stray
// non-darwin pods cannot land here.
func configureNode(n *corev1.Node, name, ip string) {
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	n.Labels["kubernetes.io/os"] = "darwin"
	n.Labels["kubernetes.io/arch"] = "arm64"
	n.Labels["kubernetes.io/hostname"] = name
	n.Labels["k3sm.io/native"] = "true"
	n.Labels["type"] = "k3sm"

	// Well-known topology labels, GA keys only (the v1.36.2 scheduler reads these; the
	// deprecated failure-domain.beta.kubernetes.io aliases are cruft). zone is set to THIS
	// node's name — == kubernetes.io/hostname by construction (same `name`): a DELIBERATE
	// per-node failure domain, since each Mac is a genuine independent one. A zone
	// topologySpread with whenUnsatisfiable: DoNotSchedule thus degrades to host-spread
	// (fail-open) instead of stranding pods Pending on a missing label, and never FALSELY
	// claims co-located Macs share a failure domain (which a shared static zone would).
	// region is one static value all nodes agree on — k3sm has no cloud-region concept.
	n.Labels[corev1.LabelTopologyZone] = name
	n.Labels[corev1.LabelTopologyRegion] = defaultNodeRegion

	// vm RuntimeClass node-capability gate (M5.1): advertise the
	// Virtualization.framework backend via the k3sm.io/virtualization label ONLY when
	// this node can run it, so the vm RuntimeClass nodeSelector pins vm pods to a
	// capable node. nodeVMCapable is false today (k3sm has no per-backend availability
	// signal — see its doc), so the label is absent and a vm pod stays Unschedulable —
	// the fail-closed posture for a non-VZ cluster.
	applyVirtualizationLabel(n, nodeVMCapable())

	n.Status.NodeInfo.OperatingSystem = "darwin"
	n.Status.NodeInfo.Architecture = "arm64"
	n.Status.NodeInfo.KubeletVersion = "k3sm-m1"

	// Advertise REAL host memory (hw.memsize) as node capacity. A failed read, or
	// an implausible value (0, or one above math.MaxInt64 that would convert to a
	// negative quantity), is a host-fact hiccup — not a misconfiguration: log it
	// and fall back to the documented default so the node still registers.
	memBytes, err := hostMemBytes()
	if err != nil || memBytes == 0 || memBytes > math.MaxInt64 {
		slog.Warn("host memory read failed or implausible; advertising default node memory capacity",
			"error", err, "raw_bytes", memBytes, "default_bytes", defaultMemBytes)
		memBytes = defaultMemBytes
	}
	n.Status.Capacity = nodeCapacity(runtime.NumCPU(), memBytes, 110)
	// System-reserved memory carve-out (B41): hold back max(2Gi, 10% of capacity) from
	// Allocatable for the CO-LOCATED control plane, so the scheduler cannot commit 100%
	// of RAM to pod requests and starve apiserver/scheduler/KCM/kine/runtimed/node-agent
	// (all in the one io.k3sm.server job). Capacity stays the true hw.memsize; cpu/pods
	// pass through unchanged. This is a SCHEDULING-ONLY hold-back — no kubepods cgroup
	// enforces it at runtime, so it lowers (not eliminates) the chance macOS jetsam kills
	// the largest process (the control plane); the runtime fix (a jetsam-priority band)
	// is B46. See nodeAllocatable / DESIGN §5a.
	capMem := n.Status.Capacity.Memory().Value()
	reserve := memReserveBytes(capMem)
	n.Status.Allocatable = nodeAllocatable(n.Status.Capacity, reserve)
	reserveTerm := "floor" // the 2Gi default dominated (small host)
	if reserve > defaultMemReserveBytes {
		reserveTerm = "pct" // 10% of capacity dominated (large host)
	}
	slog.Info("node memory system-reserved carve-out for the co-located control plane",
		"capacity_mem_bytes", capMem,
		"reserve_bytes", reserve,
		"allocatable_mem_bytes", n.Status.Allocatable.Memory().Value(),
		"reserve_term", reserveTerm)
	n.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: ip},
		{Type: corev1.NodeHostName, Address: name},
	}
	n.Status.DaemonEndpoints.KubeletEndpoint.Port = 10250

	// Provider taint: the load-bearing placement guard. Only pods that tolerate
	// k3sm.io/provider:NoSchedule (the darwin workloads the server provisions a
	// toleration for) schedule here, so stray Linux pods cannot land on this node.
	// The os=darwin ValidatingAdmissionPolicy is the intent guard on top of it.
	n.Spec.Taints = upsertTaint(n.Spec.Taints, corev1.Taint{
		Key:    policy.ProviderTaintKey,
		Effect: corev1.TaintEffectNoSchedule,
	})
}

// applyVirtualizationLabel sets (vmCapable) or clears (!vmCapable) the
// k3sm.io/virtualization node label the vm RuntimeClass pins its nodeSelector to.
// The label is present (value "true") only when the node can run the
// Virtualization.framework backend; otherwise it is removed, so a vm pod has no node
// to land on and stays Unschedulable — the fail-closed posture for a non-VZ cluster.
// Clearing (not merely omitting) handles a node that loses VZ capability across a
// restart.
func applyVirtualizationLabel(n *corev1.Node, vmCapable bool) {
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	if vmCapable {
		n.Labels[runtimeclass.LabelVirtualization] = runtimeclass.LabelTrue
		return
	}
	delete(n.Labels, runtimeclass.LabelVirtualization)
}

// nodeVMCapable reports whether this node can run the vm RuntimeClass backend
// (Virtualization.framework + the com.apple.security.virtualization entitlement) —
// the source of truth for the k3sm.io/virtualization node label.
//
// It returns false TODAY, by design: runtimed's GetRuntimeInfo RPC reports only the
// SELECTED host-process backend's health (one "SandboxBackend" condition), NOT
// per-backend (VZ) availability, so k3sm has no truthful signal to set the label
// from — and the foundation must not FAKE it. Defaulting the label ABSENT is
// fail-closed: no VZ node ⇒ a vm pod stays Pending/Unschedulable, complementing
// runtimed's runtime-refusal backstop (sandbox.ErrBackendUnavailable on a vm
// CreatePod). Lighting this up needs a runtimed GetRuntimeInfo per-backend
// availability extension (a reported M5.1 cross-repo need); the provider would query
// it once at node bring-up and thread the result here.
func nodeVMCapable() bool { return false }

// defaultNodeRegion is the single static topology.kubernetes.io/region every k3sm
// node advertises. k3sm has no cloud-region concept, so all nodes agree on one
// region; zone, by contrast, is per-node (== the node name — see configureNode).
const defaultNodeRegion = "k3sm"

// upsertTaint adds t to taints if a taint with the same key+effect is not
// already present.
func upsertTaint(taints []corev1.Taint, t corev1.Taint) []corev1.Taint {
	for _, existing := range taints {
		if existing.Key == t.Key && existing.Effect == t.Effect {
			return taints
		}
	}
	return append(taints, t)
}

// kubeletServingTLS builds the TLS config the VK node serves on :10250. The
// cert's SANs include the node InternalIP (so the apiserver, started with
// --kubelet-preferred-address-types=InternalIP, dials by IP and verifies), the
// node name, and loopback. ClientAuth is left at NoClientCert: M1 keeps the
// apiserver's AlwaysAllow posture, so the proxy connects without a client cert.
func kubeletServingTLS(nodeName, nodeIP string) (*tls.Config, error) {
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(nodeIP); ip != nil && !ip.Equal(net.ParseIP("127.0.0.1")) {
		ips = append(ips, ip)
	}
	cert, err := certs.SelfSignedServing([]string{nodeName, "localhost"}, ips)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}, nil
}

func defaultNodeName() string {
	h, _ := os.Hostname()
	h = strings.TrimSuffix(strings.ToLower(h), ".local")
	if h == "" {
		h = "node"
	}
	return "k3sm-" + h
}
