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
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	vknode "github.com/virtual-kubelet/virtual-kubelet/node"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/policy"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// compile-time check that the VK adapter satisfies the full VK provider contract.
var _ nodeutil.Provider = (*provider.VKProvider)(nil)

// nodeOptions configures a Virtual Kubelet node bring-up. It is shared by the
// standalone `k3sm node` command and the in-process node `k3sm server` runs.
type nodeOptions struct {
	kubeconfig string
	nodeName   string
	listen     string
	podRoot    string
	nodeIP     string
	runtime    string // "hostprocess" (default) or "runtimed"
	dnsShim    string // getaddrinfo DNS shim dylib path (runtimed only)
	dnsVIP     string // cluster DNS VIP the per-pod Seatbelt egress is scoped to (runtimed)
	domain     string // cluster DNS domain the in-pod shim search list is built from (runtimed)
	serveTLS   bool   // serve the kubelet HTTP API over TLS (M1.2: logs/exec over the proxy)
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
	fs.StringVar(&opts.runtime, "runtime", "hostprocess", "pod runtime: hostprocess (native processes) or runtimed (image runtime)")
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.StringVar(&opts.dnsVIP, "dns-vip", dns.DefaultDNSVIP, "cluster DNS VIP the per-pod Seatbelt egress is scoped to (runtimed runtime only)")
	fs.StringVar(&opts.domain, "cluster-domain", defaultClusterDomain, "cluster DNS domain the in-pod getaddrinfo shim search list is built from (runtimed runtime only)")
	fs.BoolVar(&opts.serveTLS, "serve-tls", false, "serve the kubelet HTTP API over TLS so kubectl logs/exec work via the apiserver proxy")
	_ = fs.Parse(args)

	if opts.kubeconfig == "" {
		return fmt.Errorf("--kubeconfig (or $KUBECONFIG) is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return startNode(ctx, opts)
}

// startNode builds the client, selects the runtime, registers the VK node, and
// blocks until ctx ends or the node exits. The server calls it directly with an
// already-built kubeconfig.
func startNode(ctx context.Context, opts nodeOptions) error {
	restCfg, err := clientcmd.BuildConfigFromFlags("", opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	prov, runtimeLabel, err := buildProvider(opts, cs)
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

	// The kubelet HTTP API (logs/exec) only serves when BOTH a TLS config and a
	// handler are set. Wire a mux with the provider routes attached so the
	// apiserver→node proxy reaches /containerLogs (M1.2).
	mux := http.NewServeMux()
	nodeOpts := []nodeutil.NodeOpt{
		func(c *nodeutil.NodeConfig) error {
			c.Client = cs
			c.HTTPListenAddr = opts.listen
			c.NumWorkers = 4
			c.TLSConfig = servingTLS // nil = plain HTTP (M0 path); set = kubelet-serving TLS
			if servingTLS != nil {
				c.Handler = api.InstrumentHandler(nodeutil.WithAuth(nodeutil.NoAuth(), mux))
			}
			return nil
		},
	}
	if servingTLS != nil {
		nodeOpts = append(nodeOpts, nodeutil.AttachProviderRoutes(mux))
	}

	n, err := nodeutil.NewNode(opts.nodeName,
		func(pc nodeutil.ProviderConfig) (nodeutil.Provider, vknode.NodeProvider, error) {
			configureNode(pc.Node, opts.nodeName, opts.nodeIP)
			return prov, nil, nil // nil NodeProvider -> NewNaiveNodeProvider (auto-Ready + lease heartbeat)
		},
		nodeOpts...,
	)
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
// runtime. HostProcess is the default (M0 native processes, no isolation);
// runtimed is the M1 image runtime (OCI pull → clonefile → ad-hoc-sign →
// Seatbelt confine), wrapped in the VK adapter. cs is the apiserver client the
// runtimed provider resolves volumes/env/imagePullSecrets with (M2.1/M2.6).
func buildProvider(opts nodeOptions, cs kubernetes.Interface) (nodeutil.Provider, string, error) {
	switch opts.runtime {
	case "", "hostprocess":
		return provider.NewHostProcess(opts.nodeName, opts.podRoot, opts.nodeIP), "hostprocess", nil
	case "runtimed":
		rt, err := provider.NewRuntimed(runtimedConfig(opts, cs))
		if err != nil {
			return nil, "", fmt.Errorf("build runtimed provider: %w", err)
		}
		return provider.NewVKProvider(rt, opts.nodeName), "runtimed", nil
	default:
		return nil, "", fmt.Errorf("unknown --runtime %q (want hostprocess or runtimed)", opts.runtime)
	}
}

// defaultClusterDomain is the canonical Kubernetes cluster DNS domain used when
// --cluster-domain is unset. It matches dns.PodDNSConfig's own empty-domain default
// (apis has no exported const yet — a candidate follow-up to mirror dns.DefaultDNSVIP
// / netv1.DefaultNDots) and the server/agent --cluster-domain flag default.
const defaultClusterDomain = "cluster.local"

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
		clusterDomain = defaultClusterDomain
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
	// Allocatable == Capacity today; a system-reserved carve-out (Allocatable <
	// Capacity) is B15's node-pressure/eviction scope, a deliberate future diff.
	n.Status.Allocatable = n.Status.Capacity.DeepCopy()
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
