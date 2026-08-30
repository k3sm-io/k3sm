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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"

	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/policy"
	"k3sm.io/k3sm/pkg/ports"
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
	pathShim   string // path-rebase DYLD shim dylib path (runtimed only)
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
	// standalone marks bring-up via the naked `k3sm node` command (runNode is the
	// ONLY constructor that sets it true). `k3sm node` stands up no cluster-DNS
	// resolver of its own — only `k3sm server`/`k3sm agent` call netserve.New
	// before reaching this shared bring-up (grep `netserve.New` across cmd/k3sm) —
	// so runtimedConfig uses this flag to guard the K3SM_DNS_* env injection off
	// (B43): left unset (the zero value, false), a standalone node would inject
	// env pointing at a VIP with nothing listening, blackholing every pod's
	// cluster-DNS lookup for ~2s per search candidate before falling through,
	// where the pre-injection behavior deferred to the host resolver immediately.
	standalone bool
}

// serverKubeletListen is the kubelet HTTP API listen address the in-process node
// of `k3sm server` and `k3sm agent` uses: the WILDCARD on the kubelet API port,
// so the apiserver node-proxy reaches it at whatever address the node advertises.
// nodeKubeletListen is the standalone `k3sm node` default (loopback-scoped).
//
// Both are built from ports.KubeletAPIPort — the port was two bare literals inside
// address strings before B116, with no constant anywhere, while it is one of the
// two wildcard listeners the reserved-port guard exists to protect.
var (
	serverKubeletListen = serverKubeletListenOn(ports.KubeletAPIPort)
	nodeKubeletListen   = loopbackNodeIP + ":" + strconv.Itoa(ports.KubeletAPIPort)
)

// serverKubeletListenOn is serverKubeletListen at a caller-chosen PORT — the one
// derivation `k3sm server --kubelet-port` goes through, so a second control plane
// on one host can give its node a listener of its own instead of contending for
// the single fixed default.
//
// It substitutes the port and NOTHING else. The result is the same wildcard form
// serverKubeletListen has always had, because the address is not the port's to
// move: the kubelet API's identity rests on serving TLS plus network reach (see
// proxyableNodeIP and vkadapter.NewNode), so a derivation that also touched the
// host part would change that surface's exposure while claiming to renumber a
// port.
func serverKubeletListenOn(port int) string { return ":" + strconv.Itoa(port) }

// kubeletEndpointPort is the INVERSE of serverKubeletListenOn: the port number the
// node advertises in .status.daemonEndpoints.kubeletEndpoint, read back off the very
// address its kubelet HTTP API listener binds. That endpoint is what the apiserver
// node-proxy dials for `kubectl logs`/`exec`/`top node`, so advertising anything but
// the bound port hands every client a connection refusal — which is precisely what a
// per-instance allocation (`k3sm server --kubelet-port`, and the `k3sm dev` port
// window that drives it) produced while this was the fixed ports.KubeletAPIPort
// constant: the node came up healthy on its own port and its diagnostics endpoints
// were unreachable.
//
// An unparseable or out-of-range value falls back to the shared default rather than
// advertising 0, which no client can dial at all: the fallback is only ever reached
// by a listen address the process would also have failed to bind, so it degrades to
// the historical answer instead of publishing a nonsense one.
func kubeletEndpointPort(listen string) int32 {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return int32(ports.KubeletAPIPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return int32(ports.KubeletAPIPort)
	}
	return int32(port)
}

// runNode registers this Mac as a Virtual Kubelet node and runs pods via the
// selected runtime (M0 walking skeleton + M1 runtimed image runtime).
func runNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	opts := nodeOptions{}
	fs.StringVar(&opts.kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "path to a kubeconfig for the cluster")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.listen, "listen", nodeKubeletListen, "address for the kubelet HTTP API (logs/exec)")
	fs.StringVar(&opts.podRoot, "pod-root", filepath.Join(os.TempDir(), "k3sm-pods"), "directory for per-pod logs/state")
	fs.StringVar(&opts.nodeIP, "node-ip", "127.0.0.1", "node/pod IP to advertise")
	addRuntimeFlag(fs, &opts.runtime)
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.StringVar(&opts.pathShim, "path-shim", "", "path-rebase DYLD shim dylib path (runtimed runtime only)")
	// Default "" (NOT dns.DefaultDNSVIP): the standalone node binds no resolver on
	// any VIP, so defaulting this to the real cluster DNS VIP would silently inject
	// K3SM_DNS_* pointing at a dead address (B43). See standaloneDNSGuard.
	fs.StringVar(&opts.dnsVIP, "dns-vip", "", "cluster DNS VIP the per-pod Seatbelt egress is scoped to (runtimed runtime only; standalone `k3sm node` binds no resolver — leave unset, see the startup log)")
	fs.StringVar(&opts.domain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain the in-pod getaddrinfo shim search list is built from (runtimed runtime only)")
	fs.BoolVar(&opts.serveTLS, "serve-tls", false, "serve the kubelet HTTP API over TLS so kubectl logs/exec work via the apiserver proxy")
	_ = fs.Parse(args)
	opts.standalone = true

	// B43: fail fast on an explicit --dns-vip (this process has nothing bound on
	// it) rather than silently injecting a dead VIP; otherwise log once that
	// cluster DNS is unavailable here so the guard's absence of K3SM_DNS_* env
	// isn't mistaken for a bug. Checked before the --kubeconfig requirement below
	// so a misconfigured flag is reported without needing a live cluster.
	if err := standaloneDNSGuard(opts, slog.Default()); err != nil {
		return err
	}

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

// standaloneDNSGuard is the B43 guard against the standalone-node dead-VIP
// blackhole: `k3sm node --runtime runtimed` threads --dns-vip/--cluster-domain
// into runtimedConfig, which (pre-B43) always injected the K3SM_DNS_* env the
// DYLD getaddrinfo shim reads — but this command starts no resolver on that VIP
// (only server.go/agent.go call netserve.New before reaching the shared
// startNode/buildProvider/runtimedConfig path). A pod's shim then dialed a dead
// VIP: a silent ~2s-per-search-candidate timeout instead of the pre-B18
// immediate defer to the host resolver.
//
// The operator decision (2026-08-28, B43) is DEV-ONLY: guard the injection off
// rather than build a standalone resolver. So an explicit --dns-vip — a request
// this process cannot honor — fails fast with a clear error (better than a
// silent blackhole); an unset one (the flag's new "" default) just logs that
// cluster DNS is unavailable here, and runtimedConfig (opts.standalone) leaves
// the injection inputs empty so no K3SM_DNS_* env reaches any pod.
//
// A no-op for --runtime hostprocess: that path never calls runtimedConfig, so
// --dns-vip is already inert there (its own flag help already scopes it to
// "runtimed runtime only").
func standaloneDNSGuard(opts nodeOptions, log *slog.Logger) error {
	if resolveRuntime(opts.runtime) != runtimeRuntimed {
		return nil
	}
	if opts.dnsVIP != "" {
		return fmt.Errorf("--dns-vip %q requested, but standalone `k3sm node` binds no cluster-DNS resolver in this process (only `k3sm server`/`k3sm agent` do) — drop --dns-vip, or run `k3sm server`/`k3sm agent` for cluster DNS instead of blackholing pod lookups against a dead VIP", opts.dnsVIP)
	}
	log.Info("standalone node: no cluster-DNS resolver runs in this process; pods will NOT receive K3SM_DNS_* env and fall back to the host resolver (run `k3sm server` or `k3sm agent` for cluster DNS)")
	return nil
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

// loopbackNodeIP is the --node-ip default. On the runtimed datapath it is
// rewritten to a globally-unicast address (see nodeInternalIP) because the
// apiserver node-proxy rejects a loopback NodeInternalIP — its isProxyableHostname
// runs net.IP.IsGlobalUnicast(), which loopback fails — with HTTP 400, breaking
// `kubectl top node` (GET /nodes/<n>/proxy/stats/summary). Off the datapath
// (`k3sm dev` rootless) proxyableNodeIP does the same job with a host interface
// address, since no adapter is there to alias a derived one.
const loopbackNodeIP = "127.0.0.1"

// isLoopbackDefault reports whether nodeIP is the shipped --node-ip default, i.e.
// the operator did not choose an address. It is the ONE value predicate all four
// call sites share (server.go's mesh rewrite and its apiserver-VIP-backend pin,
// node.go's advertise derivation, and the LB/ingress config assembly) — a
// flag.Visit-style "was it set?" predicate would diverge from it the moment a
// caller passes 127.0.0.1 explicitly, and a bare "127.0.0.1" literal (which one
// site carried) diverges from the const the moment the default moves.
//
// The predicate is shared; the DECISIONS keyed on it are NOT. A mesh server
// rewrites the loopback default to --mesh-ip; a datapath node derives the pod
// /24's mesh-egress .1. They must stay separate, and the derivation must run
// STRICTLY AFTER the mesh rewrite (see advertisedNodeIP): applied first, a mesh
// server would advertise 100.64.0.1 while its peers know it by its mesh IP.
func isLoopbackDefault(nodeIP string) bool {
	return nodeIP == loopbackNodeIP
}

// derivedNodeAdvertiseIP returns the address DERIVED for this node (the pod /24's
// reserved mesh-egress .1), or "" when no derivation applies — because the node
// runs no datapath, because the operator chose an explicit --node-ip (or the mesh
// rewrite already replaced the loopback default with --mesh-ip), or because the
// podCIDR does not yield one.
//
// It is deliberately distinct from advertisedNodeIP: only a DERIVED address is a
// pod-CIDR /32 this node must alias on lo0 to answer for. An explicit --node-ip or
// a mesh IP is the operator's/mesh's address and must never be aliased on lo0 here.
func derivedNodeAdvertiseIP(opts nodeOptions) string {
	if !opts.netMode.DataPath() || !isLoopbackDefault(opts.nodeIP) {
		return ""
	}
	return nodeInternalIP(opts.podCIDR)
}

// advertisedNodeIP is the address this node advertises: the derived mesh-egress
// .1 when the derivation applies, else opts.nodeIP verbatim (an explicit
// --node-ip, or the --mesh-ip the server already substituted). It is the SINGLE
// function both startNode (which stamps it on the Node object, the kubelet
// serving-cert SANs and the podnet adapter) and lbHostingConfigs (which publishes
// it as EXTERNAL-IP) call, so the two cannot disagree about what this node is.
func advertisedNodeIP(opts nodeOptions) string {
	if ip := derivedNodeAdvertiseIP(opts); ip != "" {
		return ip
	}
	return opts.nodeIP
}

// proxyableNodeIP returns the address the node REGISTERS as its NodeInternalIP —
// the one address the apiserver node-proxy will dial. It runs STRICTLY AFTER
// advertisedNodeIP, as the second tier of the same decision:
//
//	tier 1 (datapath):  the derived mesh-egress .1, aliased on lo0 by the podnet
//	                    adapter — advertisedNodeIP already returned it;
//	tier 2 (here):      no datapath, so nothing aliases an address for us — take
//	                    one the host ALREADY answers on, i.e. a globally-unicast
//	                    address of one of its own up interfaces;
//	tier 3 (fail-soft): no such address — keep the loopback default. `kubectl top`
//	                    stays broken, but the node still registers. A metrics
//	                    nicety never costs a node its registration.
//
// Without it a `k3sm dev` node (--network none, so DataPath()==false) registers
// InternalIP=127.0.0.1, and every GET /api/v1/nodes/<n>/proxy/... is refused
// with HTTP 400 "address not allowed": upstream's node-proxy ResourceLocation
// calls isProxyableHostname, which resolves the address and requires
// net.IP.IsGlobalUnicast() on EVERY result — loopback, unspecified, link-local
// and multicast all fail it (k8s v1.36.2 pkg/registry/core/node/strategy.go:256
// and :275-291; the address itself is picked by GetPreferredNodeAddress under
// the executor's --kubelet-preferred-address-types=InternalIP).
//
// It is DELIBERATELY not written back to opts.nodeIP. In the no-datapath posture
// that value is also the POD-facing address (podIP ≈ nodeIP — see buildProvider
// and runtimedConfig), and moving pod IPs is a different change with a different
// blast radius. The two values coincide in every other posture.
//
// SECURITY: this opens no port and widens no bind. `k3sm server`/`k3sm agent`
// already listen on the WILDCARD serverKubeletListen (*:10250), so the kubelet
// API — whose provider routes are served behind nodeutil.NoAuth(), identity
// resting on serving-TLS plus network reach (see vkadapter.NewNode) — is
// reachable at the host's interface addresses with or without this. All that
// changes is which of those addresses the Node object names. The substitution is
// therefore gated on wildcardListen: a listener scoped to loopback (standalone
// `k3sm node`) is never re-advertised at an address it does not serve.
func proxyableNodeIP(opts nodeOptions) string {
	if !isLoopbackDefault(opts.nodeIP) || !wildcardListen(opts.listen) {
		return opts.nodeIP
	}
	if ip := firstProxyableIP(hostInterfaceIPs()); ip != "" {
		return ip
	}
	return opts.nodeIP
}

// hostInterfaceIPs reports the addresses of this host's own up, non-loopback
// interfaces. It is a package var so proxyableNodeIP's selection is unit-testable:
// a test cannot add or remove an address on the machine running it.
var hostInterfaceIPs = func() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			// One unreadable interface must not hide the rest.
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ips = append(ips, n.IP)
			}
		}
	}
	return ips
}

// firstProxyableIP returns the first address in ips that satisfies the upstream
// node-proxy predicate (net.IP.IsGlobalUnicast — the SAME stdlib call
// isProxyableHostname makes), preferring IPv4 because that is what a dual-stack
// Mac's clients dial. It returns "" when no address qualifies, which is the
// caller's fail-soft signal. Interface order is net.Interfaces' index order, so
// the choice is stable across restarts.
func firstProxyableIP(ips []net.IP) string {
	var v6 string
	for _, ip := range ips {
		if ip == nil || !ip.IsGlobalUnicast() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		if v6 == "" {
			v6 = ip.String()
		}
	}
	return v6
}

// wildcardListen reports whether listen binds EVERY local address (":10250",
// "0.0.0.0:10250", "[::]:10250") rather than one scoped address. It is the
// bind-then-advertise check proxyableNodeIP gates on: the node may only name an
// address its kubelet API listener actually answers on. An unparseable value is
// treated as scoped — the conservative direction, since a wrong "yes" advertises
// an address that refuses the connection.
func wildcardListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// nodeInternalIP derives the globally-unicast address the VK node advertises as
// its NodeInternalIP from the node's pod /24: the reserved mesh-egress /32 (.1,
// podnet.MeshEgressIP). That address is RFC-6598 unicast (IsGlobalUnicast()==true
// → passes the apiserver node-proxy's isProxyableHostname), deterministic across
// restarts, never handed to a pod, and reachable on the same Mac once aliased on
// lo0 (the podnet adapter's ReconcileStartup plumbs that alias). It is DECOUPLED
// from the apiserver bind/advertise-address (executor.Config.NodeIP stays
// loopback, so the in-pod kubernetes endpoint is unaffected). Returns "" on a bad
// podCIDR so the caller keeps the loopback default rather than inventing an
// address.
func nodeInternalIP(podCIDR string) string {
	prefix, err := netip.ParsePrefix(podCIDR)
	if err != nil {
		return ""
	}
	ip, err := podnet.MeshEgressIP(prefix)
	if err != nil {
		return ""
	}
	return ip.String()
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

// nodeAPIRequestTimeout bounds every apiserver round-trip the node's client
// makes (rest.Config.Timeout → the http.Client the clientset dials with).
// Without it a stalled request — a half-open socket to the loopback apiserver, a
// TLS handshake against a listener that accepted but never answered — blocks its
// caller forever with nothing logged, because clientcmd.BuildConfigFromFlags
// leaves Timeout at its zero value ("no timeout").
//
// Picked against three real numbers:
//   - a healthy registration round-trip against the loopback apiserver takes
//     MILLISECONDS to low seconds, so 90s is orders of magnitude of headroom —
//     a slow-but-healthy start (cold page-in, a busy machine, a control plane
//     still settling) cannot trip it, which matters because a too-tight bound
//     would turn a healthy start into a failure and be worse than the hang;
//   - the apiserver's own --request-timeout default is 60s, so any non-watch
//     request the server is legitimately still serving is ended by the SERVER
//     first (a legible 504) — 90s never pre-empts it;
//   - the sibling nodeStartupTimeout is 5m, so a wedged round-trip surfaces at
//     90s with room to spare inside the startup bound rather than silently
//     consuming it.
//
// Accepted cost: rest.Config.Timeout applies to watches too, so the node's
// informers re-establish their watch every 90s instead of the reflector's
// 5–10m. That is a cheap re-watch from the last resourceVersion (no relist) on
// a loopback apiserver watching one node's pods.
const nodeAPIRequestTimeout = 90 * time.Second

// nodeRESTConfig loads the node's kubeconfig and applies nodeAPIRequestTimeout.
// It exists as a named seam so the timeout on the config the node's clientset is
// built from is unit-testable — startNode itself needs a live apiserver.
func nodeRESTConfig(kubeconfig string) (*rest.Config, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cfg.Timeout = nodeAPIRequestTimeout
	return cfg, nil
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

	// Advertise a globally-unicast NodeInternalIP on the runtimed datapath so the
	// apiserver node-proxy accepts /nodes/<n>/proxy/stats/summary (kubectl top
	// node): a loopback InternalIP fails isProxyableHostname (IsGlobalUnicast) →
	// HTTP 400. Derive the node's reserved mesh-egress .1 (never a pod IP); the
	// podnet adapter's startup reconcile aliases it on lo0 so the same-host proxy
	// dial reaches the :10250 listener. This mutates only the by-value node opts —
	// executor.Config.NodeIP (the apiserver bind) stays loopback, so the in-pod
	// kubernetes endpoint is unaffected — and flows to the node's advertised
	// address, its kubelet serving-cert SANs, and the adapter's node alias. An
	// explicit --node-ip (e.g. --mesh-ip, already globally-unicast) is honored.
	opts.nodeIP = advertisedNodeIP(opts)

	// Second tier of the same decision, for the postures the derivation above does
	// not cover (`k3sm dev` rootless: --network none, so no adapter aliases a /32
	// for us). It yields the ONE address registered as NodeInternalIP — the address
	// the apiserver node-proxy dials — and is deliberately kept OUT of opts.nodeIP,
	// which in a no-datapath posture is also the pod-facing address. See
	// proxyableNodeIP for the upstream predicate and the security note.
	internalIP := proxyableNodeIP(opts)
	if internalIP != opts.nodeIP {
		slog.Info("registering a host interface address as NodeInternalIP so the apiserver node-proxy can dial this node (kubectl top/logs/exec); the kubelet API listener is already wildcard-bound, so no new port is opened",
			"internal_ip", internalIP, "node_ip", opts.nodeIP, "listen", opts.listen)
	}

	restCfg, err := nodeRESTConfig(opts.kubeconfig)
	if err != nil {
		return err
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

	prov, netAdapter, runtimeLabel, caps, err := buildProvider(ctx, opts, cs, recorder)
	if err != nil {
		return err
	}

	// M10.1 startup reconcile — MUST run here, in-process, before the node serves.
	// The embedded runtimed runtime is driven by direct RPC (provider.NewRuntimed),
	// never runtime.Server.Serve, so runtimed's own once-before-serve reconcile never
	// fires on this path. Run the adapter's reconcile directly: it sweeps stale lo0
	// aliases a prior `launchctl kickstart -k` left behind AND plumbs the node's own
	// mesh-egress /32 on lo0 so the apiserver node-proxy dial to NodeInternalIP:10250
	// (kubectl top node / logs / exec) reaches the :10250 listener. Fail closed,
	// matching runtimed's sticky-once contract. nil for hostprocess / --network none.
	//
	// Its SIBLING — the startup POD reap, stranded on this path for the same reason —
	// is not here: it lives inside provider.NewRuntimed (called from buildProvider
	// above), so it cannot be omitted by a caller and runs before any CreatePod is
	// served. It DEGRADES rather than failing closed; see the comment at that call.
	if netAdapter != nil {
		if err := netAdapter.ReconcileStartup(ctx); err != nil {
			return fmt.Errorf("pod network startup reconcile: %w", err)
		}
	}

	var servingTLS *tls.Config
	if opts.serveTLS {
		servingTLS, err = kubeletServingTLS(opts.nodeName, opts.nodeIP, internalIP)
		if err != nil {
			return fmt.Errorf("kubelet serving tls: %w", err)
		}
	}

	// Build the VK node through the adapter: it encapsulates the kubelet HTTP API
	// wiring (logs/exec only serve when BOTH a TLS config and a handler are set, so
	// the apiserver→node proxy reaches /containerLogs — M1.2) and the
	// nil-NodeProvider → NaiveNodeProvider (auto-Ready + lease heartbeat) path.
	// nodeStatus is assigned by the NodeProvider callback below, which VK invokes
	// SYNCHRONOUSLY inside NewNode — so it is set before NewNode returns and the
	// status loop can be started right after, with no handshake.
	var nodeStatus *provider.NodeStatusProvider
	n, err := vkadapter.NewNode(opts.nodeName, vkadapter.NodeConfig{
		Client:         cs,
		Provider:       prov,
		HTTPListenAddr: opts.listen,
		NumWorkers:     4,
		TLSConfig:      servingTLS, // nil = plain HTTP (M0 path); set = kubelet-serving TLS
		ConfigureNode:  func(nd *corev1.Node) { configureNode(nd, opts.nodeName, internalIP, opts.listen, caps) },
		// Replace VK's auto-Ready naive node provider with the real one: it samples
		// this Mac for memory/disk/PID pressure and debounces the runtime's health
		// into Ready. It receives the node AFTER configureNode stamped it, and
		// republishes that exact object every interval with only the conditions
		// changed — VK assigns the published Status wholesale, so anything not
		// carried through would be erased from the registered node.
		NodeProvider: func(nd *corev1.Node) (vkadapter.NodeProvider, error) {
			nsp, nerr := provider.NewNodeStatusProvider(provider.NodeStatusConfig{
				Node:           nd,
				DataRoot:       opts.podRoot,
				RuntimeHealthy: runtimeHealthProbe(prov),
				Log:            slog.Default(),
			})
			if nerr != nil {
				return nil, nerr
			}
			nodeStatus = nsp
			return nsp, nil
		},
	})
	if err != nil {
		return fmt.Errorf("new node: %w", err)
	}

	errc := make(chan error, 1)
	go func() { errc <- n.Run(ctx) }()
	// The status loop's first publication is what marks the node Ready (supplying a
	// node provider disables VK's own ready callback), so it must run for the whole
	// life of the node, not only after startup succeeds. Its first UpdateStatus
	// blocks until VK registers the notify callback, so starting it here is safe.
	go func() { _ = nodeStatus.Run(ctx) }()

	if err := awaitNodeReady(ctx, n.Ready(), errc, nodeStartupTimeout, opts.nodeName, opts.listen); err != nil {
		return err
	}
	log.Printf("k3sm node %q ready (runtime=%s listen=%s pod-root=%s)", opts.nodeName, runtimeLabel, opts.listen, opts.podRoot)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// runtimeHealthReporter is the optional provider capability the node-status loop
// reads for the Ready condition. It is declared at this consumer so the node
// command depends on the one method it needs, not on a concrete provider type.
type runtimeHealthReporter interface {
	RuntimeHealthy(ctx context.Context) bool
}

// runtimeHealthProbe returns prov's runtime-health probe, or nil when prov
// exposes none. A nil result tells the status provider that Ready must never be
// contradicted — the M0 host-process runtime has no health surface, and a node
// must not be marked NotReady on a question its runtime cannot answer.
func runtimeHealthProbe(prov vkadapter.Provider) func(context.Context) bool {
	h, ok := prov.(runtimeHealthReporter)
	if !ok {
		return nil
	}
	return h.RuntimeHealthy
}

// nodeStartupTimeout bounds startNode's wait for the VK node to signal readiness.
//
// Picked against two measured numbers and deliberately far from both: a healthy
// bring-up on the lab Macs signals Ready in SECONDS (provider construction plus
// the first Node registration), while the 2026-08-27 wedge was still sitting in
// this wait at THREE MINUTES with the VK run loop alive and no Node object ever
// created. 5m is ~2 orders of magnitude past the healthy path — a slow but
// healthy start (cold page-in, a retried apiserver dial, a busy machine) cannot
// trip it — and still turns the wedge into a bounded, reported failure instead
// of a process that blocks forever and logs nothing.
const nodeStartupTimeout = 5 * time.Minute

// errNodeStartupTimeout is returned by awaitNodeReady when the Virtual Kubelet
// node signals neither readiness nor exit before the deadline. It does NOT
// diagnose why registration failed — only that it never completed.
var errNodeStartupTimeout = errors.New("node startup timed out")

// awaitNodeReady waits for a Virtual Kubelet node to finish starting: it returns
// nil once ready closes, the wrapped run-loop error if errc fires first,
// ctx.Err() on cancellation, and errNodeStartupTimeout when neither channel
// fires within timeout.
//
// It is factored out of startNode purely so the deadline is unit-testable —
// startNode builds a real apiserver client and a real VK node, so the wait
// itself is otherwise unreachable from a unit test.
//
// nodeName and listen are carried only for the diagnostic. The timeout message
// must let an operator reading nothing but the log tell "VK never signalled
// Ready" (this error) apart from "VK returned an error" (the wrapped errc case),
// because the observed failure logged neither: the node stayed absent from
// `kubectl get node` and every pod reported Unschedulable with no further clue.
func awaitNodeReady(ctx context.Context, ready <-chan struct{}, errc <-chan error, timeout time.Duration, nodeName, listen string) error {
	t := time.NewTimer(timeout)
	defer t.Stop()

	select {
	case <-ready:
		return nil
	case err := <-errc:
		return fmt.Errorf("node exited during startup: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return fmt.Errorf("%w after %s: virtual-kubelet %q signalled neither ready nor exit "+
			"(its Ready channel never closed and its Run loop has not returned, so no Node object "+
			"reached the apiserver; listen=%s) — pods will report Unschedulable until a node registers",
			errNodeStartupTimeout, timeout, nodeName, listen)
	}
}

// buildProvider selects and constructs the VK provider for the requested
// runtime. runtimed is the default (defaultRuntime — the M1 image runtime: OCI
// pull → clonefile → ad-hoc-sign → Seatbelt confine, per-pod /32 pod IPs via
// the injected podnet adapter), wrapped in the VK adapter; hostprocess is the
// explicit rootless-dev opt-out (M0 native processes, no isolation, podIP ≈
// nodeIP — its documented shape, untouched by M10.1). cs is the apiserver
// client the runtimed provider resolves volumes/env/imagePullSecrets with
// (M2.1/M2.6). recorder is the EventRecorder both provider paths emit pod
// lifecycle Events to: the HostProcess path emits Pulled/Created/Started/Killing,
// the runtimed path emits the BackOff crash-loop Event (B26).
// buildProvider constructs the VK provider for the selected runtime and reports the
// node's runtimed-advertised capabilities — the source of every k3sm.io/* capability
// node label (k3sm.io/virtualization from B1, k3sm.io/rosetta{,-linux} from B103).
//
// The capabilities travel as ONE provider.NodeCapabilities struct, never as adjacent
// positional bools: three same-typed bools in a signature make a transposition
// compile cleanly and mislabel the node fail-OPEN (advertising a capability it lacks),
// which is exactly the failure the fail-closed probe exists to prevent. They come from
// ONE GetRuntimeInfo RPC (provider.Capabilities) so the label set is internally
// coherent.
//
// The in-process host-process runtime has no vm backend and no Rosetta probe, so a node
// running it returns the ZERO value — correct AND fail-closed by construction (nothing
// advertised), with no per-capability false to keep in sync.
func buildProvider(ctx context.Context, opts nodeOptions, cs kubernetes.Interface, recorder record.EventRecorder) (vkadapter.Provider, *provider.PodNetAdapter, string, provider.NodeCapabilities, error) {
	switch resolveRuntime(opts.runtime) {
	case runtimeHostProcess:
		return provider.NewHostProcess(opts.nodeName, opts.podRoot, opts.nodeIP, recorder), nil, runtimeHostProcess, provider.NodeCapabilities{}, nil
	case runtimeRuntimed:
		cfg := runtimedConfig(opts, cs)
		// The runtimed path emits the Warning BackOff Event for a throttled
		// container re-exec (B26), so `kubectl describe pod` on a crash-looping pod
		// shows the crash loop in its Events table.
		cfg.Recorder = recorder
		adapter, err := buildPodNetAdapter(opts)
		if err != nil {
			return nil, nil, "", provider.NodeCapabilities{}, err
		}
		if adapter != nil {
			cfg.Network = adapter
		}
		rt, err := provider.NewRuntimed(cfg)
		if err != nil {
			return nil, nil, "", provider.NodeCapabilities{}, fmt.Errorf("build runtimed provider: %w", err)
		}
		// Return the adapter so startNode can run its startup reconcile IN-PROCESS:
		// the embedded runtimed runtime is driven by direct RPC (NewRuntimed), never
		// runtime.Server.Serve, so runtimed's once-before-serve reconcileNetworkStartup
		// never fires on this path. Dropping the adapter here would strand both the
		// stale-alias sweep and the node's own lo0 alias (kubectl top node / node-proxy).
		//
		// Capabilities is probed ONCE, here at bring-up: runtimed evaluates every
		// capability probe once in its own constructor, so re-probing per reconcile
		// would report the same immutable answer. The operator consequence — a host
		// that GAINS or LOSES Rosetta needs `launchctl kickstart -k system/io.k3sm.server`
		// before the label tracks it — is documented in docs/user/vm-runtimeclass.md
		// and the loss-direction ceiling in docs/user/limitations.md.
		return provider.NewVKProvider(rt, opts.nodeName), adapter, runtimeRuntimed, rt.Capabilities(ctx), nil
	default:
		return nil, nil, "", provider.NodeCapabilities{}, fmt.Errorf("unknown --runtime %q (want %s or %s)", opts.runtime, runtimeRuntimed, runtimeHostProcess)
	}
}

// buildPodNetwork constructs a podnet.Network over the node's /24 with the alias
// backend the resolved host-network mode selects (the netd helper when
// unprivileged, the direct root-gated manager otherwise). It is the ONE place
// those podnet.Options are assembled, so a future option cannot reach one call
// site and miss the other.
//
// TWO call sites construct one (they are the same in this process):
//
//   - buildPodNetAdapter, below — the node's ALLOCATING Network. darwin-net stays
//     the sole node-/24 allocator, and this is the instance that holds that
//     allocator's state.
//   - ensureAdvertisedNodeAlias (server.go step 4d) — a stateless throwaway used
//     ONLY for EnsureNodeAlias, which touches the alias manager and nothing else:
//     the node's .1 lies outside the allocator's [.2,.254] range, so no IPAM state
//     is read or written and the two instances cannot disagree about any pod's IP.
//
// The safety of a second instance rests on that ONE property (alias-only use), not
// on call ordering: podnet's mutex is per-Network, so two instances serialize
// nothing between them. Today the call sites are strictly sequential within
// runServer (step 4d completes before step 5 builds the adapter) and the alias
// operation is idempotent besides, but do NOT rely on that — if a second
// construction ever needs Setup/Teardown/SweepStale, share the allocating instance
// instead of building another.
func buildPodNetwork(opts nodeOptions, log *slog.Logger) (*podnet.Network, error) {
	if opts.podCIDR == "" {
		return nil, fmt.Errorf("pod network needs the node podCIDR (the enrolled /24) and none was configured")
	}
	prefix, err := netip.ParsePrefix(opts.podCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse node podCIDR %q: %w", opts.podCIDR, err)
	}
	popts := []podnet.Option{podnet.WithLogger(log)}
	if opts.netMode.UsesHelper() {
		popts = append(popts, podnet.WithNetdHelper(opts.netMode.Socket))
	}
	nw, err := podnet.New(prefix, popts...)
	if err != nil {
		return nil, fmt.Errorf("build pod network for %s: %w", opts.podCIDR, err)
	}
	return nw, nil
}

// buildPodNetAdapter constructs the node's one ALLOCATING podnet.Network (see
// buildPodNetwork) and wraps it in the provider adapter that bridges it into
// runtimed's PodNetwork + startup-reconcile seams (M10.1). It returns nil (no
// adapter — runtimed keeps podIP ≈ nodeIP) only for the EXPLICIT no-datapath
// backend (`--network none`, control-plane-only/CI); a missing podCIDR with a
// datapath is a fail-fast error, never a fallback.
func buildPodNetAdapter(opts nodeOptions) (*provider.PodNetAdapter, error) {
	if !opts.netMode.DataPath() {
		return nil, nil
	}
	nw, err := buildPodNetwork(opts, slog.Default())
	if err != nil {
		return nil, err
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
// resolvePathShim returns the path-rebase DYLD shim dylib installed beside the
// k3sm binary (/Library/k3sm/<PathShimName> in the packaged layout), or "" when
// absent — so a from-source/dev run without the staged shim leaves absolute mount
// paths reaching the host (the pre-shim behavior) rather than failing to inject.
func resolvePathShim() string {
	return resolveSiblingDylib(install.PathShimName)
}

// resolveDNSShim returns the getaddrinfo DNS shim dylib installed beside the k3sm
// binary, or "" when absent (a from-source/dev run without it leaves pods on the
// system resolver — cluster names NXDOMAIN, but bring-up proceeds).
func resolveDNSShim() string {
	return resolveSiblingDylib(install.DNSShimName)
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolveSiblingDylib returns the absolute path of name next to the running k3sm
// executable when it exists as a file, else "" (graceful: a missing pod-support
// dylib disables its feature rather than failing the node).
func resolveSiblingDylib(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), name)
	if fi, err := os.Stat(p); err != nil || fi.IsDir() {
		return ""
	}
	return p
}

// B43: opts.standalone (set ONLY by runNode) skips the empty-dnsVIP default-fill
// below, leaving ResolverVIP "". dns.PodDNSConfig then builds a DNSConfig with an
// empty ClusterDNSIP, which Validate() rejects — the SAME "dnsCfg not usable"
// path injectClusterDNSEnv already documents (dns.ConfigToEnv returns nil, no
// K3SM_DNS_* env is appended, the shim defers to the host resolver) — rather than
// inventing a second no-DNS fallback. server.go/agent.go never set opts.standalone,
// so their nodeOptions are unaffected and keep injecting exactly as before B43.
func runtimedConfig(opts nodeOptions, cs kubernetes.Interface) provider.RuntimedConfig {
	resolverVIP := opts.dnsVIP
	if resolverVIP == "" && !opts.standalone {
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
		NodeName: opts.nodeName,
		NodeIP:   opts.nodeIP,
		Root:     opts.podRoot,
		// Prefer an explicit --dns-shim; else resolve the staged shim next to the
		// binary (the packaged server plist passes no --dns-shim). Empty leaves pods
		// on the system resolver.
		DyldShim: firstNonEmpty(opts.dnsShim, resolveDNSShim()),
		// Prefer an explicit --path-shim; else resolve the staged shim next to the
		// binary. `k3sm dev` re-execs a `go build` binary whose siblings are a
		// temp dir, so the sibling lookup finds nothing there and the flag is the
		// ONLY way the dev cluster gets absolute volume mounts.
		PathShim:      firstNonEmpty(opts.pathShim, resolvePathShim()),
		ResolverVIP:   resolverVIP,
		ClusterDomain: clusterDomain,
		APIServerVIP:  apiServerVIP(),
		Client:        cs,
		// Fence every pod off the root helper socket at the sandbox: pods share the
		// _k3sm uid with the legitimate helper client, so the SBPL must deny
		// connect() to the privileged daemon. Denied regardless of run-as-root vs
		// helper mode (a pod must never drive netd).
		DeniedUnixSocketPaths: []string{netd.DefaultSocketPath},
		// Wire the process default logger so the runtimed provider is not SILENT: it
		// otherwise falls back to a DiscardHandler, dropping pod-lifecycle + cluster-DNS
		// wiring logs the operator needs (server.log had no provider lines at all).
		Logger: slog.Default(),
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

// hostArchFacts is the raw host-architecture evidence nodeArch derives the node's
// reported architecture from. It is a STRUCT, not a bare string, because no single
// reading is truthful on its own — measured on Apple Silicon natively and from a
// process spawned under `arch -x86_64`:
//
//	hw.machine              arm64 native / x86_64 translated  -> LIES under translation
//	uname -m                arm64 native / x86_64 translated  -> LIES under translation
//	hw.optional.arm64       1     native / 1     translated   -> TRUTHFUL (hardware)
//	sysctl.proc_translated  0     native / 1     translated   -> is THIS process translated
//
// runtime.GOARCH is deliberately absent from this struct: it is the arch the BINARY
// was BUILT for, never the node's. See nodeArch for why both obvious answers are wrong.
type hostArchFacts struct {
	// arm64Capable is hw.optional.arm64 — the HARDWARE can execute arm64. It reads 1
	// on every Apple Silicon Mac including from inside a translated process, which is
	// exactly what makes it the truth source. The sysctl does not exist on an Intel
	// Mac (ENOENT), which reads as a truthful false.
	arm64Capable bool
	// machine is hw.machine — the machine AS SEEN BY THIS PROCESS: "arm64" natively,
	// "x86_64" when this process itself runs translated. A cross-check only, never
	// the primary source.
	machine string
	// procTranslated is sysctl.proc_translated — whether THIS process runs under
	// Rosetta, i.e. whether machine above is a translated view rather than the host's.
	procTranslated bool
}

// readHostArchFacts probes the three host-architecture sysctls. It is a package var so
// tests inject host facts — including a non-arm64 host, which cannot be reproduced on
// an Apple Silicon developer machine — without hitting a real syscall, keeping nodeArch
// hermetic; production reads the live sysctls via golang.org/x/sys/unix.
var readHostArchFacts = func() (hostArchFacts, error) {
	machine, err := unix.Sysctl("hw.machine")
	if err != nil {
		return hostArchFacts{}, fmt.Errorf("sysctl hw.machine: %w", err)
	}
	return hostArchFacts{
		arm64Capable:   sysctlFlag("hw.optional.arm64"),
		machine:        machine,
		procTranslated: sysctlFlag("sysctl.proc_translated"),
	}, nil
}

// sysctlFlag reports whether a boolean-valued (4-byte int) sysctl is present and
// non-zero. A MISSING key is a truthful false, not an error: neither hw.optional.arm64
// nor sysctl.proc_translated exists on an Intel Mac, where "not arm64-capable" and
// "not translated" are precisely the right answers.
func sysctlFlag(name string) bool {
	v, err := unix.SysctlUint32(name)
	return err == nil && v != 0
}

// defaultNodeArch is the architecture advertised when the host-fact probe fails or
// returns something unrecognized. Like defaultMemBytes above it is a logged FALLBACK,
// not an assertion: k3sm ships darwin/arm64-only (doctor hard-fails a non-arm64 host
// at install time), so the supported-platform value is the least-wrong answer, and
// omitting kubernetes.io/arch entirely would strand every pod that selects on it.
const defaultNodeArch = "arm64"

// nodeArch derives the architecture the node reports — as both the kubernetes.io/arch
// label and NodeInfo.Architecture — from host facts. It is pure (no syscall) so it is
// unit-tested directly, and returns "" when the facts are unrecognizable so the caller
// can log and fall back.
//
// The hardware capability (hw.optional.arm64) is the truth source. Both obvious
// alternatives are wrong:
//
//   - runtime.GOARCH reports the arch the BINARY was built for. A Go toolchain that is
//     itself amd64-under-Rosetta (a real, observed configuration: `go env GOARCH` says
//     amd64 on an arm64 Mac) then produces a binary that labels an Apple Silicon node
//     kubernetes.io/arch=amd64, attracting amd64-only workloads to a node whose native
//     arch is arm64. The bug is invisible on a correctly-configured host.
//   - a bare hw.machine is correct only while the reading process happens to be native;
//     it flips to x86_64 the moment the daemon itself runs translated.
//
// procTranslated is a second arm64 witness rather than a correction term: Rosetta 2
// translation exists only on Apple Silicon, so a translated reader proves arm64
// hardware even if the capability read came back false.
func nodeArch(f hostArchFacts) string {
	if f.arm64Capable || f.procTranslated {
		return "arm64"
	}
	switch f.machine {
	case "arm64", "arm64e":
		return "arm64"
	case "x86_64", "x86_64h":
		return "amd64"
	default:
		return ""
	}
}

// hostNodeArch reads the host-arch seam and derives the reported node architecture,
// logging and falling back to defaultNodeArch on a failed or unrecognized probe (a
// host-fact hiccup must not keep the node from registering).
func hostNodeArch() string {
	facts, err := readHostArchFacts()
	if err == nil {
		if arch := nodeArch(facts); arch != "" {
			return arch
		}
	}
	slog.Warn("host architecture probe failed or unrecognized; advertising the default node architecture",
		"error", err,
		"machine", facts.machine,
		"arm64_capable", facts.arm64Capable,
		"proc_translated", facts.procTranslated,
		"default_arch", defaultNodeArch)
	return defaultNodeArch
}

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
// fallback), the runtimed-probed k3sm.io/* capability labels, and the provider taint
// (the load-bearing placement guard) so stray non-darwin pods cannot land here.
//
// caps is the ONE fail-closed capability snapshot buildProvider probed from runtimed;
// its zero value advertises nothing — including its GPU facts, which additionally
// drive the mlx.k3sm.io/gpu extended resource on Capacity/Allocatable.
//
// listen is the SAME kubelet HTTP API listen address handed to the VK adapter, not a
// second copy of the port: the advertised daemon endpoint is derived from it here
// (kubeletEndpointPort) so the node cannot name a port its listener does not answer
// on. Passing the address rather than a pre-extracted port is deliberate — one
// derivation, at the one place both facts are in scope.
func configureNode(n *corev1.Node, name, ip, listen string, caps provider.NodeCapabilities) {
	labels := nodeLabels(n)
	labels["kubernetes.io/os"] = "darwin"
	// The reported architecture is DERIVED from host facts through the readHostArchFacts
	// seam (see nodeArch), never from runtime.GOARCH and never from a bare hw.machine —
	// both of which report amd64/x86_64 on an Apple Silicon Mac under conditions that are
	// invisible on a correctly-configured host. One derivation feeds BOTH this label and
	// NodeInfo.Architecture below, so the two can never disagree.
	arch := hostNodeArch()
	labels["kubernetes.io/arch"] = arch
	labels["kubernetes.io/hostname"] = name
	labels["k3sm.io/native"] = "true"
	labels["type"] = "k3sm"

	// Well-known topology labels, GA keys only (the v1.36.2 scheduler reads these; the
	// deprecated failure-domain.beta.kubernetes.io aliases are cruft). zone is set to THIS
	// node's name — == kubernetes.io/hostname by construction (same `name`): a DELIBERATE
	// per-node failure domain, since each Mac is a genuine independent one. A zone
	// topologySpread with whenUnsatisfiable: DoNotSchedule thus degrades to host-spread
	// (fail-open) instead of stranding pods Pending on a missing label, and never FALSELY
	// claims co-located Macs share a failure domain (which a shared static zone would).
	// region is one static value all nodes agree on — k3sm has no cloud-region concept.
	labels[corev1.LabelTopologyZone] = name
	labels[corev1.LabelTopologyRegion] = defaultNodeRegion

	// vm RuntimeClass node-capability gate (M5.1/B1): advertise the
	// Virtualization.framework backend via the k3sm.io/virtualization label ONLY when
	// this node can run it, so the vm RuntimeClass nodeSelector pins vm pods to a
	// capable node. caps.VMBackend is the runtimed VMBackendAvailable probe
	// (buildProvider, fail-closed on any error); a false value leaves the label absent
	// so a vm pod stays Unschedulable — the fail-closed posture for a non-VZ cluster.
	applyVirtualizationLabel(n, caps.VMBackend)

	// Rosetta translation-capability labels (B103), same fail-closed presence-only
	// discipline as the virtualization label above.
	applyRosettaLabels(n, caps)

	n.Status.NodeInfo.OperatingSystem = "darwin"
	// Architecture is the machine's NATIVE ISA (the same derived value as the
	// kubernetes.io/arch label above) and stays arm64 on a Rosetta-capable Apple
	// Silicon node: a translated-payload capability is advertised ONLY through the
	// k3sm.io/rosetta{,-linux} labels, never by making this (or kubernetes.io/arch)
	// report a foreign arch to every generic client.
	n.Status.NodeInfo.Architecture = arch
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
	// GPU advertisement: the mlx.k3sm.io/gpu extended resource in Capacity AND
	// Allocatable plus the mlx.k3sm.io chip/memory labels, fail-closed off runtimed's
	// GPUFacts and REMOVED on capability loss (see applyGPUAdvertisement). It runs
	// AFTER both resource lists are built, deliberately: nodeAllocatable DeepCopies
	// Capacity, so advertising earlier would have the GPU reach Allocatable by copy
	// rather than by decision — and the removal direction would then have to know
	// about that coupling to undo it from both.
	applyGPUAdvertisement(n, caps.GPU)

	n.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: ip},
		{Type: corev1.NodeHostName, Address: name},
	}
	// The ADVERTISED kubelet endpoint is derived from the address the listener
	// actually binds — never the fixed default — so a per-instance allocation
	// (`--kubelet-port`) stays dialable by the apiserver node-proxy.
	n.Status.DaemonEndpoints.KubeletEndpoint.Port = kubeletEndpointPort(listen)

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
//
// It is a thin named alias for setLabelPresence, deliberately: this is B1's
// entry point (and B1's test's), but the set-or-DELETE mechanism must have exactly ONE
// implementation. A hand-rolled copy here is how the two drift, and the fail-open
// direction of a drift (writing "false" instead of deleting) still satisfies an
// `exists`-style nodeSelector on a node that LOST the capability.
func applyVirtualizationLabel(n *corev1.Node, vmCapable bool) {
	setLabelPresence(n, runtimeclass.LabelVirtualization, vmCapable)
}

// applyRosettaLabels sets or CLEARS the two Rosetta translation-capability node
// labels (B103), mirroring applyVirtualizationLabel — which is the delete-on-loss
// precedent this follows (B1's shipped k3sm.io/virtualization; NOT B94, which was
// refused with zero commits, so it is no precedent for anything):
//
//   - k3sm.io/rosetta       ⇔ caps.RosettaHost            (darwin/amd64 Mach-O, host Rosetta 2)
//   - k3sm.io/rosetta-linux ⇔ caps.VMBackend ∧ caps.RosettaGuest (linux/amd64 ELF in a VZ guest)
//
// The linux key is a CONJUNCTION because Rosetta for Linux translates inside a guest:
// a Rosetta-installed but VZ-INCAPABLE node carries k3sm.io/rosetta but must NOT
// carry k3sm.io/rosetta-linux, or the scheduler would bind linux/amd64 payloads to a
// node with no guest to run them in. The two keys are otherwise INDEPENDENT — host
// translation and guest translation are separate probes, so either may be advertised
// without the other.
//
// Presence-only, and DELETE (never "false") on loss: a node that loses a capability
// across a restart must stop advertising it, and a "false" value would still satisfy
// an `exists`-style selector. The label is a truthful capability claim, so the
// fail-closed direction is always absence.
func applyRosettaLabels(n *corev1.Node, caps provider.NodeCapabilities) {
	setLabelPresence(n, runtimeclass.LabelRosetta, caps.RosettaHost)
	// The ONE place the conjunction is composed (pkg/runtimeclass's LabelRosettaLinux
	// doc names this function as that place). It gets its own log line because NEITHER
	// underlying condition explains this outcome: a node with guest Rosetta but no vm
	// backend withholds the label while RosettaGuestAvailable is TRUE, and
	// docs/user/troubleshooting.md sends the operator looking for exactly this key.
	rosettaLinux := caps.VMBackend && caps.RosettaGuest
	setLabelPresence(n, runtimeclass.LabelRosettaLinux, rosettaLinux)
	if !rosettaLinux {
		slog.Info("node capability label withheld: it requires BOTH the vm backend and guest Rosetta (Rosetta for Linux translates inside a guest)",
			"label", runtimeclass.LabelRosettaLinux, "vm_backend", caps.VMBackend, "rosetta_guest", caps.RosettaGuest)
	}
}

// setLabelPresence stamps key=runtimeclass.LabelTrue on n when present, and DELETES key
// otherwise — the presence-only capability-label discipline in ONE place (every
// capability label goes through here, applyVirtualizationLabel included), so a new
// capability key cannot accidentally ship a "false" value or an omit-instead-of-delete.
//
// It also logs the DECISION naming the LABEL KEY: the provider side logs the runtimed
// condition + Reason (the "why"), but only this side knows which k3sm.io/* key that
// verdict resolved to — and the key is what the operator greps for.
func setLabelPresence(n *corev1.Node, key string, present bool) {
	labels := nodeLabels(n)
	if present {
		labels[key] = runtimeclass.LabelTrue
		slog.Debug("node capability label stamped", "label", key, "value", runtimeclass.LabelTrue)
		return
	}
	delete(labels, key)
	slog.Info("node capability label absent: the capability was not advertised by runtimed, so the key is DELETED (never set to \"false\")", "label", key)
}

// nodeLabels returns n's label map, allocating it when nil — the ONE nil-Labels guard
// every label writer in this file goes through (it was triplicated across
// configureNode, applyVirtualizationLabel, and applyRosettaLabels). The returned map
// aliases n.Labels, so writes through it land on the node.
func nodeLabels(n *corev1.Node) map[string]string {
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	return n.Labels
}

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
// cert's SANs include loopback, the node name, and EVERY address in nodeIPs —
// which must cover the registered NodeInternalIP, since the apiserver (started
// with --kubelet-preferred-address-types=InternalIP) dials that address by IP and
// verifies the cert against it. The advertised address and the registered
// InternalIP diverge in the no-datapath posture (see proxyableNodeIP), so both
// are passed; duplicates and unparseable entries are dropped. ClientAuth is left
// at NoClientCert: M1 keeps the apiserver's AlwaysAllow posture, so the proxy
// connects without a client cert.
func kubeletServingTLS(nodeName string, nodeIPs ...string) (*tls.Config, error) {
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	for _, s := range nodeIPs {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if slices.ContainsFunc(ips, ip.Equal) {
			continue
		}
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
