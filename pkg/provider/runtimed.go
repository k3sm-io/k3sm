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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
	"k8s.io/utils/clock"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
	"k3sm.io/runtimed/pkg/mount"
	runtimed "k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// resyncInterval is the period of the GetPodStatus backstop poll that recovers
// any status event the streaming watch dropped (the runtime's broker drops on a
// full subscriber buffer). It bounds staleness independent of the stream.
const resyncInterval = 10 * time.Second

// runtimedRuntime is the Runtime backed by runtimed's in-process node runtime
// (runtimev1.RuntimeServer via runtime.New): OCI pull → clonefile → ad-hoc-sign
// → Seatbelt confine. It translates corev1.Pod ⇄ the runtime PodBox/PodStatus
// contract, deriving the corev1 fields runtimed's lossy renderer omits.
//
// Concurrency: mu guards the per-pod bookkeeping (the stable StartTime and the
// last-seen Pod spec keyed by pod id). The wrapped runtime is itself
// concurrency-safe. The status callback set by Watch runs OUTSIDE mu.
type runtimedRuntime struct {
	rt       runtimev1.RuntimeServer
	nodeName string
	nodeIP   string
	rootfs   string
	dyldShim string
	// resolverVIP and clusterDomain are the cluster DNS inputs buildBox feeds
	// dns.PodDNSConfig (per-pod namespace) to derive the K3SM_DNS_* env the DYLD
	// getaddrinfo shim reads — so an in-pod unqualified Service lookup expands and
	// resolves against the cluster DNS VIP. They mirror RuntimedConfig.ResolverVIP /
	// .ClusterDomain.
	resolverVIP   string
	clusterDomain string
	// deniedSocks are AF_UNIX socket paths every pod's SBPL must deny connect()
	// to — the root k3sm-netd helper socket and the runtimed control socket, so a
	// same-uid (_k3sm) pod cannot drive a privileged daemon. Threaded onto each
	// PodBox's SandboxProfile (apis SandboxProfile.denied_unix_socket_paths).
	//
	// It is the UNION of the non-omittable base set this package derives
	// (baseSocketDenies) and whatever the caller supplied in
	// RuntimedConfig.DeniedUnixSocketPaths — sorted and deduplicated once, at
	// construction, so buildBox stamps a settled value.
	deniedSocks []string
	log         *slog.Logger

	// resolver supplies ConfigMap/Secret data for the M2.1 env resolution the
	// provider performs before sending the box to runtimed (runtimed reads only
	// literal env). It is the SAME resolver wired into runtimed's Deps for volume
	// materialization. nil ⇒ data-backed env/volumes fail closed.
	resolver mount.Resolver

	// network is the per-node pod-IP seam (the podnet adapter, M10.1) — the SAME
	// instance wired into runtimed's Deps.Network, so the provider's
	// allocate-before-translate Setup and the runtimed-side seam Setup are one
	// idempotent authority. nil ⇒ podIP ≈ nodeIP (the --network none / no-datapath
	// posture; runtimed then keeps its single-node NodeNetwork).
	network PodNetwork

	// clk, dial, and probeTransport are the provider-served probe seams (M2.2):
	// the clock that schedules probe loops and the http/tcp I/O the checks use.
	// Production defaults are wired in newRuntimedWith; tests inject fakes.
	clk            clock.Clock
	dial           dialFunc
	probeTransport http.RoundTripper

	// client force-deletes a pod from the apiserver the instant its containers are
	// torn down. Virtual Kubelet's PodController (v1.12.0) otherwise delays the
	// API-side delete of a running-then-deleted pod by the FULL
	// deletionGracePeriodSeconds: its prompt path (syncPodInProvider force-deleting
	// on !running) is reachable only via the informer, whose podShouldEnqueue →
	// podsEqual ignores .status, so a terminal NotifyPods report can't trigger it.
	// runtimed already stopped the pod synchronously in DeletePod, so a grace-0
	// delete here is correct and safe (VK's later delayed delete no-ops on NotFound).
	// nil in unit tests that don't exercise the API removal.
	client kubernetes.Interface

	// recorder emits the pod lifecycle Events the runtimed path owns.
	recorder record.EventRecorder

	mu      sync.Mutex
	track   map[string]*podTrack  // pod id -> bookkeeping
	probers map[string]*podProber // pod id -> provider-served probe runner (M2.2)
	notify  func(*corev1.Pod)
}

// podTrack is the provider-side bookkeeping the runtime does not retain: a stable
// StartTime (set once at CreatePod, never regenerated) and the last Pod object
// (for namespace/name lookup and status reconstruction by pod id).
type podTrack struct {
	pod       *corev1.Pod
	startTime metav1.Time

	// readyMu guards lastReady, the last PodReady condition buildStatus computed for
	// this pod. It is a STABLE prior for readyTransitionTime so PodReady's
	// LastTransitionTime flips only on a real status change — pod (the desired-spec
	// object) never carries the computed PodReady, so without this the LTT would reset
	// to Now() every resync tick (see buildStatus). readyMu is separate from r.mu
	// because GetPods reconstructs status OUTSIDE r.mu.
	readyMu   sync.Mutex
	lastReady corev1.PodCondition

	// restartMu guards restarts — the per-container exit-driven restart
	// bookkeeping of the B26 authority (runtimed_restart.go): the termination
	// idempotency latch, the CrashLoopBackOff schedule, and the pending-re-exec
	// state the status overlay renders. Separate from r.mu for the same reason
	// as readyMu (buildStatus runs outside r.mu); lock order is r.mu →
	// restartMu, never the reverse.
	restartMu sync.Mutex
	restarts  map[string]*containerRestart // container name -> restart bookkeeping

	// hookMu guards postStart — the per-container postStart hook bookkeeping of
	// the B39 fidelity path (poststart.go): the pending/failed readiness gate the
	// status overlay reads, and the pod-scoped cancel of each in-flight hook.
	// Separate from r.mu for the same reason as readyMu (buildStatus runs outside
	// r.mu); it is never held together with r.mu or restartMu.
	hookMu    sync.Mutex
	postStart map[string]*postStartHook // container name -> postStart bookkeeping
}

// RuntimedConfig configures a runtimedRuntime.
type RuntimedConfig struct {
	// NodeName is the registering node's name.
	NodeName string
	// Recorder receives the pod lifecycle Events the provider emits.
	Recorder record.EventRecorder
	// NodeIP is the node InternalIP stamped as HostIP on every pod status.
	NodeIP string
	// Root is runtimed's on-disk root (image cache + pod dirs); empty uses the
	// runtimed default (/var/lib/k3sm).
	Root string
	// DyldShim, when set, is the getaddrinfo DNS shim dylib injected into each
	// pod via the PodBox annotation runtimed maps to DYLD_INSERT_LIBRARIES.
	DyldShim string
	// PathShim, when set, is the path-rebase DYLD shim dylib runtimed injects into a
	// mounting container so an absolute volume mount resolves under the pod data
	// volume (no chroot). Empty leaves a pod's absolute mount path reaching the host.
	PathShim string
	// ResolverVIP is the cluster DNS Service VIP (10.43.0.10) the per-pod Seatbelt
	// egress allow-list is scoped to (threaded into runtimed's sandbox.Posture), so
	// a confined pod's DNS reaches the node-local resolver. Empty leaves runtimed's
	// built-in default (sandbox.DefaultResolverVIP), which is NOT the k3sm VIP — the
	// commands always set it from the cluster DNS VIP.
	ResolverVIP string
	// ClusterDomain is the cluster DNS suffix (e.g. "cluster.local") buildBox feeds
	// dns.PodDNSConfig to build the in-pod shim search list. It MUST match the served
	// zone the per-node resolver answers for (the same --cluster-domain the
	// resolver is started with): a mismatch makes every unqualified Service lookup
	// NXDOMAIN. Empty defaults to dns.DefaultClusterDomain ("cluster.local",
	// darwin-net) inside PodDNSConfig.
	ClusterDomain string
	// APIServerVIP is the in-cluster Kubernetes API Service VIP (the kubernetes
	// ClusterIP, 10.43.0.1) the per-pod Seatbelt egress is ADDITIONALLY scoped to,
	// so a confined pod's in-cluster client-go (in-pod kubectl) can reach the API
	// VIP. Empty emits no API-server egress rule.
	APIServerVIP string
	// DeniedUnixSocketPaths are ADDITIONAL AF_UNIX socket paths every pod's SBPL
	// denies connect() to (the root k3sm-netd helper socket): pods run as the same
	// _k3sm uid as the legitimate helper client, so the socket must be denied at the
	// sandbox so a pod cannot drive the privileged daemon. Threaded as data because
	// runtimed cannot import darwin-net.
	//
	// It EXTENDS, and can never replace or shrink, the base deny-set the provider
	// derives for itself (baseSocketDenies) — an empty value still yields a
	// profile that denies the runtimed control socket.
	DeniedUnixSocketPaths []string
	// Network is the pod-IP seam (the podnet adapter over darwin-net's IPAM,
	// M10.1), shared verbatim with the embedded runtimed daemon (Deps.Network) so
	// there is exactly ONE allocator: the provider's CreatePod resolves the pod's
	// /32 through it BEFORE translation (box.PodIp + the downward-API status.podIP
	// env carry it), and runtimed's later seam Setup — idempotent per podID —
	// returns the SAME address. nil keeps runtimed's single-node NodeNetwork
	// (podIP ≈ NodeIP): the explicit --network none / no-datapath posture, never a
	// silent production fallback (the commands fail fast via the runtimed
	// preflight instead).
	Network PodNetwork
	// Client is the apiserver client the provider resolves ConfigMap/Secret data,
	// SA tokens (M2.1 volumes/env), and imagePullSecret credentials (M2.6) with —
	// runtimed never talks to the apiserver. nil disables data-backed
	// volumes/env/credentials (they fail closed / pull anonymously).
	Client kubernetes.Interface
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// NewRuntimed builds a runtimedRuntime, constructing the in-process runtime with
// production defaults (real image puller/signer, the exec-shim Seatbelt backend,
// posix_spawn/kqueue supervisor). It returns an error if the runtime cannot be
// constructed (e.g. its cache dir).
func NewRuntimed(cfg RuntimedConfig) (*runtimedRuntime, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// runtimed never talks to the apiserver: the provider (which holds the client)
	// supplies the volume Resolver + imagePullSecret CredentialResolver. nil client
	// ⇒ nil seams ⇒ data-backed volumes fail closed, pulls are anonymous.
	var resolver mount.Resolver
	var creds runtimed.CredentialResolver
	if cfg.Client != nil {
		resolver = newKubeResolver(cfg.Client)
		creds = newKubeCredentials(cfg.Client)
	}
	// The pod network runtimed drives: the injected podnet adapter (per-pod /32
	// lo0 aliases + the startup stale-alias reconcile) when configured, else the
	// single-node NodeNetwork pinned to this node's IP (podIP ≈ nodeIP — the
	// documented --network none posture).
	var network supervisor.PodNetwork = supervisor.NodeNetwork{IP: cfg.NodeIP}
	if cfg.Network != nil {
		network = cfg.Network
	}
	rt, err := runtimed.New(runtimed.Config{
		Root:           cfg.Root,
		RuntimeVersion: "k3sm-m1",
		Logger:         log,
		// Scope each pod's Seatbelt egress to the cluster DNS + API VIPs so a
		// confined pod's DNS and in-pod client-go reach the node-local resolver /
		// API VIP (M3.3). runtimed threads these into its per-pod sandbox.Posture.
		ResolverVIP:  cfg.ResolverVIP,
		APIServerVIP: cfg.APIServerVIP,
		PathShimPath: cfg.PathShim,
	}, runtimed.Deps{
		Resolver:    resolver,
		Credentials: creds,
		Network:     network,
	})
	if err != nil {
		return nil, fmt.Errorf("init runtimed: %w", err)
	}
	// Startup pod reap — MUST run here, in-process, before any CreatePod can be
	// served. The embedded node drives this Runtime by direct RPC and never runs
	// runtime.Server.Serve, so runtimed's own once-before-serve reap never fires on
	// the shipped path: the reaper existed but was UNREACHABLE here, leaving pod
	// process groups a prior `launchctl kickstart -k` orphaned onto launchd running
	// (holding ports, surviving uninstall). This is the exact sibling of the M10.1
	// network startup reconcile, and for the exact same reason — see the comment
	// block at cmd/k3sm/node.go's netAdapter.ReconcileStartup call.
	//
	// It is sourced HERE, in the constructor, rather than in cmd: a caller cannot
	// omit it, and the wiring is unit-testable without a live node (cmd is a thin
	// main).
	//
	// DEGRADES, it does not fail closed — the one way it differs from that network
	// sibling, which returns its error and aborts node startup. ReapOrphanedPods
	// always returns nil by contract (an unreadable reap store alerts and skips the
	// reap): a best-effort orphan store is not a scheduling precondition, and
	// propagating its I/O fault would exit main and launchd-crash-loop the node.
	// The returned error is therefore checked-and-logged, never propagated — do NOT
	// "harden" this into a startup failure.
	if err := rt.ReapOrphanedPods(); err != nil {
		log.Error("startup pod reap reported an error (degraded, node continues)", "err", err)
	}
	return newRuntimedWith(rt, cfg, resolver, log), nil
}

// newRuntimedWith wraps an existing runtime server (tests inject a fake) with the
// volume/env Resolver. The Summary API (kubectl top) is served off the runtime's
// typed ListPodStats RPC, so no per-pod-metrics capability is captured here.
func newRuntimedWith(rt runtimev1.RuntimeServer, cfg RuntimedConfig, resolver mount.Resolver, log *slog.Logger) *runtimedRuntime {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Startup visibility for BOTH pod-support shims: an empty dyld_shim (the
	// getaddrinfo shim was not resolved beside the binary) or a wrong resolver_vip
	// silently leaves pods on the system resolver (cluster names NXDOMAIN), and an
	// empty path_shim silently ENOENTs every ABSOLUTE volume-mount path in-pod
	// (runtimed injects no path rebase).
	//
	// Both keys are logged UNCONDITIONALLY, empty value included: path_shim was
	// omitted from this line while its dns sibling was logged, so an absent
	// path-rebase shim — the exact cause of the in-pod ENOENTs — was INVISIBLE in
	// the server log and got mis-diagnosed as another subsystem. An absent shim
	// must read as empty here, never as a missing key.
	recorder := cfg.Recorder
	if recorder == nil {
		recorder = nopRecorder{}
	}
	log.Info("runtimed provider configured",
		"dyld_shim", cfg.DyldShim,
		"path_shim", cfg.PathShim,
		"resolver_vip", cfg.ResolverVIP,
		"cluster_domain", cfg.ClusterDomain)
	return &runtimedRuntime{
		rt:            rt,
		nodeName:      cfg.NodeName,
		nodeIP:        cfg.NodeIP,
		rootfs:        cfg.Root,
		dyldShim:      cfg.DyldShim,
		resolverVIP:   cfg.ResolverVIP,
		clusterDomain: cfg.ClusterDomain,
		// Derived HERE, in the one constructor production and the fake-injected
		// tests share, so no caller can construct a provider whose pods are missing
		// the base deny-set.
		deniedSocks:    unionSocketDenies(baseSocketDenies(cfg.Root), cfg.DeniedUnixSocketPaths),
		resolver:       resolver,
		network:        cfg.Network,
		client:         cfg.Client,
		log:            log,
		recorder:       recorder,
		clk:            clock.RealClock{},
		dial:           (&net.Dialer{}).DialContext,
		probeTransport: newProbeTransport(),
		track:          map[string]*podTrack{},
		probers:        map[string]*podProber{},
	}
}

// baseSocketDenies returns the AF_UNIX deny-set the provider adds to every
// pod profile ON ITS OWN AUTHORITY: the runtimed control socket, in both
// spellings a daemon can serve it at. root is RuntimedConfig.Root (empty ⇒ the
// runtime default work-dir).
//
// It is derived rather than accepted from the caller because a deny the producer
// must remember to list is a deny that gets forgotten — the caller-supplied list
// (RuntimedConfig.DeniedUnixSocketPaths) named the k3sm-netd helper socket and
// not this one. Callers EXTEND this set; they cannot shrink it.
//
// TWO SPELLINGS, and neither implies the other:
//
//   - runtimed.DefaultSocketPath — the absolute default a daemon started without
//     an explicit socket path listens on, wherever its work-dir happens to be; and
//   - <root>/run/runtimed.sock — a work-dir-derived spelling NO code path serves
//     today. The daemon takes its socket from --socket, defaulting to the
//     absolute const above and never derived from --root, so this entry is cheap
//     insurance against a future root-derived socket rather than a description of
//     current behaviour. Stated plainly because a maintainer who checks the
//     stronger claim would find no such derivation and delete the entry as dead.
//
// This mirrors the SBPL generator's own posture resolution, which pins the
// ABSOLUTE run-dir into the file-deny set in addition to the work-dir-derived one
// for exactly this asymmetry (see sandbox.RunSubdir). Both leaf names are taken
// from runtimed's exported const so a rename upstream cannot leave a deny
// guarding a socket nobody serves. In the default posture the two spellings
// coincide and only one is emitted.
//
// WHAT THIS BUYS, precisely: the node builds its runtime IN-PROCESS (NewRuntimed
// → runtime.New), and the installed launch daemons do not include a standalone
// k3sm-runtimed, so on a stock install there is no socket being served and no
// live channel this closes. It PRE-POSITIONS the rule — a channel can never
// appear before the deny that covers it — and it fences the standalone
// k3sm-runtimed posture used in a lab.
//
// WHAT IT DOES NOT COVER. A Seatbelt path-deny is not a capability boundary:
//
//   - a daemon started with a different --socket path: this is a const plus a
//     work-dir derivation and does not track that flag;
//   - any control endpoint reachable over TCP/localhost, which the profile's
//     allow_network stanza permits outright; and
//   - a socket fd already open and inherited across exec, which no path deny can
//     revoke.
//
// netd's socket is in the base set for the SAME reason, and deliberately so: the
// node command still passes it, but a deny that only exists because a caller
// remembered to pass it is the exact defect this base set exists to remove — and
// netd being the ONE the caller did remember is not a reason to leave it the one
// that can be forgotten. Both are unioned, so the caller's list stays additive.
func baseSocketDenies(root string) []string {
	if root == "" {
		root = sandbox.DefaultWorkDir
	}
	leaf := filepath.Base(runtimed.DefaultSocketPath)
	return []string{
		runtimed.DefaultSocketPath,
		filepath.Join(root, sandbox.RunSubdir, leaf),
		netd.DefaultSocketPath,
		filepath.Join(root, sandbox.RunSubdir, filepath.Base(netd.DefaultSocketPath)),
	}
}

// stampSocketDenies merges the provider's non-omittable deny-set onto sp.
//
// It is a method rather than two inline lines so the union is FALSIFIABLE: no
// end-to-end case can tell a union from a plain assignment today, because
// nothing in the translation path pre-sets the field — so without a seam to
// assert through, a regression to `=` would be caught by nothing. A nil profile
// is a no-op; it fails closed further down, where the generator refuses a box
// with no data volume.
func (r *runtimedRuntime) stampSocketDenies(sp *runtimev1.SandboxProfile) {
	if sp == nil {
		return
	}
	sp.DeniedUnixSocketPaths = unionSocketDenies(sp.GetDeniedUnixSocketPaths(), r.deniedSocks)
}

// unionSocketDenies returns the sorted, deduplicated union of the socket-path
// sets, dropping empty entries. Union — never replace — is what keeps a
// caller-supplied list additive with respect to the base deny-set.
func unionSocketDenies(sets ...[]string) []string {
	var out []string
	for _, set := range sets {
		for _, p := range set {
			if p != "" {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// NodeCapabilities are the node-capability facts runtimed advertises as
// GetRuntimeInfo RuntimeConditions and the node command turns into truthful node
// labels. They travel as ONE struct, from ONE RPC, deliberately: three separate
// probes could each observe a DIFFERENT daemon state and produce an incoherent
// label set (k3sm.io/rosetta-linux stamped from a later observation while
// k3sm.io/virtualization was deleted from an earlier one). Every field fails CLOSED
// — the zero value advertises nothing (B103).
type NodeCapabilities struct {
	// VMBackend is the VMBackendAvailable condition: this host can run the vm
	// RuntimeClass (Virtualization.framework isSupported + the
	// com.apple.security.virtualization entitlement). Drives k3sm.io/virtualization (B1).
	VMBackend bool
	// RosettaHost is the RosettaHostAvailable condition: this host can translate
	// darwin/amd64 Mach-O payloads via Rosetta 2 on the NATIVE host-process spine.
	// Drives k3sm.io/rosetta.
	RosettaHost bool
	// RosettaGuest is the RosettaGuestAvailable condition: a Linux guest on this host
	// could translate linux/amd64 ELF payloads via Rosetta for Linux. It is only HALF
	// of k3sm.io/rosetta-linux — that label is RosettaGuest AND VMBackend, since
	// without the vm backend there is no guest to translate in (see
	// cmd/k3sm applyRosettaLabels).
	RosettaGuest bool
	// GPU is the host's GPU facts as runtimed reports them, carried VERBATIM from
	// GetRuntimeInfoResponse.gpu (the raw chip_brand keeps its spaces — the node-label
	// slug is derived by the advertiser, per the mlx.k3sm.io chip-slug rule). It drives
	// the mlx.k3sm.io/gpu extended resource and the mlx.k3sm.io chip/memory labels (see
	// cmd/k3sm applyGPUAdvertisement).
	//
	// nil means this daemon reports no GPU facts AT ALL — an older daemon — which is
	// DISTINCT from a report of a host with no usable GPU (present, MetalAvailable
	// false). The two are deliberately not collapsed here: they advertise the same
	// nothing, but only one of them is fixed by upgrading the daemon, and the consumer
	// says so in its log line. A pointer, unlike the bools above, is therefore a
	// three-state fact and its zero value still fails CLOSED.
	GPU *runtimev1.GPUFacts
}

// Capabilities probes runtimed ONCE and reports every node capability the node
// command labels from. One RPC for all three booleans is load-bearing: separate
// calls could straddle a daemon restart and yield a mutually-inconsistent label set.
// It fails CLOSED (the zero value — nothing advertised) on an RPC error, so a probe
// failure never FALSELY advertises a capability the node does not have.
func (r *runtimedRuntime) Capabilities(ctx context.Context) NodeCapabilities {
	info, err := r.rt.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		r.log.Warn("node-capability probe failed; advertising no capabilities (fail-closed)", "err", err)
		return NodeCapabilities{}
	}
	caps := nodeCapabilitiesFromInfo(info)
	// Log at the boundary WITH each withheld capability's Reason: the condition's
	// Reason/Message is the only answer to "why is my node not labelled rosetta?",
	// and it is discarded once this returns a bare bool.
	logWithheldCapability(r.log, info, runtimed.ConditionVMBackendAvailable, caps.VMBackend)
	logWithheldCapability(r.log, info, runtimed.ConditionRosettaHostAvailable, caps.RosettaHost)
	logWithheldCapability(r.log, info, runtimed.ConditionRosettaGuestAvailable, caps.RosettaGuest)
	return caps
}

// Healthy reports whether runtimed considers itself able to serve pods, from the
// overall health flag on its runtime-info response (the conditions detail which
// subsystem is at fault; this is the summary the node's Ready condition needs).
//
// It fails CLOSED: a failed probe reports unhealthy, because a runtime that
// cannot answer is not a runtime that has answered yes. The caller debounces the
// verdict over consecutive samples, so one failed probe never reaches the node
// object on its own.
func (r *runtimedRuntime) Healthy(ctx context.Context) bool {
	info, err := r.rt.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		r.log.Warn("runtime health probe failed; reporting unhealthy (fail-closed)", "err", err)
		return false
	}
	if !info.GetHealthy() {
		r.log.Warn("runtime reports itself unhealthy", "conditions", len(info.GetConditions()))
	}
	return info.GetHealthy()
}

// nodeCapabilitiesFromInfo maps a GetRuntimeInfo response to the node capabilities.
// Pure — so the truthful-labeling mapping is unit-tested without a live runtimed.
//
// It fails CLOSED on every degenerate input: a nil response, an empty condition
// list, a condition ABSENT from the list (an older runtimed that predates the
// capability), and any status that is not explicitly TRUE — including UNKNOWN and
// the proto zero UNSPECIFIED, which a `!= FALSE` test would have read as capable.
// The condition Type strings are IMPORTED from runtimed, never restated here: the
// reader fails closed, so a typo would mean a permanently-absent label with no error
// anywhere — importing makes a producer/consumer rename a COMPILE error (B103).
func nodeCapabilitiesFromInfo(info *runtimev1.GetRuntimeInfoResponse) NodeCapabilities {
	return NodeCapabilities{
		VMBackend:    conditionTrue(info, runtimed.ConditionVMBackendAvailable),
		RosettaHost:  conditionTrue(info, runtimed.ConditionRosettaHostAvailable),
		RosettaGuest: conditionTrue(info, runtimed.ConditionRosettaGuestAvailable),
		// The GPU facts are a MESSAGE on the response, not a RuntimeCondition, so they
		// are read straight through rather than via conditionTrue. The getter is
		// nil-safe on both the response and the field, which is what makes the
		// older-daemon case (no gpu field) a nil that advertises nothing.
		GPU: info.GetGpu(),
	}
}

// conditionTrue reports whether info carries condType with status TRUE. FIRST match
// wins (a duplicated Type — which runtimed never emits — is resolved by the first
// occurrence, the documented verdict); an absent condition or any non-TRUE status is
// false.
func conditionTrue(info *runtimev1.GetRuntimeInfoResponse, condType string) bool {
	c := findRuntimeCondition(info, condType)
	return c.GetStatus() == runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
}

// findRuntimeCondition returns the FIRST condition of the given Type, or nil. The
// proto getters are nil-safe, so callers may use the result unchecked.
func findRuntimeCondition(info *runtimev1.GetRuntimeInfoResponse, condType string) *runtimev1.RuntimeCondition {
	for _, c := range info.GetConditions() {
		if c.GetType() == condType {
			return c
		}
	}
	return nil
}

// logWithheldCapability logs, at the capability boundary, why a capability is NOT
// advertised — carrying the condition's Reason/Message (the runtimed reason
// vocabulary: NotInstalled / TranslationFailed / NotSupported / QueryFailed /
// VMBackendUnavailable) so an operator can answer "why is my node not labelled
// rosetta?" from server.log. An advertised capability is logged at Debug; an ABSENT
// condition (an older runtimed) is reported as such rather than as a silent false.
//
// It names the CONDITION, never a k3sm.io/* label key: this package holds no label
// vocabulary (the keys live in pkg/runtimeclass, next to the selector that consumes
// them), and one condition does not map 1:1 to one label anyway — rosetta-linux is a
// conjunction. The paired line naming the LABEL the verdict resolved to is emitted by
// cmd/k3sm's setLabelPresence / applyRosettaLabels, which own that decision.
func logWithheldCapability(log *slog.Logger, info *runtimev1.GetRuntimeInfoResponse, condType string, advertised bool) {
	if advertised {
		log.Debug("node capability advertised", "condition", condType)
		return
	}
	c := findRuntimeCondition(info, condType)
	if c == nil {
		log.Info("node capability withheld: runtimed does not report this condition (older daemon); failing closed",
			"condition", condType)
		return
	}
	log.Info("node capability withheld by runtimed; the node will NOT be labelled for it",
		"condition", condType, "status", c.GetStatus().String(), "reason", c.GetReason(), "message", c.GetMessage())
}

// Compile-time check that runtimedRuntime satisfies the Runtime seam and the
// optional StatsSource capability (the Summary API surface, M2.3).
var (
	_ Runtime        = (*runtimedRuntime)(nil)
	_ StatsSource    = (*runtimedRuntime)(nil)
	_ HealthReporter = (*runtimedRuntime)(nil)
)

// podIP resolves the pod's IP BEFORE translation — the M10.1 ordering fix: the
// /32 must exist before toPodBox so box.PodIp, the downward-API status.podIP
// env fieldRefs (resolvePodBoxEnv reads box.GetPodIp()), the SBPL bind
// discipline, and pod status all carry ONE authority. The runtimed-side seam's
// later Setup for the same podID is idempotent and returns the SAME address.
//
// Branches (each documented, never a silent fallback):
//   - no adapter (nil network — the --network none posture): podIP ≈ nodeIP.
//   - spec.hostNetwork: the pod shares the node's addresses — no /32. The pod is
//     marked on the adapter so the runtimed-side seam Setup (which the
//     host-process spine calls unconditionally) also resolves it to the node IP.
//   - vm RuntimeClass: no lo0 /32 (which would make the host answer for the
//     guest and blackhole it), so this branch returns the node IP and routes the
//     pod away from the host-process Setup. The guest is MEANT to own its own
//     address inside its netstack via darwin-net podnet.Network.SetupGuest, but
//     that is NOT WIRED: SetupGuest is implemented and unit-tested in
//     darwin-net/pkg/podnet/guest.go, and has no production caller anywhere —
//     there is no transport carrying a GuestNetwork to runtimed yet (the
//     consumer-side supervisor.GuestNetwork seam, M5.1-d2 / B6). Until it
//     lands, a vm pod REPORTS THE NODE IP rather than its guest address; that
//     is a placeholder, not the intended end state. See
//     k3sm/pkg/runtimeclass/doc.go for the lab-gated remainder.
//   - otherwise: the podnet /32. Pool exhaustion surfaces as a distinguishable
//     error (errors.Is(err, podnet.ErrPoolExhausted) holds through the wrap).
func (r *runtimedRuntime) podIP(ctx context.Context, pod *corev1.Pod) (string, error) {
	if r.network == nil {
		return r.nodeIP, nil
	}
	id := string(pod.UID)
	if pod.Spec.HostNetwork {
		r.network.MarkHostNetwork(id)
		return r.nodeIP, nil
	}
	if backend, err := podSandboxBackend(pod); err == nil && backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		// An unknown RuntimeClass error is NOT handled here — toPodBox owns that
		// fail-closed rejection; this branch only routes a resolved vm pod away
		// from the host-process /32.
		return r.nodeIP, nil
	}
	ip, err := r.network.Setup(ctx, id)
	if err != nil {
		if errors.Is(err, podnet.ErrPoolExhausted) {
			return "", fmt.Errorf("pod ip pool exhausted on node %s (253 pods/node): allocate pod ip for %s/%s: %w", r.nodeName, pod.Namespace, pod.Name, err)
		}
		return "", fmt.Errorf("allocate pod ip for %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	return ip, nil
}

// releasePodNetwork tears down the pod's network allocation, log-and-continue —
// a teardown error never blocks pod deletion. runtimed's DeletePod RPC already
// tears the seam down on its side; this provider-side call (idempotent no-op
// then) covers the paths where the RPC failed or the pod never reached the
// runtime (a translate failure after allocation), so a churned pod cannot leak
// one of the 253 node addresses. The adapter's startup sweep is the backstop.
func (r *runtimedRuntime) releasePodNetwork(pod *corev1.Pod) {
	if r.network == nil {
		return
	}
	if err := r.network.Teardown(string(pod.UID)); err != nil {
		r.log.Warn("pod network teardown", "namespace", pod.Namespace, "name", pod.Name, "err", err)
	}
}

// buildBox translates pod to a PodBox and resolves its env into LITERAL values —
// runtimed reads only EnvVar.value and never talks to the apiserver, so the
// provider resolves configMap/secret/envFrom (via its Resolver) and downward-API
// (via the node identity) here, before the box crosses the runtime boundary.
// podIP is the pod's already-resolved IP (see podIP — allocated BEFORE this
// translation so the box and its resolved env carry the real /32).
func (r *runtimedRuntime) buildBox(ctx context.Context, pod *corev1.Pod, podIP string) (*runtimev1.PodBox, error) {
	// Per-pod cluster DNS config: the search list is namespace-scoped
	// (<ns>.svc.<domain>, …) so an unqualified Service name in this pod's namespace
	// resolves first. toPodBox injects it (DNSPolicy-gated) into the containers.
	dnsCfg := dns.PodDNSConfig(r.resolverVIP, r.clusterDomain, pod.Namespace)
	// B20a: a ClusterFirst pod's spec.dnsConfig additively augments the cluster base
	// (extra search domains appended+deduped, ndots override). The merge is GATED here
	// on the cluster-DNS policy — NOT left to injectClusterDNSEnv's downstream gate —
	// so the B20a/B20b seam is structural: a None/Default pod gets the UNMERGED base,
	// so when B20b makes None inject its own config it can't inherit a cluster-base
	// merge. dnsConfigOverride does the corev1→discrete-params extraction (k3sm is the
	// corev1-aware layer); dns.MergeDNSConfig can only ADD search/ndots, never repoint
	// the cluster server VIP.
	if clusterDNSPolicy(pod.Spec.DNSPolicy) && pod.Spec.DNSConfig != nil {
		searches, ndots := dnsConfigOverride(pod.Spec.DNSConfig)
		var dropped int
		dnsCfg, dropped = dns.MergeDNSConfig(dnsCfg, searches, ndots)
		if dropped > 0 {
			// The pod's merged search list exceeded the in-pod cap (MaxSearchDomains, a
			// deliberate divergence from upstream's 32); the tail was truncated. Log once
			// here at the corev1-aware boundary WITH pod identity — the darwin-net merge
			// primitive stays pure and returns the count rather than logging blind.
			r.log.WarnContext(ctx, "pod dnsConfig search list truncated to the in-pod cap",
				"namespace", pod.Namespace, "name", pod.Name, "dropped", dropped, "cap", dns.MaxSearchDomains)
		}
	}
	box, err := toPodBox(pod, podIP, r.podRoot(string(pod.UID)), r.dyldShim, dnsCfg)
	if err != nil {
		return nil, err
	}
	// Deny every pod the daemon control sockets: pods share the _k3sm uid with the
	// legitimate daemon clients, so the sandbox is where a privileged daemon is
	// fenced off from the workload.
	//
	// UNCONDITIONAL on the deny-set being non-empty, and a UNION rather than an
	// assignment. An emptiness guard would let a caller that supplied no paths
	// render a profile with no socket-deny stanza at all — indistinguishable, in the
	// generated profile, from "nothing needed denying", which is the worst shape a
	// default-deny control can take; and a bare `=` would drop any deny a future
	// translation step had already put on the box.
	//
	// NO ASYMMETRY: baseSocketDenies carries BOTH daemon sockets non-omittably.
	// The node command still passes netd's, and that stays harmless because this
	// is a union — but a deny that exists only because a caller remembered to pass
	// it is precisely the defect the base set removes, and netd being the one the
	// caller did remember is no reason to leave it the one that can be forgotten.
	r.stampSocketDenies(box.SandboxProfile)
	if err := resolvePodBoxEnv(ctx, box, r.nodeName, r.nodeIP, r.resolver); err != nil {
		return nil, err
	}
	// In-pod cluster-DNS visibility: log the FINAL injected state (after
	// resolvePodBoxEnv) so a "no such host" failure shows whether the getaddrinfo
	// shim (dyld annotation) and its K3SM_DNS_SERVER env actually landed on the box.
	if cs := box.GetContainers(); len(cs) > 0 {
		var dnsServer string
		for _, e := range cs[0].GetEnv() {
			if e.GetName() == "K3SM_DNS_SERVER" {
				dnsServer = e.GetValue()
				break
			}
		}
		r.log.Info("pod box cluster-DNS wiring",
			"pod", pod.Name,
			"dyld_annotation", box.GetAnnotations()[dyldInsertAnnotation],
			"k3sm_dns_server", dnsServer,
			"dns_policy", string(pod.Spec.DNSPolicy))
	}
	return box, nil
}

// CreatePod translates the pod to a PodBox and asks the runtime to start it. The
// runtime returns a typed failure inside the response (the RPC itself returns
// nil) when the fail-closed gate rejects the pod; CreatePod surfaces that as an
// error so VK marks the pod failed.
func (r *runtimedRuntime) CreatePod(ctx context.Context, pod *corev1.Pod) error {
	// Bind the pod's ServiceAccount to the request context so the shared volume
	// Resolver mints the in-pod-API token (projected SA-token volume) against the
	// RIGHT SA — runtimed threads this ctx to mount.Materialize in-process (M2.4).
	ctx = withServiceAccount(ctx, podServiceAccount(pod))
	id := string(pod.UID)
	start := metav1.Now()
	r.log.Info("CreatePod", "namespace", pod.Namespace, "name", pod.Name)
	// M10.1 ordering (BINDING): allocate the pod's /32 BEFORE translation/env
	// resolution so box.PodIp and the status.podIP downward-API env carry it. A
	// translate failure below does NOT release it here (an idempotent retry or
	// the eventual DeletePod → releasePodNetwork reclaims it; auto-releasing
	// would also rip a live pod's alias away on an UpdatePod translate error).
	podIP, err := r.podIP(ctx, pod)
	if err != nil {
		// Log here (not just return) so the failure reaches server.log — VK's own
		// create-error log does not, so a pod stuck Pending is otherwise invisible.
		r.log.Error("CreatePod: allocate podIP", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		return fmt.Errorf("create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	box, err := r.buildBox(ctx, pod, podIP)
	if err != nil {
		r.log.Error("CreatePod: translate/buildBox", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		return fmt.Errorf("translate pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	r.mu.Lock()
	old := r.track[id]
	if old != nil {
		start = old.startTime // idempotent: keep the original start time
	}
	t := &podTrack{pod: pod.DeepCopy(), startTime: start}
	r.track[id] = t
	r.mu.Unlock()
	if old != nil {
		// The replaced track's pending re-execs must not fire against the new
		// track's bookkeeping (their goroutines would clear nothing and could
		// double-restart a container the fresh CreatePod just spawned), and its
		// in-flight postStart hooks belong to the containers being replaced.
		old.cancelRestarts()
		old.cancelPostStart()
	}

	resp, err := r.rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		r.log.Error("CreatePod: runtimed RPC", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		return fmt.Errorf("runtimed create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		r.log.Error("CreatePod: runtimed rejected the pod", "namespace", pod.Namespace, "name", pod.Name,
			"message", e.GetMessage(), "reason", resp.GetFailureReason().String())
		return fmt.Errorf("runtimed create pod %s/%s rejected: %s (%s)", pod.Namespace, pod.Name, e.GetMessage(), resp.GetFailureReason().String())
	}
	// Start the provider-served probe runner (M2.2): the VK provider replaces the
	// kubelet, so it must execute the pod's probes itself. No-op for a probe-free
	// pod; idempotent for a repeated CreatePod.
	r.startProber(pod, resp.GetStatus().GetPodIp())
	// Dispatch each container's postStart hook (B10 + the B39 fidelity: the
	// container is held NotReady until the hook completes, a failure kills it per
	// its restart policy, and the hook's lifetime is the pod's). Each hook runs in
	// its own goroutine so CreatePod and the reconcile loop never block on it.
	r.runPostStart(t, pod, resp.GetStatus().GetPodIp())
	r.dispatch(id, resp.GetStatus())
	return nil
}

// UpdatePod forwards labels/annotations changes (the only fields runtimed
// updates in place); other changes need a recreate and are reported by the
// runtime as a typed precondition failure, surfaced here as an error.
func (r *runtimedRuntime) UpdatePod(ctx context.Context, pod *corev1.Pod) error {
	// Same SA binding as CreatePod, in case the runtime re-materializes volumes on
	// an in-place update (M2.4).
	ctx = withServiceAccount(ctx, podServiceAccount(pod))
	id := string(pod.UID)
	r.mu.Lock()
	if t, ok := r.track[id]; ok {
		t.pod = pod.DeepCopy()
	}
	r.mu.Unlock()

	// Same allocate-before-translate ordering as CreatePod; Setup is idempotent
	// per podID, so an update re-reads the pod's existing /32 (one authority).
	podIP, err := r.podIP(ctx, pod)
	if err != nil {
		return fmt.Errorf("update pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	box, err := r.buildBox(ctx, pod, podIP)
	if err != nil {
		return fmt.Errorf("translate pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	resp, err := r.rt.UpdatePod(ctx, &runtimev1.UpdatePodRequest{Pod: box})
	if err != nil {
		return fmt.Errorf("runtimed update pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		return fmt.Errorf("runtimed update pod %s/%s: %s", pod.Namespace, pod.Name, e.GetMessage())
	}
	r.dispatch(id, resp.GetStatus())
	return nil
}

// DeletePod runs the pod's preStop hooks (B10), then stops the pod's processes and
// forgets the bookkeeping. Idempotent. The SIGTERM→SIGKILL grace window is the pod's
// termination budget (deletion/termination grace, k8s 30s default) MINUS the preStop
// wall-time (floored at 1s), since runtimed treats a 0 grace as immediate-kill (M2.3).
func (r *runtimedRuntime) DeletePod(ctx context.Context, pod *corev1.Pod) error {
	id := string(pod.UID)
	// Cancel any in-flight postStart hook FIRST (B39): a hook must not outlive the
	// pod, and termination must not wait on one — upstream tears the pod worker's
	// context down on delete, which aborts a running hook.
	if t := r.trackByID(id); t != nil {
		t.cancelPostStart()
	}
	// Serve preStop hooks BEFORE termination (B10): runtimed sends SIGTERM
	// synchronously inside DeletePod, so the provider runs preStop first and passes
	// the RESIDUAL grace (the budget minus the hook's wall-time, floored at 1s).
	// best-effort — a failed hook is logged inside runPreStop, the delete proceeds.
	grace := r.runPreStop(ctx, pod)
	_, err := r.rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: id, GracePeriodSeconds: grace})
	if err != nil {
		return fmt.Errorf("runtimed delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	// Stop the probe runner before forgetting the pod (stopProber waits for the
	// loops outside the lock, so no probe goroutine outlives the pod).
	r.stopProber(id)
	// Release the pod's /32 (log-and-continue; idempotent after runtimed's own
	// delete-path teardown) so pod churn never leaks a node pool address.
	r.releasePodNetwork(pod)
	r.mu.Lock()
	t := r.track[id]
	delete(r.track, id)
	r.mu.Unlock()
	if t != nil {
		// Abort any pending exit-driven re-exec (B26): no restart goroutine may
		// outlive the pod, and a deleted pod must never be re-spawned.
		t.cancelRestarts()
	}
	// Force-delete the pod from the apiserver now that runtimed has torn its
	// containers down (r.rt.DeletePod is synchronous). Virtual Kubelet would
	// otherwise leave a running-then-deleted pod in the API for the FULL
	// deletionGracePeriodSeconds — see the r.client field doc for why its prompt
	// path is unreachable via status. grace 0 = immediate; best-effort and
	// NotFound-tolerant (VK may have force-deleted it first; either order is fine).
	r.forceDeleteFromAPI(ctx, pod)
	return nil
}

// forceDeleteFromAPI removes pod from the apiserver with grace 0 so a
// terminated-then-deleted pod disappears promptly instead of lingering the whole
// deletionGracePeriodSeconds under VK's delayed-delete fallback. Best-effort: a nil
// client (unit tests) or a NotFound (already gone) is a no-op; any other error is
// logged and swallowed so the delete path never blocks on the API.
func (r *runtimedRuntime) forceDeleteFromAPI(ctx context.Context, pod *corev1.Pod) {
	if r.client == nil {
		return
	}
	zero := int64(0)
	err := r.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	if err != nil && !apierrors.IsNotFound(err) {
		r.log.Warn("force-delete pod from apiserver after teardown",
			"namespace", pod.Namespace, "name", pod.Name, "err", err)
	}
}

// GetPodStatus returns the named pod's status, NotFound if it is unknown.
func (r *runtimedRuntime) GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error) {
	id, _, pod, ok := r.lookup(namespace, name)
	if !ok {
		return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+name)
	}
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil {
		return nil, fmt.Errorf("runtimed get pod status %s/%s: %w", namespace, name, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		return nil, vkadapter.NotFoundf("pod %q not found in runtime", namespace+"/"+name)
	}
	t := r.trackByID(id)
	if t == nil {
		return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+name)
	}
	st := r.buildStatus(pod.DeepCopy(), t, resp.GetStatus(), r.proberFor(id))
	return &st, nil
}

// GetPods returns every tracked pod with its current status applied.
func (r *runtimedRuntime) GetPods(ctx context.Context) ([]*corev1.Pod, error) {
	r.mu.Lock()
	tracks := make([]*podTrack, 0, len(r.track))
	for _, t := range r.track {
		tracks = append(tracks, t)
	}
	r.mu.Unlock()

	out := make([]*corev1.Pod, 0, len(tracks))
	for _, t := range tracks {
		pod := t.pod.DeepCopy()
		resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: string(pod.UID)})
		if err == nil && (resp.GetError() == nil || resp.GetError().GetCode() == 0) {
			pod.Status = r.buildStatus(pod, t, resp.GetStatus(), r.proberFor(string(pod.UID)))
		}
		out = append(out, pod)
	}
	return out, nil
}

// buildStatus reconstructs the pod's corev1 status via toPodStatus, threading the
// track's last computed PodReady so PodReady.LastTransitionTime flips ONLY on a real
// status change — not every resync tick.
//
// pod here is a DeepCopy of t.pod, the IMMUTABLE desired-spec object (CreatePod /
// UpdatePod replace the pointer, and it never carries the computed PodReady). Without
// this seed, readyTransitionTime would never find a prior PodReady on the runtimed
// path and would reset LastTransitionTime to Now() on every backstop/watch tick —
// churning pod status (a kine write per resync per pod) and, worse, resetting the
// minReadySeconds availability window every ~10s so a Deployment never marks the pod
// available: a rolling-update stall, the very failure B79 fixes. The M0 HostProcess
// path is exempt (it persists computed status back onto rec.pod, a stable prior).
//
// Locking: t.readyMu guards lastReady because GetPods reconstructs status OUTSIDE
// r.mu (it snapshots tracks under the lock, then builds each unlocked), so concurrent
// GetPods/emit for the same track must not race on lastReady. The lock is held ONLY
// around the lastReady read and write — never across toPodStatus or the prober.
//
// buildStatus is also the B26 convergence point: every runtime status
// observation (stream emit, backstop GetPods, direct GetPodStatus, probe-driven
// publish) flows through here, so observeExits sees each container termination
// regardless of which path delivered it (idempotent per termination), and
// applyRestartOverlay renders the CrashLoopBackOff surface + Running phase hold
// on every published status while a re-exec is pending. B39's postStart readiness
// gate rides the same convergence, so no publish path can leak a Ready container
// whose postStart hook has not completed.
func (r *runtimedRuntime) buildStatus(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus, ps probeState) corev1.PodStatus {
	r.observeExits(pod, t, rs)
	t.readyMu.Lock()
	prior := t.lastReady
	t.readyMu.Unlock()
	if prior.Type == corev1.PodReady {
		// Seed the desired-spec copy's conditions with the last PodReady so
		// readyTransitionTime finds its prior status+LTT. PodReady is provider-owned,
		// so toPodStatus's carry-forward excludes it — no duplication.
		pod.Status.Conditions = append(pod.Status.Conditions, prior)
	}
	st := toPodStatus(pod, rs, r.nodeIP, t.startTime, ps)
	r.applyRestartOverlay(pod, t, st)
	// LAST, so its readiness re-derivation sees every other overlay's verdict: a
	// container whose postStart has not completed is NotReady, and the pod's
	// ContainersReady/PodReady follow (B39).
	r.applyPostStartOverlay(pod, t, st)
	if c := findPodCondition(st.Conditions, corev1.PodReady); c != nil {
		t.readyMu.Lock()
		t.lastReady = *c
		t.readyMu.Unlock()
	}
	return *st
}

// trackByID returns the track for pod id under r.mu, or nil if the pod was deleted.
func (r *runtimedRuntime) trackByID(id string) *podTrack {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.track[id]
}

// Watch drives the VK status callback off the runtime's streaming
// WatchPodStatus, with resync-on-stream-break plus a periodic GetPodStatus
// backstop. The goroutine's lifetime is bounded by ctx.
func (r *runtimedRuntime) Watch(ctx context.Context, cb func(*corev1.Pod)) {
	r.mu.Lock()
	r.notify = cb
	r.mu.Unlock()

	go r.runWatch(ctx)
	go r.runBackstop(ctx)
}

// runWatch consumes the runtime's WatchPodStatus stream, reconnecting whenever it
// breaks (the runtime re-sends current snapshots on every reconnect, so no event
// is lost across a break). It runs until ctx is cancelled.
func (r *runtimedRuntime) runWatch(ctx context.Context) {
	for ctx.Err() == nil {
		stream := newWatchStream(ctx)
		done := make(chan error, 1)
		go func() {
			done <- r.rt.WatchPodStatus(&runtimev1.WatchPodStatusRequest{}, stream)
		}()
		r.consume(ctx, stream, done)
		if ctx.Err() != nil {
			return
		}
		// Stream broke; brief backoff before resync to avoid a hot loop.
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// consume reads events off one stream until it ends or ctx is cancelled,
// dispatching each to the VK callback.
func (r *runtimedRuntime) consume(ctx context.Context, stream *watchStream, done <-chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case ev := <-stream.ch:
			if ev == nil {
				continue
			}
			r.emit(ev.GetStatus())
		}
	}
}

// runBackstop periodically reconciles every tracked pod via GetPodStatus,
// recovering any event the streaming watch dropped. It runs until ctx ends.
func (r *runtimedRuntime) runBackstop(ctx context.Context) {
	t := time.NewTicker(resyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pods, err := r.GetPods(ctx)
			if err != nil {
				continue
			}
			cb := r.callback()
			if cb == nil {
				continue
			}
			for _, p := range pods {
				cb(p.DeepCopy())
			}
		}
	}
}

// emit reconstructs the full Pod for a status event (by pod id) and runs the VK
// callback. An event for an untracked pod (already deleted) is dropped.
func (r *runtimedRuntime) emit(rs *runtimev1.PodStatus) {
	if rs == nil {
		return
	}
	id := rs.GetPodId()
	r.mu.Lock()
	t, ok := r.track[id]
	cb := r.notify
	pr := r.probers[id]
	var pod *corev1.Pod
	if ok {
		pod = t.pod.DeepCopy()
	}
	r.mu.Unlock()
	if !ok || cb == nil {
		return
	}
	var ps probeState
	if pr != nil {
		ps = pr
	}
	pod.Status = r.buildStatus(pod, t, rs, ps)
	cb(pod)
}

// dispatch runs the callback for a status returned synchronously by a mutating
// RPC (so VK sees the new state immediately, not only via the stream).
func (r *runtimedRuntime) dispatch(id string, rs *runtimev1.PodStatus) {
	if rs == nil {
		return
	}
	go r.emit(rs)
}

// callback returns the current VK callback under the lock.
func (r *runtimedRuntime) callback() func(*corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.notify
}

// lookup resolves a (namespace, name) to a pod id, its stable start time, and the
// tracked Pod object. The Pod is returned so the pod-less GetPodStatus path can
// carry forward / derive Status.QOSClass in toPodStatus (B12); callers that need
// only the id discard it. The returned *corev1.Pod is the tracked object, which is
// immutable once stored (CreatePod/UpdatePod replace the pointer under r.mu, never
// mutate the object in place), so reading it after the lock is released is safe.
func (r *runtimedRuntime) lookup(namespace, name string) (string, metav1.Time, *corev1.Pod, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.track {
		if t.pod.Namespace == namespace && t.pod.Name == name {
			return id, t.startTime, t.pod, true
		}
	}
	return "", metav1.Time{}, nil, false
}

// StatsSummary builds the kubelet Summary API snapshot kubectl top reads (M2.3),
// consuming the runtime's typed ListPodStats RPC (apis:M2.2). Each PodStats sample
// carries the proc_pid_rusage working-set footprint runtimed meters
// (ri_phys_footprint, NOT RSS), per-container; the provider maps it to the kubelet
// Summary shape and fills the stable per-pod StartTime from its own bookkeeping
// (the runtime sample carries only the sample timestamp). A pod runtimed does not
// sample (no memory limit ⇒ no metering in M2) is absent from the response and so
// from the summary.
func (r *runtimedRuntime) StatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error) {
	summary := &statsv1alpha1.Summary{Node: statsv1alpha1.NodeStats{NodeName: r.nodeName}}
	resp, err := r.rt.ListPodStats(ctx, &runtimev1.ListPodStatsRequest{})
	if err != nil {
		return nil, fmt.Errorf("runtimed list pod stats: %w", err)
	}
	for _, ps := range resp.GetPodStats() {
		if ps == nil {
			continue
		}
		summary.Pods = append(summary.Pods, toPodStats(ps, r.startTimeFor(ps.GetPodId())))
	}
	return summary, nil
}

// startTimeFor returns the stable StartTime the provider recorded for the pod id
// at CreatePod, or the zero time for an untracked pod (the runtime does not retain
// it). The Summary API reports the pod start, not the per-sample timestamp.
func (r *runtimedRuntime) startTimeFor(id string) metav1.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.track[id]; ok {
		return t.startTime
	}
	return metav1.Time{}
}

// toPodStats maps a runtime PodStats sample (the ListPodStats wire form) to the
// kubelet Summary API PodStats the VK summary handler serves. startTime is the
// provider's stable per-pod value; the working-set footprint flows through verbatim.
func toPodStats(ps *runtimev1.PodStats, startTime metav1.Time) statsv1alpha1.PodStats {
	out := statsv1alpha1.PodStats{
		PodRef:    statsv1alpha1.PodReference{Name: ps.GetName(), Namespace: ps.GetNamespace(), UID: ps.GetPodId()},
		StartTime: startTime,
		CPU:       toCPUStats(ps.GetCpu()),
		Memory:    toMemoryStats(ps.GetMemory()),
	}
	for _, c := range ps.GetContainers() {
		if c == nil {
			continue
		}
		out.Containers = append(out.Containers, statsv1alpha1.ContainerStats{
			Name:      c.GetName(),
			StartTime: startTime,
			CPU:       toCPUStats(c.GetCpu()),
			Memory:    toMemoryStats(c.GetMemory()),
		})
	}
	return out
}

// toMemoryStats maps a runtime MemoryStats to the kubelet Summary MemoryStats.
// working_set_bytes (ri_phys_footprint) is what kubectl top reports; usage/rss are
// carried when non-zero. A nil sample maps to nil so the field stays absent rather
// than reporting a spurious zero working set.
func toMemoryStats(m *runtimev1.MemoryStats) *statsv1alpha1.MemoryStats {
	if m == nil {
		return nil
	}
	ws := m.GetWorkingSetBytes()
	out := &statsv1alpha1.MemoryStats{Time: protoTime(m.GetTimestamp()), WorkingSetBytes: &ws}
	if u := m.GetUsageBytes(); u != 0 {
		out.UsageBytes = &u
	}
	if rss := m.GetRssBytes(); rss != 0 {
		out.RSSBytes = &rss
	}
	return out
}

// toCPUStats maps a runtime CPUStats to the kubelet Summary CPUStats (best-effort
// CPU accounting; k3sm enforces no CFS millicores). A nil sample maps to nil.
func toCPUStats(c *runtimev1.CPUStats) *statsv1alpha1.CPUStats {
	if c == nil {
		return nil
	}
	out := &statsv1alpha1.CPUStats{Time: protoTime(c.GetTimestamp())}
	if n := c.GetUsageNanoCores(); n != 0 {
		out.UsageNanoCores = &n
	}
	if t := c.GetUsageCoreNanoSeconds(); t != 0 {
		out.UsageCoreNanoSeconds = &t
	}
	return out
}

// podRoot returns the per-pod rootfs parent passed to the PodBox sandbox profile.
// The empty-Root fallback is the runtime's own default work-dir const, the SAME
// one baseSocketDenies derives the work-dir-relative socket spelling from —
// two literals here would let the pod dir and the deny path disagree about where
// the runtime root is.
func (r *runtimedRuntime) podRoot(id string) string {
	root := r.rootfs
	if root == "" {
		root = sandbox.DefaultWorkDir
	}
	return root + "/pods/" + id
}
