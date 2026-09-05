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

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
	"k3sm.io/runtimed/pkg/image"
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

	// resolver supplies ConfigMap/Secret data for the env resolution the
	// provider performs before sending the box to runtimed (runtimed reads only
	// literal env). It is the SAME resolver wired into runtimed's Deps for volume
	// materialization. nil ⇒ data-backed env/volumes fail closed.
	resolver mount.Resolver

	// network is the per-node pod-IP seam (the podnet adapter) — the SAME
	// instance wired into runtimed's Deps.Network, so the provider's
	// allocate-before-translate Setup and the runtimed-side seam Setup are one
	// idempotent authority. nil ⇒ podIP ≈ nodeIP (the --network none / no-datapath
	// posture; runtimed then keeps its single-node NodeNetwork).
	network PodNetwork

	// transport is the vm-pod transport-override feed (the consumer half):
	// it publishes the published-/32 -> live-lease map into the Service proxy's
	// routing table as each vm pod's guest reports its DHCP lease. nil is the
	// inert feed (no sink configured — the --network none / no-datapath posture),
	// and every method tolerates a nil receiver.
	transport *transportFeed

	// guestArtifacts records whether this node's pinned guest boot artifacts were
	// ensured and verified at construction — the VMArtifactsAvailable
	// capability Capabilities reports and cmd/k3sm turns into the
	// k3sm.io/vm-artifacts node label.
	//
	// It is a k3sm-side fact, not a runtimed RuntimeCondition, because ENSURE runS
	// here: runtimed owns the mechanism (guestartifacts.EnsureGuestArtifacts) but
	// the daemon that calls it is this one, and a node may not advertise a
	// capability whose outcome the advertiser did not observe. It mirrors exactly
	// what was wired into the vm backend — true iff a locator was installed — so
	// the label can never claim more than CreateVM can deliver.
	guestArtifacts bool

	// clk, dial, and probeTransport are the provider-served probe seams:
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
	probers map[string]*podProber // pod id -> provider-served probe runner
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
	// bookkeeping (runtimed_restart.go): the termination
	// idempotency latch, the CrashLoopBackOff schedule, and the pending-re-exec
	// state the status overlay renders. Separate from r.mu for the same reason
	// as readyMu (buildStatus runs outside r.mu); lock order is r.mu →
	// restartMu, never the reverse.
	restartMu sync.Mutex
	restarts  map[string]*containerRestart // container name -> restart bookkeeping

	// hookMu guards postStart — the per-container postStart hook bookkeeping of
	// the postStart fidelity path (poststart.go): the pending/failed readiness gate the
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
	// shared verbatim with the embedded runtimed daemon (Deps.Network) so
	// there is exactly ONE allocator: the provider's CreatePod resolves the pod's
	// /32 through it BEFORE translation (box.PodIp + the downward-API status.podIP
	// env carry it), and runtimed's later seam Setup — idempotent per podID —
	// returns the SAME address. nil keeps runtimed's single-node NodeNetwork
	// (podIP ≈ NodeIP): the explicit --network none / no-datapath posture, never a
	// silent production fallback (the commands fail fast via the runtimed
	// preflight instead).
	Network PodNetwork
	// TransportOverrides is the Service-proxy seam a vm pod's LIVE TRANSPORT
	// address is published through (darwin-net's *proxy.RoutingTable, reached via
	// the node's netserve Server). The provider is the only component holding both
	// halves of a vm pod's two-address identity — the published /32 its IPAM
	// carved and the DHCP lease the guest reported through runtimed — so it is the
	// only one that can feed the map. nil runs the feed inert: no override is ever
	// installed and every backend is dialed at its published address exactly as a
	// host-process pod's is.
	TransportOverrides TransportOverrideSink
	// Client is the apiserver client the provider resolves ConfigMap/Secret data,
	// SA tokens (volumes/env), and imagePullSecret credentials with —
	// runtimed never talks to the apiserver. nil disables data-backed
	// volumes/env/credentials (they fail closed / pull anonymously).
	Client kubernetes.Interface
	// ImageMirrors supplies the CLUSTER MIRROR candidates runtimed's puller falls
	// back to when this node's own ingest registry misses a NODE-RELATIVE
	// reference (a `localhost:<port>/…` image the operator pushed on a different
	// Mac). k3sm.io/k3sm/pkg/clustermirror is the shipped implementation; the
	// contract, including why the puller and not the source does the reference
	// rewrite and why no credential crosses the seam, is owned by
	// runtimed/pkg/image's MirrorSource.
	//
	// nil is the SINGLE-NODE posture and the complete, correct behavior there: no
	// candidate is ever produced, so no fallback can run and a pull's own registry
	// error stands as its answer. The provider never blocks on it — the source
	// answers from a cache that may not have synced, and "no candidates yet" is a
	// valid answer at any moment.
	ImageMirrors image.MirrorSource
	// ClusterRegistries names ADDITIONAL registry authorities that spell THIS
	// node's own ingest registry — its per-node Service DNS name and the VIP
	// behind it — which runtimed's puller must classify exactly as it classifies a
	// loopback spelling: plain HTTP on the primary fetch (go-containerregistry
	// infers http only for loopback and RFC 1918, so a Service name would
	// otherwise be dialled as HTTPS against a plain-HTTP listener) and eligible
	// for the peer-mirror fallback. The contract, including why the set carries
	// its own fetcher, is owned by runtimed/pkg/image's WithClusterRegistries.
	//
	// nil is the default and leaves the loopback-only classification byte for
	// byte. runtimed REFUSES a malformed authority at construction rather than
	// silently never matching it, so a bad value here fails the node's bring-up.
	ClusterRegistries []string
	// LocalRegistryHost names THIS NODE's own ingest registry as a reference
	// spells it ("localhost:<port>"). When set, a pull for a reference that names
	// no registry at all resolves against it before normalising to Docker Hub —
	// the local-development loop `k3sm image load` and the ingest registry exist
	// for. The contract, and the bounded cost of the divergence, are owned by
	// runtimed/pkg/image's WithLocalRegistry.
	//
	// It MUST be a loopback spelling or one of ClusterRegistries above; runtimed
	// refuses anything else at construction, which fails the node's bring-up
	// rather than silently treating a third-party registry as this node's own. ""
	// is the default and leaves bare-name resolution stock.
	LocalRegistryHost string
	// GuestArtifacts is this node's ENSURED, digest-verified guest boot artifact
	// set — the kernel, the initramfs and the cmdline a vm pod boots from.
	// It is DATA, already materialised by GuestArtifactSource.Ensure before this
	// config is built, never a directory this constructor would fetch into: daemon
	// start is not a place to discover that a hundred megabytes are missing.
	//
	// nil is the FAIL-CLOSED posture and the shipped one on any node whose ensure
	// did not succeed (an unminted pin, no network, a digest mismatch). It leaves
	// the vm backend's artifact locator unset, so CreateVM fails every vm pod with
	// sandbox.ErrGuestArtifactsUnavailable while every native pod is untouched.
	GuestArtifacts *EnsuredGuestArtifacts
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
	// The vm backend is constructed HERE, rather than left to runtimed's own
	// default, ONLY when this node has verified guest artifacts to wire into it:
	// sandbox.WithGuestArtifacts is a construction option, and runtimed's default
	// backend deliberately leaves the locator unset (its feeder — this — is a
	// separate deliverable). Everything else about the backend is runtimed's
	// default reproduced verbatim, so the ONE difference between a node with
	// artifacts and a node without is the locator.
	//
	// The state root is passed through runtimeRoot for a reason worth keeping: an
	// empty Root means "runtimed's default", and a backend built with an empty
	// state root has its vm orphan store DISABLED — a daemon `kill -9`ed while a
	// guest ran would leave a helper no later start could find. Defaulting the
	// root at this call site is what makes the override behaviourally identical to
	// the default it replaces.
	var deps runtimed.Deps
	if cfg.GuestArtifacts != nil {
		deps.VMBackend = sandbox.NewVMBackend(
			sandbox.WithStateRoot(runtimeRoot(cfg.Root)),
			sandbox.WithLogger(log),
			sandbox.WithGuestArtifacts(guestArtifactLocator(*cfg.GuestArtifacts)),
		)
	}
	deps.Resolver = resolver
	deps.Credentials = creds
	deps.Network = network
	// The cluster-mirror seam. Threaded as DATA, exactly like the resolver and the
	// credential resolver above and for the same reason: runtimed never reads the
	// apiserver, so the component that knows the cluster's peers is the one that
	// must supply them. nil (single node, or a node with no client) leaves
	// runtimed's puller byte-identical to its pre-mirror behavior.
	deps.ImageMirrors = cfg.ImageMirrors
	// The same DATA treatment, and for the same reason: runtimed never reads the
	// apiserver, so the component that published the Service is the one that must
	// name it.
	deps.ClusterRegistries = cfg.ClusterRegistries
	deps.LocalRegistryHost = cfg.LocalRegistryHost
	rt, err := runtimed.New(runtimed.Config{
		Root:           cfg.Root,
		RuntimeVersion: "k3sm-m1",
		Logger:         log,
		// Scope each pod's Seatbelt egress to the cluster DNS + API VIPs so a
		// confined pod's DNS and in-pod client-go reach the node-local resolver /
		// API VIP. runtimed threads these into its per-pod sandbox.Posture.
		ResolverVIP:  cfg.ResolverVIP,
		APIServerVIP: cfg.APIServerVIP,
		PathShimPath: cfg.PathShim,
	}, deps)
	if err != nil {
		return nil, fmt.Errorf("init runtimed: %w", err)
	}
	// Startup pod reap — MUST run here, in-process, before any CreatePod can be
	// served. The embedded node drives this Runtime by direct RPC and never runs
	// runtime.Server.Serve, so runtimed's own once-before-serve reap never fires on
	// the shipped path: the reaper existed but was UNREACHABLE here, leaving pod
	// process groups a prior `launchctl kickstart -k` orphaned onto launchd running
	// (holding ports, surviving uninstall). This is the exact sibling of the
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
		transport:      newTransportFeed(cfg.TransportOverrides, log),
		guestArtifacts: cfg.GuestArtifacts != nil,
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
//   - <root>/run/runtimed.sock — the work-dir-derived spelling THIS node serves,
//     produced by RuntimedSocketPath. That is the ONE derivation the node's
//     control-socket listener also goes through, so the socket a node actually
//     binds is by construction a socket every pod profile denies. The standalone
//     k3sm-runtimed daemon still takes its socket from --socket, defaulting to
//     the absolute const above and never derived from --root, which is why both
//     spellings are emitted rather than one; in the default posture they coincide
//     and the dedupe leaves a single entry.
//
// This mirrors the SBPL generator's own posture resolution, which pins the
// ABSOLUTE run-dir into the file-deny set in addition to the work-dir-derived one
// for exactly this asymmetry (see sandbox.RunSubdir). Both leaf names are taken
// from runtimed's exported const so a rename upstream cannot leave a deny
// guarding a socket nobody serves. In the default posture the two spellings
// coincide and only one is emitted.
//
// WHAT THIS BUYS, precisely: the node builds its runtime IN-PROCESS (NewRuntimed
// → runtime.New) and SERVES it on the derived socket above, so this deny closes
// a LIVE channel rather than pre-positioning against a future one. It has to:
// the socket's 0700-dir / 0600-node posture admits the daemon's own uid, and a
// confined pod runs as that same uid, so the filesystem permissions alone do not
// fence a pod out of the node's control API. The deny is what does. It also
// fences the standalone k3sm-runtimed posture used in a lab.
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
	return []string{
		runtimed.DefaultSocketPath,
		RuntimedSocketPath(root),
		netd.DefaultSocketPath,
		filepath.Join(root, sandbox.RunSubdir, filepath.Base(netd.DefaultSocketPath)),
	}
}

// RuntimedSocketPath returns the unix socket a node whose runtime root is root
// serves its runtimed gRPC control API on: <root>/run/runtimed.sock, the leaf
// name taken from runtimed's own exported default so a rename upstream cannot
// leave the two out of step. An empty root means the runtime default work-dir,
// for which the result is exactly runtimed.DefaultSocketPath — so a stock
// install serves the very path `k3sm image` dials by default, and a second
// instance with its own root (a `k3sm dev` cluster, a lab node) serves beside
// its own image store instead of contending for the shared one.
//
// It is EXPORTED and used by baseSocketDenies so there is exactly one derivation
// of this path in the tree. That is the point: the served socket and the pod
// deny-set are then the same string by construction, and a node cannot come to
// serve a control API at an address no pod profile denies.
func RuntimedSocketPath(root string) string {
	if root == "" {
		root = sandbox.DefaultWorkDir
	}
	return filepath.Join(root, sandbox.RunSubdir, filepath.Base(runtimed.DefaultSocketPath))
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

// ConditionVMArtifactsAvailable is the NAME the guest-artifact capability is
// narrated under.
//
// It is a k3sm-local string, NOT one of runtimed's imported RuntimeCondition Type
// constants, because no RuntimeCondition carries this fact: the ensure runs here,
// so runtimed has nothing to report (see NodeCapabilities.VMArtifacts). It is
// exported so the log line, the ledger, the docs and the integration gate all
// spell the capability the same way — a capability whose name is retyped at each
// site is one an operator cannot grep for.
const ConditionVMArtifactsAvailable = "VMArtifactsAvailable"

// NodeCapabilities are the node-capability facts runtimed advertises as
// GetRuntimeInfo RuntimeConditions and the node command turns into truthful node
// labels. They travel as ONE struct, from ONE RPC, deliberately: three separate
// probes could each observe a DIFFERENT daemon state and produce an incoherent
// label set (k3sm.io/rosetta-linux stamped from a later observation while
// k3sm.io/virtualization was deleted from an earlier one). Every field fails CLOSED
// — the zero value advertises nothing.
type NodeCapabilities struct {
	// VMBackend is the VMBackendAvailable condition: this host can run the vm
	// RuntimeClass (Virtualization.framework isSupported + the
	// com.apple.security.virtualization entitlement). Drives k3sm.io/virtualization.
	VMBackend bool
	// VMArtifacts is the VMArtifactsAvailable condition: this node holds the pinned
	// guest kernel + initramfs, digest-verified on THIS daemon start, so a booted
	// guest has something to boot. Drives k3sm.io/vm-artifacts.
	//
	// It is the ONE field here that does NOT come off the GetRuntimeInfo response,
	// and the asymmetry is deliberate rather than an oversight: the ensure runs in
	// k3sm (GuestArtifactSource.Ensure, at daemon start), so runtimed has no
	// condition to report — it is handed the outcome as a construction input. It
	// still fails CLOSED with the rest of the struct: the zero value advertises
	// nothing, and a probe error leaves it false along with everything else.
	//
	// It is INDEPENDENT of VMBackend. The two answer different questions — "can
	// this Mac run a guest" and "does this node have a guest to run" — and either
	// can be true without the other (an entitled Mac that could not fetch; an
	// air-gap-seeded cache on a Mac with no VZ). A vm pod needs both, which is why
	// the vm RuntimeClass still selects on k3sm.io/virtualization and this label is
	// additive advertisement, not a second scheduling gate.
	VMArtifacts bool
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
	// Stamped from what THIS provider wired, not read back off the response: the
	// ensure is k3sm's (see NodeCapabilities.VMArtifacts), so the runtime has no
	// opinion to report and a `conditionTrue` read would be permanently false.
	caps.VMArtifacts = r.guestArtifacts
	// Log at the boundary WITH each withheld capability's Reason: the condition's
	// Reason/Message is the only answer to "why is my node not labelled rosetta?",
	// and it is discarded once this returns a bare bool.
	logWithheldCapability(r.log, info, runtimed.ConditionVMBackendAvailable, caps.VMBackend)
	logWithheldCapability(r.log, info, runtimed.ConditionRosettaHostAvailable, caps.RosettaHost)
	logWithheldCapability(r.log, info, runtimed.ConditionRosettaGuestAvailable, caps.RosettaGuest)
	// The artifact capability has no RuntimeCondition to carry a Reason, so its
	// withheld case is narrated here with the condition name the ledger and the
	// docs use. GuestArtifactSource.Ensure already logged the CAUSE at start; this
	// line is what an operator finds when they ask why the node is not labelled.
	if !caps.VMArtifacts {
		r.log.Info("node capability withheld: "+ConditionVMArtifactsAvailable+
			" is false — no digest-verified guest boot artifacts were wired into this runtime, so every vm pod fails closed",
			"condition", ConditionVMArtifactsAvailable)
	}
	return caps
}

// GetRuntimeInfo forwards one runtime-info probe to the in-process runtime,
// verbatim — no interpretation, no fail-closed substitution.
//
// It exists so a consumer that needs a FACT off the runtime-info response rather
// than a node-capability verdict (the MLX operator's GPU facts, which carry the
// memory ceilings its pre-render fit check sizes against) can read it from the
// SAME embedded runtime this provider already drives, instead of opening a second
// connection to a daemon the shipped install does not even run standalone.
//
// It deliberately returns the error rather than swallowing it the way Capabilities
// and Healthy do: those two answer "may this node advertise X", where an
// unanswerable probe MUST read as no; this one answers "what did the runtime say",
// where an unanswerable probe is not a fact about the host and the caller has to
// be able to tell the two apart.
//
// The signature matches runtimev1.RuntimeServer's method exactly, so this value
// satisfies a one-method consumer interface over that RPC with no adapter.
func (r *runtimedRuntime) GetRuntimeInfo(ctx context.Context, req *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	return r.rt.GetRuntimeInfo(ctx, req)
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
// anywhere — importing makes a producer/consumer rename a COMPILE error.
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

// ServableRuntime implements the optional ControlSocketSource capability: it
// hands back the in-process *runtime.Runtime this provider drives, so the node
// can additionally SERVE it on runtimed's gRPC control socket and the
// daemon-side `k3sm image` commands work on a stock install.
//
// It is comma-ok rather than a bare pointer because the field it reads is the
// runtimev1.RuntimeServer seam newRuntimedWith accepts, and the unit tests
// inject a fake through exactly that seam. false therefore means "this provider
// is not driving a real runtimed runtime" — a test double, or any future
// out-of-process backend — and the caller serves nothing, which is the only
// honest answer: a Server can only be built over the concrete runtime.
//
// It returns the runtime UNWRAPPED and shared, not a copy: the whole point is
// that the socket serves the SAME instance the VK node drives, so an image
// loaded over the socket is visible to the next pod this node starts. A second
// runtime over the same root would be a second writer to one image store.
func (r *runtimedRuntime) ServableRuntime() (*runtimed.Runtime, bool) {
	rt, ok := r.rt.(*runtimed.Runtime)
	return rt, ok
}

// Compile-time check that runtimedRuntime satisfies the Runtime seam and the
// optional StatsSource capability (the Summary API surface).
var (
	_ Runtime             = (*runtimedRuntime)(nil)
	_ StatsSource         = (*runtimedRuntime)(nil)
	_ HealthReporter      = (*runtimedRuntime)(nil)
	_ ControlSocketSource = (*runtimedRuntime)(nil)
)

// podIP resolves the pod's IP BEFORE translation — the ordering rule: the
// /32 must exist before toPodBox so box.PodIp, the downward-API status.podIP
// env fieldRefs (resolvePodBoxEnv reads box.GetPodIp()), the SBPL bind
// discipline, and pod status all carry ONE authority. The runtimed-side seam's
// later Setup for the same podID is idempotent and returns the SAME address.
//
// Branches (each documented, never a silent fallback):
//
//   - no adapter (nil network — the --network none posture): podIP ≈ nodeIP.
//
//   - spec.hostNetwork: the pod shares the node's addresses — no /32. The pod is
//     marked on the adapter so the runtimed-side seam Setup (which the
//     host-process spine calls unconditionally) also resolves it to the node IP.
//
//   - vm RuntimeClass: the /32 darwin-net podnet.Network.SetupGuest allocated for
//     the guest, via setupGuestNetwork — the SAME address the adapter carries to
//     runtimed as sandbox.VMSpec.Network through the runtime.GuestNetworker seam.
//     SetupGuest is idempotent per podID, so buildBox's later call a few frames
//     down returns this very address and there is still exactly one authority.
//     NO lo0 alias is plumbed for it (SetupGuest is the not-taken branch of
//     podnet's path fork): a host alias for the guest's address would make the
//     host answer for the guest and blackhole it.
//
//     WHY THE GUEST'S /32 IS PUBLISHED WHILE THE HOST DOES NOT HOLD IT. A vm pod
//     has TWO addresses and they are never reconciled into one. This /32 is its
//     cluster IDENTITY — what status.podIP, its EndpointSlices, cluster DNS and
//     every NetworkPolicy carry — and it is deliberately live on no interface.
//     The address that carries bytes is the guest's macOS-assigned vmnet DHCP
//     lease, reported by the guest agent as PodStatus.guest_transport_address;
//     it is never published, because a lease churns on every guest restart while
//     an identity must not. The dial paths TRANSLATE between the two:
//     observeTransport feeds the Service proxy a published->live override map
//     keyed on exactly this /32 (proxy.RoutingTable.SetTransportOverrides), so a
//     Service backend picked and policy-checked on the identity is dialed at the
//     lease. Publishing the node IP here — which this branch used to do — gave
//     every vm pod on a node the same status.podIP, which no override map can be
//     keyed on and which no Service could distinguish.
//
//   - otherwise: the podnet /32. Pool exhaustion surfaces as a distinguishable
//     error (errors.Is(err, podnet.ErrPoolExhausted) holds through the wrap) —
//     identically for the guest branch, which draws from the same node pool.
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
		// fail-closed rejection; this branch only routes a resolved vm pod to the
		// guest allocation instead of the host-process one.
		//
		// The dropped truncation count is buildBox's to report: podDNSConfig is
		// pure and this is the FIRST of the create path's two calls, so warning
		// here would double-report one pod's truncated search list.
		dnsCfg, _ := r.podDNSConfig(pod)
		gn, err := r.setupGuestNetwork(ctx, pod, dnsCfg)
		if err != nil {
			return "", err
		}
		if !gn.PodIP.IsValid() {
			// The seam allocated nothing. Fail the create rather than fall back to
			// the node IP: a vm pod published at the node's address is unaddressable
			// as a Service backend and indistinguishable from every other guest.
			return "", fmt.Errorf("allocate pod ip for %s/%s: the guest network carries no address", pod.Namespace, pod.Name)
		}
		return gn.PodIP.String(), nil
	}
	ip, err := r.network.Setup(ctx, id)
	if err != nil {
		return "", r.allocError(pod, err)
	}
	return ip, nil
}

// allocError names a pod-IP allocation failure. Exhaustion of the node pool gets
// the FRIENDLY leading clause (the 253-address ceiling is a node fact an operator
// can act on, not an internal error), and the podnet sentinel is preserved with %w
// either way.
//
// It is one function because there are now TWO consumers of that one pool — the
// host-process Setup above and the vm-guest SetupGuest — and exhaustion must read
// the same from both. Duplicating the phrasing at the second call site is exactly
// how one of them would later stop being legible.
func (r *runtimedRuntime) allocError(pod *corev1.Pod, err error) error {
	if errors.Is(err, podnet.ErrPoolExhausted) {
		return fmt.Errorf("pod ip pool exhausted on node %s (253 pods/node): allocate pod ip for %s/%s: %w", r.nodeName, pod.Namespace, pod.Name, err)
	}
	return fmt.Errorf("allocate pod ip for %s/%s: %w", pod.Namespace, pod.Name, err)
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

// setupGuestNetwork produces the guest network config of a vm-RuntimeClass pod
// and hands it to the adapter, which records it for runtimed to read back on the
// vm route (runtime.GuestNetworker -> sandbox.VMSpec.Network). It is the
// producer half; runtimed is the consumer half and never derives this itself.
// It RETURNS the config, because podIP publishes the allocated /32 as the pod's
// cluster identity — the zero value (with an invalid PodIP) for every pod the
// guards below exclude.
//
// WHERE IT RUNS. Twice on the create path, both times before translation, and
// that is safe because it is idempotent per podID: podIP calls it to learn the
// address it must publish, and buildBox calls it immediately before toPodBox.
// The buildBox call site is the one the ordering argument below is about.
// It must be BEFORE translation (the pod's network exists before the box that
// describes it), and it must consume the SAME dnsCfg value toPodBox is given —
// the per-pod, namespace-scoped config after the spec.dnsConfig merge. Deriving it a second time here would create a second
// authority for one pod's DNS, and the guest's /etc/resolv.conf would be free to
// disagree with the host-process shim env built from the first.
//
// WHAT IS EXCLUDED, and why each:
//   - a nil adapter (--network none) has nothing to allocate from;
//   - a spec.hostNetwork pod allocates NOTHING by construction (podIP marks it
//     and returns the node IP), so it must not draw a guest address either — the
//     hostNetwork check comes FIRST here for exactly the reason it comes first in
//     podIP: one pod, one answer;
//   - a non-vm pod is served by the host-process Setup and reads no guest config.
//
// A RuntimeClass that does not resolve is NOT rejected here — toPodBox owns that
// fail-closed rejection a few lines later, and duplicating it would give one
// error two spellings.
//
// It FAILS the create: a vm pod whose guest config could not be produced would
// boot with no resolver, pass readiness, and fail on its first in-app DNS lookup
// — indistinguishable at that point from an application bug. Pool exhaustion is
// named through the shared allocError, so it reads identically to a host-process
// pod exhausting the same 253 addresses.
func (r *runtimedRuntime) setupGuestNetwork(ctx context.Context, pod *corev1.Pod, dnsCfg netv1.DNSConfig) (sandbox.GuestNetworkConfig, error) {
	if r.network == nil || pod.Spec.HostNetwork {
		return sandbox.GuestNetworkConfig{}, nil
	}
	backend, err := podSandboxBackend(pod)
	if err != nil || backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return sandbox.GuestNetworkConfig{}, nil
	}
	gn, err := r.network.SetupGuest(ctx, string(pod.UID), dnsCfg)
	if err != nil {
		return sandbox.GuestNetworkConfig{}, r.allocError(pod, err)
	}
	return gn, nil
}

// podDNSConfig derives one pod's cluster DNS config: the namespace-scoped cluster
// base (dns.PodDNSConfig), additively merged with a ClusterFirst pod's
// spec.dnsConfig (extra search domains appended+deduped, an ndots override).
// The merge is GATED on the cluster-DNS policy — NOT left to injectClusterDNSEnv's
// downstream gate — so the seam is structural: a None/Default pod gets the
// UNMERGED base, so when a later change makes None inject its own config it cannot
// inherit a cluster-base merge. dnsConfigOverride does the corev1→discrete-params extraction
// (k3sm is the corev1-aware layer); dns.MergeDNSConfig can only ADD search/ndots,
// never repoint the cluster server VIP.
//
// It returns the config and the number of search domains the in-pod cap DROPPED,
// and logs nothing: the create path calls it twice for a vm pod (podIP, to learn
// the guest address it must publish, and buildBox, to translate), so warning inside
// would double-report one pod's truncation. buildBox owns that warning.
//
// It exists as one function for the same reason allocError does: the guest's
// /etc/resolv.conf and its containers' injected K3SM_DNS_* env are derived from
// this value, and a second derivation is how the two would come to disagree.
func (r *runtimedRuntime) podDNSConfig(pod *corev1.Pod) (netv1.DNSConfig, int) {
	dnsCfg := dns.PodDNSConfig(r.resolverVIP, r.clusterDomain, pod.Namespace)
	if !clusterDNSPolicy(pod.Spec.DNSPolicy) || pod.Spec.DNSConfig == nil {
		return dnsCfg, 0
	}
	searches, ndots := dnsConfigOverride(pod.Spec.DNSConfig)
	return dns.MergeDNSConfig(dnsCfg, searches, ndots)
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
	dnsCfg, dropped := r.podDNSConfig(pod)
	if dropped > 0 {
		// The pod's merged search list exceeded the in-pod cap (MaxSearchDomains, a
		// deliberate divergence from upstream's 32); the tail was truncated. Log once
		// here at the corev1-aware boundary WITH pod identity — the darwin-net merge
		// primitive stays pure and returns the count rather than logging blind, and
		// podDNSConfig's other caller (podIP) deliberately drops the count so one
		// pod's truncation is reported once.
		r.log.WarnContext(ctx, "pod dnsConfig search list truncated to the in-pod cap",
			"namespace", pod.Namespace, "name", pod.Name, "dropped", dropped, "cap", dns.MaxSearchDomains)
	}
	// Produce the vm pod's GUEST network config BEFORE translation, from the very
	// dnsCfg above — the one-authority ordering applied to the guest carrier.
	// A no-op for every non-vm pod, and idempotent for a vm pod whose address podIP
	// already drew through this same call.
	if _, err := r.setupGuestNetwork(ctx, pod, dnsCfg); err != nil {
		return nil, err
	}
	box, err := toPodBox(pod, podIP, r.nodeIP, r.podRoot(string(pod.UID)), r.dyldShim, dnsCfg, r.log)
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
	// Bind the pod's identity (ServiceAccount + name + UID) to the request context
	// so the shared volume Resolver mints the in-pod-API token (projected SA-token
	// volume) against the RIGHT SA and pins it to THIS Pod object — runtimed
	// threads this ctx to mount.Materialize in-process. The pod-object half
	// is what makes the token die with the pod instead of outliving it to expiry
	// see kubeResolver.ServiceAccountToken.
	ctx = withPodIdentity(ctx, pod)
	id := string(pod.UID)
	start := metav1.Now()
	r.log.Info("CreatePod", "namespace", pod.Namespace, "name", pod.Name)
	// Ordering (BINDING): allocate the pod's /32 BEFORE translation/env
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
	// Refuse an annotated pod this node's capabilities cannot serve BEFORE
	// the RPC, and before any bookkeeping — a pod refused here leaves no track and
	// no prober, exactly as if it had never been created. It logs and records its
	// own Warning Event (preflightImagePlatform); the error is returned already
	// wrapped.
	if err := r.preflightImagePlatform(ctx, pod, box); err != nil {
		return err
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
	// Start the provider-served probe runner: the VK provider replaces the
	// kubelet, so it must execute the pod's probes itself. No-op for a probe-free
	// pod; idempotent for a repeated CreatePod.
	r.startProber(pod, resp.GetStatus().GetPodIp())
	// Dispatch each container's postStart hook (the
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
	// Same identity binding as CreatePod, in case the runtime re-materializes
	// volumes on an in-place update.
	ctx = withPodIdentity(ctx, pod)
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

// DeletePod runs the pod's preStop hooks, then stops the pod's processes and
// forgets the bookkeeping. Idempotent. The SIGTERM→SIGKILL grace window is the pod's
// termination budget (deletion/termination grace, k8s 30s default) MINUS the preStop
// wall-time (floored at 1s), since runtimed treats a 0 grace as immediate-kill.
func (r *runtimedRuntime) DeletePod(ctx context.Context, pod *corev1.Pod) error {
	id := string(pod.UID)
	// Cancel any in-flight postStart hook FIRST: a hook must not outlive the
	// pod, and termination must not wait on one — upstream tears the pod worker's
	// context down on delete, which aborts a running hook.
	if t := r.trackByID(id); t != nil {
		t.cancelPostStart()
	}
	// Serve preStop hooks BEFORE termination: runtimed sends SIGTERM
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
	// Drop any Service-proxy transport override for the pod IN THE SAME STEP. No
	// further status will ever arrive to retract it, and an override that outlives
	// its guest points at a lease macOS is free to hand to the NEXT guest — a
	// cross-pod misdelivery, not a failed dial (see transportFeed).
	r.transport.drop(id)
	r.mu.Lock()
	t := r.track[id]
	delete(r.track, id)
	r.mu.Unlock()
	if t != nil {
		// Abort any pending exit-driven re-exec: no restart goroutine may
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
// available: a rolling-update stall. The HostProcess
// path is exempt (it persists computed status back onto rec.pod, a stable prior).
//
// Locking: t.readyMu guards lastReady because GetPods reconstructs status OUTSIDE
// r.mu (it snapshots tracks under the lock, then builds each unlocked), so concurrent
// GetPods/emit for the same track must not race on lastReady. The lock is held ONLY
// around the lastReady read and write — never across toPodStatus or the prober.
//
// buildStatus is also the restart-bookkeeping convergence point: every runtime status
// observation (stream emit, backstop GetPods, direct GetPodStatus, probe-driven
// publish) flows through here, so observeExits sees each container termination
// regardless of which path delivered it (idempotent per termination), and
// applyRestartOverlay renders the CrashLoopBackOff surface + Running phase hold
// on every published status while a re-exec is pending. The postStart readiness
// gate rides the same convergence, so no publish path can leak a Ready container
// whose postStart hook has not completed.
func (r *runtimedRuntime) buildStatus(pod *corev1.Pod, t *podTrack, rs *runtimev1.PodStatus, ps probeState) corev1.PodStatus {
	r.observeExits(pod, t, rs)
	// Feed the Service proxy this pod's live transport address, on the
	// same convergence the exit observation rides. It reads the status and the
	// node's own guest record; it contributes NOTHING to the corev1 status being
	// built, because the live address must never reach status.podIP, the
	// EndpointSlice or DNS (see observeTransport).
	r.observeTransport(string(pod.UID), rs)
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
	// ContainersReady/PodReady follow.
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
// carry forward / derive Status.QOSClass in toPodStatus; callers that need
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

// StatsSummary builds the kubelet Summary API snapshot kubectl top reads,
// consuming the runtime's typed ListPodStats RPC. Each PodStats sample
// carries the proc_pid_rusage working-set footprint runtimed meters
// (ri_phys_footprint, NOT RSS), per-container; the provider maps it to the kubelet
// Summary shape and fills the stable per-pod StartTime from its own bookkeeping
// (the runtime sample carries only the sample timestamp). A pod runtimed does not
// sample (no memory limit ⇒ no metering) is absent from the response and so
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
