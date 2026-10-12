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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	crdconfig "k3sm.io/apis/config/crd"
	"k3sm.io/darwin-net/pkg/dns"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/crdensure"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
	"k3sm.io/k3sm/pkg/mlx/operator"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/policy"
	"k3sm.io/k3sm/pkg/ports"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// serverOptions configures `k3sm server` — the all-in-one control plane + node.
type serverOptions struct {
	workDir string
	// clearCrashLoop clears the crash-loop record and exits instead of serving.
	clearCrashLoop bool
	nodeName       string
	// nodeIP is the node's advertised InternalIP and nothing else. A non-loopback
	// value is aliased on lo0 by the pod network, so it must be an address this
	// node answers for inside its pod range (on a mesh server, leave it at the
	// default and the mesh path advertises --mesh-ip). It is never the etcd peer
	// address: that is etcdPeerIP, a LAN address that is already on an interface
	// and must never be aliased on lo0.
	nodeIP string
	meshIP string // wireguard mesh IP; set => multi-node worker-join supervisor
	// etcdPeerIP is the embedded-etcd member's peer address (--etcd-peer-ip): this
	// server's LAN address, which the peer listener binds and every other server
	// dials. Required in the etcd posture and by --cluster-reset; unused otherwise.
	etcdPeerIP string
	podRoot    string
	// logs is the container-log flag group, passed through to the in-process node.
	logs     containerLogOptions
	rtName   string
	dnsShim  string
	pathShim string
	apiPort  int
	kinePort int // kine (etcd shim) listen port; per-server, so two control planes on one host never share a datastore
	// kubeletPort is the port the in-process node serves the kubelet HTTP API
	// (logs/exec/stats) on. Per-server for the same reason kinePort is: it is a
	// singleton listener, so two control planes on one Mac cannot both have the
	// default. Only the PORT is configurable — the bind stays the wildcard
	// serverKubeletListenOn builds, and the API's auth posture is untouched.
	kubeletPort int
	// schedulerPort / controllerManagerPort are the two co-located control-plane
	// components' secure-serving ports. Per-server for the same reason as the
	// two above — each is a singleton listener — and they were the LAST fixed
	// ones, so with these a second control plane on one Mac contends for nothing.
	// Only the PORT is configurable: both components stay bound to loopback,
	// which executor.LoopbackServingArgs renders and does not take from here.
	schedulerPort         int
	controllerManagerPort int
	clusterIP             string // DNS VIP the per-node resolver binds + pods resolve against
	domain                string
	network               string // host-network backend: auto (default) | none | direct | helper

	// clusterInit / serverJoin select the embedded-etcd HA posture (see
	// etcdPosture): --cluster-init forms a new etcd cluster on this server,
	// --server-join adds this server to an existing one as a learner. Neither is
	// the single-node kine posture. They are mutually exclusive.
	clusterInit bool
	serverJoin  bool
	// clusterReset turns this server's existing etcd member into a one-member
	// cluster and exits; it never starts the daemon (executor.ClusterReset).
	clusterReset bool
	// etcdPeerPort / etcdMetricsPort are the etcd member's peer (node IP) and
	// metrics (loopback) listener ports. Per-server for the same reason as the
	// other singleton ports: two members on one host each need their own.
	etcdPeerPort    int
	etcdMetricsPort int
	// etcdSnapshotCron, etcdSnapshotRetention and etcdDisableSnapshots are the
	// scheduled etcd snapshot (k3s's flags and defaults). Read in the etcd posture
	// only: a single-server SQLite datastore has no schedule, as in k3s.
	etcdSnapshotCron      string
	etcdSnapshotRetention int
	etcdDisableSnapshots  bool
	joinServer            string // an existing server's LAN address: the CA bundle and the etcd member route (HA server-join)
	token                 string // static admin bearer token (standalone) or the server-class join token (HA server-join)
	// tokenFile is a file holding that token, read once at start. It is how the
	// INSTALLED daemon is given its static admin token: the value never appears
	// on the argv a plist publishes. See resolveTokenFile.
	tokenFile string

	psaEnforceBaseline bool // flip the PSA cluster-default enforce level privileged→baseline (the baseline-enforce cutover; default = warn-only)

	ingressHTTPPort  int // ingress HTTP listener port, bound on the wildcard (0 disables; 80 = production, an explicit high port = integration tier)
	ingressHTTPSPort int // ingress HTTPS listener port (same contract as ingressHTTPPort; 443 = production)

	// registryPort is the loopback port the node-local OCI ingest registry serves
	// on. 0 DISABLES it, and that is the shipped default: the registry stages and
	// runs a pinned zot child, which is real disk and a real process, and a server
	// that never ingests a locally built image should pay for neither.
	registryPort int
}

// executorConfig renders the control-plane Config these flags describe. It is
// PURE and lives outside runServer for one reason: every port on it is a
// singleton listener that a second control plane on the same Mac has to be able
// to move, and a flag that is parsed but never assigned here reproduces that
// defect exactly — an operator-supplied port silently replaced by the default,
// with the collision surfacing as whichever component loses the bind. runServer
// fills the rest of the Config (payload dir, datastore, mesh) from the
// environment, which is not testable this way and not what keeps colliding.
func (opts serverOptions) executorConfig(logger *slog.Logger) executor.Config {
	return executor.Config{
		WorkDir:               opts.workDir,
		APIServerPort:         opts.apiPort,
		KinePort:              opts.kinePort,
		SchedulerPort:         opts.schedulerPort,
		ControllerManagerPort: opts.controllerManagerPort,
		NodeIP:                opts.nodeIP,
		// false ships baseline-WARN; true is the enforce cutover (see the
		// flag comment above — executor.Config.PSAEnforceBaseline is the single seam).
		PSAEnforceBaseline: opts.psaEnforceBaseline,
		Etcd:               opts.etcdConfig(),
		Logger:             logger,
	}
}

// etcdPosture reports whether these flags select the embedded-etcd HA posture. It is
// the ONE predicate every HA decision in `k3sm server` derives from — the encryption
// refusal, the etcd CA population, the bootstrap-bundle route and publish — so no two
// of them can disagree about whether this server is HA.
func (opts serverOptions) etcdPosture() bool {
	return opts.clusterInit || opts.serverJoin
}

// role is this server's CA mint role, derived from --server-join alone: a server
// that joined an HA control plane never mints a CA (certs.RoleJoined), with or
// without --server; every other server is a mint authority.
func (opts serverOptions) role() certs.Role {
	if opts.serverJoin {
		return certs.RoleJoined
	}
	return certs.RoleMintAuthority
}

// posture is the CA posture of these flags, from the one HA predicate: the etcd
// posture needs the etcd CA pair as well.
func (opts serverOptions) posture() certs.Posture {
	if opts.etcdPosture() {
		return certs.PostureEtcd
	}
	return certs.PostureKine
}

// etcdConfig renders the executor's etcd block for these flags: nil in the kine
// posture. The member name is the canonical node name, and the peer address is
// --etcd-peer-ip (the LAN address). It is deliberately NOT --node-ip: that flag is
// the node's advertised address, which the pod network aliases on lo0, and a LAN
// address aliased there is refused by netd's policy (it is outside the node's pod
// range) and would shadow the interface that actually carries it. A
// --cluster-reset with neither role flag is treated as an init member: a reset
// makes a one-member cluster either way.
func (opts serverOptions) etcdConfig() *executor.EtcdConfig {
	role := executor.EtcdRole(0)
	switch {
	case opts.serverJoin:
		role = executor.EtcdJoin
	case opts.clusterInit, opts.clusterReset:
		role = executor.EtcdInit
	default:
		return nil
	}
	return &executor.EtcdConfig{
		Role:        role,
		Name:        opts.nodeName,
		PeerIP:      opts.etcdPeerIP,
		PeerPort:    opts.etcdPeerPort,
		MetricsPort: opts.etcdMetricsPort,
		Snapshots:   opts.etcdSnapshotSchedule(),
	}
}

// etcdSnapshotSchedule renders the scheduled-snapshot block: nil with
// --etcd-disable-snapshots, and nil for an expression validateEtcdSnapshotFlags
// would have refused (it runs before any config is built).
func (opts serverOptions) etcdSnapshotSchedule() *executor.EtcdSnapshotSchedule {
	if opts.etcdDisableSnapshots {
		return nil
	}
	cron, err := executor.ParseCron(opts.etcdSnapshotCron)
	if err != nil {
		return nil
	}
	return &executor.EtcdSnapshotSchedule{Cron: cron, Retention: opts.etcdSnapshotRetention}
}

// etcdSnapshotFlagsChanged reports whether any scheduled-snapshot flag differs from
// its default.
func (opts serverOptions) etcdSnapshotFlagsChanged() bool {
	return opts.etcdDisableSnapshots ||
		opts.etcdSnapshotRetention != executor.DefaultEtcdSnapshotRetention ||
		strings.Join(strings.Fields(opts.etcdSnapshotCron), " ") != executor.DefaultEtcdSnapshotCron
}

// validateEtcdSnapshotFlags refuses a schedule that cannot run: an expression that
// does not parse or never fires, or a retention below one. It checks them in every
// posture, because a typo is worth stopping even where the schedule is not read.
func (opts serverOptions) validateEtcdSnapshotFlags() error {
	if _, err := executor.ParseCron(opts.etcdSnapshotCron); err != nil {
		return fmt.Errorf("--etcd-snapshot-schedule-cron: %w", err)
	}
	if opts.etcdSnapshotRetention < 1 {
		return fmt.Errorf("--etcd-snapshot-retention %d: %w", opts.etcdSnapshotRetention, executor.ErrEtcdSnapshotRetention)
	}
	return nil
}

// logEtcdSnapshotPosture says once, at start, when the snapshot flags are not
// read: in the kine posture (k3s takes no scheduled snapshot of a SQLite datastore
// either) or with the schedule turned off.
func (opts serverOptions) logEtcdSnapshotPosture(logger *slog.Logger) {
	switch {
	case !opts.etcdPosture() && opts.etcdSnapshotFlagsChanged():
		logger.Info("the etcd snapshot flags are ignored: scheduled snapshots are an embedded etcd feature, and a single-server SQLite datastore is backed up with `k3sm snapshot save`")
	case opts.etcdPosture() && opts.etcdDisableSnapshots:
		logger.Info("scheduled etcd snapshots are off (--etcd-disable-snapshots); take them with `k3sm snapshot save`")
	}
}

// validateEtcdFlags refuses the HA flag combinations that cannot describe a server,
// before any state is touched: --cluster-init with --server-join; either one (or
// --cluster-reset) without a non-loopback --etcd-peer-ip, which the member advertises
// to its peers as its own address; --etcd-peer-ip outside that posture, where nothing
// reads it; and a --node-ip equal to the peer address, which is the pre-split grammar
// (the LAN address on --node-ip) and would have the pod network alias the LAN address
// on lo0 at every start.
func (opts serverOptions) validateEtcdFlags() error {
	if opts.clusterInit && opts.serverJoin {
		return errors.New("--cluster-init and --server-join are mutually exclusive: --cluster-init forms a new etcd cluster on this server, --server-join adds it to an existing one")
	}
	if !opts.etcdPosture() && !opts.clusterReset {
		if opts.etcdPeerIP != "" {
			return errors.New("--etcd-peer-ip needs --cluster-init, --server-join or --cluster-reset: it is the embedded etcd member's peer address, and a single-server control plane runs no etcd member")
		}
		return nil
	}
	ip := net.ParseIP(opts.etcdPeerIP)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		hint := ""
		if n := net.ParseIP(opts.nodeIP); n != nil && !n.IsLoopback() && !n.IsUnspecified() {
			hint = fmt.Sprintf("; --node-ip %s no longer carries the etcd peer address, pass this server's LAN address as --etcd-peer-ip instead", opts.nodeIP)
		}
		return fmt.Errorf("%w (got --etcd-peer-ip %q; the etcd peer listener binds this address and every other server dials it%s)", executor.ErrEtcdNeedsNodeIP, opts.etcdPeerIP, hint)
	}
	if n := net.ParseIP(opts.nodeIP); n != nil && n.Equal(ip) {
		return fmt.Errorf("--node-ip %s is the etcd peer address: --node-ip is the node's advertised address, which the pod network aliases on lo0, and a LAN address must never be aliased there. Drop --node-ip (a mesh server advertises its --mesh-ip) and keep the LAN address on --etcd-peer-ip only", opts.nodeIP)
	}
	return nil
}

// deniedLocalPorts is the set of loopback TCP ports every confined pod's sandbox
// on this node denies connect() to. It is a METHOD, not a literal at each use,
// because the set has exactly two consumers that must never disagree: the node's
// provider config (nodeOptions.deniedLocalPorts, which becomes each pod's SBPL)
// and the cluster admission policy that rejects a Service published on one of
// these ports (policy.EnsureRejectServiceDeniedLocalPort). A second literal is how
// the guard and the thing it guards drift: the policy would reject Services on a
// port nothing denies, while the port that IS denied stayed publishable.
//
// It is the datastore's loopback client port (--kine-port: kine's plaintext socket,
// or in the etcd posture the etcd member's TLS client listener), which no pod has
// any business reaching, and in the etcd posture also the member's loopback metrics
// listener (--etcd-metrics-port): plain HTTP with no authentication, describing the
// datastore. The peer port is not here: it listens on the node IP, not loopback,
// and requires a peer-CA certificate no pod can read.
func (opts serverOptions) deniedLocalPorts() []int {
	if opts.etcdPosture() {
		return []int{opts.kinePort, opts.etcdMetricsPort}
	}
	return []int{opts.kinePort}
}

// registerServerFlags binds `k3sm server`'s flags onto fs and returns the error
// (if any) from resolving the posture-aware --work-dir DEFAULT, which the caller
// surfaces after Parse so an explicit --work-dir can still override it.
//
// It is a function rather than an inline block in runServer for the same reason
// registerAgentFlags is: the REGISTERED SURFACE is then assertable without
// parsing argv through a live bring-up — including the negative assertions,
// which are the ones that cannot be written any other way. The dev-only
// guest-artifact directory override is exactly such a negative
// (TestGuestArtifactsDirOverrideIsDevOnly): a flag whose absence is the
// requirement can only be checked against the real flag set.
func registerServerFlags(fs *flag.FlagSet, opts *serverOptions) error {
	// The work-dir default is POSTURE-AWARE (decoupled from the root-only
	// DefaultWorkDir const): root → /var/lib/k3sm/server, the unprivileged _k3sm
	// control plane → <home>/server (the root const would EACCES). A resolve error
	// (unprivileged with no home) is surfaced after Parse so an explicit --work-dir
	// can still override it.
	defaultWorkDir, workDirErr := executor.ResolveWorkDir()
	fs.StringVar(&opts.workDir, "work-dir", defaultWorkDir, "control-plane state root (binaries, kine DB, certs, kubeconfig); posture-aware default")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.BoolVar(&opts.clearCrashLoop, "clear-crashloop", false, "clear the crash-loop record under --work-dir and exit 0 instead of serving; a parked daemon then exits and launchd starts a clean boot")
	fs.StringVar(&opts.nodeIP, "node-ip", "127.0.0.1", "node InternalIP to advertise; a non-loopback value is aliased on lo0 by the pod network, so it must lie in this node's pod range (leave it at the default on a mesh server: the node then advertises --mesh-ip). Never the etcd peer address: that is --etcd-peer-ip")
	fs.StringVar(&opts.meshIP, "mesh-ip", "", "wireguard mesh IP to bind the apiserver + worker-join supervisor on (enables multi-node join; empty = single-node)")
	fs.StringVar(&opts.podRoot, "pod-root", "", "runtimed on-disk root (image cache + pod dirs); empty derives <work-dir parent> so the SBPL work-dir resides under the daemon home — set this to move PVCs off /Users, which the sandbox always denies")
	registerContainerLogFlags(fs, &opts.logs)
	addRuntimeFlag(fs, &opts.rtName)
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.StringVar(&opts.pathShim, "path-shim", "", "path-rebase DYLD shim dylib path (runtimed runtime only)")
	fs.IntVar(&opts.apiPort, "api-port", executor.DefaultAPIServerPort, "apiserver secure port")
	// The datastore port is per-SERVER, not per-host: two control planes on one Mac
	// sharing it is not a bind contest but a silent datastore takeover — the second
	// server finds the port already serving and comes up healthy against the first
	// server's database. The executor refuses that outright; this flag is how a
	// second control plane on the same host gets a datastore of its own.
	fs.IntVar(&opts.kinePort, "kine-port", executor.DefaultKinePort, "kine (etcd shim) listen port on 127.0.0.1 — every control plane on a host needs its own")
	// The node's kubelet-API port. Same per-server reasoning as --kine-port, one
	// process further down the bring-up: a second server on the default port gets
	// a healthy control plane and then a node that dies with "listen tcp :10250:
	// bind: address already in use". This renumbers the LISTENER ONLY; it does not
	// change the bind address or the API's authn posture.
	fs.IntVar(&opts.kubeletPort, "kubelet-port", ports.KubeletAPIPort, "kubelet HTTP API (logs/exec/stats) listen port — every node on a host needs its own")
	// The scheduler's and controller-manager's secure ports, the last two fixed
	// singletons in a server's listener set. A second server on the defaults gets
	// a healthy apiserver and then a controller-manager that dies on the bind —
	// which used to surface downstream as a namespace bootstrap that never
	// completes, because nothing was running the service-account controller.
	// These flags renumber loopback listeners; they cannot publish one.
	fs.IntVar(&opts.schedulerPort, "scheduler-port", executor.DefaultSchedulerPort, "kube-scheduler secure-serving port on 127.0.0.1 — every control plane on a host needs its own")
	fs.IntVar(&opts.controllerManagerPort, "controller-manager-port", executor.DefaultControllerManagerPort, "kube-controller-manager secure-serving port on 127.0.0.1 — every control plane on a host needs its own")
	// Pod Security Admission. The SHIPPED default is baseline-WARN only (enforce stays
	// privileged; warn=baseline + audit=restricted — audit-observable, zero
	// rejection). This flag is the documented, REVERSIBLE cutover MECHANISM for the
	// baseline-enforce flip: set it only after a pre-flight scan proves the cluster
	// clean; dropping the flag reverts the posture on the next boot. It is an operator argv toggle of a single apiserver config
	// value, not a runtime feature-flag code path.
	fs.BoolVar(&opts.psaEnforceBaseline, "psa-enforce-baseline", false, "flip the cluster-wide Pod Security Admission default ENFORCE level from privileged to baseline (the baseline-enforce cutover; the shipped default is baseline-warn only)")
	// Ingress listener ports. 80/443 is the production posture; an EXPLICIT
	// high-port pair (e.g. 8080/8443) is the integration-tier mode. There is
	// deliberately NO silent fallback between the two — a failed bind is logged and
	// boundedly retried, never re-ported. The listeners bind the WILDCARD; a
	// privileged port goes through the root netd helper when one is present
	// (netd authorizes it against the canonical kube-system/k3sm-ingress Service),
	// a high port binds in-process. They are started BEFORE svclb so they win a
	// contest for these ports against a user LoadBalancer Service declaring them.
	fs.IntVar(&opts.ingressHTTPPort, "ingress-http-port", 80, "ingress HTTP listener port, bound on ALL interfaces (80 = production; an explicit high port is the integration-tier mode; 0 disables the HTTP listener)")
	fs.IntVar(&opts.ingressHTTPSPort, "ingress-https-port", 443, "ingress HTTPS listener port, bound on ALL interfaces (443 = production; an explicit high port is the integration-tier mode; 0 disables the HTTPS listener)")
	// The node-local OCI ingest registry (pkg/registrysvc). DISABLED by default —
	// it is opt-in capacity, not part of a control plane. When enabled it binds
	// LOOPBACK ONLY and that is not configurable: pull is anonymous and push is
	// plain HTTP, so the whole posture rests on nothing off-host being able to
	// reach it. `k3sm dev` enables it on a per-instance allocated port.
	fs.IntVar(&opts.registryPort, "registry-port", 0, "node-local OCI ingest registry port on 127.0.0.1 — push locally built images here and pull them by `localhost:<port>/<ref>` (0 disables; "+strconv.Itoa(executor.DefaultRegistryPort)+" is the suggested port)")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP the per-node resolver binds and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain")
	fs.StringVar(&opts.network, "network", hostnet.NetworkAuto, "host-network backend: auto (root→direct, unprivileged→netd helper +probe) | none (control-plane-only, no datapath/probe) | direct (force lo0, root) | helper (force netd helper)")
	// Embedded etcd HA (the k3s shape). --cluster-init forms a new etcd cluster on
	// this server; --server-join (with --server and a server-class --token) adds this
	// server to an existing one as a learner that is then promoted. Either needs a
	// non-loopback --etcd-peer-ip: the member's peer listener binds it. It is a flag
	// of its own because the peer address is a LAN address already on an interface,
	// while --node-ip is the node's advertised address that the pod network aliases
	// on lo0; one flag carrying both crash-looped every HA server at its pod-network
	// startup reconcile. There is no external-datastore flag; a retired one fails as
	// an unknown flag.
	fs.BoolVar(&opts.clusterInit, "cluster-init", false, "form a new embedded etcd HA control plane on this server (requires a non-loopback --etcd-peer-ip); a restart of an existing member is unaffected")
	fs.BoolVar(&opts.serverJoin, "server-join", false, "join an existing embedded etcd HA control plane (requires a non-loopback --etcd-peer-ip); with --server it also fetches the identical-CA bundle from an existing server")
	fs.StringVar(&opts.etcdPeerIP, "etcd-peer-ip", "", "this server's LAN address, which the embedded etcd member's peer listener binds and every other server dials (embedded etcd HA and --cluster-reset only; not loopback). It is never aliased on lo0 and is not the node's advertised address (--node-ip)")
	fs.BoolVar(&opts.clusterReset, "cluster-reset", false, "turn this server's existing etcd member into a one-member cluster that keeps its data, then exit; refused while the server is running. Restart the server normally afterwards")
	fs.IntVar(&opts.etcdPeerPort, "etcd-peer-port", executor.DefaultEtcdPeerPort, "etcd peer listener port on --etcd-peer-ip (embedded etcd HA only) — every member on a host needs its own")
	fs.IntVar(&opts.etcdMetricsPort, "etcd-metrics-port", executor.DefaultEtcdMetricsPort, "etcd metrics listener port on 127.0.0.1 (embedded etcd HA only) — every member on a host needs its own")
	// Scheduled etcd snapshots: k3s's three flags with k3s's defaults. Each server
	// snapshots its own member into <work-dir>/db/snapshots.
	fs.StringVar(&opts.etcdSnapshotCron, "etcd-snapshot-schedule-cron", executor.DefaultEtcdSnapshotCron, "when to take a scheduled etcd snapshot, as a five-field cron expression in local time (embedded etcd HA only)")
	fs.IntVar(&opts.etcdSnapshotRetention, "etcd-snapshot-retention", executor.DefaultEtcdSnapshotRetention, "how many of this server's scheduled etcd snapshots to keep; manual snapshots are never removed (embedded etcd HA only)")
	fs.BoolVar(&opts.etcdDisableSnapshots, "etcd-disable-snapshots", false, "take no scheduled etcd snapshots (embedded etcd HA only)")
	// HA server-join: a SECOND control-plane server reconstructs the identical
	// cluster + signing CAs from the first server's AES-256-GCM bundle. --token is the
	// SERVER-class token (off argv via $K3SM_TOKEN, like the agent).
	fs.StringVar(&opts.joinServer, "server", "", "an existing server's LAN address (its --etcd-peer-ip): the joining server fetches the identical-CA bootstrap bundle from it and, on its first start, is added to the etcd cluster through it (HA server-join; requires --server-join and --token or --token-file)")
	fs.StringVar(&opts.token, "token", os.Getenv("K3SM_TOKEN"), "server-class join token (K10<caHash>::server:<secret>) for the HA server-join (or $K3SM_TOKEN)")
	// The static admin token as a FILE, and the only way the installed daemon is
	// given one. A LaunchDaemon plist is read by launchd as root but the token on
	// its argv was readable by every account on the Mac — in the plist, in `ps`,
	// and in launchd's own job description — and this one authenticates as
	// system:masters. `k3sm install` stages the value at <data-root>/server/token
	// (0600, owned by the daemon's user) and renders this flag pointing at it.
	//
	// With --server-join the file holds the server-class JOIN token instead, the
	// same value --token would carry: `k3sm install --server-join` stages it at
	// <data-root>/server/join-token and renders this flag pointing there, because
	// that credential reconstructs every cluster CA and must stay off the argv
	// just as the admin token does.
	fs.StringVar(&opts.tokenFile, "token-file", "", "a file holding this server's token, read once at start and preferred over --token and $K3SM_TOKEN: the static admin token, or with --server-join the server-class join token. It must not be group- or world-readable. This is how a supervised server is given its token: the daemon is told where the token is and never what it is")
	return workDirErr
}

// refuseShadowedWorkDir refuses to bring the control plane up when workDir sits
// directly inside a data root that /etc/fstab declares as a mount point but
// which is not mounted — the installed posture, <dataRoot>/server. Coming up
// there means creating the datastore in the bare mountpoint on the boot disk,
// so the cluster silently loses every object on the real volume; refusing costs
// a restart once the volume is mounted.
//
// The cheap containment test comes first: a work-dir outside the data root (a
// --work-dir override, the unprivileged <home>/server dev posture) is none of
// this function's business and does not even read /etc/fstab. An inspection
// error is not a refusal — EnsureWorkDirWritable reports the real failure.
func refuseShadowedWorkDir(fsys dataroot.FS, workDir, dataRoot string) error {
	if filepath.Dir(filepath.Clean(workDir)) != filepath.Clean(dataRoot) {
		return nil
	}
	st, err := dataroot.Read(fsys, dataRoot)
	if err != nil {
		return nil
	}
	if st.Shadowed() {
		return dataroot.Refusal(dataRoot)
	}
	return nil
}

// runServer brings up the control plane (via the executor) and a Virtual Kubelet
// node in one process, then hosts darwin-net's Service proxy + per-node DNS resolver +
// DNS shim and provisions the os=darwin admission policy. It blocks until
// interrupted, then shuts the control plane down cleanly.
//
// It is the orchestrator only: provisioning lives in serverprovision.go and each
// post-bring-up phase in serverphases.go. Every defer stays here, in bring-up
// order, so the teardown order is read off this one body (LIFO).
func runServer(args []string) (err error) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	opts := serverOptions{}
	workDirErr := registerServerFlags(fs, &opts)
	_ = fs.Parse(args)

	logger := newDaemonLogger(os.Stderr, slog.LevelInfo)

	// Free refusals, the crash-loop breaker and the `--network` backend.
	breaker, mode, done, err := preflightServer(&opts, workDirErr, logger)
	if done || err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Secrets encryption and a tripped breaker PARK here (admitServerStart).
	encryptionConfig, done, err := admitServerStart(ctx, opts, breaker, mode, logger)
	if done || err != nil {
		return err
	}

	// 1. Control plane (child-process executor). Stop tears it down in reverse.
	cfg, pki, err := provisionControlPlane(ctx, &opts, encryptionConfig, logger)
	if err != nil {
		return err
	}
	// 1b. The mesh IP must answer on this host before the apiserver binds it.
	// FAIL-FAST, unlike the log-and-continue mesh bring-up at 4b.
	if err = ensureMeshIPAlias(ctx, opts.meshIP, mode, logger); err != nil {
		return err
	}

	// A control-plane child that dies after bring-up must take this process with
	// it, or launchd's restart-on-EXIT KeepAlive never fires (componentExitHandler).
	ctx, crashCancel := context.WithCancel(ctx)
	defer crashCancel()
	var crashedComponent atomic.Pointer[string]
	var cpProbe supervisedProbe // filled by startControlPlane once the executor exists
	cfg.OnComponentExit = componentExitHandler(&crashedComponent, breaker, &cpProbe, crashCancel, logger)
	// A crash cancels ctx, so most errors below would be a bare "context canceled"
	// (and startNode's a nil). Rewriting err here, once, names the crashed
	// component on every return path after this point (componentExitHandler).
	defer func() {
		name := crashedComponent.Load()
		if name == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("control-plane component %q exited; restarting the daemon", *name)
			return
		}
		err = fmt.Errorf("control-plane component %q exited; restarting the daemon: %w", *name, err)
	}()

	// The control-plane node's mesh teardown handle, declared and deferred HERE —
	// BEFORE the control plane's own shutdown defer below — so LIFO runs it LAST,
	// once exec.Stop has signalled and reaped every component. The order is not
	// cosmetic: in the mesh posture the apiserver BINDS and advertises the mesh IP,
	// so tearing the utun and its alias down first would pull the interface out
	// from under a control plane that is still draining.
	// It stays a no-op until step 4b's enroll assigns it, and forever under
	// `--network none`, so registering it this early costs nothing.
	meshDown := meshTeardown(noMeshTeardown)
	defer func() { meshTeardownOnExit(ctx, meshDown, logger) }()

	// The HA etcd member route, then the supervised executor (startControlPlane).
	plan, exec, err := startControlPlane(ctx, opts, mode, cfg, pki, breaker, &cpProbe, logger)
	if err != nil {
		return err
	}
	// The control-plane teardown, as a stage that OVERLAPS the node's embedded
	// runtime close instead of queueing behind it: the node fires cpStop.begin at
	// the very start of its own teardown (nodeOpts.onExitBegin below), and this
	// defer waits for what that began. If the node never got that far — a bring-up
	// that failed before startNode's teardown ran — finish runs the stop itself,
	// which is exactly what this defer did before. Its budget is still
	// executor.StopBound, one named stage of the plist's ExitTimeOut, which
	// pkg/install derives from that same symbol; see exitoverlap.go.
	cpStop := newControlPlaneStopper(ctx, exec.Stop, logger)
	defer func() {
		// A wait that timed out has already reported itself, with the stage and the
		// launchd consequence in its fields; logging it again here would double-report
		// one event under two messages.
		if err := cpStop.finish(); err != nil && !errors.Is(err, errControlPlaneStopTimeout) {
			logger.Error("control-plane shutdown", "err", err)
		}
	}()
	logger.Info("k3sm control plane healthy", "kubeconfig", exec.Kubeconfig())
	// A bring-up that stays healthy for the whole window resets the breaker;
	// a crash before then leaves the record for the count (see crashBreaker).
	healthyReset := time.AfterFunc(executor.CrashLoopWindow, breaker.resetIfHealthy)
	defer healthyReset.Stop()

	// 2. Client for the post-bring-up provisioning + Service watch.
	restCfg, cs, err := kubeclient.FromPath(exec.Kubeconfig())
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	// 3–3c. Admission policies, the fail-closed RBAC graph, the embedded add-ons.
	if err = provisionServerCluster(ctx, plan, restCfg, cs, logger); err != nil {
		return err
	}
	// 3c''/3c'. Each stop drains before exec.Stop's defer (LIFO runs it first).
	stopHelm := startHelmController(ctx, plan, restCfg, cs, logger)
	defer stopHelm()
	stopManifests := startManifestDir(ctx, restCfg, cs, logger)
	defer stopManifests()
	// Can this node host vm guests? Asked before the registry and datapath use it.
	vmCapable := vmBackendAvailable()
	// 3d. The ingest registry; torn down BEFORE the control plane (LIFO).
	stopRegistry, registryPuller := startServerRegistry(ctx, plan, cs, vmCapable, logger)
	defer stopRegistry()
	// 4a. The MeshPeer CRD, FAIL-CLOSED, before anything that can write a MeshPeer.
	if err = ensureMeshPeerCRD(ctx, opts.meshIP, func() (crdensure.CRDClient, error) {
		return apiextensionsclient.NewForConfig(restCfg)
	}, logger); err != nil {
		return err
	}
	// 4b. This server joins its own mesh through the ONE shared enroller.
	sm, err := enrollServerMesh(ctx, plan, restCfg, cs, exec.Kubeconfig(), meshDown, logger)
	meshDown = sm.down
	if err != nil {
		return err
	}
	// 4c. The node-local datapath (Service proxy + per-node DNS resolver).
	net, nodeAddressing := startServerDatapath(ctx, plan, cs, sm, vmCapable, logger)
	// 4d. The worker-join supervisor; its stop closes the HA etcd admin client.
	closeEtcdAdmin := startJoinSupervisor(ctx, plan, cs, sm, logger)
	defer closeEtcdAdmin()
	// 4e/4f. Each stop drains before exec.Stop's defer (LIFO runs it first).
	stopProvisioner := startProvisioner(ctx, plan, cs, logger)
	defer stopProvisioner()
	mlxGPU, stopMLX := startMLXOperator(ctx, plan, restCfg, cs, logger)
	defer stopMLX()
	if sm.dataPathRefused != nil { // this server's pod range is not its own
		return parkServerDataPath(ctx, opts, sm.dataPathRefused, logger)
	}
	nodeOpts, err := serverNodeOptions(plan, restCfg, nodeAddressing,
		serverNodeWiring{net: net, mlxGPU: mlxGPU, cpStop: cpStop, registryPuller: registryPuller}, logger)
	if err != nil {
		return err
	}
	// 4g/4h, then 5's label repair (prepareServerNode). The deferred crash check
	// above names the component on the startNode path too.
	if err = prepareServerNode(ctx, plan, cs, nodeOpts, logger); err != nil {
		return err
	}
	return startNode(ctx, nodeOpts)
}

// startServerDatapath is step 4c: it hosts the node-local datapath — darwin-net's
// Service proxy (exempted from the DNS VIP, which the per-node resolver below
// owns) + the per-node cluster DNS resolver bound to the DNS VIP + the pod
// DNSConfig the shim consumes. The NetdSocket routes the proxy/resolver privileged
// lo0/port ops through the root helper when unprivileged (empty in root mode →
// direct ops); Disabled (--network none) runs no datapath. It returns the Server
// and the addressing half of the in-process node's options.
//
// MeshEgressIP and PeerMeshEgressIPs are seeded from step 4b's enroll. The
// dialer's source bind is DESTINATION-SCOPED (darwin-net binds it only for a
// destination inside the cluster pod CIDR and outside this node's own /24), so
// wiring a real mesh-egress source here does not disturb loopback, ClusterIP or
// node-LAN dials — an unscoped source bind is what made this wiring unsafe
// before.
//
// A server whose pod range is not its own (sm.dataPathRefused) starts NO datapath
// and returns zero values: runServerNode parks it before anything reads them.
func startServerDatapath(ctx context.Context, plan serverPlan, cs kubernetes.Interface, sm serverMesh, vmCapable bool, logger *slog.Logger) (*netserve.Server, nodeOptions) {
	if sm.dataPathRefused != nil {
		return nil, nodeOptions{}
	}
	opts, mode := plan.opts, plan.mode
	// The kubernetes-VIP backend: ONLY the loopback-advertise posture (single
	// node) pins the static proxy backend at the apiserver's real loopback listen
	// address — upstream validation rejects loopback endpoint addresses, so no
	// kubernetes EndpointSlice can exist there. A mesh apiserver binds/advertises
	// the mesh IP, publishes its OWN valid endpoints, and the proxy must follow
	// that real slice (a static loopback pin would route the VIP at a
	// non-listening address).
	apiServerEndpoint := ""
	if isLoopbackDefault(opts.nodeIP) {
		apiServerEndpoint = "127.0.0.1:" + strconv.Itoa(opts.apiPort)
	}
	// nodeAddressing holds the only inputs advertisedNodeIP reads. The full
	// nodeOpts cannot be built this early: it needs this netserve Server (its
	// transportOverrides) and the MLX runtime hook, both constructed at or after
	// this point. So the addressing half is built once here and nodeOpts
	// copies it, rather than a second literal restating the same fields.
	nodeAddressing := nodeOptions{nodeIP: opts.nodeIP, podCIDR: sm.podCIDR, netMode: mode}
	net := netserve.New(netserve.Config{
		Client:            cs,
		WorkDir:           opts.workDir,
		DNSVIP:            opts.clusterIP,
		ClusterDomain:     opts.domain,
		APIServerEndpoint: apiServerEndpoint,
		NodeIP:            opts.nodeIP,
		// The address the in-process node and the ingress host advertise. It is
		// derived from nodeAddressing, which nodeOpts copies its three
		// addressing fields from, so both read one value.
		NodeAddress:       advertisedNodeIP(nodeAddressing),
		PodCIDR:           sm.podCIDR,
		MeshEgressIP:      sm.egressIP,
		PeerMeshEgressIPs: sm.peerEgress,
		VMBackend:         vmCapable,
		VMNetSubnet:       netserve.DefaultVMNetSubnet,
		// cs is the admin client (exec.Kubeconfig()), so the policy watcher's
		// cluster-wide NetworkPolicies, Pods and Namespaces reads are allowed
		// and PodScopeNode stays empty. TestServerNetservePolicyClientIsAdmin
		// pins both.
		EnforceNetworkPolicy: true,
		NetdSocket:           mode.Socket,
		Disabled:             !mode.DataPath(),
		Logger:               logger,
	})
	go func() {
		if err := net.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("darwin-net services", "err", err)
		}
	}()
	return net, nodeAddressing
}

// serverNodeWiring is what the in-process node's options take from the phases
// before them: the datapath Server (step 4c), the MLX GPU source (step 4f), the
// control-plane stopper, and the ingest registry's puller wiring (step 3d).
type serverNodeWiring struct {
	net            *netserve.Server
	mlxGPU         *operator.RuntimeGPU
	cpStop         *controlPlaneStopper
	registryPuller registryPullerWiring
}

// serverNodeOptions builds the in-process node's options, mints its client
// identity, and sets its kubelet serving cert (step 4f-bis).
//
// The in-process node's options are built after step 4f and before the
// LB/ingress block, and the LB/ingress configuration is derived from this same
// value — so the address `kubectl get svc` shows as EXTERNAL-IP and the address
// the Node object advertises cannot diverge (they read one podCIDR, one nodeIP,
// one netMode through one shared derivation, advertisedNodeIP).
func serverNodeOptions(plan serverPlan, restCfg *rest.Config, nodeAddressing nodeOptions, w serverNodeWiring, logger *slog.Logger) (nodeOptions, error) {
	opts, mode := plan.opts, plan.mode
	// The kubelet endpoint's client-identity anchor is read here, off the work dir's
	// PKI: EnsureHierarchy has run (the mesh provisioning, or the executor's
	// provisionComponentCerts during exec.Start), so the signing CA certificate
	// exists in EVERY posture — single-node, `k3sm dev`, mesh and HA alike. It is
	// the same CA the apiserver's --client-ca-file trusts and the issuer of the
	// --kubelet-client-certificate the executor just minted, so the node and the
	// apiserver agree on the identity by construction rather than by configuration.
	// A read failure stops the server: :10250 is not served unauthenticated.
	kubeletClientCA, err := os.ReadFile(certs.SigningCACertPath(opts.workDir))
	if err != nil {
		return nodeOptions{}, fmt.Errorf("read the kubelet endpoint's client-identity CA: %w", err)
	}

	// The in-process node's CLIENT identity: system:node:<name> in the system:nodes
	// group, minted in memory from the same signing CA, exactly what a joined worker
	// carries. The node no longer shares the admin kubeconfig the bring-up
	// runs on (that client keeps system:masters, and so does everything built on
	// it). The hierarchy is loaded here rather than reusing plan.hierarchy, which is
	// set only on the mesh path; EnsureHierarchy LOADS the existing CAs in every
	// posture, because the executor's provisioning step created them at exec.Start.
	// It takes this server's own role all the same, so a joined server proves here
	// that it only loads.
	nodeHierarchy, err := certs.EnsureHierarchy(opts.workDir, opts.role(), opts.posture())
	if err != nil {
		return nodeOptions{}, fmt.Errorf("load the CA hierarchy for the server node's client identity: %w", err)
	}
	nodeRESTCfg, err := serverNodeRESTConfig(restCfg, nodeHierarchy, opts.nodeName)
	if err != nil {
		return nodeOptions{}, err
	}
	if cn, notAfter, err := clientCertIdentity(nodeRESTCfg.CertData); err == nil {
		logger.Info("minted the server node's client identity (in memory, never written to disk)", "cn", cn, "groups", nodesGroup, "not_after", notAfter.UTC().Format(time.RFC3339))
	} else {
		return nodeOptions{}, fmt.Errorf("read back the server node's client identity: %w", err)
	}

	nodeOpts := nodeOptions{
		restConfig: nodeRESTCfg,
		nodeName:   opts.nodeName,
		listen:     serverKubeletListenOn(opts.kubeletPort),
		podRoot:    opts.podRoot,
		logs:       opts.logs,
		nodeIP:     nodeAddressing.nodeIP,
		// The one cluster Service CIDR; see nodeOptions.serviceCIDR.
		serviceCIDR: install.DefaultServiceCIDR,
		runtime:     opts.rtName,
		dnsShim:     opts.dnsShim,
		pathShim:    opts.pathShim,
		dnsVIP:      opts.clusterIP,         // scope the pod Seatbelt egress to the same cluster DNS VIP the resolver binds
		domain:      opts.domain,            // SAME cluster domain the per-node resolver serves → in-pod shim search list
		podCIDR:     nodeAddressing.podCIDR, // this server's --mesh-ip /24 (same source as the netserve locality)
		netMode:     nodeAddressing.netMode, // the resolved --network backend the podnet alias plumbing follows
		serveTLS:    true,                   // serve kubelet API over TLS so logs/exec work via the proxy

		kubeletClientCAPEM: kubeletClientCA, // :10250 requires the apiserver's client cert

		// Close the loop opened at step 4f: the node publishes its in-process
		// runtime here, and the MLX operator's fit check starts reading live GPU
		// facts off it. A hostprocess node never calls it, leaving the fit check
		// skipped — the honest answer where there is no runtimed to ask.
		attachRuntimeInfo: w.mlxGPU.Attach,
		// Start this server's control-plane stop the moment the node begins tearing
		// down, so it drains while the node closes its embedded runtime rather than
		// after it. runServer's defer is what waits for it.
		onExitBegin: w.cpStop.begin,
		// The Service proxy this same process built (step 4c) is where the
		// provider publishes a vm pod's live guest lease, so a Service backed by a
		// guest is dialed at the address that carries bytes while everything else
		// keys on the /32 the pod publishes. nil under --network none, where there
		// is no proxy to feed.
		transportOverrides: nodeTransportOverrides(w.net, mode),
		// How runtimed spells this node's own ingest registry (step 3d): the
		// loopback authority a bare "app:v1" resolves against first, and the
		// non-loopback spellings of the same registry — a reference naming one of
		// them is node-relative in exactly the sense a `localhost:<port>/…`
		// reference is, so it gets the same plain-HTTP transport and the same
		// peer-mirror brokering. Zero on a node with no registry.
		localRegistryHost: w.registryPuller.LocalHost,
		clusterRegistries: w.registryPuller.ClusterRegistries,
		// This server's own kine port — the SAME resolved value (flag or default)
		// that reaches executor.Config.KinePort — so every pod's SBPL denies
		// connect() to the node's plaintext datastore listener. The deny is by
		// port, not address (Seatbelt cannot filter by IP), so a Service that
		// reuses this port number is also unreachable from confined pods.
		deniedLocalPorts: opts.deniedLocalPorts(),
	}

	// 4f-bis. The control-plane node's OWN kubelet serving cert.
	//
	// A worker receives one in its join response; this node never joins, so nothing
	// hands it one and it self-signed — against its own apiserver, which the mesh
	// provisioning started with --kubelet-certificate-authority=<cluster CA>. That is
	// the defect in its purest form: `kubectl logs` against the control-plane node
	// failed with "x509: certificate signed by unknown authority" on the very machine
	// holding the CA that could have signed it. It runs HERE because the SAN set is
	// read off the finished nodeOpts, and it fails the whole bring-up on a
	// mint error rather than degrading to the self-signed cert that is the defect.
	if err := setServerKubeletServing(&nodeOpts, plan.hierarchy, opts.meshIP); err != nil {
		return nodeOptions{}, err
	}
	return nodeOpts, nil
}

// crdClientFactory builds the apiextensions client a CRD ensure applies through.
//
// It is a FACTORY rather than a client so that a bring-up which provisions no CRD
// constructs none: `k3sm server` without --mesh-ip has no MeshPeer consumer, and a
// client built unconditionally would add a new way for the single-node path to fail
// at a step it never needed.
type crdClientFactory func() (crdensure.CRDClient, error)

// ensureMeshPeerCRD server-side-applies the MeshPeer CustomResourceDefinition and
// blocks until the API server reports it Established, on the MESH path only.
//
// meshIP empty is the single-node posture: it returns nil having called newClient
// zero times. That gate lives HERE, not at the call site, so "which bring-up
// provisions the CRD" has one answer that a test can drive both sides of.
//
// The manifest is k3sm.io/apis' own bytes (crdconfig.MeshPeerCRD) applied through
// pkg/crdensure — the same applier the MLX operator uses for MLXModel — so there is
// no second apply path and no shadow copy of the schema. An error is returned, never
// logged and swallowed: the caller fail-closes on it (see step 4a in runServer).
//
// Step 4a runs it on the MESH path only, BEFORE anything that can write a MeshPeer
// exists. Nothing used to apply it: the manifest shipped in k3sm.io/apis and every
// worker join 500'd at the enroller's write until a human installed the CRD by
// hand.
//
// The ORDER is the point. It must precede newMeshEnroller (step 4b) and therefore
// the join listener startBootstrapServer opens, because the first worker to reach
// that listener writes a MeshPeer — a CRD ensured afterwards would still lose
// whichever join won the race. It also precedes this server's OWN enroll, which is
// the very first MeshPeer written on a fresh cluster.
//
// FAIL-CLOSED, like the RBAC graph at step 3b and unlike the log-and-continue
// admission policies at step 3: a missing MeshPeer CRD is not a missing advisory,
// it is a control plane that accepts worker joins and then fails every one of
// them. Halting with the reason beats serving a supervisor that cannot enroll.
// Single-node provisions NOTHING, so the call adds no failure mode there.
func ensureMeshPeerCRD(ctx context.Context, meshIP string, newClient crdClientFactory, logger *slog.Logger) error {
	if meshIP == "" {
		return nil
	}
	c, err := newClient()
	if err != nil {
		return fmt.Errorf("build apiextensions client for the %s crd: %w", crdconfig.MeshPeerCRDName, err)
	}
	if _, err := crdensure.Ensure(ctx, c, crdconfig.MeshPeerCRD(), crdensure.Options{Log: logger}); err != nil {
		return fmt.Errorf("ensure the %s crd (worker joins cannot enroll without it): %w", crdconfig.MeshPeerCRDName, err)
	}
	logger.Info("ensured the MeshPeer CRD; worker enroll writes can now land", "crd", crdconfig.MeshPeerCRDName)
	return nil
}

// kubeletServingValidFor is the lifetime of the control-plane node's kubelet
// serving cert. It is pinned to the SAME 365d writeAPIServerServingCert gives the
// apiserver's leaf: both are re-minted by every boot of the same process, so a
// shorter life here would only mean the node's cert expired first on a long-lived
// server — a second expiry date to reason about, buying nothing.
const kubeletServingValidFor = 365 * 24 * time.Hour

// setServerKubeletServing mints the control-plane node's kubelet serving keypair
// from the CLUSTER CA and stores it on nodeOpts, for the posture where the
// apiserver was told to verify node certs against that CA.
//
// meshIP == "" is the single-node/dev posture: it leaves the fields EMPTY, so
// kubeletServingTLS self-signs exactly as before. That branch is load-bearing — a
// single-node apiserver configures no --kubelet-certificate-authority, so a
// cluster-CA leaf would buy nothing and the self-signed path stays the default this
// change does not disturb.
//
// The pair is held in MEMORY and re-minted on every boot: nothing is written to
// disk, so no new private key file joins the work dir and pkg/executor's rotation
// fence needs no new path (the artifact is nevertheless REPORTED there — see
// reissuedArtifacts — because a credential re-issued on every boot belongs in the
// rotation report whether or not it lands on a filesystem).
//
// It FAILS CLOSED. A cluster CA that cannot issue is an error the caller must
// propagate: falling back to a self-signed leaf here would silently reproduce the
// exact defect this function exists to remove, and would do it in the one case
// (broken PKI) where an operator most needs to be told.
func setServerKubeletServing(nodeOpts *nodeOptions, hierarchy *certs.Hierarchy, meshIP string) error {
	if meshIP == "" {
		return nil
	}
	// Checked BEFORE issuing, and down to the key: a CA loaded without its private
	// half cannot sign, and x509.CreateCertificate's reaction to one is not a
	// diagnosable error. Refusing here names the real fault — the work dir's PKI —
	// where an operator can act on it.
	if hierarchy == nil || hierarchy.Cluster == nil || hierarchy.Cluster.Cert == nil || hierarchy.Cluster.Key == nil {
		return fmt.Errorf("mint the control-plane node's kubelet serving cert: no usable cluster CA (the multi-node posture needs the signing half of the CA hierarchy the apiserver's --kubelet-certificate-authority names)")
	}
	certPEM, keyPEM, err := hierarchy.Cluster.IssueServing(
		nodeOpts.nodeName,
		[]string{nodeOpts.nodeName, "localhost"},
		serverKubeletServingIPs(*nodeOpts, meshIP),
		kubeletServingValidFor,
	)
	if err != nil {
		return fmt.Errorf("mint the control-plane node's kubelet serving cert: %w", err)
	}
	nodeOpts.kubeletServingCertPEM = certPEM
	nodeOpts.kubeletServingKeyPEM = keyPEM
	return nil
}

// nodesGroup is the group every node client identity carries (O=system:nodes), the
// one the Node authorizer and NodeRestriction key on beside the system:node:<name>
// user.
const nodesGroup = "system:nodes"

// serverNodeRESTConfig builds the client config the control-plane node's in-process
// Virtual Kubelet node runs on: CN=system:node:<nodeName>, O=system:nodes, signed
// by the SIGNING CA the apiserver's --client-ca-file trusts. That is the identity a
// joined worker already carries, so the server's node is authorized by the Node
// authorizer, admitted by NodeRestriction, and granted only what pkg/rbac already
// grants the system:nodes group; it no longer rides the admin identity.
//
// It starts from rest.AnonymousClientConfig(admin): the admin config's Host and its
// server-trust half (CA, ServerName, Insecure) are kept, and EVERY credential is
// dropped by construction (bearer token and token file, client cert and key files,
// exec and auth providers, basic auth, impersonation), so nothing of the admin
// identity can ride along. The minted pair is then the only credential.
//
// The pair is held in memory and re-minted on every boot, like the node's kubelet
// serving pair: no key file joins the work dir. Its lifetime is the per-boot
// component leaves' (executor.ComponentCertValidity). The admin config's rate
// limiter is dropped too, so the node's own request budget applies.
//
// This narrows the node CLIENT only. The server process still holds the admin
// kubeconfig and the signing CA; it is not a process boundary.
//
// It fails closed: a hierarchy without a usable signing CA is an error, never a
// fallback to the admin identity.
func serverNodeRESTConfig(admin *rest.Config, h *certs.Hierarchy, nodeName string) (*rest.Config, error) {
	if admin == nil {
		return nil, errors.New("mint the server node's client identity: no admin client config to take the apiserver address from")
	}
	if nodeName == "" {
		return nil, errors.New("mint the server node's client identity: empty node name")
	}
	if h == nil || h.Signing == nil || h.Signing.Cert == nil || h.Signing.Key == nil {
		return nil, errors.New("mint the server node's client identity: no usable signing CA (the work dir's PKI must carry the signing half of the CA hierarchy)")
	}
	certPEM, keyPEM, err := h.Signing.IssueClient(nodeSystemPrefix+nodeName, []string{nodesGroup}, executor.ComponentCertValidity)
	if err != nil {
		return nil, fmt.Errorf("mint the server node's client identity: %w", err)
	}
	cfg := rest.AnonymousClientConfig(admin)
	cfg.RateLimiter = nil
	cfg.TLSClientConfig.CertData = certPEM
	cfg.TLSClientConfig.KeyData = keyPEM
	applyNodeClientBudget(cfg)
	return cfg, nil
}

// clientCertIdentity reads the subject CN and NotAfter off a PEM client cert, for
// the bring-up log line. It reads the certificate only, never key material.
func clientCertIdentity(certPEM []byte) (string, time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", time.Time{}, errors.New("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.Subject.CommonName, cert.NotAfter, nil
}

// serverKubeletServingIPs is the IP SAN set of that cert: every address the
// apiserver might dial this node's :10250 at, deduplicated, unparseable entries
// dropped.
//
//   - meshIP — what peers know this node by, and what a mesh apiserver binds;
//   - the ADVERTISED address (advertisedNodeIP) and the raw nodeOpts.nodeIP — the
//     two can differ, and startNode advertises the derived one;
//   - the REGISTERED InternalIP (proxyableNodeIP of the advertised opts, exactly as
//     startNode computes it). This is the address --kubelet-preferred-address-types
//     =InternalIP makes the apiserver dial, and in the NO-DATAPATH posture it
//     legitimately diverges from the advertised address — so omitting it would
//     reproduce the broken-logs/exec defect as a SAN mismatch instead of an issuer
//     mismatch, which is the
//     same broken logs/exec with a less legible error;
//   - 127.0.0.1 — the same-host dial.
//
// A superset is the safe direction here: every address in the set is one this node
// already serves on (the listen is the wildcard), so naming it in a SAN grants no
// reach that did not exist. Omitting one silently breaks logs/exec.
func serverKubeletServingIPs(nodeOpts nodeOptions, meshIP string) []net.IP {
	advertised := nodeOpts
	advertised.nodeIP = advertisedNodeIP(nodeOpts)
	candidates := []string{
		meshIP,
		nodeOpts.nodeIP,
		advertised.nodeIP,
		proxyableNodeIP(advertised),
		"127.0.0.1",
	}
	var ips []net.IP
	for _, c := range candidates {
		ip := net.ParseIP(c)
		if ip == nil || slices.ContainsFunc(ips, ip.Equal) {
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}

// writeAPIServerServingCert issues the apiserver's serving cert from the cluster CA
// (so a joining node that pinned the cluster CA verifies the apiserver via its
// kubeconfig) with SANs covering the mesh IP, loopback, the kubernetes service IP,
// and the in-cluster DNS names. It writes the cert 0644 and the key 0600 under the
// PKI dir and returns their paths for --tls-cert-file / --tls-private-key-file.
func writeAPIServerServingCert(workDir string, clusterCA *certs.CA, meshIP string) (certFile, keyFile string, err error) {
	dnsNames := []string{
		"kubernetes", "kubernetes.default", "kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local", "localhost",
	}
	ips := []net.IP{net.ParseIP(meshIP), net.ParseIP("127.0.0.1"), net.ParseIP("10.43.0.1")}
	certPEM, keyPEM, err := clusterCA.IssueServing("kube-apiserver", dnsNames, ips, 365*24*time.Hour)
	if err != nil {
		return "", "", fmt.Errorf("issue apiserver serving cert: %w", err)
	}
	certFile = certs.APIServerServingCertPath(workDir)
	keyFile = certs.APIServerServingKeyPath(workDir)
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write apiserver serving cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write apiserver serving key: %w", err)
	}
	return certFile, keyFile, nil
}

// provisionClusterPolicies lays down the cluster-scoped admission policies and the
// vm RuntimeClass on a freshly-healthy control plane. Every step is
// LOG-AND-CONTINUE: none of them can halt bring-up (unlike the fail-closed RBAC
// graph that follows), because a node that refuses to start is strictly worse than
// a node missing an advisory.
//
// The set is POSTURE-INDEPENDENT — mode is logged, never branched on. That is the
// The fix: the foreign-user ceiling used to be provisioned only under the netd
// helper backend, so a `--network none`/`direct` cluster ran with no such policy
// object at all and admitted the very pods the ceiling exists to reject.
//
// euid is the effective uid of this process; the foreign-user policy's allowed
// identity is derived from it by provider.PodExecutionUID, which answers "what uid
// do pods here actually execute as" rather than "what uid is the server".
func provisionClusterPolicies(ctx context.Context, cs kubernetes.Interface, mode hostnet.Mode, euid int, deniedLocalPorts []int, logger *slog.Logger) {
	allowedUID := provider.PodExecutionUID(euid)
	logger.Info("provisioning cluster admission policies",
		"network-backend", mode.Backend.String(), "pod-execution-uid", allowedUID)
	// The os=darwin ValidatingAdmissionPolicy (intent guard).
	if err := policy.EnsureDarwinAdmission(ctx, cs); err != nil {
		logger.Error("provision admission policy", "err", err)
	}
	// Honest-gap Warn advisories on Services: externalTrafficPolicy: Local
	// is not honored (the userspace splice does not preserve client source IP) and
	// UDP ports have no datapath yet (the proxy opens no UDP listener). They warn at
	// the API (never reject) so the divergence is visible in kubectl. Provisioned
	// unconditionally — these are inherent Service-model limits, not mode-specific.
	if err := policy.EnsureExternalTrafficPolicyLocalWarn(ctx, cs); err != nil {
		logger.Error("provision externalTrafficPolicy=Local warn policy", "err", err)
	}
	if err := policy.EnsureUDPServiceWarn(ctx, cs); err != nil {
		logger.Error("provision UDP-service warn policy", "err", err)
	}
	// DENY a type: LoadBalancer Service declaring a port k3sm's own wildcard
	// listeners own (the NodePort range, the kubelet API port). Log-and-continue
	// like every sibling Ensure*, but the message NAMES the consequence: a silently
	// absent Deny VAP is otherwise indistinguishable from a present one, and the
	// operator would only meet the collision as an unexplained <pending> Service
	// (svclb still refuses the bind — that is the datapath half of the guard).
	if err := policy.EnsureRejectReservedLoadBalancerPort(ctx, cs); err != nil {
		logger.Error("provision reserved-loadbalancer-port DENY policy: a LoadBalancer Service declaring a k3sm-reserved port (NodePort range / kubelet API port) will now be ACCEPTED by the API instead of rejected; svclb still refuses to bind it, so such a Service stays <pending> with only a log line to explain it", "err", err)
	}
	// DENY a Service published on one of this node's DENIED LOCAL PORTS — the
	// loopback ports every confined pod's sandbox denies connect() to (the kine
	// listener), stamped onto the node from the SAME opts.deniedLocalPorts() value
	// passed here. No type gate: the deny is by port number, so a ClusterIP is as
	// unreachable as a LoadBalancer. Log-and-continue like every sibling Ensure*,
	// and the message names the consequence, because the failure this rejects is
	// invisible: the Service is created, its endpoints go Ready, and every pod's
	// connect() is refused inside its own sandbox with nothing in the cluster to say so.
	if err := policy.EnsureRejectServiceDeniedLocalPort(ctx, cs, deniedLocalPorts); err != nil {
		logger.Error("provision denied-local-port DENY policy: a Service published on a port every confined pod's sandbox denies (the node's loopback datastore listener) will now be ACCEPTED by the API; it will be created with Ready endpoints and still be unreachable from every pod, with no cluster-level event to explain it", "err", err, "denied-local-ports", deniedLocalPorts)
	}
	// Honest-gap Warn advisory on Pods: a pod with no toleration for the
	// provider taint (k3sm.io/provider:NoSchedule, on EVERY node) is left
	// Unschedulable by the scheduler. Warn at the API (never reject — a non-tolerating
	// pod is valid k8s) so a directly-created pod's omission is visible in kubectl.
	// Provisioned UNCONDITIONALLY (not mode-gated): the taint is on every node.
	if err := policy.EnsureProviderTolerationWarn(ctx, cs); err != nil {
		logger.Error("provision provider-toleration warn policy", "err", err)
	}
	// Honest-plumbing Warn advisory on Pods: a pod carrying a HAND-SET
	// k3sm.io/internet-egress annotation (without the operator-managed discriminator
	// label pkg/mlx.Render stamps) opts its sandbox into allow_internet_egress. The
	// policy + its unit tests landed before any call site existed, so a running
	// cluster provisioned six policies and hand-setting the annotation warned
	// nothing — the same tests-pass-but-wiring-absent class as the operator's
	// unwired GPU source above. Provisioned
	// UNCONDITIONALLY like its siblings: the annotation is read on every runtime path,
	// not only under MLX. Log-and-continue — it is advisory, never a boundary.
	if err := policy.EnsureEgressAnnotationWarn(ctx, cs); err != nil {
		logger.Error("provision hand-set-internet-egress warn policy", "err", err)
	}
	// The same honest-plumbing advisory for the OTHER opt-in annotation: a pod
	// carrying a hand-set k3sm.io/xcode-toolchain annotation widens its sandbox with
	// read access to this node's developer toolchain. Provisioned right beside its
	// sibling and on the same terms — unconditional (the annotation is read on every
	// native runtime path), advisory, log-and-continue — so the pair cannot drift
	// into the state where one opt-in warns and the other passes unremarked.
	if err := policy.EnsureXcodeToolchainAnnotationWarn(ctx, cs); err != nil {
		logger.Error("provision hand-set-xcode-toolchain warn policy", "err", err)
	}
	// MUTATING policy on Pods: a DaemonSet-owned pod is created by the DS
	// controller (KCM), so the CREATE-Warn advisory above never reaches its author and
	// the pod sits Unschedulable against the provider taint. Inject the provider
	// toleration (never the os=darwin nodeSelector — Res.7) so DS pods schedule.
	// CHANGES the stored object, unlike the Warn/Deny VAPs. Log-and-continue; requires
	// the executor's v1beta1 runtime-config + MutatingAdmissionPolicy feature gate.
	if err := policy.EnsureDaemonSetTolerationMutation(ctx, cs); err != nil {
		logger.Error("provision daemonset-toleration mutating policy", "err", err)
	}
	// Every pod runs as ONE uid (no per-pod uid isolation), so REJECT a pod
	// requesting a foreign runAsUser/runAsGroup/fsGroup/supplementalGroups at
	// admission rather than letting it wedge at spawn. Provisioned UNCONDITIONALLY,
	// like its siblings: the ceiling is a product-wide property. It used to sit
	// behind `if mode.UsesHelper()` — a deliberate choice, on the reasoning that a
	// root server can honor a real drop and `none` is CI-only — but that made the
	// networking-backend selector stand in for "can the runtime honor a uid drop",
	// so `--network none`/`direct` clusters had NO policy object and admitted the
	// pods the ceiling exists to reject. Accepted cost of the operator's ratified
	// Option A: a root server no longer serves a foreign-fsGroup pod it could
	// genuinely have honored.
	if err := policy.EnsureNoForeignUserAdmission(ctx, cs, allowedUID); err != nil {
		logger.Error("provision foreign-user admission policy: a pod requesting a foreign runAsUser/fsGroup will now be ADMITTED and then wedge at spawn (or silently run as the wrong identity) instead of being rejected at the API", "err", err)
	}
	// The memory-only default LimitRange in the `default` namespace:
	// containers that omit resources get honest memory defaults (memory IS enforced
	// via the rusage sampler→OOMKill); deliberately NO cpu key (best-effort only).
	// Create-or-update like every sibling Ensure* (see pkg/policy.ensure:
	// a create-only provisioner freezes the shipped defaults at whatever a cluster
	// was first created with); log-and-continue like the sibling advisories.
	if err := policy.EnsureDefaultLimitRange(ctx, cs); err != nil {
		logger.Error("provision default memory limitrange", "err", err)
	}
	// Provision the vm RuntimeClass (node.k8s.io/v1 "vm", handler vm, with a
	// scheduling.nodeSelector pinning it to VZ-capable nodes via
	// k3sm.io/virtualization). Log-and-continue (NOT fail-closed like rbac): a missing
	// RuntimeClass cannot lock workers out — it only makes a vm pod unschedulable / a
	// vm-pod admission rejected — so it never halts bring-up. No node advertises the
	// VZ label today (runtimed reports no per-backend availability), so a vm pod stays
	// Pending — the correct posture for this non-VZ foundation.
	if err := runtimeclass.Provision(ctx, cs); err != nil {
		logger.Error("provision vm runtime class", "err", err)
	}
}

// canonicalServerNodeName checks the server's --node-name. A name with no
// canonical form is refused, and so is one that only differs from its canonical
// form (case, surrounding spaces): an operator's explicit flag is never renamed
// silently, because the node's Node object, certificates and node-password
// binding would then carry a name the operator did not choose.
func canonicalServerNodeName(given string) (string, error) {
	name, err := bootstrap.CanonicalNodeName(given)
	if err != nil {
		return "", fmt.Errorf("--node-name: %w", err)
	}
	if name != given {
		return "", fmt.Errorf("--node-name %q is not in canonical form; pass --node-name %s", given, name)
	}
	return name, nil
}
