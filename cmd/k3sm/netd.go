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
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
	"k3sm.io/k3sm/pkg/netdsvc"
)

// netdOptions configures `k3sm netd` — the root privileged-network helper.
type netdOptions struct {
	socket      string
	nodePodCIDR string
	serviceCIDR string
	serviceUID  int
	meshKeyDir  string
	kubeconfig  string
	nodeIP      string
	// dnsVIP and clusterDomain are the node resolver entry's server and
	// cluster match domain. Their defaults are the same constants the server
	// and agent --dns-vip/--cluster-domain flags default to, and the installed
	// plists pass neither, so the three daemons agree by construction.
	dnsVIP        string
	clusterDomain string
}

// netdFlags registers `k3sm netd`'s flags against opts and returns the set. It
// is split out of runNetd so the DEFAULTS are reachable without running the
// daemon (which requires root): the node-pod-CIDR default is a cross-command
// invariant, and a test that re-derives it by hand would pin the derivation
// rather than the value the flag actually carries.
func netdFlags(opts *netdOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("netd", flag.ExitOnError)
	fs.StringVar(&opts.socket, "socket", netd.DefaultSocketPath, "unix socket to listen on")
	// The pre-adoption node /24 default is DERIVED, never typed: it is the
	// index-0 carve of the cluster pod CIDR (defaultNodePodCIDR) a single node
	// gives itself, and the two must be the SAME value. netd's adoption treats
	// "the identity already in force" as a no-op and refuses a DIFFERENT identity
	// once anything is live, so a literal here that drifted from the carve would
	// turn a silent no-op into a refused adoption on a node that already holds
	// aliases. A mesh server's plist overrides it with this server's --mesh-ip /24
	// (install.MeshNodePodCIDR), the range its ConfigureMesh carries. One
	// derivation each, so drift is not expressible.
	fs.StringVar(&opts.nodePodCIDR, "node-pod-cidr", defaultNodePodCIDR(), "this node's pod /24 (a pod-IP alias must fall within it); PRE-ADOPTION VALUE — on a worker the real prefix is decided by the join and a ConfigureMesh replaces this value, so a worker's installed plist passes none; a mesh server's installed plist passes the /24 its --mesh-ip is the mesh-egress address of, because the server aliases that address before its own enrol")
	fs.StringVar(&opts.serviceCIDR, "service-cidr", install.DefaultServiceCIDR, "cluster Service CIDR (REQUIRED so the proxy's ClusterIP VIP aliases are admitted)")
	fs.IntVar(&opts.serviceUID, "service-uid", -1, "the _k3sm uid the daemon admits as a peer (default: look up _k3sm)")
	fs.StringVar(&opts.meshKeyDir, "mesh-key-dir", install.MeshKeyDir, "root-only directory the mesh key resolver reads (empty disables ConfigureMesh)")
	fs.StringVar(&opts.kubeconfig, "kubeconfig", "", "kubeconfig the privileged-port authorizer reads with: Services (VIP and ingress binds), and this node's Pods and EndpointSlices (relay binds on published vm pod addresses) — the control plane's admin kubeconfig on a server, the node credential the join wrote on a worker (empty denies every <1024 bind)")
	fs.StringVar(&opts.dnsVIP, "dns-vip", dns.DefaultDNSVIP, "cluster DNS VIP the node resolver entry routes svc and the cluster domain to")
	fs.StringVar(&opts.clusterDomain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain the node resolver entry registers as a match domain")
	fs.StringVar(&opts.nodeIP, "node-ip", "", "this node's own InternalIP: the only non-VIP address a <1024 bind is authorized on, and only when the canonical ingress LoadBalancer Service declares the port; empty denies every node-address bind. DORMANT: ingress/svclb bind the wildcard in-process and the installed plist passes no --node-ip")
	return fs
}

// runNetd runs the root k3sm-netd helper: it serves the only irreducibly-root
// network operations (lo0 aliases, utun/wireguard/routes, pf MSS anchor,
// privileged-port binds) over a unix socket the unprivileged _k3sm control plane
// drives. It is the SAME binary re-exec'd in netd mode (the root LaunchDaemon
// runs `k3sm netd …`), preserving the one-binary doctrine. It requires root.
func runNetd(args []string) error {
	opts := netdOptions{}
	_ = netdFlags(&opts).Parse(args)

	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm netd must run as root (it owns lo0/utun/pf/privileged-port ops); it is launched by the io.k3sm.netd LaunchDaemon")
	}

	logger := newDaemonLogger(os.Stderr, slog.LevelInfo)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nodeCIDR, err := netip.ParsePrefix(opts.nodePodCIDR)
	if err != nil {
		return fmt.Errorf("parse --node-pod-cidr %q: %w", opts.nodePodCIDR, err)
	}
	svcCIDR, err := netip.ParsePrefix(opts.serviceCIDR)
	if err != nil {
		return fmt.Errorf("parse --service-cidr %q: %w", opts.serviceCIDR, err)
	}

	uid, err := resolveServiceUID(opts.serviceUID)
	if err != nil {
		return err
	}
	// Before anything else this job does: launchd starts netd ahead of the
	// _k3sm jobs, and those cannot start while their log trees are wrong.
	reapplyLogPolicy(install.NewDarwinSystem(), uint32(uid), logger)

	// The node's own InternalIP for the node-address LB branch of the port
	// authorizer. Empty is a valid posture — the branch simply denies —
	// so only a NON-empty value that fails to parse is a config error.
	var nodeIP netip.Addr
	if opts.nodeIP != "" {
		nodeIP, err = netip.ParseAddr(opts.nodeIP)
		if err != nil {
			return fmt.Errorf("parse --node-ip %q: %w", opts.nodeIP, err)
		}
	}

	declares, lbDeclarers, gid := buildServiceSet(ctx, opts.kubeconfig, logger)

	cfg, err := netdsvc.BuildConfig(netdsvc.Options{
		NodePodCIDR:        nodeCIDR,
		ServiceCIDR:        svcCIDR,
		ServiceUID:         uint32(uid),
		Declares:           declares,
		LBDeclarers:        lbDeclarers,
		NodeAddressService: canonicalLBService(),
		NodeIP:             nodeIP,
		VMPodPorts:         buildVMPodSet(ctx, opts.kubeconfig, logger),
		MeshKeyDir:         opts.meshKeyDir,
		Logger:             logger,
	})
	if err != nil {
		return err
	}

	l, err := listenNetd(opts.socket, install.DefaultDataRoot, gid, osOwnership{})
	if err != nil {
		return err
	}
	// identity-path is logged because it is the one input whose ABSENCE is silent:
	// with no mesh key dir the daemon persists nothing, so an adopted /24 is lost
	// on the next restart and the only evidence is this field being empty.
	logger.Info("k3sm-netd serving", "socket", opts.socket, "node-pod-cidr", nodeCIDR, "service-cidr", svcCIDR, "service-uid", uid, "node-ip", opts.nodeIP, "identity-path", cfg.IdentityPath)

	stopResolver := startNodeResolver(opts, logger)
	defer stopResolver()

	srv := netd.NewServer(cfg)
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		return fmt.Errorf("netd serve: %w", err)
	}
	return nil
}

// startNodeResolver publishes the node resolver entry (netdsvc.NodeResolver)
// through the SystemConfiguration dynamic store and returns the function that
// removes it at shutdown. It writes the FULL entry on every start, so a netd
// respawned by launchd after a crash overwrites whatever configd kept.
//
// A failure is logged and does not stop netd: the entry is how shim-less host
// and pod processes reach the node DNS, while netd's own verbs (lo0 aliases,
// utun, pf, privileged binds) are what every pod needs to exist at all.
// `k3sm status` reports an entry that is not there.
func startNodeResolver(opts netdOptions, logger *slog.Logger) (stop func()) {
	noop := func() {}
	vip, err := netip.ParseAddr(opts.dnsVIP)
	if err != nil {
		logger.Error("node resolver entry not published: bad --dns-vip", "dns-vip", opts.dnsVIP, "err", err)
		return noop
	}
	store, err := netdsvc.OpenSystemStore()
	if err != nil {
		logger.Error("node resolver entry not published: cannot open the dynamic store", "err", err)
		return noop
	}
	nr, err := netdsvc.NewNodeResolver(store, vip, opts.clusterDomain, logger)
	if err != nil {
		_ = store.Close() // nothing was published; the close error adds nothing
		logger.Error("node resolver entry not published", "err", err)
		return noop
	}
	if err := nr.Start(); err != nil {
		logger.Error("node resolver entry not published", "err", err)
	}
	return func() {
		if err := nr.Stop(); err != nil {
			logger.Error("node resolver entry not removed at shutdown", "err", err)
		}
		_ = store.Close() // the session holds nothing that outlives the removal above
	}
}

// resolveServiceUID returns the explicit --service-uid when set (>= 0), else the
// looked-up _k3sm uid. It errors if neither is available, because a daemon that
// does not know which peer uid to admit cannot authenticate the control plane.
func resolveServiceUID(flagUID int) (int, error) {
	if flagUID >= 0 {
		return flagUID, nil
	}
	u, err := user.Lookup(install.DefaultServiceUser)
	if err != nil {
		return 0, fmt.Errorf("look up service user %s (pass --service-uid): %w", install.DefaultServiceUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("parse %s uid %q: %w", install.DefaultServiceUser, u.Uid, err)
	}
	return uid, nil
}

// logPolicyEnsurer is the slice of install.System netd re-applies the log
// ownership policy through: the installer's own ensure functions, so netd
// carries no second copy of the owners, groups or modes.
type logPolicyEnsurer interface {
	EnsureLogDir(dir string, uid uint32) error
	EnsureContainerLogDir(dir string, uid uint32) error
}

// reapplyLogPolicy re-applies, at every netd start, the two log-tree policies
// `k3sm install` lays down: the daemon log dir (install.LogDir, with the server,
// agent, netd and datavol logs EnsureLogDir pre-creates inside it) and every
// directory of the container-log tree (install.ContainerLogDirs).
//
// Only the installer created them before, so a tree that disappeared after the
// install stayed gone. A macOS upgrade does exactly that: /var/log came back
// with /var/log/k3sm root:wheel 0744 and no agent.log, and without
// /var/log/pods or /var/log/containers. launchd then could not open the _k3sm
// agent's StandardOutPath as _k3sm and refused to start it, and once that was
// fixed by hand the agent exited on the missing /var/log/pods. netd is the one
// k3sm job that runs as root and launchd starts it before the _k3sm jobs, so
// re-applying here repairs the trees on the next boot with nobody involved.
//
// uid is the service uid netd already resolved to admit its peer: the same
// _k3sm account lookup the installer's EnsureServiceUser performs. Every ensure
// is idempotent. An error is logged at Warn and never fails netd's start: netd's
// own verbs are what every pod needs to exist, and a log tree it could not
// repair is something `sudo k3sm install` still fixes.
func reapplyLogPolicy(sys logPolicyEnsurer, uid uint32, logger *slog.Logger) {
	if err := sys.EnsureLogDir(install.LogDir, uid); err != nil {
		logger.Warn("netd: could not re-apply the daemon log directory policy; run `sudo k3sm install` to repair it",
			"dir", install.LogDir, "uid", uid, "err", err)
	} else {
		logger.Info("netd: re-applied the daemon log directory policy", "dir", install.LogDir, "uid", uid,
			"files", []string{install.ServerLogPath(), install.AgentLogPath(), install.NetdLogPath(), install.DatavolLogPath()})
	}
	for _, dir := range install.ContainerLogDirs() {
		if err := sys.EnsureContainerLogDir(dir, uid); err != nil {
			logger.Warn("netd: could not re-apply the container log directory policy; run `sudo k3sm install` to repair it",
				"dir", dir, "uid", uid, "err", err)
			continue
		}
		logger.Info("netd: re-applied the container log directory policy", "dir", dir, "uid", uid)
	}
}

// canonicalLBService names the ONE Service whose declaration authorizes a
// privileged bind on the node's own address: the canonical ingress
// LoadBalancer. It is bound to pkg/ingresshost's constants — the single source
// of that identity, and the same pair ingresshost provisions the Service
// under — so the allowlist can never drift from the Service that actually
// exists.
func canonicalLBService() netdsvc.ServiceRef {
	return netdsvc.ServiceRef{Namespace: ingresshost.ServiceNamespace, Name: ingresshost.ServiceName}
}

// buildServiceSet returns the privileged-port authorizer's two predicates —
// declares (some Service declares a given port; the Service-CIDR-VIP branch)
// and lbDeclarers (WHICH Services of TYPE LoadBalancer declare it, by
// namespace+name; the node-own-address branch, whose allowlist match
// netdsvc applies) — backed by one Services informer, plus the _k3sm gid for
// the socket group. With no kubeconfig both predicates are nil, so the daemon
// denies every <1024 bind (fail safe). The informer runs until ctx ends; the
// predicates read its synced cache.
//
// The kubeconfig is whichever credential this NODE holds, not the server's: on a
// worker the installed plist passes the node kubeconfig the join wrote, because
// nothing on a worker ever writes the control plane's admin kubeconfig and a
// credential that never loads is indistinguishable here from deny-all.
func buildServiceSet(ctx context.Context, kubeconfig string, logger *slog.Logger) (declares func(int) bool, lbDeclarers func(int) []netdsvc.ServiceRef, gid int) {
	gid = serviceGID()
	if kubeconfig == "" {
		logger.Warn("no --kubeconfig: privileged-port (<1024) binds will be denied (no authoritative Service set)")
		return nil, nil, gid
	}

	// The Service authorizer is populated ASYNCHRONOUSLY. netd is bootstrapped by
	// launchd BEFORE the unprivileged _k3sm server writes its kubeconfig and brings
	// up the apiserver, so the Services informer cannot sync at startup. Building it
	// synchronously here (the previous behavior) failed on the not-yet-present
	// kubeconfig and left the authorizer nil for the daemon's whole life — so every
	// <1024 infra-VIP bind (the apiserver ClusterIP :443, the DNS VIP :53) was
	// denied and cluster DNS never came up. Instead the authorizer starts deny-all
	// and a background goroutine swaps in the live Service lister once the kubeconfig
	// exists and its cache syncs (both happen seconds after boot). The netd socket
	// does NOT wait on this, so a privileged bind attempted before the swap is denied
	// fail-safe and the caller (netserve/ingresshost) retries it once netd is ready.
	var mu sync.RWMutex
	var lister corev1listers.ServiceLister // nil until ready → deny (fail-safe)

	current := func() corev1listers.ServiceLister {
		mu.RLock()
		defer mu.RUnlock()
		return lister
	}
	declares = func(port int) bool {
		l := current()
		if l == nil {
			return false
		}
		return serviceDeclaresPort(l, port)
	}
	lbDeclarers = func(port int) []netdsvc.ServiceRef {
		l := current()
		if l == nil {
			return nil
		}
		return lbServicesDeclaringPort(l, port)
	}

	go activateServiceAuthorizer(ctx, kubeconfig, logger, func(l corev1listers.ServiceLister) {
		mu.Lock()
		lister = l
		mu.Unlock()
	})

	return declares, lbDeclarers, gid
}

// activateServiceAuthorizer waits for the server's kubeconfig to appear and its
// apiserver to serve, builds a synced Services informer, then hands the live lister
// to install so netd can authorize <1024 infra-VIP binds against the real Service
// set. It RETRIES until the informer syncs (the kubeconfig may be absent, or the
// apiserver not yet up) or ctx is cancelled — netd must self-heal after the boot
// race, never permanently deny.
func activateServiceAuthorizer(ctx context.Context, kubeconfig string, logger *slog.Logger, install func(corev1listers.ServiceLister)) {
	const retry = 2 * time.Second
	var failures authorizerFailureLog
	for {
		if ctx.Err() != nil {
			return
		}
		lister, err := startServiceInformer(ctx, kubeconfig)
		if err != nil {
			failures.note(logger, kubeconfig, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
				continue
			}
		}
		install(lister)
		logger.Info("Service authorizer ready: privileged (<1024) infra-VIP binds now authorized against the live Service set",
			"kubeconfig", kubeconfig)
		return
	}
}

// kubeconfigUnusableError marks a startServiceInformer failure that happened
// before any request was made: the kubeconfig is missing, unreadable, or not a
// kubeconfig. It is a transparent wrapper (its text is the wrapped error's), so
// marking an error changes how it is classified and nothing about how it reads.
// missing is set only by the existence check, so a kubeconfig that is present
// but names a certificate file that is not is never reported as absent.
type kubeconfigUnusableError struct {
	err     error
	missing bool
}

func (e kubeconfigUnusableError) Error() string { return e.err.Error() }
func (e kubeconfigUnusableError) Unwrap() error { return e.err }

// authorizerRoleRemedy is the remedy named beside a credential-shaped failure.
// The case it is written for is a Mac that changed role by hand: netd's plist
// still names the previous role's credential, and only an install rewrites it.
const authorizerRoleRemedy = "if this Mac changed role, netd still holds the previous role's credential: run `sudo k3sm uninstall`, then `sudo k3sm install` for the role this Mac should have"

// missingKubeconfigWarnAfter is how many CONSECUTIVE failed attempts may find
// the kubeconfig absent before that absence is logged at WARN. netd is started
// before the server writes the kubeconfig, so a missing file is the normal
// state for the first seconds of every server boot and must not WARN then. At
// the authorizer's 2s retry cadence, 30 attempts is about a minute (longer in
// practice, since an attempt can itself take time), well past any boot window
// and short enough that a file that is never coming is reported the same
// minute.
const missingKubeconfigWarnAfter = 30

// credentialRejectedWarnAfter is how many CONSECUTIVE failed attempts may find
// netd's credential rejected (401 Unauthorized) before that is logged at WARN.
// The apiserver refuses even a valid admin token for the first seconds of a
// server boot while its authenticators finish bootstrapping (observed: about
// 2s), so a 401 on the first attempts is the boot race and must not WARN. A
// credential that is genuinely stale (a Mac that changed role by hand) is
// rejected forever, so a short window costs little: at the 2s retry cadence 10
// attempts is about 20s (longer in practice, since one attempt can take up to
// serviceInformerSyncTimeout), well past the observed race.
const credentialRejectedWarnAfter = 10

// authorizerRewarnEvery is how many repeats of the SAME WARN-class error pass
// before that error is warned again (a different WARN-class error warns at once
// and restarts the count; a Debug-class failure in between leaves it alone, so
// a flapping apiserver cannot turn the reminder into spam). Warning once for the
// daemon's life would let a standing failure (a rejected credential, an
// unusable kubeconfig, one that never appeared) scroll out of every log view
// while privileged binds stay denied. At the 2s retry cadence 150 attempts is
// about five minutes: one line per five minutes is a reminder, not spam.
const authorizerRewarnEvery = 150

// authorizerFailureClass is how a failed authorizer attempt is logged.
type authorizerFailureClass int

const (
	// failDebug is the ordinary boot race (a dial error, a sync timeout):
	// always Debug.
	failDebug authorizerFailureClass = iota
	// failWindowed is a failure that is the boot race for the first attempts
	// and a standing fault after them (a kubeconfig not yet written, a
	// credential the still-bootstrapping apiserver rejects): Debug until it
	// has held for its window of consecutive attempts, then WARN.
	failWindowed
	// failImmediate is never the boot race (an unusable kubeconfig; a 403,
	// which is an authorized identity denied a verb, an RBAC fact): WARN on
	// first sighting.
	failImmediate
)

// authorizerFailureLog decides the level of each failed authorizer attempt.
//
// Each failure is classified (authorizerFailureReason). failDebug failures
// stay at Debug. failImmediate failures are logged at WARN with the reason and
// a remedy on first sighting. failWindowed failures stay at Debug until the
// same failure has held for its window (missingKubeconfigWarnAfter for a
// missing kubeconfig, credentialRejectedWarnAfter for a rejected credential)
// of consecutive attempts, then are treated like failImmediate. A WARN is
// logged once per distinct error and at Debug when the same error comes back
// on the next retry, until authorizerRewarnEvery repeats have passed and it is
// warned again. It is owned by the single retry loop, so it needs no lock.
type authorizerFailureLog struct {
	lastWarned string
	// sinceWarn counts repeats of lastWarned since it was last logged at
	// WARN.
	sinceWarn int
	// streak counts consecutive attempts that failed with the windowed
	// failure named by streakReason; any other outcome resets it.
	streak       int
	streakReason string
}

// note logs one failed attempt. It logs the kubeconfig PATH only: a parse
// error from a kubeconfig can quote the file's contents, so the WARN for an
// unusable kubeconfig carries a fixed reason and never the error text, and the
// WARN for a rejected credential carries only the apiserver's status reason.
func (l *authorizerFailureLog) note(logger *slog.Logger, kubeconfig string, err error) {
	reason, class, window := authorizerFailureReason(err)
	warn := false
	switch class {
	case failImmediate:
		l.streak, l.streakReason = 0, ""
		warn = true
	case failWindowed:
		if reason != l.streakReason {
			l.streak, l.streakReason = 0, reason
		}
		l.streak++
		warn = l.streak >= window
	case failDebug:
		l.streak, l.streakReason = 0, ""
	}
	if !warn {
		logger.Debug("Service authorizer not ready; <1024 binds denied until the server's kubeconfig + apiserver are up",
			"kubeconfig", kubeconfig, "err", err)
		return
	}
	msg := err.Error()
	if msg == l.lastWarned {
		l.sinceWarn++
	}
	if msg != l.lastWarned || l.sinceWarn >= authorizerRewarnEvery {
		l.lastWarned, l.sinceWarn = msg, 0
		logger.Warn("Service authorizer cannot start; <1024 binds stay denied until it does",
			"kubeconfig", kubeconfig, "reason", reason, "remedy", authorizerRoleRemedy)
		return
	}
	logger.Debug("Service authorizer still cannot start", "kubeconfig", kubeconfig, "reason", reason)
}

// authorizerFailureReason classifies a startServiceInformer error and is the
// one place a failure's class and window are decided. reason is safe to log
// (it never carries kubeconfig contents or token bytes) and is empty for
// failDebug. window is how many consecutive attempts a failWindowed failure
// must hold before it is logged at WARN; it is zero for every other class.
func authorizerFailureReason(err error) (reason string, class authorizerFailureClass, window int) {
	switch {
	case apierrors.IsUnauthorized(err):
		return "the apiserver rejected netd's credential (401 Unauthorized)", failWindowed, credentialRejectedWarnAfter
	case apierrors.IsForbidden(err):
		return "the apiserver refused netd's credential access to Services (403 Forbidden)", failImmediate, 0
	}
	var unusable kubeconfigUnusableError
	switch {
	case !errors.As(err, &unusable):
		return "", failDebug, 0
	case unusable.missing:
		return "the kubeconfig netd was handed still does not exist, long after a server boot would have written it", failWindowed, missingKubeconfigWarnAfter
	default:
		return "the kubeconfig netd was handed cannot be read or is not a valid kubeconfig", failImmediate, 0
	}
}

// serviceInformerSyncTimeout bounds one attempt's wait for the initial Services
// cache sync, so a not-yet-serving apiserver is a retryable error rather than a
// hang. activateServiceAuthorizer retries the whole attempt on its own timer.
const serviceInformerSyncTimeout = 10 * time.Second

// startServiceInformer loads kubeconfig, builds a client, and hands off to
// runServiceInformer. It returns a retryable error if the kubeconfig is
// absent/unreadable, the client can't be built, or the cache doesn't sync in time.
func startServiceInformer(ctx context.Context, kubeconfig string) (corev1listers.ServiceLister, error) {
	if _, err := os.Stat(kubeconfig); err != nil {
		return nil, fmt.Errorf("stat kubeconfig: %w", kubeconfigUnusableError{err: err, missing: errors.Is(err, fs.ErrNotExist)})
	}
	_, cs, err := kubeclient.FromPath(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", kubeconfigUnusableError{err: err})
	}
	return runServiceInformer(ctx, cs, serviceInformerSyncTimeout)
}

// runServiceInformer starts a Services informer against cs and blocks on the
// initial cache sync, returning the lister once it is warm.
//
// The informer runs under a context of this ATTEMPT's own, not the daemon's. That
// distinction is the whole point: this function is called on a retry loop, and it
// is called at boot with a kubeconfig whose token the server is about to rewrite.
// Started against the daemon context, a failed attempt left its reflector running
// for the daemon's life, re-listing with the stale credential every few seconds —
// so each retry stacked another one, and netd logged Unauthorized forever while the
// attempt that eventually succeeded worked fine. Cancelling here on every error path
// (and calling Shutdown, which blocks until the goroutines are gone) makes a failed
// attempt leave nothing behind. The successful attempt's informer survives, tied to
// ctx, because that is the one whose lister the caller keeps.
func runServiceInformer(ctx context.Context, cs kubernetes.Interface, syncTimeout time.Duration) (corev1listers.ServiceLister, error) {
	factory := informers.NewSharedInformerFactory(cs, 30*time.Second)
	svcInformer := factory.Core().V1().Services().Informer()
	lister := factory.Core().V1().Services().Lister()

	runCtx, cancel := context.WithCancel(ctx)
	keep := false
	// Deferred rather than inline, so every failure exit — including one added
	// later — tears this attempt's reflector down. Shutdown blocks until the
	// goroutines are actually gone, which is what makes "left nothing behind" a
	// fact rather than a hope.
	defer func() {
		if keep {
			return
		}
		cancel()
		factory.Shutdown()
	}()

	// The reflector's list/watch failures never reach the caller on their own:
	// a rejected credential shows up here only as a sync timeout. Keeping the
	// last one lets the timeout carry the real cause (a 401/403 stays an
	// apierrors status in the chain), so the caller can tell a stale
	// credential from an apiserver that is simply not up yet. The default
	// handler still runs, so the reflector's own logging is unchanged.
	var (
		lastMu  sync.Mutex
		lastErr error
	)
	if err := svcInformer.SetWatchErrorHandlerWithContext(func(ctx context.Context, r *cache.Reflector, err error) {
		lastMu.Lock()
		lastErr = err
		lastMu.Unlock()
		cache.DefaultWatchErrorHandler(ctx, r, err)
	}); err != nil {
		return nil, fmt.Errorf("set the service informer's watch error handler: %w", err)
	}

	factory.Start(runCtx.Done())
	syncCtx, cancelSync := context.WithTimeout(runCtx, syncTimeout)
	defer cancelSync()
	if !cache.WaitForCacheSync(syncCtx.Done(), svcInformer.HasSynced) {
		lastMu.Lock()
		cause := lastErr
		lastMu.Unlock()
		if cause != nil {
			return nil, fmt.Errorf("service cache did not sync within %s: %w", syncTimeout, cause)
		}
		return nil, fmt.Errorf("service cache did not sync within %s", syncTimeout)
	}
	keep = true
	return lister, nil
}

// serviceDeclaresPort reports whether a Service in the cache declares port —
// the authoritative check that gates a privileged Service-CIDR-VIP bind.
func serviceDeclaresPort(lister corev1listers.ServiceLister, port int) bool {
	svcs, err := lister.List(labels.Everything())
	if err != nil {
		return false
	}
	for _, s := range svcs {
		for _, p := range s.Spec.Ports {
			if int(p.Port) == port {
				return true
			}
		}
	}
	return false
}

// lbServicesDeclaringPort returns the IDENTITIES of the Services of type
// LoadBalancer in the cache that declare port. It deliberately reports who
// declared rather than a bare bool: netdsvc's node-own-address branch is an
// allowlist keyed on namespace+name, and its refusal names the Services that
// declared the port but are not the canonical one. A ClusterIP Service
// declaring :80 is not reported at all — it cannot authorize a node-address
// listener under any policy.
func lbServicesDeclaringPort(lister corev1listers.ServiceLister, port int) []netdsvc.ServiceRef {
	svcs, err := lister.List(labels.Everything())
	if err != nil {
		return nil
	}
	var refs []netdsvc.ServiceRef
	for _, s := range svcs {
		if s.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		for _, p := range s.Spec.Ports {
			if int(p.Port) == port {
				refs = append(refs, netdsvc.ServiceRef{Namespace: s.Namespace, Name: s.Name})
				break
			}
		}
	}
	return refs
}

// serviceGID returns the _k3sm primary gid for the socket group (so the
// unprivileged control plane, a group member, can connect a 0660 socket). It
// falls back to the wheel group (0) when _k3sm is not yet known.
func serviceGID() int {
	if u, err := user.Lookup(install.DefaultServiceUser); err == nil {
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			return gid
		}
	}
	return 0
}

// listenNetd prepares the data root and the SHARED run directory, removes any
// stale socket, listens, and sets the socket group + 0660 mode so the _k3sm
// control plane can connect (the SCM_CREDS uid verifier is the authoritative
// peer gate on top). It splits into a REFUSAL and an ALIGNMENT, because the two
// data-root failures netd has actually caused want opposite responses.
//
// REFUSE (2026-09-05): when the data root is declared in /etc/fstab as a mount
// point but nothing is mounted there, netd creates and chowns NOTHING and
// returns dataroot.Refusal. Creating <root>/run inside the bare mountpoint
// hides the real volume; on the day this was found netd made that shadow
// root-owned, the _k3sm server could not create its work-dir beside it, and the
// server crash-looped ~500 times. The kinder-looking outcome is the worse one:
// a service-user-owned shadow would have let the control plane build a fresh,
// empty datastore over a perfectly good one. launchd's KeepAlive re-runs netd,
// so this refusal repeats — one line per attempt — until the volume is mounted.
//
// ALIGN: otherwise netd applies the install ownership table (install.OwnershipOf)
// to what it finds — see alignStateTree. The data root is root's, root:wheel
// 0755, so a root an older build left owned by the service user is healed here,
// at the next netd start, and never re-owned to the service user; the trees the
// unprivileged daemons write under it are the service user's, and netd creates
// any that are missing, because under a root-owned root the service user cannot.
// The mesh key directory is root's and netd never touches it or its contents;
// the other root-owned trees under the root (the auto-deploy manifest
// directory) are created when missing and healed to root:wheel like the root.
// Their contents are never touched.
//
// netd runs as root, so it needs no ownership of the run directory to create
// its socket inside it, and it never takes that directory for root: that was
// the 2026-09-02 boot-order bug in which install set _k3sm 0700, netd re-owned
// root:wheel on bootstrap, and the server's dial failed permission-denied in a
// crash loop. When the service user does not exist yet (a pre-install posture)
// netd logs and leaves the service-user trees exactly as they are.
func listenNetd(socket, dataRoot string, gid int, own ownership) (net.Listener, error) {
	dir := filepath.Dir(socket)
	root := filepath.Clean(dataRoot)

	st, err := dataroot.Read(own, root)
	if err != nil {
		return nil, fmt.Errorf("inspect data root %s: %w", root, err)
	}
	if st.Shadowed() {
		return nil, dataroot.Refusal(root)
	}
	// Which levels MkdirAll is about to create — decided BEFORE it creates them,
	// since afterwards every level looks equally present.
	created := missingLevels(own, root, dir)

	if err := own.MkdirAll(dir, install.StateRootMode); err != nil {
		return nil, fmt.Errorf("create socket dir %s: %w", dir, err)
	}
	if err := alignStateRoot(own, root); err != nil {
		return nil, err
	}
	if err := alignRootTrees(own, root); err != nil {
		return nil, err
	}
	uid, _, lerr := own.Lookup(install.DefaultServiceUser)
	if lerr != nil {
		slog.Error("netd: service user not found; the service user's trees are left as-is",
			"user", install.DefaultServiceUser, "err", lerr)
	} else {
		if err := alignServiceTrees(own, root, uid); err != nil {
			return nil, err
		}
		svc, _ := install.OwnershipOf(install.StateRun)
		for _, level := range alignTargets(own, created, dir, uid) {
			if isTableLevel(root, level) {
				continue // alignServiceTrees applied the table's row
			}
			if err := alignDir(own, level, svc.UID(uid), svc.GID, svc.Mode); err != nil {
				return nil, err
			}
		}
	}
	warnLegacyMeshKeys(own, root)
	// Remove a stale socket from a previous run so Listen does not EADDRINUSE.
	if err := own.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket %s: %w", socket, err)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socket, err)
	}
	if err := own.Chown(socket, 0, gid); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chown socket %s group %d: %w", socket, gid, err)
	}
	if err := own.Chmod(socket, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chmod socket %s 0660: %w", socket, err)
	}
	return l, nil
}

// missingLevels returns the directory levels from root (exclusive) down to dir
// (inclusive) that do not exist yet — exactly the ones a MkdirAll(dir) is about
// to create. Once the first level is missing every level below it is too, so
// the walk stops stat-ing and simply collects. A dir outside root yields dir
// alone when it is missing (netd still owns what it creates).
func missingLevels(own ownership, root, dir string) []string {
	rel, err := filepath.Rel(root, filepath.Clean(dir))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		if _, serr := own.Stat(dir); serr != nil {
			return []string{filepath.Clean(dir)}
		}
		return nil
	}
	if rel == "." {
		return nil
	}
	var (
		out     []string
		cur     = root
		missing bool
	)
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		if !missing {
			if _, err := own.Stat(cur); err != nil {
				missing = true
			}
		}
		if missing {
			out = append(out, cur)
		}
	}
	return out
}

// alignTargets is created plus the socket dir when that already existed but has
// drifted off the service user — the case the 2026-09-02 fix exists for, which
// a create-time-only alignment would stop healing. Levels that already existed
// and are already correct are left untouched.
func alignTargets(own ownership, created []string, dir string, uid int) []string {
	dir = filepath.Clean(dir)
	if len(created) > 0 && created[len(created)-1] == dir {
		return created
	}
	if dirOwnerUID(own, dir) == uid {
		return created
	}
	return append(created, dir)
}

// alignStateRoot applies the table's root row to the data root: root:wheel,
// install.StateRootMode. A root found with any other owner, group or mode — the
// service-user-owned root every build before the root-owned layout left behind
// — is re-owned and warned about once; a correct one is not touched.
//
// It runs BEFORE any service-user tree is touched, and that order is the safety
// argument for alignServiceTrees: once the root is root's, no unprivileged
// principal can rename or replace an entry directly inside it.
func alignStateRoot(own ownership, root string) error {
	want, _ := install.OwnershipOf(install.StateRoot)
	fi, err := own.Lstat(root)
	if err != nil {
		return fmt.Errorf("stat data root %s: %w", root, err)
	}
	uid, gid := statOwner(fi)
	if uid == want.UID(0) && gid == want.GID && fi.Mode().Perm() == want.Mode {
		return nil
	}
	if err := alignDir(own, root, want.UID(0), want.GID, want.Mode); err != nil {
		return err
	}
	slog.Warn("netd: aligned data-root ownership", "dir", root,
		"from", fmt.Sprintf("uid=%d gid=%d mode=%04o", uid, gid, fi.Mode().Perm()),
		"to", fmt.Sprintf("uid=%d gid=%d mode=%04o", want.UID(0), want.GID, want.Mode))
	return nil
}

// alignRootTrees applies the table's root-owned rows below the data root
// (install.RootTreeLevels): each is created when missing and re-owned to root
// when it has drifted, so a manifest directory the service user could write,
// and so every pod could, is never left in place. Like alignServiceTrees it
// never recurses and never follows a symlink.
func alignRootTrees(own ownership, root string) error {
	for _, level := range install.RootTreeLevels() {
		want, _ := install.OwnershipOf(level)
		path := level.Path(root)
		fi, err := own.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := own.MkdirAll(path, want.Mode); err != nil {
				return fmt.Errorf("create %s: %w", path, err)
			}
			if err := alignDir(own, path, want.UID(0), want.GID, want.Mode); err != nil {
				return err
			}
			continue
		case err != nil:
			return fmt.Errorf("stat %s: %w", path, err)
		case !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0:
			slog.Warn("netd: a root-owned tree is not a directory; left alone", "path", path, "mode", fi.Mode().String())
			continue
		}
		uid, gid := statOwner(fi)
		if uid == want.UID(0) && gid == want.GID && fi.Mode().Perm() == want.Mode {
			continue
		}
		if err := alignDir(own, path, want.UID(0), want.GID, want.Mode); err != nil {
			return err
		}
		slog.Warn("netd: aligned a root-owned tree's ownership", "dir", path,
			"from", fmt.Sprintf("uid=%d gid=%d mode=%04o", uid, gid, fi.Mode().Perm()),
			"to", fmt.Sprintf("uid=%d gid=%d mode=%04o", want.UID(0), want.GID, want.Mode))
	}
	return nil
}

// alignServiceTrees applies the table's service-user rows: each tree directly
// under the data root that an unprivileged daemon writes is created when
// missing (under a root-owned root the service user cannot create it) and
// re-owned when it has drifted. It never recurses, never follows a symlink (an
// entry that is not a real directory is warned about and left alone), and never
// touches the key directory, which is not a service-user row.
func alignServiceTrees(own ownership, root string, serviceUID int) error {
	for _, level := range install.ServiceLevels() {
		want, _ := install.OwnershipOf(level)
		path := level.Path(root)
		fi, err := own.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := own.MkdirAll(path, want.Mode); err != nil {
				return fmt.Errorf("create %s: %w", path, err)
			}
			if err := alignDir(own, path, want.UID(serviceUID), want.GID, want.Mode); err != nil {
				return err
			}
			continue
		case err != nil:
			return fmt.Errorf("stat %s: %w", path, err)
		case !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0:
			slog.Warn("netd: a service-user tree is not a directory; left alone", "path", path, "mode", fi.Mode().String())
			continue
		}
		uid, gid := statOwner(fi)
		if uid == want.UID(serviceUID) && gid == want.GID && fi.Mode().Perm() == want.Mode {
			continue
		}
		if err := alignDir(own, path, want.UID(serviceUID), want.GID, want.Mode); err != nil {
			return err
		}
		slog.Warn("netd: aligned a service-user tree's ownership", "dir", path,
			"from", fmt.Sprintf("uid=%d gid=%d mode=%04o", uid, gid, fi.Mode().Perm()),
			"to", fmt.Sprintf("uid=%d gid=%d mode=%04o", want.UID(serviceUID), want.GID, want.Mode))
	}
	return nil
}

// warnLegacyMeshKeys warns once per key an older build left in the legacy
// location inside the run dir. netd does not move it: the move is the root
// installer's (it copies, verifies, and only then removes), and a daemon that
// moved keys at start would be a second, unverified implementation of it.
func warnLegacyMeshKeys(own ownership, root string) {
	for _, path := range install.LegacyMeshKeyFiles(root) {
		fi, err := own.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		slog.Warn("netd: a mesh key file is still in the legacy run-dir location, where the service user can unlink it; run `sudo k3sm install` to move it into the root-owned key dir (netd does not move it)",
			"path", path, "keyDir", install.MeshKeyDir)
	}
}

// isTableLevel reports whether dir is one of the ownership table's levels under
// root, so the socket-dir alignment below does not apply a second policy to a
// directory the table already decided.
func isTableLevel(root, dir string) bool {
	dir = filepath.Clean(dir)
	for _, level := range install.StateLevels() {
		if level.Path(root) == dir {
			return true
		}
	}
	return false
}

// alignDir applies one owner, group and mode to one directory, non-recursively.
// The chown does not follow a symlink.
func alignDir(own ownership, dir string, uid, gid int, mode fs.FileMode) error {
	if err := own.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", dir, uid, gid, err)
	}
	if err := own.Chmod(dir, mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", dir, mode, err)
	}
	return nil
}

// statOwner reports a FileInfo's owning uid and gid, or -1/-1 when the
// platform payload is absent.
func statOwner(fi fs.FileInfo) (uid, gid int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

// dirOwnerUID reports dir's owning uid, or -1 when it cannot be determined
// (absent, or a FileInfo without the platform payload).
func dirOwnerUID(own ownership, dir string) int {
	fi, err := own.Stat(dir)
	if err != nil {
		return -1
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		return int(st.Uid)
	}
	return -1
}
