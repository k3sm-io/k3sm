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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/darwin-net/pkg/netd"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/install"
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
}

// runNetd runs the root k3sm-netd helper: it serves the only irreducibly-root
// network operations (lo0 aliases, utun/wireguard/routes, pf MSS anchor,
// privileged-port binds) over a unix socket the unprivileged _k3sm control plane
// drives. It is the SAME binary re-exec'd in netd mode (the root LaunchDaemon
// runs `k3sm netd …`), preserving the one-binary doctrine. It requires root.
func runNetd(args []string) error {
	fs := flag.NewFlagSet("netd", flag.ExitOnError)
	opts := netdOptions{}
	fs.StringVar(&opts.socket, "socket", netd.DefaultSocketPath, "unix socket to listen on")
	fs.StringVar(&opts.nodePodCIDR, "node-pod-cidr", "100.64.0.0/24", "this node's pod /24 (a pod-IP alias must fall within it)")
	fs.StringVar(&opts.serviceCIDR, "service-cidr", install.DefaultServiceCIDR, "cluster Service CIDR (REQUIRED so the proxy's ClusterIP VIP aliases are admitted)")
	fs.IntVar(&opts.serviceUID, "service-uid", -1, "the _k3sm uid the daemon admits as a peer (default: look up _k3sm)")
	fs.StringVar(&opts.meshKeyDir, "mesh-key-dir", install.MeshKeyDir, "root-only directory the mesh key resolver reads (empty disables ConfigureMesh)")
	fs.StringVar(&opts.kubeconfig, "kubeconfig", "", "kubeconfig the privileged-port authorizer's Service informer uses (empty denies every <1024 bind)")
	fs.StringVar(&opts.nodeIP, "node-ip", "", "this node's own InternalIP: the only non-VIP address a <1024 bind is authorized on, and only when the canonical ingress LoadBalancer Service declares the port; empty denies every node-address bind. DORMANT: ingress/svclb bind the wildcard in-process and the installed plist passes no --node-ip")
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm netd must run as root (it owns lo0/utun/pf/privileged-port ops); it is launched by the io.k3sm.netd LaunchDaemon")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
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
	logger.Info("k3sm-netd serving", "socket", opts.socket, "node-pod-cidr", nodeCIDR, "service-cidr", svcCIDR, "service-uid", uid, "node-ip", opts.nodeIP)

	srv := netd.NewServer(cfg)
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		return fmt.Errorf("netd serve: %w", err)
	}
	return nil
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
	for {
		if ctx.Err() != nil {
			return
		}
		lister, err := startServiceInformer(ctx, kubeconfig)
		if err != nil {
			logger.Debug("Service authorizer not ready; <1024 binds denied until the server's kubeconfig + apiserver are up",
				"kubeconfig", kubeconfig, "err", err)
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

// serviceInformerSyncTimeout bounds one attempt's wait for the initial Services
// cache sync, so a not-yet-serving apiserver is a retryable error rather than a
// hang. activateServiceAuthorizer retries the whole attempt on its own timer.
const serviceInformerSyncTimeout = 10 * time.Second

// startServiceInformer loads kubeconfig, builds a client, and hands off to
// runServiceInformer. It returns a retryable error if the kubeconfig is
// absent/unreadable, the client can't be built, or the cache doesn't sync in time.
func startServiceInformer(ctx context.Context, kubeconfig string) (corev1listers.ServiceLister, error) {
	if _, err := os.Stat(kubeconfig); err != nil {
		return nil, fmt.Errorf("stat kubeconfig: %w", err)
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
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

	factory.Start(runCtx.Done())
	syncCtx, cancelSync := context.WithTimeout(runCtx, syncTimeout)
	defer cancelSync()
	if !cache.WaitForCacheSync(syncCtx.Done(), svcInformer.HasSynced) {
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
// ALIGN: otherwise netd applies the install ownership policy to what it finds.
// The data root itself gets install.DataRootMode owned by the service user when
// it is missing or has drifted (the second 2026-09-05 defect: netd's MkdirAll
// created a plain root root-owned and only re-owned run/). Each directory netd
// creates below it — and the socket dir if it has drifted — gets the run-dir
// policy: service user, 0700, non-recursively.
//
// netd runs as root, so it needs no ownership of these directories to create
// its socket inside them, and it never takes them for root: that was the
// 2026-09-02 boot-order bug in which install set _k3sm 0700, netd re-owned
// root:wheel on bootstrap, and the server's dial failed permission-denied in a
// crash loop. When the service user does not exist yet (a pre-install posture)
// netd logs and leaves ownership exactly as it is.
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
	var rootPerm fs.FileMode
	if fi, serr := own.Stat(root); serr == nil {
		rootPerm = fi.Mode().Perm()
	}
	// Which levels MkdirAll is about to create — decided BEFORE it creates them,
	// since afterwards every level looks equally present.
	created := missingLevels(own, root, dir)

	if err := own.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create socket dir %s: %w", dir, err)
	}
	uid, sgid, lerr := own.Lookup(install.DefaultServiceUser)
	if lerr != nil {
		slog.Error("netd: service user not found; data-root ownership left as-is",
			"user", install.DefaultServiceUser, "err", lerr)
	} else {
		if !st.Exists || st.OwnerUID != uid || rootPerm != install.DataRootMode {
			if err := own.Chown(root, uid, install.DataRootGID); err != nil {
				return nil, fmt.Errorf("chown data root %s to the service user: %w", root, err)
			}
			if err := own.Chmod(root, install.DataRootMode); err != nil {
				return nil, fmt.Errorf("chmod data root %s %#o: %w", root, install.DataRootMode, err)
			}
			slog.Warn("netd: aligned data-root ownership", "dir", root,
				"from", fmt.Sprintf("uid=%d mode=%04o", st.OwnerUID, rootPerm),
				"to", fmt.Sprintf("uid=%d mode=%04o", uid, install.DataRootMode))
		}
		for _, level := range alignTargets(own, created, dir, uid) {
			if err := alignRunDir(own, level, uid, sgid); err != nil {
				return nil, err
			}
		}
	}
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

// alignRunDir applies the run-directory policy to one directory: owned by the
// service user, 0700, non-recursive.
func alignRunDir(own ownership, dir string, uid, sgid int) error {
	if err := own.Chown(dir, uid, sgid); err != nil {
		return fmt.Errorf("chown %s to the service user: %w", dir, err)
	}
	if err := own.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s 0700: %w", dir, err)
	}
	return nil
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
