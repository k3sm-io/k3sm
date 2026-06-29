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
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/darwin-net/pkg/netd"

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

	declares, gid := buildServiceSet(ctx, opts.kubeconfig, logger)

	cfg, err := netdsvc.BuildConfig(netdsvc.Options{
		NodePodCIDR: nodeCIDR,
		ServiceCIDR: svcCIDR,
		ServiceUID:  uint32(uid),
		Declares:    declares,
		MeshKeyDir:  opts.meshKeyDir,
		Logger:      logger,
	})
	if err != nil {
		return err
	}

	l, err := listenNetd(opts.socket, gid)
	if err != nil {
		return err
	}
	logger.Info("k3sm-netd serving", "socket", opts.socket, "node-pod-cidr", nodeCIDR, "service-cidr", svcCIDR, "service-uid", uid)

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

// buildServiceSet returns the privileged-port authorizer's declares predicate
// (a Service declares a given port) backed by a Services informer, plus the
// _k3sm gid for the socket group. With no kubeconfig the predicate is nil, so
// the daemon denies every <1024 bind (fail safe). The informer runs until ctx
// ends; the predicate reads its synced cache.
func buildServiceSet(ctx context.Context, kubeconfig string, logger *slog.Logger) (func(int) bool, int) {
	gid := serviceGID()
	if kubeconfig == "" {
		logger.Warn("no --kubeconfig: privileged-port (<1024) binds will be denied (no authoritative Service set)")
		return nil, gid
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		logger.Error("load kubeconfig for Service authorizer; <1024 binds will be denied", "err", err)
		return nil, gid
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		logger.Error("build client for Service authorizer; <1024 binds will be denied", "err", err)
		return nil, gid
	}
	factory := informers.NewSharedInformerFactory(cs, 30*time.Second)
	lister := factory.Core().V1().Services().Lister()
	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	declares := func(port int) bool { return serviceDeclaresPort(lister, port) }
	return declares, gid
}

// serviceDeclaresPort reports whether any Service in the cache declares port (a
// ClusterIP/NodePort/targetPort match), the authoritative check that gates a
// privileged-port bind.
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

// listenNetd creates the root-owned socket directory, removes any stale socket,
// listens, and sets the socket group + 0660 mode so the _k3sm control plane can
// connect (the SCM_CREDS uid verifier is the authoritative peer gate on top).
func listenNetd(socket string, gid int) (net.Listener, error) {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create socket dir %s: %w", dir, err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return nil, fmt.Errorf("chown socket dir %s root:wheel: %w", dir, err)
	}
	// Remove a stale socket from a previous run so Listen does not EADDRINUSE.
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket %s: %w", socket, err)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socket, err)
	}
	if err := os.Chown(socket, 0, gid); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chown socket %s group %d: %w", socket, gid, err)
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chmod socket %s 0660: %w", socket, err)
	}
	return l, nil
}
