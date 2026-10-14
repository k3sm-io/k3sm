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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/netbind"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/ports"
	"k3sm.io/k3sm/pkg/svclb"
)

// wildcardBindAddr is the address every LoadBalancer and ingress listener binds:
// the IPv4 wildcard, as an EXPLICIT netip.Addr.
//
// It is deliberately NOT the ":port" form. `net.Listen("tcp", ":80")` yields a
// DUAL-STACK [::] socket with IPV6_V6ONLY=0, which would additionally expose the
// listener on every IPv6 link-local/SLAAC address — a surface neither the mesh
// (IPv4 /24 AllowedIPs) nor the ratified parity argument (Docker Desktop's vpnkit
// and k3s' klipper-lb both publish IPv4) covers. netip.AddrFrom4 pins Is4().
var wildcardBindAddr = netip.AddrFrom4([4]byte{})

// statusOwnedPodCIDR is the pod address space whose LoadBalancer/Ingress status
// entries the k3sm controllers own and therefore retract. It is the CLUSTER
// aggregate, not this node's /24, so a node that re-enrolls into a different /24
// still retracts the entry its previous life wrote. Derived from darwin-net's one
// cluster-CIDR constant, so there is no second literal to drift.
func statusOwnedPodCIDR() netip.Prefix {
	return podnet.ClusterPodCIDR
}

// lbHostingConfigs assembles the server-side LoadBalancer configurations: the
// svclb decider and the ingress host. It is a PURE function of the node's
// already-resolved options: the whole decision — the bind address, the
// advertise address, the binder selection and the retraction scope — is made
// here rather than inline inside runServer behind exec.Start, where no unit test
// can reach it. The decider's PeerAddresses (the MeshPeer source) needs a REST
// config and is wired by the caller; the per-node svclb half is lbHosterConfig.
//
// The two addresses are DIFFERENT and both are decided here:
//
//   - BindAddr is the IPv4 wildcard for the ingress host (and, in
//     lbHosterConfig, for every svclb hoster). The BINDER differs, and
//     ingressBinder owns that choice. The ingress host's privileged 80/443
//     listeners go through the root netd helper when netdSocket names one (the
//     k3s ServiceLB shape): netd already holds root-owned Service-VIP sockets on
//     those ports, and on Darwin a wildcard bind by a DIFFERENT uid than an
//     existing specific-address socket on the same port fails with EADDRINUSE,
//     so an unprivileged 0.0.0.0:80 loses to netd's VIP:80 for the daemon's
//     whole life. netd grants that wildcard only for a port the canonical
//     kube-system/k3sm-ingress Service declares (pkg/netdsvc). The high-port
//     integration mode, and a node with no netd (root/direct posture), keep
//     netbind.Direct.
//   - The advertise address is the node's derived globally-unicast InternalIP
//     (nodeAdvertiseAddr): the ingress host's AdvertiseAddr and the decider's
//     SelfAddr, the address the server's own node is published at.
//
// It NEVER writes back into the node options: opts is by value, and opts.nodeIP
// feeds the apiserver's --advertise-address/--bind-address in runServer. One
// assignment there would invalidate the loopback admin kubeconfig, empty the
// `kubernetes` VIP's only static backend and change the NetworkPolicy seed.
//
// The port-range checks keep this seam TOTAL (a uint16 conversion would otherwise
// silently truncate 70000 to 4464). runServer also rejects an out-of-range argv at
// flag-parse time; this one holds for any caller of the seam, argv or test.
//
// netdSocket is the root netd helper's socket, or "" when this node has none
// (netdSocketFor derives it from the resolved --network posture).
func lbHostingConfigs(cs kubernetes.Interface, opts nodeOptions, netdSocket string, httpPort, httpsPort int, log *slog.Logger) (svclb.DeciderConfig, ingresshost.Config, error) {
	if httpPort < 0 || httpPort > 65535 {
		return svclb.DeciderConfig{}, ingresshost.Config{}, fmt.Errorf("--ingress-http-port %d is out of range (0-65535)", httpPort)
	}
	if httpsPort < 0 || httpsPort > 65535 {
		return svclb.DeciderConfig{}, ingresshost.Config{}, fmt.Errorf("--ingress-https-port %d is out of range (0-65535)", httpsPort)
	}
	advertise := nodeAdvertiseAddr(opts, log)
	lb := svclb.DeciderConfig{
		Client:   cs,
		SelfNode: opts.nodeName,
		SelfAddr: advertise,
		Logger:   log,
	}
	ih := ingresshost.Config{
		Client:        cs,
		BindAddr:      wildcardBindAddr,
		AdvertiseAddr: advertise,
		PodCIDR:       statusOwnedPodCIDR(),
		HTTPPort:      uint16(httpPort),
		HTTPSPort:     uint16(httpsPort),
		NodeName:      opts.nodeName,
		Binder:        ingressBinder(netdSocket, httpPort, httpsPort),
		Logger:        log,
	}
	return lb, ih, nil
}

// nodeAdvertiseAddr is the address this node's LoadBalancer and Ingress entries
// are published at: advertisedNodeIP, the SAME function startNode uses, called
// on the SAME nodeOptions value runServer passes to startNode, so the address
// kubectl shows as EXTERNAL-IP cannot disagree with the address the Node object
// carries.
//
// The advertise address is DERIVED, and it may fail: a bad/absent podCIDR
// yields the raw --node-ip, which may itself be the loopback default on a
// no-datapath node. A loopback EXTERNAL-IP is worse than none (nothing off this
// Mac can reach it), so the result is then the ZERO Addr: listeners still bind,
// and nothing is published for this node.
func nodeAdvertiseAddr(opts nodeOptions, log *slog.Logger) netip.Addr {
	if addr, err := netip.ParseAddr(advertisedNodeIP(opts)); err == nil && !addr.IsLoopback() {
		return addr.Unmap()
	}
	log.Warn("loadbalancer/ingress status will not list this node: no advertisable node address could be derived; listeners still bind",
		"node-ip", opts.nodeIP, "pod-cidr", opts.podCIDR, "datapath", opts.netMode.DataPath())
	return netip.Addr{}
}

// lbHosterConfig is the per-node svclb configuration: the hoster every node
// process runs (each joined worker and the server's own node), on the node's
// OWN client. Its listeners bind the IPv4 wildcard through the single
// in-process binder (a nil Binder is netbind.Direct): netd grants a privileged
// wildcard only to the canonical ingress Service, so a helper binder would fail
// every tenant listener. ReservedPorts is the datapath-side half of the
// reserved-port guard (the admission VAP is the legible half), from the same
// single source as the CEL and the apiserver argv.
func lbHosterConfig(cs kubernetes.Interface, opts nodeOptions, log *slog.Logger) svclb.HosterConfig {
	return svclb.HosterConfig{
		Client:        cs,
		NodeName:      opts.nodeName,
		BindAddr:      wildcardBindAddr,
		ReservedPorts: ports.ReservedSet(),
		Logger:        log,
	}
}

// lbHosterResetTimeout bounds the hoster's synchronous start-of-life reset in
// startNode. It runs before the node publishes status, so on a restart the
// reset lands ahead of the node's Ready; a slower apiserver only defers it to
// the hoster's own retry loop, which binds nothing until it lands.
const lbHosterResetTimeout = 5 * time.Second

// startLBHoster starts this node's svclb hoster: it lands the start-of-life
// reset of the node's bound report (bounded, before the caller starts the node's
// status loop), then runs the hoster until ctx ends. A node with no datapath
// hosts nothing (the splice needs the node's Service proxy behind the ClusterIP
// VIP). The returned stop cancels the hoster and waits for its listeners to
// drain.
func startLBHoster(ctx context.Context, opts nodeOptions, cs kubernetes.Interface, log *slog.Logger) (stop func()) {
	if !opts.netMode.DataPath() {
		log.Info("svclb hoster disabled on this node: no datapath (--network none)", "node", opts.nodeName)
		return noStop
	}
	var h *svclb.Hoster
	err := opts.lan.attach("", advertisedNodeIP(opts), func(sets lanSets) (lanFamily, error) {
		cfg := lbHosterConfig(cs, opts, log)
		cfg.BindAddrs = sets.listeners
		var err error
		if h, err = svclb.NewHoster(cfg); err != nil {
			return nil, err
		}
		return hosterLANFamily{h: h}, nil
	})
	if err != nil {
		log.Error("svclb hoster disabled", "node", opts.nodeName, "err", err)
		return noStop
	}
	resetCtx, cancel := context.WithTimeout(ctx, lbHosterResetTimeout)
	if err := h.Reset(resetCtx); err != nil && !apierrors.IsNotFound(err) {
		log.Warn("svclb hoster: bound report reset did not land before the node started; the hoster retries it and binds nothing until it does", "node", opts.nodeName, "err", err)
	}
	cancel()
	hctx, hcancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := h.Run(hctx); err != nil && hctx.Err() == nil {
			log.Error("svclb hoster", "node", opts.nodeName, "err", err)
		}
	}()
	return func() {
		hcancel()
		<-done
	}
}

// lbPeerAddresses is the decider's MeshPeer address source: each node's mesh
// address from its MeshPeer record, which only the server's guarded enroll path
// writes (never the node itself). A record without a parsable, non-loopback
// MeshIP contributes nothing, so that node is never advertised.
func lbPeerAddresses(list func(context.Context) ([]netv1.MeshPeerSpec, error)) func(context.Context) (map[string]netip.Addr, error) {
	return func(ctx context.Context) (map[string]netip.Addr, error) {
		peers, err := list(ctx)
		if err != nil {
			return nil, err
		}
		out := make(map[string]netip.Addr, len(peers))
		for _, p := range peers {
			a, err := netip.ParseAddr(p.MeshIP)
			if err != nil || a.IsLoopback() || a.IsUnspecified() || p.NodeName == "" {
				continue
			}
			out[p.NodeName] = a.Unmap()
		}
		return out, nil
	}
}

// errMeshPeerCacheNotSynced is what the cached MeshPeer lister returns before
// its informer's first LIST lands; the decider keeps its last good address set.
var errMeshPeerCacheNotSynced = errors.New("the MeshPeer cache has not synced yet")

// meshPeerCacheSyncTimeout bounds how long the decider's start waits for the
// MeshPeer cache. Past it the decider runs anyway and advertises only this
// server's own node until the cache syncs.
const meshPeerCacheSyncTimeout = 30 * time.Second

// meshPeerCache is the decider's MeshPeer lister, served from a watch-backed
// informer over lw: one LIST at start, then the watch keeps the store current,
// so a decider reconcile reads memory instead of issuing a LIST against the
// apiserver. The caller runs the informer. Before the first LIST lands the
// lister returns errMeshPeerCacheNotSynced.
func meshPeerCache(lw cache.ListerWatcher) (cache.SharedIndexInformer, func(context.Context) ([]netv1.MeshPeerSpec, error)) {
	inf := cache.NewSharedIndexInformer(lw, &netv1.MeshPeer{}, 0, cache.Indexers{})
	list := func(context.Context) ([]netv1.MeshPeerSpec, error) {
		if !inf.HasSynced() {
			return nil, errMeshPeerCacheNotSynced
		}
		items := inf.GetStore().List()
		specs := make([]netv1.MeshPeerSpec, 0, len(items))
		for _, item := range items {
			if p, ok := item.(*netv1.MeshPeer); ok {
				specs = append(specs, p.Spec)
			}
		}
		return specs, nil
	}
	return inf, list
}

// meshPeerListWatch is the MeshPeer list-watch over cfg's identity (the
// server's admin client), built the same way as the one-shot lister.
func meshPeerListWatch(cfg *rest.Config) (cache.ListerWatcher, error) {
	client, err := meshPeerRESTClient(cfg)
	if err != nil {
		return nil, err
	}
	return cache.NewListWatchFromClient(client, meshPeerResource, metav1.NamespaceAll, fields.Everything()), nil
}

// netdSocketFor returns the netd helper socket the ingress host binds through,
// or "" when the resolved posture routes no privileged op through the helper
// (root/direct binds 80/443 itself; --network none runs no datapath).
func netdSocketFor(mode hostnet.Mode) string {
	if !mode.UsesHelper() {
		return ""
	}
	return mode.Socket
}

// ingressBinder selects the binder for the ingress host's wildcard listeners.
// With no netd (netdSocket == "") every listener binds in-process
// (netbind.Direct). With netd, a privileged (<1024) listener binds through the
// helper and a non-privileged one stays in-process, because netd grants a
// wildcard only below 1024: 80/443 get a netbind.Netd, the 8080/8443
// integration pair gets netbind.Direct, and a mixed pair gets a binder that
// splits by port. A disabled listener (port 0) does not vote.
func ingressBinder(netdSocket string, httpPort, httpsPort int) netbind.Binder {
	direct := netbind.Direct{}
	if netdSocket == "" {
		return direct
	}
	var priv, unpriv int
	for _, p := range []int{httpPort, httpsPort} {
		switch {
		case p == 0:
		case p < privilegedPortCeiling:
			priv++
		default:
			unpriv++
		}
	}
	helper := &netbind.Netd{Client: wire.NewClient(netdSocket)}
	switch {
	case priv == 0:
		return direct
	case unpriv == 0:
		return helper
	default:
		return portSplitBinder{privileged: helper, unprivileged: direct}
	}
}

// privilegedPortCeiling is the first port an unprivileged process may bind on
// a specific address; netd brokers only the ports below it.
const privilegedPortCeiling = 1024

// portSplitBinder routes a listener below privilegedPortCeiling to privileged
// and every other listener to unprivileged.
type portSplitBinder struct {
	privileged   netbind.Binder
	unprivileged netbind.Binder
}

// Listen binds addr through the binder its port selects.
func (b portSplitBinder) Listen(ctx context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	if addr.Port() < privilegedPortCeiling {
		return b.privileged.Listen(ctx, network, addr)
	}
	return b.unprivileged.Listen(ctx, network, addr)
}

// ensureAdvertisedNodeAlias plumbs the lo0 /32 alias for the address the
// LoadBalancer/Ingress statuses will advertise, BEFORE either controller starts.
//
// Why here and not only in startNode's podnet reconcile (which runs later): a
// wildcard bind cannot witness the advertised address, so the packages' honesty
// contract ("never advertise a dead address") no longer covers reachability. The
// controllers write status as soon as their listeners bind; without this call the
// window between that write and startNode's ReconcileStartup shows an EXTERNAL-IP
// that answers from nowhere — and it fails by TIMEOUT (100.64/10 has no local
// route, so the dial leaves via the default gateway), not the loud EADDRNOTAVAIL
// the old specific bind produced.
//
// It acts ONLY on a DERIVED address (derivedNodeAdvertiseIP): an explicit
// --node-ip or a mesh IP belongs to the operator or the mesh device, and aliasing
// it on lo0 here would make this host answer for an address it must not own.
// EnsureNodeAlias is idempotent and SweepStale deliberately excludes the .1, so
// ReconcileStartup re-ensuring it later inside startNode is a no-op — no liveness
// probe, no ticker, no control-flow inversion.
//
// Log-and-continue: startNode's reconcile is the fail-closed authority for this
// alias. A failure here degrades to the pre-existing window, it does not halt
// bring-up.
func ensureAdvertisedNodeAlias(ctx context.Context, opts nodeOptions, log *slog.Logger) {
	derived := derivedNodeAdvertiseIP(opts)
	if derived == "" {
		return
	}
	addr, err := netip.ParseAddr(derived)
	if err != nil {
		log.Error("advertised node address does not parse; lo0 alias not ensured", "addr", derived, "err", err)
		return
	}
	// A SECOND podnet.Network over the same /24, built through the shared
	// buildPodNetwork so the two constructions cannot drift on podnet.Options.
	// This instance is a stateless throwaway used ONLY for EnsureNodeAlias — see
	// buildPodNetwork's doc for why that is safe and what would make it unsafe.
	// The node's one ALLOCATING Network is still the adapter startNode builds.
	nw, err := buildPodNetwork(opts, log)
	if err != nil {
		log.Error("build pod network for the advertised lo0 alias", "pod-cidr", opts.podCIDR, "err", err)
		return
	}
	if err := nw.EnsureNodeAlias(ctx, addr); err != nil {
		log.Error("ensure advertised node lo0 alias before LB/ingress hosting; the advertised EXTERNAL-IP may not answer until the node's startup reconcile runs",
			"addr", addr.String(), "err", err)
		return
	}
	log.Info("advertised node lo0 alias ensured before LB/ingress hosting", "addr", addr.String())
}
