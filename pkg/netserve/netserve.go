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

package netserve

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/proxy"
)

// defaultPodCIDR is the node's pod CIDR used for backend locality classification
// in the routing table (a hint/metric in M1; steering does not depend on it).
const defaultPodCIDR = "100.64.0.0/24"

// Config configures the network services the server hosts.
type Config struct {
	// Client is the cluster client the Service/EndpointSlice watcher uses.
	Client kubernetes.Interface
	// WorkDir is where the rendered Corefile is written.
	WorkDir string
	// DNSVIP is the cluster DNS VIP the in-process resolver binds and pods resolve
	// against (the rendered Corefile is the unconsumed native-CoreDNS export).
	DNSVIP string
	// ClusterDomain is the cluster DNS domain (e.g. cluster.local).
	ClusterDomain string
	// NodeIP is the node InternalIP (reserved for future mesh wiring).
	NodeIP string
	// PodCIDR is the node pod CIDR; empty uses defaultPodCIDR.
	PodCIDR string
	// MeshEgressIP, when set, is the node's reserved mesh-egress /32
	// (podnet.MeshEgressIP) the Service proxy's backend dialer sources cross-node
	// dials from, so a dial that egresses the wireguard utun carries a source
	// inside this node's AllowedIPs and wireguard does not blackhole the return
	// path (proxy.WithMeshEgressSource). REQUIRED on a multi-node worker (set from
	// the join result); MUST be empty on a single node and on a node whose
	// mesh-egress lo0 alias is not yet plumbed (the dialer binds this address
	// unconditionally, so a non-local value would break every backend dial).
	MeshEgressIP string
	// NetdSocket, when non-empty, routes the proxy's privileged operations (the
	// lo0 ClusterIP VIP alias and any privileged-port <1024 bind) through the root
	// k3sm-netd helper at this socket, so the proxy runs unprivileged (the _k3sm
	// control plane). Empty keeps the direct ifconfig/net.Listen path (the explicit
	// run-as-root mode). It is the single construction-time backend selection — set
	// it from hostnet.Mode.Socket.
	NetdSocket string
	// Disabled, when true, runs NO Service-proxy datapath: Run writes the Corefile
	// (DNS config artifact) and then blocks until ctx, but never starts the proxy
	// or its Service/EndpointSlice watcher, so no lo0 VIP plumbing is attempted.
	// It is the netserve side of `--network none` (control-plane-only / CI), set
	// from !hostnet.Mode.DataPath() — an explicit backend, not a silent fallback.
	Disabled bool
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// Server hosts the userspace Service proxy + the per-node cluster DNS resolver as
// goroutines (the macOS-native kube-proxy + node-local CoreDNS analog).
type Server struct {
	cfg   Config
	proxy *proxy.Proxy
	watch *proxy.Watcher
	log   *slog.Logger
	// dnsVIP is the infra DNS VIP the per-node resolver owns and the proxy is
	// exempted from (proxy.WithInfraVIPExemptions). Zero (invalid) when cfg.DNSVIP
	// did not parse: the resolver does not run and the proxy is not exempted.
	dnsVIP netip.Addr
	// meshEgress is the mesh-egress /32 the proxy's backend dialer is sourced from
	// (proxy.WithMeshEgressSource); the zero Addr leaves the kernel's default
	// source selection (single-node / no mesh-egress alias).
	meshEgress netip.Addr
	// binder plumbs the DNS VIP alias + binds 53/UDP+TCP through the selected
	// host-network backend (netd helper when unprivileged, direct as root).
	binder dnsBinder
}

// New builds the network Server: a proxy.Proxy over a routing table keyed by the
// node pod CIDR (exempted from the infra DNS VIP, sourced from the mesh-egress /32
// when set), the Service/EndpointSlice watcher that drives it, and the per-node
// cluster DNS resolver bound to the DNS VIP. It does not start anything; call Run.
func New(cfg Config) *Server {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cidrStr := cfg.PodCIDR
	if cidrStr == "" {
		cidrStr = defaultPodCIDR
	}
	cidr, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		cidr = netip.Prefix{} // LocalityUnknown; non-fatal
	}
	table := proxy.NewRoutingTable(cidr)
	opts := []proxy.Option{proxy.WithLogger(log)}
	if cfg.NetdSocket != "" {
		// Unprivileged posture: route the lo0 VIP alias + privileged-port binds
		// through the root netd helper rather than running them directly as root.
		opts = append(opts, proxy.WithNetdHelper(cfg.NetdSocket))
	}

	// Infra DNS VIP (10.43.0.10): the per-node resolver owns it (53/UDP+TCP), so
	// the proxy must step aside or its kube-dns Service reconcile races the
	// resolver for the socket (EADDRINUSE). The API VIP (10.43.0.1) is deliberately
	// NOT exempted — the proxy owns it as a normal ClusterIP Service and L4-forwards
	// to the apiserver endpoint (node-local by each node's proxy owning the VIP).
	s := &Server{cfg: cfg, log: log, binder: newDNSBinder(cfg.NetdSocket)}
	if vip, err := netip.ParseAddr(cfg.DNSVIP); err == nil {
		s.dnsVIP = vip
		opts = append(opts, proxy.WithInfraVIPExemptions(vip))
	} else if cfg.DNSVIP != "" {
		log.Warn("DNS VIP did not parse; per-node resolver disabled and proxy not exempted", "dns-vip", cfg.DNSVIP, "err", err)
	}
	// Cross-node backend dials must egress the utun from this node's mesh-egress
	// /32 or wireguard drops the return packet; an invalid/empty value leaves the
	// dialer on default source selection (single node).
	if egress, err := netip.ParseAddr(cfg.MeshEgressIP); err == nil {
		s.meshEgress = egress
		opts = append(opts, proxy.WithMeshEgressSource(egress))
	}

	s.proxy = proxy.New(table, opts...)
	s.watch = proxy.NewWatcher(cfg.Client, s.proxy, log)
	return s
}

// Run renders the (currently unconsumed) CoreDNS Corefile to the workdir, then runs the Service proxy
// and its watcher until ctx is cancelled. Both the proxy's worker-supervision
// loop and the watcher's informers honor ctx; Run returns when they stop. When
// the Config is Disabled (`--network none`), it writes the Corefile and blocks
// until ctx WITHOUT starting the proxy/watcher (no lo0 VIP plumbing attempted).
func (s *Server) Run(ctx context.Context) error {
	if err := s.writeCorefile(); err != nil {
		s.log.Error("write corefile", "err", err)
	}

	if s.cfg.Disabled {
		s.log.Info("network datapath disabled (--network none): control-plane-only, no Service proxy")
		<-ctx.Done()
		return nil
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.proxy.Run(gctx) })
	g.Go(func() error { return s.watch.Run(gctx) })
	// The per-node cluster DNS resolver. It is best-effort: a bind/serve failure is
	// logged and the goroutine returns nil so it never tears the Service proxy down
	// (a node with a degraded resolver still serves ClusterIP/NodePort traffic).
	g.Go(func() error { s.runResolver(gctx); return nil })

	err := g.Wait()
	if ctx.Err() != nil {
		return nil // clean shutdown
	}
	return err
}

// runResolver brings up the per-node cluster DNS resolver: it ensures the DNS VIP
// lo0 alias and binds 53/UDP+53/TCP through the selected backend (the netd helper
// when unprivileged), then serves cluster Service A records (the kubernetes VIP
// among them, so in-pod client-go resolves the API VIP node-locally) and forwards
// off-cluster names upstream. It runs until ctx is cancelled. Any failure is
// logged and returns (the caller treats it as non-fatal); it never propagates an
// error that would stop the Service proxy.
func (s *Server) runResolver(ctx context.Context) {
	if !s.dnsVIP.IsValid() {
		return // DNS VIP did not parse (logged in New)
	}

	// The cluster Service zone, read from informer caches (no apiserver round-trip
	// per query): Services for the A/VIP answers, EndpointSlices for the M10.1
	// identity records (headless all-backends A, StatefulSet hostname identity,
	// SRV, PTR). Both listers are created BEFORE Start so both informers run;
	// warm the caches before serving.
	domain := s.cfg.ClusterDomain
	if domain == "" {
		domain = dns.DefaultClusterDomain
	}
	factory := informers.NewSharedInformerFactory(s.cfg.Client, 30*time.Second)
	lister := factory.Core().V1().Services().Lister()
	sliceLister := factory.Discovery().V1().EndpointSlices().Lister()
	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	if ctx.Err() != nil {
		return
	}
	zone := serviceZone{services: lister, slices: sliceLister, domain: domain}
	resolver := newClusterResolver(s.dnsVIP, domain, zone, systemForwarder{}, s.log)

	if err := s.binder.ensureAlias(ctx, s.dnsVIP); err != nil {
		s.log.Error("ensure DNS VIP lo0 alias; per-node resolver disabled", "vip", s.dnsVIP.String(), "err", err)
		return
	}
	ap := netip.AddrPortFrom(s.dnsVIP, dns.DefaultDNSPort)
	udp, err := s.binder.listenUDP(ctx, ap)
	if err != nil {
		s.log.Error("bind DNS VIP 53/UDP; per-node resolver disabled", "addr", ap.String(), "err", err)
		return
	}
	tcp, err := s.binder.listenTCP(ctx, ap)
	if err != nil {
		_ = udp.Close()
		s.log.Error("bind DNS VIP 53/TCP; per-node resolver disabled", "addr", ap.String(), "err", err)
		return
	}
	s.log.Info("per-node cluster DNS resolver listening", "vip", ap.String(), "domain", resolver.domain)

	rg, rctx := errgroup.WithContext(ctx)
	rg.Go(func() error { return resolver.serveUDP(rctx, udp) })
	rg.Go(func() error { return resolver.serveTCP(rctx, tcp) })
	if err := rg.Wait(); err != nil && ctx.Err() == nil {
		s.log.Error("per-node cluster DNS resolver stopped", "err", err)
	}
}

// CorefilePath is where Run writes the rendered CoreDNS configuration (an
// unconsumed native-CoreDNS export — the in-process resolver, not a CoreDNS
// binary, serves cluster DNS today; see doc.go).
func (s *Server) CorefilePath() string {
	return filepath.Join(s.cfg.WorkDir, "Corefile")
}

// PodDNSConfig returns the netv1.DNSConfig a pod in namespace should receive (the
// cluster DNS VIP + domain + the standard search list with default ndots) — the
// data the getaddrinfo shim is initialized with. It is darwin-net's PodDNSConfig,
// not a reimplementation.
func (s *Server) PodDNSConfig(namespace string) netv1.DNSConfig {
	return dns.PodDNSConfig(s.cfg.DNSVIP, s.cfg.ClusterDomain, namespace)
}

// writeCorefile renders the CoreDNS configuration (bound to the DNS VIP, serving
// the cluster domain) and writes it to the workdir as the native-CoreDNS export.
// NOTE: nothing currently loads it — the in-process resolver (resolver.go) serves
// cluster DNS; the Corefile is kept for the deferred native-CoreDNS follow-up.
func (s *Server) writeCorefile() error {
	opts := dns.CorefileOptions{
		ClusterDomain: s.cfg.ClusterDomain,
		BindIP:        s.cfg.DNSVIP,
		Port:          dns.DefaultDNSPort,
	}
	if err := os.MkdirAll(s.cfg.WorkDir, 0o755); err != nil {
		return fmt.Errorf("mkdir workdir: %w", err)
	}
	if err := os.WriteFile(s.CorefilePath(), []byte(opts.Corefile()), 0o644); err != nil {
		return fmt.Errorf("write corefile: %w", err)
	}
	return nil
}
