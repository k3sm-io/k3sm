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
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// APIServerEndpoint is the apiserver's reachable host:port (e.g. 127.0.0.1:6444).
	// The Service proxy is EndpointSlice-only and needs a backend for the kubernetes
	// Service VIP (10.43.0.1:443); single-node the apiserver advertises 127.0.0.1,
	// which its endpoint reconciler refuses to publish, so NO default/kubernetes
	// EndpointSlice exists and the proxy resets in-pod HTTPS to the API VIP (EOF).
	// Run provisions a slice pointing here (the address the proxy dials from the
	// host) when set; empty skips it (the apiserver owns the singleton on a routable node).
	APIServerEndpoint string
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
	// PeerMeshEgressIPs are the peer nodes' reserved mesh-egress /32s known at
	// construction (a worker seeds them from the join snapshot). Together with
	// NodeIP and MeshEgressIP they seed the NetworkPolicy table's ALWAYS-ALLOW
	// source set (M10.4): a peer's Service proxy re-originates cross-node traffic
	// from its mesh-egress /32, and such node-origin dialers must never be locked
	// out by a pod policy. Dynamic-peer gap (documented follow-up): a peer that
	// enrolls AFTER construction is not re-seeded — no MeshPeer-event plumbing
	// feeds the policy table — so its dials are unattributable and FAIL OPEN with
	// a throttled Warn (proxy.PolicyTable's unknown-source contract). The gap can
	// only widen allows, never manufacture a deny.
	PeerMeshEgressIPs []string
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
	// policy is the NetworkPolicy L4-subset verdict table (M10.4), seeded with the
	// always-allow node-origin /32s (NodeIP, MeshEgressIP, PeerMeshEgressIPs) and
	// wired into the proxy's accept paths via proxy.WithPolicyTable.
	policy *proxy.PolicyTable
	// policyWatch resolves NetworkPolicies+Pods+Namespaces into policy's verdict
	// state; Run hosts it beside the Service watcher (same client, same errgroup).
	policyWatch *proxy.PolicyWatcher
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
// when set, policy-gated by the seeded NetworkPolicy table), the Service/
// EndpointSlice watcher that drives it, the NetworkPolicy watcher that resolves
// policies into table verdicts, and the per-node cluster DNS resolver bound to
// the DNS VIP. It does not start anything; call Run.
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

	// M10.4 — NetworkPolicy hosting, unconditional when the datapath runs (the
	// nil-table proxy default is the off-switch upstream of this assembler). The
	// verdict table is seeded with the always-allow node-origin sources — the
	// node's InternalIP, this node's mesh-egress /32, and the peer mesh-egress
	// /32s known at construction — so a pod policy can never lock out node-origin
	// dialers (the in-process Ingress, apiserver webhooks, peer Service proxies).
	// NewPolicyTable skips invalid (zero) addrs, so unset values pass through.
	seeds := make([]netip.Addr, 0, 2+len(cfg.PeerMeshEgressIPs))
	nodeIP, _ := netip.ParseAddr(cfg.NodeIP) // zero on parse failure → skipped by NewPolicyTable
	seeds = append(seeds, nodeIP, s.meshEgress)
	for _, p := range cfg.PeerMeshEgressIPs {
		a, _ := netip.ParseAddr(p) // zero on parse failure → skipped by NewPolicyTable
		seeds = append(seeds, a)
	}
	s.policy = proxy.NewPolicyTable(seeds...)
	opts = append(opts, proxy.WithPolicyTable(s.policy))

	s.proxy = proxy.New(table, opts...)
	s.watch = proxy.NewWatcher(cfg.Client, s.proxy, log)
	s.policyWatch = proxy.NewPolicyWatcher(cfg.Client, s.policy, log)
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
	// The NetworkPolicy watcher (M10.4) runs beside the Service watcher: same
	// client, same lifecycle. The table stays empty (allow-everything) until its
	// informers sync — the documented fail-open — so it never gates bring-up.
	g.Go(func() error { return s.policyWatch.Run(gctx) })
	// Provision the canonical kube-system/kube-dns Service BEFORE the resolver binds:
	// it is the DECLARING SUBJECT the netd port authorizer confirms the privileged
	// DNS-VIP :53 bind against (exactly as k3sm-ingress is for :80/:443). Without it
	// netd denies the bind ("no service declares port 53") and the per-node resolver
	// stays dark — in-pod cluster DNS fails. Best-effort: a failure is logged, not
	// fatal (the resolver's bind retry outlasts a transient apiserver).
	if s.dnsVIP.IsValid() {
		if err := s.ensureDNSService(ctx); err != nil {
			s.log.Warn("ensure kube-dns Service; netd may deny the DNS VIP bind", "err", err)
		}
	}
	// Provision the default/kubernetes EndpointSlice so the Service proxy has a
	// backend for the API VIP (in-pod client-go). See Config.APIServerEndpoint.
	if s.cfg.APIServerEndpoint != "" {
		if err := s.ensureKubernetesEndpointSlice(ctx); err != nil {
			s.log.Warn("ensure default/kubernetes EndpointSlice; in-pod API VIP has no backend", "err", err)
		}
	}
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

// ensureDNSService idempotently provisions kube-system/kube-dns: a selector-less
// ClusterIP Service pinned to the DNS VIP that declares 53/UDP+TCP. The per-node
// in-process resolver IS the implementation (there are no endpoints), so the
// Service exists for two reasons: the netd port authorizer confirms the resolver's
// privileged :53 VIP bind against a DECLARING Service (an explicit policy chain,
// never allowed-by-coincidence — like k3sm-ingress for :80/:443), and in-cluster
// `kube-dns`/`kubernetes.io/name: CoreDNS` discovery resolves. The proxy is
// exempted from this VIP (WithInfraVIPExemptions) so it never races the resolver
// for the socket.
func (s *Server) ensureDNSService(ctx context.Context) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-dns",
			Namespace: "kube-system",
			Labels: map[string]string{
				"k3sm.io/managed":               "true",
				"k8s-app":                       "kube-dns",
				"kubernetes.io/name":            "CoreDNS",
				"kubernetes.io/cluster-service": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: s.dnsVIP.String(),
			Ports: []corev1.ServicePort{
				{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP},
				{Name: "dns-tcp", Port: 53, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	if _, err := s.cfg.Client.CoreV1().Services("kube-system").Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create kube-dns service %s: %w", s.dnsVIP, err)
	}
	return nil
}

// ensureKubernetesEndpointSlice idempotently provisions a default/kubernetes
// EndpointSlice pointing at the apiserver (Config.APIServerEndpoint), so the
// EndpointSlice-only Service proxy has a backend for the kubernetes Service VIP
// (10.43.0.1:443). Single-node the apiserver advertises 127.0.0.1 and its endpoint
// reconciler refuses to publish that loopback endpoint, so it creates neither the
// Endpoints nor the slice — leaving the proxy to reset in-pod HTTPS to the API VIP
// (EOF). The slice carries the kubernetes.io/service-name=kubernetes label (how the
// proxy maps it to the Service) with a DISTINCT name so a future routable-node
// apiserver reconciler (which owns the "kubernetes"-named slice) never collides.
func (s *Server) ensureKubernetesEndpointSlice(ctx context.Context) error {
	host, portStr, err := net.SplitHostPort(s.cfg.APIServerEndpoint)
	if err != nil {
		return fmt.Errorf("parse api-server endpoint %q: %w", s.cfg.APIServerEndpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parse api-server port %q: %w", portStr, err)
	}
	p := int32(port)
	name := "https"
	proto := corev1.ProtocolTCP
	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-k3sm",
			Namespace: "default",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: "kubernetes",
				"k3sm.io/managed":            "true",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{host},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
		Ports: []discoveryv1.EndpointPort{{
			Name:     &name,
			Port:     &p,
			Protocol: &proto,
		}},
	}
	if _, err := s.cfg.Client.DiscoveryV1().EndpointSlices("default").Create(ctx, slice, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create default/kubernetes EndpointSlice -> %s: %w", s.cfg.APIServerEndpoint, err)
	}
	return nil
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

	// The DNS VIP is a privileged (:53 < 1024) bind that goes through the netd
	// helper, whose Service authorizer is populated ASYNCHRONOUSLY after boot (it
	// authorizes :53 only once the kube-dns Service is in its cache — see
	// cmd/k3sm/netd.go buildServiceSet). netd and this server are separate launchd
	// daemons racing at startup, so the first bind attempt is routinely denied. A
	// one-shot bind (the previous behavior) permanently disabled cluster DNS on that
	// transient denial; retry with backoff so the resolver comes up as soon as netd
	// self-heals, rather than staying dark for the daemon's life.
	ap := netip.AddrPortFrom(s.dnsVIP, dns.DefaultDNSPort)
	udp, tcp, err := s.bindDNSVIP(ctx, ap)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("bind DNS VIP; per-node resolver disabled after retries (check the netd helper's Service authorizer + the kube-dns Service)",
				"addr", ap.String(), "err", err)
		}
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

// dnsBindRetrySchedule backs off the DNS-VIP bind while the netd helper's Service
// authorizer catches up after boot (netd is a separate launchd daemon whose <1024
// authorizer syncs seconds after this server starts). The cumulative window
// (~2.5 min) comfortably spans the kubeconfig-write + apiserver-up + kube-dns
// Service-create sequence netd must observe before it authorizes :53.
var dnsBindRetrySchedule = []time.Duration{
	2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
}

// bindDNSVIP ensures the DNS VIP lo0 alias and binds 53/UDP+53/TCP, retrying the
// whole sequence with backoff (dnsBindRetrySchedule) until it succeeds or ctx is
// cancelled. The <1024 bind flows through the netd helper, which denies it until
// its Service authorizer syncs — so a transient denial is expected at boot and must
// not permanently disable the resolver. On success it returns both listeners; on
// ctx cancellation or exhausted retries it returns the last error (both closed).
func (s *Server) bindDNSVIP(ctx context.Context, ap netip.AddrPort) (net.PacketConn, net.Listener, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		udp, tcp, err := s.bindDNSVIPOnce(ctx, ap)
		if err == nil {
			return udp, tcp, nil
		}
		lastErr = err
		if attempt >= len(dnsBindRetrySchedule) {
			return nil, nil, lastErr
		}
		delay := dnsBindRetrySchedule[attempt]
		s.log.Warn("DNS VIP bind failed (netd authorizer likely not yet synced); retrying",
			"addr", ap.String(), "attempt", attempt+1, "retry-in", delay, "err", err)
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// bindDNSVIPOnce performs a single alias+bind attempt, closing any partial listener
// so a failed attempt leaks nothing before the caller retries.
func (s *Server) bindDNSVIPOnce(ctx context.Context, ap netip.AddrPort) (net.PacketConn, net.Listener, error) {
	if err := s.binder.ensureAlias(ctx, s.dnsVIP); err != nil {
		return nil, nil, fmt.Errorf("ensure DNS VIP lo0 alias: %w", err)
	}
	udp, err := s.binder.listenUDP(ctx, ap)
	if err != nil {
		return nil, nil, fmt.Errorf("bind 53/UDP: %w", err)
	}
	tcp, err := s.binder.listenTCP(ctx, ap)
	if err != nil {
		_ = udp.Close()
		return nil, nil, fmt.Errorf("bind 53/TCP: %w", err)
	}
	return udp, tcp, nil
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
