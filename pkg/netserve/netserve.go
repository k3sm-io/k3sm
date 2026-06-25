package netserve

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"
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
	// DNSVIP is the cluster DNS VIP CoreDNS binds and pods resolve against.
	DNSVIP string
	// ClusterDomain is the cluster DNS domain (e.g. cluster.local).
	ClusterDomain string
	// NodeIP is the node InternalIP (reserved for future mesh wiring).
	NodeIP string
	// PodCIDR is the node pod CIDR; empty uses defaultPodCIDR.
	PodCIDR string
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// Server hosts the userspace Service proxy + CoreDNS config wiring as goroutines.
type Server struct {
	cfg   Config
	proxy *proxy.Proxy
	watch *proxy.Watcher
	log   *slog.Logger
}

// New builds the network Server: a proxy.Proxy over a routing table keyed by the
// node pod CIDR, plus the Service/EndpointSlice watcher that drives it. It does
// not start anything; call Run.
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
	p := proxy.New(table, proxy.WithLogger(log))
	w := proxy.NewWatcher(cfg.Client, p, log)
	return &Server{cfg: cfg, proxy: p, watch: w, log: log}
}

// Run renders the CoreDNS Corefile to the workdir, then runs the Service proxy
// and its watcher until ctx is cancelled. Both the proxy's worker-supervision
// loop and the watcher's informers honor ctx; Run returns when they stop.
func (s *Server) Run(ctx context.Context) error {
	if err := s.writeCorefile(); err != nil {
		s.log.Error("write corefile", "err", err)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.proxy.Run(gctx) })
	g.Go(func() error { return s.watch.Run(gctx) })

	err := g.Wait()
	if ctx.Err() != nil {
		return nil // clean shutdown
	}
	return err
}

// CorefilePath is where Run writes the rendered CoreDNS configuration.
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
// the cluster domain) and writes it to the workdir for CoreDNS to load.
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
