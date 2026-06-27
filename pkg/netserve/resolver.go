package netserve

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	corev1listers "k8s.io/client-go/listers/core/v1"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// recordTTL is the TTL (seconds) stamped on the A records the resolver answers.
// Short because cluster Service VIPs are stable but the per-node resolver is the
// authority and re-reads its Service cache on every query (no staleness window).
const recordTTL = 30

// resolverQueryTimeout bounds a single query's handling (a cluster lookup is
// in-memory; an upstream forward dials the host resolver). It keeps a wedged
// upstream from leaking a per-query goroutine.
const resolverQueryTimeout = 5 * time.Second

// tcpIdleTimeout bounds how long a DNS-over-TCP connection may sit idle between
// messages before the resolver closes it, so a stalled client cannot pin a
// connection goroutine open.
const tcpIdleTimeout = 10 * time.Second

// dnsZone resolves an in-cluster Service A record. It is the consumer-side seam
// the resolver reads the cluster zone through; the production impl is backed by a
// Services lister, tests inject a map.
type dnsZone interface {
	// LookupService returns the IPv4 ClusterIP of the namespace/name Service, with
	// ok==false when no such Service exists or its ClusterIP is not a routable IPv4
	// (a headless "None" or an IPv6-only Service yields ok==false → NXDOMAIN).
	LookupService(namespace, name string) (netip.Addr, bool)
}

// dnsForwarder resolves a non-cluster name to IPv4 addresses upstream. It is the
// seam for off-cluster names (the per-node resolver is authoritative only for the
// cluster domain); the production impl wraps net.Resolver, tests inject a fake.
type dnsForwarder interface {
	// LookupIP4 resolves host to its IPv4 addresses upstream. It returns a
	// not-found error for NXDOMAIN (mapped to NXDOMAIN) and any other error for a
	// transient upstream failure (mapped to SERVFAIL).
	LookupIP4(ctx context.Context, host string) ([]netip.Addr, error)
}

// clusterResolver is k3sm's per-node, in-process cluster DNS server. It binds the
// DNS VIP on every node and answers:
//   - A records for <svc>.<ns>.svc.<domain> from the cluster Service set (this
//     includes kubernetes.default.svc.<domain> → the apiserver ClusterIP, e.g.
//     10.43.0.1, so an in-pod client-go resolves the API VIP node-locally), and
//   - everything else by forwarding to the host's upstream resolver.
//
// # Divergence from CoreDNS-the-binary (deliberate, documented)
//
// k3sm does NOT run CoreDNS-the-binary nor embed CoreDNS-the-library here. darwin-net
// supplies only the Corefile RENDERING (dns.CorefileOptions, for an external CoreDNS
// deployment) and a client-side dns.Resolver — there is no embeddable DNS server
// seam. CoreDNS-the-binary cannot inherit the netd-helper-passed socket fd under
// launchd (no socket activation), and the unprivileged _k3sm posture binds the
// <1024 DNS VIP only via that helper fd; embedding CoreDNS-the-library (which owns
// its own socket creation) over a passed fd is intractable. So k3sm runs this
// minimal authoritative resolver over the helper/direct-bound sockets instead.
//
// The divergence is scope, not behavior for the M3.3 acceptance: this resolver
// answers Service A records + forwards, which is what in-pod kubectl and cluster
// DNS need. It does NOT implement SRV, PTR, headless per-pod A records, pod A
// records (<ip>.<ns>.pod.<domain>), or AAAA (k3sm's service CIDR is IPv4); those
// are the documented gaps a future darwin-net dns.Server seam would close.
//
// Concurrency: clusterResolver holds no mutable state after construction (zone and
// fwd are themselves concurrency-safe), so respond is safe for concurrent callers.
type clusterResolver struct {
	vip    netip.Addr
	domain string
	zone   dnsZone
	fwd    dnsForwarder
	log    *slog.Logger
}

// newClusterResolver builds the resolver for the DNS VIP and cluster domain over
// the given zone and upstream forwarder.
func newClusterResolver(vip netip.Addr, domain string, zone dnsZone, fwd dnsForwarder, log *slog.Logger) *clusterResolver {
	if domain == "" {
		domain = "cluster.local"
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &clusterResolver{vip: vip, domain: domain, zone: zone, fwd: fwd, log: log}
}

// serveUDP answers datagram queries on pc until ctx is cancelled. Each datagram is
// handled in its own goroutine (a forward may block on the upstream resolver) and
// tracked so serveUDP drains in-flight handlers before returning — no goroutine
// leak under -race. Cancelling ctx closes pc, which unblocks ReadFrom.
func (r *clusterResolver) serveUDP(ctx context.Context, pc net.PacketConn) error {
	go func() { <-ctx.Done(); _ = pc.Close() }()

	var wg sync.WaitGroup
	defer wg.Wait()

	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown (pc closed)
			}
			return fmt.Errorf("dns udp read: %w", err)
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		wg.Add(1)
		go func(query []byte, addr net.Addr) {
			defer wg.Done()
			qctx, cancel := context.WithTimeout(ctx, resolverQueryTimeout)
			defer cancel()
			resp, err := r.respond(qctx, query)
			if err != nil {
				r.log.Debug("dns udp respond", "err", err)
				return
			}
			if _, err := pc.WriteTo(resp, addr); err != nil {
				r.log.Debug("dns udp write", "err", err)
			}
		}(query, addr)
	}
}

// serveTCP answers length-prefixed DNS-over-TCP queries on ln until ctx is
// cancelled. Each connection gets its own goroutine bounded by ctx (a watcher
// closes the conn on cancellation) and an idle read deadline; serveTCP drains
// in-flight connections before returning.
func (r *clusterResolver) serveTCP(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown (ln closed)
			}
			return fmt.Errorf("dns tcp accept: %w", err)
		}
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			r.handleTCPConn(ctx, conn)
		}(conn)
	}
}

// handleTCPConn serves one or more length-prefixed messages on conn until EOF, an
// idle timeout, a malformed frame, or ctx cancellation. A child watcher closes
// conn on ctx.Done so a blocked read wakes up promptly at shutdown.
func (r *clusterResolver) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-connCtx.Done(); _ = conn.Close() }()

	var lenbuf [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := io.ReadFull(conn, lenbuf[:]); err != nil {
			return // EOF, idle timeout, or conn closed at shutdown
		}
		msg := make([]byte, binary.BigEndian.Uint16(lenbuf[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		qctx, qcancel := context.WithTimeout(connCtx, resolverQueryTimeout)
		resp, err := r.respond(qctx, msg)
		qcancel()
		if err != nil {
			r.log.Debug("dns tcp respond", "err", err)
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		_ = conn.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// respond decodes a single query and renders the DNS response. It is the pure core
// of the resolver (zone + forwarder are injectable), so it is unit-tested directly.
// A cluster Service name resolves from the zone (NXDOMAIN when absent); a name in
// the cluster domain that is not a Service A name is NXDOMAIN (pod/SRV records are
// the documented gap); any other name is forwarded upstream. Only A is answered
// with addresses — AAAA and other types get an empty NOERROR (NODATA).
func (r *clusterResolver) respond(ctx context.Context, query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, fmt.Errorf("parse query header: %w", err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("parse question: %w", err)
	}

	qname := normalizeDNSName(q.Name.String())
	rcode := dnsmessage.RCodeSuccess
	var answers []netip.Addr

	switch svc, ns, isService := parseClusterServiceName(qname, r.domain); {
	case isService:
		// In-cluster Service: answer A from the cluster zone, else NXDOMAIN.
		if q.Type == dnsmessage.TypeA {
			if addr, ok := r.zone.LookupService(ns, svc); ok {
				answers = []netip.Addr{addr}
			} else {
				rcode = dnsmessage.RCodeNameError
			}
		}
	case inClusterDomain(qname, r.domain):
		// In the cluster domain but not a Service A name (a pod/SRV/headless name).
		// Unsupported here (the documented divergence) — answer NXDOMAIN rather than
		// forward, so a cluster name never leaks to the upstream resolver.
		rcode = dnsmessage.RCodeNameError
	default:
		// Off-cluster: forward to the host upstream (A only; k3sm is IPv4).
		if q.Type == dnsmessage.TypeA {
			addrs, ferr := r.fwd.LookupIP4(ctx, strings.TrimSuffix(qname, "."))
			switch {
			case ferr == nil:
				answers = addrs
			case isNotFound(ferr):
				rcode = dnsmessage.RCodeNameError
			default:
				r.log.Debug("dns forward", "name", qname, "err", ferr)
				rcode = dnsmessage.RCodeServerFailure
			}
		}
	}

	return buildResponse(hdr.ID, q, answers, rcode)
}

// buildResponse renders a response carrying the question, any A answers, and the
// rcode. RecursionAvailable is set so a resolver client does not treat the answer
// as refusing recursion.
func buildResponse(id uint16, q dnsmessage.Question, answers []netip.Addr, rcode dnsmessage.RCode) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 id,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, fmt.Errorf("start questions: %w", err)
	}
	if err := b.Question(q); err != nil {
		return nil, fmt.Errorf("write question: %w", err)
	}
	if len(answers) > 0 {
		if err := b.StartAnswers(); err != nil {
			return nil, fmt.Errorf("start answers: %w", err)
		}
		for _, a := range answers {
			if !a.Is4() {
				continue
			}
			rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: recordTTL}
			if err := b.AResource(rh, dnsmessage.AResource{A: a.As4()}); err != nil {
				return nil, fmt.Errorf("write A answer: %w", err)
			}
		}
	}
	return b.Finish()
}

// parseClusterServiceName splits an A query name of the form
// <svc>.<ns>.svc.<domain> into its service and namespace, with ok==false when the
// name is not a two-label Service name under .svc.<domain>. qname must already be
// normalized (lowercased, no trailing dot).
func parseClusterServiceName(qname, domain string) (svc, ns string, ok bool) {
	host, found := strings.CutSuffix(qname, ".svc."+domain)
	if !found {
		return "", "", false
	}
	parts := strings.Split(host, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// inClusterDomain reports whether qname falls under the cluster domain (so it must
// be answered authoritatively here and never forwarded upstream).
func inClusterDomain(qname, domain string) bool {
	return qname == domain || strings.HasSuffix(qname, "."+domain)
}

// normalizeDNSName lowercases an ASCII DNS name and strips a single trailing dot
// so zone lookups and suffix matches are canonical.
func normalizeDNSName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

// isNotFound reports whether err is an upstream NXDOMAIN / no-such-host (vs a
// transient failure), so respond can map it to NXDOMAIN rather than SERVFAIL.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// serviceZone is the production dnsZone: it reads the cluster Service set from a
// Services lister (an informer cache), so a lookup is in-memory with no apiserver
// round-trip per query.
type serviceZone struct {
	lister corev1listers.ServiceLister
}

// LookupService returns the namespace/name Service's IPv4 ClusterIP, with
// ok==false for an absent Service or a non-IPv4 ClusterIP (headless "None"/IPv6).
func (z serviceZone) LookupService(namespace, name string) (netip.Addr, bool) {
	svc, err := z.lister.Services(namespace).Get(name)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}

// systemForwarder is the production dnsForwarder: it forwards off-cluster names to
// the host's configured resolver via net.Resolver. On macOS (k3sm builds with cgo)
// this routes through getaddrinfo/configd — the host's real upstream — which is
// correct, because the per-node resolver runs in the unconfined _k3sm control-plane
// process, not under a pod sandbox.
type systemForwarder struct{}

// LookupIP4 resolves host's IPv4 addresses via the default system resolver.
func (systemForwarder) LookupIP4(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	return out, nil
}

// dnsBinder ensures the DNS VIP's lo0 alias and binds the 53/UDP + 53/TCP sockets
// on it through the selected host-network backend (the netd helper when
// unprivileged, direct ops as root). It is the one seam the resolver bring-up
// crosses; the helper-vs-direct selection is made once by newDNSBinder.
type dnsBinder interface {
	// ensureAlias plumbs the /32 lo0 alias for vip so the <1024 socket can bind it
	// (a bind to a non-local address fails with EADDRNOTAVAIL).
	ensureAlias(ctx context.Context, vip netip.Addr) error
	// listenTCP binds a TCP listener on the specific addr.
	listenTCP(ctx context.Context, addr netip.AddrPort) (net.Listener, error)
	// listenUDP binds a UDP socket on the specific addr.
	listenUDP(ctx context.Context, addr netip.AddrPort) (net.PacketConn, error)
}

// newDNSBinder selects the resolver bind backend: the netd helper (the
// unprivileged _k3sm posture — the daemon plumbs the alias and binds the <1024 VIP
// port, passing the socket back over SCM_RIGHTS) when netdSocket is set, else the
// direct root path. It mirrors proxy.WithNetdHelper's one construction-time choice.
func newDNSBinder(netdSocket string) dnsBinder {
	if netdSocket != "" {
		return &helperDNSBinder{client: wire.NewClient(netdSocket)}
	}
	return &directDNSBinder{}
}

// helperDNSBinder routes the DNS VIP alias + the privileged-port bind through the
// root k3sm-netd daemon (the same daemon the Service proxy uses), so the resolver
// runs unprivileged. The daemon admits the alias (the VIP is in the pinned Service
// CIDR) and authorizes the <1024 bind (the kube-dns Service declares :53), then
// passes the listening socket back via SCM_RIGHTS.
type helperDNSBinder struct {
	client *wire.Client
}

func (b *helperDNSBinder) ensureAlias(ctx context.Context, vip netip.Addr) error {
	return b.client.EnsureAlias(ctx, vip)
}

func (b *helperDNSBinder) listenTCP(ctx context.Context, addr netip.AddrPort) (net.Listener, error) {
	f, err := b.client.BindPort(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("helper bind tcp %s: %w", addr, err)
	}
	defer f.Close()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("adopt helper tcp socket %s: %w", addr, err)
	}
	return ln, nil
}

func (b *helperDNSBinder) listenUDP(ctx context.Context, addr netip.AddrPort) (net.PacketConn, error) {
	f, err := b.client.BindPort(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("helper bind udp %s: %w", addr, err)
	}
	defer f.Close()
	pc, err := net.FilePacketConn(f)
	if err != nil {
		return nil, fmt.Errorf("adopt helper udp socket %s: %w", addr, err)
	}
	return pc, nil
}

// directDNSBinder is the explicit run-as-root path: it creates the lo0 alias and
// binds the sockets directly (root can bind <1024). It is the resolver analog of
// proxy.directBinder + the lo0 alias manager.
//
// NOTE (residual): darwin-net does not export a non-helper lo0 alias creator (its
// lo0AliasManager is unexported), so the alias here shells out to ifconfig,
// duplicating that logic. An exported darwin-net seam (or routing direct-mode alias
// creation through netd too) would remove this duplication. The unprivileged
// production posture uses helperDNSBinder, which has no such duplication.
type directDNSBinder struct{}

func (b *directDNSBinder) ensureAlias(ctx context.Context, vip netip.Addr) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("direct DNS-VIP alias %s requires root (use --network helper unprivileged)", vip)
	}
	if err := exec.CommandContext(ctx, "ifconfig", "lo0", "alias", vip.String()+"/32", "up").Run(); err != nil {
		return fmt.Errorf("ifconfig lo0 alias %s: %w", vip, err)
	}
	return nil
}

func (b *directDNSBinder) listenTCP(ctx context.Context, addr netip.AddrPort) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", addr.String())
}

func (b *directDNSBinder) listenUDP(ctx context.Context, addr netip.AddrPort) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, "udp", addr.String())
}
