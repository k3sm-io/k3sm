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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"

	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/install"
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

// serviceTarget is the discriminated result of a cluster Service lookup: exactly
// one of IP / ExternalName is set. A normal Service yields IP (its IPv4 ClusterIP,
// answered as an A record directly); an ExternalName Service yields ExternalName
// (chased through the upstream forwarder and flattened CNAME→A — see respond).
type serviceTarget struct {
	// IP is the Service's IPv4 ClusterIP, set for a normal (non-ExternalName) Service.
	IP netip.Addr
	// ExternalName is the trailing-dot-trimmed Spec.ExternalName, set for an
	// ExternalName Service (mutually exclusive with IP).
	ExternalName string
}

// dnsZone resolves an in-cluster Service to its A-record target. It is the
// consumer-side seam the resolver reads the cluster zone through; the production
// impl is backed by a Services lister, tests inject a map.
type dnsZone interface {
	// LookupService resolves the namespace/name Service to its target. A normal
	// Service yields a serviceTarget with IP set (its IPv4 ClusterIP); an
	// ExternalName Service yields one with ExternalName set. ok==false → NXDOMAIN
	// when no such Service exists, it is headless ("None") or IPv6-only, or it is an
	// ExternalName with an empty Spec.ExternalName.
	LookupService(namespace, name string) (serviceTarget, bool)
}

// identitySource is the OPTIONAL record-synthesis capability of a dnsZone
// (M10.1): headless all-backends A sets, per-endpoint identity A records
// (StatefulSet hostname / dashed-IP), SRV per named port, and the authoritative
// PTR reverse zone. The resolver detects it with a type assertion (the same
// optional-capability pattern as provider.StatsSource): the production
// serviceZone implements it off the Services + EndpointSlices listers; a zone
// without it keeps the pre-M10.1 A/VIP-only behavior.
type identitySource interface {
	// SynthRecords synthesizes the namespace/name Service's full record set
	// (dns.Synthesize semantics). ok==false for an absent or ExternalName
	// Service (the latter stays on the LookupService CNAME-flatten chase path).
	SynthRecords(namespace, name string) (dns.RecordSet, bool)
	// LookupPTR resolves an in-addr.arpa owner name (lower-case, no trailing
	// dot) to its target name across the whole cluster Service set.
	LookupPTR(reverseName string) (string, bool)
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
// The divergence is scope, not behavior: this resolver answers cluster Service
// A records + forwards off-cluster names — and, since M10.1, the DNS identity
// surface synthesized by darwin-net's dns.Synthesize (consumed, never
// reimplemented): headless all-backends A sets, per-endpoint identity A records
// (<hostname>.<svc>... for StatefulSet pods, dashed-IP otherwise), SRV per
// named port, stateless pod A names (<dashed-ip>.<ns>.pod.<domain> via
// dns.PodAddrFromName), and an AUTHORITATIVE reverse zone — in-addr.arpa names
// inside the cluster pod CIDR + service CIDR answer locally (PTR hit or
// NXDOMAIN) and are NEVER forwarded upstream. AAAA stays unanswered (k3sm's
// CIDRs are IPv4).
//
// ExternalName Services ARE resolved (B19): the target is chased through the
// upstream forwarder and FLATTENED CNAME→A — the resolver is A-only, so a client
// gets the target's A records under the queried name, never the upstream CNAME RR (a
// TypeCNAME / ai_canonname query gets NODATA, the same rule the off-cluster forward
// already applies). One gap: an ExternalName whose target is itself inside the
// cluster domain is unsupported (NXDOMAIN) — it is deliberately not re-resolved
// in-cluster (that would risk a resolver loop) and must never leak to the host
// upstream.
//
// Concurrency: clusterResolver holds no mutable state after construction (zone and
// fwd are themselves concurrency-safe), so respond is safe for concurrent callers.
type clusterResolver struct {
	vip    netip.Addr
	domain string
	zone   dnsZone
	// ident is the zone's optional record-synthesis capability (type-asserted
	// from zone at construction); nil keeps the A/VIP-only behavior.
	ident identitySource
	fwd   dnsForwarder
	log   *slog.Logger
	// podCIDR and serviceCIDR bound the AUTHORITATIVE reverse zones: an
	// in-addr.arpa name for an address inside either answers locally (PTR hit
	// or NXDOMAIN) and never leaks upstream. podCIDR is the CLUSTER pod CIDR
	// (100.64.0.0/10 — every node's /24, not just this one's), serviceCIDR the
	// pinned cluster Service CIDR.
	podCIDR     netip.Prefix
	serviceCIDR netip.Prefix
}

// newClusterResolver builds the resolver for the DNS VIP and cluster domain over
// the given zone and upstream forwarder. The zone's identitySource capability
// (record synthesis + PTR) is detected by type assertion.
func newClusterResolver(vip netip.Addr, domain string, zone dnsZone, fwd dnsForwarder, log *slog.Logger) *clusterResolver {
	if domain == "" {
		domain = dns.DefaultClusterDomain
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &clusterResolver{vip: vip, domain: domain, zone: zone, fwd: fwd, log: log, podCIDR: podnet.ClusterPodCIDR}
	r.ident, _ = zone.(identitySource)
	// The pinned Service CIDR (the same install.DefaultServiceCIDR the netd
	// daemon admits VIP aliases from). A parse failure leaves the zero Prefix —
	// authoritativeReverse then simply excludes it — but the constant is pinned
	// and covered by tests, so this is defensive, not a fallback code path.
	if p, err := netip.ParsePrefix(install.DefaultServiceCIDR); err == nil {
		r.serviceCIDR = p.Masked()
	}
	return r
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

// dnsAnswer carries the typed answers respond renders: A addresses, SRV
// records, and/or a single PTR target (exactly the record types this resolver
// is authoritative for). The zero value is an empty answer section.
type dnsAnswer struct {
	a   []netip.Addr
	srv []dns.SRVRecord
	ptr string
}

// respond decodes a single query and renders the DNS response. It is the pure core
// of the resolver (zone + forwarder are injectable), so it is unit-tested directly.
//
//   - <svc>.<ns>.svc.<domain> A: a normal Service answers its ClusterIP, an
//     ExternalName Service is chased through the forwarder (flattened CNAME→A),
//     a headless Service answers every included backend pod IP (synthesis), and
//     an absent one is NXDOMAIN.
//   - deeper names under .svc.<domain> (per-endpoint identity A records,
//     _<port>._<proto> SRV owner names) answer from the synthesized record set.
//   - <dashed-ip>.<ns>.pod.<domain> A decodes statelessly (dns.PodAddrFromName).
//   - in-addr.arpa PTR inside the cluster pod/service CIDRs is AUTHORITATIVE:
//     a PTR hit or NXDOMAIN, never an upstream forward.
//   - any other cluster-domain name is NXDOMAIN (never leaked upstream); any
//     off-cluster name forwards (A only; k3sm is IPv4). Unanswered types get an
//     empty NOERROR (NODATA).
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
	var ans dnsAnswer

	switch extra, svc, ns, inSvcZone := parseClusterZoneName(qname, r.domain); {
	case strings.HasSuffix(qname, ".in-addr.arpa"):
		ans, rcode = r.respondReverse(q.Type, qname)
	case inSvcZone && len(extra) == 0:
		// The exact <svc>.<ns> Service name. A answers ClusterIP / ExternalName
		// chase / headless synthesis; SRV on the bare service name is NODATA when
		// the service exists (SRV owner names are the _port._proto forms below).
		if q.Type == dnsmessage.TypeA {
			switch target, ok := r.zone.LookupService(ns, svc); {
			case !ok:
				// Not a VIP-answerable Service: a headless (ClusterIP None) Service
				// synthesizes its all-backends A set; an absent/pending/IPv6 one is
				// NXDOMAIN (synthesis also declines those).
				ans.a, rcode = r.synthA(ns, svc, qname)
			case target.ExternalName != "":
				// ExternalName: resolve the target upstream and stamp its A records
				// under the QUERIED name (buildResponse owns that flatten). A target
				// inside the cluster domain is NOT forwarded — that would both leak the
				// cluster name to the host upstream and fail to resolve there — so it is
				// NXDOMAIN. Deliberately NOT recursive in-cluster re-resolution, which
				// would risk a resolver loop; the in-cluster-target case is a documented
				// gap.
				if inClusterDomain(target.ExternalName, r.domain) {
					rcode = dnsmessage.RCodeNameError
				} else {
					ans.a, rcode = r.forward(ctx, target.ExternalName)
				}
			default:
				ans.a = []netip.Addr{target.IP}
			}
		} else if q.Type == dnsmessage.TypeSRV {
			ans.srv, rcode = r.synthSRV(ns, svc, qname)
		}
	case inSvcZone:
		// A deeper name under <svc>.<ns>.svc.<domain>: a per-endpoint identity A
		// record (<hostname>.<svc>... / <dashed-ip>.<svc>...) or an SRV owner name
		// (_<port>._<proto>.<svc>...). Answered from the synthesized set; a miss
		// is NXDOMAIN (never forwarded).
		switch q.Type {
		case dnsmessage.TypeA:
			ans.a, rcode = r.synthA(ns, svc, qname)
		case dnsmessage.TypeSRV:
			ans.srv, rcode = r.synthSRV(ns, svc, qname)
		}
	case strings.HasSuffix(qname, ".pod."+r.domain):
		// Stateless pod A name: <dashed-ip>.<ns>.pod.<domain> decodes to its
		// address (upstream kube-dns semantics — no existence check); a malformed
		// pod name is NXDOMAIN.
		if q.Type == dnsmessage.TypeA {
			if addr, _, err := dns.PodAddrFromName(qname, r.domain); err == nil {
				ans.a = []netip.Addr{addr}
			} else {
				rcode = dnsmessage.RCodeNameError
			}
		}
	case inClusterDomain(qname, r.domain):
		// In the cluster domain but not an answerable name. NXDOMAIN rather than
		// forward, so a cluster name never leaks to the upstream resolver.
		rcode = dnsmessage.RCodeNameError
	default:
		// Off-cluster: forward to the host upstream (A only; k3sm is IPv4).
		if q.Type == dnsmessage.TypeA {
			ans.a, rcode = r.forward(ctx, qname)
		}
	}

	return buildResponse(hdr.ID, q, ans, rcode)
}

// synthA answers an A query for owner qname from the (ns, svc) Service's
// synthesized record set: the headless all-backends set for the bare service
// name, a per-endpoint identity record for the deeper names. A missing zone
// capability, absent Service, or unknown owner name is NXDOMAIN — except an
// owner that exists only as an SRV name, which is NODATA (the name exists).
func (r *clusterResolver) synthA(ns, svc, qname string) ([]netip.Addr, dnsmessage.RCode) {
	if r.ident == nil {
		return nil, dnsmessage.RCodeNameError
	}
	rs, ok := r.ident.SynthRecords(ns, svc)
	if !ok {
		return nil, dnsmessage.RCodeNameError
	}
	if a := rs.A[qname]; len(a) > 0 {
		return a, dnsmessage.RCodeSuccess
	}
	if len(rs.SRV[qname]) > 0 {
		return nil, dnsmessage.RCodeSuccess // the name exists as an SRV owner: NODATA
	}
	return nil, dnsmessage.RCodeNameError
}

// synthSRV answers an SRV query for owner qname from the (ns, svc) Service's
// synthesized record set. An owner that exists only as an A name (the bare
// service / an identity record) is NODATA; an unknown owner is NXDOMAIN.
func (r *clusterResolver) synthSRV(ns, svc, qname string) ([]dns.SRVRecord, dnsmessage.RCode) {
	if r.ident == nil {
		return nil, dnsmessage.RCodeNameError
	}
	rs, ok := r.ident.SynthRecords(ns, svc)
	if !ok {
		return nil, dnsmessage.RCodeNameError
	}
	if srv := rs.SRV[qname]; len(srv) > 0 {
		return srv, dnsmessage.RCodeSuccess
	}
	if len(rs.A[qname]) > 0 {
		return nil, dnsmessage.RCodeSuccess // the name exists as an A owner: NODATA
	}
	return nil, dnsmessage.RCodeNameError
}

// respondReverse answers an in-addr.arpa query. The resolver is AUTHORITATIVE
// for the cluster pod CIDR + service CIDR reverse zones: a PTR query for an
// address inside them answers locally — the synthesized PTR target on a hit,
// NXDOMAIN on a miss — and is NEVER forwarded upstream (a cluster address must
// not leak to the host resolver). A reverse name outside those CIDRs (or a
// non-PTR type) is an empty NOERROR: the forwarder is A-only by design, so no
// reverse name is ever sent upstream either way.
func (r *clusterResolver) respondReverse(qtype dnsmessage.Type, qname string) (dnsAnswer, dnsmessage.RCode) {
	if qtype != dnsmessage.TypePTR {
		return dnsAnswer{}, dnsmessage.RCodeSuccess
	}
	ip, ok := addrFromReverseName(qname)
	if !ok || !r.authoritativeReverse(ip) {
		return dnsAnswer{}, dnsmessage.RCodeSuccess
	}
	if r.ident != nil {
		if target, ok := r.ident.LookupPTR(qname); ok {
			return dnsAnswer{ptr: target}, dnsmessage.RCodeSuccess
		}
	}
	return dnsAnswer{}, dnsmessage.RCodeNameError
}

// authoritativeReverse reports whether ip falls inside a reverse zone this
// resolver owns (the cluster pod CIDR or the pinned Service CIDR).
func (r *clusterResolver) authoritativeReverse(ip netip.Addr) bool {
	return (r.podCIDR.IsValid() && r.podCIDR.Contains(ip)) ||
		(r.serviceCIDR.IsValid() && r.serviceCIDR.Contains(ip))
}

// addrFromReverseName decodes a <d>.<c>.<b>.<a>.in-addr.arpa owner name into
// the IPv4 address a.b.c.d. ok==false for anything else.
func addrFromReverseName(qname string) (netip.Addr, bool) {
	rev, found := strings.CutSuffix(qname, ".in-addr.arpa")
	if !found {
		return netip.Addr{}, false
	}
	octets := strings.Split(rev, ".")
	if len(octets) != 4 {
		return netip.Addr{}, false
	}
	// Reverse-name octet order is least-significant first.
	addr, err := netip.ParseAddr(octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0])
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}

// forward resolves an off-cluster host through the upstream forwarder, mapping its
// three outcomes to (addrs, rcode): a successful lookup → (addrs, RCodeSuccess); an
// upstream not-found → (nil, RCodeNameError), i.e. NXDOMAIN; any other (transient)
// error → (nil, RCodeServerFailure), i.e. SERVFAIL, with a debug log. Both the
// off-cluster default path and the ExternalName chase route through it, so a
// transient SERVFAIL is never collapsed into a cacheable NXDOMAIN.
func (r *clusterResolver) forward(ctx context.Context, host string) ([]netip.Addr, dnsmessage.RCode) {
	addrs, err := r.fwd.LookupIP4(ctx, host)
	switch {
	case err == nil:
		return addrs, dnsmessage.RCodeSuccess
	case isNotFound(err):
		return nil, dnsmessage.RCodeNameError
	default:
		r.log.Debug("dns forward", "name", host, "err", err)
		return nil, dnsmessage.RCodeServerFailure
	}
}

// buildResponse renders a response carrying the question, the typed answers
// (A / SRV / PTR), and the rcode. RecursionAvailable is set so a resolver
// client does not treat the answer as refusing recursion.
func buildResponse(id uint16, q dnsmessage.Question, ans dnsAnswer, rcode dnsmessage.RCode) ([]byte, error) {
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
	if len(ans.a) > 0 || len(ans.srv) > 0 || ans.ptr != "" {
		if err := b.StartAnswers(); err != nil {
			return nil, fmt.Errorf("start answers: %w", err)
		}
	}
	for _, a := range ans.a {
		if !a.Is4() {
			continue
		}
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: recordTTL}
		if err := b.AResource(rh, dnsmessage.AResource{A: a.As4()}); err != nil {
			return nil, fmt.Errorf("write A answer: %w", err)
		}
	}
	for _, s := range ans.srv {
		target, err := dnsmessage.NewName(s.Target + ".")
		if err != nil {
			return nil, fmt.Errorf("srv target %q: %w", s.Target, err)
		}
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: recordTTL}
		if err := b.SRVResource(rh, dnsmessage.SRVResource{
			Priority: s.Priority,
			Weight:   s.Weight,
			Port:     s.Port,
			Target:   target,
		}); err != nil {
			return nil, fmt.Errorf("write SRV answer: %w", err)
		}
	}
	if ans.ptr != "" {
		target, err := dnsmessage.NewName(ans.ptr + ".")
		if err != nil {
			return nil, fmt.Errorf("ptr target %q: %w", ans.ptr, err)
		}
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: recordTTL}
		if err := b.PTRResource(rh, dnsmessage.PTRResource{PTR: target}); err != nil {
			return nil, fmt.Errorf("write PTR answer: %w", err)
		}
	}
	return b.Finish()
}

// parseClusterServiceName splits an A query name of the form
// <svc>.<ns>.svc.<domain> into its service and namespace, with ok==false when the
// name is not a two-label Service name under .svc.<domain>. qname must already be
// normalized (lowercased, no trailing dot).
func parseClusterServiceName(qname, domain string) (svc, ns string, ok bool) {
	extra, svc, ns, ok := parseClusterZoneName(qname, domain)
	if !ok || len(extra) != 0 {
		return "", "", false
	}
	return svc, ns, true
}

// parseClusterZoneName splits any name under .svc.<domain> into its owning
// service and namespace (the two labels immediately before the suffix) plus the
// extra leading labels: a per-endpoint identity name yields one extra label
// (the hostname / dashed IP), an SRV owner name two (_port, _proto), the bare
// service name none. ok==false when the name is not under .svc.<domain> or
// lacks the two service labels. qname must already be normalized.
func parseClusterZoneName(qname, domain string) (extra []string, svc, ns string, ok bool) {
	host, found := strings.CutSuffix(qname, ".svc."+domain)
	if !found {
		return nil, "", "", false
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return nil, "", "", false
	}
	for _, p := range parts {
		if p == "" {
			return nil, "", "", false
		}
	}
	return parts[:len(parts)-2], parts[len(parts)-2], parts[len(parts)-1], true
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
// Services lister and the backend endpoints from an EndpointSlices lister (both
// informer caches), so a lookup is in-memory with no apiserver round-trip per
// query. It also implements identitySource (M10.1): the record-synthesis inputs
// are extracted from those listers and handed to darwin-net's dns.Synthesize —
// consumed, never reimplemented.
type serviceZone struct {
	services corev1listers.ServiceLister
	// slices supplies the EndpointSlice endpoints (pod IPs + hostname + ready)
	// synthesis consumes. nil disables the identitySource capability (tests /
	// legacy construction), keeping the A/VIP-only behavior.
	slices discoverylisters.EndpointSliceLister
	// domain is the cluster DNS domain the synthesized owner names are rooted
	// at — the SAME domain the resolver serves (a mismatch would synthesize
	// names no query ever matches).
	domain string
}

// Compile-time check: the production zone carries the synthesis capability.
var _ identitySource = serviceZone{}

// LookupService resolves the namespace/name Service to its target. It branches on
// the Service TYPE, not on an empty ClusterIP — that is overloaded with a headless
// "None" and a still-pending ClusterIP, both of which must yield NXDOMAIN, not a
// forward. An ExternalName Service with a non-empty Spec.ExternalName yields that
// name (trailing dot trimmed) for the upstream chase; every other Service yields its
// IPv4 ClusterIP. ok==false (→ NXDOMAIN) for an absent Service, an ExternalName with
// an empty Spec.ExternalName, or a non-IPv4 ClusterIP (headless "None"/IPv6/pending).
func (z serviceZone) LookupService(namespace, name string) (serviceTarget, bool) {
	svc, err := z.services.Services(namespace).Get(name)
	if err != nil {
		return serviceTarget{}, false
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName && svc.Spec.ExternalName != "" {
		return serviceTarget{ExternalName: strings.TrimSuffix(svc.Spec.ExternalName, ".")}, true
	}
	addr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil || !addr.Is4() {
		return serviceTarget{}, false
	}
	return serviceTarget{IP: addr}, true
}

// SynthRecords implements identitySource: it synthesizes the namespace/name
// Service's record set (headless all-backends A, per-endpoint identity A, SRV
// per named port, PTR) via dns.Synthesize. ok==false for an absent or
// ExternalName Service, a non-IPv4/pending ClusterIP, a nil slices lister, or a
// synthesis input error — all of which the caller answers as NXDOMAIN.
func (z serviceZone) SynthRecords(namespace, name string) (dns.RecordSet, bool) {
	if z.slices == nil {
		return dns.RecordSet{}, false
	}
	svc, err := z.services.Services(namespace).Get(name)
	if err != nil {
		return dns.RecordSet{}, false
	}
	return z.synthesize(svc)
}

// LookupPTR implements identitySource: it resolves an in-addr.arpa owner name
// to its target by scanning the cluster Service set (a service ClusterIP → the
// service name; a headless backend pod IP → its endpoint identity name). PTR
// queries are rare and the Service set is dev-scale, so the scan synthesizes on
// demand rather than maintaining a reverse index.
func (z serviceZone) LookupPTR(reverseName string) (string, bool) {
	if z.slices == nil {
		return "", false
	}
	svcs, err := z.services.List(labels.Everything())
	if err != nil {
		return "", false
	}
	for _, svc := range svcs {
		rs, ok := z.synthesize(svc)
		if !ok {
			continue
		}
		if target, ok := rs.PTR[reverseName]; ok {
			return target, true
		}
	}
	return "", false
}

// synthesize builds the record set for one Service from its EndpointSlices.
func (z serviceZone) synthesize(svc *corev1.Service) (dns.RecordSet, bool) {
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return dns.RecordSet{}, false // chased through the forwarder, never synthesized
	}
	endpoints, slicePorts := z.endpointsFor(svc.Namespace, svc.Name)
	in, ok := synthServiceInput(svc, slicePorts)
	if !ok {
		return dns.RecordSet{}, false
	}
	rs, err := dns.Synthesize(z.domain, in, endpoints)
	if err != nil {
		return dns.RecordSet{}, false // malformed inputs → no records (NXDOMAIN), never a partial set
	}
	return rs, true
}

// endpointsFor extracts the synthesis endpoints + the deduped endpoint (target)
// ports from the Service's IPv4 EndpointSlices (matched by the standard
// kubernetes.io/service-name label).
func (z serviceZone) endpointsFor(namespace, name string) ([]dns.SynthEndpoint, []dns.SynthPort) {
	sel := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: name})
	slices, err := z.slices.EndpointSlices(namespace).List(sel)
	if err != nil {
		return nil, nil
	}
	var endpoints []dns.SynthEndpoint
	var ports []dns.SynthPort
	seenPorts := map[string]struct{}{}
	for _, slice := range slices {
		if slice.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		for _, ep := range slice.Endpoints {
			if len(ep.Addresses) == 0 {
				continue
			}
			addr, err := netip.ParseAddr(ep.Addresses[0])
			if err != nil || !addr.Is4() {
				continue
			}
			e := dns.SynthEndpoint{IP: addr.Unmap()}
			if ep.Hostname != nil {
				e.Hostname = *ep.Hostname
			}
			// A nil Ready condition means "unknown — consumers should treat it as
			// serving" (the EndpointConditions contract), so only an explicit false
			// excludes.
			e.Ready = ep.Conditions.Ready == nil || *ep.Conditions.Ready
			endpoints = append(endpoints, e)
		}
		for _, p := range slice.Ports {
			if p.Port == nil {
				continue
			}
			sp := dns.SynthPort{Port: uint16(*p.Port)}
			if p.Name != nil {
				sp.Name = *p.Name
			}
			if p.Protocol != nil {
				sp.Protocol = string(*p.Protocol)
			}
			key := sp.Name + "/" + sp.Protocol
			if _, seen := seenPorts[key]; seen {
				continue
			}
			seenPorts[key] = struct{}{}
			ports = append(ports, sp)
		}
	}
	return endpoints, ports
}

// synthServiceInput maps a corev1.Service to the dns.SynthService synthesis
// input. A headless service carries the EndpointSlice (target) ports; a normal
// one its spec ports + ClusterIP. ok==false when a normal service has no
// answerable IPv4 ClusterIP (pending/IPv6) — those must stay NXDOMAIN.
func synthServiceInput(svc *corev1.Service, slicePorts []dns.SynthPort) (dns.SynthService, bool) {
	in := dns.SynthService{
		Name:                     svc.Name,
		Namespace:                svc.Namespace,
		Headless:                 svc.Spec.ClusterIP == corev1.ClusterIPNone,
		PublishNotReadyAddresses: svc.Spec.PublishNotReadyAddresses,
	}
	if in.Headless {
		in.Ports = slicePorts
		return in, true
	}
	addr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil || !addr.Is4() {
		return dns.SynthService{}, false
	}
	in.ClusterIP = addr.Unmap()
	for _, p := range svc.Spec.Ports {
		in.Ports = append(in.Ports, dns.SynthPort{Name: p.Name, Port: uint16(p.Port), Protocol: string(p.Protocol)})
	}
	return in, true
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
