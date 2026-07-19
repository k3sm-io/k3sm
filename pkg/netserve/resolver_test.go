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
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/darwin-net/pkg/dns"
)

// mapZone is a fake cluster Service zone (key "ns/name" → serviceTarget). A missing
// key is ok==false (NXDOMAIN), modeling an absent Service, a headless "None", or an
// IPv6-only Service — exactly the cases the production serviceZone collapses to
// ok==false (its real Type-branching is proven in TestServiceZoneBranchesOnType).
type mapZone map[string]serviceTarget

func (z mapZone) LookupService(namespace, name string) (serviceTarget, bool) {
	t, ok := z[namespace+"/"+name]
	return t, ok
}

// mapForwarder is a fake upstream forwarder (host → IPv4 addrs); a miss returns a
// not-found net.DNSError so respond maps it to NXDOMAIN.
type mapForwarder map[string][]netip.Addr

func (f mapForwarder) LookupIP4(_ context.Context, host string) ([]netip.Addr, error) {
	a, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return a, nil
}

// recordingForwarder is a fake dnsForwarder that records every host it is asked to
// resolve (so a test can prove the ExternalName chase forwards the TARGET, not the
// queried cluster name) and answers from a fixed host→addrs map. A host absent from
// the map returns a not-found net.DNSError (→ NXDOMAIN); when failWith is set, every
// lookup returns it instead (a transient, non-not-found error → SERVFAIL).
type recordingForwarder struct {
	mu       sync.Mutex
	answers  map[string][]netip.Addr
	failWith error
	calls    []string
}

func (f *recordingForwarder) LookupIP4(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.calls = append(f.calls, host)
	f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// called reports whether the forwarder was ever asked to resolve host.
func (f *recordingForwarder) called(host string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.calls, host)
}

// callCount returns how many times the forwarder was invoked.
func (f *recordingForwarder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestM3_3_ResolverAnswersClusterAndForwards is an M3.3-a1 unit proof: the
// in-process per-node resolver answers cluster Service A records — including
// kubernetes.default.svc.cluster.local → the API VIP (so an in-pod client-go
// resolves the kubernetes endpoint NODE-LOCALLY, the in-pod-kubectl half of
// M3.3-a1) — and forwards off-cluster names upstream, over BOTH the UDP and TCP
// transports it binds on the DNS VIP. The live cross-node DNS is the m3.sh lab leg;
// this pins the resolver's wire behavior.
func TestM3_3_ResolverAnswersClusterAndForwards(t *testing.T) {
	t.Parallel()

	zone := mapZone{
		"default/kubernetes": {IP: netip.MustParseAddr("10.43.0.1")},  // the API VIP, node-local
		"default/web":        {IP: netip.MustParseAddr("10.43.0.55")}, // a normal ClusterIP
	}
	fwd := mapForwarder{
		"example.com": {netip.MustParseAddr("93.184.216.34")},
	}
	r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, fwd, testLogger())

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	udpDone := make(chan error, 1)
	tcpDone := make(chan error, 1)
	go func() { udpDone <- r.serveUDP(ctx, udp) }()
	go func() { tcpDone <- r.serveTCP(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-udpDone; err != nil {
			t.Errorf("serveUDP returned %v, want nil on clean shutdown", err)
		}
		if err := <-tcpDone; err != nil {
			t.Errorf("serveTCP returned %v, want nil on clean shutdown", err)
		}
	})

	udpAddr := udp.LocalAddr().String()
	tcpAddr := ln.Addr().String()

	cases := []struct {
		name      string
		query     string
		wantRCode dnsmessage.RCode
		wantAddrs []string
	}{
		{"api VIP node-local", "kubernetes.default.svc.cluster.local", dnsmessage.RCodeSuccess, []string{"10.43.0.1"}},
		{"cluster service", "web.default.svc.cluster.local", dnsmessage.RCodeSuccess, []string{"10.43.0.55"}},
		{"absent cluster service NXDOMAIN", "missing.default.svc.cluster.local", dnsmessage.RCodeNameError, nil},
		{"off-cluster forwarded", "example.com", dnsmessage.RCodeSuccess, []string{"93.184.216.34"}},
		{"off-cluster not found NXDOMAIN", "nope.invalid", dnsmessage.RCodeNameError, nil},
	}
	for _, tc := range cases {
		for _, transport := range []string{"udp", "tcp"} {
			t.Run(tc.name+"/"+transport, func(t *testing.T) {
				var rcode dnsmessage.RCode
				var addrs []netip.Addr
				if transport == "udp" {
					rcode, addrs = queryUDP(t, udpAddr, tc.query)
				} else {
					rcode, addrs = queryTCP(t, tcpAddr, tc.query)
				}
				if rcode != tc.wantRCode {
					t.Fatalf("rcode = %v, want %v", rcode, tc.wantRCode)
				}
				got := make([]string, len(addrs))
				for i, a := range addrs {
					got[i] = a.String()
				}
				if !equalStrings(got, tc.wantAddrs) {
					t.Fatalf("addrs = %v, want %v", got, tc.wantAddrs)
				}
			})
		}
	}
}

// TestNewClusterResolverDefaultsDomain pins the B42 consolidation on the netserve
// side: newClusterResolver with an EMPTY cluster domain falls back to the
// single-sourced dns.DefaultClusterDomain — the SAME const cmd/k3sm's runtimedConfig
// fallback and the --cluster-domain flag defaults now resolve to (closing the B18
// desync between the served zone and the pod-search suffix). It proves both the stored
// domain field and that the empty-domain resolver actually SERVES that default zone: a
// cluster Service under *.svc.<dns.DefaultClusterDomain> resolves node-locally.
func TestNewClusterResolverDefaultsDomain(t *testing.T) {
	t.Parallel()

	zone := mapZone{
		"default/web": serviceTarget{IP: netip.MustParseAddr("10.43.0.55")},
	}
	r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "", zone, mapForwarder{}, testLogger())
	if r.domain != dns.DefaultClusterDomain {
		t.Fatalf("newClusterResolver(domain=\"\").domain = %q, want dns.DefaultClusterDomain (%q)", r.domain, dns.DefaultClusterDomain)
	}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	udpDone := make(chan error, 1)
	go func() { udpDone <- r.serveUDP(ctx, udp) }()
	t.Cleanup(func() {
		cancel()
		if err := <-udpDone; err != nil {
			t.Errorf("serveUDP returned %v, want nil on clean shutdown", err)
		}
	})

	// A cluster Service under the DEFAULT zone resolves to its ClusterIP, proving the
	// empty-domain resolver serves *.svc.<dns.DefaultClusterDomain> (not some other suffix).
	rcode, addrs := queryUDP(t, udp.LocalAddr().String(), "web.default.svc."+dns.DefaultClusterDomain)
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, want success for a Service under the default zone", rcode)
	}
	got := make([]string, len(addrs))
	for i, a := range addrs {
		got[i] = a.String()
	}
	if !equalStrings(got, []string{"10.43.0.55"}) {
		t.Fatalf("addrs = %v, want [10.43.0.55] (the cluster Service VIP under the default zone)", got)
	}
}

// TestM3_3_ResolverBindsViaHelper is an M3.3-a1 unit proof of the bind backend
// SELECTION: an unprivileged node (a non-empty netd socket) binds the DNS VIP
// through the netd helper (which plumbs the alias and passes the <1024 socket back
// over SCM_RIGHTS), while the explicit run-as-root mode binds directly. The live
// fd-passing bind is the lab leg; this pins which backend the resolver selects.
func TestM3_3_ResolverBindsViaHelper(t *testing.T) {
	t.Parallel()

	if b, ok := newDNSBinder("/var/lib/k3sm/run/netd.sock").(*helperDNSBinder); !ok || b == nil {
		t.Fatalf("newDNSBinder(socket) = %T, want *helperDNSBinder (unprivileged posture routes the DNS VIP bind through the helper)", newDNSBinder("/var/lib/k3sm/run/netd.sock"))
	}
	if _, ok := newDNSBinder("").(*directDNSBinder); !ok {
		t.Fatalf("newDNSBinder(\"\") = %T, want *directDNSBinder (run-as-root binds directly)", newDNSBinder(""))
	}
}

// TestParseClusterServiceName checks the <svc>.<ns>.svc.<domain> A-name parser and
// the cluster-domain containment used to keep cluster names off the upstream.
func TestParseClusterServiceName(t *testing.T) {
	t.Parallel()
	const domain = "cluster.local"
	cases := []struct {
		qname              string
		wantSvc, wantNS    string
		wantOK, wantInZone bool
	}{
		{"kubernetes.default.svc.cluster.local", "kubernetes", "default", true, true},
		{"web.prod.svc.cluster.local", "web", "prod", true, true},
		{"too.many.labels.svc.cluster.local", "", "", false, true}, // in domain, not a 2-label svc name
		{"6-4-3-2.default.pod.cluster.local", "", "", false, true}, // pod record (unsupported) but in domain
		{"example.com", "", "", false, false},                      // off-cluster → forwarded
	}
	for _, tc := range cases {
		svc, ns, ok := parseClusterServiceName(tc.qname, domain)
		if ok != tc.wantOK || svc != tc.wantSvc || ns != tc.wantNS {
			t.Errorf("parseClusterServiceName(%q) = (%q,%q,%v), want (%q,%q,%v)", tc.qname, svc, ns, ok, tc.wantSvc, tc.wantNS, tc.wantOK)
		}
		if got := inClusterDomain(tc.qname, domain); got != tc.wantInZone {
			t.Errorf("inClusterDomain(%q) = %v, want %v", tc.qname, got, tc.wantInZone)
		}
	}
}

// queryUDP sends an A query for name to a UDP DNS server and returns its rcode + A
// answers.
func queryUDP(t *testing.T, server, name string) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatalf("dial udp %s: %v", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(buildAQuery(t, name)); err != nil {
		t.Fatalf("write udp query: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read udp response: %v", err)
	}
	return parseResponse(t, buf[:n])
}

// queryTCP sends a length-prefixed A query for name to a TCP DNS server and returns
// its rcode + A answers.
func queryTCP(t *testing.T, server, name string) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	conn, err := net.Dial("tcp", server)
	if err != nil {
		t.Fatalf("dial tcp %s: %v", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := buildAQuery(t, name)
	out := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(out[:2], uint16(len(q)))
	copy(out[2:], q)
	if _, err := conn.Write(out); err != nil {
		t.Fatalf("write tcp query: %v", err)
	}
	var lenbuf [2]byte
	if _, err := io.ReadFull(conn, lenbuf[:]); err != nil {
		t.Fatalf("read tcp len: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenbuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read tcp response: %v", err)
	}
	return parseResponse(t, resp)
}

// buildAQuery packs an A-record query for name (FQDN-normalized).
func buildAQuery(t *testing.T, name string) []byte {
	t.Helper()
	return buildTypedQuery(t, name, dnsmessage.TypeA)
}

// buildTypedQuery packs a query of the given record type for name (FQDN-normalized).
func buildTypedQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	if name == "" || name[len(name)-1] != '.' {
		name += "."
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("question: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("finish query: %v", err)
	}
	return msg
}

// parseResponse decodes a DNS response into its rcode + the A-record addresses.
func parseResponse(t *testing.T, resp []byte) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatalf("parse response header: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	var addrs []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatalf("answer header: %v", err)
		}
		if ah.Type != dnsmessage.TypeA {
			_ = p.SkipAnswer()
			continue
		}
		ar, err := p.AResource()
		if err != nil {
			t.Fatalf("a resource: %v", err)
		}
		addrs = append(addrs, netip.AddrFrom4(ar.A))
	}
	return hdr.RCode, addrs
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestExternalNameResolvesViaForwarder is the B19 unit proof: the per-node resolver
// resolves an ExternalName Service by chasing spec.externalName through the upstream
// forwarder and FLATTENING CNAME→A — the target's A records are stamped under the
// QUERIED cluster name, with no CNAME RR. It pins the load-bearing correctness points
// the pre-build critiques converged on: only a Type==ExternalName Service is chased
// (an absent/headless one still NXDOMAINs), an ExternalName target inside the cluster
// domain is NOT forwarded (anti-leak → NXDOMAIN), and a transient forward failure is
// SERVFAIL, never a cacheable NXDOMAIN.
func TestExternalNameResolvesViaForwarder(t *testing.T) {
	t.Parallel()
	const domain = "cluster.local"
	vip := netip.MustParseAddr("10.43.0.10")

	// (a)+(b)+(c): an ExternalName Service is chased; the forwarder is asked for the
	// TARGET (not the cluster qname), and the target's A records are stamped under the
	// QUERIED name with no CNAME RR (the flatten contract).
	t.Run("chase flattens target A under queried name", func(t *testing.T) {
		fwd := &recordingForwarder{answers: map[string][]netip.Addr{
			"db.example.com": {netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("203.0.113.8")},
		}}
		zone := mapZone{"prod/db": {ExternalName: "db.example.com"}}
		r := newClusterResolver(vip, domain, zone, fwd, testLogger())

		rcode, addrs, aNames, cnames := respondQuery(t, r, "db.prod.svc.cluster.local", dnsmessage.TypeA)
		// (a) NOERROR + the target's A records.
		if rcode != dnsmessage.RCodeSuccess {
			t.Fatalf("rcode = %v, want NOERROR", rcode)
		}
		if got := addrStrings(addrs); !equalStrings(got, []string{"203.0.113.7", "203.0.113.8"}) {
			t.Fatalf("addrs = %v, want the target's A records", got)
		}
		// (a) stamped under the QUERIED cluster name (the flatten), not the target.
		for _, n := range aNames {
			if normalizeDNSName(n) != "db.prod.svc.cluster.local" {
				t.Fatalf("A record owner = %q, want the queried name db.prod.svc.cluster.local", n)
			}
		}
		// (b) the forwarder was asked for the TARGET, and the cluster qname never leaked.
		if !fwd.called("db.example.com") {
			t.Fatalf("forwarder was not asked for the ExternalName target db.example.com")
		}
		if fwd.called("db.prod.svc.cluster.local") {
			t.Fatalf("forwarder was asked for the cluster qname (qname leak)")
		}
		// (c) no CNAME RR — the resolver flattens to A only.
		if cnames != 0 {
			t.Fatalf("answer carried %d CNAME RRs, want 0 (CNAME→A flatten)", cnames)
		}
	})

	// (d): only a Type==ExternalName Service is chased. A lookup that yields ok==false
	// — an ABSENT Service and a headless "None" Service (serviceZone collapses both to
	// ok==false; TestServiceZoneBranchesOnType proves the None branch) — is NXDOMAIN
	// and is NEVER forwarded.
	t.Run("absent and headless None NXDOMAIN never chased", func(t *testing.T) {
		fwd := &recordingForwarder{}
		zone := mapZone{} // no entry → ok==false (absent / headless None / IPv6-only)
		r := newClusterResolver(vip, domain, zone, fwd, testLogger())

		for _, q := range []string{
			"absent.prod.svc.cluster.local",   // a Service that does not exist
			"headless.prod.svc.cluster.local", // a ClusterIP "None" Service (ok==false)
		} {
			rcode, addrs, _, _ := respondQuery(t, r, q, dnsmessage.TypeA)
			if rcode != dnsmessage.RCodeNameError {
				t.Fatalf("%s: rcode = %v, want NXDOMAIN", q, rcode)
			}
			if len(addrs) != 0 {
				t.Fatalf("%s: got addrs %v, want none", q, addrs)
			}
		}
		if fwd.callCount() != 0 {
			t.Fatalf("forwarder was invoked %d times for ok==false lookups, want 0 (only Type==ExternalName chases)", fwd.callCount())
		}
	})

	// (e) anti-leak: an ExternalName target INSIDE the cluster domain is NOT forwarded
	// — it is NXDOMAIN, and the forwarder is never asked for it.
	t.Run("in-cluster target NXDOMAIN not forwarded", func(t *testing.T) {
		fwd := &recordingForwarder{}
		zone := mapZone{"prod/loop": {ExternalName: "other.ns2.svc.cluster.local"}}
		r := newClusterResolver(vip, domain, zone, fwd, testLogger())

		rcode, addrs, _, _ := respondQuery(t, r, "loop.prod.svc.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeNameError {
			t.Fatalf("rcode = %v, want NXDOMAIN for an in-cluster-domain ExternalName target", rcode)
		}
		if len(addrs) != 0 {
			t.Fatalf("got addrs %v, want none", addrs)
		}
		if fwd.called("other.ns2.svc.cluster.local") {
			t.Fatalf("forwarder was asked for the in-cluster target (cluster-name leak)")
		}
		if fwd.callCount() != 0 {
			t.Fatalf("forwarder was invoked %d times for an in-cluster target, want 0", fwd.callCount())
		}
	})

	// (f): a TRANSIENT forward error (not a not-found) is SERVFAIL, never a cacheable
	// NXDOMAIN — the shared forward() helper preserves the distinction for the chase.
	t.Run("transient forward error is SERVFAIL", func(t *testing.T) {
		fwd := &recordingForwarder{failWith: &net.DNSError{Err: "server misbehaving", Name: "db.example.com", IsTemporary: true}}
		zone := mapZone{"prod/db": {ExternalName: "db.example.com"}}
		r := newClusterResolver(vip, domain, zone, fwd, testLogger())

		rcode, _, _, _ := respondQuery(t, r, "db.prod.svc.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeServerFailure {
			t.Fatalf("rcode = %v, want SERVFAIL for a transient forward error", rcode)
		}
	})

	// guard: an AAAA query for an ExternalName Service is NODATA (empty NOERROR), never
	// NXDOMAIN — the chase lives inside the A-only guard, and no forward fires.
	t.Run("AAAA ExternalName is NODATA not NXDOMAIN", func(t *testing.T) {
		fwd := &recordingForwarder{answers: map[string][]netip.Addr{
			"db.example.com": {netip.MustParseAddr("203.0.113.7")},
		}}
		zone := mapZone{"prod/db": {ExternalName: "db.example.com"}}
		r := newClusterResolver(vip, domain, zone, fwd, testLogger())

		rcode, addrs, _, _ := respondQuery(t, r, "db.prod.svc.cluster.local", dnsmessage.TypeAAAA)
		if rcode != dnsmessage.RCodeSuccess {
			t.Fatalf("rcode = %v, want NOERROR (NODATA) for an AAAA ExternalName query", rcode)
		}
		if len(addrs) != 0 {
			t.Fatalf("got A addrs %v for an AAAA query, want none", addrs)
		}
		if fwd.callCount() != 0 {
			t.Fatalf("forwarder fired %d times for an AAAA query, want 0 (chase is A-only)", fwd.callCount())
		}
	})
}

// TestServiceZoneBranchesOnType pins the production serviceZone's load-bearing
// branch: it keys off Service TYPE, not an empty ClusterIP (which is overloaded with
// a headless "None" and a pending ClusterIP). An ExternalName Service yields its
// target (trailing dot trimmed); a headless "None", an IPv6 ClusterIP, an empty
// ExternalName, and an absent Service all yield ok==false (NXDOMAIN) — so none is
// mistaken for a forwardable target.
func TestServiceZoneBranchesOnType(t *testing.T) {
	t.Parallel()

	svc := func(name string, spec corev1.ServiceSpec) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: name}, Spec: spec}
	}
	zone := newServiceZone(t, fake.NewClientset(
		svc("ext", corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "db.example.com"}),
		svc("ext-dot", corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "db.example.com."}),
		svc("ext-empty", corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: ""}),
		svc("clusterip", corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.43.0.55"}),
		svc("headless", corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "None"}),
		svc("ipv6", corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "fd00::1"}),
	))

	cases := []struct {
		name        string
		svc         string
		wantOK      bool
		wantIP      string
		wantExtName string
	}{
		{"ExternalName yields target", "ext", true, "", "db.example.com"},
		{"ExternalName trailing dot trimmed", "ext-dot", true, "", "db.example.com"},
		{"ExternalName empty is NXDOMAIN", "ext-empty", false, "", ""},
		{"ClusterIP yields IP", "clusterip", true, "10.43.0.55", ""},
		{"headless None is NXDOMAIN", "headless", false, "", ""},
		{"IPv6 ClusterIP is NXDOMAIN", "ipv6", false, "", ""},
		{"absent is NXDOMAIN", "ghost", false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, ok := zone.LookupService("prod", tc.svc)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if tc.wantExtName != "" {
				if target.ExternalName != tc.wantExtName || target.IP.IsValid() {
					t.Fatalf("target = %+v, want ExternalName %q and no IP", target, tc.wantExtName)
				}
				return
			}
			if got := target.IP.String(); got != tc.wantIP || target.ExternalName != "" {
				t.Fatalf("target = %+v, want IP %q and no ExternalName", target, tc.wantIP)
			}
		})
	}
}

// newServiceZone builds a production serviceZone over Services + EndpointSlices
// listers fed by the fake clientset's objects (informer caches, warmed before
// return), so the real Type-branching LookupService AND the M10.1 record
// synthesis are exercised end to end.
func newServiceZone(t *testing.T, cs *fake.Clientset) serviceZone {
	t.Helper()
	factory := informers.NewSharedInformerFactory(cs, 0)
	z := serviceZone{
		services: factory.Core().V1().Services().Lister(),
		slices:   factory.Discovery().V1().EndpointSlices().Lister(),
		domain:   "cluster.local",
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	return z
}

// respondQuery drives the resolver's pure core (r.respond) for a single query of the
// given type and returns the rcode, the A-record addresses, the owner names those A
// records were stamped under, and the count of CNAME RRs in the answer (to pin the
// CNAME→A flatten: zero).
func respondQuery(t *testing.T, r *clusterResolver, name string, qtype dnsmessage.Type) (dnsmessage.RCode, []netip.Addr, []string, int) {
	t.Helper()
	resp, _, err := r.respond(context.Background(), buildTypedQuery(t, name, qtype))
	if err != nil {
		t.Fatalf("respond(%q): %v", name, err)
	}
	return parseFullResponse(t, resp)
}

// parseFullResponse decodes a DNS response into its rcode, A addresses, the owner
// names of those A records, and the number of CNAME RRs in the answer section.
func parseFullResponse(t *testing.T, resp []byte) (dnsmessage.RCode, []netip.Addr, []string, int) {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatalf("parse response header: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	var addrs []netip.Addr
	var aNames []string
	cnames := 0
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatalf("answer header: %v", err)
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			ar, err := p.AResource()
			if err != nil {
				t.Fatalf("a resource: %v", err)
			}
			addrs = append(addrs, netip.AddrFrom4(ar.A))
			aNames = append(aNames, ah.Name.String())
		case dnsmessage.TypeCNAME:
			cnames++
			if err := p.SkipAnswer(); err != nil {
				t.Fatalf("skip cname: %v", err)
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				t.Fatalf("skip answer: %v", err)
			}
		}
	}
	return hdr.RCode, addrs, aNames, cnames
}

// addrStrings renders addrs as their string forms for comparison.
func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

// TestOversizedUDPResponseTruncatesToTCP asserts the RFC 1035 UDP behavior for a
// non-EDNS (plain, no OPT) query: an answer set too large for a 512-byte plain-UDP
// response is served as header+question with TC set — the whole answer set is
// dropped, never partially packed. RFC 2181 §9 PERMITS partial data, so this
// drop-all is a legal DIVERGENCE from CoreDNS's partial-packing, not a correctness
// edge (registered as an owed alignment row — see the truncateResponse TODO). The
// same query over TCP returns the full set. The client half (TCP refetch on TC)
// lives in darwin-net's resolver and getaddrinfo shim — a CROSS-PR dependency that
// holds only once darwin-net #38 merges, not a present in-tree fact.
func TestOversizedUDPResponseTruncatesToTCP(t *testing.T) {
	t.Parallel()

	// 40 A records ≈ 40×16B of answer sections — comfortably past 512 bytes.
	big := make([]netip.Addr, 0, 40)
	for i := range 40 {
		big = append(big, netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}))
	}
	fwd := mapForwarder{"big.example.com": big}
	r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", mapZone{}, fwd, testLogger())

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	udpDone := make(chan error, 1)
	tcpDone := make(chan error, 1)
	go func() { udpDone <- r.serveUDP(ctx, udp) }()
	go func() { tcpDone <- r.serveTCP(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-udpDone; err != nil {
			t.Errorf("serveUDP returned %v, want nil on clean shutdown", err)
		}
		if err := <-tcpDone; err != nil {
			t.Errorf("serveTCP returned %v, want nil on clean shutdown", err)
		}
	})

	// UDP: TC set, SUCCESS rcode, no answers — never a partial set.
	conn, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(buildAQuery(t, "big.example.com")); err != nil {
		t.Fatalf("write udp query: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read udp response: %v", err)
	}
	if n > maxUDPResponse {
		t.Fatalf("UDP response is %d bytes, want <= %d", n, maxUDPResponse)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(buf[:n])
	if err != nil {
		t.Fatalf("parse udp response: %v", err)
	}
	if !hdr.Truncated {
		t.Fatalf("oversized UDP response has TC unset")
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("truncated response rcode = %v, want success", hdr.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	if _, err := p.AnswerHeader(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		t.Fatalf("truncated response carries answers (err=%v), want none", err)
	}

	// TCP: the full 40-record set.
	rcode, addrs := queryTCP(t, ln.Addr().String(), "big.example.com")
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("tcp rcode = %v, want success", rcode)
	}
	if len(addrs) != len(big) {
		t.Fatalf("tcp answers = %d records, want %d", len(addrs), len(big))
	}
}
