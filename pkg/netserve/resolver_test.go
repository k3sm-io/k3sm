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
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mapZone is a fake cluster Service zone (key "ns/name" → ClusterIP).
type mapZone map[string]netip.Addr

func (z mapZone) LookupService(namespace, name string) (netip.Addr, bool) {
	a, ok := z[namespace+"/"+name]
	return a, ok
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
		"default/kubernetes": netip.MustParseAddr("10.43.0.1"),  // the API VIP, node-local
		"default/web":        netip.MustParseAddr("10.43.0.55"), // a normal ClusterIP
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
	if name == "" || name[len(name)-1] != '.' {
		name += "."
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeA,
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
