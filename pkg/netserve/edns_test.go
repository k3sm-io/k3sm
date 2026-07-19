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
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"k3sm.io/darwin-net/pkg/dns"
)

// headlessResolver builds a resolver over a single headless (ClusterIP None)
// Service in namespace prod with nEndpoints READY IPv4 backends. With withPort,
// each backend carries a hostname (<svc>-<i>) and the slice a named port pg/tcp,
// so the SRV owner _pg._tcp.<svc>.prod.svc.cluster.local synthesizes one SRV per
// endpoint. The bare <svc>.prod.svc.cluster.local A owner synthesizes the
// all-backends A set — the M10.1 record shapes that drive UDP truncation in
// production (the synthA/synthSRV path, not the forwarder path).
func headlessResolver(t *testing.T, svc string, nEndpoints int, withPort bool) *clusterResolver {
	t.Helper()
	eps := make([]discoveryv1.Endpoint, 0, nEndpoints)
	for i := range nEndpoints {
		ip := netip.AddrFrom4([4]byte{100, 64, byte(i / 256), byte(i % 256)})
		e := discoveryv1.Endpoint{
			Addresses:  []string{ip.String()},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}
		if withPort {
			e.Hostname = ptr.To(fmt.Sprintf("%s-%d", svc, i))
		}
		eps = append(eps, e)
	}
	var ports []discoveryv1.EndpointPort
	if withPort {
		ports = []discoveryv1.EndpointPort{{Name: ptr.To("pg"), Port: ptr.To[int32](5432), Protocol: ptr.To(corev1.ProtocolTCP)}}
	}
	cs := fake.NewClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: svc},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Namespace: "prod", Name: svc + "-1", Labels: map[string]string{discoveryv1.LabelServiceName: svc}},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   eps,
			Ports:       ports,
		},
	)
	zone := newServiceZone(t, cs)
	return newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, &recordingForwarder{}, testLogger())
}

// buildEDNSQuery packs a query of the given type carrying an OPT pseudo-record
// (RFC 6891) that advertises udpSize, EDNS version 0, DO clear.
func buildEDNSQuery(t *testing.T, name string, qtype dnsmessage.Type, udpSize uint16) []byte {
	t.Helper()
	return buildEDNSQueryV(t, name, qtype, udpSize, 0, false)
}

// buildEDNSQueryV packs a query with a fully specified OPT: advertised UDP size,
// EDNS version, and DO bit — so a test can drive the version>0 (BADVERS) and
// DO-echo paths.
func buildEDNSQueryV(t *testing.T, name string, qtype dnsmessage.Type, udpSize uint16, version uint8, do bool) []byte {
	t.Helper()
	if name == "" || name[len(name)-1] != '.' {
		name += "."
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("question: %v", err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatalf("start additionals: %v", err)
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(int(udpSize), dnsmessage.RCodeSuccess, do); err != nil {
		t.Fatalf("set query OPT: %v", err)
	}
	opt.TTL |= uint32(version) << 16 // EDNS version lives in the TTL's second byte
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		t.Fatalf("write query OPT: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("finish query: %v", err)
	}
	return msg
}

// dnsResp is the parsed shape of a response the EDNS tests assert against.
type dnsResp struct {
	rcode    dnsmessage.RCode
	opCode   dnsmessage.OpCode
	tc       bool
	rd       bool
	aCount   int
	srvCount int
	hasOPT   bool
	optSize  uint16
	optVer   uint8
	optDO    bool
	extRCode dnsmessage.RCode
}

// parseDNSResp decodes a response into its header flags, answer-type counts, and
// (if present) its OPT pseudo-record fields.
func parseDNSResp(t *testing.T, msg []byte) dnsResp {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		t.Fatalf("parse response header: %v", err)
	}
	out := dnsResp{rcode: hdr.RCode, opCode: hdr.OpCode, tc: hdr.Truncated, rd: hdr.RecursionDesired}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
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
			out.aCount++
		case dnsmessage.TypeSRV:
			out.srvCount++
		}
		if err := p.SkipAnswer(); err != nil {
			t.Fatalf("skip answer: %v", err)
		}
	}
	if err := p.SkipAllAuthorities(); err != nil {
		t.Fatalf("skip authorities: %v", err)
	}
	for {
		ah, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatalf("additional header: %v", err)
		}
		if ah.Type == dnsmessage.TypeOPT {
			out.hasOPT = true
			out.optSize = uint16(ah.Class)
			out.optVer = uint8(ah.TTL >> 16)
			out.optDO = ah.DNSSECAllowed()
			out.extRCode = ah.ExtendedRCode(hdr.RCode)
		}
		if err := p.SkipAdditional(); err != nil {
			t.Fatalf("skip additional: %v", err)
		}
	}
	return out
}

// udpExchange sends query to a UDP DNS server and returns the raw response
// datagram (up to 2048 bytes, enough for a 1232-byte EDNS response).
func udpExchange(t *testing.T, server string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatalf("dial udp %s: %v", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write udp query: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read udp response: %v", err)
	}
	return buf[:n]
}

// serveResolverUDP starts serveUDP on a fresh loopback socket and returns its
// address, draining the server on cleanup.
func serveResolverUDP(t *testing.T, r *clusterResolver) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.serveUDP(ctx, pc) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serveUDP returned %v, want nil on clean shutdown", err)
		}
	})
	return pc.LocalAddr().String()
}

// TestEDNSHonorsAdvertisedUDPSize is the core M10.1/EDNS0 proof over the headless
// SYNTHESIS path (synthA, not the forwarder): a headless Service's all-backends A
// set that overflows the 512 floor is TRUNCATED for a non-EDNS client but served
// WHOLE, over UDP with no TC, to an EDNS client advertising dns.EDNSUDPPayloadSize
// — and the response carries a well-formed OPT whose datagram (OPT included) never
// exceeds the advertised size.
func TestEDNSHonorsAdvertisedUDPSize(t *testing.T) {
	t.Parallel()
	const svc = "big"
	const n = 60 // >512-byte A set, comfortably under 1232
	r := headlessResolver(t, svc, n, false)
	addr := serveResolverUDP(t, r)
	qname := svc + ".prod.svc.cluster.local"

	// Non-EDNS client: still capped at 512 → TC, no answers, no OPT.
	plain := parseDNSResp(t, udpExchange(t, addr, buildAQuery(t, qname)))
	if !plain.tc {
		t.Fatalf("non-EDNS oversized response has TC unset")
	}
	if plain.aCount != 0 {
		t.Fatalf("non-EDNS truncated response carries %d A records, want 0", plain.aCount)
	}
	if plain.hasOPT {
		t.Fatalf("non-EDNS response carries an OPT, want none (plain DNS)")
	}

	// EDNS client advertising 1232: the whole set over UDP, no TC, well-formed OPT.
	raw := udpExchange(t, addr, buildEDNSQuery(t, qname, dnsmessage.TypeA, dns.EDNSUDPPayloadSize))
	if len(raw) > dns.EDNSUDPPayloadSize {
		t.Fatalf("EDNS datagram is %d bytes, want <= %d (advertised)", len(raw), dns.EDNSUDPPayloadSize)
	}
	got := parseDNSResp(t, raw)
	if got.tc {
		t.Fatalf("EDNS response TC set, want the full set served over UDP")
	}
	if got.aCount != n {
		t.Fatalf("EDNS response carries %d A records, want %d (the whole synthesized set)", got.aCount, n)
	}
	if !got.hasOPT {
		t.Fatalf("EDNS response carries no OPT, want a well-formed one (RFC 6891 §6.1.1)")
	}
	if got.optSize != dns.EDNSUDPPayloadSize {
		t.Fatalf("response OPT advertises %d, want dns.EDNSUDPPayloadSize (%d)", got.optSize, dns.EDNSUDPPayloadSize)
	}
	if got.optVer != 0 {
		t.Fatalf("response OPT version = %d, want 0", got.optVer)
	}
	if got.optDO {
		t.Fatalf("response OPT DO bit set, want clear (query did not set DO)")
	}
	if got.extRCode != dnsmessage.RCodeSuccess {
		t.Fatalf("response extended RCODE = %v, want NOERROR", got.extRCode)
	}
}

// TestUDPTruncationBoundary pins the guard operator (`>`, not `>=`, in serveUDP):
// a response of EXACTLY the negotiated size is served un-truncated, one byte over
// is truncated. It drives both the non-EDNS 512 floor and an exact EDNS boundary
// measured from a real synthesized response.
func TestUDPTruncationBoundary(t *testing.T) {
	t.Parallel()

	// Non-EDNS floor: a small A set fits under 512 → not truncated.
	t.Run("non-EDNS small set fits", func(t *testing.T) {
		t.Parallel()
		r := headlessResolver(t, "small", 5, false)
		addr := serveResolverUDP(t, r)
		got := parseDNSResp(t, udpExchange(t, addr, buildAQuery(t, "small.prod.svc.cluster.local")))
		if got.tc {
			t.Fatalf("5-record response TC set, want it to fit under 512")
		}
		if got.aCount != 5 {
			t.Fatalf("response carries %d A records, want 5", got.aCount)
		}
	})

	// EDNS exact boundary: measure the full response length L (with its OPT), then
	// advertise exactly L → not truncated (len == negotiated, `>` is false); and
	// advertise L-1 → truncated (len > negotiated).
	t.Run("EDNS exact size not truncated, one under truncates", func(t *testing.T) {
		t.Parallel()
		const svc = "boundary"
		const n = 60
		r := headlessResolver(t, svc, n, false)
		qname := svc + ".prod.svc.cluster.local"

		full, negotiated, err := r.respond(context.Background(), buildEDNSQuery(t, qname, dnsmessage.TypeA, dns.EDNSUDPPayloadSize))
		if err != nil {
			t.Fatalf("respond: %v", err)
		}
		if negotiated != dns.EDNSUDPPayloadSize {
			t.Fatalf("negotiated = %d, want %d", negotiated, dns.EDNSUDPPayloadSize)
		}
		l := len(full)
		if l <= maxUDPResponse || l > dns.EDNSUDPPayloadSize {
			t.Fatalf("measured response is %d bytes; want in (%d, %d] — adjust n", l, maxUDPResponse, dns.EDNSUDPPayloadSize)
		}

		addr := serveResolverUDP(t, r)

		// Advertise exactly L: len(resp) == negotiated, so `>` is false → full set.
		exact := udpExchange(t, addr, buildEDNSQuery(t, qname, dnsmessage.TypeA, uint16(l)))
		if len(exact) != l {
			t.Fatalf("exact-boundary datagram is %d bytes, want %d", len(exact), l)
		}
		if r := parseDNSResp(t, exact); r.tc || r.aCount != n {
			t.Fatalf("exact-boundary response tc=%v aCount=%d, want tc=false aCount=%d (== negotiated must NOT truncate)", r.tc, r.aCount, n)
		}

		// Advertise L-1: len(resp) > negotiated → truncated, still ≤ advertised.
		under := udpExchange(t, addr, buildEDNSQuery(t, qname, dnsmessage.TypeA, uint16(l-1)))
		if len(under) > l-1 {
			t.Fatalf("truncated datagram is %d bytes, want <= %d (advertised)", len(under), l-1)
		}
		ur := parseDNSResp(t, under)
		if !ur.tc {
			t.Fatalf("one-under-boundary response has TC unset, want truncated")
		}
		if ur.aCount != 0 {
			t.Fatalf("truncated response carries %d A records, want 0 (drop-all)", ur.aCount)
		}
		if !ur.hasOPT {
			t.Fatalf("truncated EDNS response dropped its OPT, want it preserved (RFC 6891 §6.2.3)")
		}
		if ur.optSize != dns.EDNSUDPPayloadSize {
			t.Fatalf("truncated response OPT advertises %d, want %d", ur.optSize, dns.EDNSUDPPayloadSize)
		}
	})

	// Floor clamp: an OPT advertising below 512 is clamped up to 512, so an A set
	// over 512 still truncates for such a client.
	t.Run("advertised below 512 clamps to 512", func(t *testing.T) {
		t.Parallel()
		r := headlessResolver(t, "clamp", 60, false)
		addr := serveResolverUDP(t, r)
		raw := udpExchange(t, addr, buildEDNSQuery(t, "clamp.prod.svc.cluster.local", dnsmessage.TypeA, 300))
		if len(raw) > maxUDPResponse {
			t.Fatalf("clamped datagram is %d bytes, want <= %d (floor)", len(raw), maxUDPResponse)
		}
		if got := parseDNSResp(t, raw); !got.tc {
			t.Fatalf("sub-512 advertised size did not clamp to 512: response not truncated")
		}
	})
}

// TestEDNSLargeHeadlessSRVSet proves EDNS negotiation delivers the k8s-DNS-spec
// SRV expectation: a StatefulSet-shaped headless SRV set that overflows 512
// (SRV RDATA is several× an A record, so it crosses the floor at far fewer
// endpoints) is truncated for a non-EDNS client but served whole under 1232.
func TestEDNSLargeHeadlessSRVSet(t *testing.T) {
	t.Parallel()
	const svc = "sset"
	const n = 15 // SRV set > 512 bytes, still < 1232
	r := headlessResolver(t, svc, n, true)
	srvName := "_pg._tcp." + svc + ".prod.svc.cluster.local"

	full, _, err := r.respond(context.Background(), buildEDNSQuery(t, srvName, dnsmessage.TypeSRV, dns.EDNSUDPPayloadSize))
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	if l := len(full); l <= maxUDPResponse || l > dns.EDNSUDPPayloadSize {
		t.Fatalf("SRV set is %d bytes; want in (%d, %d] — adjust n", l, maxUDPResponse, dns.EDNSUDPPayloadSize)
	}

	addr := serveResolverUDP(t, r)

	// Non-EDNS: the SRV set overflows 512 → TC, no answers.
	plain := parseDNSResp(t, udpExchange(t, addr, buildTypedQuery(t, srvName, dnsmessage.TypeSRV)))
	if !plain.tc {
		t.Fatalf("non-EDNS SRV response has TC unset, want truncated (SRV set > 512)")
	}
	if plain.srvCount != 0 {
		t.Fatalf("non-EDNS truncated response carries %d SRV records, want 0", plain.srvCount)
	}

	// EDNS 1232: the whole SRV set over UDP, no TC.
	raw := udpExchange(t, addr, buildEDNSQuery(t, srvName, dnsmessage.TypeSRV, dns.EDNSUDPPayloadSize))
	if len(raw) > dns.EDNSUDPPayloadSize {
		t.Fatalf("EDNS SRV datagram is %d bytes, want <= %d", len(raw), dns.EDNSUDPPayloadSize)
	}
	got := parseDNSResp(t, raw)
	if got.tc {
		t.Fatalf("EDNS SRV response TC set, want the full set over UDP")
	}
	if got.srvCount != n {
		t.Fatalf("EDNS SRV response carries %d records, want %d (one per ready endpoint)", got.srvCount, n)
	}
	if !got.hasOPT || got.optSize != dns.EDNSUDPPayloadSize {
		t.Fatalf("EDNS SRV response OPT = {present:%v size:%d}, want {true %d}", got.hasOPT, got.optSize, dns.EDNSUDPPayloadSize)
	}
}

// TestEDNSResponseSemantics pins the response OPT + opcode/version guards:
// the DO bit is echoed only when the query set it; an EDNS version > 0 gets
// BADVERS (extended RCODE 16) with an OPT and no answers; a non-Query opcode gets
// NOTIMP with the opcode echoed and no answers; and RD is echoed from the query.
func TestEDNSResponseSemantics(t *testing.T) {
	t.Parallel()
	zone := mapZone{"default/web": {IP: netip.MustParseAddr("10.43.0.55")}}
	r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, mapForwarder{}, testLogger())
	const qname = "web.default.svc.cluster.local"

	t.Run("DO echoed only when queried", func(t *testing.T) {
		t.Parallel()
		for _, do := range []bool{true, false} {
			resp, _, err := r.respond(context.Background(), buildEDNSQueryV(t, qname, dnsmessage.TypeA, dns.EDNSUDPPayloadSize, 0, do))
			if err != nil {
				t.Fatalf("respond: %v", err)
			}
			got := parseDNSResp(t, resp)
			if !got.hasOPT {
				t.Fatalf("do=%v: response carries no OPT", do)
			}
			if got.optDO != do {
				t.Fatalf("do=%v: response OPT DO = %v, want %v (echo only when queried)", do, got.optDO, do)
			}
			if got.aCount != 1 {
				t.Fatalf("do=%v: response carries %d A records, want 1", do, got.aCount)
			}
		}
	})

	t.Run("EDNS version > 0 is BADVERS", func(t *testing.T) {
		t.Parallel()
		resp, _, err := r.respond(context.Background(), buildEDNSQueryV(t, qname, dnsmessage.TypeA, dns.EDNSUDPPayloadSize, 1, false))
		if err != nil {
			t.Fatalf("respond: %v", err)
		}
		got := parseDNSResp(t, resp)
		if !got.hasOPT {
			t.Fatalf("BADVERS response carries no OPT, want our OPT (RFC 6891 §6.1.3)")
		}
		if got.extRCode != ednsBADVERS {
			t.Fatalf("extended RCODE = %d, want BADVERS (%d)", got.extRCode, ednsBADVERS)
		}
		if got.aCount != 0 {
			t.Fatalf("BADVERS response carries %d A records, want 0", got.aCount)
		}
	})

	t.Run("non-Query opcode is NOTIMP with opcode echoed", func(t *testing.T) {
		t.Parallel()
		const opUpdate dnsmessage.OpCode = 5
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, OpCode: opUpdate, RecursionDesired: true})
		if err := b.StartQuestions(); err != nil {
			t.Fatalf("start questions: %v", err)
		}
		if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(qname + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
			t.Fatalf("question: %v", err)
		}
		query, err := b.Finish()
		if err != nil {
			t.Fatalf("finish query: %v", err)
		}
		resp, _, err := r.respond(context.Background(), query)
		if err != nil {
			t.Fatalf("respond: %v", err)
		}
		got := parseDNSResp(t, resp)
		if got.rcode != dnsmessage.RCodeNotImplemented {
			t.Fatalf("rcode = %v, want NOTIMP for a non-Query opcode", got.rcode)
		}
		if got.opCode != opUpdate {
			t.Fatalf("response opcode = %d, want %d echoed", got.opCode, opUpdate)
		}
		if got.aCount != 0 {
			t.Fatalf("NOTIMP response carries %d A records, want 0 (no Query semantics)", got.aCount)
		}
	})

	t.Run("RD echoed from query", func(t *testing.T) {
		t.Parallel()
		// buildAQuery sets RecursionDesired: true.
		got := parseDNSResp(t, mustRespond(t, r, buildAQuery(t, qname)))
		if !got.rd {
			t.Fatalf("RD = false, want it echoed from the RD-set query")
		}
	})
}

// mustRespond drives r.respond and fails on error, returning the response bytes.
func mustRespond(t *testing.T, r *clusterResolver, query []byte) []byte {
	t.Helper()
	resp, _, err := r.respond(context.Background(), query)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	return resp
}

// TestTCPOversizedResponseServfail pins the 65535 TCP guard: a response larger
// than a uint16 length prefix can frame is replaced by a minimal SERVFAIL rather
// than wrapping the prefix into a corrupt frame (RFC 1035 §4.2.2).
func TestTCPOversizedResponseServfail(t *testing.T) {
	t.Parallel()

	// A direct unit test of servfailResponse: it echoes the question + RD, carries
	// no answers, and reports SERVFAIL.
	t.Run("servfailResponse is a minimal SERVFAIL", func(t *testing.T) {
		t.Parallel()
		out, err := servfailResponse(buildAQuery(t, "big.example.com"))
		if err != nil {
			t.Fatalf("servfailResponse: %v", err)
		}
		got := parseDNSResp(t, out)
		if got.rcode != dnsmessage.RCodeServerFailure {
			t.Fatalf("rcode = %v, want SERVFAIL", got.rcode)
		}
		if got.aCount != 0 {
			t.Fatalf("SERVFAIL carries %d A records, want 0", got.aCount)
		}
		if !got.rd {
			t.Fatalf("SERVFAIL dropped RD, want it echoed")
		}
	})

	// The TCP path guard end to end: a forwarder answer set large enough to build a
	// >65535-byte response makes handleTCPConn emit SERVFAIL, not a wrapped frame.
	t.Run("over 65535 bytes over TCP is SERVFAIL", func(t *testing.T) {
		t.Parallel()
		// ~5000 A records × ~16 B ≈ 80 KB, past the 65535 uint16 ceiling.
		big := make([]netip.Addr, 0, 5000)
		for i := range 5000 {
			big = append(big, netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
		}
		fwd := mapForwarder{"huge.example.com": big}
		r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", mapZone{}, fwd, testLogger())

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- r.serveTCP(ctx, ln) }()
		t.Cleanup(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("serveTCP returned %v, want nil on clean shutdown", err)
			}
		})

		rcode, addrs := queryTCP(t, ln.Addr().String(), "huge.example.com")
		if rcode != dnsmessage.RCodeServerFailure {
			t.Fatalf("rcode = %v, want SERVFAIL for a >65535-byte response", rcode)
		}
		if len(addrs) != 0 {
			t.Fatalf("SERVFAIL carries %d A records, want 0", len(addrs))
		}
	})
}
