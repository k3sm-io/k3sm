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
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

// identityFixture builds the M10.1 identity-record cluster: a headless
// StatefulSet-shaped Service (db, ClusterIP None, named port pg/5432) with two
// READY hostname-carrying endpoints + one NOT-ready one, a headless Service
// publishing not-ready addresses, and a normal ClusterIP Service (web) for the
// VIP PTR leg.
func identityFixture(t *testing.T) (*clusterResolver, *recordingForwarder) {
	t.Helper()
	slice := func(name, svc string, eps []discoveryv1.Endpoint, ports []discoveryv1.EndpointPort) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Namespace: "prod", Name: name, Labels: map[string]string{discoveryv1.LabelServiceName: svc}},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   eps,
			Ports:       ports,
		}
	}
	ep := func(ip, hostname string, ready bool) discoveryv1.Endpoint {
		e := discoveryv1.Endpoint{Addresses: []string{ip}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(ready)}}
		if hostname != "" {
			e.Hostname = ptr.To(hostname)
		}
		return e
	}
	pgPort := []discoveryv1.EndpointPort{{Name: ptr.To("pg"), Port: ptr.To[int32](5432), Protocol: ptr.To(corev1.ProtocolTCP)}}

	cs := fake.NewClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db-all"},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone,
				PublishNotReadyAddresses: true,
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web"},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.43.0.55",
				Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
			},
		},
		slice("db-1", "db", []discoveryv1.Endpoint{
			ep("100.64.0.10", "db-0", true),
			ep("100.64.0.11", "db-1", true),
			ep("100.64.0.12", "db-2", false), // not ready → excluded
		}, pgPort),
		slice("db-all-1", "db-all", []discoveryv1.Endpoint{
			ep("100.64.0.20", "", false), // not ready but PUBLISHED (dashed-IP identity)
		}, nil),
	)
	zone := newServiceZone(t, cs)
	fwd := &recordingForwarder{}
	return newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, fwd, testLogger()), fwd
}

// srvAnswer is one parsed SRV RR (target normalized, no trailing dot).
type srvAnswer struct {
	target string
	port   uint16
}

// respondTyped drives respond and returns the rcode plus the parsed A, SRV, and
// PTR answers.
func respondTyped(t *testing.T, r *clusterResolver, name string, qtype dnsmessage.Type) (dnsmessage.RCode, []netip.Addr, []srvAnswer, []string) {
	t.Helper()
	resp, _, err := r.respond(context.Background(), buildTypedQuery(t, name, qtype))
	if err != nil {
		t.Fatalf("respond(%q): %v", name, err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatalf("parse response header: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	var addrs []netip.Addr
	var srvs []srvAnswer
	var ptrs []string
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
		case dnsmessage.TypeSRV:
			sr, err := p.SRVResource()
			if err != nil {
				t.Fatalf("srv resource: %v", err)
			}
			srvs = append(srvs, srvAnswer{target: normalizeDNSName(sr.Target.String()), port: sr.Port})
		case dnsmessage.TypePTR:
			pr, err := p.PTRResource()
			if err != nil {
				t.Fatalf("ptr resource: %v", err)
			}
			ptrs = append(ptrs, normalizeDNSName(pr.PTR.String()))
		default:
			if err := p.SkipAnswer(); err != nil {
				t.Fatalf("skip answer: %v", err)
			}
		}
	}
	return hdr.RCode, addrs, srvs, ptrs
}

// TestHeadlessServiceReturnsAllPodIPs is the M10.1-a1 server-side DNS-identity
// gate (Res.1): the per-node resolver serves the record surface darwin-net's
// dns.Synthesize builds from the Services + EndpointSlices listers — the
// headless all-ready-backends A set (readiness-filtered), the StatefulSet
// hostname identity A record, one SRV per endpoint under the named port, the
// AUTHORITATIVE in-addr.arpa reverse zone (PTR hit or NXDOMAIN, never an
// upstream forward for an in-CIDR reverse name), the publishNotReadyAddresses
// override, and the stateless <dashed-ip>.<ns>.pod.<domain> decode.
//
// Fails-before: every one of these names was NXDOMAIN (the documented pre-M10.1
// divergence); passes-after with the synthesis wired.
func TestHeadlessServiceReturnsAllPodIPs(t *testing.T) {
	t.Parallel()
	r, fwd := identityFixture(t)

	t.Run("headless A answers every READY backend pod IP", func(t *testing.T) {
		rcode, addrs, _, _ := respondTyped(t, r, "db.prod.svc.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeSuccess {
			t.Fatalf("rcode = %v, want NOERROR", rcode)
		}
		got := addrStrings(addrs)
		slices.Sort(got)
		want := []string{"100.64.0.10", "100.64.0.11"}
		if !equalStrings(got, want) {
			t.Fatalf("headless A = %v, want %v (all ready backends, not-ready excluded)", got, want)
		}
	})

	t.Run("hostname identity record answers the pod's /32", func(t *testing.T) {
		rcode, addrs, _, _ := respondTyped(t, r, "db-0.db.prod.svc.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeSuccess {
			t.Fatalf("rcode = %v, want NOERROR", rcode)
		}
		if got := addrStrings(addrs); !equalStrings(got, []string{"100.64.0.10"}) {
			t.Fatalf("identity A = %v, want [100.64.0.10]", got)
		}
	})

	t.Run("SRV answers one record per ready endpoint with resolvable targets", func(t *testing.T) {
		rcode, _, srvs, _ := respondTyped(t, r, "_pg._tcp.db.prod.svc.cluster.local", dnsmessage.TypeSRV)
		if rcode != dnsmessage.RCodeSuccess {
			t.Fatalf("rcode = %v, want NOERROR", rcode)
		}
		if len(srvs) != 2 {
			t.Fatalf("SRV answers = %v, want 2 (one per ready endpoint)", srvs)
		}
		var targets []string
		for _, s := range srvs {
			if s.port != 5432 {
				t.Errorf("SRV port = %d, want 5432", s.port)
			}
			targets = append(targets, s.target)
			// Every SRV target is itself resolvable as an A record.
			trc, taddrs, _, _ := respondTyped(t, r, s.target, dnsmessage.TypeA)
			if trc != dnsmessage.RCodeSuccess || len(taddrs) != 1 {
				t.Errorf("SRV target %q A lookup = (%v, %v), want one address", s.target, trc, taddrs)
			}
		}
		slices.Sort(targets)
		want := []string{"db-0.db.prod.svc.cluster.local", "db-1.db.prod.svc.cluster.local"}
		if !equalStrings(targets, want) {
			t.Fatalf("SRV targets = %v, want %v", targets, want)
		}
	})

	t.Run("PTR is authoritative for pod and service CIDR reverse names", func(t *testing.T) {
		// Pod-IP hit → the endpoint's identity name.
		rcode, _, _, ptrs := respondTyped(t, r, "10.0.64.100.in-addr.arpa", dnsmessage.TypePTR)
		if rcode != dnsmessage.RCodeSuccess || !equalStrings(ptrs, []string{"db-0.db.prod.svc.cluster.local"}) {
			t.Fatalf("pod PTR = (%v, %v), want (NOERROR, [db-0.db.prod.svc.cluster.local])", rcode, ptrs)
		}
		// Service-VIP hit → the service name.
		rcode, _, _, ptrs = respondTyped(t, r, "55.0.43.10.in-addr.arpa", dnsmessage.TypePTR)
		if rcode != dnsmessage.RCodeSuccess || !equalStrings(ptrs, []string{"web.prod.svc.cluster.local"}) {
			t.Fatalf("VIP PTR = (%v, %v), want (NOERROR, [web.prod.svc.cluster.local])", rcode, ptrs)
		}
		// An in-CIDR miss is NXDOMAIN — answered locally, NEVER forwarded upstream.
		rcode, _, _, ptrs = respondTyped(t, r, "99.0.64.100.in-addr.arpa", dnsmessage.TypePTR)
		if rcode != dnsmessage.RCodeNameError || len(ptrs) != 0 {
			t.Fatalf("unknown in-CIDR PTR = (%v, %v), want (NXDOMAIN, none)", rcode, ptrs)
		}
		if n := fwd.callCount(); n != 0 {
			t.Fatalf("forwarder fired %d times for in-CIDR reverse names, want 0 (authoritative)", n)
		}
	})

	t.Run("publishNotReadyAddresses includes not-ready endpoints", func(t *testing.T) {
		rcode, addrs, _, _ := respondTyped(t, r, "db-all.prod.svc.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeSuccess {
			t.Fatalf("rcode = %v, want NOERROR", rcode)
		}
		if got := addrStrings(addrs); !equalStrings(got, []string{"100.64.0.20"}) {
			t.Fatalf("publishNotReady A = %v, want [100.64.0.20]", got)
		}
	})

	t.Run("dashed-ip pod name decodes statelessly", func(t *testing.T) {
		rcode, addrs, _, _ := respondTyped(t, r, "100-64-0-33.prod.pod.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeSuccess || !equalStrings(addrStrings(addrs), []string{"100.64.0.33"}) {
			t.Fatalf("pod A = (%v, %v), want (NOERROR, [100.64.0.33])", rcode, addrStrings(addrs))
		}
		rcode, addrs, _, _ = respondTyped(t, r, "not-an-ip.prod.pod.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeNameError || len(addrs) != 0 {
			t.Fatalf("malformed pod name = (%v, %v), want (NXDOMAIN, none)", rcode, addrs)
		}
	})

	t.Run("existing VIP behavior intact", func(t *testing.T) {
		rcode, addrs, _, _ := respondTyped(t, r, "web.prod.svc.cluster.local", dnsmessage.TypeA)
		if rcode != dnsmessage.RCodeSuccess || !equalStrings(addrStrings(addrs), []string{"10.43.0.55"}) {
			t.Fatalf("VIP A = (%v, %v), want (NOERROR, [10.43.0.55])", rcode, addrStrings(addrs))
		}
	})
}
