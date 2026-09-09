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
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

// r.respond is the per-QUERY core of the cluster resolver: every DNS lookup from
// every Pod on the node lands here (serveUDP at resolver.go:223 hands it one
// datagram; serveTCP the same per message). It is the hottest path in k3sm, and
// until these benchmarks existed nothing in the repo measured it — the tree
// carried zero benchmarks, so every allocation claim about this path was
// unfalsifiable.
//
// These are BASELINE measurements, deliberately landed before any optimisation,
// so a later change is judged against a recorded number rather than a memory of
// one. Read them with -benchmem; allocs/op is the figure that matters, not ns/op:
// the resolver is not CPU-bound, it is GC-pressure-bound at Pod-density scale.
//
// Each benchmark names the real query shape it models, because the shapes differ
// by an order of magnitude in cost and an average over them would be a number
// describing no actual workload.

// benchResolver builds a resolver over the fake mapZone — the A/VIP-only
// posture (no identitySource), which is the cheapest cluster path and therefore
// the cleanest floor to measure the parse+build cost against.
func benchResolver() *clusterResolver {
	zone := mapZone{
		"default/kubernetes": {IP: netip.MustParseAddr("10.43.0.1")},
		"prod/web":           {IP: netip.MustParseAddr("10.43.0.55")},
		"prod/ext":           {ExternalName: "example.internal"},
	}
	fwd := mapForwarder{
		"example.internal": {netip.MustParseAddr("93.184.216.34")},
		"off.example.com":  {netip.MustParseAddr("93.184.216.34")},
	}
	return newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, fwd, testLogger())
}

// benchRespond is the shared driver: it pins the response as consumed so the
// compiler cannot elide the work, and fails loudly if the query shape stops
// answering — a benchmark measuring an error path is measuring nothing.
func benchRespond(b *testing.B, r *clusterResolver, query []byte) {
	b.Helper()
	ctx := context.Background()
	// Prove the shape answers BEFORE the timed loop, so a silent regression to an
	// error return cannot masquerade as an optimisation.
	if _, _, err := r.respond(ctx, query); err != nil {
		b.Fatalf("respond: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	var sink int
	for range b.N {
		resp, _, err := r.respond(ctx, query)
		if err != nil {
			b.Fatalf("respond: %v", err)
		}
		sink += len(resp)
	}
	b.StopTimer()
	if sink == 0 {
		b.Fatal("every response was empty; the benchmark measured nothing")
	}
}

// BenchmarkRespondClusterA is the dominant real query: a Pod resolving an
// in-cluster Service to its ClusterIP. This is the number to beat.
func BenchmarkRespondClusterA(b *testing.B) {
	benchRespond(b, benchResolver(), buildAQuery(b, "web.prod.svc.cluster.local"))
}

// BenchmarkRespondClusterA_EDNS is the same query carrying a client OPT, which
// is what a modern resolver actually sends. It is separated from the plain case
// because the EDNS branch runs findOPT (resolver.go:504), which starts a SECOND
// dnsmessage.Parser at byte 0 and re-walks every section of a message respond
// has already parsed — the delta between this and BenchmarkRespondClusterA is
// the cost of that second pass.
func BenchmarkRespondClusterA_EDNS(b *testing.B) {
	benchRespond(b, benchResolver(), buildEDNSQuery(b, "web.prod.svc.cluster.local", dnsmessage.TypeA, 1232))
}

// BenchmarkRespondNXDOMAIN pins the miss path: an in-zone name with no Service.
// Misses are common (a search-list walk issues several per successful lookup),
// so a miss that costs more than a hit is a real workload problem.
func BenchmarkRespondNXDOMAIN(b *testing.B) {
	benchRespond(b, benchResolver(), buildAQuery(b, "absent.prod.svc.cluster.local"))
}

// BenchmarkRespondOffCluster is the forwarded path — an off-cluster name handed
// to the upstream. The forwarder here is a map, so this measures k3sm's own
// per-query cost around the forward and NOT the upstream's latency.
func BenchmarkRespondOffCluster(b *testing.B) {
	benchRespond(b, benchResolver(), buildAQuery(b, "off.example.com"))
}

// BenchmarkRespondSearchListMiss models what the in-Pod resolv.conf search list
// actually generates: the ndots walk appends each search domain in turn, so a
// single `curl web` becomes several queries for names that do not exist in the
// cluster zone at all. This is the shape a Pod emits most often in aggregate.
func BenchmarkRespondSearchListMiss(b *testing.B) {
	benchRespond(b, benchResolver(), buildAQuery(b, "web.svc.cluster.local"))
}

// The identity/synthesis posture — the REAL serviceZone over informer listers,
// which is what production runs. mapZone above cannot reach synthA, SRV
// synthesis, or LookupPTR, so those paths need the production zone to be
// measured at all.
func benchIdentityResolver(b *testing.B) *clusterResolver {
	b.Helper()
	pgPort := []discoveryv1.EndpointPort{{
		Name: ptr.To("pg"), Port: ptr.To[int32](5432), Protocol: ptr.To(corev1.ProtocolTCP),
	}}
	cs := fake.NewClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web"},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.43.0.55",
				Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
			},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "prod", Name: "db-1",
				Labels: map[string]string{discoveryv1.LabelServiceName: "db"},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				benchEndpoint("100.64.0.10", "db-0"),
				benchEndpoint("100.64.0.11", "db-1"),
				benchEndpoint("100.64.0.12", "db-2"),
			},
			Ports: pgPort,
		},
	)
	return newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local",
		newServiceZone(b, cs), mapForwarder{}, testLogger())
}

// BenchmarkRespondHeadlessA is the headless all-backends synthesis: one query
// fans out to every ready endpoint, so its cost scales with backend count.
func BenchmarkRespondHeadlessA(b *testing.B) {
	benchRespond(b, benchIdentityResolver(b), buildAQuery(b, "db.prod.svc.cluster.local"))
}

// BenchmarkRespondReversePTR is the one the code itself calls out as a
// tradeoff: LookupPTR (resolver.go:940) has no reverse index, so it Lists EVERY
// Service and synthesizes each one's full RecordSet to find a single PTR
// target. The comment justifies it with "PTR queries are rare and the Service
// set is dev-scale" — this benchmark is what makes that claim falsifiable
// rather than asserted, and it is the per-query cost that would be paid if the
// premise is ever wrong.
func BenchmarkRespondReversePTR(b *testing.B) {
	benchRespond(b, benchIdentityResolver(b),
		buildTypedQuery(b, "10.0.64.100.in-addr.arpa", dnsmessage.TypePTR))
}

// BenchmarkFindOPT isolates the second parse from everything around it, so the
// double-parse cost is attributable on its own rather than inferred from a
// delta between two larger benchmarks.
func BenchmarkFindOPT(b *testing.B) {
	query := buildEDNSQuery(b, "web.prod.svc.cluster.local", dnsmessage.TypeA, 1232)
	if _, ok := findOPT(query); !ok {
		b.Fatal("findOPT found no OPT in an EDNS query; the benchmark models nothing")
	}
	b.ReportAllocs()
	b.ResetTimer()
	var found int
	for range b.N {
		if _, ok := findOPT(query); ok {
			found++
		}
	}
	b.StopTimer()
	if found != b.N {
		b.Fatalf("findOPT hit %d of %d iterations", found, b.N)
	}
}

// BenchmarkNormalizeDNSName isolates the qname normalisation respond does on
// every single query, whatever the shape.
func BenchmarkNormalizeDNSName(b *testing.B) {
	const name = "web.prod.svc.cluster.local."
	b.ReportAllocs()
	var n int
	for range b.N {
		n += len(normalizeDNSName(name))
	}
	if n == 0 {
		b.Fatal("normalizeDNSName returned only empty strings")
	}
}

// benchEndpoint is a ready IPv4 endpoint with a hostname — the shape headless
// identity synthesis consumes. identity_test.go's equivalent is a local closure
// inside identityFixture and so cannot be reused from here.
func benchEndpoint(ip, hostname string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Hostname:   ptr.To(hostname),
		Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
	}
}

// The PTR path's justification in LookupPTR (resolver.go:940) rests on two
// premises: that "PTR queries are rare" and that "the Service set is
// dev-scale". The second is measurable, and a documented assumption nobody has
// measured is exactly the kind that goes quietly wrong — so this pins the
// SHAPE of the curve, not just one point on it.
//
// LookupPTR keeps no reverse index: it Lists every Service and synthesizes each
// one's complete RecordSet, then checks whether the answer happens to be in
// there. If the cost is linear in Service count, then "dev-scale" is doing all
// the load-bearing work in that comment, and the premise is the fix's
// precondition rather than a throwaway remark.
func BenchmarkRespondReversePTRByServiceCount(b *testing.B) {
	for _, n := range []int{1, 10, 50, 200} {
		b.Run(fmt.Sprintf("services=%d", n), func(b *testing.B) {
			objs := make([]runtime.Object, 0, n*2)
			for i := range n {
				svc := fmt.Sprintf("svc%d", i)
				objs = append(objs, &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: svc},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone},
				})
				objs = append(objs, &discoveryv1.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "prod", Name: svc + "-1",
						Labels: map[string]string{discoveryv1.LabelServiceName: svc},
					},
					AddressType: discoveryv1.AddressTypeIPv4,
					// One endpoint each, so the per-Service synthesis cost is the
					// variable under test and endpoint fan-out is held constant.
					Endpoints: []discoveryv1.Endpoint{
						benchEndpoint(fmt.Sprintf("100.64.1.%d", i%250), "e0"),
					},
				})
			}
			r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local",
				newServiceZone(b, fake.NewClientset(objs...)), mapForwarder{}, testLogger())
			// A MISS is the worst and most honest case: a hit can short-circuit on
			// whichever Service happens to be scanned first, which would make the
			// measurement depend on map iteration order rather than on the work.
			benchRespond(b, r, buildTypedQuery(b, "254.9.64.100.in-addr.arpa", dnsmessage.TypePTR))
		})
	}
}
