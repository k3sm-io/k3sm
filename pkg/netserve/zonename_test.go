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
	"strings"
	"testing"
)

// parseClusterZoneName decides which branch of respond a query takes, so its
// label arithmetic is load-bearing for every in-cluster lookup: the bare
// <svc>.<ns> name, the per-endpoint identity name, and the SRV owner name are
// three different answers separated only by the extra-label count.
//
// It used to materialize the labels with strings.Split and hand back a slice
// whose only reader was len(). It now counts by index instead. These cases pin
// the contract across that change — in particular the empty-label refusal,
// which the old code got by testing every split element against "" and the new
// code gets by rejecting a leading dot, a trailing dot, or a "..". Those two
// formulations must agree on every input, and a disagreement would be a silent
// routing change (an empty service name reaching a zone lookup).
func TestParseClusterZoneNameCountsLabels(t *testing.T) {
	t.Parallel()
	const domain = "cluster.local"
	for _, tc := range []struct {
		name      string
		qname     string
		wantOK    bool
		wantExtra int
		wantSvc   string
		wantNS    string
	}{
		{
			name:   "bare service name has no extra labels",
			qname:  "web.prod.svc.cluster.local",
			wantOK: true, wantExtra: 0, wantSvc: "web", wantNS: "prod",
		},
		{
			name:   "per-endpoint identity name has one extra label",
			qname:  "db-0.db.prod.svc.cluster.local",
			wantOK: true, wantExtra: 1, wantSvc: "db", wantNS: "prod",
		},
		{
			name:   "dashed-IP identity name has one extra label",
			qname:  "100-64-0-10.db.prod.svc.cluster.local",
			wantOK: true, wantExtra: 1, wantSvc: "db", wantNS: "prod",
		},
		{
			name:   "SRV owner name has two extra labels",
			qname:  "_pg._tcp.db.prod.svc.cluster.local",
			wantOK: true, wantExtra: 2, wantSvc: "db", wantNS: "prod",
		},
		{
			name:   "three extra labels still count correctly",
			qname:  "a.b.c.db.prod.svc.cluster.local",
			wantOK: true, wantExtra: 3, wantSvc: "db", wantNS: "prod",
		},
		{
			name:   "not under the svc zone at all",
			qname:  "web.prod.pod.cluster.local",
			wantOK: false,
		},
		{
			name:   "off-cluster name",
			qname:  "example.com",
			wantOK: false,
		},
		{
			name:   "a single label carries no service/namespace pair",
			qname:  "prod.svc.cluster.local",
			wantOK: false,
		},
		{
			name:   "the bare suffix itself",
			qname:  ".svc.cluster.local",
			wantOK: false,
		},
		// The empty-label family — the cases where the index scan has to agree
		// with the old per-element "" test. Each of these must stay ok==false:
		// an empty label is not a name, and admitting one would send "" to a
		// Service lookup.
		{
			name:   "leading dot yields an empty first label",
			qname:  ".web.prod.svc.cluster.local",
			wantOK: false,
		},
		{
			name:   "doubled dot yields an empty middle label",
			qname:  "a..prod.svc.cluster.local",
			wantOK: false,
		},
		{
			name:   "doubled dot between service and namespace",
			qname:  "web..prod.svc.cluster.local",
			wantOK: false,
		},
		{
			name:   "doubled dot deep in the extra labels",
			qname:  "a..b.db.prod.svc.cluster.local",
			wantOK: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			extra, svc, ns, ok := parseClusterZoneName(tc.qname, domain)
			if ok != tc.wantOK {
				t.Fatalf("parseClusterZoneName(%q) ok = %v, want %v", tc.qname, ok, tc.wantOK)
			}
			if !tc.wantOK {
				// A rejected name must also report zero values, so a caller that
				// ignores ok cannot act on half-parsed state.
				if extra != 0 || svc != "" || ns != "" {
					t.Errorf("rejected %q but returned (%d, %q, %q), want (0, \"\", \"\")",
						tc.qname, extra, svc, ns)
				}
				return
			}
			if extra != tc.wantExtra {
				t.Errorf("parseClusterZoneName(%q) extraLabels = %d, want %d", tc.qname, extra, tc.wantExtra)
			}
			if svc != tc.wantSvc {
				t.Errorf("parseClusterZoneName(%q) svc = %q, want %q", tc.qname, svc, tc.wantSvc)
			}
			if ns != tc.wantNS {
				t.Errorf("parseClusterZoneName(%q) ns = %q, want %q", tc.qname, ns, tc.wantNS)
			}
		})
	}
}

// TestParseClusterZoneNameMatchesSplitSemantics is a differential check against
// the exact implementation this function replaced. It is not a duplicate of the
// table above: the table pins the cases somebody thought of, and this pins
// EQUIVALENCE over a generated corpus, including shapes nobody enumerated.
//
// The reference below is the original body verbatim, so if the two ever
// disagree the failure names the input that separates them.
func TestParseClusterZoneNameMatchesSplitSemantics(t *testing.T) {
	t.Parallel()
	const domain = "cluster.local"

	// reference is the pre-optimisation implementation, kept here as the oracle.
	reference := func(qname, domain string) (extra int, svc, ns string, ok bool) {
		host, found := strings.CutSuffix(qname, ".svc."+domain)
		if !found {
			return 0, "", "", false
		}
		parts := strings.Split(host, ".")
		if len(parts) < 2 {
			return 0, "", "", false
		}
		for _, p := range parts {
			if p == "" {
				return 0, "", "", false
			}
		}
		return len(parts) - 2, parts[len(parts)-2], parts[len(parts)-1], true
	}

	// A corpus of label sequences built from pieces that exercise the boundary
	// conditions: empties in every position, single labels, and the underscore
	// forms SRV uses.
	pieces := []string{"", "a", "web", "_tcp", "db-0", "100-64-0-10"}
	var corpus []string
	for _, a := range pieces {
		corpus = append(corpus, a+".svc."+domain)
		for _, b := range pieces {
			corpus = append(corpus, a+"."+b+".svc."+domain)
			for _, c := range pieces {
				corpus = append(corpus, a+"."+b+"."+c+".svc."+domain)
			}
		}
	}
	// Plus names that miss the zone entirely, and the degenerate inputs.
	corpus = append(corpus, "", ".", "..", "svc."+domain, domain,
		"example.com", "web.prod.pod."+domain, ".svc."+domain)

	for _, qname := range corpus {
		wExtra, wSvc, wNS, wOK := reference(qname, domain)
		gExtra, gSvc, gNS, gOK := parseClusterZoneName(qname, domain)
		if gOK != wOK || gExtra != wExtra || gSvc != wSvc || gNS != wNS {
			t.Errorf("parseClusterZoneName(%q) = (%d, %q, %q, %v), reference = (%d, %q, %q, %v)",
				qname, gExtra, gSvc, gNS, gOK, wExtra, wSvc, wNS, wOK)
		}
	}
}

// TestParseClusterZoneNameDoesNotAllocate is the regression guard on the reason
// the function was rewritten. The old strings.Split cost one allocation on
// every in-cluster query — measured at 14% of the allocations in
// BenchmarkRespondClusterA, the hottest path in k3sm — and nothing but a test
// stops it coming back, because reintroducing Split would leave every
// behavioural test green.
//
// The ".svc."+domain concatenation is deliberately included in what is
// measured: at the default cluster domain it is 18 bytes and the compiler keeps
// it on the stack, which is WHY the count is zero. A longer domain would push
// it past the 32-byte temporary buffer and onto the heap, so this test also
// pins the cheap-domain assumption that makes the zero real.
func TestParseClusterZoneNameDoesNotAllocate(t *testing.T) {
	// Not parallel: AllocsPerRun requires exclusive use of the process.
	names := []string{
		"web.prod.svc.cluster.local",         // bare service
		"db-0.db.prod.svc.cluster.local",     // identity
		"_pg._tcp.db.prod.svc.cluster.local", // SRV owner
		"absent.prod.svc.cluster.local",      // in-zone miss
		"example.com",                        // off-cluster (early return)
	}
	for _, qname := range names {
		got := testing.AllocsPerRun(200, func() {
			extra, svc, ns, ok := parseClusterZoneName(qname, "cluster.local")
			// Consume every result so nothing is optimised away.
			if ok && (extra < 0 || svc == "\x00" || ns == "\x00") {
				t.Fatal("unreachable")
			}
		})
		if got != 0 {
			t.Errorf("parseClusterZoneName(%q) allocated %.0f time(s) per call, want 0 "+
				"(a strings.Split or a heap-escaping concatenation has come back on the hottest path in k3sm)",
				qname, got)
		}
	}
}
