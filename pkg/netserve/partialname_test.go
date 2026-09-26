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
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// TestPartialNamesAreCompletedServerSide pins the resolver half of the node
// resolver floor: the host's supplemental resolver entry routes the "svc" and
// cluster-domain suffixes to the node DNS for every process, and macOS applies
// no ndots to it, so a shim-less client's partial name arrives as-is. respond
// completes name.ns.svc to the Service FQDN and answers under the client's
// ORIGINAL qname; refuses name.svc (ambiguous) as NXDOMAIN without forwarding;
// forwards a two-label name.ns (no namespace is opted in); leaves an FQDN
// unchanged. Every query here is a wire name ending in the root dot, so the
// classifier must be run on the normalized name for completion to happen.
func TestPartialNamesAreCompletedServerSide(t *testing.T) {
	t.Parallel()

	zone := mapZone{
		"default/kubernetes": {IP: netip.MustParseAddr("10.43.0.1")},
		"shop/web":           {IP: netip.MustParseAddr("10.43.0.55")},
	}

	cases := []struct {
		name        string
		query       string
		wantRCode   dnsmessage.RCode
		wantAddrs   []string
		wantOwner   string
		wantForward string // the host the forwarder must have been asked; "" = never called
	}{
		{"name.ns.svc completes to the ClusterIP", "kubernetes.default.svc.", dnsmessage.RCodeSuccess, []string{"10.43.0.1"}, "kubernetes.default.svc.", ""},
		{"mixed case name.ns.svc completes", "Web.Shop.SVC.", dnsmessage.RCodeSuccess, []string{"10.43.0.55"}, "Web.Shop.SVC.", ""},
		{"absent name.ns.svc is NXDOMAIN, not forwarded", "missing.shop.svc.", dnsmessage.RCodeNameError, nil, "", ""},
		{"name.svc is refused", "web.svc.", dnsmessage.RCodeNameError, nil, "", ""},
		{"deeper svc name is refused", "a.b.c.svc.", dnsmessage.RCodeNameError, nil, "", ""},
		{"name.ns is forwarded (no namespace opted in)", "web.shop.", dnsmessage.RCodeNameError, nil, "", "web.shop"},
		{"FQDN unchanged", "web.shop.svc.cluster.local.", dnsmessage.RCodeSuccess, []string{"10.43.0.55"}, "web.shop.svc.cluster.local.", ""},
		{"off-cluster name forwarded unchanged", "example.com.", dnsmessage.RCodeSuccess, []string{"93.184.216.34"}, "example.com.", "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fwd := &recordingForwarder{answers: map[string][]netip.Addr{
				"example.com": {netip.MustParseAddr("93.184.216.34")},
			}}
			r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", zone, fwd, testLogger())

			rcode, addrs, owners, _ := respondQuery(t, r, tc.query, dnsmessage.TypeA)
			if rcode != tc.wantRCode {
				t.Fatalf("rcode = %v, want %v", rcode, tc.wantRCode)
			}
			if got := addrStrings(addrs); !equalStrings(got, tc.wantAddrs) {
				t.Fatalf("addrs = %v, want %v", got, tc.wantAddrs)
			}
			for _, o := range owners {
				if o != tc.wantOwner {
					t.Fatalf("answer owner = %q, want the client's original qname %q", o, tc.wantOwner)
				}
			}
			switch {
			case tc.wantForward == "" && fwd.callCount() != 0:
				t.Fatalf("forwarder called %v, want no upstream query", fwd.calls)
			case tc.wantForward != "" && !fwd.called(tc.wantForward):
				t.Fatalf("forwarder calls = %v, want %q forwarded", fwd.calls, tc.wantForward)
			}
		})
	}
}
