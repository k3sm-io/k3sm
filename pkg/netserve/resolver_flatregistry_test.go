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
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"k3sm.io/darwin-net/pkg/dns"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestResolverAnswersFlatRegistryNameFromAnyNamespace pins the flat registry
// name: the bare registry-k3sm and every search-suffixed form a pod's search
// list produces answer as the registry Service's ClusterIP from any namespace,
// the canonical name keeps answering through the ordinary Service path, an
// absent registry Service leaves those names as they were (NXDOMAIN or
// forwarded, never a crash), and an ordinary partial name keeps its behaviour.
func TestResolverAnswersFlatRegistryNameFromAnyNamespace(t *testing.T) {
	// The resolver answers under darwin-net's names; the registry Service is
	// published under registrysvc's. They must be the same Service.
	if registrysvc.FlatServiceName != dns.RegistryServiceName || registrysvc.FlatServiceNamespace != dns.RegistryServiceNamespace {
		t.Fatalf("registry Service %s/%s != resolver flat name %s/%s",
			registrysvc.FlatServiceNamespace, registrysvc.FlatServiceName,
			dns.RegistryServiceNamespace, dns.RegistryServiceName)
	}

	registryIP := netip.MustParseAddr("10.43.0.77")
	appIP := netip.MustParseAddr("10.43.0.20")
	offIP := netip.MustParseAddr("203.0.113.9")
	withRegistry := mapZone{
		dns.RegistryServiceNamespace + "/" + dns.RegistryServiceName: {IP: registryIP},
		"team/app": {IP: appIP},
	}
	withoutRegistry := mapZone{"team/app": {IP: appIP}}
	fwd := mapForwarder{"example.com": {offIP}}

	name := dns.RegistryServiceName
	tests := []struct {
		name      string
		zone      mapZone
		qname     string
		qtype     dnsmessage.Type
		wantRCode dnsmessage.RCode
		wantAddrs []netip.Addr
	}{
		{"bare name", withRegistry, name, dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"bare name with trailing dot", withRegistry, name + ".", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"bare name mixed case", withRegistry, "Registry-K3sm", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"other namespace svc form", withRegistry, name + ".team.svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"default namespace svc form", withRegistry, name + ".default.svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"svc.cluster.local form", withRegistry, name + ".svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"cluster.local form", withRegistry, name + ".cluster.local", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"canonical name keeps the Service path", withRegistry, name + "." + dns.RegistryServiceNamespace + ".svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{registryIP}},
		{"AAAA on a flat form is empty NOERROR", withRegistry, name + ".team.svc.cluster.local", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, nil},
		{"AAAA on the bare name is empty NOERROR", withRegistry, name, dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, nil},
		{"absent Service: other namespace svc form stays NXDOMAIN", withoutRegistry, name + ".team.svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"absent Service: svc.cluster.local stays NXDOMAIN", withoutRegistry, name + ".svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"absent Service: cluster.local stays NXDOMAIN", withoutRegistry, name + ".cluster.local", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"absent Service: bare name forwards as before", withoutRegistry, name, dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"prefix lookalike is not a flat form", withRegistry, name + "-x.team.svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"ordinary partial name app.team.svc completes", withRegistry, "app.team.svc", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{appIP}},
		{"ordinary partial name x.svc is refused", withRegistry, "app.svc", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"ordinary FQDN answers its own Service", withRegistry, "app.team.svc.cluster.local", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{appIP}},
		{"off-cluster name still forwards", withRegistry, "example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{offIP}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newClusterResolver(netip.MustParseAddr("10.43.0.10"), "cluster.local", tc.zone, fwd, testLogger())
			rcode, addrs, owners, _ := respondQuery(t, r, tc.qname, tc.qtype)
			if rcode != tc.wantRCode {
				t.Fatalf("%s %v: rcode = %v, want %v", tc.qname, tc.qtype, rcode, tc.wantRCode)
			}
			if !slices.Equal(addrs, tc.wantAddrs) {
				t.Fatalf("%s %v: addrs = %v, want %v", tc.qname, tc.qtype, addrs, tc.wantAddrs)
			}
			// The answer is stamped under the name that was asked.
			for _, o := range owners {
				if o != tc.qname && o != tc.qname+"." {
					t.Fatalf("%s: A owner = %q, want the queried name", tc.qname, o)
				}
			}
		})
	}
}
