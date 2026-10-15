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
	"maps"
	"slices"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// TestSnapshotAccessorsNameThePinnedAndUnproxiedVIPs pins what the services
// record carries beside the table: the pinned kubernetes Service and its backend
// only when the apiserver endpoint is static, and the DNS VIP only when it parses.
func TestSnapshotAccessorsNameThePinnedAndUnproxiedVIPs(t *testing.T) {
	cases := []struct {
		name          string
		dnsVIP, apiEP string
		wantPinned    map[string][]string
		wantUnproxied []string
	}{
		{name: "single node", dnsVIP: "10.43.0.10", apiEP: "127.0.0.1:6444",
			wantPinned: map[string][]string{"default/kubernetes": {"127.0.0.1:6444"}}, wantUnproxied: []string{"10.43.0.10"}},
		{name: "mesh apiserver", dnsVIP: "10.43.0.10", wantUnproxied: []string{"10.43.0.10"}},
		{name: "no DNS VIP", dnsVIP: "not-an-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Config{Client: fake.NewClientset(), WorkDir: t.TempDir(), DNSVIP: tc.dnsVIP, APIServerEndpoint: tc.apiEP})
			if got := s.PinnedBackends(); !maps.EqualFunc(got, tc.wantPinned, slices.Equal) {
				t.Errorf("PinnedBackends = %v, want %v", got, tc.wantPinned)
			}
			if got := s.UnproxiedClusterIPs(); !slices.Equal(got, tc.wantUnproxied) {
				t.Errorf("UnproxiedClusterIPs = %v, want %v", got, tc.wantUnproxied)
			}
			if got := s.VIPStates(); len(got) != 0 {
				t.Errorf("an unstarted proxy reports %v", got)
			}
		})
	}
}
