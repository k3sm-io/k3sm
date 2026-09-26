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
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/proxy"
)

// TestNodeAddressIsPassedToTheProxy proves netserve.New hands the configured
// node address to the Service proxy (proxy.WithNodeAddress): a backend at that
// address, which is where the ingress host's wildcard listener is published on
// the canonical kube-system/k3sm-ingress Service, is classified as on this node
// and dialed over the loopback path, not the mesh. It observes the effect on the
// proxy's own routing table rather than the option value, so it fails if the
// option is dropped or fed a different address. darwin-net's proxy tests prove
// the classification; this proves k3sm supplies the address.
func TestNodeAddressIsPassedToTheProxy(t *testing.T) {
	t.Parallel()
	// A mesh server's advertised address: outside this node's pod /24, so only
	// the option can make it node-local.
	const nodeAddr = "100.100.0.7"
	key := proxy.PortKey{ClusterIP: "10.43.0.80", Port: 80, Protocol: "TCP"}
	eps := []netv1.Endpoint{{IP: nodeAddr, Port: 80, Ready: true}}

	locality := func(t *testing.T, cfg Config) proxy.Locality {
		t.Helper()
		s := New(cfg)
		if n := s.table.SetEndpoints(key, eps); n != 1 {
			t.Fatalf("SetEndpoints admitted %d backends, want 1", n)
		}
		b, err := s.table.Pick(key)
		if err != nil {
			t.Fatalf("Pick: %v", err)
		}
		return b.Locality()
	}
	base := func() Config {
		return Config{
			Client:        fake.NewClientset(),
			WorkDir:       t.TempDir(),
			DNSVIP:        "10.43.0.10",
			ClusterDomain: "cluster.local",
			PodCIDR:       "100.64.1.0/24",
		}
	}

	withAddr := base()
	withAddr.NodeAddress = nodeAddr
	if got := locality(t, withAddr); got != proxy.LocalityNode {
		t.Errorf("backend at the configured node address has locality %v, want LocalityNode (on this node, loopback dial)", got)
	}

	other := base()
	other.NodeAddress = "100.100.0.8"
	if got := locality(t, other); got == proxy.LocalityNode {
		t.Errorf("backend at a DIFFERENT address was classified LocalityNode: the option must carry the configured node address, not any address")
	}

	if got := locality(t, base()); got == proxy.LocalityNode {
		t.Errorf("with no NodeAddress the backend was classified LocalityNode: nothing else may mark it node-local")
	}
}
