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

package main

import (
	"context"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TestEnrollDirectDerivesTheCableEndpoint pins the cable-only join: the joiner
// names no endpoint, and the enroller derives it from the index it assigns and
// the joiner's port, writing it as both the Endpoint and the one direct candidate.
func TestEnrollDirectDerivesTheCableEndpoint(t *testing.T) {
	e, _ := enrollerOverStub(t)
	req := netv1.MeshEnrollRequest{NodeName: "worker-1", PublicKey: testPubKey}
	resp, alloc, err := e.EnrollDirect(context.Background(), "worker-1", req, bootstrap.JoinDirect{PortOrdinal: 1, MeshPort: 51820})
	if err != nil {
		t.Fatalf("EnrollDirect: %v", err)
	}
	if !alloc.Fresh || resp.PodCIDR != "100.64.1.0/24" {
		t.Fatalf("allocation %v podCIDR %q, want a fresh index 1", alloc, resp.PodCIDR)
	}
	var self *netv1.MeshPeerSpec
	for i := range resp.Peers {
		if resp.Peers[i].NodeName == "worker-1" {
			self = &resp.Peers[i]
		}
	}
	if self == nil {
		t.Fatalf("no peer for worker-1 in %+v", resp.Peers)
	}
	// Index 1, port 1: 169.254.0.10.
	if self.Endpoint != "169.254.0.10:51820" {
		t.Errorf("endpoint = %q, want the derived 169.254.0.10:51820", self.Endpoint)
	}
	if len(self.Endpoints) != 1 || self.Endpoints[0].Link != netv1.EndpointLinkDirect || self.Endpoints[0].Address != self.Endpoint {
		t.Errorf("candidates = %+v, want the one direct candidate", self.Endpoints)
	}
	if _, err := directEndpoint(podnet.ClusterPodCIDR, "100.64.1.0/24", bootstrap.JoinDirect{PortOrdinal: 9, MeshPort: 51820}); err == nil {
		t.Error("a port ordinal with no address derived one anyway")
	}
}
