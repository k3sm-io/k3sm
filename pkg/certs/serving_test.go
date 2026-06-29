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

package certs

import (
	"crypto/x509"
	"net"
	"testing"
)

// TestSelfSignedServingSANs verifies the minted kubelet-serving cert carries the
// node InternalIP in its SANs — the load-bearing requirement so the apiserver
// (with --kubelet-preferred-address-types=InternalIP) can dial the node by IP
// and verify the cert, closing the M0.3 logs/exec gap.
func TestSelfSignedServingSANs(t *testing.T) {
	nodeIP := net.ParseIP("192.168.64.7")
	pair, err := SelfSignedServing([]string{"k3sm-node", "localhost"}, []net.IP{net.ParseIP("127.0.0.1"), nodeIP})
	if err != nil {
		t.Fatalf("SelfSignedServing: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	foundIP := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(nodeIP) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("node IP %s not in cert SANs %v", nodeIP, leaf.IPAddresses)
	}
	foundDNS := false
	for _, n := range leaf.DNSNames {
		if n == "k3sm-node" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Errorf("node name not in cert DNS SANs %v", leaf.DNSNames)
	}
	if leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("cert must be usable for server auth")
	}
}
