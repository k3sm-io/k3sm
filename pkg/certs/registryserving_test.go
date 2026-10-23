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
	"slices"
	"testing"
	"time"
)

// TestIssueRegistryServing pins the registry's serving leaf: a server-auth
// certificate from the issuing CA carrying exactly the SANs asked for, whose
// chain verifies against that CA for every one of them, presented without the
// anchor; and a refusal, not a panic, from a CA that cannot sign.
func TestIssueRegistryServing(t *testing.T) {
	ca, err := NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	names := []string{"registry-k3sm", "registry-k3sm.k3sm-registry"}
	ips := []net.IP{net.ParseIP("10.43.0.9").To4(), net.ParseIP("100.64.0.1").To4()}

	t.Run("a server-auth leaf that verifies for every SAN", func(t *testing.T) {
		pair, err := ca.IssueRegistryServing("registry-k3sm", names, ips, time.Hour)
		if err != nil {
			t.Fatalf("IssueRegistryServing: %v", err)
		}
		if len(pair.Certificate) != 1 {
			t.Errorf("chain length = %d, want the leaf alone", len(pair.Certificate))
		}
		leaf := pair.Leaf
		if leaf == nil {
			t.Fatal("no parsed leaf")
		}
		if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
			t.Errorf("EKU = %v, want server auth only", leaf.ExtKeyUsage)
		}
		if !slices.Equal(leaf.DNSNames, names) {
			t.Errorf("DNS SANs = %v, want %v", leaf.DNSNames, names)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		for _, host := range []string{"registry-k3sm", "registry-k3sm.k3sm-registry", "10.43.0.9", "100.64.0.1"} {
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
				t.Errorf("verify for %s: %v", host, err)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "registry.example.com"}); err == nil {
			t.Error("the leaf verifies for a name it was not issued for")
		}
	})

	t.Run("a CA without its key refuses", func(t *testing.T) {
		pub := &CA{Cert: ca.Cert}
		if _, err := pub.IssueRegistryServing("registry-k3sm", names, ips, time.Hour); err == nil {
			t.Fatal("a CA with no private key minted a certificate")
		}
		var nilCA *CA
		if _, err := nilCA.IssueRegistryServing("registry-k3sm", names, ips, time.Hour); err == nil {
			t.Fatal("a nil CA minted a certificate")
		}
	})

	t.Run("no DNS name refuses", func(t *testing.T) {
		if _, err := ca.IssueRegistryServing("registry-k3sm", nil, ips, time.Hour); err == nil {
			t.Fatal("a leaf with no DNS SAN was minted")
		}
	})
}
