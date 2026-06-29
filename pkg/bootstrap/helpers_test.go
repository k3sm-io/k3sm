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

package bootstrap_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// fakeClock is a mutable clock for TTL tests.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// fakeEnroller is a controller-mediated enroll stub: it returns a fixed assigned
// podCIDR + mesh-egress IP and a canned peer snapshot.
type fakeEnroller struct {
	podCIDR string
	meshIP  string
	peers   []netv1.MeshPeerSpec
}

func (f *fakeEnroller) Enroll(_ context.Context, nodeName string, _ netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error) {
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  f.podCIDR,
		MeshIP:   f.meshIP,
		Peers:    f.peers,
	}.WithDefaults(), nil
}

// newTestCSR mints an ECDSA P-256 keypair and a PEM CSR carrying the given subject +
// SANs (the form a joining node submits).
func newTestCSR(t *testing.T, subject pkix.Name, dnsNames []string, ips []net.IP) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     subject,
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

// parseCertPEM parses the first CERTIFICATE block of certPEM.
func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no CERTIFICATE PEM block in %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// parseTLSChain parses a tls.Certificate's presented DER chain into x509 certs.
func parseTLSChain(t *testing.T, tc tls.Certificate) []*x509.Certificate {
	t.Helper()
	out := make([]*x509.Certificate, 0, len(tc.Certificate))
	for _, der := range tc.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse chain cert: %v", err)
		}
		out = append(out, c)
	}
	return out
}

// containsString reports whether s is in xs.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
