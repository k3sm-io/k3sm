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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// fakeClock is a mutable clock for TTL tests.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// fakeEnroller is a controller-mediated enroll stub: it returns a fixed assigned
// podCIDR + mesh-egress IP and a canned peer snapshot, and holds ONE stored peer
// spec so an endpoint refresh can be observed as the mutation it is.
//
// Locking discipline: mu guards peer + refreshes; httptest serves each request on
// its own goroutine.
type fakeEnroller struct {
	podCIDR string
	meshIP  string
	peers   []netv1.MeshPeerSpec

	mu sync.Mutex
	// peer is the stored MeshPeer spec RefreshEndpoint updates. Nil models a node
	// with no peer (the rejoin case), which returns bootstrap.ErrNoMeshPeer.
	peer *netv1.MeshPeerSpec
	// refreshes counts EVERY RefreshEndpoint call, including the ones that fail.
	// A denial test asserts it stayed zero: "the request was refused" and "the
	// write never happened" are different claims, and only the second one matters.
	refreshes int
	// deregistered is the node name of every Deregister call, in order. A denial
	// test asserts it stayed empty for the same reason refreshes does.
	deregistered []string
	// deregisterErr is what Deregister returns, so a row can drive the handler's
	// 500 arm.
	deregisterErr error
}

// Enroll hands out the SAME fixed assignment to every node, so it carves no index
// and reports every enroll as a reuse — which is the honest answer for a fixture
// that has no index space, and the one that keeps the failed-join reap (scoped to
// a FRESH allocation) out of these rows.
func (f *fakeEnroller) Enroll(_ context.Context, nodeName string, _ netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, bootstrap.Allocation, error) {
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  f.podCIDR,
		MeshIP:   f.meshIP,
		Peers:    f.peers,
	}.WithDefaults(), bootstrap.AllocationReused, nil
}

// ReleaseAllocation satisfies bootstrap.Enroller. Nothing here is ever a fresh
// allocation, so a reap reaching this fixture is a wiring mistake — or a handler
// that reaps a REUSED allocation, which is the defect the B339 gate forbids.
func (f *fakeEnroller) ReleaseAllocation(_ context.Context, nodeName string) error {
	return fmt.Errorf("the join fixture's enroller was asked to release %q, an allocation it never carved", nodeName)
}

func (f *fakeEnroller) RefreshEndpoint(_ context.Context, _, endpoint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	if f.peer == nil {
		return bootstrap.ErrNoMeshPeer
	}
	f.peer.Endpoint = endpoint
	return nil
}

// Deregister records the node name and drops the stored peer, which is what the
// real enroller's MeshPeer delete does to the state a later snapshot reads.
func (f *fakeEnroller) Deregister(_ context.Context, nodeName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deregistered = append(f.deregistered, nodeName)
	if f.deregisterErr != nil {
		return f.deregisterErr
	}
	f.peer = nil
	return nil
}

// deregisters returns the node names Deregister was called with, in order.
func (f *fakeEnroller) deregisters() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deregistered...)
}

// snapshot returns the stored peer spec and the refresh call count.
func (f *fakeEnroller) snapshot() (netv1.MeshPeerSpec, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peer == nil {
		return netv1.MeshPeerSpec{}, f.refreshes
	}
	return *f.peer, f.refreshes
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

// nodeCSRPEM mints an ECDSA P-256 keypair and returns the PEM CSR a joining node
// submits, carrying the subject a kubelet asks for plus the given SANs. It is the
// PEM form of newTestCSR, for the tests that POST a hand-built JoinRequest rather
// than call the Join client.
func nodeCSRPEM(t *testing.T, nodeName string, dnsNames []string, ips []net.IP) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "system:node:" + nodeName, Organization: []string{"system:nodes"}},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
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
