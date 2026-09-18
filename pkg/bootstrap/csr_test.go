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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// TestCSRIssuesSystemNodeIdentity proves the HTTP-CSR approver mints the canonical
// kubelet identity CN=system:node:<name>, O=system:nodes bound to the authenticated
// node + InternalIP, and REJECTS a CSR requesting another node's name or IP (a
// cross-node SAN).
func TestCSRIssuesSystemNodeIdentity(t *testing.T) {
	signingCA, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	id := bootstrap.NodeIdentity{NodeName: "worker-a", InternalIP: "10.0.0.1"}

	// A well-formed CSR for this node yields the system:node identity.
	csr := newTestCSR(t, pkix.Name{CommonName: "ignored-by-server"}, []string{"worker-a"}, []net.IP{net.ParseIP("10.0.0.1")})
	certPEM, err := bootstrap.ApproveAndSignNodeCSR(signingCA, csr, id, time.Hour)
	if err != nil {
		t.Fatalf("approve CSR: %v", err)
	}
	leaf := parseCertPEM(t, certPEM)
	if leaf.Subject.CommonName != "system:node:worker-a" {
		t.Errorf("CN = %q, want system:node:worker-a", leaf.Subject.CommonName)
	}
	if !containsString(leaf.Subject.Organization, "system:nodes") {
		t.Errorf("O = %v, want system:nodes", leaf.Subject.Organization)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth] (a CLIENT credential)", leaf.ExtKeyUsage)
	}
	foundIP := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("10.0.0.1")) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("node InternalIP not bound as a SAN: %v", leaf.IPAddresses)
	}
	if err := leaf.CheckSignatureFrom(signingCA.Cert); err != nil {
		t.Errorf("node cert must be signed by the signing CA: %v", err)
	}

	// A CSR requesting a DIFFERENT node's IP is rejected (cross-node SAN).
	crossIP := newTestCSR(t, pkix.Name{}, []string{"worker-a"}, []net.IP{net.ParseIP("10.0.0.2")})
	if _, err := bootstrap.ApproveAndSignNodeCSR(signingCA, crossIP, id, time.Hour); !errors.Is(err, bootstrap.ErrCrossNodeSAN) {
		t.Errorf("cross-node IP SAN err = %v, want ErrCrossNodeSAN", err)
	}

	// A CSR requesting a DIFFERENT node's name is rejected (cross-node SAN).
	crossName := newTestCSR(t, pkix.Name{}, []string{"worker-b"}, []net.IP{net.ParseIP("10.0.0.1")})
	if _, err := bootstrap.ApproveAndSignNodeCSR(signingCA, crossName, id, time.Hour); !errors.Is(err, bootstrap.ErrCrossNodeSAN) {
		t.Errorf("cross-node name SAN err = %v, want ErrCrossNodeSAN", err)
	}

	// An empty identity is refused (no name/IP to bind to).
	if _, err := bootstrap.ApproveAndSignNodeCSR(signingCA, csr, bootstrap.NodeIdentity{}, time.Hour); !errors.Is(err, bootstrap.ErrEmptyIdentity) {
		t.Errorf("empty identity err = %v, want ErrEmptyIdentity", err)
	}
}

// TestKubeletServingFromClusterCA confirms the kubelet-serving cert is issued by the
// CLUSTER CA (so --kubelet-certificate-authority verifies it) and is SAN-bound to the
// node, rejecting a cross-node IP.
func TestKubeletServingFromClusterCA(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	id := bootstrap.NodeIdentity{NodeName: "worker-a", InternalIP: "10.0.0.1"}

	csr := newTestCSR(t, pkix.Name{CommonName: "worker-a"}, []string{"worker-a", "localhost"}, []net.IP{net.ParseIP("10.0.0.1")})
	certPEM, err := bootstrap.ApproveAndSignKubeletServing(clusterCA, csr, id, time.Hour)
	if err != nil {
		t.Fatalf("approve serving CSR: %v", err)
	}
	leaf := parseCertPEM(t, certPEM)
	if leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("kubelet-serving cert must be ServerAuth, got %v", leaf.ExtKeyUsage)
	}
	if err := leaf.CheckSignatureFrom(clusterCA.Cert); err != nil {
		t.Errorf("kubelet-serving cert must chain to the cluster CA: %v", err)
	}

	cross := newTestCSR(t, pkix.Name{}, nil, []net.IP{net.ParseIP("10.9.9.9")})
	if _, err := bootstrap.ApproveAndSignKubeletServing(clusterCA, cross, id, time.Hour); !errors.Is(err, bootstrap.ErrCrossNodeSAN) {
		t.Errorf("cross-node serving SAN err = %v, want ErrCrossNodeSAN", err)
	}
}

// TestCheckNodeCSRKeyPolicy is the key table CheckNodeCSR applies before it spends
// anything on a CSR: which key types and sizes a node credential may be issued
// over, and — the last two rows — that an unacceptable key is refused BEFORE the
// self-signature is verified.
//
// The ordering is the load-bearing half. Verifying a CSR's signature is the
// expensive step and its cost is chosen by the unauthenticated caller who picked
// the key, so an oversized modulus must cost a bit-length comparison and not a
// verification. The refusable rows below are therefore built WITHOUT a valid
// signature: reaching ErrUnsupportedCSRKey at all proves the key was judged first.
//
// The oversized row uses a 4097-bit modulus assembled directly rather than a
// generated 8192-bit key: generation would add seconds to the package's tests to
// exercise one BitLen comparison, and the bound is a comparison against
// maxRSAKeyBits, not a property of a well-formed key.
func TestCheckNodeCSRKeyPolicy(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("P-256 key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA-2048 key: %v", err)
	}
	smallRSAKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("RSA-1024 key: %v", err)
	}
	// 2^4096 + 1: 4097 bits, one over the maximum.
	hugeModulus := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 4096), big.NewInt(1))

	cases := []struct {
		name string
		csr  *x509.CertificateRequest
		want error
	}{
		{"P-256, what the k3sm client mints", signedCSR(t, ecKey), nil},
		{"ed25519", signedCSR(t, edKey), nil},
		{"RSA at the minimum", signedCSR(t, rsaKey), nil},
		{"RSA below the minimum", signedCSR(t, smallRSAKey), bootstrap.ErrUnsupportedCSRKey},
		{"an ECDSA curve outside the NIST set", unsignedCSR(&ecdsa.PublicKey{Curve: elliptic.P224()}), bootstrap.ErrUnsupportedCSRKey},
		{"a key type nothing in the stack speaks", unsignedCSR(struct{}{}), bootstrap.ErrUnsupportedCSRKey},
		{"RSA above the maximum", unsignedCSR(&rsa.PublicKey{N: hugeModulus, E: 65537}), bootstrap.ErrUnsupportedCSRKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := bootstrap.CheckNodeCSR(tc.csr, "worker-a")
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CheckNodeCSR = %v, want it accepted", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("CheckNodeCSR = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "self-signature") {
				t.Errorf("CheckNodeCSR spent a signature verification on an unacceptable key: %v", err)
			}
		})
	}
}

// signedCSR mints a real, self-signed CSR over key — the form a joining node
// submits, signature and all.
func signedCSR(t *testing.T, key crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "system:node:worker-a"},
		DNSNames: []string{"worker-a"},
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

// unsignedCSR is a CSR carrying pub and NO valid signature — a key nobody could
// have proved possession of. Every check that runs after the key policy fails on
// it, so an ErrUnsupportedCSRKey from one of these is proof the key was judged
// first.
func unsignedCSR(pub any) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: "system:node:worker-a"},
		DNSNames:  []string{"worker-a"},
		PublicKey: pub,
	}
}
