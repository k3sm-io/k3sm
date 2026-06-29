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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
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
