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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
)

// The B213 unit ladder: the kubelet endpoint's SERVING half.
//
// The defect these tests exist against: on a `--mesh-ip` cluster the apiserver is
// started with --kubelet-certificate-authority=<cluster CA>, but every node —
// workers AND the control-plane node itself — served a cert from
// certs.SelfSignedServing, which chains to nothing. The apiserver rejected every
// :10250 with "x509: certificate signed by unknown authority", so kubectl
// logs/exec was broken cluster-wide while every node reported Ready.

// testClusterCA returns a CA standing in for the cluster CA (the anchor
// --kubelet-certificate-authority names).
func testClusterCA(t *testing.T) *certs.CA {
	t.Helper()
	ca, err := certs.NewCA("k3sm-test-cluster-ca")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

// verifyChain reports whether leaf chains to ca as a server certificate.
func verifyChain(t *testing.T, leaf *x509.Certificate, ca *certs.CA) error {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatalf("append CA PEM to pool")
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// TestKubeletServingTLSUsesIssuedPair is the core of B213: given the cluster-CA
// issued pair, the endpoint presents THAT leaf — it verifies against the CA the
// apiserver was told to trust — and B176's client-auth stamping is still applied to
// the same config. Both halves are asserted together because the fix edits the very
// function that carries the client half; presenting a verifiable cert while losing
// RequireAndVerifyClientCert would trade one defect for a worse one.
func TestKubeletServingTLSUsesIssuedPair(t *testing.T) {
	t.Parallel()
	ca := testClusterCA(t)
	certPEM, keyPEM, err := ca.IssueServing("k3sm-worker",
		[]string{"k3sm-worker", "localhost"},
		[]net.IP{net.ParseIP("100.64.2.1"), net.ParseIP("127.0.0.1")},
		kubeletServingValidFor)
	if err != nil {
		t.Fatalf("IssueServing: %v", err)
	}

	cfg, err := kubeletServingTLS(testKubeletAuth(t), certPEM, keyPEM, "k3sm-worker", "100.64.2.1")
	if err != nil {
		t.Fatalf("kubeletServingTLS: %v", err)
	}
	if len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) == 0 {
		t.Fatalf("kubeletServingTLS presented no certificate")
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// The exact issued bytes, not a fresh cert with similar properties.
	if !bytes.Equal(leaf.Raw, parseCertPEM(t, certPEM).Raw) {
		t.Error("the presented leaf is not the issued certificate — something re-minted it")
	}
	if err := verifyChain(t, leaf, ca); err != nil {
		t.Errorf("the presented leaf does not chain to the cluster CA: %v — this is the B213 symptom (x509: unknown authority) the apiserver reports", err)
	}
	if leaf.Issuer.CommonName == leaf.Subject.CommonName {
		t.Error("the presented leaf is self-signed; the issued pair was ignored")
	}

	// B176, unchanged: the serving half never ships without the client half.
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want tls.RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("nil ClientCAs: the endpoint would verify no client certificate at all")
	}
}

// TestKubeletServingTLSSelfSignedDefault pins the DEV posture the fix must not
// disturb: with no issued pair the node self-signs, exactly as single-node
// `k3sm server` and standalone `k3sm node` still do. That branch is correct only
// because such an apiserver names no --kubelet-certificate-authority, so the
// assertion is deliberately two-sided — self-signed AND not chaining to a cluster CA.
func TestKubeletServingTLSSelfSignedDefault(t *testing.T) {
	t.Parallel()
	ca := testClusterCA(t)
	cfg, err := kubeletServingTLS(testKubeletAuth(t), nil, nil, "k3sm-dev", "192.168.1.42")
	if err != nil {
		t.Fatalf("kubeletServingTLS: %v", err)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Issuer.CommonName != leaf.Subject.CommonName {
		t.Errorf("leaf issuer %q != subject %q — the dev default must stay self-signed", leaf.Issuer.CommonName, leaf.Subject.CommonName)
	}
	if err := verifyChain(t, leaf, ca); err == nil {
		t.Error("the self-signed dev leaf verified against a cluster CA it was never issued by")
	}
	// The SAN contract the dev path has carried since M0.3.
	wantIPs := []string{"127.0.0.1", "192.168.1.42"}
	for _, w := range wantIPs {
		if !hasIPSAN(leaf, w) {
			t.Errorf("self-signed leaf IP SANs %v missing %s", leaf.IPAddresses, w)
		}
	}
}

// TestKubeletServingTLSRejectsHalfPair pins the fail-fast: half a keypair is an
// error, never a quiet fall-through to self-signed. The message must point at the
// SERVER, because one server-side write site emits both halves together — an
// operator sent hunting on the worker would be looking in the wrong machine.
func TestKubeletServingTLSRejectsHalfPair(t *testing.T) {
	t.Parallel()
	ca := testClusterCA(t)
	certPEM, keyPEM, err := ca.IssueServing("k3sm-worker", []string{"k3sm-worker"}, []net.IP{net.ParseIP("127.0.0.1")}, kubeletServingValidFor)
	if err != nil {
		t.Fatalf("IssueServing: %v", err)
	}
	cases := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{"cert without key", certPEM, nil},
		{"key without cert", nil, keyPEM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kubeletServingTLS(testKubeletAuth(t), tc.cert, tc.key, "k3sm-worker", "127.0.0.1")
			if !errors.Is(err, errHalfKubeletServingPair) {
				t.Fatalf("err = %v, want errHalfKubeletServingPair", err)
			}
			if !bytes.Contains([]byte(err.Error()), []byte("server")) {
				t.Errorf("the half-pair error does not name the server-side cause: %v", err)
			}
		})
	}
}

// TestAgentNodeOptionsCarriesServingPair proves the worker hop: the join-delivered
// serving pair reaches the in-process node, and runAgent refuses a join that did not
// deliver one rather than serving a cert the apiserver will reject.
func TestAgentNodeOptionsCarriesServingPair(t *testing.T) {
	t.Parallel()
	ca := testClusterCA(t)
	certPEM, keyPEM, err := ca.IssueServing("k3sm-worker", []string{"k3sm-worker"}, []net.IP{net.ParseIP("100.64.2.1")}, kubeletServingValidFor)
	if err != nil {
		t.Fatalf("IssueServing: %v", err)
	}
	res := &bootstrap.JoinResult{
		PodCIDR:               "100.64.2.0/24",
		MeshIP:                "100.64.2.1",
		ClientCAPEM:           ca.CertPEM,
		ClusterCAPEM:          ca.CertPEM,
		KubeletServingCertPEM: certPEM,
		KubeletServingKeyPEM:  keyPEM,
	}
	opts := agentOptions{nodeName: "k3sm-worker", nodeIP: "100.64.2.1"}

	t.Run("the pair reaches the node options", func(t *testing.T) {
		nodeOpts := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
		if !bytes.Equal(nodeOpts.kubeletServingCertPEM, certPEM) || !bytes.Equal(nodeOpts.kubeletServingKeyPEM, keyPEM) {
			t.Error("the join-delivered kubelet serving pair did not reach the worker's in-process node; its :10250 would present a self-signed cert the apiserver refuses")
		}
		if !nodeOpts.serveTLS {
			t.Error("a joined worker must serve the kubelet API over TLS")
		}
	})

	t.Run("a complete pair is accepted", func(t *testing.T) {
		if err := requireJoinedServingPair(res); err != nil {
			t.Fatalf("requireJoinedServingPair rejected a complete pair: %v", err)
		}
	})

	// The refusal, on the shape a real old server produces: bootstrap.Join always
	// generates the serving KEY locally (it made the CSR), so the absent half is
	// always the CERT.
	t.Run("no serving cert refuses the start", func(t *testing.T) {
		err := requireJoinedServingPair(&bootstrap.JoinResult{ClientCAPEM: ca.CertPEM, KubeletServingKeyPEM: keyPEM})
		if err == nil {
			t.Fatal("runAgent accepted a join that delivered no kubelet serving cert — the node would register Ready with logs/exec broken")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("SERVER")) && !bytes.Contains([]byte(err.Error()), []byte("server")) {
			t.Errorf("the refusal does not point at the server that owes the cert: %v", err)
		}
	})

	t.Run("a cert with no key refuses the start", func(t *testing.T) {
		err := requireJoinedServingPair(&bootstrap.JoinResult{KubeletServingCertPEM: certPEM})
		if !errors.Is(err, errHalfKubeletServingPair) {
			t.Fatalf("err = %v, want errHalfKubeletServingPair", err)
		}
	})
}

// TestServerMeshNodeOptionsMintFromClusterCA covers the half of B213 the original
// prescription missed: the CONTROL-PLANE node never joins, so nothing hands it a
// pair and it must mint its own — which is exactly where the defect was observed.
//
// The SAN set is the sharp part. It must cover every address the apiserver may dial
// this node at, INCLUDING the registered InternalIP in the no-datapath posture,
// where it legitimately diverges from the advertised address: a narrowed list would
// reproduce the same broken logs/exec as a SAN mismatch rather than an issuer one.
func TestServerMeshNodeOptionsMintFromClusterCA(t *testing.T) {
	ca := testClusterCA(t)
	hierarchy := &certs.Hierarchy{Cluster: ca, Signing: testClusterCA(t)}

	t.Run("mesh: the leaf chains to the cluster CA and covers every dialable address", func(t *testing.T) {
		const (
			meshIP  = "100.64.0.1"
			nodeLAN = "192.168.1.42"
		)
		nodeOpts := nodeOptions{
			nodeName: "k3sm-cp",
			nodeIP:   nodeLAN, // an explicit --node-ip, distinct from --mesh-ip
			listen:   serverKubeletListen,
			podCIDR:  "100.64.0.0/24",
			netMode:  hostnet.Mode{Backend: hostnet.BackendDirect},
		}
		if err := setServerKubeletServing(&nodeOpts, hierarchy, meshIP); err != nil {
			t.Fatalf("setServerKubeletServing: %v", err)
		}
		leaf := parsePairLeaf(t, nodeOpts)
		if err := verifyChain(t, leaf, ca); err != nil {
			t.Fatalf("the server's own kubelet serving cert does not chain to the cluster CA: %v", err)
		}
		for _, want := range []string{meshIP, nodeLAN, "127.0.0.1"} {
			if !hasIPSAN(leaf, want) {
				t.Errorf("IP SANs %v missing %s", leaf.IPAddresses, want)
			}
		}
		if !hasDNSSAN(leaf, "k3sm-cp") || !hasDNSSAN(leaf, "localhost") {
			t.Errorf("DNS SANs %v must cover the node name and localhost", leaf.DNSNames)
		}
		// 365d, the same life writeAPIServerServingCert gives the apiserver leaf.
		life := leaf.NotAfter.Sub(leaf.NotBefore)
		if life < kubeletServingValidFor || life > kubeletServingValidFor+2*time.Hour {
			t.Errorf("validity %s, want ~%s (matching the apiserver serving cert)", life, kubeletServingValidFor)
		}
	})

	// The no-datapath divergent case: --mesh-ip 127.0.0.1 --network none. The
	// advertised address stays loopback while the REGISTERED InternalIP becomes a
	// host interface address — and that is the address the apiserver dials.
	t.Run("no-datapath: the SANs cover the divergent registered InternalIP", func(t *testing.T) {
		const hostLAN = "192.168.1.42"
		stubHostIPs(t, hostLAN)
		nodeOpts := nodeOptions{
			nodeName: "k3sm-cp",
			nodeIP:   loopbackNodeIP,
			listen:   serverKubeletListen,
			podCIDR:  "100.64.0.0/24",
			netMode:  hostnet.Mode{Backend: hostnet.BackendNone},
		}
		internalIP := proxyableNodeIP(nodeOpts)
		if internalIP == nodeOpts.nodeIP {
			t.Fatalf("test setup: InternalIP %s did not diverge from the advertised address; this case proves nothing", internalIP)
		}
		if err := setServerKubeletServing(&nodeOpts, hierarchy, loopbackNodeIP); err != nil {
			t.Fatalf("setServerKubeletServing: %v", err)
		}
		leaf := parsePairLeaf(t, nodeOpts)
		if !hasIPSAN(leaf, internalIP) {
			t.Errorf("IP SANs %v missing the REGISTERED InternalIP %s — the apiserver dials that address (--kubelet-preferred-address-types=InternalIP), so logs/exec would fail on a SAN mismatch", leaf.IPAddresses, internalIP)
		}
		if !hasIPSAN(leaf, "127.0.0.1") {
			t.Errorf("IP SANs %v missing the loopback same-host dial", leaf.IPAddresses)
		}
	})

	t.Run("single node: no pair, so the self-signed dev default stands", func(t *testing.T) {
		nodeOpts := nodeOptions{nodeName: "k3sm-solo", nodeIP: loopbackNodeIP, listen: serverKubeletListen}
		if err := setServerKubeletServing(&nodeOpts, hierarchy, ""); err != nil {
			t.Fatalf("setServerKubeletServing on the single-node path: %v", err)
		}
		if len(nodeOpts.kubeletServingCertPEM) != 0 || len(nodeOpts.kubeletServingKeyPEM) != 0 {
			t.Error("the single-node path minted a cluster-CA pair; that posture names no --kubelet-certificate-authority and must keep self-signing")
		}
	})
}

// TestServerMeshMintFailsClosedWithoutCA pins the direction of failure. A CA that
// cannot issue must stop the server, NOT degrade to a self-signed cert: the
// degradation is silent, indistinguishable from health at registration time, and is
// precisely the state B213 describes.
func TestServerMeshMintFailsClosedWithoutCA(t *testing.T) {
	t.Parallel()
	unsignable := &certs.CA{Cert: testClusterCA(t).Cert} // a CA with no private key
	cases := []struct {
		name      string
		hierarchy *certs.Hierarchy
	}{
		{"no hierarchy at all", nil},
		{"hierarchy with no cluster CA", &certs.Hierarchy{}},
		{"a cluster CA that cannot sign", &certs.Hierarchy{Cluster: unsignable}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodeOpts := nodeOptions{nodeName: "k3sm-cp", nodeIP: "100.64.0.1", listen: serverKubeletListen}
			err := setServerKubeletServing(&nodeOpts, tc.hierarchy, "100.64.0.1")
			if err == nil {
				t.Fatal("a mesh server minted nothing and reported success — bring-up would continue with a self-signed cert the apiserver refuses")
			}
			if len(nodeOpts.kubeletServingCertPEM) != 0 || len(nodeOpts.kubeletServingKeyPEM) != 0 {
				t.Error("a failed mint left partial material on the node options")
			}
		})
	}
}

// parsePairLeaf parses the certificate half of the pair nodeOpts carries, asserting
// the two halves actually load as a usable keypair.
func parsePairLeaf(t *testing.T, nodeOpts nodeOptions) *x509.Certificate {
	t.Helper()
	if len(nodeOpts.kubeletServingCertPEM) == 0 || len(nodeOpts.kubeletServingKeyPEM) == 0 {
		t.Fatal("no kubelet serving pair was minted")
	}
	if _, err := kubeletServingCertificate(nodeOpts.kubeletServingCertPEM, nodeOpts.kubeletServingKeyPEM, nodeOpts.nodeName, nil); err != nil {
		t.Fatalf("the minted pair does not load as a TLS keypair: %v", err)
	}
	return parseCertPEM(t, nodeOpts.kubeletServingCertPEM)
}

// parseCertPEM parses the first CERTIFICATE block of a PEM bundle.
func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no CERTIFICATE block in the PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func hasIPSAN(leaf *x509.Certificate, want string) bool {
	w := net.ParseIP(want)
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(w) {
			return true
		}
	}
	return false
}

func hasDNSSAN(leaf *x509.Certificate, want string) bool {
	for _, n := range leaf.DNSNames {
		if n == want {
			return true
		}
	}
	return false
}
