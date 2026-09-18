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

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// The canonical kubelet identity. The Node authorizer keys off exactly this
// subject: CN=system:node:<nodeName>, O=system:nodes. --client-ca-file is wired
// unconditionally so these certs authenticate in every posture.
const (
	systemNodePrefix = "system:node:"
	systemNodesGroup = "system:nodes"
)

// Sentinel errors. Compare with errors.Is.
var (
	// ErrEmptyIdentity is returned when a NodeIdentity is missing its name or IP.
	ErrEmptyIdentity = errors.New("bootstrap: node identity missing name or InternalIP")
	// ErrCrossNodeSAN is returned when a CSR requests a SAN (an IP or a node name)
	// that is not bound to the authenticated node — the approver refuses to mint a
	// certificate naming a node other than the one the bootstrap identity proved.
	ErrCrossNodeSAN = errors.New("bootstrap: CSR requests a SAN bound to a different node")
	// ErrUnsupportedCSRKey is returned when a CSR's public key is not one a node
	// credential may be issued over: an unknown algorithm, a curve outside the NIST
	// set the rest of the stack speaks, or an undersized RSA modulus.
	ErrUnsupportedCSRKey = errors.New("bootstrap: CSR public key is not an acceptable node key")
)

// minRSAKeyBits is the smallest RSA modulus a node CSR may carry. k3sm's own
// client mints P-256 (join.go generateCSR); the bound exists for a CSR this
// server did not generate.
const minRSAKeyBits = 2048

// CheckNodeCSR validates everything about a joining node's CSR that can be judged
// WITHOUT the mesh address the enroll has not yet assigned: the self-signature
// (the proof that the requester holds the private key), the public key, and the
// half of the SAN policy that does not depend on the address — no DNS SAN naming
// another identity, and no more IP SANs than the one a node may assert about
// itself.
//
// It exists to be called BEFORE the enroll. The enroll ALLOCATES this node's pod
// /24, so every rejection on its far side leaves a MeshPeer and an index behind;
// a token holder could otherwise burn the cluster's index space with joins that
// abort at a CSR it never intended to be signed. What this cannot judge — whether
// an IP SAN is the address the allocator actually assigned — stays with the
// approver (NodeIdentity.checkSANs), which is the only thing left on the far side.
func CheckNodeCSR(csr *x509.CertificateRequest, nodeName string) error {
	if csr == nil || nodeName == "" {
		return ErrEmptyIdentity
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("verify CSR self-signature: %w", err)
	}
	if err := checkCSRKey(csr.PublicKey); err != nil {
		return err
	}
	if err := checkDNSSANs(csr.DNSNames, nodeName); err != nil {
		return err
	}
	if len(csr.IPAddresses) > 1 {
		return fmt.Errorf("%w: %d IP SANs requested, and a node asserts at most its own address", ErrCrossNodeSAN, len(csr.IPAddresses))
	}
	return nil
}

// checkCSRKey accepts the key types a node credential may be issued over: NIST
// ECDSA, Ed25519, and RSA at or above minRSAKeyBits. Anything else is refused
// rather than handed to the CA, because a key the signer accepts but the kubelet's
// TLS stack cannot use fails much later and much less legibly.
func checkCSRKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return fmt.Errorf("%w: the ECDSA curve is outside P-256/P-384/P-521", ErrUnsupportedCSRKey)
	case ed25519.PublicKey:
		return nil
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < minRSAKeyBits {
			return fmt.Errorf("%w: the RSA key is %d bits, below the %d-bit minimum", ErrUnsupportedCSRKey, bits, minRSAKeyBits)
		}
		return nil
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedCSRKey, pub)
	}
}

// checkDNSSANs rejects any DNS SAN not bound to nodeName. The permitted set — the
// bare node name, its system:node: form, and localhost — is fixed by the node's
// NAME alone, which is what makes this half of the SAN policy decidable before the
// enroll assigns an address (see CheckNodeCSR).
func checkDNSSANs(names []string, nodeName string) error {
	for _, d := range names {
		switch d {
		case nodeName, systemNodePrefix + nodeName, "localhost":
		default:
			return fmt.Errorf("%w: DNS SAN %q is not node %q", ErrCrossNodeSAN, d, nodeName)
		}
	}
	return nil
}

// NodeIdentity is the authenticated bootstrap context a CSR is approved against: the
// node name the node-password bound and the node's InternalIP. The approver binds
// the issued certificate's subject + SANs to THIS identity, so a node cannot obtain
// a credential or serving cert for any name/address but its own.
type NodeIdentity struct {
	// NodeName is the node name the node-password is bound to.
	NodeName string
	// InternalIP is the node's advertised InternalIP — the only IP SAN the approver
	// permits in an issued certificate.
	InternalIP string
}

// validate checks the identity is fully specified and returns the parsed IP.
func (id NodeIdentity) validate() (net.IP, error) {
	if id.NodeName == "" || id.InternalIP == "" {
		return nil, ErrEmptyIdentity
	}
	ip := net.ParseIP(id.InternalIP)
	if ip == nil {
		return nil, fmt.Errorf("%w: InternalIP %q is not an IP", ErrEmptyIdentity, id.InternalIP)
	}
	return ip, nil
}

// checkSANs rejects any SAN in the CSR not bound to id: an IP SAN other than the
// node InternalIP, or a DNS SAN naming a node other than id.NodeName (system:node:
// and the bare name + localhost are the only permitted DNS SANs). This is the
// cross-node-SAN guard the CSR auto-approver enforces.
func (id NodeIdentity) checkSANs(csr *x509.CertificateRequest, ip net.IP) error {
	for _, reqIP := range csr.IPAddresses {
		if !reqIP.Equal(ip) {
			return fmt.Errorf("%w: IP SAN %s is not node %q InternalIP %s", ErrCrossNodeSAN, reqIP, id.NodeName, id.InternalIP)
		}
	}
	return checkDNSSANs(csr.DNSNames, id.NodeName)
}

// ApproveAndSignNodeCSR validates csr against id (rejecting any cross-node SAN) and,
// on success, signs it with the SIGNING CA as a CLIENT certificate with the
// authoritative subject CN=system:node:<id.NodeName>, O=system:nodes and exactly the
// node InternalIP as an IP SAN. The CSR's own subject is ignored — the server sets
// the identity. This is the HTTP-CSR issuance the join exchange uses to hand a node
// its kubelet client credential (never the admin kubeconfig).
func ApproveAndSignNodeCSR(signingCA *certs.CA, csr *x509.CertificateRequest, id NodeIdentity, validFor time.Duration) ([]byte, error) {
	ip, err := id.validate()
	if err != nil {
		return nil, err
	}
	if err := id.checkSANs(csr, ip); err != nil {
		return nil, err
	}
	subject := pkix.Name{
		CommonName:   systemNodePrefix + id.NodeName,
		Organization: []string{systemNodesGroup},
	}
	return signingCA.SignClientCSR(csr, subject, nil, []net.IP{ip}, validFor)
}

// ApproveAndSignKubeletServing validates csr against id and signs it with the
// CLUSTER CA as a SERVING certificate (CN=id.NodeName) carrying the node InternalIP +
// name as SANs, so the apiserver — started --kubelet-certificate-authority=<cluster
// CA> — verifies the node's :10250 endpoint and remote exec/logs are not MITM-able.
// The node keeps its own serving private key (the server signs only its CSR).
func ApproveAndSignKubeletServing(clusterCA *certs.CA, csr *x509.CertificateRequest, id NodeIdentity, validFor time.Duration) ([]byte, error) {
	ip, err := id.validate()
	if err != nil {
		return nil, err
	}
	if err := id.checkSANs(csr, ip); err != nil {
		return nil, err
	}
	subject := pkix.Name{CommonName: id.NodeName}
	dns := []string{id.NodeName, "localhost"}
	return clusterCA.SignServingCSR(csr, subject, dns, []net.IP{ip}, validFor)
}
