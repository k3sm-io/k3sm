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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// The canonical kubelet identity. The Node authorizer (M4) keys off exactly this
// subject: CN=system:node:<nodeName>, O=system:nodes. Wiring --client-ca-file in M3
// so these certs authenticate makes the M4 Node,RBAC flip a pure authorizer switch.
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
)

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
	for _, d := range csr.DNSNames {
		switch d {
		case id.NodeName, systemNodePrefix + id.NodeName, "localhost":
		default:
			return fmt.Errorf("%w: DNS SAN %q is not node %q", ErrCrossNodeSAN, d, id.NodeName)
		}
	}
	return nil
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
