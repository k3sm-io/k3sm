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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
)

// The update signer is the identity whose signature authorises a managed
// update on a node: the server mints it in memory from the cluster CA at
// every start, and a node's k3sm-netd root helper runs a release only when
// its payload is signed by a certificate that chains to the cluster CA and
// carries this subject and ExtKeyUsageCodeSigning. darwin-net's
// wire.UpdateSignerCommonName and wire.UpdateSignerOrganization are the same
// strings (pinned by a test in pkg/update).
const (
	// UpdateSignerCommonName is the update signer's CommonName.
	UpdateSignerCommonName = "k3sm:update-signer"
	// UpdateSignerOrganization is the update signer's Organization.
	UpdateSignerOrganization = "k3sm:update-signers"
	// UpdateSignerValidity is the signer certificate's lifetime. It is
	// re-minted at every server start, so the lifetime bounds only a server
	// that runs for a year without restarting.
	UpdateSignerValidity = 365 * 24 * time.Hour
)

// ErrUpdateSignerIdentity refuses a certificate that would carry the update
// signer's subject or the code-signing usage through any path but
// IssueUpdateSigner.
var ErrUpdateSignerIdentity = errors.New("certs: only the update signer may carry its subject or the code-signing usage")

// refuseUpdateSignerIdentity is the check signLeaf applies to every other
// issuer: no CommonName or Organization of the update signer, and no
// code-signing (or any-usage) extended key usage.
func refuseUpdateSignerIdentity(subject pkix.Name, ekus []x509.ExtKeyUsage) error {
	switch {
	case subject.CommonName == UpdateSignerCommonName,
		slices.Contains(subject.Organization, UpdateSignerOrganization),
		slices.Contains(ekus, x509.ExtKeyUsageCodeSigning),
		slices.Contains(ekus, x509.ExtKeyUsageAny):
		return fmt.Errorf("%w (CN=%q O=%q)", ErrUpdateSignerIdentity, subject.CommonName, subject.Organization)
	}
	return nil
}

// UpdateSigner is the in-memory update-signing identity: an ECDSA P-256 key and
// its certificate from the cluster CA. The key is never written anywhere.
type UpdateSigner struct {
	// Key signs payloads.
	Key *ecdsa.PrivateKey
	// Cert is the parsed certificate; CertPEM its PEM, which a payload carries.
	Cert    *x509.Certificate
	CertPEM []byte
}

// IssueUpdateSigner mints a fresh update signer from c, which must be the
// cluster CA (the anchor every node and its root helper pin): CN
// UpdateSignerCommonName, O UpdateSignerOrganization, ExtKeyUsageCodeSigning
// only, valid for UpdateSignerValidity.
func (c *CA) IssueUpdateSigner() (*UpdateSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate the update signer key: %w", err)
	}
	der, err := c.issueLeaf(&key.PublicKey, pkix.Name{CommonName: UpdateSignerCommonName, Organization: []string{UpdateSignerOrganization}},
		nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, UpdateSignerValidity)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse the update signer certificate: %w", err)
	}
	return &UpdateSigner{Key: key, Cert: cert, CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
