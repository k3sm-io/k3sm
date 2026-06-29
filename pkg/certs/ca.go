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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// ErrPinMismatch is returned by VerifyPinnedChain when the server's presented
// chain does not anchor in a CA certificate whose SHA-256 matches the pin. Compare
// with errors.Is, never by string match.
var ErrPinMismatch = errors.New("certs: presented chain does not match the pinned CA hash")

// CA is a certificate authority — a self-signed CA certificate plus its private
// key — that signs the leaf certificates k3sm's PKI issues in M3+: the apiserver
// serving cert, kubelet-serving certs, and the system:node client certs handed to
// joining nodes. k3sm stands up two CAs (DESIGN §5c, docs/m3-plan.md): a CLUSTER CA
// (the serving anchor the join token pins) and a SIGNING CA (issues node client
// certs). The PEM encodings are cached so the server can write them to disk and
// embed them in kubeconfigs without re-marshalling.
type CA struct {
	// Cert is the parsed CA certificate.
	Cert *x509.Certificate
	// Key is the CA private key (never serialized off this host except as KeyPEM,
	// which stays in the 0600 server work dir).
	Key *ecdsa.PrivateKey
	// CertPEM is the PEM-encoded CA certificate (the form written to disk, embedded
	// in a node kubeconfig's certificate-authority-data, and hashed for the pin).
	CertPEM []byte
	// KeyPEM is the PEM-encoded CA private key.
	KeyPEM []byte
}

// NewCA creates a new self-signed ECDSA P-256 CA with the given common name. The
// CA is valid for ten years (a control-plane lifetime); leaf certs it issues are
// short-lived. ECDSA P-256 keeps the CA small and signing fast.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// LoadCA reconstructs a CA from its PEM-encoded certificate and private key (the
// form NewCA emits and the server persists to its 0600 work dir). It is how a
// running server reloads a CA created on a previous boot.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("certs: load CA: no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("certs: load CA: no PRIVATE KEY PEM block")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// PinHash returns the lowercase hex SHA-256 of the CA certificate DER. This is the
// value embedded in a K10 join token (FormatToken) and the anchor VerifyPinnedChain
// checks the server's presented chain against — pinned trust WITHOUT
// insecure-skip-tls-verify.
func (c *CA) PinHash() string {
	sum := sha256.Sum256(c.Cert.Raw)
	return hex.EncodeToString(sum[:])
}

// IssueServing mints a fresh serving keypair signed by this CA, for a server the CA
// owns the key material of (the apiserver / a same-host kubelet-serving cert). The
// returned cert is usable for ServerAuth and carries dnsNames + ipAddrs as SANs. For
// a remote node that must keep its own serving private key, sign its CSR with
// SignServingCSR instead.
func (c *CA) IssueServing(cn string, dnsNames []string, ipAddrs []net.IP, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serving key: %w", err)
	}
	der, err := c.signLeaf(&key.PublicKey, pkix.Name{CommonName: cn}, dnsNames, ipAddrs, x509.ExtKeyUsageServerAuth, validFor)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal serving key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// IssueClient mints a fresh CLIENT keypair (ExtKeyUsageClientAuth) signed by this CA,
// for a client identity the CA owns the key material of. cn becomes the certificate's
// CommonName (the authenticated user) and org its Organization (the RBAC groups). It is
// how the HA path issues the admin kubeconfig's CN=k3sm-admin, O=system:masters client
// cert from the SIGNING CA — every server reconstructs the identical signing CA, so the
// one cert authenticates kubectl against ANY apiserver (unlike a per-server static
// token). The cert carries no SANs (a client cert is identified by subject, not SAN).
func (c *CA) IssueClient(cn string, org []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}
	der, err := c.signLeaf(&key.PublicKey, pkix.Name{CommonName: cn, Organization: org}, nil, nil, x509.ExtKeyUsageClientAuth, validFor)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal client key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ServingChainTLS builds a tls.Certificate that PRESENTS the full chain
// [serving-leaf, CA] so a pinning client (VerifyPinnedChain) sees this CA in the
// peer certificates and can verify the leaf against the pinned anchor without first
// possessing the CA out of band. It is how the bootstrap supervisor's TLS listener
// is configured so a joining node's CA-hash pin succeeds.
func (c *CA) ServingChainTLS(cn string, dnsNames []string, ipAddrs []net.IP, validFor time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serving key: %w", err)
	}
	der, err := c.signLeaf(&key.PublicKey, pkix.Name{CommonName: cn}, dnsNames, ipAddrs, x509.ExtKeyUsageServerAuth, validFor)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse serving leaf: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, c.Cert.Raw}, // [leaf, CA] — present the chain for pinning
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// SignClientCSR signs csr as a CLIENT certificate (ExtKeyUsageClientAuth) with the
// authoritative subject + SANs the caller specifies, IGNORING the subject the CSR
// itself requested. The CSR contributes only its public key (proven held via its
// self-signature, which is checked). This is the issuance primitive the node-CSR
// approver uses to mint a CN=system:node:<name>, O=system:nodes identity bound to
// the authenticated bootstrap context.
func (c *CA) SignClientCSR(csr *x509.CertificateRequest, subject pkix.Name, dnsSANs []string, ipSANs []net.IP, validFor time.Duration) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify CSR self-signature: %w", err)
	}
	der, err := c.signLeaf(csr.PublicKey, subject, dnsSANs, ipSANs, x509.ExtKeyUsageClientAuth, validFor)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SignServingCSR signs csr as a SERVING certificate (ExtKeyUsageServerAuth) with the
// caller's authoritative subject + SANs, ignoring the CSR's requested subject. It is
// how the bootstrap server mints a joining node's kubelet-serving cert from the
// cluster CA (so the apiserver, started --kubelet-certificate-authority=<cluster CA>,
// verifies it and remote exec/logs are not MITM-able) while the node keeps its own
// serving private key.
func (c *CA) SignServingCSR(csr *x509.CertificateRequest, subject pkix.Name, dnsSANs []string, ipSANs []net.IP, validFor time.Duration) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify CSR self-signature: %w", err)
	}
	der, err := c.signLeaf(csr.PublicKey, subject, dnsSANs, ipSANs, x509.ExtKeyUsageServerAuth, validFor)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// signLeaf is the shared leaf-issuance core: build the template, set the extended
// key usage, and sign with the CA key.
func (c *CA) signLeaf(pub any, subject pkix.Name, dnsSANs []string, ipSANs []net.IP, eku x509.ExtKeyUsage, validFor time.Duration) ([]byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	if validFor <= 0 {
		validFor = 365 * 24 * time.Hour
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		DNSNames:              dnsSANs,
		IPAddresses:           ipSANs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, c.Cert, pub, c.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate: %w", err)
	}
	return der, nil
}

// VerifyPinnedChain verifies that the server's TLS-presented chain (leaf-first,
// exactly cs.PeerCertificates) anchors in a CA certificate whose lowercase-hex
// SHA-256 equals pinnedHash, AND that the leaf chains to that pinned CA. It returns
// nil only then; otherwise it wraps ErrPinMismatch.
//
// This is the join client's trust primitive. The pin REPLACES the system trust
// store: the live dialer sets InsecureSkipVerify (which disables only Go's default
// verification) and supplies this callback, which re-imposes real verification
// against the token-pinned anchor. Including a copy of the genuine CA in the chain
// does not help an attacker — the leaf is verified against ONLY the pinned CA (other
// presented certs are demoted to intermediates), so a leaf the attacker signed will
// not chain to it. It is NOT insecure-skip-tls-verify.
func VerifyPinnedChain(pinnedHash string, presented []*x509.Certificate) error {
	if len(presented) == 0 {
		return fmt.Errorf("%w: empty presented chain", ErrPinMismatch)
	}
	want := strings.ToLower(strings.TrimSpace(pinnedHash))
	if want == "" {
		return fmt.Errorf("%w: empty pin", ErrPinMismatch)
	}
	var pinned *x509.Certificate
	inter := x509.NewCertPool()
	for i, crt := range presented {
		sum := sha256.Sum256(crt.Raw)
		if hex.EncodeToString(sum[:]) == want {
			pinned = crt
			continue
		}
		if i > 0 {
			inter.AddCert(crt)
		}
	}
	if pinned == nil {
		return fmt.Errorf("%w: no presented certificate matches %s", ErrPinMismatch, want)
	}
	roots := x509.NewCertPool()
	roots.AddCert(pinned)
	leaf := presented[0]
	if leaf.Equal(pinned) {
		// Degenerate: the server presented only the CA. Accept iff it is a valid
		// self-signed CA matching the pin (not a usable serving identity, but
		// internally consistent with the pin).
		if _, err := pinned.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
			return fmt.Errorf("%w: pinned CA does not self-verify: %v", ErrPinMismatch, err)
		}
		return nil
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("%w: leaf does not chain to pinned CA: %v", ErrPinMismatch, err)
	}
	return nil
}

// randomSerial returns a random 128-bit certificate serial number.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}
