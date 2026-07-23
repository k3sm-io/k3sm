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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Hierarchy is k3sm's two-CA PKI (DESIGN §5c): the CLUSTER CA — the
// serving anchor a join token pins and the issuer of kubelet-serving certs — and the
// SIGNING CA that issues system:node client certs. They are independent self-signed
// roots (the k3s server-ca / client-ca split): a compromised serving key cannot mint
// client identities.
type Hierarchy struct {
	// Cluster is the cluster CA (the pinned serving anchor; --kubelet-certificate-authority).
	Cluster *CA
	// Signing is the signing CA (issues node client certs; --client-ca-file).
	Signing *CA
}

// On-disk filenames within the PKI dir: the two CA keypairs, plus the multi-node
// apiserver serving keypair the mesh path issues from the cluster CA.
const (
	clusterCACert = "cluster-ca.crt"
	clusterCAKey  = "cluster-ca.key"
	signingCACert = "signing-ca.crt"
	signingCAKey  = "signing-ca.key"
	apiServerCert = "apiserver.crt"
	apiServerKey  = "apiserver.key"
)

// PKIDir returns the directory under the server work dir that holds the CA
// hierarchy (certs world-readable 0644, keys 0600).
func PKIDir(workDir string) string { return filepath.Join(workDir, "tls") }

// ClusterCACertPath / SigningCACertPath are the CA certificate paths the apiserver's
// --kubelet-certificate-authority / --client-ca-file flags point at.
func ClusterCACertPath(workDir string) string { return filepath.Join(PKIDir(workDir), clusterCACert) }
func SigningCACertPath(workDir string) string { return filepath.Join(PKIDir(workDir), signingCACert) }

// ClusterCAKeyPath / SigningCAKeyPath are the CA PRIVATE KEY paths (0600). They are
// exported so a caller can NAME a key file — to os.Stat it, or to report on it —
// without re-joining the layout. Nothing outside EnsureHierarchy / WriteHierarchy
// should ever OPEN them: pin verification needs only the certificate.
func ClusterCAKeyPath(workDir string) string { return filepath.Join(PKIDir(workDir), clusterCAKey) }
func SigningCAKeyPath(workDir string) string { return filepath.Join(PKIDir(workDir), signingCAKey) }

// APIServerServingCertPath / APIServerServingKeyPath are the multi-node apiserver's
// cluster-CA-signed serving keypair under the PKI dir (--tls-cert-file /
// --tls-private-key-file). The mesh server re-issues them on every boot; a
// single-node server self-signs into its own cert dir instead, so these need not exist.
func APIServerServingCertPath(workDir string) string {
	return filepath.Join(PKIDir(workDir), apiServerCert)
}
func APIServerServingKeyPath(workDir string) string {
	return filepath.Join(PKIDir(workDir), apiServerKey)
}

// ErrNoHierarchy reports that a CA CERTIFICATE is absent from the work dir's PKI
// directory — there is no hierarchy to read. It is deliberately a hard, typed failure
// rather than a mint: EnsureHierarchy CREATES and persists a fresh CA when both files
// are absent, so a read-only caller that fell through to it against the wrong work dir
// (a forgotten sudo resolves <home>/server, not /var/lib/k3sm/server) would leave a
// stray CA behind and report a pin no node trusts. Compare with errors.Is.
var ErrNoHierarchy = errors.New("certs: no CA hierarchy in the work dir's PKI directory")

// ErrIncompleteHierarchy reports that a CA certificate is present but its private key
// is not — the half-present hierarchy ensureCA also refuses. Distinct from
// ErrNoHierarchy so a caller can tell "nothing here" (wrong work dir / missing
// privilege) from "the PKI on this host is damaged". Compare with errors.Is.
var ErrIncompleteHierarchy = errors.New("certs: incomplete CA hierarchy (a CA certificate has no private key)")

// LoadCAPins reads ONLY the two CA CERTIFICATES from workDir's PKI directory and
// returns their PinHash values (the lowercase-hex SHA-256 of the certificate DER that
// a K10 join token pins). It is the read-only counterpart of EnsureHierarchy:
//
//   - it CREATES NOTHING — an absent hierarchy is ErrNoHierarchy, never a freshly
//     minted CA, and no directory is made;
//   - it never OPENS a CA private key — the keys are os.Stat'ed only, solely to reject
//     a half-present hierarchy (ErrIncompleteHierarchy), so it works against keys the
//     caller cannot read.
//
// It is what `k3sm certificate rotate` verifies the hierarchy with before and after a
// control-plane restart.
func LoadCAPins(workDir string) (cluster, signing string, err error) {
	cluster, err = caPin(ClusterCACertPath(workDir), ClusterCAKeyPath(workDir))
	if err != nil {
		return "", "", fmt.Errorf("cluster CA: %w", err)
	}
	signing, err = caPin(SigningCACertPath(workDir), SigningCAKeyPath(workDir))
	if err != nil {
		return "", "", fmt.Errorf("signing CA: %w", err)
	}
	return cluster, signing, nil
}

// caPin returns the pin of the certificate at certPath, having first confirmed its key
// exists at keyPath. The key is STATTED ONLY — never opened, never parsed.
func caPin(certPath, keyPath string) (string, error) {
	if _, err := os.Stat(certPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s is absent", ErrNoHierarchy, certPath)
		}
		return "", fmt.Errorf("stat %s: %w", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s is absent", ErrIncompleteHierarchy, keyPath)
		}
		return "", fmt.Errorf("stat %s: %w", keyPath, err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", certPath, err)
	}
	pin, err := certPin(certPEM)
	if err != nil {
		return "", fmt.Errorf("%s: %w", certPath, err)
	}
	return pin, nil
}

// certPin returns the lowercase-hex SHA-256 of a PEM-encoded certificate's DER — the
// same value CA.PinHash returns, computed without the private key.
func certPin(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("certs: no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// EnsureHierarchy loads the cluster + signing CAs from the work dir's PKI directory,
// creating and persisting them on first call (idempotent across restarts). CA keys
// are written 0600; certs 0644. It fails fast on a partially-written hierarchy rather
// than silently regenerating (which would invalidate every issued node cert).
func EnsureHierarchy(workDir string) (*Hierarchy, error) {
	dir := PKIDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create PKI dir: %w", err)
	}
	cluster, err := ensureCA(dir, clusterCACert, clusterCAKey, "k3sm-cluster-ca")
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	signing, err := ensureCA(dir, signingCACert, signingCAKey, "k3sm-signing-ca")
	if err != nil {
		return nil, fmt.Errorf("signing CA: %w", err)
	}
	return &Hierarchy{Cluster: cluster, Signing: signing}, nil
}

// WriteHierarchy writes h's four CA PEMs into the work dir's PKI directory (certs
// 0644, keys 0600) — the inverse of EnsureHierarchy's load. The HA server-join path
// calls it AFTER decrypting the AES-256-GCM bootstrap bundle and BEFORE EnsureHierarchy,
// so EnsureHierarchy then LOADS the IDENTICAL cluster + signing CAs instead of minting
// fresh, divergent ones (which would split cluster trust). It REFUSES to overwrite any
// existing CA file: a server that already has a hierarchy must never be silently
// re-based onto another's — the import is a first-write, not a replace.
func WriteHierarchy(workDir string, h *Hierarchy) error {
	if h == nil || h.Cluster == nil || h.Signing == nil {
		return fmt.Errorf("certs: write hierarchy: cluster and signing CA are required")
	}
	dir := PKIDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create PKI dir: %w", err)
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{clusterCACert, h.Cluster.CertPEM, 0o644},
		{clusterCAKey, h.Cluster.KeyPEM, 0o600},
		{signingCACert, h.Signing.CertPEM, 0o644},
		{signingCAKey, h.Signing.KeyPEM, 0o600},
	}
	for _, f := range files {
		p := filepath.Join(dir, f.name)
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("certs: write hierarchy: %s already exists (refusing to overwrite an existing CA)", f.name)
		}
		if err := os.WriteFile(p, f.data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

// ensureCA loads the CA at dir/<certFile>+<keyFile>, or creates + persists a new one
// with the given common name when neither exists. A half-present pair is an error.
func ensureCA(dir, certFile, keyFile, commonName string) (*CA, error) {
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", certFile, err)
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", keyFile, err)
		}
		return LoadCA(certPEM, keyPEM)
	case certErr == nil || keyErr == nil:
		return nil, fmt.Errorf("incomplete CA: exactly one of %s / %s is present", certFile, keyFile)
	}
	ca, err := NewCA(commonName)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.CertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", certFile, err)
	}
	if err := os.WriteFile(keyPath, ca.KeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", keyFile, err)
	}
	return ca, nil
}
