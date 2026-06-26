package certs

import (
	"fmt"
	"os"
	"path/filepath"
)

// Hierarchy is k3sm's two-CA PKI (DESIGN §5c, docs/m3-plan.md): the CLUSTER CA — the
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

// Cluster/Signing CA on-disk filenames within the PKI dir.
const (
	clusterCACert = "cluster-ca.crt"
	clusterCAKey  = "cluster-ca.key"
	signingCACert = "signing-ca.crt"
	signingCAKey  = "signing-ca.key"
)

// PKIDir returns the directory under the server work dir that holds the CA
// hierarchy (certs world-readable 0644, keys 0600).
func PKIDir(workDir string) string { return filepath.Join(workDir, "tls") }

// ClusterCACertPath / SigningCACertPath are the CA certificate paths the apiserver's
// --kubelet-certificate-authority / --client-ca-file flags point at.
func ClusterCACertPath(workDir string) string { return filepath.Join(PKIDir(workDir), clusterCACert) }
func SigningCACertPath(workDir string) string { return filepath.Join(PKIDir(workDir), signingCACert) }

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
