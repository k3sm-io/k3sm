package certs

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadCARoundTrip confirms a CA survives a PEM persist/reload (the form the
// server writes to disk and reloads on the next boot), keeping the same pin.
func TestLoadCARoundTrip(t *testing.T) {
	ca, err := NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Error("CA cert must have IsCA set")
	}
	reloaded, err := LoadCA(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}
	if reloaded.PinHash() != ca.PinHash() {
		t.Errorf("reloaded pin %q != original %q", reloaded.PinHash(), ca.PinHash())
	}
	// The reloaded key still signs leaves the original CA verifies.
	certPEM, keyPEM, err := reloaded.IssueServing("svc", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("issue serving: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("leaf from reloaded CA must verify against the original CA: %v", err)
	}
	if len(keyPEM) == 0 {
		t.Error("IssueServing returned an empty key")
	}
}

// TestEnsureHierarchy checks the two-CA hierarchy is created on first call,
// persisted, and reloaded identically (stable pins so issued node certs stay valid
// across a server restart), with the keys written 0600.
func TestEnsureHierarchy(t *testing.T) {
	wd := t.TempDir()
	h1, err := EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("ensure (create): %v", err)
	}
	if h1.Cluster.PinHash() == h1.Signing.PinHash() {
		t.Error("cluster and signing CA must be distinct")
	}
	h2, err := EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("ensure (reload): %v", err)
	}
	if h1.Cluster.PinHash() != h2.Cluster.PinHash() || h1.Signing.PinHash() != h2.Signing.PinHash() {
		t.Error("EnsureHierarchy must be stable across calls (not regenerate)")
	}
	for _, f := range []string{clusterCAKey, signingCAKey} {
		info, err := os.Stat(filepath.Join(PKIDir(wd), f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600 (CA key must not be world-readable)", f, info.Mode().Perm())
		}
	}
}
