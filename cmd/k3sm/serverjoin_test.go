package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// TestNodePasswordSharedAcrossServersInHA proves the datastore-backed node-password
// store: a binding written via one server's store (over the shared datastore) is
// enforced by another server's store — so the first-write-wins anti-impersonation
// guard holds across HA servers (a name bound on A cannot be re-bound with a different
// password on B). Without this, each server's in-memory store binds independently and
// anti-impersonation is voided. The Secret stores a bcrypt HASH, never the cleartext.
func TestNodePasswordSharedAcrossServersInHA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := fake.NewClientset() // one fake datastore, two stores (server A + server B)
	a := newSecretNodePasswords(cs)
	b := newSecretNodePasswords(cs)

	// A binds worker-1; B (sharing the datastore) verifies the SAME password and rejects
	// a different one.
	if err := a.Ensure(ctx, "worker-1", "pw1"); err != nil {
		t.Fatalf("A bind worker-1: %v", err)
	}
	if err := b.Ensure(ctx, "worker-1", "pw1"); err != nil {
		t.Errorf("B must see A's binding and accept the same password: %v", err)
	}
	if err := b.Ensure(ctx, "worker-1", "impersonator"); !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
		t.Errorf("B verify wrong password err = %v, want ErrNodePasswordMismatch (anti-impersonation across servers)", err)
	}

	// The stored password is a bcrypt hash, never the cleartext.
	sec, err := cs.CoreV1().Secrets(bootstrapStateNamespace).Get(ctx, "worker-1"+nodePasswordSecretSuffix, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node-password secret: %v", err)
	}
	stored := sec.Data[nodePasswordHashKey]
	if len(stored) == 0 || string(stored) == "pw1" {
		t.Errorf("node-password must be stored hashed, got %q", stored)
	}

	// First-write-wins works in the other direction too (B binds, A enforces).
	if err := b.Ensure(ctx, "worker-2", "pwB"); err != nil {
		t.Fatalf("B bind worker-2: %v", err)
	}
	if err := a.Ensure(ctx, "worker-2", "pwB"); err != nil {
		t.Errorf("A must see B's binding: %v", err)
	}
	if err := a.Ensure(ctx, "worker-2", "nope"); !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
		t.Errorf("A verify wrong password err = %v, want ErrNodePasswordMismatch", err)
	}
}

// TestAdminKubeconfigUsesClientCert proves the HA admin kubeconfig authenticates with a
// signing-CA-issued system:masters CLIENT CERT (reconstructible on every server) and
// verifies the apiserver against the cluster CA — NOT a per-server static token or
// insecure-skip — so kubectl works against ANY server.
func TestAdminKubeconfigUsesClientCert(t *testing.T) {
	t.Parallel()
	wd := t.TempDir()
	h, err := certs.EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("hierarchy: %v", err)
	}
	path := filepath.Join(wd, "admin.kubeconfig")
	if err := writeAdminClientCertKubeconfig(path, "https://10.0.0.1:6444", h); err != nil {
		t.Fatalf("write admin kubeconfig: %v", err)
	}

	cfg, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load admin kubeconfig: %v", err)
	}
	user := cfg.AuthInfos["k3sm-admin"]
	if user == nil {
		t.Fatal("admin kubeconfig missing the k3sm-admin user")
	}
	if len(user.ClientCertificateData) == 0 {
		t.Error("admin kubeconfig must use a client certificate, not a token")
	}
	if user.Token != "" {
		t.Error("admin kubeconfig must NOT carry a static bearer token")
	}

	// The client cert is O=system:masters and signed by the SIGNING CA.
	block, _ := pem.Decode(user.ClientCertificateData)
	if block == nil {
		t.Fatal("client-certificate-data is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	found := false
	for _, o := range leaf.Subject.Organization {
		if o == "system:masters" {
			found = true
		}
	}
	if !found {
		t.Errorf("client cert O = %v, want it to contain system:masters", leaf.Subject.Organization)
	}
	if err := leaf.CheckSignatureFrom(h.Signing.Cert); err != nil {
		t.Errorf("admin client cert must be signed by the signing CA: %v", err)
	}

	// The cluster verifies the apiserver via the cluster CA (not insecure-skip).
	cl := cfg.Clusters["k3sm"]
	if cl == nil {
		t.Fatal("admin kubeconfig missing the k3sm cluster")
	}
	if cl.InsecureSkipTLSVerify {
		t.Error("admin kubeconfig must NOT skip TLS verification")
	}
	if len(cl.CertificateAuthorityData) == 0 {
		t.Error("admin kubeconfig must embed the cluster CA for server verification")
	}
	if string(cl.CertificateAuthorityData) != string(h.Cluster.CertPEM) {
		t.Error("admin kubeconfig CA must be the cluster CA")
	}
}
