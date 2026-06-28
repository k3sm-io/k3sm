package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// serverSecretPath is where the server-bootstrap secret (the CA-bundle endpoint
// credential + the bundle's KDF passphrase) is persisted, 0600, under the work dir.
func serverSecretPath(workDir string) string { return filepath.Join(workDir, "server-token") }

// adminKubeconfigPath is the HA admin kubeconfig (a signing-CA-issued system:masters
// client cert, usable against any server), distinct from the executor's loopback token
// kubeconfig the in-process components keep.
func adminKubeconfigPath(workDir string) string { return filepath.Join(workDir, "admin.kubeconfig") }

// importServerCABundle is the FAIL-CLOSED HA server-join: it fetches the existing
// server's AES-256-GCM CA bundle over a CA-pinned TLS connection, decrypts it with the
// server token's secret, and writes the reconstructed cluster + signing CA PEMs under
// this server's PKI dir — so the subsequent certs.EnsureHierarchy LOADS the IDENTICAL
// CAs. Any failure returns an error (the caller halts bring-up); it NEVER falls through
// to minting fresh, divergent CAs. It also records the server secret locally so this
// server's own bundle endpoint can seal + serve once it is an equal member.
func importServerCABundle(ctx context.Context, opts serverOptions, logger *slog.Logger) error {
	tok, err := bootstrap.ParseServerToken(opts.token)
	if err != nil {
		return fmt.Errorf("parse server token: %w", err)
	}
	bootstrapURL := fmt.Sprintf("https://%s:%d", opts.joinServer, bootstrapPort)
	logger.Info("HA server-join: importing the identical-CA bundle from the existing server", "server", bootstrapURL)
	if err := bootstrap.ImportCABundle(ctx, bootstrap.ServerJoinOptions{
		Server:  bootstrapURL,
		Token:   opts.token,
		WorkDir: opts.workDir,
	}); err != nil {
		return err
	}
	if err := bootstrap.SaveServerSecret(serverSecretPath(opts.workDir), tok.Secret); err != nil {
		return err
	}
	logger.Info("HA server-join: reconstructed the identical cluster + signing CAs from the bundle")
	return nil
}

// liveBundleSource implements bootstrap.BundleSource by sealing the live in-memory
// hierarchy on demand (a fresh salt + nonce per fetch; all decrypt to the same plaintext
// under the same secret). The server always holds the hierarchy after EnsureHierarchy,
// so serving needs no datastore round-trip.
type liveBundleSource struct {
	hierarchy *certs.Hierarchy
	secret    string
}

// SealedBundle marshals the hierarchy and AES-256-GCM-seals it under the server secret.
func (b *liveBundleSource) SealedBundle(_ context.Context) ([]byte, error) {
	plaintext, err := b.hierarchy.Marshal()
	if err != nil {
		return nil, err
	}
	return bootstrap.SealBundle(b.secret, plaintext)
}

// bootstrapStateNamespace / *Secret* names: k3sm's datastore-backed bootstrap state
// lives as kube-system Secrets, which ride the shared Postgres in HA (the k3s
// bootstrap-key model). A name bound on server A is therefore visible on server B.
const (
	bootstrapStateNamespace   = "kube-system"
	bootstrapBundleSecretName = "k3sm-bootstrap"
	nodePasswordSecretSuffix  = ".node-password.k3sm"
	nodePasswordHashKey       = "hash"
)

// publishBootstrapBundle stores the sealed CA bundle in the shared datastore as a
// kube-system Secret (the k3s bootstrap-key model) — durability + the source of record.
// Idempotent: the first server publishes it; subsequent calls tolerate AlreadyExists so
// the stored envelope stays stable. Best-effort at the call site (the live endpoint
// seals from the in-memory hierarchy, so serving does not depend on this).
func publishBootstrapBundle(ctx context.Context, cs kubernetes.Interface, sealed []byte) error {
	_, err := cs.CoreV1().Secrets(bootstrapStateNamespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: bootstrapStateNamespace, Name: bootstrapBundleSecretName},
		Data:       map[string][]byte{"bundle": sealed},
	}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// secretNodePasswords is a datastore-backed bootstrap.NodePasswordStore: each node's
// bcrypt-hashed node-password is a kube-system Secret (mirroring k3s's
// <node>.node-password.k3s), so the first-write-wins anti-impersonation binding is
// SHARED across HA servers (a name bound on server A is enforced on server B — both read
// the one Postgres). The per-process MemoryNodePasswords binds independently per server,
// which voids anti-impersonation under HA.
type secretNodePasswords struct {
	secrets corev1client.SecretInterface
}

// newSecretNodePasswords builds the datastore-backed node-password store over the
// kube-system Secrets of cs.
func newSecretNodePasswords(cs kubernetes.Interface) *secretNodePasswords {
	return &secretNodePasswords{secrets: cs.CoreV1().Secrets(bootstrapStateNamespace)}
}

// Ensure binds nodeName→hash(password) on first sight (Create) and verifies on every
// subsequent call (constant-time bcrypt). A Create that races another server resolves to
// AlreadyExists → it re-reads and verifies, so the binding is first-write-wins across the
// shared datastore.
func (s *secretNodePasswords) Ensure(ctx context.Context, nodeName, password string) error {
	if nodeName == "" || password == "" {
		return fmt.Errorf("bootstrap: node-password Ensure needs a non-empty name and password")
	}
	name := nodeName + nodePasswordSecretSuffix
	sec, err := s.secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		hash, herr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if herr != nil {
			return fmt.Errorf("hash node-password: %w", herr)
		}
		_, cerr := s.secrets.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: bootstrapStateNamespace, Name: name},
			Data:       map[string][]byte{nodePasswordHashKey: hash},
		}, metav1.CreateOptions{})
		if cerr == nil {
			return nil // we bound it (first write wins)
		}
		if !apierrors.IsAlreadyExists(cerr) {
			return fmt.Errorf("create node-password secret: %w", cerr)
		}
		// Raced with another server; fall through to verify against the winner.
		sec, err = s.secrets.Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return fmt.Errorf("get node-password secret: %w", err)
	}
	if bcrypt.CompareHashAndPassword(sec.Data[nodePasswordHashKey], []byte(password)) != nil {
		return bootstrap.ErrNodePasswordMismatch
	}
	return nil
}

// writeAdminClientCertKubeconfig writes a 0600 admin kubeconfig authenticated by a
// signing-CA-issued CN=k3sm-admin, O=system:masters CLIENT CERT and verifying the
// apiserver against the cluster CA. Because every HA server reconstructs the identical
// signing + cluster CAs, the one kubeconfig works against ANY server's apiserver — so
// kubectl survives a server death without re-pointing, unlike a per-server static token.
func writeAdminClientCertKubeconfig(path, server string, h *certs.Hierarchy) error {
	certPEM, keyPEM, err := h.Signing.IssueClient("k3sm-admin", []string{"system:masters"}, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("issue admin client cert: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %q
    certificate-authority-data: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm-admin
current-context: k3sm
users:
- name: k3sm-admin
  user:
    client-certificate-data: %s
    client-key-data: %s
`,
		server,
		b64(h.Cluster.CertPEM),
		b64(certPEM),
		b64(keyPEM),
	)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write admin kubeconfig: %w", err)
	}
	return nil
}
