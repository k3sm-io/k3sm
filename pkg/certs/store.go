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
	"io/fs"
	"os"
	"path/filepath"
)

// Hierarchy is k3sm's CA PKI (DESIGN §5c). Every multi-node server holds two CAs: the
// CLUSTER CA — the serving anchor a join token pins and the issuer of kubelet-serving
// certs — and the SIGNING CA that issues system:node client certs. They are
// independent self-signed roots (the k3s server-ca / client-ca split): a compromised
// serving key cannot mint client identities.
//
// An etcd-backed HA server holds two more, the etcd SERVER CA and the etcd PEER CA
// (EnsureEtcdCAs), which anchor only etcd's client and peer TLS. Neither existing CA
// can serve as etcd's anchor: the signing CA issues every joined worker's client cert,
// so trusting it at etcd would hand every worker the whole datastore, and the cluster
// CA would be safe only while it never issues a clientAuth leaf, an invariant nothing
// enforces. k3s draws the same line (its etcd server-ca / peer-ca).
type Hierarchy struct {
	// Cluster is the cluster CA (the pinned serving anchor; --kubelet-certificate-authority).
	Cluster *CA
	// Signing is the signing CA (issues node client certs; --client-ca-file).
	Signing *CA
	// EtcdServer is the etcd server CA: the issuer and --trusted-ca-file of etcd's
	// client listener (server-client.crt) and of the etcd clients (client.crt). It is
	// nil outside the etcd HA posture.
	EtcdServer *CA
	// EtcdPeer is the etcd peer CA: the issuer and --peer-trusted-ca-file of the
	// member-to-member mutual TLS (peer-server-client.crt). It is nil outside the
	// etcd HA posture.
	EtcdPeer *CA
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

// On-disk filenames within the etcd PKI subdirectory (<PKI>/etcd, mode 0700). The
// names follow k3s's server/tls/etcd layout.
const (
	etcdDirName              = "etcd"
	etcdServerCACert         = "server-ca.crt"
	etcdServerCAKey          = "server-ca.key"
	etcdPeerCACert           = "peer-ca.crt"
	etcdPeerCAKey            = "peer-ca.key"
	etcdServerClientCert     = "server-client.crt"
	etcdServerClientKey      = "server-client.key"
	etcdPeerServerClientCert = "peer-server-client.crt"
	etcdPeerServerClientKey  = "peer-server-client.key"
	etcdClientCert           = "client.crt"
	etcdClientKey            = "client.key"
)

// Common names of the two etcd CA roots.
const (
	etcdServerCACN = "k3sm-etcd-server-ca"
	etcdPeerCACN   = "k3sm-etcd-peer-ca"
)

// EtcdPaths names every file of the etcd PKI under <PKI>/etcd. The two CA pairs are
// minted once by the first HA server (EnsureEtcdCAs) and carried to every other
// server by the bootstrap bundle; the three leaf pairs are re-issued by each server
// on every boot.
type EtcdPaths struct {
	// Dir is <PKI>/etcd, mode 0700.
	Dir string
	// ServerCACert / ServerCAKey are the etcd server CA (--trusted-ca-file).
	ServerCACert, ServerCAKey string
	// PeerCACert / PeerCAKey are the etcd peer CA (--peer-trusted-ca-file).
	PeerCACert, PeerCAKey string
	// ServerClientCert / ServerClientKey are etcd's client-listener keypair, issued
	// by the server CA with serverAuth+clientAuth (--cert-file / --key-file).
	ServerClientCert, ServerClientKey string
	// PeerServerClientCert / PeerServerClientKey are the member's peer keypair, issued
	// by the peer CA with serverAuth+clientAuth (--peer-cert-file / --peer-key-file).
	PeerServerClientCert, PeerServerClientKey string
	// ClientCert / ClientKey are the etcd client identity (clientAuth only) the
	// apiserver and the local admin client present, issued by the server CA.
	ClientCert, ClientKey string
}

// EtcdCertPaths returns the etcd PKI file layout under workDir's PKI directory. It
// creates nothing.
func EtcdCertPaths(workDir string) EtcdPaths {
	dir := filepath.Join(PKIDir(workDir), etcdDirName)
	j := func(name string) string { return filepath.Join(dir, name) }
	return EtcdPaths{
		Dir:                  dir,
		ServerCACert:         j(etcdServerCACert),
		ServerCAKey:          j(etcdServerCAKey),
		PeerCACert:           j(etcdPeerCACert),
		PeerCAKey:            j(etcdPeerCAKey),
		ServerClientCert:     j(etcdServerClientCert),
		ServerClientKey:      j(etcdServerClientKey),
		PeerServerClientCert: j(etcdPeerServerClientCert),
		PeerServerClientKey:  j(etcdPeerServerClientKey),
		ClientCert:           j(etcdClientCert),
		ClientKey:            j(etcdClientKey),
	}
}

// PKIDir returns the directory under the server work dir that holds the CA
// hierarchy (certs world-readable 0644, keys 0600).
func PKIDir(workDir string) string { return filepath.Join(workDir, "tls") }

// ClusterCACertPath / SigningCACertPath are the CA certificate paths the apiserver's
// --kubelet-certificate-authority / --client-ca-file flags point at.
func ClusterCACertPath(workDir string) string { return filepath.Join(PKIDir(workDir), clusterCACert) }
func SigningCACertPath(workDir string) string { return filepath.Join(PKIDir(workDir), signingCACert) }

// ClusterCAKeyPath / SigningCAKeyPath are the CA PRIVATE KEY paths (0600). They are
// exported so a caller can NAME a key file — to os.Stat it, or to report on it —
// without re-joining the layout. Nothing outside EnsureHierarchy /
// ReconcileImportedHierarchy should ever OPEN them: pin verification needs only the
// certificate.
func ClusterCAKeyPath(workDir string) string { return filepath.Join(PKIDir(workDir), clusterCAKey) }
func SigningCAKeyPath(workDir string) string { return filepath.Join(PKIDir(workDir), signingCAKey) }

// APIServerServingCertPath / APIServerServingKeyPath are the multi-node apiserver's
// cluster-CA-signed serving keypair under the PKI dir (--tls-cert-file /
// --tls-private-key-file). The mesh server re-issues them on every boot; a
// single-node server self-signs into its own cert dir instead, so these need not exist.
//
// NOT to be confused with the file of the same basename under executor's
// APIServerCertDir (<workDir>/apiserver-certs/apiserver.crt): that one is the
// apiserver's OWN self-signed material, is also the controller-manager's
// --root-ca-file and every pod's projected kube-root-ca.crt, and is deliberately
// OUT of rotation scope (replacing it is a cluster-wide trust event). This one is a
// leaf re-issued from the cluster CA on every boot — rotating it is routine. The two
// resolve to different directories; the presence of THIS file is what distinguishes a
// mesh server from a single-node one.
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

// ErrIncompleteHierarchy reports a DAMAGED hierarchy: a CA certificate present
// without its private key or a private key without its certificate (the half-present
// pair ensureCA also refuses), or a PKI entry that is not a regular file. Distinct
// from ErrNoHierarchy so a caller can tell "nothing here" (wrong work dir / missing
// privilege) from "the PKI on this host is damaged". Compare with errors.Is.
var ErrIncompleteHierarchy = errors.New("certs: damaged CA hierarchy (a CA certificate without its private key, a CA private key without its certificate, or a PKI path that is not a regular file)")

// LoadCAPins reads ONLY the two CA CERTIFICATES from workDir's PKI directory and
// returns their PinHash values (the lowercase-hex SHA-256 of the certificate DER that
// a K10 join token pins). It is the read-only counterpart of EnsureHierarchy:
//
//   - it CREATES NOTHING — an absent hierarchy is ErrNoHierarchy, never a freshly
//     minted CA, and no directory is made;
//   - it never OPENS a CA private key — the keys are os.Lstat'ed only, solely to reject
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
//
// Both paths are LSTAT'ed and required to be REGULAR files. A symlink in the PKI dir
// is never legitimate (EnsureHierarchy/ReconcileImportedHierarchy only ever create
// regular files), and following one would let a planted link redirect this — frequently root — read at
// an arbitrary file, or point the key path at some unrelated existing file and make
// ErrIncompleteHierarchy unreachable for a hierarchy that is in fact half-present.
func caPin(certPath, keyPath string) (string, error) {
	if err := statRegular(certPath, ErrNoHierarchy); err != nil {
		return "", err
	}
	if err := statRegular(keyPath, ErrIncompleteHierarchy); err != nil {
		return "", err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", certPath, err)
	}
	pin, err := CertPin(certPEM)
	if err != nil {
		return "", fmt.Errorf("%s: %w", certPath, err)
	}
	return pin, nil
}

// statRegular lstats path and requires a regular file, reporting absence as the
// caller's sentinel (which file is missing means different things) and a non-regular
// entry as a damaged hierarchy. A stat error that is neither — EACCES on the PKI dir,
// typically a forgotten sudo — is returned wrapped so errors.Is(err, os.ErrPermission)
// still holds and the CLI can offer the same remedy as an absent hierarchy.
func statRegular(path string, absent error) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s is absent", absent, path)
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrIncompleteHierarchy, path)
	}
	return nil
}

// CertPin returns the lowercase-hex SHA-256 of a PEM-encoded certificate's DER — the
// same value CA.PinHash returns, computed without the private key.
//
// It is exported because a node holds its cluster CA as PEM and nothing else: the
// join token that first carried the pin is TTL-bounded and deliberately not
// retained, so any later pinned dial (the mesh-endpoint refresh) has to re-derive
// the anchor from the persisted certificate.
func CertPin(certPEM []byte) (string, error) {
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

// EnsureEtcdCAs loads the etcd server and peer CAs from <PKI>/etcd, creating and
// persisting them on first call (idempotent across restarts; certs 0644, keys 0600,
// the directory 0700). They are self-signed roots distinct from the cluster and
// signing CAs and from each other. Like EnsureHierarchy it refuses a half-present
// pair rather than silently re-minting, which would invalidate every etcd member's
// certificates. Only the etcd HA posture calls it; a joining server finds the pairs
// already installed by ReconcileImportedHierarchy from the bootstrap bundle and so
// LOADS the identical CAs.
func EnsureEtcdCAs(workDir string) (server, peer *CA, err error) {
	dir, err := ensureEtcdDir(workDir)
	if err != nil {
		return nil, nil, err
	}
	server, err = ensureCA(dir, etcdServerCACert, etcdServerCAKey, etcdServerCACN)
	if err != nil {
		return nil, nil, fmt.Errorf("etcd server CA: %w", err)
	}
	peer, err = ensureCA(dir, etcdPeerCACert, etcdPeerCAKey, etcdPeerCACN)
	if err != nil {
		return nil, nil, fmt.Errorf("etcd peer CA: %w", err)
	}
	return server, peer, nil
}

// ensureEtcdDir creates <PKI>/etcd (the PKI dir 0755 as EnsureHierarchy makes it, the
// etcd subdirectory 0700) and returns its path. An existing entry that is not a
// directory is refused.
func ensureEtcdDir(workDir string) (string, error) {
	if err := os.MkdirAll(PKIDir(workDir), 0o755); err != nil {
		return "", fmt.Errorf("create PKI dir: %w", err)
	}
	dir := EtcdCertPaths(workDir).Dir
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("create etcd PKI dir: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("stat etcd PKI dir: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("certs: etcd PKI dir %s is not a directory", dir)
	}
	return dir, nil
}

// caSpec is one CA keypair of the hierarchy: its id (for reports), the directory it
// lives in, its file names there, and the Hierarchy field that holds it in memory.
type caSpec struct {
	id string
	// dir returns the keypair's directory under workDir; it creates nothing.
	dir func(workDir string) string
	// ensureDir creates the keypair's directory with its mode (the PKI dir 0755, the
	// etcd subdirectory 0700) and returns its path.
	ensureDir func(workDir string) (string, error)
	certFile  string
	keyFile   string
	ca        func(*Hierarchy) *CA
}

// caSpecs is the whole CA hierarchy, one row per CA, in install order. Every walk over
// the on-disk hierarchy (MissingOnDisk, ReconcileImportedHierarchy) goes through
// it, so a CA is never added to one walk and forgotten by another.
var caSpecs = []caSpec{
	{id: "cluster", dir: PKIDir, ensureDir: ensurePKIDir, certFile: clusterCACert, keyFile: clusterCAKey,
		ca: func(h *Hierarchy) *CA { return h.Cluster }},
	{id: "signing", dir: PKIDir, ensureDir: ensurePKIDir, certFile: signingCACert, keyFile: signingCAKey,
		ca: func(h *Hierarchy) *CA { return h.Signing }},
	{id: "etcd-server", dir: etcdPKIDir, ensureDir: ensureEtcdDir, certFile: etcdServerCACert, keyFile: etcdServerCAKey,
		ca: func(h *Hierarchy) *CA { return h.EtcdServer }},
	{id: "etcd-peer", dir: etcdPKIDir, ensureDir: ensureEtcdDir, certFile: etcdPeerCACert, keyFile: etcdPeerCAKey,
		ca: func(h *Hierarchy) *CA { return h.EtcdPeer }},
}

// etcdPKIDir returns <PKI>/etcd; it creates nothing.
func etcdPKIDir(workDir string) string { return EtcdCertPaths(workDir).Dir }

// ensurePKIDir creates the PKI dir (0755, as EnsureHierarchy makes it) and returns it.
func ensurePKIDir(workDir string) (string, error) {
	dir := PKIDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create PKI dir: %w", err)
	}
	return dir, nil
}

// hierarchyComplete reports whether h carries every CA of the table.
func hierarchyComplete(h *Hierarchy) bool {
	if h == nil {
		return false
	}
	for _, spec := range caSpecs {
		if spec.ca(h) == nil {
			return false
		}
	}
	return true
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
