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
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// parseFirstCert parses the first CERTIFICATE PEM block of certPEM.
func parseFirstCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// newTestHierarchy builds an in-memory four-CA hierarchy (distinct cluster, signing,
// etcd server and etcd peer roots) for the bundle tests.
func newTestHierarchy(t *testing.T) *Hierarchy {
	t.Helper()
	mk := func(cn string) *CA {
		ca, err := NewCA(cn)
		if err != nil {
			t.Fatalf("%s: %v", cn, err)
		}
		return ca
	}
	return &Hierarchy{
		Cluster:    mk("k3sm-cluster-ca"),
		Signing:    mk("k3sm-signing-ca"),
		EtcdServer: mk(etcdServerCACN),
		EtcdPeer:   mk(etcdPeerCACN),
	}
}

// TestHierarchyMarshalUnmarshalRoundTrip proves the bundle plaintext round-trips: the
// CA PEMs Marshal emits Unmarshal back into a hierarchy with the IDENTICAL pins,
// and the reconstructed signing CA still issues a cert the original verifies (the keys,
// not just the certs, survived). This is the plaintext the AES-256-GCM bundle seals.
func TestHierarchyMarshalUnmarshalRoundTrip(t *testing.T) {
	src := newTestHierarchy(t)
	data, err := src.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var dst Hierarchy
	if err := dst.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dst.Cluster.PinHash() != src.Cluster.PinHash() {
		t.Errorf("cluster pin %q != source %q", dst.Cluster.PinHash(), src.Cluster.PinHash())
	}
	if dst.Signing.PinHash() != src.Signing.PinHash() {
		t.Errorf("signing pin %q != source %q", dst.Signing.PinHash(), src.Signing.PinHash())
	}

	// The reconstructed signing key still issues a client cert the SOURCE signing CA
	// verifies — proving the private key (not only the cert) round-tripped.
	certPEM, _, err := dst.Signing.IssueClient("k3sm-admin", []string{"system:masters"}, time.Hour)
	if err != nil {
		t.Fatalf("issue client from reconstructed signing CA: %v", err)
	}
	leaf := parseFirstCert(t, certPEM)
	if err := leaf.CheckSignatureFrom(src.Signing.Cert); err != nil {
		t.Errorf("client cert from reconstructed signing CA must verify against the source CA: %v", err)
	}

	// A version mismatch is rejected (tamper-evident schema).
	bad, err := json.Marshal(marshalledHierarchy{
		SchemaVersion:    999,
		ClusterCACertPEM: src.Cluster.CertPEM,
		ClusterCAKeyPEM:  src.Cluster.KeyPEM,
		SigningCACertPEM: src.Signing.CertPEM,
		SigningCAKeyPEM:  src.Signing.KeyPEM,
	})
	if err != nil {
		t.Fatalf("marshal bad-version: %v", err)
	}
	if err := (&Hierarchy{}).Unmarshal(bad); err == nil {
		t.Error("Unmarshal must reject an unsupported schema version")
	}
}

// TestImportedHierarchyThenEnsureLoads proves the HA import-then-load primitive:
// ReconcileImportedHierarchy into an empty work dir lays down the four CA keypairs
// (keys 0600, the etcd pairs in a 0700 subdirectory), and a SUBSEQUENT EnsureHierarchy
// / EnsureEtcdCAs LOADS them — returning the IDENTICAL pins instead of minting fresh,
// divergent CAs. It also confirms an import never replaces an existing CA: a different
// hierarchy is refused as ErrHierarchyDiverged.
func TestImportedHierarchyThenEnsureLoads(t *testing.T) {
	src := newTestHierarchy(t)
	wd := t.TempDir()

	if err := ReconcileImportedHierarchy(wd, src); err != nil {
		t.Fatalf("import hierarchy: %v", err)
	}
	ep := EtcdCertPaths(wd)
	for _, f := range []string{
		filepath.Join(PKIDir(wd), clusterCAKey), filepath.Join(PKIDir(wd), signingCAKey),
		ep.ServerCAKey, ep.PeerCAKey,
	} {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600", f, info.Mode().Perm())
		}
	}
	if info, err := os.Stat(ep.Dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("etcd PKI dir: stat err %v, mode %v, want 0700", err, info)
	}

	loaded, err := EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("ensure (load imported): %v", err)
	}
	if loaded.Cluster.PinHash() != src.Cluster.PinHash() || loaded.Signing.PinHash() != src.Signing.PinHash() {
		t.Error("EnsureHierarchy after the import must LOAD the imported CAs (identical pins), not mint fresh ones")
	}
	eServer, ePeer, err := EnsureEtcdCAs(wd)
	if err != nil {
		t.Fatalf("ensure etcd CAs (load imported): %v", err)
	}
	if eServer.PinHash() != src.EtcdServer.PinHash() || ePeer.PinHash() != src.EtcdPeer.PinHash() {
		t.Error("EnsureEtcdCAs after the import must LOAD the imported etcd CAs (identical pins)")
	}

	// A second import of a different hierarchy into a dir that already has the CAs
	// is refused (no silent rebase), the refusal names the CA and both pins and is
	// machine-checkable as ErrHierarchyDiverged, and the incumbent CA is left
	// byte-for-byte intact — a refusal that had already truncated the file would
	// have destroyed the trust it exists to protect.
	before, err := os.ReadFile(filepath.Join(PKIDir(wd), clusterCACert))
	if err != nil {
		t.Fatalf("read the incumbent CA: %v", err)
	}
	other := newTestHierarchy(t)
	err = ReconcileImportedHierarchy(wd, other)
	if err == nil {
		t.Fatal("an import must refuse to replace an existing CA")
	}
	if !errors.Is(err, ErrHierarchyDiverged) {
		t.Errorf("refusal %v must wrap ErrHierarchyDiverged", err)
	}
	for _, want := range []string{"cluster CA", src.Cluster.PinHash(), other.Cluster.PinHash()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q must contain %q", err, want)
		}
	}
	after, err := os.ReadFile(filepath.Join(PKIDir(wd), clusterCACert))
	if err != nil {
		t.Fatalf("read the CA after the refusal: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the refused write modified the incumbent CA")
	}
}
