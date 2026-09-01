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
	"io/fs"
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

// newTestHierarchy builds an in-memory two-CA hierarchy (distinct cluster + signing
// roots) for the bundle tests.
func newTestHierarchy(t *testing.T) *Hierarchy {
	t.Helper()
	cluster, err := NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signing, err := NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	return &Hierarchy{Cluster: cluster, Signing: signing}
}

// TestHierarchyMarshalUnmarshalRoundTrip proves the bundle plaintext round-trips: the
// four CA PEMs Marshal emits Unmarshal back into a hierarchy with the IDENTICAL pins,
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

// TestWriteHierarchyThenEnsureLoads proves the HA import-then-load primitive: WriteHierarchy
// lays down the four CA PEMs (keys 0600), and a SUBSEQUENT EnsureHierarchy LOADS them —
// returning the IDENTICAL pins instead of minting fresh, divergent CAs. It also confirms
// WriteHierarchy refuses to overwrite an existing CA (an import is a first-write).
func TestWriteHierarchyThenEnsureLoads(t *testing.T) {
	src := newTestHierarchy(t)
	wd := t.TempDir()

	if err := WriteHierarchy(wd, src); err != nil {
		t.Fatalf("write hierarchy: %v", err)
	}
	for _, f := range []string{clusterCAKey, signingCAKey} {
		info, err := os.Stat(filepath.Join(PKIDir(wd), f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600", f, info.Mode().Perm())
		}
	}

	loaded, err := EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("ensure (load imported): %v", err)
	}
	if loaded.Cluster.PinHash() != src.Cluster.PinHash() || loaded.Signing.PinHash() != src.Signing.PinHash() {
		t.Error("EnsureHierarchy after WriteHierarchy must LOAD the imported CAs (identical pins), not mint fresh ones")
	}

	// A second write into a dir that already has the CAs is refused (no silent
	// rebase), the refusal names the file and is machine-checkable as fs.ErrExist
	// (the kernel's O_EXCL, not a stat-then-write), and the incumbent CA is left
	// byte-for-byte intact — a refusal that had already truncated the file would
	// have destroyed the trust it exists to protect.
	before, err := os.ReadFile(filepath.Join(PKIDir(wd), clusterCACert))
	if err != nil {
		t.Fatalf("read the incumbent CA: %v", err)
	}
	err = WriteHierarchy(wd, newTestHierarchy(t))
	if err == nil {
		t.Fatal("WriteHierarchy must refuse to overwrite an existing CA")
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Errorf("refusal %v must wrap fs.ErrExist", err)
	}
	for _, want := range []string{clusterCACert, "refusing to overwrite an existing CA"} {
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
