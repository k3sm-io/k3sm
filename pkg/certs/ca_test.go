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
	"crypto/rsa"
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
	h1, err := EnsureHierarchy(wd, RoleMintAuthority, PostureKine)
	if err != nil {
		t.Fatalf("ensure (create): %v", err)
	}
	if h1.Cluster.PinHash() == h1.Signing.PinHash() {
		t.Error("cluster and signing CA must be distinct")
	}
	h2, err := EnsureHierarchy(wd, RoleMintAuthority, PostureKine)
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

// TestLeafKeyUsageFollowsKeyType pins the leaf key usage per key type: key
// encipherment only for RSA, digital signature for every key.
func TestLeafKeyUsageFollowsKeyType(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		pub  any
		want x509.KeyUsage
	}{
		{"ecdsa signs only", &ec.PublicKey, x509.KeyUsageDigitalSignature},
		{"rsa signs and enciphers", &rk.PublicKey, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := leafKeyUsage(tc.pub); got != tc.want {
				t.Errorf("leafKeyUsage = %b, want %b", got, tc.want)
			}
		})
	}
}
