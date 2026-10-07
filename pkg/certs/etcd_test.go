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
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// poolOf returns a cert pool holding exactly the given CAs.
func poolOf(cas ...*CA) *x509.CertPool {
	p := x509.NewCertPool()
	for _, ca := range cas {
		p.AddCert(ca.Cert)
	}
	return p
}

// verifyAs verifies leafPEM against roots for the given key usage.
func verifyAs(t *testing.T, leafPEM []byte, roots *x509.CertPool, usage x509.ExtKeyUsage) error {
	t.Helper()
	_, err := parseFirstCert(t, leafPEM).Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	return err
}

// TestEtcdCAsDistinctFromClusterAndSigning proves EnsureEtcdCAs mints two self-signed
// roots that are distinct from each other and from the cluster and signing CAs, with
// the documented CNs, and lays them out under <PKI>/etcd with the documented modes.
func TestEtcdCAsDistinctFromClusterAndSigning(t *testing.T) {
	wd := t.TempDir()
	h, err := EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	server, peer, err := EnsureEtcdCAs(wd)
	if err != nil {
		t.Fatalf("EnsureEtcdCAs: %v", err)
	}

	cas := map[string]*CA{"cluster": h.Cluster, "signing": h.Signing, "etcd-server": server, "etcd-peer": peer}
	seen := map[string]string{}
	for name, ca := range cas {
		pin := ca.PinHash()
		if other, dup := seen[pin]; dup {
			t.Errorf("%s CA shares a pin with the %s CA", name, other)
		}
		seen[pin] = name
		if !ca.Cert.IsCA {
			t.Errorf("%s CA is not a CA certificate", name)
		}
		if err := ca.Cert.CheckSignatureFrom(ca.Cert); err != nil {
			t.Errorf("%s CA is not self-signed: %v", name, err)
		}
	}
	for _, etcd := range []string{"etcd-server", "etcd-peer"} {
		for _, other := range []string{"cluster", "signing", "etcd-server", "etcd-peer"} {
			if etcd == other {
				continue
			}
			if err := cas[etcd].Cert.CheckSignatureFrom(cas[other].Cert); err == nil {
				t.Errorf("%s CA must not be signed by the %s CA", etcd, other)
			}
		}
	}
	if got := server.Cert.Subject.CommonName; got != "k3sm-etcd-server-ca" {
		t.Errorf("etcd server CA CN = %q, want k3sm-etcd-server-ca", got)
	}
	if got := peer.Cert.Subject.CommonName; got != "k3sm-etcd-peer-ca" {
		t.Errorf("etcd peer CA CN = %q, want k3sm-etcd-peer-ca", got)
	}

	ep := EtcdCertPaths(wd)
	if ep.Dir != filepath.Join(PKIDir(wd), "etcd") {
		t.Errorf("etcd dir = %q, want <PKI>/etcd", ep.Dir)
	}
	modes := []struct {
		path string
		want os.FileMode
	}{
		{ep.Dir, 0o700},
		{ep.ServerCACert, 0o644},
		{ep.ServerCAKey, 0o600},
		{ep.PeerCACert, 0o644},
		{ep.PeerCAKey, 0o600},
	}
	for _, m := range modes {
		info, err := os.Stat(m.path)
		if err != nil {
			t.Fatalf("stat %s: %v", m.path, err)
		}
		if info.Mode().Perm() != m.want {
			t.Errorf("%s mode = %o, want %o", m.path, info.Mode().Perm(), m.want)
		}
	}
	// The leaf paths are named, not created (later stages mint them).
	for _, p := range []string{ep.ServerClientCert, ep.ServerClientKey, ep.PeerServerClientCert, ep.PeerServerClientKey, ep.ClientCert, ep.ClientKey} {
		if filepath.Dir(p) != ep.Dir {
			t.Errorf("%s is not under the etcd PKI dir", p)
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("EnsureEtcdCAs must not create leaf %s (stat err %v)", p, err)
		}
	}
}

// TestEnsureEtcdCAsIdempotentAndRefusesHalfPair proves a second EnsureEtcdCAs LOADS
// the persisted CAs (identical pins) and that a half-present pair is refused rather
// than silently re-minted.
func TestEnsureEtcdCAsIdempotentAndRefusesHalfPair(t *testing.T) {
	wd := t.TempDir()
	s1, p1, err := EnsureEtcdCAs(wd)
	if err != nil {
		t.Fatalf("first EnsureEtcdCAs: %v", err)
	}
	s2, p2, err := EnsureEtcdCAs(wd)
	if err != nil {
		t.Fatalf("second EnsureEtcdCAs: %v", err)
	}
	if s1.PinHash() != s2.PinHash() || p1.PinHash() != p2.PinHash() {
		t.Error("EnsureEtcdCAs must load, not regenerate, on a second call")
	}

	tests := []struct {
		name   string
		remove func(EtcdPaths) string
	}{
		{"server CA key missing", func(p EtcdPaths) string { return p.ServerCAKey }},
		{"server CA cert missing", func(p EtcdPaths) string { return p.ServerCACert }},
		{"peer CA key missing", func(p EtcdPaths) string { return p.PeerCAKey }},
		{"peer CA cert missing", func(p EtcdPaths) string { return p.PeerCACert }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			if _, _, err := EnsureEtcdCAs(wd); err != nil {
				t.Fatalf("seed: %v", err)
			}
			victim := tc.remove(EtcdCertPaths(wd))
			if err := os.Remove(victim); err != nil {
				t.Fatalf("remove %s: %v", victim, err)
			}
			if _, _, err := EnsureEtcdCAs(wd); err == nil || !strings.Contains(err.Error(), "incomplete CA") {
				t.Errorf("EnsureEtcdCAs with %s removed: err = %v, want an incomplete-CA refusal", filepath.Base(victim), err)
			}
			if _, err := os.Stat(victim); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the refusal must not re-create %s", victim)
			}
		})
	}
}

// TestIssueServerClientDualEKU proves the etcd leaves carry exactly the documented
// extended key usages: the server-client and peer-server-client leaves both
// serverAuth and clientAuth (and verify as either), client.crt clientAuth only.
func TestIssueServerClientDualEKU(t *testing.T) {
	h := newTestHierarchy(t)
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	serverClient, _, err := h.EtcdServer.IssueServerClient("etcd-server", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("issue server-client: %v", err)
	}
	peerServerClient, _, err := h.EtcdPeer.IssueServerClient("etcd-peer", nil, []net.IP{net.ParseIP("192.0.2.10")}, time.Hour)
	if err != nil {
		t.Fatalf("issue peer-server-client: %v", err)
	}
	client, _, err := h.EtcdServer.IssueClient("etcd-client", nil, time.Hour)
	if err != nil {
		t.Fatalf("issue client: %v", err)
	}

	tests := []struct {
		name     string
		leaf     []byte
		ca       *CA
		wantEKU  []x509.ExtKeyUsage
		wantSANs int
	}{
		{"server-client.crt", serverClient, h.EtcdServer, both, 2},
		{"peer-server-client.crt", peerServerClient, h.EtcdPeer, both, 1},
		{"client.crt", client, h.EtcdServer, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := parseFirstCert(t, tc.leaf)
			if !slices.Equal(leaf.ExtKeyUsage, tc.wantEKU) {
				t.Errorf("EKU = %v, want %v", leaf.ExtKeyUsage, tc.wantEKU)
			}
			if leaf.IsCA {
				t.Error("leaf must not be a CA")
			}
			if got := len(leaf.DNSNames) + len(leaf.IPAddresses); got != tc.wantSANs {
				t.Errorf("SAN count = %d, want %d", got, tc.wantSANs)
			}
			roots := poolOf(tc.ca)
			for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
				err := verifyAs(t, tc.leaf, roots, usage)
				want := slices.Contains(tc.wantEKU, usage)
				if want && err != nil {
					t.Errorf("must verify for usage %v: %v", usage, err)
				}
				if !want && err == nil {
					t.Errorf("must NOT verify for usage %v", usage)
				}
			}
		})
	}

	// The single-EKU issuers keep their single EKU (signLeaf's slice change is
	// shape-preserving for every existing caller).
	serving, _, err := h.Cluster.IssueServing("k3sm-apiserver", []string{"localhost"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue serving: %v", err)
	}
	if got := parseFirstCert(t, serving).ExtKeyUsage; !slices.Equal(got, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("IssueServing EKU = %v, want serverAuth only", got)
	}
}

// TestBundleV2RoundTripCarriesEtcdCAs proves the schema-2 bundle carries all four CA
// pairs with identical pins (and working keys), and that Marshal refuses a hierarchy
// missing any of them.
func TestBundleV2RoundTripCarriesEtcdCAs(t *testing.T) {
	src := newTestHierarchy(t)
	data, err := src.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var envelope struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.SchemaVersion != 2 {
		t.Errorf("schemaVersion = %d, want 2", envelope.SchemaVersion)
	}

	var dst Hierarchy
	if err := dst.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pairs := []struct {
		name     string
		src, dst *CA
	}{
		{"cluster", src.Cluster, dst.Cluster},
		{"signing", src.Signing, dst.Signing},
		{"etcd server", src.EtcdServer, dst.EtcdServer},
		{"etcd peer", src.EtcdPeer, dst.EtcdPeer},
	}
	for _, p := range pairs {
		if p.dst == nil {
			t.Errorf("%s CA missing after round trip", p.name)
			continue
		}
		if p.dst.PinHash() != p.src.PinHash() {
			t.Errorf("%s pin %q != source %q", p.name, p.dst.PinHash(), p.src.PinHash())
		}
		// The private key round-tripped too: a leaf from the reconstructed CA
		// verifies against the source CA.
		leafPEM, _, err := p.dst.IssueServerClient("probe", nil, nil, time.Hour)
		if err != nil {
			t.Fatalf("%s: issue from reconstructed CA: %v", p.name, err)
		}
		if err := parseFirstCert(t, leafPEM).CheckSignatureFrom(p.src.Cert); err != nil {
			t.Errorf("%s: leaf from reconstructed CA does not verify against the source: %v", p.name, err)
		}
	}

	missing := []struct {
		name string
		drop func(*Hierarchy)
	}{
		{"no etcd server CA", func(h *Hierarchy) { h.EtcdServer = nil }},
		{"no etcd peer CA", func(h *Hierarchy) { h.EtcdPeer = nil }},
		{"no cluster CA", func(h *Hierarchy) { h.Cluster = nil }},
		{"no signing CA", func(h *Hierarchy) { h.Signing = nil }},
	}
	for _, tc := range missing {
		t.Run(tc.name, func(t *testing.T) {
			h := *src
			tc.drop(&h)
			if _, err := h.Marshal(); err == nil {
				t.Error("Marshal must require all four CAs")
			}
			if err := ReconcileImportedHierarchy(t.TempDir(), &h); err == nil {
				t.Error("ReconcileImportedHierarchy must require all four CAs")
			}
		})
	}
}

// TestBundleRefusesSchemaV1WithoutWriting proves a schema-1 envelope (a server that
// predates etcd HA) is refused with the named error, leaves the receiver untouched,
// and — following the import order ImportCABundle uses (Unmarshal, then
// ReconcileImportedHierarchy only on success) — writes nothing into the target PKI dir. Other
// unknown versions keep the generic refusal.
func TestBundleRefusesSchemaV1WithoutWriting(t *testing.T) {
	const wantV1 = "unsupported schema version 1: this server predates etcd HA; every HA server must run the same release"
	src := newTestHierarchy(t)
	envelope := func(version int) []byte {
		// A v1 server emits only the cluster and signing pairs.
		data, err := json.Marshal(map[string]any{
			"schemaVersion":    version,
			"clusterCACertPEM": src.Cluster.CertPEM,
			"clusterCAKeyPEM":  src.Cluster.KeyPEM,
			"signingCACertPEM": src.Signing.CertPEM,
			"signingCAKeyPEM":  src.Signing.KeyPEM,
		})
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		return data
	}

	tests := []struct {
		name    string
		version int
		want    string
		notWant string
	}{
		{"schema 1 (predates etcd HA)", 1, wantV1, ""},
		{"schema 0", 0, "unsupported schema version 0", "predates etcd HA"},
		{"schema 3", 3, "unsupported schema version 3", "predates etcd HA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			var h Hierarchy
			err := h.Unmarshal(envelope(tc.version))
			if err == nil {
				if werr := ReconcileImportedHierarchy(wd, &h); werr != nil {
					t.Logf("write after accepted unmarshal: %v", werr)
				}
				t.Fatalf("Unmarshal must refuse schema %d", tc.version)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to contain %q", err, tc.want)
			}
			if tc.notWant != "" && strings.Contains(err.Error(), tc.notWant) {
				t.Errorf("err = %q must not contain %q", err, tc.notWant)
			}
			if h.Cluster != nil || h.Signing != nil || h.EtcdServer != nil || h.EtcdPeer != nil {
				t.Error("a refused Unmarshal must leave the receiver untouched")
			}
			if _, err := os.Stat(PKIDir(wd)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refused bundle must write nothing (PKI dir stat err %v)", err)
			}
		})
	}

	// A schema-2 envelope missing an etcd pair is refused too.
	v2 := envelope(2)
	if err := (&Hierarchy{}).Unmarshal(v2); err == nil || !strings.Contains(err.Error(), "etcd server CA") {
		t.Errorf("a v2 envelope without the etcd pairs: err = %v, want an etcd server CA refusal", err)
	}
}

// TestSigningCAClientCertRejectedByEtcdTrust proves a worker's system:node client
// cert — issued by the signing CA, which every joined worker holds one of — does not
// verify as a client against etcd's trust (the server CA, nor the peer CA), so no
// worker can reach the datastore.
func TestSigningCAClientCertRejectedByEtcdTrust(t *testing.T) {
	h := newTestHierarchy(t)
	nodeCert, _, err := h.Signing.IssueClient("system:node:x", []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatalf("issue node cert: %v", err)
	}
	// Non-vacuous: the same cert IS a valid client against the signing CA.
	if err := verifyAs(t, nodeCert, poolOf(h.Signing), x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("precondition: node cert must verify against the signing CA: %v", err)
	}
	tests := []struct {
		name  string
		roots *x509.CertPool
	}{
		{"etcd server CA (--trusted-ca-file)", poolOf(h.EtcdServer)},
		{"etcd peer CA (--peer-trusted-ca-file)", poolOf(h.EtcdPeer)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyAs(t, nodeCert, tc.roots, x509.ExtKeyUsageClientAuth); err == nil {
				t.Error("a signing-CA system:node cert must NOT verify against etcd trust")
			}
		})
	}
}

// TestEtcdClientCertRejectedByAPIServerTrust proves the reverse boundary: an etcd
// client cert (and the dual-EKU etcd leaves) do not verify against the apiserver's
// --client-ca-file (the signing CA) nor the cluster CA.
func TestEtcdClientCertRejectedByAPIServerTrust(t *testing.T) {
	h := newTestHierarchy(t)
	client, _, err := h.EtcdServer.IssueClient("etcd-client", nil, time.Hour)
	if err != nil {
		t.Fatalf("issue etcd client: %v", err)
	}
	serverClient, _, err := h.EtcdServer.IssueServerClient("etcd-server", []string{"localhost"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue etcd server-client: %v", err)
	}
	peerServerClient, _, err := h.EtcdPeer.IssueServerClient("etcd-peer", nil, []net.IP{net.ParseIP("192.0.2.10")}, time.Hour)
	if err != nil {
		t.Fatalf("issue etcd peer-server-client: %v", err)
	}
	// Non-vacuous: the etcd client cert IS a valid client against the etcd server CA.
	if err := verifyAs(t, client, poolOf(h.EtcdServer), x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("precondition: etcd client cert must verify against the etcd server CA: %v", err)
	}
	leaves := map[string][]byte{"client.crt": client, "server-client.crt": serverClient, "peer-server-client.crt": peerServerClient}
	roots := []struct {
		name string
		pool *x509.CertPool
	}{
		{"signing CA (--client-ca-file)", poolOf(h.Signing)},
		{"cluster CA", poolOf(h.Cluster)},
	}
	for leafName, leaf := range leaves {
		for _, r := range roots {
			t.Run(leafName+" vs "+r.name, func(t *testing.T) {
				if err := verifyAs(t, leaf, r.pool, x509.ExtKeyUsageClientAuth); err == nil {
					t.Errorf("an etcd-CA %s must NOT verify against the %s", leafName, r.name)
				}
			})
		}
	}
}
