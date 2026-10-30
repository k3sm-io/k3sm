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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// machOBody is a file that starts with the 64-bit Mach-O magic as an arm64
// binary stores it.
func machOBody(tag string) []byte {
	return append([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}, tag...)
}

// payloadEntry is one tar member of a test archive.
type payloadEntry struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	link     string
	// size, when set, is the header size of a member written without its
	// content (the archive ends after the header).
	size int64
}

func regEntry(name string, body []byte) payloadEntry {
	return payloadEntry{name: name, typeflag: tar.TypeReg, mode: 0o755, body: body}
}

func dirEntry(name string) payloadEntry {
	return payloadEntry{name: name, typeflag: tar.TypeDir, mode: 0o755}
}

// payloadFixture is a release archive, its manifest and its signer.
type payloadFixture struct {
	ca       *CA
	signer   *x509.Certificate
	key      *ecdsa.PrivateKey
	entries  []payloadEntry
	manifest func(*PayloadManifest)
	sign     func(manifest []byte) []byte
	archive  func([]byte) []byte
	limits   payloadLimits
}

func newPayloadFixture(t *testing.T) *payloadFixture {
	t.Helper()
	ca, err := NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ca.IssueUpdateSigner()
	if err != nil {
		t.Fatal(err)
	}
	return &payloadFixture{
		ca:     ca,
		signer: s.Cert,
		key:    s.Key,
		entries: []payloadEntry{
			regEntry("k3sm", machOBody("k3sm")),
			regEntry("k3sm-execshim", machOBody("execshim")),
			dirEntry("cp-payload/"),
			regEntry("cp-payload/kine", machOBody("kine")),
			{name: "cp-payload/etcd.version", typeflag: tar.TypeReg, mode: 0o644, body: []byte("v3.6.5\n")},
		},
		limits: defaultPayloadLimits,
	}
}

// buildArchive writes the gzip tar of entries.
func buildArchive(t *testing.T, entries []payloadEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	headerOnly := false
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body)), Format: tar.FormatPAX}
		if e.typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		if e.size != 0 {
			hdr.Size = e.size
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if e.size != 0 {
			headerOnly = true
			break
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !headerOnly {
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	} else if err := tw.Flush(); err != nil && !strings.Contains(err.Error(), "missed writing") {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// run builds the archive and the signed manifest, writes the archive to a
// file and verifies it into a fresh directory.
func (f *payloadFixture) run(t *testing.T) (*PayloadManifest, string, error) {
	t.Helper()
	archive := buildArchive(t, f.entries)
	m := PayloadManifest{Version: "v0.3.0", KubeMinor: "1.35", CompatibleFrom: "v0.2.0", ArchiveSHA256: sha256Hex(archive)}
	for _, e := range f.entries {
		if e.typeflag != tar.TypeReg {
			continue
		}
		kind := PayloadVersionMarker
		if isMachOHeader(e.body) || e.size != 0 {
			kind = PayloadMachO
		}
		m.Members = append(m.Members, PayloadMember{Path: strings.TrimPrefix(e.name, "./"), SHA256: sha256Hex(e.body), Kind: kind})
	}
	if f.manifest != nil {
		f.manifest(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var sig []byte
	if f.sign != nil {
		sig = f.sign(raw)
	} else {
		sig = signManifest(t, f.key, raw)
	}
	if f.archive != nil {
		archive = f.archive(archive)
	}
	dir := t.TempDir()
	ap := filepath.Join(dir, "archive.tar.gz")
	if err := os.WriteFile(ap, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	af, err := os.Open(ap)
	if err != nil {
		t.Fatal(err)
	}
	defer af.Close()
	dst := filepath.Join(dir, "stage", "v0.3.0.partial")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	p := SignedPayload{
		ClusterCAPEM:  f.ca.CertPEM,
		SignerCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.signer.Raw}),
		Manifest:      raw,
		Signature:     sig,
	}
	got, err := verifySignedPayload(context.Background(), p, af, dst, f.limits)
	return got, dst, err
}

func signManifest(t *testing.T, key *ecdsa.PrivateKey, raw []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// leafUnderCA issues a certificate with the update signer's subject and the
// given usages straight from ca, bypassing the guard that keeps every other
// issuer off that subject, as a compromised or mistaken issuer could.
func leafUnderCA(t *testing.T, ca *CA, ekus []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.issueLeaf(&key.PublicKey, pkix.Name{CommonName: UpdateSignerCommonName, Organization: []string{UpdateSignerOrganization}},
		nil, nil, ekus, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// dropMember removes path from the manifest.
func dropMember(path string) func(*PayloadManifest) {
	return func(m *PayloadManifest) {
		m.Members = slices.DeleteFunc(m.Members, func(mem PayloadMember) bool { return mem.Path == path })
	}
}

// TestVerifySignedPayload is the k3sm-leg verifier's gate: one accepted
// payload and every refusal the signed-payload check owes.
func TestVerifySignedPayload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(t *testing.T, f *payloadFixture)
		want  error
		check func(t *testing.T, m *PayloadManifest, dst string)
	}{
		{
			name: "accepts a signed payload whose files match its manifest",
			edit: func(*testing.T, *payloadFixture) {},
			check: func(t *testing.T, m *PayloadManifest, dst string) {
				if m == nil || m.Version != "v0.3.0" || len(m.Members) != 4 {
					t.Fatalf("manifest = %+v", m)
				}
				for rel, mode := range map[string]fs.FileMode{
					"k3sm": 0o755, "k3sm-execshim": 0o755, "cp-payload/kine": 0o755, "cp-payload/etcd.version": 0o644,
				} {
					fi, err := os.Lstat(filepath.Join(dst, filepath.FromSlash(rel)))
					if err != nil {
						t.Fatalf("extracted %s: %v", rel, err)
					}
					if !fi.Mode().IsRegular() || fi.Mode().Perm() != mode {
						t.Errorf("%s mode = %v, want regular %v", rel, fi.Mode(), mode)
					}
				}
				b, err := os.ReadFile(filepath.Join(dst, "cp-payload", "kine"))
				if err != nil || !bytes.Equal(b, machOBody("kine")) {
					t.Errorf("cp-payload/kine = %q, %v", b, err)
				}
			},
		},
		{
			name: "tampered digest",
			edit: func(_ *testing.T, f *payloadFixture) {
				f.manifest = func(m *PayloadManifest) { m.Members[1].SHA256 = sha256Hex(machOBody("other")) }
			},
			want: ErrPayloadDigest,
		},
		{
			name: "signer with the wrong EKU",
			edit: func(t *testing.T, f *payloadFixture) {
				f.signer, f.key = leafUnderCA(t, f.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			},
			want: ErrPayloadSignature,
		},
		{
			name: "signer not chaining to the CA",
			edit: func(t *testing.T, f *payloadFixture) {
				other, err := NewCA("k3sm-cluster-ca")
				if err != nil {
					t.Fatal(err)
				}
				s, err := other.IssueUpdateSigner()
				if err != nil {
					t.Fatal(err)
				}
				f.signer, f.key = s.Cert, s.Key
			},
			want: ErrPayloadSignature,
		},
		{
			name: "unsigned or wrongly signed manifest",
			edit: func(t *testing.T, f *payloadFixture) {
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.sign = func(raw []byte) []byte { return signManifest(t, other, raw) }
			},
			want: ErrPayloadSignature,
		},
		{
			name: "manifest mismatch",
			edit: func(_ *testing.T, f *payloadFixture) {
				f.manifest = func(m *PayloadManifest) {
					m.Members = append(m.Members, PayloadMember{Path: "k3sm-vmhost", SHA256: sha256Hex(machOBody("vmhost")), Kind: PayloadMachO})
				}
			},
			want: ErrPayloadManifest,
		},
		{
			name: "extra member",
			edit: func(_ *testing.T, f *payloadFixture) {
				f.entries = append(f.entries, regEntry("k3sm-extra", machOBody("extra")))
				f.manifest = dropMember("k3sm-extra")
			},
			want: ErrPayloadManifest,
		},
		{
			name: "non-Mach-O member that is not a declared non-code file",
			edit: func(_ *testing.T, f *payloadFixture) {
				f.entries = append(f.entries, regEntry("cp-payload/run.sh", []byte("#!/bin/sh\nid\n")))
				f.manifest = func(m *PayloadManifest) {
					for i := range m.Members {
						if m.Members[i].Path == "cp-payload/run.sh" {
							m.Members[i].Kind = PayloadMachO
						}
					}
				}
			},
			want: ErrPayloadMember,
		},
		{
			name: "symlink member",
			edit: func(_ *testing.T, f *payloadFixture) {
				f.entries = append(f.entries, payloadEntry{name: "cp-payload/zot", typeflag: tar.TypeSymlink, mode: 0o777, link: "/usr/bin/true"})
			},
			want: ErrPayloadMember,
		},
		{
			name: "hard-link member",
			edit: func(_ *testing.T, f *payloadFixture) {
				f.entries = append(f.entries, payloadEntry{name: "cp-payload/zot", typeflag: tar.TypeLink, mode: 0o755, link: "k3sm"})
			},
			want: ErrPayloadMember,
		},
		{
			name: `".." member`,
			edit: func(_ *testing.T, f *payloadFixture) {
				f.entries = append([]payloadEntry{regEntry("cp-payload/../../escape", machOBody("escape"))}, f.entries...)
				f.manifest = dropMember("cp-payload/../../escape")
			},
			want: ErrPayloadMember,
			check: func(t *testing.T, _ *PayloadManifest, dst string) {
				if _, err := os.Lstat(filepath.Join(dst, "..", "escape")); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("a file escaped the destination: %v", err)
				}
			},
		},
		{
			name: "setuid member",
			edit: func(_ *testing.T, f *payloadFixture) { f.entries[0].mode = 0o4755 },
			want: ErrPayloadMember,
		},
		{
			name: "archive over 2 GiB",
			edit: func(t *testing.T, f *payloadFixture) {
				if MaxPayloadArchiveBytes != 2<<30 || defaultPayloadLimits.archiveBytes != MaxPayloadArchiveBytes {
					t.Fatalf("archive bound = %d (default %d), want 2 GiB", MaxPayloadArchiveBytes, defaultPayloadLimits.archiveBytes)
				}
				// The bound is scaled down: the case proves the check, the
				// line above pins the production value.
				f.limits.archiveBytes = 64
			},
			want: ErrPayloadTooLarge,
		},
		{
			name: "extraction over 4 GiB",
			edit: func(t *testing.T, f *payloadFixture) {
				if MaxPayloadExtractedBytes != 4<<30 || defaultPayloadLimits.extractedBytes != MaxPayloadExtractedBytes {
					t.Fatalf("extraction bound = %d, want 4 GiB", MaxPayloadExtractedBytes)
				}
				f.entries = append(f.entries, payloadEntry{name: "cp-payload/huge", typeflag: tar.TypeReg, mode: 0o755, size: MaxPayloadExtractedBytes})
			},
			want: ErrPayloadTooLarge,
		},
		{
			name: "more than 64 members",
			edit: func(t *testing.T, f *payloadFixture) {
				if MaxPayloadMembers != 64 || defaultPayloadLimits.members != MaxPayloadMembers {
					t.Fatalf("member bound = %d, want 64", MaxPayloadMembers)
				}
				for len(f.entries) <= MaxPayloadMembers {
					f.entries = append(f.entries, dirEntry("cp-payload/"))
				}
			},
			want: ErrPayloadTooLarge,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPayloadFixture(t)
			tc.edit(t, f)
			m, dst, err := f.run(t)
			t.Logf("VerifySignedPayload: %v", err)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("VerifySignedPayload = %v, want accepted", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("VerifySignedPayload = %v, want %v", err, tc.want)
			case tc.want != nil && m != nil:
				t.Fatalf("VerifySignedPayload returned a manifest with a refusal")
			}
			if tc.check != nil {
				tc.check(t, m, dst)
			}
		})
	}
}

// TestVerifySignedPayloadRefusesMore covers the refusals the gate table does
// not list.
func TestVerifySignedPayloadRefusesMore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(t *testing.T, f *payloadFixture)
		want error
	}{
		{"no signature", func(_ *testing.T, f *payloadFixture) { f.sign = func([]byte) []byte { return nil } }, ErrPayloadSignature},
		{"archive bytes changed after signing", func(_ *testing.T, f *payloadFixture) {
			f.archive = func(b []byte) []byte { return append(slices.Clone(b), 0) }
		}, ErrPayloadDigest},
		{"absolute member", func(_ *testing.T, f *payloadFixture) {
			f.entries = append([]payloadEntry{regEntry("/tmp/escape", machOBody("x"))}, f.entries...)
			f.manifest = dropMember("/tmp/escape")
		}, ErrPayloadMember},
		{"setgid member", func(_ *testing.T, f *payloadFixture) { f.entries[1].mode = 0o2755 }, ErrPayloadMember},
		{"device member", func(_ *testing.T, f *payloadFixture) {
			f.entries = append(f.entries, payloadEntry{name: "cp-payload/null", typeflag: tar.TypeChar, mode: 0o666})
		}, ErrPayloadMember},
		{"fifo member", func(_ *testing.T, f *payloadFixture) {
			f.entries = append(f.entries, payloadEntry{name: "cp-payload/fifo", typeflag: tar.TypeFifo, mode: 0o644})
		}, ErrPayloadMember},
		{"directory holding no member", func(_ *testing.T, f *payloadFixture) {
			f.entries = append(f.entries, dirEntry("lib/"))
		}, ErrPayloadManifest},
		{"Mach-O declared as a version marker", func(_ *testing.T, f *payloadFixture) {
			f.entries = append(f.entries, regEntry("cp-payload/zot.version", machOBody("zot")))
			f.manifest = func(m *PayloadManifest) {
				for i := range m.Members {
					if m.Members[i].Path == "cp-payload/zot.version" {
						m.Members[i].Kind = PayloadVersionMarker
					}
				}
			}
		}, ErrPayloadMember},
		{"member written twice", func(_ *testing.T, f *payloadFixture) {
			f.entries = append(f.entries, regEntry("k3sm", machOBody("k3sm")))
			f.manifest = func(m *PayloadManifest) { m.Members = m.Members[:4] }
		}, ErrPayloadMember},
		{"unknown manifest field", func(_ *testing.T, f *payloadFixture) {
			f.manifest = func(m *PayloadManifest) { m.Members[0].Kind = "script" }
		}, ErrPayloadManifest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPayloadFixture(t)
			tc.edit(t, f)
			_, _, err := f.run(t)
			t.Logf("VerifySignedPayload: %v", err)
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifySignedPayload = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifySignedPayloadRefusesANonCABundle requires every certificate of
// the cluster CA bundle to be a CA.
func TestVerifySignedPayloadRefusesANonCABundle(t *testing.T) {
	t.Parallel()
	f := newPayloadFixture(t)
	f.ca.CertPEM = append(slices.Clone(f.ca.CertPEM), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.signer.Raw})...)
	_, _, err := f.run(t)
	if !errors.Is(err, ErrPayloadSignature) || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("VerifySignedPayload = %v, want %v for a non-CA certificate", err, ErrPayloadSignature)
	}
}
