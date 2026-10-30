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
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"
)

// Bounds on a signed release payload. A node stages at most this much from a
// release archive it has not yet verified.
const (
	// MaxPayloadArchiveBytes is the largest release archive accepted.
	MaxPayloadArchiveBytes int64 = 2 << 30
	// MaxPayloadExtractedBytes is the most an archive may unpack to, every
	// member counted.
	MaxPayloadExtractedBytes int64 = 4 << 30
	// MaxPayloadMembers is the most entries an archive may hold, directories
	// included, and the most members a manifest may list.
	MaxPayloadMembers = 64
	// MaxPayloadManifestBytes is the largest manifest accepted.
	MaxPayloadManifestBytes = 64 << 10
	// MaxClusterCABytes is the largest cluster CA bundle accepted.
	MaxClusterCABytes = 1 << 20
)

// Sentinel errors of VerifySignedPayload. Every refusal wraps exactly one.
var (
	// ErrPayloadSignature refuses a payload whose signer certificate does not
	// chain to the cluster CA as the update signer, or whose manifest
	// signature does not verify.
	ErrPayloadSignature = errors.New("certs: the payload signature is not the update signer's")
	// ErrPayloadDigest refuses an archive or an extracted file whose sha256
	// is not the one the signed manifest names.
	ErrPayloadDigest = errors.New("certs: a payload digest does not match the signed manifest")
	// ErrPayloadManifest refuses a malformed manifest, or an extracted set
	// that is not exactly the manifest's member set.
	ErrPayloadManifest = errors.New("certs: the payload does not match its signed manifest")
	// ErrPayloadMember refuses an archive member that is not a plain
	// relative regular file or directory, or a file whose content is not the
	// kind the manifest declares.
	ErrPayloadMember = errors.New("certs: the payload holds an unsafe member")
	// ErrPayloadTooLarge refuses an archive, an extraction or a member count
	// over its bound.
	ErrPayloadTooLarge = errors.New("certs: the payload is over its size bound")
)

// PayloadMemberKind is what a manifest member is.
type PayloadMemberKind string

const (
	// PayloadMachO is a Mach-O executable or library, which the Apple code
	// signature check covers.
	PayloadMachO PayloadMemberKind = "mach-o"
	// PayloadVersionMarker is a small text file named <name>.version that is
	// copied as data and never executed or loaded.
	PayloadVersionMarker PayloadMemberKind = "version-marker"
)

// PayloadMember is one file of a release archive as its manifest lists it.
type PayloadMember struct {
	// Path is the member's clean slash-separated path relative to the
	// archive root.
	Path string `json:"path"`
	// SHA256 is the member's lowercase hex sha256.
	SHA256 string `json:"sha256"`
	// Kind is the member's kind.
	Kind PayloadMemberKind `json:"kind"`
}

// PayloadManifest is the signed description of a release archive, delivered
// beside the archive rather than inside it.
type PayloadManifest struct {
	// Version is the release version the archive carries.
	Version string `json:"version"`
	// KubeMinor is the Kubernetes minor version the release ships.
	KubeMinor string `json:"kubeMinor"`
	// CompatibleFrom is the oldest installed version this release may
	// update in place.
	CompatibleFrom string `json:"compatibleFrom"`
	// RequiresInstaller is true when the release cannot be activated in
	// place and needs the installer.
	RequiresInstaller bool `json:"requiresInstaller,omitempty"`
	// ArchiveSHA256 is the lowercase hex sha256 of the whole archive.
	ArchiveSHA256 string `json:"archiveSHA256"`
	// Members lists every regular file the archive carries, each once.
	Members []PayloadMember `json:"members"`
}

// SignedPayload is what VerifySignedPayload checks a copied archive against.
type SignedPayload struct {
	// ClusterCAPEM is the cluster CA bundle the signer must chain to; every
	// certificate in it must be a CA.
	ClusterCAPEM []byte
	// SignerCertPEM is the one PEM certificate of the update signer.
	SignerCertPEM []byte
	// Manifest is the manifest JSON exactly as it was signed.
	Manifest []byte
	// Signature is the ASN.1 ECDSA signature over sha256(Manifest).
	Signature []byte
	// Now is the time the signer's validity is checked at; zero means the
	// current time.
	Now time.Time
}

// payloadLimits are the bounds a verification applies. Production uses
// defaultPayloadLimits; the seam exists so a test can exercise a bound
// without writing gigabytes.
type payloadLimits struct {
	archiveBytes   int64
	extractedBytes int64
	members        int
}

var defaultPayloadLimits = payloadLimits{
	archiveBytes:   MaxPayloadArchiveBytes,
	extractedBytes: MaxPayloadExtractedBytes,
	members:        MaxPayloadMembers,
}

// VerifySignedPayload is the k3sm check of a release archive the caller has
// already copied somewhere only root can write. In order, it:
//
//  1. verifies that the signer certificate chains to the cluster CA at
//     p.Now, carries the Code Signing extended key usage itself and names
//     the update signer (UpdateSignerCommonName, UpdateSignerOrganization),
//     and that its ECDSA signature verifies over sha256(p.Manifest);
//  2. parses the verified manifest strictly;
//  3. hashes archive (at most MaxPayloadArchiveBytes) and requires the
//     manifest's ArchiveSHA256;
//  4. extracts the gzip tar archive into dst, an existing empty directory,
//     refusing any symlink, hard link, device or other non-regular member,
//     an absolute or unclean path or a ".." component, a set-id or sticky
//     bit, a file the manifest does not list, more than MaxPayloadMembers
//     entries and more than MaxPayloadExtractedBytes in total;
//  5. re-reads every file now under dst and requires the set to equal the
//     manifest's members, each with its sha256, each Mach-O member to be a
//     Mach-O and every other file to be a declared version marker.
//
// It returns the manifest only when every step passed. Extended attributes
// in the archive are never applied. On a refusal dst may hold a partial
// extraction, which the caller discards.
func VerifySignedPayload(ctx context.Context, p SignedPayload, archive io.ReadSeeker, dst string) (*PayloadManifest, error) {
	return verifySignedPayload(ctx, p, archive, dst, defaultPayloadLimits)
}

func verifySignedPayload(ctx context.Context, p SignedPayload, archive io.ReadSeeker, dst string, lim payloadLimits) (*PayloadManifest, error) {
	if err := verifyManifestSignature(p); err != nil {
		return nil, err
	}
	m, err := parsePayloadManifest(p.Manifest, lim.members)
	if err != nil {
		return nil, err
	}
	if err := checkArchiveDigest(archive, m.ArchiveSHA256, lim.archiveBytes); err != nil {
		return nil, err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind the archive copy: %w", err)
	}
	if err := extractPayload(ctx, io.LimitReader(archive, lim.archiveBytes), dst, m, lim); err != nil {
		return nil, err
	}
	if err := checkExtractedSet(ctx, dst, m); err != nil {
		return nil, err
	}
	return m, nil
}

// verifyManifestSignature is step 1 of VerifySignedPayload.
func verifyManifestSignature(p SignedPayload) error {
	roots, err := parseClusterCAPool(p.ClusterCAPEM)
	if err != nil {
		return err
	}
	signer, err := parseOneCert(p.SignerCertPEM)
	if err != nil {
		return err
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return fmt.Errorf("%w: the signer certificate does not chain to the cluster CA: %w", ErrPayloadSignature, err)
	}
	// x509 treats a leaf with no extended key usage as valid for any usage,
	// so the leaf itself must carry Code Signing: another certificate under
	// the same CA never stands in for the signer.
	if !slices.Contains(signer.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return fmt.Errorf("%w: the signer certificate does not carry the Code Signing extended key usage", ErrPayloadSignature)
	}
	if signer.Subject.CommonName != UpdateSignerCommonName || !slices.Contains(signer.Subject.Organization, UpdateSignerOrganization) {
		return fmt.Errorf("%w: the signer certificate names CN=%q O=%q, not the update signer", ErrPayloadSignature,
			signer.Subject.CommonName, signer.Subject.Organization)
	}
	pub, ok := signer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: the signer key is %T, not ECDSA", ErrPayloadSignature, signer.PublicKey)
	}
	if len(p.Manifest) > MaxPayloadManifestBytes {
		return fmt.Errorf("%w: the manifest is larger than %d bytes", ErrPayloadTooLarge, MaxPayloadManifestBytes)
	}
	digest := sha256.Sum256(p.Manifest)
	if len(p.Signature) == 0 || !ecdsa.VerifyASN1(pub, digest[:], p.Signature) {
		return fmt.Errorf("%w: the manifest signature does not verify", ErrPayloadSignature)
	}
	return nil
}

// parseClusterCAPool reads a PEM bundle in which every certificate is a CA.
func parseClusterCAPool(raw []byte) (*x509.CertPool, error) {
	if len(raw) > MaxClusterCABytes {
		return nil, fmt.Errorf("%w: the cluster CA is larger than %d bytes", ErrPayloadSignature, MaxClusterCABytes)
	}
	pool := x509.NewCertPool()
	n := 0
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse the cluster CA: %w", ErrPayloadSignature, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("%w: the cluster CA holds a certificate that is not a CA (%s)", ErrPayloadSignature, cert.Subject)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: the cluster CA holds no PEM certificate", ErrPayloadSignature)
	}
	return pool, nil
}

// parseOneCert decodes exactly one PEM certificate.
func parseOneCert(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: the signer certificate is not a PEM CERTIFICATE", ErrPayloadSignature)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: the signer certificate PEM holds more than one block", ErrPayloadSignature)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse the signer certificate: %w", ErrPayloadSignature, err)
	}
	return cert, nil
}

// maxManifestStringLen bounds the manifest's version strings.
const maxManifestStringLen = 64

// maxPayloadDepth bounds the directory depth of a member path.
const maxPayloadDepth = 16

// parsePayloadManifest decodes a verified manifest strictly and checks every
// field.
func parsePayloadManifest(raw []byte, maxMembers int) (*PayloadManifest, error) {
	var m PayloadManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: the manifest is not valid JSON: %w", ErrPayloadManifest, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: the manifest holds more than one JSON value", ErrPayloadManifest)
	}
	for _, f := range []struct{ name, val string }{
		{"version", m.Version}, {"kubeMinor", m.KubeMinor}, {"compatibleFrom", m.CompatibleFrom},
	} {
		if !validManifestString(f.val) {
			return nil, fmt.Errorf("%w: the manifest %s %q is not a version string", ErrPayloadManifest, f.name, f.val)
		}
	}
	if !validSHA256Hex(m.ArchiveSHA256) {
		return nil, fmt.Errorf("%w: the manifest archiveSHA256 is not a lowercase hex sha256", ErrPayloadManifest)
	}
	if len(m.Members) == 0 {
		return nil, fmt.Errorf("%w: the manifest lists no member", ErrPayloadManifest)
	}
	if len(m.Members) > maxMembers {
		return nil, fmt.Errorf("%w: the manifest lists more than %d members", ErrPayloadTooLarge, maxMembers)
	}
	seen := make(map[string]bool, len(m.Members))
	for _, mem := range m.Members {
		if !cleanMemberPath(mem.Path) {
			return nil, fmt.Errorf("%w: the manifest member path %q is not a clean relative path", ErrPayloadManifest, mem.Path)
		}
		if seen[mem.Path] {
			return nil, fmt.Errorf("%w: the manifest lists %s twice", ErrPayloadManifest, mem.Path)
		}
		seen[mem.Path] = true
		if !validSHA256Hex(mem.SHA256) {
			return nil, fmt.Errorf("%w: the manifest member %s has no lowercase hex sha256", ErrPayloadManifest, mem.Path)
		}
		switch mem.Kind {
		case PayloadMachO:
		case PayloadVersionMarker:
			base := path.Base(mem.Path)
			if !strings.HasSuffix(base, versionMarkerSuffix) || base == versionMarkerSuffix {
				return nil, fmt.Errorf("%w: the version marker %s is not named <name>%s", ErrPayloadManifest, mem.Path, versionMarkerSuffix)
			}
		default:
			return nil, fmt.Errorf("%w: the manifest member %s has unknown kind %q", ErrPayloadManifest, mem.Path, mem.Kind)
		}
	}
	// A member path may not also be the directory of another member.
	for p := range seen {
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			if seen[d] {
				return nil, fmt.Errorf("%w: the manifest lists %s as a file and a directory", ErrPayloadManifest, d)
			}
		}
	}
	return &m, nil
}

// validManifestString reports whether s is a non-empty bounded version
// string of letters, digits and ".+-_".
func validManifestString(s string) bool {
	if s == "" || len(s) > maxManifestStringLen {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".+-_", c)
		if !ok {
			return false
		}
	}
	return true
}

// validSHA256Hex reports whether s is a lowercase hex sha256.
func validSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// cleanMemberPath reports whether name is a clean relative slash path with no
// "." or ".." component, no NUL or backslash, within maxPayloadDepth.
func cleanMemberPath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\x00\\") || path.Clean(name) != name {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxPayloadDepth {
		return false
	}
	for _, c := range parts {
		if c == "." || c == ".." || c == "" {
			return false
		}
	}
	return true
}

// checkArchiveDigest hashes at most limit bytes of archive and requires want.
func checkArchiveDigest(archive io.Reader, want string, limit int64) error {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(archive, limit+1))
	if err != nil {
		return fmt.Errorf("read the archive copy: %w", err)
	}
	if n > limit {
		return fmt.Errorf("%w: the archive is larger than %d bytes", ErrPayloadTooLarge, limit)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: the archive has sha256 %s, the signed manifest says %s", ErrPayloadDigest, got, want)
	}
	return nil
}
