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

package update

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"

	"k3sm.io/k3sm/pkg/certs"
)

// The Node annotations of a managed update that this module adds beside the
// apis keys (updatesv1alpha1.AnnotationUpdateVersion, AnnotationUpdatePayload
// and AnnotationUpdatePhase). The controller writes them with the payload in
// its handover patch; the node and its root helper read them. They are
// published here, once, so neither side spells a literal.
const (
	// AnnotationUpdatePayload is the canonical payload JSON (EncodePayload),
	// the bytes the signature covers.
	AnnotationUpdatePayload = updatesv1alpha1.AnnotationUpdatePayload
	// AnnotationUpdatePayloadSig is the base64 (standard encoding) of the DER
	// ECDSA signature over SHA-256 of the exact payload bytes.
	AnnotationUpdatePayloadSig = "k3sm.io/update-payload-sig"
	// AnnotationUpdateSigner is the PEM certificate of the key that signed,
	// the server's update signer (certs.IssueUpdateSigner).
	AnnotationUpdateSigner = "k3sm.io/update-signer"
)

// ErrUnsigned refuses a payload that does not carry a valid signature of the
// cluster's update signer. A node can write its own annotations through the
// Node authorizer, so a payload is authorised by the signature alone.
var ErrUnsigned = errors.New("update refused: the payload is not signed by the cluster's update signer")

// EncodePayload is the canonical payload encoding: the fields in their
// declared order ({"version","url","sha256","signature","allowDowngrade"},
// allowDowngrade only when true), no HTML escaping and no trailing newline.
// The controller signs exactly these bytes and writes them on the Node.
func EncodePayload(p Payload) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, fmt.Errorf("encode the update payload: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// SignPayload signs payload with s and returns the AnnotationUpdatePayloadSig
// value.
func SignPayload(s *certs.UpdateSigner, payload []byte) (string, error) {
	if s == nil || s.Key == nil {
		return "", errors.New("sign the update payload: no update signer")
	}
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, s.Key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign the update payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// SignedPayload is a payload whose signature verified: the parsed payload,
// and the exact bytes the root helper re-verifies.
type SignedPayload struct {
	Payload Payload
	// Raw is the payload bytes, as signed.
	Raw []byte
	// Signature is the DER ECDSA signature.
	Signature []byte
	// SignerPEM is the signer certificate.
	SignerPEM []byte
}

// VerifySignedPayload checks a payload against the cluster CA before anything
// in it is trusted: the signer is one PEM certificate that chains to roots
// (the cluster CA alone, never the system roots) for code signing at now,
// names certs.UpdateSignerCommonName and certs.UpdateSignerOrganization and
// holds an ECDSA key; the signature verifies over SHA-256 of payload; and only
// then is the payload parsed (ParsePayload). Every refusal wraps ErrUnsigned
// or ErrRefused.
func VerifySignedPayload(roots *x509.CertPool, payload []byte, sigB64, signerPEM string, now time.Time) (SignedPayload, error) {
	if roots == nil {
		return SignedPayload{}, fmt.Errorf("%w: this node holds no cluster CA to check it against", ErrUnsigned)
	}
	if len(payload) == 0 || sigB64 == "" || signerPEM == "" {
		return SignedPayload{}, fmt.Errorf("%w: the payload, its signature or the signer certificate is missing", ErrUnsigned)
	}
	block, rest := pem.Decode([]byte(signerPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return SignedPayload{}, fmt.Errorf("%w: the signer is not one PEM certificate", ErrUnsigned)
	}
	signer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("%w: the signer certificate does not parse: %w", ErrUnsigned, err)
	}
	if _, err := signer.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return SignedPayload{}, fmt.Errorf("%w: the signer does not chain to the cluster CA for code signing: %w", ErrUnsigned, err)
	}
	if signer.Subject.CommonName != certs.UpdateSignerCommonName || !slices.Contains(signer.Subject.Organization, certs.UpdateSignerOrganization) {
		return SignedPayload{}, fmt.Errorf("%w: the signer is CN=%q O=%q", ErrUnsigned, signer.Subject.CommonName, signer.Subject.Organization)
	}
	pub, ok := signer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return SignedPayload{}, fmt.Errorf("%w: the signer key is not ECDSA", ErrUnsigned)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("%w: the signature is not base64", ErrUnsigned)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return SignedPayload{}, fmt.Errorf("%w: the signature does not verify over the payload", ErrUnsigned)
	}
	p, err := ParsePayload(string(payload))
	if err != nil {
		return SignedPayload{}, err
	}
	return SignedPayload{Payload: p, Raw: payload, Signature: sig, SignerPEM: []byte(signerPEM)}, nil
}

// CAPool is a pool holding the PEM certificates in caPEM, or nil when there
// are none.
func CAPool(caPEM []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	if len(caPEM) == 0 || !pool.AppendCertsFromPEM(caPEM) {
		return nil
	}
	return pool
}
