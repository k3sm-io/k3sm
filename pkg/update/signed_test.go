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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/certs"
)

func testSignedPayload(t *testing.T) (*certs.CA, *certs.UpdateSigner, []byte, string) {
	t.Helper()
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ca.IssueUpdateSigner()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodePayload(Payload{
		Version:   "v0.2.0",
		URL:       "https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz",
		SHA256:    strings.Repeat("ab", 32),
		Signature: "if-signed",
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignPayload(s, raw)
	if err != nil {
		t.Fatal(err)
	}
	return ca, s, raw, sig
}

// craftedSigner is a certificate the test signs directly with key, past
// pkg/certs's guard, to stand for a signer no k3sm path would issue.
func craftedSigner(t *testing.T, ca *certs.CA, subject pkix.Name, eku x509.ExtKeyUsage, notAfter time.Time) (*certs.UpdateSigner, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: subject, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return &certs.UpdateSigner{Key: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestSignedPayloadRoundTrip is the trust chain: a payload signed by the
// cluster CA's update signer verifies against that CA, and a node-forged
// payload, a foreign CA, a signer with another usage or subject, an expired
// signer and a mangled signature are all refused.
func TestSignedPayloadRoundTrip(t *testing.T) {
	t.Parallel()
	ca, s, raw, sig := testSignedPayload(t)
	roots := CAPool(ca.CertPEM)
	now := time.Now()
	got, err := VerifySignedPayload(roots, raw, sig, string(s.CertPEM), now)
	if err != nil {
		t.Fatalf("VerifySignedPayload = %v", err)
	}
	if got.Payload.Version != "v0.2.0" || string(got.Raw) != string(raw) || string(got.SignerPEM) != string(s.CertPEM) {
		t.Errorf("verified %+v", got.Payload)
	}
	if der, _ := base64.StdEncoding.DecodeString(sig); string(got.Signature) != string(der) {
		t.Error("Signature is not the DER the annotation carries")
	}

	refuse := func(name string, roots *x509.CertPool, raw []byte, sig, signer string) {
		t.Helper()
		if _, err := VerifySignedPayload(roots, raw, sig, signer, now); !errors.Is(err, ErrUnsigned) {
			t.Errorf("%s: VerifySignedPayload = %v, want ErrUnsigned", name, err)
		}
	}
	forged := []byte(strings.Replace(string(raw), "github.com", "evil.example", 1))
	refuse("a node-forged payload under the server's signature", roots, forged, sig, string(s.CertPEM))
	refuse("an unsigned payload", roots, raw, "", "")
	refuse("no cluster CA", nil, raw, sig, string(s.CertPEM))
	other, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.IssueUpdateSigner()
	if err != nil {
		t.Fatal(err)
	}
	fsig, _ := SignPayload(foreign, raw)
	refuse("a signer from a foreign CA", roots, raw, fsig, string(foreign.CertPEM))
	subj := pkix.Name{CommonName: certs.UpdateSignerCommonName, Organization: []string{certs.UpdateSignerOrganization}}
	for name, c := range map[string]struct {
		subject pkix.Name
		eku     x509.ExtKeyUsage
		after   time.Time
	}{
		"a signer for client auth":  {subj, x509.ExtKeyUsageClientAuth, now.Add(time.Hour)},
		"a signer with another CN":  {pkix.Name{CommonName: "system:node:worker", Organization: []string{certs.UpdateSignerOrganization}}, x509.ExtKeyUsageCodeSigning, now.Add(time.Hour)},
		"a signer with no signer O": {pkix.Name{CommonName: certs.UpdateSignerCommonName, Organization: []string{"system:nodes"}}, x509.ExtKeyUsageCodeSigning, now.Add(time.Hour)},
		"an expired signer":         {subj, x509.ExtKeyUsageCodeSigning, now.Add(-time.Hour)},
	} {
		cs, certPEM := craftedSigner(t, ca, c.subject, c.eku, c.after)
		csig, _ := SignPayload(cs, raw)
		refuse(name, roots, raw, csig, certPEM)
	}
	refuse("a signature that is not base64", roots, raw, "%%%", string(s.CertPEM))
	refuse("two certificates as the signer", roots, raw, sig, string(s.CertPEM)+string(s.CertPEM))
}

// TestEncodePayloadIsCanonical pins the exact signed bytes and the subject
// darwin-net's root helper requires.
func TestEncodePayloadIsCanonical(t *testing.T) {
	t.Parallel()
	raw, err := EncodePayload(Payload{Version: "v0.2.0", URL: "https://github.com/a?b=1&c=<2>", SHA256: "00", Signature: "required", AllowDowngrade: true})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"v0.2.0","url":"https://github.com/a?b=1&c=<2>","sha256":"00","signature":"required","allowDowngrade":true}`
	if string(raw) != want {
		t.Errorf("EncodePayload =\n%s\nwant\n%s", raw, want)
	}
	if certs.UpdateSignerCommonName != wire.UpdateSignerCommonName || certs.UpdateSignerOrganization != wire.UpdateSignerOrganization {
		t.Errorf("the signer subject %q/%q differs from the root helper's %q/%q",
			certs.UpdateSignerCommonName, certs.UpdateSignerOrganization, wire.UpdateSignerCommonName, wire.UpdateSignerOrganization)
	}
}
