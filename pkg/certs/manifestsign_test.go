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
	"errors"
	"testing"
)

// TestSignManifestVerifies pins that a manifest the update signer signs with
// SignManifest is one VerifySignedPayload accepts, and that the bounds hold.
func TestSignManifestVerifies(t *testing.T) {
	t.Run("a SignManifest signature verifies over the payload", func(t *testing.T) {
		f := newPayloadFixture(t)
		s := &UpdateSigner{Key: f.key, Cert: f.signer}
		f.sign = func(raw []byte) []byte {
			sig, err := s.SignManifest(raw)
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}
		if _, _, err := f.run(t); err != nil {
			t.Fatalf("a manifest signed by SignManifest was refused: %v", err)
		}
	})
	t.Run("another signer's signature is refused", func(t *testing.T) {
		f := newPayloadFixture(t)
		other, err := f.ca.IssueUpdateSigner()
		if err != nil {
			t.Fatal(err)
		}
		f.sign = func(raw []byte) []byte {
			sig, err := other.SignManifest(raw)
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}
		if _, _, err := f.run(t); !errors.Is(err, ErrPayloadSignature) {
			t.Fatalf("err %v, want ErrPayloadSignature", err)
		}
	})
	t.Run("no signer, an empty or an oversized manifest is refused", func(t *testing.T) {
		var nilSigner *UpdateSigner
		if _, err := nilSigner.SignManifest([]byte("{}")); err == nil {
			t.Fatal("a nil signer signed")
		}
		f := newPayloadFixture(t)
		s := &UpdateSigner{Key: f.key, Cert: f.signer}
		if _, err := s.SignManifest(nil); err == nil {
			t.Fatal("an empty manifest was signed")
		}
		if _, err := s.SignManifest(bytes.Repeat([]byte(" "), MaxPayloadManifestBytes+1)); err == nil {
			t.Fatal("an oversized manifest was signed")
		}
	})
}

// TestParsePayloadManifest pins the exported strict parse: the same refusals
// as the verifier's, and the size bound before any decoding.
func TestParsePayloadManifest(t *testing.T) {
	good := `{"version":"v0.3.0","kubeMinor":"1.35","compatibleFrom":"v0.2.0","archiveSHA256":"` + sha256Hex([]byte("a")) +
		`","members":[{"path":"k3sm","sha256":"` + sha256Hex([]byte("b")) + `","kind":"mach-o"}]}`
	for _, tc := range []struct {
		name string
		raw  string
		want error
	}{
		{"a valid manifest", good, nil},
		{"an unknown key", `{"extra":1,` + good[1:], ErrPayloadManifest},
		{"a repeated key", `{"version":"v0.3.1",` + good[1:], ErrPayloadManifest},
		{"no members", `{"version":"v0.3.0","kubeMinor":"1.35","compatibleFrom":"v0.2.0","archiveSHA256":"` + sha256Hex([]byte("a")) + `","members":[]}`, ErrPayloadManifest},
		{"over the size bound", good + string(bytes.Repeat([]byte(" "), MaxPayloadManifestBytes)), ErrPayloadTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParsePayloadManifest([]byte(tc.raw))
			if tc.want == nil {
				if err != nil || m.Version != "v0.3.0" || m.KubeMinor != "1.35" {
					t.Fatalf("parse: %v (%+v)", err, m)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
}
