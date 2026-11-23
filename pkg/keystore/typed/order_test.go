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

package typed

import (
	"errors"
	"testing"

	"k3sm.io/apis/keystore/credential"
)

// envelopeOf is an envelope assembled by hand from encoded fields, in the
// order given, so a test can write one Encode refuses.
func envelopeOf(fields ...[]byte) []byte {
	return cat(append([][]byte{{EnvelopeVersion}}, fields...)...)
}

// TestExpiryOrderEnforced is review round 4, item 4: Decode refuses, as
// ErrCorrupt, a token whose expiresAt is not after its issuedAt and an oauth
// pair whose accessExpiresAt is not after its accessIssuedAt, and Encode
// refuses both as ErrInvalidCredential, so the two still agree.
func TestExpiryOrderEnforced(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind credential.Kind
		b    []byte
	}{
		{"token expiring at its issue time", credential.KindToken,
			envelopeOf(tlv(tagValue, []byte("t")), tlv(tagExpiresAt, be(100)), tlv(tagIssuedAt, be(100)))},
		{"token expiring before its issue time", credential.KindToken,
			envelopeOf(tlv(tagValue, []byte("t")), tlv(tagExpiresAt, be(99)), tlv(tagIssuedAt, be(100)))},
		{"access token expiring at its issue time", credential.KindOAuth,
			envelopeOf(tlv(tagAccessToken, []byte("a")), tlv(tagAccessExpiresAt, be(100)), tlv(tagAccessIssuedAt, be(100)),
				tlv(tagRefreshToken, []byte("r")), tlv(tagRefreshOwner, []byte("local")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.kind, tc.b); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Decode: %v, want ErrCorrupt", err)
			}
		})
	}
	tok := Envelope{Credential: Credential{Value: []byte("t"), ExpiresAt: unix(100), IssuedAt: unix(100)}}
	if _, err := Encode(credential.KindToken, tok); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Encode of a token expiring at its issue time: %v, want ErrInvalidCredential", err)
	}
	pair := Envelope{Credential: Credential{AccessToken: []byte("a"), AccessExpiresAt: unix(100), AccessIssuedAt: unix(101), RefreshOwner: "local"}, RefreshToken: []byte("r")}
	if _, err := Encode(credential.KindOAuth, pair); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Encode of an access token expiring before its issue time: %v, want ErrInvalidCredential", err)
	}
}
