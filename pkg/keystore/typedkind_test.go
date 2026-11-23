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

package keystore

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"k3sm.io/apis/keystore/credential"

	"k3sm.io/k3sm/pkg/keystore/typed"
)

// typedKinds maps each typed kind byte to its credential kind.
var typedKinds = map[byte]credential.Kind{
	kindToken: credential.KindToken,
	kindSSH:   credential.KindSSH,
	kindOAuth: credential.KindOAuth,
}

// sealedTyped returns the file of a record of kind byte k sealing pt.
func sealedTyped(t *testing.T, k byte, pt []byte) []byte {
	t.Helper()
	r := testRecord()
	r.kind = k
	if err := r.seal(testKey, scopeSystem, pt, rand.Reader); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return r.marshal()
}

func typedEnvelope(t *testing.T, k credential.Kind) []byte {
	t.Helper()
	var e typed.Envelope
	switch k {
	case credential.KindToken:
		e.Credential = typed.Credential{Value: []byte("tok"), ExpiresAt: unixUTC(1800000000), IssuedAt: unixUTC(1790000000)}
	case credential.KindSSH:
		e.Credential = typed.Credential{Algorithm: typed.SSHAlgorithmEd25519, Seed: make([]byte, 32)}
	case credential.KindOAuth:
		e.Credential = typed.Credential{AccessToken: []byte("a"), AccessExpiresAt: unixUTC(1790003600), AccessIssuedAt: unixUTC(1790000000), RefreshOwner: "local"}
		e.RefreshToken = []byte("r")
	}
	b, err := typed.Encode(k, e)
	if err != nil {
		t.Fatalf("encode %s: %v", k, err)
	}
	return b
}

// TestKindByteTable walks every kind byte through parseRecord: 1 to 5 and
// 0xFF parse; 6 to 0xFC are ErrKindUnsupported and not ErrCorrupt; 0, 0xFD
// and 0xFE are ErrCorrupt and not ErrKindUnsupported. A typed record with an
// envelope version this build does not know is ErrKindUnsupported too.
func TestKindByteTable(t *testing.T) {
	good := sealedTyped(t, kindToken, typedEnvelope(t, credential.KindToken))
	for k := 0; k <= 0xFF; k++ {
		_, err := parseRecord(kindByte(good, byte(k)))
		switch {
		case k >= 1 && k <= 5 || k == 0xFF:
			if err != nil {
				t.Errorf("kind %#02x: %v, want it parsed", k, err)
			}
		case k >= 6 && k <= 0xFC:
			if !errors.Is(err, ErrKindUnsupported) || errors.Is(err, ErrCorrupt) {
				t.Errorf("kind %#02x: %v, want ErrKindUnsupported alone", k, err)
			}
		default:
			if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrKindUnsupported) {
				t.Errorf("kind %#02x: %v, want ErrCorrupt alone", k, err)
			}
		}
	}

	t.Run("unknown envelope version", func(t *testing.T) {
		for k, ck := range typedKinds {
			env := typedEnvelope(t, ck)
			env[0] = typed.EnvelopeVersion + 1
			r, err := parseRecord(sealedTyped(t, k, env))
			if err != nil {
				t.Fatalf("%s: parse: %v", ck, err)
			}
			pt, err := r.open(testKey, scopeSystem)
			if err != nil {
				t.Fatalf("%s: open: %v", ck, err)
			}
			if _, err := typed.Decode(ck, pt); !errors.Is(err, ErrKindUnsupported) || errors.Is(err, ErrCorrupt) {
				t.Errorf("%s: decode: %v, want ErrKindUnsupported alone", ck, err)
			}
		}
	})

	if typed.MaxEnvelopeSize != MaxValueSize {
		t.Errorf("typed.MaxEnvelopeSize %d, MaxValueSize %d: the envelope must fit a value", typed.MaxEnvelopeSize, MaxValueSize)
	}
}

// TestTypedKindRelabelFailsOpen: the kind byte is in the AAD, so a typed
// record relabelled as any other kind a record carries parses and then fails
// to open, while the unrelabelled record opens to its envelope.
func TestTypedKindRelabelFailsOpen(t *testing.T) {
	carried := []byte{byte(KindEd25519), byte(KindOpaque), kindToken, kindSSH, kindOAuth, kindPointer}
	for k, ck := range typedKinds {
		file := sealedTyped(t, k, typedEnvelope(t, ck))
		r, err := parseRecord(file)
		if err != nil {
			t.Fatalf("%s: parse: %v", ck, err)
		}
		pt, err := r.open(testKey, scopeSystem)
		if err != nil {
			t.Fatalf("%s: open: %v", ck, err)
		}
		if _, err := typed.Decode(ck, pt); err != nil {
			t.Fatalf("%s: decode: %v", ck, err)
		}
		for _, other := range carried {
			if other == k {
				continue
			}
			r, err := parseRecord(kindByte(file, other))
			if err != nil {
				t.Fatalf("%s as %#02x: parse: %v", ck, other, err)
			}
			if _, err := r.open(testKey, scopeSystem); !errors.Is(err, ErrCorrupt) {
				t.Errorf("%s relabelled %#02x: open: %v, want ErrCorrupt", ck, other, err)
			}
		}
	}
}

func unixUTC(s int64) time.Time { return time.Unix(s, 0).UTC() }
