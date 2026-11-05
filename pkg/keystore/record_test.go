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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

// testKey is a fixed 32-byte seal key for record-level tests.
var testKey = bytes.Repeat([]byte{0x42}, 32)

func testRecord() record {
	r := record{kind: byte(KindOpaque), name: "signer-key", version: 7, created: 1_700_000_000}
	copy(r.generation[:], bytes.Repeat([]byte{0xA5}, generationSize))
	return r
}

// TestAADLayout pins the associated data byte for byte: five length-prefixed
// fields, in the order the design gives. A change here is a format change.
func TestAADLayout(t *testing.T) {
	r := testRecord()
	want := "00000001" + "01" + // LP(record format 1)
		"00000001" + "02" + // LP(kind: opaque)
		"0000000a" + hex.EncodeToString([]byte("signer-key")) + // LP(name)
		"00000008" + "0000000000000007" + // LP(version, 8 bytes BE)
		"00000010" + strings.Repeat("a5", generationSize) // LP(generation, 16 bytes)
	if got := hex.EncodeToString(r.aad()); got != want {
		t.Fatalf("aad =\n%s\nwant\n%s", got, want)
	}
}

// TestAADBindsEveryField is gate row G2: a record moved to another kind, name,
// version or generation fails to open, and so does one whose format byte
// changed.
func TestAADBindsEveryField(t *testing.T) {
	sealed := testRecord()
	if err := sealed.seal(testKey, []byte("value"), rand.Reader); err != nil {
		t.Fatalf("seal: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(r *record)
	}{
		{"kind", func(r *record) { r.kind = byte(KindEd25519) }},
		{"name", func(r *record) { r.name = "signer-kez" }},
		{"version", func(r *record) { r.version = 8 }},
		{"generation", func(r *record) { r.generation[15] ^= 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sealed
			r.ciphertext = bytes.Clone(sealed.ciphertext)
			if _, err := r.open(testKey); err != nil {
				t.Fatalf("unmodified open: %v", err)
			}
			tt.mutate(&r)
			if _, err := r.open(testKey); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("open after changing the %s: %v, want ErrCorrupt", tt.name, err)
			}
		})
	}
	t.Run("format", func(t *testing.T) {
		b := sealed.marshal()
		b[0] = recordFormat + 1
		if _, err := parseRecord(b); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("parse with format %d: %v, want ErrCorrupt", b[0], err)
		}
	})
	t.Run("created is not bound", func(t *testing.T) {
		r := sealed
		r.created++
		if _, err := r.open(testKey); err != nil {
			t.Fatalf("open after changing created: %v, want success (created is display metadata)", err)
		}
	})
}

// TestSealNonceIsFresh is the library half of gate row G3: every seal draws
// its nonce from the entropy source, so two seals of one plaintext under one
// key, name and version differ, and a failed read is an error, never a fixed
// nonce. The Rewrap half lands with Rewrap.
func TestSealNonceIsFresh(t *testing.T) {
	a, b := testRecord(), testRecord()
	if err := a.seal(testKey, []byte("same"), rand.Reader); err != nil {
		t.Fatalf("seal a: %v", err)
	}
	if err := b.seal(testKey, []byte("same"), rand.Reader); err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if a.nonce == b.nonce || bytes.Equal(a.ciphertext, b.ciphertext) {
		t.Fatalf("two seals share a nonce or ciphertext: %x %x", a.nonce, b.nonce)
	}

	c := testRecord()
	want := bytes.Repeat([]byte{0x5c}, nonceSize)
	if err := c.seal(testKey, []byte("same"), bytes.NewReader(want)); err != nil {
		t.Fatalf("seal c: %v", err)
	}
	if !bytes.Equal(c.nonce[:], want) {
		t.Fatalf("nonce = %x, want the entropy source's bytes %x", c.nonce, want)
	}

	d := testRecord()
	if err := d.seal(testKey, []byte("same"), iotest.ErrReader(errors.New("no entropy"))); err == nil {
		t.Fatal("seal with a failing entropy source succeeded")
	}
}

func TestRecordRoundTrip(t *testing.T) {
	r := testRecord()
	if err := r.seal(testKey, []byte("value"), rand.Reader); err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := parseRecord(r.marshal())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pt, err := got.open(testKey)
	if err != nil || string(pt) != "value" {
		t.Fatalf("open = %q %v", pt, err)
	}
	if !bytes.Equal(got.marshal(), r.marshal()) {
		t.Fatal("marshal(parse(b)) != b")
	}
}

func TestParseRecordRefusesMalformed(t *testing.T) {
	r := testRecord()
	if err := r.seal(testKey, []byte("value"), rand.Reader); err != nil {
		t.Fatalf("seal: %v", err)
	}
	good := r.marshal()
	nameLen := func(n uint16) []byte {
		b := bytes.Clone(good)
		binary.BigEndian.PutUint16(b[2:], n)
		return b
	}
	ctLen := func(delta uint32) []byte {
		b := bytes.Clone(good)
		off := 4 + len(r.name) + 44
		binary.BigEndian.PutUint32(b[off:], binary.BigEndian.Uint32(b[off:])+delta)
		return b
	}
	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"short header", good[:headerSize-1]},
		{"zero name length", nameLen(0)},
		{"name length past the file", nameLen(uint16(len(good)))},
		{"name length over the limit", nameLen(maxNameLen + 1)},
		{"ciphertext length short of the file", ctLen(^uint32(0))}, // minus one
		{"ciphertext length past the file", ctLen(1)},
		{"truncated", good[:len(good)-1]},
		{"trailing byte", append(bytes.Clone(good), 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseRecord(tt.b); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parse: %v, want ErrCorrupt", err)
			}
		})
	}
}

// FuzzParseRecord: the parser never panics, and what it accepts re-encodes to
// the same bytes, so there is one encoding of each record.
func FuzzParseRecord(f *testing.F) {
	r := testRecord()
	if err := r.seal(testKey, []byte("value"), rand.Reader); err != nil {
		f.Fatalf("seal: %v", err)
	}
	f.Add(r.marshal())
	f.Add([]byte{})
	f.Add(make([]byte, headerSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseRecord(b)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parse error %v is not ErrCorrupt", err)
			}
			return
		}
		if !bytes.Equal(got.marshal(), b) {
			t.Fatalf("marshal(parse(b)) != b")
		}
	})
}

func TestCheckName(t *testing.T) {
	good := []string{"a", "0", "signer-key", "signer.key", "a-b.c-d", "a--b", strings.Repeat("a", maxNameLen), strings.Repeat("a.", maxNameLen/2) + "a"}
	bad := []string{"", ".", "..", ".lock", "a/b", "../x", "-a", "a-", "a.", "Key", "sIgner", "a_b", "a b", "a\x00b", "a\nb", "é", strings.Repeat("a", maxNameLen+1),
		// Each dot-separated label begins and ends with a letter or digit, as a
		// Kubernetes DNS-1123 subdomain requires.
		"a..b", "a.-b", "a-.b", "a-..a", "0..0"}
	for _, n := range good {
		if err := checkName(n); err != nil {
			t.Errorf("checkName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range bad {
		if err := checkName(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("checkName(%q) = %v, want ErrInvalidName", n, err)
		}
	}
}

// FuzzCheckName: any accepted name is a safe, single, case-unique file name,
// and a DNS-1123 subdomain: every label begins and ends with a letter or digit.
func FuzzCheckName(f *testing.F) {
	for _, s := range []string{"signer-key", ".lock", "..", "a/b", "Key", "a.-b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if checkName(name) != nil {
			return
		}
		if len(name) == 0 || len(name) > maxNameLen || name[0] == '.' || strings.ContainsAny(name, "/\x00") || strings.ToLower(name) != name {
			t.Fatalf("checkName accepted %q", name)
		}
		for _, bad := range []string{"..", ".-", "-."} {
			if strings.Contains(name, bad) {
				t.Fatalf("checkName accepted %q, which has a label that does not begin and end with a letter or digit", name)
			}
		}
	})
}

func TestCheckValue(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	expanded := ed25519.NewKeyFromSeed(seed)
	mismatched := bytes.Clone(expanded)
	mismatched[63] ^= 1
	tests := []struct {
		name  string
		kind  Kind
		value []byte
		ok    bool
	}{
		{"ed25519 seed", KindEd25519, seed, true},
		{"ed25519 expanded", KindEd25519, expanded, true},
		{"ed25519 expanded with a foreign public half", KindEd25519, mismatched, false},
		{"ed25519 short", KindEd25519, seed[:31], false},
		{"ed25519 seed plus a newline", KindEd25519, append(bytes.Clone(seed), '\n'), false},
		{"opaque", KindOpaque, []byte("x"), true},
		{"opaque at the limit", KindOpaque, make([]byte, MaxValueSize), true},
		{"opaque over the limit", KindOpaque, make([]byte, MaxValueSize+1), false},
		{"opaque empty", KindOpaque, nil, false},
		{"unknown kind", KindUnknown, []byte("x"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkValue(tt.kind, tt.value); (err == nil) != tt.ok {
				t.Fatalf("checkValue = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	k1 := deriveKeys(bytes.Repeat([]byte{1}, masterSize))
	k2 := deriveKeys(bytes.Repeat([]byte{2}, masterSize))

	if got := fingerprint(KindEd25519, seed, k1.fingerprint); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("ed25519 fingerprint = %s, want sha256 of the public key", got)
	}
	if fingerprint(KindEd25519, ed25519.NewKeyFromSeed(seed), k1.fingerprint) != fingerprint(KindEd25519, seed, k2.fingerprint) {
		t.Fatal("an ed25519 fingerprint depends on the master or on the key's form")
	}
	value := []byte("hunter2")
	plain := sha256.Sum256(value)
	a, b := fingerprint(KindOpaque, value, k1.fingerprint), fingerprint(KindOpaque, value, k2.fingerprint)
	if a == b {
		t.Fatal("an opaque fingerprint does not depend on the master")
	}
	if len(a) != 32 || strings.HasPrefix(hex.EncodeToString(plain[:]), a) {
		t.Fatalf("opaque fingerprint %s is not a truncated keyed digest", a)
	}
}

func TestDerivedKeysAreSeparate(t *testing.T) {
	master := bytes.Repeat([]byte{9}, masterSize)
	k := deriveKeys(master)
	if bytes.Equal(k.seal, master) || bytes.Equal(k.fingerprint, master) || bytes.Equal(k.seal, k.fingerprint) {
		t.Fatal("a derived key equals the master or the other derived key")
	}
}
