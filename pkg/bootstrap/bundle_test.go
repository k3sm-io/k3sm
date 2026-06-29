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

package bootstrap_test

import (
	"bytes"
	"errors"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
)

const testServerSecret = "a3f1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

// TestCABundleSealUnsealRoundTrip proves the crypto core: SealBundle → OpenBundle under
// the same secret returns the exact plaintext, and the envelope is NOT the plaintext
// (it is encrypted, and prefixed with the versioned magic header).
func TestCABundleSealUnsealRoundTrip(t *testing.T) {
	plaintext := []byte("the four CA PEMs — cluster+signing cert+key")
	env, err := bootstrap.SealBundle(testServerSecret, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(env, plaintext) {
		t.Fatal("the sealed envelope must not contain the plaintext (it must be encrypted)")
	}
	if !bytes.HasPrefix(env, []byte("K3SB")) {
		t.Errorf("envelope missing the magic prefix: %q", env[:4])
	}

	got, err := bootstrap.OpenBundle(testServerSecret, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip plaintext = %q, want %q", got, plaintext)
	}
}

// TestCABundleWrongSecretFailsClosed proves the fail-closed property: a wrong secret OR
// a corrupt ciphertext fails the GCM tag and yields ErrBundleOpen with NO plaintext — a
// leaked-but-wrong secret can never reconstruct the CAs.
func TestCABundleWrongSecretFailsClosed(t *testing.T) {
	env, err := bootstrap.SealBundle(testServerSecret, []byte("ca-bundle"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	got, err := bootstrap.OpenBundle("b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", env)
	if !errors.Is(err, bootstrap.ErrBundleOpen) {
		t.Errorf("wrong-secret err = %v, want ErrBundleOpen", err)
	}
	if got != nil {
		t.Error("wrong-secret open must return NO plaintext")
	}

	// Corrupt the ciphertext body (last byte) — the tag must fail.
	corrupt := append([]byte(nil), env...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := bootstrap.OpenBundle(testServerSecret, corrupt); !errors.Is(err, bootstrap.ErrBundleOpen) {
		t.Errorf("corrupt-ciphertext err = %v, want ErrBundleOpen", err)
	}
}

// TestCABundleNonceUniquePerSeal proves a FRESH nonce + salt per seal (never a counter):
// sealing the SAME plaintext under the SAME secret twice yields different envelopes (so
// no GCM nonce reuse across launchctl-kickstart restarts), and both still open.
func TestCABundleNonceUniquePerSeal(t *testing.T) {
	pt := []byte("identical plaintext")
	a, err := bootstrap.SealBundle(testServerSecret, pt)
	if err != nil {
		t.Fatalf("seal a: %v", err)
	}
	b, err := bootstrap.SealBundle(testServerSecret, pt)
	if err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (fresh random salt + nonce per seal — never a counter)")
	}
	for i, env := range [][]byte{a, b} {
		got, err := bootstrap.OpenBundle(testServerSecret, env)
		if err != nil || !bytes.Equal(got, pt) {
			t.Errorf("envelope %d must still open to the plaintext (err=%v)", i, err)
		}
	}
}

// TestCABundleTamperedAADRejected proves the versioned header is bound as GCM AAD: any
// tampered authenticated-header byte (magic, version, a salt byte, a nonce byte) is
// rejected on Open — no downgrade, no parameter substitution.
func TestCABundleTamperedAADRejected(t *testing.T) {
	base, err := bootstrap.SealBundle(testServerSecret, []byte("ca-bundle-aad"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Header layout: magic(4) version(1) kdfID(1) iters(4) saltLen(1) salt(16) nonceLen(1) nonce(12).
	cases := map[string]int{
		"magic byte":   0,
		"version byte": 4,
		"first salt":   4 + 1 + 1 + 4 + 1,          // start of salt
		"last salt":    4 + 1 + 1 + 4 + 1 + 15,     // end of salt (saltLen=16)
		"first nonce":  4 + 1 + 1 + 4 + 1 + 16 + 1, // after nonceLen, start of nonce
	}
	for name, idx := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := append([]byte(nil), base...)
			tampered[idx] ^= 0x01
			if _, err := bootstrap.OpenBundle(testServerSecret, tampered); err == nil {
				t.Errorf("tampering the %s (offset %d) must be rejected", name, idx)
			}
		})
	}
}
