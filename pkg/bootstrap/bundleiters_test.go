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

package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// forgedBundle builds a structurally valid envelope carrying iters in its header and a
// ciphertext that was never sealed under any key (a forger without the secret).
func forgedBundle(iters uint32) []byte {
	salt := bytes.Repeat([]byte{0x5a}, bundleSaltLen)
	nonce := bytes.Repeat([]byte{0xa5}, bundleNonceLen)
	h := bundleHeader(salt, nonce, int(iters))
	return append(h, bytes.Repeat([]byte{0xee}, 32)...)
}

// cheapBundle seals plaintext under secret like SealBundle, but at iters rounds so an
// in-window round trip stays fast.
func cheapBundle(t *testing.T, secret string, iters int, plaintext []byte) []byte {
	t.Helper()
	salt := bytes.Repeat([]byte{0x11}, bundleSaltLen)
	nonce := bytes.Repeat([]byte{0x22}, bundleNonceLen)
	h := bundleHeader(salt, nonce, iters)
	gcm, err := bundleGCM(secret, salt, iters)
	if err != nil {
		t.Fatalf("bundleGCM: %v", err)
	}
	return append(h, gcm.Seal(nil, nonce, plaintext, h)...)
}

// TestOpenBundleRejectsIterationsOutOfRange proves the stored PBKDF2 iteration count is
// bounded before any key derivation: a forged count outside [min, max] is
// ErrBundleIterations (and ErrBundleFormat) without running the KDF, while an in-window
// count still reaches GCM, so the check masks no authentication failure.
func TestOpenBundleRejectsIterationsOutOfRange(t *testing.T) {
	t.Run("parseBundle", func(t *testing.T) {
		cases := []struct {
			name  string
			iters uint32
			ok    bool
		}{
			{"zero", 0, false},
			{"one", 1, false},
			{"min-1", bundleMinPBKDF2Iters - 1, false},
			{"min", bundleMinPBKDF2Iters, true},
			{"max", bundleMaxPBKDF2Iters, true},
			{"max+1", bundleMaxPBKDF2Iters + 1, false},
			{"sign bit", 0x80000000, false},
			{"all ones", 0xFFFFFFFF, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, _, _, iters, err := parseBundle(forgedBundle(tc.iters))
				if tc.ok {
					if err != nil {
						t.Fatalf("in-window count %d: err = %v, want nil", tc.iters, err)
					}
					if iters != int(tc.iters) {
						t.Errorf("iters = %d, want %d", iters, tc.iters)
					}
					return
				}
				if !errors.Is(err, ErrBundleIterations) {
					t.Errorf("count %d: err = %v, want ErrBundleIterations", tc.iters, err)
				}
				if !errors.Is(err, ErrBundleFormat) {
					t.Errorf("count %d: err = %v, want it to wrap ErrBundleFormat", tc.iters, err)
				}
			})
		}
	})

	t.Run("OpenBundle forged", func(t *testing.T) {
		for _, n := range []uint32{bundleMaxPBKDF2Iters + 1, 0xFFFFFFFF} {
			t.Run(fmt.Sprintf("count=%d", n), func(t *testing.T) {
				done := make(chan error, 1)
				go func() {
					_, err := OpenBundle("any-secret", forgedBundle(n))
					done <- err
				}()
				var err error
				select {
				case err = <-done:
				case <-time.After(10 * time.Second):
					t.Fatalf("OpenBundle with count %d did not return in 10s: the KDF ran on an unbounded count", n)
				}
				if !errors.Is(err, ErrBundleIterations) || !errors.Is(err, ErrBundleFormat) {
					t.Errorf("count %d: err = %v, want ErrBundleIterations wrapping ErrBundleFormat", n, err)
				}
			})
		}
	})

	t.Run("in-window round trip", func(t *testing.T) {
		const secret = "in-window-secret"
		pt := []byte("ca-bundle-cheap")
		env := cheapBundle(t, secret, bundleMinPBKDF2Iters, pt)
		got, err := OpenBundle(secret, env)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("right secret: got %q, err %v; want %q, nil", got, err, pt)
		}
		got, err = OpenBundle("wrong-secret", env)
		if !errors.Is(err, ErrBundleOpen) {
			t.Errorf("wrong secret: err = %v, want ErrBundleOpen", err)
		}
		if errors.Is(err, ErrBundleIterations) {
			t.Errorf("wrong secret: err = %v must not be ErrBundleIterations", err)
		}
		if got != nil {
			t.Error("wrong secret must return no plaintext")
		}
	})

	t.Run("salt length", func(t *testing.T) {
		const secret = "salt-length-secret"
		cases := []struct {
			name    string
			saltLen int
			ok      bool
		}{
			{"15", bundleSaltLen - 1, false},
			{"16 genuine", bundleSaltLen, true},
			{"17", bundleSaltLen + 1, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				salt := bytes.Repeat([]byte{0x33}, tc.saltLen)
				nonce := bytes.Repeat([]byte{0x44}, bundleNonceLen)
				h := bundleHeader(salt, nonce, bundleMinPBKDF2Iters)
				if !tc.ok {
					env := append(h, bytes.Repeat([]byte{0xee}, 32)...)
					_, err := OpenBundle(secret, env)
					if !errors.Is(err, ErrBundleFormat) || errors.Is(err, ErrBundleIterations) {
						t.Errorf("salt length %d: err = %v, want ErrBundleFormat and not ErrBundleIterations", tc.saltLen, err)
					}
					return
				}
				gcm, err := bundleGCM(secret, salt, bundleMinPBKDF2Iters)
				if err != nil {
					t.Fatalf("bundleGCM: %v", err)
				}
				pt := []byte("ca-bundle-salt")
				got, err := OpenBundle(secret, append(h, gcm.Seal(nil, nonce, pt, h)...))
				if err != nil || !bytes.Equal(got, pt) {
					t.Errorf("genuine 16-byte salt: got %q, err %v; want %q, nil", got, err, pt)
				}
			})
		}
	})

	t.Run("production count in window", func(t *testing.T) {
		if bundlePBKDF2Iters < bundleMinPBKDF2Iters || bundlePBKDF2Iters > bundleMaxPBKDF2Iters {
			t.Fatalf("bundlePBKDF2Iters %d outside [%d, %d]: SealBundle output would not open",
				bundlePBKDF2Iters, bundleMinPBKDF2Iters, bundleMaxPBKDF2Iters)
		}
	})
}
