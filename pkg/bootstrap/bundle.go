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
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// AES-256-GCM bootstrap-bundle envelope parameters. The CA bundle (the four
// cluster+signing CA PEMs an HA server-join reconstructs identical, certs.Hierarchy
// .Marshal) is sealed under a key DERIVED from the high-entropy server-bootstrap secret
// via PBKDF2-HMAC-SHA256 with a per-seal crypto/rand salt; a per-seal crypto/rand nonce
// (NEVER a counter — launchctl kickstart resets in-process state, so a counter would
// repeat and break GCM); and a versioned header bound as GCM AAD so a downgrade or any
// tamper fails the tag on Open. This is the k3s bootstrap-key model (DESIGN §5c),
// hardened with the AAD binding k3s omits.
const (
	bundleVersion     = 1       // envelope format version (in the AAD; bumped on a breaking change)
	bundleKDFPBKDF2   = 1       // KDF id: PBKDF2-HMAC-SHA256
	bundlePBKDF2Iters = 600_000 // pinned PBKDF2 iterations (OWASP 2023 PBKDF2-SHA256 floor); stored so a future change still reads old envelopes
	bundleSaltLen     = 16      // 128-bit KDF salt
	bundleKeyLen      = 32      // AES-256 key
	bundleNonceLen    = 12      // GCM standard nonce
	// bundleHeaderFixed is the header byte count before the variable salt/nonce:
	// magic(4) + version(1) + kdfID(1) + iters(4) + saltLen(1).
	bundleHeaderFixed = 4 + 1 + 1 + 4 + 1
)

// bundleMagic prefixes every envelope ("K3Sm Bootstrap").
var bundleMagic = [4]byte{'K', '3', 'S', 'B'}

// Sentinel errors. Compare with errors.Is.
var (
	// ErrBundleFormat is returned by OpenBundle for a structurally invalid envelope
	// (bad magic, unsupported version/KDF, truncated).
	ErrBundleFormat = errors.New("bootstrap: malformed CA bootstrap bundle envelope")
	// ErrBundleOpen is returned when authentication fails: a wrong secret, a corrupt
	// ciphertext, or ANY tampered authenticated-header byte (the GCM tag is verified
	// before any plaintext is returned — fail closed).
	ErrBundleOpen = errors.New("bootstrap: CA bootstrap bundle authentication failed (wrong secret or tampered envelope)")
)

// SealBundle AES-256-GCM-seals plaintext (the certs.Hierarchy.Marshal bytes) under a
// key derived from secret. It draws a fresh crypto/rand salt + nonce per call and binds
// the versioned header (magic+version+kdf+iters+salt+nonce) as the GCM AAD. The returned
// envelope is header || ciphertext+tag, safe to persist in the shared datastore (the
// secret never leaves the server hosts).
func SealBundle(secret string, plaintext []byte) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("bootstrap: seal bundle: empty secret")
	}
	salt := make([]byte, bundleSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	nonce := make([]byte, bundleNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	header := bundleHeader(salt, nonce, bundlePBKDF2Iters)
	gcm, err := bundleGCM(secret, salt, bundlePBKDF2Iters)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, header)
	return append(header, sealed...), nil
}

// OpenBundle authenticates + decrypts a SealBundle envelope under secret. A wrong
// secret, a corrupt ciphertext, or ANY tampered authenticated-header byte fails the GCM
// tag and returns ErrBundleOpen with NO plaintext. A structurally invalid envelope
// returns ErrBundleFormat. Callers MUST treat any error as fatal and never proceed with
// partial/absent CA material (the fail-closed contract of the HA server-join).
func OpenBundle(secret string, envelope []byte) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("bootstrap: open bundle: empty secret")
	}
	salt, nonce, ciphertext, header, iters, err := parseBundle(envelope)
	if err != nil {
		return nil, err
	}
	gcm, err := bundleGCM(secret, salt, iters)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleOpen, err)
	}
	return plaintext, nil
}

// bundleHeader renders the authenticated envelope header:
// magic(4) | version(1) | kdfID(1) | iters(4, big-endian) | saltLen(1) | salt | nonceLen(1) | nonce.
// The whole header is the GCM AAD, so every parameter is tamper-evident.
func bundleHeader(salt, nonce []byte, iters int) []byte {
	h := make([]byte, 0, bundleHeaderFixed+len(salt)+1+len(nonce))
	h = append(h, bundleMagic[:]...)
	h = append(h, bundleVersion, bundleKDFPBKDF2)
	h = binary.BigEndian.AppendUint32(h, uint32(iters))
	h = append(h, byte(len(salt)))
	h = append(h, salt...)
	h = append(h, byte(len(nonce)))
	h = append(h, nonce...)
	return h
}

// parseBundle splits an envelope into its salt, nonce, ciphertext, the authenticated
// header (AAD), and the stored iteration count, validating magic/version/KDF/lengths.
func parseBundle(envelope []byte) (salt, nonce, ciphertext, header []byte, iters int, err error) {
	if len(envelope) < bundleHeaderFixed {
		return nil, nil, nil, nil, 0, fmt.Errorf("%w: shorter than the fixed header", ErrBundleFormat)
	}
	if !bytes.Equal(envelope[:4], bundleMagic[:]) {
		return nil, nil, nil, nil, 0, fmt.Errorf("%w: bad magic", ErrBundleFormat)
	}
	off := 4
	if envelope[off] != bundleVersion {
		return nil, nil, nil, nil, 0, fmt.Errorf("%w: unsupported version %d", ErrBundleFormat, envelope[off])
	}
	off++
	if envelope[off] != bundleKDFPBKDF2 {
		return nil, nil, nil, nil, 0, fmt.Errorf("%w: unsupported kdf id %d", ErrBundleFormat, envelope[off])
	}
	off++
	iters = int(binary.BigEndian.Uint32(envelope[off:]))
	off += 4
	if iters <= 0 {
		return nil, nil, nil, nil, 0, fmt.Errorf("%w: non-positive iteration count", ErrBundleFormat)
	}
	saltLen := int(envelope[off])
	off++
	if saltLen == 0 || len(envelope) < off+saltLen+1 {
		return nil, nil, nil, nil, 0, fmt.Errorf("%w: truncated salt", ErrBundleFormat)
	}
	salt = envelope[off : off+saltLen]
	off += saltLen
	nonceLen := int(envelope[off])
	off++
	if nonceLen != bundleNonceLen || len(envelope) < off+nonceLen {
		return nil, nil, nil, nil, 0, fmt.Errorf("%w: bad nonce length", ErrBundleFormat)
	}
	nonce = envelope[off : off+nonceLen]
	off += nonceLen
	ciphertext = envelope[off:]
	header = envelope[:off]
	return salt, nonce, ciphertext, header, iters, nil
}

// bundleGCM derives the AES-256 key from secret + salt (PBKDF2-HMAC-SHA256, iters) and
// returns the GCM AEAD.
func bundleGCM(secret string, salt []byte, iters int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, secret, salt, iters, bundleKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive bundle key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return gcm, nil
}
