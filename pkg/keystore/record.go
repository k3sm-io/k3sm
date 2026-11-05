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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// This file is the record layer: the binary encoding of a sealed record, the
// associated data that binds it to its place, and the seal and open under
// AES-256-GCM. docs/design/keystore.md § "Record encoding" is its
// specification. Seal, Open and the length-prefixed field encoding are ported
// from internal/seal/seal.go in github.com/netstar-labs/keystore (Apache-2.0),
// with that package's KDF-parameter associated data replaced by the five
// fields below.

const (
	// recordFormat is the record-format version every record carries in its
	// first byte and in its associated data.
	recordFormat = 1
	// kindPointer is the kind byte of a current-pointer record. Version
	// records carry a Kind (1 or 2).
	kindPointer = 0xFF
	// headerSize is the size of a record's fixed fields: everything but the
	// name and the ciphertext. See the offset table in the design.
	headerSize = 52
	nonceSize  = 12
	tagSize    = 16
	// generationSize is the size of an entry's generation, bound into the
	// associated data of every record of that entry.
	generationSize = 16
	// pointerSize is a pointer record's plaintext: the version it names, then
	// its sequence, both big-endian uint64.
	pointerSize = 16
	// MaxValueSize is the largest value Put accepts.
	MaxValueSize = 64 << 10
	// maxNameLen bounds an entry name: a Kubernetes object name's limit, and
	// under the 255-byte file-name limit, so a name always fits its directory.
	maxNameLen = 253
	// maxRecordSize bounds what a read of one record file accepts.
	maxRecordSize = headerSize + maxNameLen + MaxValueSize + tagSize
)

// Labels of the two keys derived from the master. The master itself keys only
// HMAC-SHA256 under these fixed labels, never AES directly, so no key is used
// by two different primitives.
const (
	sealKeyLabel        = "k3sm-keystore-seal-v1"
	fingerprintKeyLabel = "k3sm-keystore-fingerprint-v1"
)

// record is one sealed file: a version record or the current pointer.
type record struct {
	kind       byte
	name       string
	version    uint64
	generation [generationSize]byte
	// created is unauthenticated display metadata: it is not in the associated
	// data, so a changed clock or a restored backup never fails an open.
	created    int64
	nonce      [nonceSize]byte
	ciphertext []byte
}

// aad is the associated data: the record format, kind, name, version and
// generation, each length-prefixed (a 4-byte big-endian length, then the
// bytes) so no field's bytes can be shifted into its neighbour.
func (r *record) aad() []byte {
	b := make([]byte, 0, 5*4+1+1+len(r.name)+8+generationSize)
	field := func(v []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	field([]byte{recordFormat})
	field([]byte{r.kind})
	field([]byte(r.name))
	field(binary.BigEndian.AppendUint64(nil, r.version))
	field(r.generation[:])
	return b
}

// marshal returns the record's file content.
func (r *record) marshal() []byte {
	b := make([]byte, 0, headerSize+len(r.name)+len(r.ciphertext))
	b = append(b, recordFormat, r.kind)
	b = binary.BigEndian.AppendUint16(b, uint16(len(r.name)))
	b = append(b, r.name...)
	b = binary.BigEndian.AppendUint64(b, r.version)
	b = append(b, r.generation[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(r.created))
	b = append(b, r.nonce[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(r.ciphertext)))
	return append(b, r.ciphertext...)
}

// parseRecord decodes a record file. It is strict: every length must agree
// with the file's size exactly, and anything else is ErrCorrupt. It does not
// check that the record belongs where it was found; openRecord does.
func parseRecord(b []byte) (record, error) {
	var r record
	if len(b) < headerSize {
		return r, fmt.Errorf("%w: %d bytes is shorter than a record header", ErrCorrupt, len(b))
	}
	if b[0] != recordFormat {
		return r, fmt.Errorf("%w: record format %d, want %d", ErrCorrupt, b[0], recordFormat)
	}
	r.kind = b[1]
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n == 0 || n > maxNameLen || len(b) < headerSize+n {
		return r, fmt.Errorf("%w: name length %d", ErrCorrupt, n)
	}
	r.name = string(b[4 : 4+n])
	rest := b[4+n:]
	r.version = binary.BigEndian.Uint64(rest[0:8])
	copy(r.generation[:], rest[8:24])
	r.created = int64(binary.BigEndian.Uint64(rest[24:32]))
	copy(r.nonce[:], rest[32:44])
	c := binary.BigEndian.Uint32(rest[44:48])
	if c < tagSize || uint64(c) != uint64(len(rest)-48) {
		return r, fmt.Errorf("%w: ciphertext length %d does not match the file", ErrCorrupt, c)
	}
	r.ciphertext = bytes.Clone(rest[48:])
	return r, nil
}

// seal encrypts plaintext into r under key with a fresh nonce from random. A
// failed read of random is an error, never a reused or zero nonce.
func (r *record) seal(key, plaintext []byte, random io.Reader) error {
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	if _, err := io.ReadFull(random, r.nonce[:]); err != nil {
		return fmt.Errorf("read a nonce: %w", err)
	}
	r.ciphertext = gcm.Seal(nil, r.nonce[:], plaintext, r.aad())
	return nil
}

// open authenticates and decrypts r under key. Any mismatch of key, nonce,
// ciphertext or associated data is ErrCorrupt; the cases are deliberately not
// told apart.
func (r *record) open(key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, r.nonce[:], r.ciphertext, r.aad())
	if err != nil {
		return nil, fmt.Errorf("%w: the record does not authenticate", ErrCorrupt)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("seal key is %d bytes, want %d", len(key), sha256.Size)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// keys are the two keys derived from one master.
type keys struct {
	seal        []byte
	fingerprint []byte
}

// deriveKeys derives the seal and fingerprint keys from master.
func deriveKeys(master []byte) keys {
	return keys{
		seal:        hmacSHA256(master, []byte(sealKeyLabel)),
		fingerprint: hmacSHA256(master, []byte(fingerprintKeyLabel)),
	}
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// fingerprint identifies value without revealing it: the SHA-256 of an
// Ed25519 key's public half, or for an opaque value an HMAC under the
// fingerprint key truncated to 16 bytes, so List is not a guessing oracle for
// a low-entropy value.
func fingerprint(kind Kind, value []byte, fpKey []byte) string {
	if kind == KindEd25519 {
		pub := ed25519.NewKeyFromSeed(value[:ed25519.SeedSize]).Public().(ed25519.PublicKey)
		sum := sha256.Sum256(pub)
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(hmacSHA256(fpKey, value)[:16])
}

// checkValue validates a value for kind before it is sealed.
func checkValue(kind Kind, value []byte) error {
	switch kind {
	case KindEd25519:
		switch len(value) {
		case ed25519.SeedSize:
			return nil
		case ed25519.PrivateKeySize:
			// The expanded form is seed then public key; a public half that
			// does not belong to the seed is a damaged key, not a valid one.
			if !bytes.Equal(ed25519.NewKeyFromSeed(value[:ed25519.SeedSize]), value) {
				return errors.New("the 64-byte Ed25519 key's public half does not match its seed")
			}
			return nil
		default:
			return fmt.Errorf("an Ed25519 key is %d or %d bytes, not %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(value))
		}
	case KindOpaque:
		if len(value) == 0 {
			return errors.New("the value is empty")
		}
		if len(value) > MaxValueSize {
			return fmt.Errorf("the value is %d bytes, over the %d-byte limit", len(value), MaxValueSize)
		}
		return nil
	default:
		return fmt.Errorf("unknown kind %d", int(kind))
	}
}

// checkName validates an entry name before it becomes a file name: 1 to 253
// bytes of lowercase letters, digits, '-' and '.', beginning and ending with a
// letter or digit. Lowercase only, because APFS is case-insensitive by default
// and two names that differ only in case would share one directory. No leading
// dot, because the store's own files (.lock, temporary files) are dot names.
func checkName(name string) error {
	if name == "" || len(name) > maxNameLen || !alnum(name[0]) || !alnum(name[len(name)-1]) {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	for i := 1; i < len(name)-1; i++ {
		if c := name[i]; !alnum(c) && c != '-' && c != '.' {
			return fmt.Errorf("%w: %q", ErrInvalidName, name)
		}
	}
	return nil
}

func alnum(c byte) bool { return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' }
