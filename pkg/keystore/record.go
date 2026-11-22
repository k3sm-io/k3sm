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
	"strconv"
	"strings"
)

// This file is the record layer: the binary encoding of a sealed record, the
// associated data that binds it to its place, and the seal and open under
// AES-256-GCM. docs/design/keystore.md § "Record encoding" is its
// specification. Seal, Open and the length-prefixed field encoding are adapted
// from the author's own internal/seal/seal.go in
// github.com/netstar-labs/keystore (Apache-2.0), with that package's
// KDF-parameter associated data replaced by the six fields below.

const (
	// recordFormat is the record-format version every record carries in its
	// first byte and in its associated data.
	recordFormat = 1
	// kindPointer is the kind byte of a current-pointer record. Version
	// records carry a Kind (1 or 2).
	// Kind bytes 0xFE (a wrapped scope key) and 0xFD (a sealed per-user
	// delivery list) are reserved for user scopes. No record carries them yet,
	// so parseRecord refuses them with every other unknown kind.
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
// HMAC-SHA256 under these fixed labels, each followed by a zero byte and the
// scope (see scopedLabel), never AES directly, so no key is used by two
// different primitives and no two scopes share a key.
const (
	sealKeyLabel        = "k3sm-keystore-seal-v1"
	fingerprintKeyLabel = "k3sm-keystore-fingerprint-v1"
)

// Scopes. A store seals and opens every record under one scope, supplied from
// its own identity and never read from a file: docs/design/keystore.md §
// "Scope". Phase A constructs only scopeSystem.
const (
	// scopeSystem is the scope of the node's own store.
	scopeSystem = "system"
	// userScopePrefix begins a user scope: "user/" and the user's decimal
	// macOS uid. The uid, never the short name: an account rename keeps the
	// uid, and a scope bound to the name would make every record of a renamed
	// user fail to open.
	userScopePrefix = "user/"
)

// errInvalidScope reports a scope checkScope refuses.
var errInvalidScope = errors.New("invalid keystore scope")

// checkScope accepts "system", or "user/" followed by a decimal uid: digits
// only, no leading zero unless it is "0", and fitting in a uint32. It refuses
// anything else, so each uid has exactly one scope string. A scope holds no
// zero byte, so scopedLabel is unambiguous.
func checkScope(scope string) error {
	if scope == scopeSystem {
		return nil
	}
	if uid, ok := strings.CutPrefix(scope, userScopePrefix); ok && decimalUID(uid) {
		return nil
	}
	return fmt.Errorf("%w: %q", errInvalidScope, scope)
}

// decimalUID reports whether s is a uint32 in canonical decimal: digits only,
// and no leading zero unless s is "0".
func decimalUID(s string) bool {
	if s == "" || (s[0] == '0' && len(s) > 1) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

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

// aad is the associated data: the record format, scope, kind, name, version
// and generation, each length-prefixed (a 4-byte big-endian length, then the
// bytes) so no field's bytes can be shifted into its neighbour. The scope is
// not in the record's bytes: the opening store supplies it, as openRecord
// checks the name against the entry's directory.
func (r *record) aad(scope string) []byte {
	b := make([]byte, 0, 6*4+1+len(scope)+1+len(r.name)+8+generationSize)
	field := func(v []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	field([]byte{recordFormat})
	field([]byte(scope))
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

// parseRecord decodes a record file. It is strict: the kind must be one a
// record carries today (the two Kinds or kindPointer; the reserved 0xFE and
// 0xFD are refused), every length must agree with the file's size exactly, and
// anything else is ErrCorrupt. It does not
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
	switch r.kind {
	case byte(KindEd25519), byte(KindOpaque), kindPointer:
	default:
		return r, fmt.Errorf("%w: unknown record kind %#02x", ErrCorrupt, r.kind)
	}
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

// seal encrypts plaintext into r under key and scope with a fresh nonce from
// random. A failed read of random is an error, never a reused or zero nonce.
func (r *record) seal(key []byte, scope string, plaintext []byte, random io.Reader) error {
	if err := checkScope(scope); err != nil {
		return err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	if _, err := io.ReadFull(random, r.nonce[:]); err != nil {
		return fmt.Errorf("read a nonce: %w", err)
	}
	r.ciphertext = gcm.Seal(nil, r.nonce[:], plaintext, r.aad(scope))
	return nil
}

// open authenticates and decrypts r under key and scope. Any mismatch of key,
// nonce, ciphertext or associated data is ErrCorrupt; the cases are
// deliberately not told apart.
func (r *record) open(key []byte, scope string) ([]byte, error) {
	if err := checkScope(scope); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, r.nonce[:], r.ciphertext, r.aad(scope))
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

// keys are the two keys derived from one master for one scope, and that
// scope, which every seal and open under them passes.
type keys struct {
	scope       string
	seal        []byte
	fingerprint []byte
	// next is the keys of master.next, when a Rewrap that crashed left one
	// that agrees with its fingerprint: a record its step 4 already moved
	// opens under them (see open). Nil otherwise, and always nil on the keys
	// a record is sealed under.
	next *keys
}

// open authenticates and decrypts r under k, and, when that fails to
// authenticate and k.next is set, once more under k.next: the reader's rule
// for the state a crashed Rewrap leaves (docs/design/keystore.md § "Rewrap").
// The lock keeps a live reader from ever seeing a Rewrap in progress.
func (k keys) open(r *record) ([]byte, error) {
	pt, err := r.open(k.seal, k.scope)
	if err != nil && k.next != nil && errors.Is(err, ErrCorrupt) {
		return r.open(k.next.seal, k.next.scope)
	}
	return pt, err
}

// deriveKeys derives scope's seal and fingerprint keys from master. It does
// not keep master, and a caller clears it once the keys are derived, so the
// raw master is held no longer than the derivation needs.
//
// The system scope derives from the master directly, as here. A user scope
// will later seal under its own scope key, wrapped by the master, which is a
// separate design; the scope in each label already keeps the scopes' keys
// apart under one master.
func deriveKeys(master []byte, scope string) (keys, error) {
	if err := checkScope(scope); err != nil {
		return keys{}, err
	}
	return keys{
		scope:       scope,
		seal:        hmacSHA256(master, scopedLabel(sealKeyLabel, scope)),
		fingerprint: hmacSHA256(master, scopedLabel(fingerprintKeyLabel, scope)),
	}, nil
}

// scopedLabel is a derivation label for scope: the label, a zero byte, then
// the scope. Neither holds a zero byte, so no two pairs give one label.
func scopedLabel(label, scope string) []byte {
	b := append([]byte(label), 0)
	return append(b, scope...)
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
			return fmt.Errorf("an Ed25519 key is %d or %d bytes, and this value is neither", ed25519.SeedSize, ed25519.PrivateKeySize)
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

// checkName validates an entry name before it becomes a file name: a
// Kubernetes DNS-1123 subdomain, that is 1 to 253 bytes of dot-separated
// labels, each lowercase letters, digits and '-', beginning and ending with a
// letter or digit. Lowercase only, because APFS is case-insensitive by default
// and two names that differ only in case would share one directory. No leading
// dot, because the store's own files (.lock, temporary files) are dot names.
// And the delivered Secret's name defaults to the entry name, so it must be a
// valid one.
func checkName(name string) error {
	if name == "" || len(name) > maxNameLen {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabel(label) {
			return fmt.Errorf("%w: %q", ErrInvalidName, name)
		}
	}
	return nil
}

// CheckName reports whether name is a valid entry name, the grammar every
// method of the store applies: a Kubernetes DNS-1123 subdomain (see
// ErrInvalidName). Unlike the store's own refusals, its error never carries
// name, so a caller may show it for an argument that could be a value typed
// where the name belongs.
func CheckName(name string) error {
	if checkName(name) != nil {
		return ErrInvalidName
	}
	return nil
}

// dnsLabel reports whether label is non-empty, lowercase letters, digits and
// '-', and begins and ends with a letter or digit. Its length bound is the
// caller's.
func dnsLabel(label string) bool {
	if label == "" || !alnum(label[0]) || !alnum(label[len(label)-1]) {
		return false
	}
	for i := 1; i < len(label)-1; i++ {
		if c := label[i]; !alnum(c) && c != '-' {
			return false
		}
	}
	return true
}

func alnum(c byte) bool { return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' }
