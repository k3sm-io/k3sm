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
	"context"
	"errors"
	"time"
)

// This file is the contract sketch for the keystore. It is deliberately
// implementation-free (no cipher code, no file I/O), and the design review in
// docs/design/keystore.md may still change any of it before the
// implementation lands.

// Kind is the type of key material an entry holds.
type Kind int

const (
	// KindUnknown is the zero Kind. No valid entry carries it, so an
	// uninitialised Kind is never mistaken for a real one.
	KindUnknown Kind = iota
	// KindEd25519 is an Ed25519 private key.
	KindEd25519
	// KindOpaque is an opaque byte string the keystore stores but does not
	// interpret.
	KindOpaque
)

// String returns the lowercase name of k, as the CLI prints it.
func (k Kind) String() string {
	switch k {
	case KindEd25519:
		return "ed25519"
	case KindOpaque:
		return "opaque"
	default:
		return "unknown"
	}
}

// Version is the metadata of one version of a named entry. It never carries
// the value: the value is returned only by Store.Get and Store.Current, and
// only alongside a Version.
type Version struct {
	// Name is the entry name the version belongs to.
	Name string
	// Version is the version number, starting at 1 and increasing by one on
	// every rotation.
	Version uint64
	// Kind is the type of key material the version holds.
	Kind Kind
	// Created is when the version was written.
	Created time.Time
	// Fingerprint identifies the value without revealing it. For
	// KindEd25519 it is a digest of the public key. For KindOpaque it is a
	// keyed digest (an HMAC under a key derived from the master key) or a
	// truncated one, never a plain hash of the value, because List output
	// would otherwise be a guessing oracle for a low-entropy value.
	Fingerprint string
}

// Entry is the metadata of a named entry: its current version and every
// version still stored. Like Version, it never carries a value.
type Entry struct {
	// Name is the entry name.
	Name string
	// Current is the version the current pointer names.
	Current Version
	// Versions is every stored version, oldest first, including Current.
	Versions []Version
	// Err is non-nil exactly when the entry could not be opened: its current
	// pointer failed authentication, is older than the recorded floor, or does
	// not parse. Current and Versions are zero then. List reports such an entry
	// here, not as an error for the whole call, so one bad entry does not hide
	// the healthy ones.
	Err error
}

// Store is the keystore contract a consumer (the CLI verbs, the delivery
// reconciler) depends on.
type Store interface {
	// Put creates the entry name at version 1 holding value. It returns
	// ErrInvalidName for a name that may not become a file name, and
	// ErrExists if the entry already exists; a new value for an existing
	// entry is a Rotate. For KindEd25519 the value is the 32-byte seed or the
	// 64-byte expanded private key, and it is validated; the encoding of the
	// delivered Secret is fixed in the design document.
	Put(ctx context.Context, name string, kind Kind, value []byte) (Version, error)
	// Current returns the version the current pointer names, with its value,
	// or ErrNotFound.
	Current(ctx context.Context, name string) (Version, []byte, error)
	// Get returns one stored version with its value, ErrNotFound when the
	// entry does not exist, or ErrVersionNotFound when the version does not.
	Get(ctx context.Context, name string, version uint64) (Version, []byte, error)
	// List returns the metadata of every entry, sorted by name, with no values.
	// An entry that cannot be opened is still returned, with Entry.Err set. The
	// call itself fails only for a problem that is not about one entry: the
	// master key missing or untrusted, or the store lock not acquired in time.
	List(ctx context.Context) ([]Entry, error)
	// Rotate writes value as the next version of name and then flips the
	// current pointer to it, returning the new version, or ErrNotFound.
	Rotate(ctx context.Context, name string, value []byte) (Version, error)
	// Delete removes the entry name and every one of its versions, or
	// returns ErrNotFound.
	Delete(ctx context.Context, name string) error
	// Rewrap re-seals every stored version under a new master key, so the
	// old master key can be retired.
	Rewrap(ctx context.Context, newMaster []byte) error
}

// The refusals. The names follow the refusal states of
// pkg/executor/secretsencryption.go.
var (
	// ErrInvalidName reports an entry name that may not be used. A name is
	// validated before it becomes a file name: it is not empty, contains no
	// path separator, and is not made only of dots.
	ErrInvalidName = errors.New("invalid keystore entry name: it must be non-empty, contain no path separator, and not consist only of dots")
	// ErrExists reports a Put on a name that already exists; a new value for
	// an existing entry is a Rotate.
	ErrExists = errors.New("keystore entry already exists; use rotate to store a new version")
	// ErrCorrupt reports a record that fails its authenticated open or does
	// not parse: it was tampered with, moved or truncated. A current pointer
	// that authenticates but is older than the recorded floor is reported the
	// same way, with a message that says so. It is distinct from
	// ErrMasterUntrusted, which concerns the master key file itself.
	ErrCorrupt = errors.New("keystore record is corrupt: it failed authentication or does not parse, so it was tampered with, moved or truncated; restore it from backup")
	// ErrNotFound reports that no entry has the requested name.
	ErrNotFound = errors.New("keystore entry not found")
	// ErrVersionNotFound reports that the entry exists but holds no such
	// version.
	ErrVersionNotFound = errors.New("keystore entry version not found")
	// ErrEncryptionOff is the delivery reconciler's refusal to write a Secret
	// while secrets encryption is off on the control plane, unless the
	// operator overrides that explicitly.
	ErrEncryptionOff = errors.New("keystore delivery refused: secrets encryption is off, so a delivered Secret would be stored in plaintext in the datastore; enable secrets encryption, or override explicitly")
	// ErrMasterMissing reports that the keystore holds entries but the master
	// key file is missing, so none of them can be opened.
	ErrMasterMissing = errors.New("the keystore master key file is missing: every entry is unreadable without it; restore it from backup")
	// ErrMasterUntrusted reports a master key file that may not be used: its
	// mode is not 0600, it is not owned by the service user, or it does not
	// match the recorded fingerprint.
	ErrMasterUntrusted = errors.New("the keystore master key file is not trusted: it must be mode 0600, owned by the service user, and match its recorded fingerprint")
)
