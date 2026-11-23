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
	"encoding/hex"
	"errors"
	"time"

	"k3sm.io/k3sm/pkg/keystore/typed"
)

// This file is the keystore's contract: the Store interface, its types and its
// refusals. FileStore (store.go) is the implementation, landing in parts as
// docs/design/keystore.md § "Acceptance gate" lays out.

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
	// KindToken is a bearer token that always carries an expiry. Its value
	// is a typed envelope (pkg/keystore/typed), read as a typed.Credential.
	KindToken
	// KindSSH is an ed25519 SSH key, a typed envelope holding its seed.
	KindSSH
	// KindOAuth is an OAuth access and refresh pair, a typed envelope whose
	// refresh token no read returns.
	KindOAuth
)

// String returns the lowercase name of k, as the CLI prints it.
func (k Kind) String() string {
	switch k {
	case KindEd25519:
		return "ed25519"
	case KindOpaque:
		return "opaque"
	case KindToken:
		return "token"
	case KindSSH:
		return "ssh"
	case KindOAuth:
		return "oauth"
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

	// identity names this version of this entry's life, and no other: a
	// digest of the entry's generation, name, version number and record
	// digest (see versionIdentity). An entry
	// deleted and put again restarts at version 1 under a fresh generation,
	// so its versions never share an identity with the old entry's. It is
	// opaque and unexported: RotateIf compares the identity of the Version
	// a writer read with the current one, and pkg/keystore exposes no
	// generation.
	identity [identitySize]byte
	// digest is the record digest of the sealed file the version was read
	// from (RecordDigest).
	digest [digestSize]byte
}

// identitySize is the length of a Version's identity.
const identitySize = 16

// RecordDigest is the hex digest of the exact sealed record the version was
// read from: the first 16 bytes of the SHA-256 of its nonce and ciphertext.
// It reveals nothing about the value. Two records of one version number
// (a failed rotation's file and its retry's) have different digests, and a
// Rewrap changes it. It is empty for a Version not read from the store.
func (v Version) RecordDigest() string {
	if v.digest == ([digestSize]byte{}) {
		return ""
	}
	return hex.EncodeToString(v.digest[:])
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
	// Err is non-nil exactly when the entry could not be opened: its generation
	// file, its current pointer or any version the pointer covers is missing,
	// fails authentication or does not parse, or the floor rules the pointer
	// out (an older sequence, or another generation). A directory with no current
	// pointer is an interrupted Put, which is not an entry and is not listed,
	// only when it holds nothing, generation, or generation and v1 (plus
	// temporary files) and the floor does not record its generation; any other
	// such directory is an entry with an Err. Current and Versions are zero
	// then. List reports such an entry here, not as an error for the whole
	// call, so one bad entry does not hide the healthy ones.
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
	// master key missing or untrusted, the entries' directory untrusted or
	// unreadable, the recorded floor untrusted or malformed, or the store lock
	// not acquired (in time, or before ctx is done).
	List(ctx context.Context) ([]Entry, error)
	// Rotate writes value as the next version of name and then flips the
	// current pointer to it, returning the new version, or ErrNotFound.
	Rotate(ctx context.Context, name string, value []byte) (Version, error)
	// Delete removes the entry name and every one of its versions, or
	// returns ErrNotFound.
	Delete(ctx context.Context, name string) error
	// Rewrap re-seals every stored version and current pointer under a new
	// master key, then retires the old one. It is resumable: a crash at any
	// step leaves every record readable, and the next call completes it.
	// Each user scope's scope.key is re-sealed with them; every other user
	// record is left as it is.
	Rewrap(ctx context.Context, newMaster []byte) error
}

// The refusals. The names follow the refusal states of
// pkg/executor/secretsencryption.go.
var (
	// ErrInvalidName reports an entry name that may not be used. A name is
	// validated before it becomes a file name: it must be a Kubernetes
	// DNS-1123 subdomain (1 to 253 bytes of dot-separated labels of lowercase
	// letters, digits and '-', each beginning and ending with a letter or
	// digit). That rules out a path separator, a name made only of dots, a
	// name that differs from another only in case (APFS is case-insensitive
	// by default), a dot name the store keeps for its own files, and a name
	// that could not be the delivered Secret's default name.
	ErrInvalidName = errors.New("invalid keystore entry name: it must be 1 to 253 bytes of dot-separated labels of lowercase letters, digits and '-', each beginning and ending with a letter or digit")
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
	// ErrKindUnsupported is returned for a record this build cannot read: a
	// kind byte from 6 to 0xFC, or a typed envelope version it does not
	// know. It was written by a newer k3sm, or altered to read as one, so
	// it is not wrapped in ErrCorrupt; its text names an upgrade first and
	// a restore when this k3sm is current. It is typed.ErrKindUnsupported,
	// so the envelope decoder's refusal matches it unmapped.
	ErrKindUnsupported = typed.ErrKindUnsupported
	// ErrKindMismatch reports a rotate, or a put over an existing name, of
	// a kind other than the entry's: an entry's kind is fixed when it is
	// created, and changing kind means a new entry name.
	ErrKindMismatch = errors.New("the keystore entry holds another kind: an entry's kind is fixed when it is created; store the new kind under a new name")
	// ErrTypedCredential reports a raw-value read (Current, Get) of a
	// typed entry, token, ssh or oauth, whose value is read only as a
	// typed.Credential (CurrentCredential, GetCredential), so no raw read
	// can carry an oauth refresh token.
	ErrTypedCredential = errors.New("the keystore entry is a typed credential: read it as a typed credential, not as raw bytes")
	// ErrVersionStale reports a RotateIf whose expected current version is
	// not the entry's current version: another write came first, or the
	// entry was deleted and put again since the expected version was read,
	// or the expected Version was not read from the store.
	ErrVersionStale = errors.New("the keystore entry's current version is not the one expected: another write came first; read it again")
	// ErrCommitted marks an error returned after a write committed: the
	// change stands, and a step after its commit point (the floor line, the
	// oauth prune, an audit line) failed. A rotation that returns it also
	// returns the Version it made current. A refresher that gets it must
	// read the entry again and work from what it reads, and never retry
	// from the pair it held: that pair is no longer current, and its refresh
	// token may already be rotated at the provider. The next write records
	// the floor and prunes what was left.
	//
	// ErrCommitted takes precedence: an error that matches it matches no
	// other sentinel of this package, ErrCorrupt included, whatever its
	// cause was (a floor refusal reads as ErrCorrupt). The cause is in the
	// message only.
	//
	// The refresher's contract on a failure that does not match it: nothing
	// was made current, and the provider may already have rotated the
	// stored pair's refresh token, so the refresher retries RotateIf with
	// the new pair it holds in memory, and never refreshes again from the
	// stored pair. When the failure matches ErrOrphanVersion, the new pair
	// is already sealed above the pointer: a retry is refused with
	// ErrOrphanVersion too, and the refresher stops and leaves the entry to
	// an operator's Adopt.
	ErrCommitted = errors.New("the change was made")
	// ErrRefreshOwnerFixed reports a rotation of an oauth entry whose new
	// pair names another refresh owner: the owner is fixed when the entry
	// is put, so the server never starts or stops refreshing a pair because
	// a rotation said so. Changing owner means rm and put again. The socket
	// answers it as invalid-value.
	ErrRefreshOwnerFixed = errors.New("the oauth entry's refresh owner is fixed when it is put: a rotation must name the same owner; to change it, rm the entry and put it again")
	// ErrFromVersionOAuth reports a rotate from an earlier version of an
	// oauth entry: resurrecting a rotated refresh token can trip the
	// provider's reuse detection and revoke the whole grant.
	ErrFromVersionOAuth = errors.New("an oauth entry cannot be rotated from an earlier version: reusing a rotated refresh token can make the provider revoke the whole grant")
	// ErrOrphanVersion reports a version of an entry, above the one its
	// current pointer names, that authenticates as this entry's: a rotation
	// crashed between writing it and flipping the pointer, or an older
	// pointer was copied back over a newer one. For oauth it may hold the
	// provider's newest refresh token, so it is never unlinked, and an oauth
	// read refuses with it rather than hand out a pair that may already be
	// spent. An oauth rotation that fails after its version file is in
	// place and before its pointer flip keeps that file and returns an
	// error matching it, never ErrCommitted.
	ErrOrphanVersion = errors.New("a sealed version of the keystore entry lies above its current pointer, left by a crashed rotation or a copied-back pointer")
	// ErrTombstoneEvicted reports a verb that made its change (a Delete, a
	// Put, a Rotate, an Adopt, a RaiseFloor) but whose floor writes dropped burials,
	// its own or other names', to stay within the floor's tombstone budget
	// or a name's cap of buried generations: a copy of each of those deleted
	// entries put back is accepted again. It comes with errCommitted
	// (Committed) when the change stands.
	ErrTombstoneEvicted = errors.New("the change is made, but the same floor write evicted tombstones to stay within the floor's tombstone budget or a name's cap of deleted generations, so a copy of each of those deleted entries put back would be accepted again; delete entries that are no longer used to make room")
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
	// ErrMasterUntrusted reports a master key that may not be used: the file
	// is a symlink, not mode 0600, not owned by the service user, not 32
	// bytes, or does not match its recorded fingerprint (or that fingerprint
	// is missing), or its directory, or cred/ above it, is a symlink, not the
	// service user's, or open to group or others.
	ErrMasterUntrusted = errors.New("the keystore master key is not trusted: the master file must be a regular file of 32 bytes, mode 0600, owned by the service user, and match its recorded fingerprint, in a directory (and cred/ above it) owned by the service user and closed to group and others")
	// ErrScopeUnsupported was Rewrap's refusal, in builds before scope-key
	// Rewrap, while the name reserved for user scopes existed. This build
	// re-wraps scope keys and no longer returns it; the sentinel stays so a
	// caller that maps it, and the reconciler's table of store sentinels,
	// keep their meaning for an older build's answer.
	ErrScopeUnsupported = errors.New("the keystore holds user scopes at the reserved path keystore/.user, which this build of k3sm cannot re-wrap: the master was not swapped and every record still opens; upgrade k3sm, then run rewrap again. If keystore/.user is not a user scope, root must remove it before rewrap can run")
	// ErrScopeAbsent reports a user scope, or a container of it, that is not
	// there: .user, .user/<uid>/, its scope.key or its entries/ directory. It
	// is not a definitive absence, and never matches ErrNotFound: a scope a
	// restore left out, a volume not yet mounted or a directory moved aside
	// must not read as "every entry gone". A read never mints a scope, so a
	// read of a uid that has stored nothing answers it.
	ErrScopeAbsent = errors.New("the user scope is absent: its directory, its scope.key or its entries/ directory is missing; a read creates nothing, and a missing scope is not an empty one")
	// ErrScopeOwnerChanged reports a user scope whose uid's live
	// GeneratedUID is a real answer that differs from the one its scope.key is
	// bound to: the account was deleted and its uid reused, so nothing of the
	// old account's opens. Root removes such a scope.
	ErrScopeOwnerChanged = errors.New("the user scope belongs to another account: the uid's GeneratedUID differs from the one its scope key is bound to, so the uid was reused; root must remove the scope")
	// ErrScopeOwnerUnknown reports that the uid's live GeneratedUID could not
	// be read: the lookup failed, passed its deadline, or answered a
	// synthesized value for a uid with no directory record. Nothing in the
	// scope opens and no scope key is minted.
	ErrScopeOwnerUnknown = errors.New("the user scope's owner could not be confirmed: the uid's GeneratedUID lookup failed, timed out or found no directory record, so nothing in the scope was opened or created")
	// ErrQuota reports a user-scope write past one of the scope's bounds:
	// 256 entries or 16 MiB of sealed records (every file in every entry
	// directory, its generation file included, and the deliveries record)
	// for put, 64 live deliveries (or 320 in all, tombstones included) for
	// deliver. rm and withdraw are never refused for a quota. rm makes room;
	// a withdraw leaves a tombstone that counts until its Secret is gone,
	// when it is reclaimed (the reconciler's pruning, a later change).
	ErrQuota = errors.New("the user scope is over its quota: at most 256 entries and 16 MiB of sealed records (the entries' files and the deliveries record), and 64 live deliveries or 320 in all; rm an entry (then put it again) to make room. Withdrawn deliveries still count until they are reclaimed once their Secret is gone")
	// ErrRewrapInProgress is a user scope's refusal to write while a Rewrap is
	// half done: master.next, or its fingerprint, is in the master directory.
	// The user path never completes a swap or mints a master, and a .user it
	// created would refuse Rewrap's resume, so it changes nothing until root
	// finishes the rewrap.
	ErrRewrapInProgress = errors.New("a keystore rewrap is in progress: root must finish it (run rewrap again) before a user scope can be written; nothing was changed")
	// ErrRewrapResumed reports that Rewrap found an earlier, interrupted
	// rewrap whose new key was already live for some record, completed it
	// under that key rather than the one supplied, and stopped. The master is
	// now that earlier key, which the caller did not choose, so Rewrap must be
	// run again to retire it.
	ErrRewrapResumed = errors.New("an earlier interrupted rewrap was completed, with a key other than the one supplied: run rewrap again to retire that key")
	// ErrRewrapNotStarted marks an error Rewrap returned before it first
	// wrote master.next from the key it was given, so nothing is sealed under
	// that key by the call. A caller holding a key it minted for that call
	// may discard it; after any other Rewrap error the key may be needed to
	// finish.
	ErrRewrapNotStarted = errors.New("nothing was sealed under the new master key")
	// ErrRewrapResumeFailed marks an error Rewrap returned while it was
	// completing an earlier, interrupted rewrap under that rewrap's key, after
	// it had advanced it: records may have moved under that key, or its
	// master swap progressed. It never matches ErrRewrapNotStarted, though
	// nothing was sealed under the key supplied: the earlier rewrap's key is
	// what finishes it, and the caller keeps every key file it holds.
	ErrRewrapResumeFailed = errors.New("an earlier interrupted rewrap was advanced and did not finish")
	// ErrRewrapSwapUnsynced marks a Rewrap error after the master swap was
	// renamed through and the directory sync (or a later step) failed, so the
	// rewrap is complete. Beside ErrRewrapResumeFailed, the swap was an
	// earlier rewrap's: the master is that rewrap's key, a new Rewrap retires
	// it, and no key file finishes anything. Alone, it was this call's own:
	// the master is the key supplied, which the caller must keep.
	ErrRewrapSwapUnsynced = errors.New("the master swap completed but did not sync")
)
