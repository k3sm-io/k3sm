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
	"fmt"
	"time"

	"k3sm.io/apis/keystore/credential"
	"k3sm.io/k3sm/pkg/keystore/typed"
)

// This file is the typed store verbs: docs/design/keystore.md § "Typed
// credentials", "Record kinds, the typed envelope and retention". A typed
// entry (token, ssh, oauth) is written from a typed.Envelope, whose issue
// time the store stamps from its clock, and read back only as a
// typed.Credential, which has no field for an oauth refresh token.

// PutCredential creates name at version 1 holding e, of the typed kind kind.
// It stamps a token's issuedAt and an oauth pair's accessIssuedAt from the
// store's clock, whatever e carries, and refuses, with
// typed.ErrInvalidCredential, a token without an expiry or with one not
// after that issue time, and an oauth pair
// without its access token, access expiry, refresh token or a refresh owner
// in the grammar. A put over an existing name of another kind is
// ErrKindMismatch, and of the same kind ErrExists. A failure after the
// pointer's rename returns the new version with an error matching
// ErrCommitted.
func (s *FileStore) PutCredential(ctx context.Context, name string, kind Kind, e typed.Envelope) (Version, error) {
	v, err := s.putCredential(ctx, name, kind, e)
	if err != nil {
		// v is the committed version when err is ErrCommitted.
		return v, fmt.Errorf("put %s: %w", name, err)
	}
	return v, nil
}

func (s *FileStore) putCredential(ctx context.Context, name string, kind Kind, e typed.Envelope) (Version, error) {
	if err := s.checkConfig(); err != nil {
		return Version{}, err
	}
	if err := checkName(name); err != nil {
		return Version{}, err
	}
	// The envelope is checked before anything is locked, and sealed with
	// the time the store takes it once it is.
	probe, err := s.envelope(kind, e)
	clear(probe)
	if err != nil {
		return Version{}, err
	}
	// The envelope is the store's own buffer, not the caller's: it is
	// cleared once sealed, whatever the outcome.
	var sealed []byte
	defer func() { clear(sealed) }()
	return s.putChecked(ctx, name, kind, func() ([]byte, error) {
		var err error
		sealed, err = s.ownedEnvelope(kind, e)
		return sealed, err
	})
}

// GenerateSSH creates name at version 1 holding a new ed25519 SSH key, its
// seed drawn from the store's random seam, with comment (empty for none). It
// returns the version and the public key's authorized_keys line; the private
// half leaves the store only by projection. A failure after the commit point
// returns both with an error matching ErrCommitted, and a Put whose floor
// write drops a tombstone returns both with a committed ErrTombstoneEvicted
// (Committed): the key exists.
func (s *FileStore) GenerateSSH(ctx context.Context, name, comment string) (Version, string, error) {
	seed, err := typed.GenerateSSH(s.rand)
	if err != nil {
		return Version{}, "", fmt.Errorf("generate %s: %w", name, err)
	}
	defer clear(seed)
	line, err := typed.SSHAuthorizedKey(seed, comment)
	if err != nil {
		return Version{}, "", fmt.Errorf("generate %s: %w", name, err)
	}
	v, err := s.PutCredential(ctx, name, KindSSH, typed.Envelope{Credential: typed.Credential{
		Algorithm: typed.SSHAlgorithmEd25519,
		Seed:      seed,
		Comment:   comment,
	}})
	if Committed(err) {
		return v, line, err
	}
	if err != nil {
		return Version{}, "", err
	}
	return v, line, nil
}

// RotateCredential writes e as the next version of the typed entry name,
// stamping its issue time as PutCredential does. kind must be the entry's
// (ErrKindMismatch otherwise), and an oauth envelope must name the entry's
// refresh owner (ErrRefreshOwnerFixed otherwise). An oauth entry keeps its current version and
// one previous: the rotation records the oldest retained version in the
// pointer and unlinks the versions below it. A failure after the pointer
// flip (the floor line, the prune) returns the new version with an error
// matching ErrCommitted: read the entry again, and never retry from the old
// pair. An oauth rotation that fails after writing its version file and
// before the flip keeps that file for Adopt and returns an error matching
// ErrOrphanVersion; see ErrCommitted for the refresher's retry contract.
func (s *FileStore) RotateCredential(ctx context.Context, name string, kind Kind, e typed.Envelope) (Version, error) {
	return s.rotateCredential(ctx, name, kind, nil, e)
}

// RotateIf is RotateCredential that refuses, with ErrVersionStale, unless
// read is the entry's current version: the same version number of the same
// life of the entry. read is a Version a read returned (CurrentCredential,
// GetCredential or the refresher's opener), which carries an opaque identity
// besides its number, so a writer that read a version (the refresher, which
// read the pair it refreshed) never writes over a newer one, nor over an
// entry deleted and put again since, whose versions restart at 1. A Version
// built by the caller has no identity and is always stale.
func (s *FileStore) RotateIf(ctx context.Context, name string, kind Kind, read Version, e typed.Envelope) (Version, error) {
	if read.Version == 0 || read.identity == ([identitySize]byte{}) {
		return Version{}, fmt.Errorf("rotate %s: %w: the expected version was not read from the store", name, ErrVersionStale)
	}
	return s.rotateCredential(ctx, name, kind, &read, e)
}

// rotateCredential is RotateCredential, and RotateIf when read is not nil.
func (s *FileStore) rotateCredential(ctx context.Context, name string, kind Kind, read *Version, e typed.Envelope) (Version, error) {
	var sealed []byte
	defer func() { clear(sealed) }() // the store's own buffer, sealed by then or refused
	v, err := func() (Version, error) {
		probe, err := s.envelope(kind, e)
		clear(probe)
		if err != nil {
			return Version{}, err
		}
		return s.rotate(ctx, name, func(en *entry, k keys, old Version) ([]byte, error) {
			if old.Kind != kind {
				return nil, fmt.Errorf("%w: %s is %s, not %s", ErrKindMismatch, name, old.Kind, kind)
			}
			if read != nil && (old.Version != read.Version || old.identity != read.identity) {
				return nil, fmt.Errorf("%w: the current version is not the one read (version %d is current, version %d was read)", ErrVersionStale, old.Version, read.Version)
			}
			if kind == KindOAuth {
				if err := s.sameRefreshOwner(en, k, old, e.Credential.RefreshOwner); err != nil {
					return nil, err
				}
			}
			var err error
			sealed, err = s.ownedEnvelope(kind, e)
			return sealed, err
		})
	}()
	if err != nil {
		// v is the committed version when err is ErrCommitted.
		return v, fmt.Errorf("rotate %s: %w", name, err)
	}
	return v, nil
}

// sameRefreshOwner refuses, with ErrRefreshOwnerFixed, an oauth rotation
// whose envelope names a refresh owner other than old's, the current version
// of en: the owner is fixed when the entry is put.
func (s *FileStore) sameRefreshOwner(en *entry, k keys, old Version, owner string) error {
	_, val, err := en.version(k, old.Version)
	defer clear(val)
	if err != nil {
		return err
	}
	env, err := typed.Decode(credential.KindOAuth, val)
	// Only the owner is compared: both tokens are cleared at once.
	s.owned(env.Credential.AccessToken)
	clear(env.Credential.AccessToken)
	clear(env.RefreshToken)
	if err != nil {
		return fmt.Errorf("%w: version %d: %w", ErrCorrupt, old.Version, err)
	}
	if env.Credential.RefreshOwner != owner {
		return fmt.Errorf("%w: the entry's refresh owner is %s, not %s", ErrRefreshOwnerFixed, env.Credential.RefreshOwner, owner)
	}
	return nil
}

// RotateFrom writes the value of version from of name as its next version:
// the rollback rotate --from-version names. It is refused for oauth with
// ErrFromVersionOAuth: a rotated refresh token is never written back. Only
// an oauth entry has a refresh owner, so that refusal also keeps RotateFrom
// from changing one. A source version whose kind is not the entry's current
// kind is refused with ErrKindMismatch.
//
// A typed value keeps the issue time and expiry it was sealed with: nothing
// is re-stamped or checked against the clock, so a token restored past its
// expiresAt becomes the current version already expired, and reads as
// expired until a new value is rotated in.
func (s *FileStore) RotateFrom(ctx context.Context, name string, from uint64) (Version, error) {
	var val []byte
	defer func() { clear(val) }() // sealed by then, or refused
	v, err := s.rotate(ctx, name, func(e *entry, k keys, old Version) ([]byte, error) {
		if old.Kind == KindOAuth {
			return nil, ErrFromVersionOAuth
		}
		if from == 0 || from > old.Version {
			return nil, ErrVersionNotFound
		}
		src, v, err := e.version(k, from)
		val = v
		if err != nil {
			return nil, err
		}
		if src.Kind != old.Kind {
			return nil, fmt.Errorf("%w: version %d is %s, but %s is %s", ErrKindMismatch, from, src.Kind, name, old.Kind)
		}
		return val, nil
	})
	if err != nil {
		// v is the committed version when err is ErrCommitted.
		return v, fmt.Errorf("rotate %s: %w", name, err)
	}
	return v, nil
}

// CurrentCredential returns the version the current pointer of the typed
// entry name names, with its typed.Credential: never an oauth refresh token.
// An ed25519 or opaque entry is ErrKindMismatch.
//
// The refresher's contract: an oauth entry with a sealed version above its
// current pointer (an orphan a crashed rotation left, holding the
// provider's newer pair) is refused with ErrOrphanVersion, never read as the
// older pair, because that pair's refresh token may already be spent at the
// provider. A refresher that gets ErrOrphanVersion stops refreshing the
// entry and leaves it to an operator's Adopt; it never rotates around it.
// A token or ssh entry is refused the same way: the orphan may be a newer
// committed version behind a copied-back pointer.
func (s *FileStore) CurrentCredential(ctx context.Context, name string) (Version, typed.Credential, error) {
	return s.credential(ctx, name, 0)
}

// GetCredential is CurrentCredential for version of name, which must be
// committed: from the oldest retained version to the current one.
func (s *FileStore) GetCredential(ctx context.Context, name string, version uint64) (Version, typed.Credential, error) {
	if version == 0 {
		return Version{}, typed.Credential{}, fmt.Errorf("%s: %w", name, ErrVersionNotFound)
	}
	return s.credential(ctx, name, version)
}

// credential reads version (0 for the current one) of name as a
// typed.Credential. The envelope is decoded here, and only its Credential,
// which has no refresh field, leaves.
func (s *FileStore) credential(ctx context.Context, name string, version uint64) (Version, typed.Credential, error) {
	var (
		v Version
		c typed.Credential
	)
	err := s.read(ctx, name, func(e *entry, k keys, fl floor) error {
		cur, _, low, err := e.checkedRange(k, fl)
		if err != nil {
			return err
		}
		if version == 0 {
			version = cur
		}
		if version > cur || version < low {
			return ErrVersionNotFound
		}
		var val []byte
		v, val, err = e.version(k, version)
		defer clear(val)
		if err != nil {
			return err
		}
		ck, ok := credentialKind(v.Kind)
		if !ok {
			return fmt.Errorf("%w: %s is %s, not a typed credential", ErrKindMismatch, name, v.Kind)
		}
		if err := readAbove(ctx, e, k, cur); err != nil {
			if v.Kind == KindOAuth && errors.Is(err, ErrOrphanVersion) {
				return fmt.Errorf("%w; the current pair's refresh token may already be spent", err)
			}
			return err
		}
		env, err := typed.Decode(ck, val)
		if err != nil {
			return fmt.Errorf("%w: version %d: %w", ErrCorrupt, version, err)
		}
		clear(env.RefreshToken)
		c = env.Credential
		return nil
	})
	if err != nil {
		return Version{}, typed.Credential{}, err
	}
	return v, c, nil
}

// ownedEnvelope is envelope for a buffer the store seals and then clears,
// handed to the owned seam.
func (s *FileStore) ownedEnvelope(kind Kind, e typed.Envelope) ([]byte, error) {
	b, err := s.envelope(kind, e)
	if err == nil {
		s.owned(b)
	}
	return b, err
}

// envelope is e encoded for kind, a typed kind, with its issue time stamped
// from the store's clock (whole UTC seconds): the sealed time the Expiring
// threshold and the refresh schedule use, never the record's unauthenticated
// created header.
func (s *FileStore) envelope(kind Kind, e typed.Envelope) ([]byte, error) {
	ck, ok := credentialKind(kind)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a typed kind", ErrKindMismatch, kind)
	}
	now := time.Unix(s.now().Unix(), 0).UTC()
	switch kind {
	case KindToken:
		e.Credential.IssuedAt = now
		// A token that expires at or before the time the store takes it is
		// refused: it would be sealed already expired. An expiry the
		// envelope lacks is refused by Encode, which names the field.
		// Compared in whole seconds, as the envelope seals both: an
		// expiry within the issue second is sealed equal to it.
		if exp := e.Credential.ExpiresAt; !exp.IsZero() && exp.Unix() <= now.Unix() {
			return nil, fmt.Errorf("%w: the token expires at %s, not after its issue time %s", typed.ErrInvalidCredential,
				exp.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
		}
	case KindOAuth:
		e.Credential.AccessIssuedAt = now
		if exp := e.Credential.AccessExpiresAt; !exp.IsZero() && exp.Unix() <= now.Unix() {
			return nil, fmt.Errorf("%w: the access token expires at %s, not after its issue time %s", typed.ErrInvalidCredential,
				exp.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}
	return typed.Encode(ck, e)
}
