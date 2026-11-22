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
	"fmt"
	"time"

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
// typed.ErrInvalidCredential, a token without an expiry and an oauth pair
// without its access token, access expiry, refresh token or a refresh owner
// in the grammar. A put over an existing name of another kind is
// ErrKindMismatch, and of the same kind ErrExists.
func (s *FileStore) PutCredential(ctx context.Context, name string, kind Kind, e typed.Envelope) (Version, error) {
	v, err := s.putCredential(ctx, name, kind, e)
	if err != nil {
		return Version{}, fmt.Errorf("put %s: %w", name, err)
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
	if _, err := s.envelope(kind, e); err != nil {
		return Version{}, err
	}
	return s.putChecked(ctx, name, kind, func() ([]byte, error) { return s.envelope(kind, e) })
}

// GenerateSSH creates name at version 1 holding a new ed25519 SSH key, its
// seed drawn from the store's random seam, with comment (empty for none). It
// returns the version and the public key's authorized_keys line; the private
// half leaves the store only by projection.
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
	if err != nil {
		return Version{}, "", err
	}
	return v, line, nil
}

// RotateCredential writes e as the next version of the typed entry name,
// stamping its issue time as PutCredential does. kind must be the entry's
// (ErrKindMismatch otherwise). An oauth entry keeps its current version and
// one previous: the rotation records the oldest retained version in the
// pointer and unlinks the versions below it.
func (s *FileStore) RotateCredential(ctx context.Context, name string, kind Kind, e typed.Envelope) (Version, error) {
	return s.rotateCredential(ctx, name, kind, 0, e)
}

// RotateIf is RotateCredential that refuses, with ErrVersionStale, unless the
// entry's current version is current: a writer that read a version (the
// refresher, which read the pair it refreshed) never writes over a newer one.
func (s *FileStore) RotateIf(ctx context.Context, name string, kind Kind, current uint64, e typed.Envelope) (Version, error) {
	if current == 0 {
		return Version{}, fmt.Errorf("rotate %s: %w: version 0 is never current", name, ErrVersionStale)
	}
	return s.rotateCredential(ctx, name, kind, current, e)
}

// rotateCredential is RotateCredential, and RotateIf when current is not 0.
func (s *FileStore) rotateCredential(ctx context.Context, name string, kind Kind, current uint64, e typed.Envelope) (Version, error) {
	v, err := func() (Version, error) {
		if _, err := s.envelope(kind, e); err != nil {
			return Version{}, err
		}
		return s.rotate(ctx, name, func(_ *entry, _ keys, old Version) ([]byte, error) {
			if old.Kind != kind {
				return nil, fmt.Errorf("%w: %s is %s, not %s", ErrKindMismatch, name, old.Kind, kind)
			}
			if current != 0 && old.Version != current {
				return nil, fmt.Errorf("%w: version %d is current, not %d", ErrVersionStale, old.Version, current)
			}
			return s.envelope(kind, e)
		})
	}()
	if err != nil {
		return Version{}, fmt.Errorf("rotate %s: %w", name, err)
	}
	return v, nil
}

// RotateFrom writes the value of version from of name as its next version:
// the rollback rotate --from-version names. It is refused for oauth with
// ErrFromVersionOAuth: a rotated refresh token is never written back. A
// typed value keeps the issue time it was sealed with.
func (s *FileStore) RotateFrom(ctx context.Context, name string, from uint64) (Version, error) {
	v, err := s.rotate(ctx, name, func(e *entry, k keys, old Version) ([]byte, error) {
		if old.Kind == KindOAuth {
			return nil, ErrFromVersionOAuth
		}
		if from == 0 || from > old.Version {
			return nil, ErrVersionNotFound
		}
		_, val, err := e.version(k, from)
		return val, err
	})
	if err != nil {
		return Version{}, fmt.Errorf("rotate %s: %w", name, err)
	}
	return v, nil
}

// CurrentCredential returns the version the current pointer of the typed
// entry name names, with its typed.Credential: never an oauth refresh token.
// An ed25519 or opaque entry is ErrKindMismatch.
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
	case KindOAuth:
		e.Credential.AccessIssuedAt = now
	}
	return typed.Encode(ck, e)
}
