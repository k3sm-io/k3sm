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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
)

// This file is Rewrap's one class of user record: each scope.key, re-sealed
// under the new master's scope-wrap key W with its plaintext (K_u), kind,
// name, version, generation and created time unchanged
// (docs/design/keystore.md § "User scope", "Rewrap of scope keys"). It moves
// in Rewrap's two phases like every other record: a scope.key.new beside it
// (step 3), then a rename over it (step 4). Nothing else under .user is
// read or written: every user record stays sealed under its K_u, byte for
// byte. The owner's live GeneratedUID is not read: the binding is the
// record's generation, which the re-seal keeps.

// UserScopeRewrapWarning is what rewrap prints, before it starts and when
// it finishes, while the keystore has a .user directory (U101): Rewrap
// re-seals each scope.key under the new master and does not re-key the
// scope key inside it.
const UserScopeRewrapWarning = "warning: user scopes exist. Rewrap re-seals each user scope's key under the new master but does not re-key it, so an old master together with an old copy of a user's scope.key still opens that user's records, old and new. After a suspected master exposure, each user must re-put their values, with new credentials from each value's issuer."

// UserScopesExist reports whether the entries' directory holds a .user
// name, whatever its type: whether rewrap prints UserScopeRewrapWarning. A
// missing entries' directory holds none. It reads one name and writes
// nothing.
func (s *FileStore) UserScopesExist(ctx context.Context) (bool, error) {
	if err := s.checkConfig(); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	root, err := s.openDir(s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }() // read-only
	_, err = root.Lstat(userScopesName)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check for keystore/%s: %w", userScopesName, err)
	}
	return true, nil
}

// eachScopeDir calls fn with every user scope directory under root's .user,
// by its uid name, in sorted order. A missing .user is no scope; a .user, or
// a scope directory, that is not a directory the store trusts is ErrCorrupt,
// since a Rewrap past it could strand a scope.key under a master that no
// longer exists. A name that is not a decimal uid is no scope.
func (s *FileStore) eachScopeDir(ctx context.Context, root *os.Root, fn func(uid string, dir *os.Root) error) error {
	users, err := s.openSubdir(root, userScopesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: keystore/%s is not a user-scope directory the store trusts, so its scope keys cannot be re-wrapped; root must restore or remove it: %w", ErrCorrupt, userScopesName, err)
	}
	defer func() { _ = users.Close() }() // each write is fsynced in its own directory
	names, err := readDirNames(users, maxDirNames)
	if err != nil {
		return err
	}
	sort.Strings(names)
	for i, n := range names {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		if n == "0" || !decimalUID(n) {
			continue
		}
		dir, err := s.openSubdir(users, n, false)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: keystore/%s/%s: %w", ErrCorrupt, userScopesName, n, err)
		}
		err = fn(n, dir)
		_ = dir.Close() // each write is fsynced by writeFile or syncDir
		if err != nil {
			return err
		}
	}
	return nil
}

// withScopeDir calls fn with the scope directory .user/<uid>.
func (s *FileStore) withScopeDir(root *os.Root, uid string, fn func(dir *os.Root) error) error {
	users, err := s.openSubdir(root, userScopesName, false)
	if err != nil {
		return fmt.Errorf("%w: keystore/%s: %w", ErrCorrupt, userScopesName, err)
	}
	defer func() { _ = users.Close() }() // nothing is written in .user itself
	dir, err := s.openSubdir(users, uid, false)
	if err != nil {
		return fmt.Errorf("%w: keystore/%s/%s: %w", ErrCorrupt, userScopesName, uid, err)
	}
	defer func() { _ = dir.Close() }() // each write is fsynced by writeFile or syncDir
	return fn(dir)
}

// planScopes lists every user scope with a scope.key, and refuses unless
// each opens under old's W or, when next is set, under next's. It reports
// whether any opens only under next's: whether a commit under next began. A
// scope directory with no scope.key holds nothing sealed under W.
func (s *FileStore) planScopes(ctx context.Context, root *os.Root, old keys, next *keys) ([]planned, bool, error) {
	var (
		out       []planned
		committed bool
	)
	err := s.eachScopeDir(ctx, root, func(uid string, dir *os.Root) error {
		r, err := s.readScopeKeyRecord(dir)
		if errors.Is(err, errNoScopeKey) {
			return nil
		}
		if err == nil {
			var underNext bool
			underNext, err = openScopeKeyEither(r, userScopePrefix+uid, old, next)
			committed = committed || underNext
		}
		if err != nil {
			return fmt.Errorf("the scope key of user/%s does not open, and a rewrap would leave it sealed under a master that no longer exists: restore it first: %w", uid, err)
		}
		out = append(out, planned{scope: uid})
		return nil
	})
	return out, committed, err
}

// openScopeKeyEither opens r under old's W and, failing that and with next
// set, under next's, reporting whether it opened only under next's.
func openScopeKeyEither(r record, scope string, old keys, next *keys) (bool, error) {
	pt, err := r.open(old.wrap, scope)
	clear(pt)
	if err == nil || next == nil || !errors.Is(err, ErrCorrupt) {
		return false, err
	}
	pt, err = r.open(next.wrap, scope)
	clear(pt)
	return err == nil, err
}

// sealScopeKey is step 3 for one scope: a scope.key still under old's W is
// re-sealed under next's into its fsynced scope.key.new, the scope.key left
// alone; one already under next's is skipped.
func (s *FileStore) sealScopeKey(root *os.Root, uid string, old, next keys) error {
	scope := userScopePrefix + uid
	err := s.withScopeDir(root, uid, func(dir *os.Root) error {
		r, err := s.readScopeKeyRecord(dir)
		if err != nil {
			return err
		}
		pt, err := r.open(old.wrap, scope)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				return err
			}
			npt, err := r.open(next.wrap, scope)
			clear(npt)
			return err
		}
		defer clear(pt)
		moved := record{kind: r.kind, name: r.name, version: r.version, generation: r.generation, created: r.created}
		if err := moved.seal(next.wrap, scope, pt, s.rand); err != nil {
			return err
		}
		return s.writeFile(dir, scopeKeyName+newSuffix, moved.marshal())
	})
	if err != nil {
		return fmt.Errorf("the scope key of user/%s: %w", uid, err)
	}
	return nil
}

// commitScopeKey is step 4 for one scope: a scope.key still under old's W
// is replaced by its scope.key.new, which must open under next's W and hold
// the same key, kind, name, version, generation and created time (else
// ErrCorrupt, and it is not renamed); one already under next's has any
// scope.key.new beside it removed.
func (s *FileStore) commitScopeKey(root *os.Root, uid string, old, next keys) error {
	scope := userScopePrefix + uid
	err := s.withScopeDir(root, uid, func(dir *os.Root) error {
		r, err := s.readScopeKeyRecord(dir)
		if err != nil {
			return err
		}
		pt, err := r.open(old.wrap, scope)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				return err
			}
			npt, err := r.open(next.wrap, scope)
			clear(npt)
			if err != nil {
				return err
			}
			if err := dir.Remove(scopeKeyName + newSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return syncDir(dir)
		}
		defer clear(pt)
		b, fi, err := readFile(dir, scopeKeyName+newSuffix, int64(maxScopeKeyRecordSize))
		if err != nil {
			return fmt.Errorf("%w: %s%s: %w", ErrCorrupt, scopeKeyName, newSuffix, err)
		}
		if err := s.checkOwned(fi, fileMode); err != nil {
			return fmt.Errorf("%w: %s%s: %w", ErrCorrupt, scopeKeyName, newSuffix, err)
		}
		nr, err := parseScopeKey(b)
		if err != nil {
			return err
		}
		npt, err := nr.open(next.wrap, scope)
		if err != nil {
			return fmt.Errorf("%s%s: %w", scopeKeyName, newSuffix, err)
		}
		same := nr.kind == r.kind && nr.name == r.name && nr.version == r.version && nr.generation == r.generation && nr.created == r.created && bytes.Equal(npt, pt)
		clear(npt)
		if !same {
			return fmt.Errorf("%w: %s%s does not hold the record it replaces", ErrCorrupt, scopeKeyName, newSuffix)
		}
		if err := dir.Rename(scopeKeyName+newSuffix, scopeKeyName); err != nil {
			return err
		}
		if err := syncDir(dir); err != nil {
			return err
		}
		return s.step("rename " + userScopesName + "/" + uid + "/" + scopeKeyName)
	})
	if err != nil {
		return fmt.Errorf("the scope key of user/%s: %w", uid, err)
	}
	return nil
}
