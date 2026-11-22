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
	"io/fs"
	"os"
	"sort"
	"strconv"

	keyentry "k3sm.io/apis/keystore/entry"
)

// This file is the user-scope store: docs/design/keystore.md § "User scope",
// "On-disk layout" and "Key hierarchy". A user scope lives under the entries'
// directory at
//
//	.user/<uid>/              0700, service user
//	  scope.key               0600, kind-0xFE record: K_u sealed under W
//	  entries/<name>/         same shape as a system entry, sealed under K_u
//
// and is reached only by descriptor from the entries' directory the store
// lock is held on: each directory is opened with openSubdir (Lstat, open,
// SameFile, owner and mode on the descriptor) and each file with readFile
// (O_NOFOLLOW, a regular file, a bounded read).
//
// Not here yet, and each the change named in the design: the delivery record
// (kind 0xFD) and scope-key Rewrap (Rewrap refuses while .user exists until
// then), quotas, and the user-scope floor. Until the user-scope floor lands,
// a user entry's pointer is checked against no floor, so a copied-back older
// pointer of a user entry is not refused; no caller outside this package
// reaches the user scope until the socket does, after the floor.

const (
	// scopeKeyName is a scope's wrapped key, scopeEntriesName its entries'
	// directory.
	scopeKeyName     = "scope.key"
	scopeEntriesName = "entries"
	// scopeKeyRecordName, scopeKeyEpoch and scopeKeySize are scope.key's
	// record name, its version (the key epoch) and its plaintext's size.
	scopeKeyRecordName = "scope"
	scopeKeyEpoch      = 1
	scopeKeySize       = 32
	// maxScopeKeyRecordSize bounds a read of scope.key: a record of its name
	// sealing a 32-byte key.
	maxScopeKeyRecordSize = headerSize + len(scopeKeyRecordName) + scopeKeySize + tagSize
)

// errNoScopeKey is a scope with no scope.key, or no directory for it: the one
// absence a mutating operation mints over.
var errNoScopeKey = fmt.Errorf("%w: no scope key", ErrScopeAbsent)

// UserScope is one uid's view of the store: the caller's own user scope and
// nothing else. Every name it is given must be user/<its uid>/<name>; any
// other name, a system/ name or another uid's included, answers ErrNotFound,
// worded exactly as an absent entry of its own, so the answer is no oracle
// for another user's names.
type UserScope struct {
	s     *FileStore
	uid   uint32
	scope string
}

// UserScope returns uid's view of the store. Uid 0 is refused: root has no
// user scope.
func (s *FileStore) UserScope(uid uint32) (*UserScope, error) {
	scope := userScopeOf(uid)
	if err := checkScope(scope); err != nil {
		return nil, err
	}
	return &UserScope{s: s, uid: uid, scope: scope}, nil
}

// notFound is the one ErrNotFound a UserScope answers for op, whatever the
// name: it carries no name, so the caller's own absent entry and another
// scope's entry read the same.
func notFound(op string) error {
	return fmt.Errorf("user scope %s: %w", op, ErrNotFound)
}

// fail wraps err for op, collapsing every ErrNotFound to notFound(op).
func fail(op string, err error) error {
	if errors.Is(err, ErrNotFound) {
		return notFound(op)
	}
	return fmt.Errorf("user scope %s: %w", op, err)
}

// own parses input as an API entry and returns its name part when it is in
// the caller's scope; any other valid entry is notFound.
func (u *UserScope) own(op, input string) (string, error) {
	e, err := ParseEntry(input)
	if err != nil {
		return "", fmt.Errorf("user scope %s: %w", op, err)
	}
	if e.Scope != keyentry.ScopeUser || e.UID != u.uid {
		return "", notFound(op)
	}
	return e.Name, nil
}

// Put stores value as version 1 of input, minting the scope on the uid's
// first mutating operation: the scope key is bound to the uid's live
// GeneratedUID, and a lookup that fails mints nothing.
func (u *UserScope) Put(ctx context.Context, input string, kind Kind, value []byte) (Version, error) {
	v, err := u.put(ctx, input, kind, value)
	if err != nil {
		return Version{}, fail("put", err)
	}
	return v, nil
}

func (u *UserScope) put(ctx context.Context, input string, kind Kind, value []byte) (Version, error) {
	if err := u.s.checkConfig(); err != nil {
		return Version{}, err
	}
	name, err := u.own("put", input)
	if err != nil {
		return Version{}, err
	}
	if err := checkValue(kind, value); err != nil {
		return Version{}, err
	}
	root, done, err := u.s.openLocked(ctx, true, true)
	if err != nil {
		return Version{}, err
	}
	defer done()
	// The master is taken, or minted, before .user exists: the mint counts
	// .user as an entry.
	k, err := u.s.masterForPut(root)
	if err != nil {
		return Version{}, err
	}
	uk, entries, err := u.openScope(root, func() ([]byte, error) { return k.wrap, nil })
	if errors.Is(err, errNoScopeKey) {
		uk, entries, err = u.mint(root, k.wrap)
	}
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = entries.Close() }() // writes are fsynced by writeFile
	e, err := u.s.createEntry(entries, name, nil)
	if err != nil {
		return Version{}, err
	}
	defer e.close()
	return u.s.writeEntry(e, uk, kind, value)
}

// Current returns the version input's pointer names, with its value.
func (u *UserScope) Current(ctx context.Context, input string) (Version, []byte, error) {
	var (
		v   Version
		val []byte
	)
	name, err := u.own("current", input)
	if err != nil {
		return Version{}, nil, err
	}
	err = u.read(ctx, func(entries *os.Root, uk keys) error {
		e, err := openEntry(entries, name, nil)
		if err != nil {
			return err
		}
		defer e.close()
		cur, _, err := e.checkedPointer(uk, nil)
		if err != nil {
			return err
		}
		v, val, err = e.version(uk, cur)
		return err
	})
	if err != nil {
		return Version{}, nil, fail("current", err)
	}
	return v, val, nil
}

// List returns every entry of the scope, sorted by name, as FileStore.List
// does: an entry that cannot be opened carries Err. A uid with no scope is
// ErrScopeAbsent.
func (u *UserScope) List(ctx context.Context) ([]Entry, error) {
	var out []Entry
	err := u.read(ctx, func(entries *os.Root, uk keys) error {
		names, err := readDirNames(entries, maxDirNames)
		if err != nil {
			return err
		}
		sort.Strings(names)
		for _, name := range names {
			if checkName(name) != nil {
				continue
			}
			e, err := openEntry(entries, name, nil)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				out = append(out, Entry{Name: name, Err: err})
				continue
			}
			out = append(out, listEntry(e, uk, nil))
			e.close()
		}
		return nil
	})
	if err != nil {
		return nil, fail("list", err)
	}
	return out, nil
}

// read runs fn on the scope's entries' directory and keys under the shared
// lock. A read never mints: a missing keystore, scope or container is
// ErrScopeAbsent.
func (u *UserScope) read(ctx context.Context, fn func(*os.Root, keys) error) error {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	root, done, err := u.s.openLocked(ctx, false, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return err
	}
	defer done()
	uk, entries, err := u.openScope(root, func() ([]byte, error) {
		k, err := u.s.loadMaster()
		return k.wrap, err
	})
	if err != nil {
		return err
	}
	defer func() { _ = entries.Close() }() // read-only; nothing to flush
	return fn(entries, uk)
}

// openScope opens the scope under root, the entries' directory, and returns
// its derived keys and its open entries' directory. wrap supplies W; it is
// called only once scope.key is found, so a missing scope is ErrScopeAbsent
// whether or not the master opens. A missing .user, .user/<uid>/ or
// scope.key is errNoScopeKey; a missing entries/ beside a scope.key is
// ErrScopeAbsent too, never an empty scope, and never minted over.
func (u *UserScope) openScope(root *os.Root, wrap func() ([]byte, error)) (keys, *os.Root, error) {
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return keys{}, nil, err
	}
	defer func() { _ = dir.Close() }() // read-only here
	ku, err := u.readScopeKey(dir, wrap)
	if err != nil {
		return keys{}, nil, err
	}
	uk, err := deriveKeys(ku, u.scope)
	clear(ku) // only the derived keys are kept
	if err != nil {
		return keys{}, nil, err
	}
	entries, err := u.s.openSubdir(dir, scopeEntriesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return keys{}, nil, fmt.Errorf("%w: the scope has a scope key and no entries/ directory", ErrScopeAbsent)
	}
	if err != nil {
		return keys{}, nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err)
	}
	return uk, entries, nil
}

// openScopeDir opens .user/<uid>/ under root, each level with openSubdir,
// creating them with create set. A missing level without create is
// errNoScopeKey.
func (u *UserScope) openScopeDir(root *os.Root, create bool) (*os.Root, error) {
	users, err := u.s.openSubdir(root, userScopesName, create)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoScopeKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, userScopesName, err)
	}
	defer func() { _ = users.Close() }() // the scope directory is opened; .user is done with
	dir, err := u.s.openSubdir(users, strconv.FormatUint(uint64(u.uid), 10), create)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoScopeKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the scope directory: %w", ErrCorrupt, err)
	}
	return dir, nil
}

// readScopeKey reads, checks and opens dir's scope.key and returns K_u, which
// the caller clears. The file must be a regular file reached without a
// symlink, owned by the service user, at most 0600, and of a scope key's
// size; the record must be kind 0xFE, named "scope", at the key epoch. The
// uid's live GeneratedUID is read (lookupGeneratedUID, failing closed) and
// must equal the record's generation, which the record authenticates under
// W: a real, different answer is ErrScopeOwnerChanged.
func (u *UserScope) readScopeKey(dir *os.Root, wrap func() ([]byte, error)) ([]byte, error) {
	b, fi, err := readFile(dir, scopeKeyName, int64(maxScopeKeyRecordSize))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, errNoScopeKey
	case errors.Is(err, errBadFile):
		return nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeKeyName, err)
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", scopeKeyName, err)
	}
	if err := u.s.checkOwned(fi, fileMode); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeKeyName, err)
	}
	r, err := parseScopeKey(b)
	if err != nil {
		return nil, err
	}
	live, err := lookupGeneratedUID(u.uid)
	if err != nil {
		return nil, err
	}
	w, err := wrap()
	if err != nil {
		return nil, err
	}
	ku, err := r.open(w, u.scope)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", scopeKeyName, err)
	}
	if len(ku) != scopeKeySize {
		clear(ku)
		return nil, fmt.Errorf("%w: %s holds %d bytes, want %d", ErrCorrupt, scopeKeyName, len(ku), scopeKeySize)
	}
	if r.generation != live {
		clear(ku)
		return nil, fmt.Errorf("%w: uid %d", ErrScopeOwnerChanged, u.uid)
	}
	return ku, nil
}

// parseScopeKey decodes a scope.key file: a record of kind 0xFE, named
// "scope", at the key epoch, with a ciphertext exactly a sealed 32-byte key.
// Anything else is ErrCorrupt.
func parseScopeKey(b []byte) (record, error) {
	r, err := parseRecordOf(b, func(kind byte) bool { return kind == kindScopeKey })
	if err != nil {
		return record{}, fmt.Errorf("%s: %w", scopeKeyName, err)
	}
	if r.name != scopeKeyRecordName || r.version != scopeKeyEpoch || len(r.ciphertext) != scopeKeySize+tagSize {
		return record{}, fmt.Errorf("%w: %s does not hold this scope's key record", ErrCorrupt, scopeKeyName)
	}
	return r, nil
}

// mint makes the scope: the uid's GeneratedUID is read first, so a lookup
// that fails creates nothing; then .user/<uid>/ and entries/ are made, and
// scope.key is written last, so a scope whose scope.key opens has its
// entries/ directory. A fresh K_u is never minted over entries: an entries/
// directory that holds anything, without a scope.key, is a scope whose key
// was lost, and ErrScopeAbsent, as the master is never minted over entries.
// The caller holds the exclusive lock.
func (u *UserScope) mint(root *os.Root, wrap []byte) (keys, *os.Root, error) {
	g, err := lookupGeneratedUID(u.uid)
	if err != nil {
		return keys{}, nil, err
	}
	dir, err := u.openScopeDir(root, true)
	if err != nil {
		return keys{}, nil, err
	}
	defer func() { _ = dir.Close() }() // writes are fsynced by writeFile
	if _, err := dir.Lstat(scopeKeyName); !errors.Is(err, fs.ErrNotExist) {
		return keys{}, nil, fmt.Errorf("%w: %s appeared while the scope was minted: %v", ErrCorrupt, scopeKeyName, err)
	}
	entries, err := u.s.openSubdir(dir, scopeEntriesName, true)
	if err != nil {
		return keys{}, nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = entries.Close() // abandoned
		}
	}()
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return keys{}, nil, err
	}
	if len(names) > 0 {
		return keys{}, nil, fmt.Errorf("%w: entries/ holds %d names and there is no scope key, so a new key would orphan them; restore scope.key", ErrScopeAbsent, len(names))
	}
	ku := make([]byte, scopeKeySize)
	defer clear(ku) // only the derived keys outlive the mint
	if err := u.s.readRandom(ku); err != nil {
		return keys{}, nil, fmt.Errorf("mint the scope key: %w", err)
	}
	rec := record{kind: kindScopeKey, name: scopeKeyRecordName, version: scopeKeyEpoch, generation: g, created: u.s.now().Unix()}
	if err := rec.seal(wrap, u.scope, ku, u.s.rand); err != nil {
		return keys{}, nil, err
	}
	if err := u.s.writeFile(dir, scopeKeyName, rec.marshal()); err != nil {
		return keys{}, nil, err
	}
	uk, err := deriveKeys(ku, u.scope)
	if err != nil {
		return keys{}, nil, err
	}
	ok = true
	return uk, entries, nil
}
