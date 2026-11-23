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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"syscall"
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
// longer exists. A name that is not a decimal uid is no scope; a decimal uid
// that can never own one (eligibleUID) is a stray, ErrCorrupt.
func (s *FileStore) eachScopeDir(ctx context.Context, root *os.Root, fn func(uid string, dir *os.Root) error) error {
	users, err := s.openSubdir(root, userScopesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: keystore/%s is not a user-scope directory the store trusts, so its scope keys cannot be re-wrapped; root must restore or remove it: %w", ErrCorrupt, userScopesName, err)
	}
	defer func() { _ = users.Close() }() // each write is fsynced in its own directory
	names, err := readDirNames(users, scopeDirNamesBound)
	if err != nil {
		return fmt.Errorf("%w: keystore/%s cannot be listed within the bound (%w); root must remove the names in it that are not user scopes, then run rewrap again", ErrCorrupt, userScopesName, err)
	}
	sort.Strings(names)
	for i, n := range names {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		if !decimalUID(n) {
			continue
		}
		// A uid that can never own a scope never had one minted: such a
		// directory is a stray, never a scope to skip or re-wrap.
		if id, _ := strconv.ParseUint(n, 10, 32); s.eligibleUID(uint32(id)) != nil {
			return fmt.Errorf("%w: keystore/%s/%s is a stray directory: uid %s can never own a user scope (%v); root must remove it by hand, then run rewrap again", ErrCorrupt, userScopesName, n, n, errIneligibleUID)
		}
		// A scope listed and then missing is damage, never a scope to skip:
		// skipping it could strand its scope.key under the old master.
		dir, err := s.openSubdir(users, n, false)
		if err != nil {
			return fmt.Errorf("%w: keystore/%s/%s: %w", ErrCorrupt, userScopesName, n, err)
		}
		if err := checkScopeKeyNew(dir, n); err != nil {
			_ = dir.Close() // read-only so far
			return err
		}
		err = fn(n, dir)
		_ = dir.Close() // each write is fsynced by writeFile or syncDir
		if err != nil {
			return err
		}
	}
	return nil
}

// scopeDirNamesBound bounds a listing of .user. It is maxDirNames; a test
// lowers it.
var scopeDirNamesBound = maxDirNames

// checkScopeKeyNew refuses a scope.key.new that is there and not a regular
// file: Rewrap only ever writes one as a file, and a directory or other
// name there would make every retry fail on it.
func checkScopeKeyNew(dir *os.Root, uid string) error {
	fi, err := dir.Lstat(scopeKeyName + newSuffix)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: keystore/%s/%s/%s%s is a %s, not a file Rewrap wrote; root must remove it, then run rewrap again", ErrCorrupt, userScopesName, uid, scopeKeyName, newSuffix, fi.Mode().Type())
	}
	return nil
}

// checkScopesPlanned re-walks .user after the commit and refuses, as
// ErrCorrupt, unless the scopes with a scope.key are exactly those plan
// re-sealed, each re-opening under next's W and holding the K_u,
// generation and created time pinned at the plan: a scope that appeared or
// went missing during the run, a scope.key swapped back to an old copy or
// damaged after its commit, or one swapped for a record under next's W with
// another K_u, would be left under a master about to be retired.
func (s *FileStore) checkScopesPlanned(ctx context.Context, root *os.Root, plan []planned, next keys) error {
	want := map[string]bool{}
	pins := map[string]scopePin{}
	for _, p := range plan {
		if p.scope != "" {
			want[p.scope] = true
			pins[p.scope] = p.pin
		}
	}
	got := map[string]bool{}
	err := s.eachScopeDir(ctx, root, func(uid string, dir *os.Root) error {
		if _, err := dir.Lstat(scopeKeyName); errors.Is(err, fs.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		got[uid] = true
		if !want[uid] {
			return nil // refused below, as a scope this rewrap did not plan
		}
		r, err := s.readScopeKeyRecord(dir)
		var pt []byte
		if err == nil {
			pt, err = r.open(next.wrap, userScopePrefix+uid)
			if err == nil {
				err = pins[uid].check(r, pt)
			}
			clear(pt)
		}
		if err != nil {
			return fmt.Errorf("%w: the scope key of user/%s does not open under the new master after its commit, so the old master is kept. Run rewrap again, which re-seals a scope key still under the old master; one that opens under neither is damage: restore keystore/%s/%s/%s from a backup, or %s, then run rewrap again: %w", ErrCorrupt, uid, userScopesName, uid, scopeKeyName, damagedScopeRecovery(uid), err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for uid := range want {
		if !got[uid] {
			return fmt.Errorf("%w: the scope key of user/%s was re-sealed and is gone; restore keystore/%s/%s from a backup, then run rewrap again", ErrCorrupt, uid, userScopesName, uid)
		}
	}
	for uid := range got {
		if !want[uid] {
			return fmt.Errorf("%w: user/%s has a scope key this rewrap did not plan; root must remove keystore/%s/%s, then run rewrap again", ErrCorrupt, uid, userScopesName, uid)
		}
	}
	return nil
}

// damagedScopeRecovery names root's recovery, short of a backup, for the
// damaged scope of uid. Removing the scope directory by hand recovers only a
// user who never delivered: for one who did, the floor records the
// deliveries record past its first sequence, and the owner's next put
// refuses to mint over it. rm-scope refuses a scope whose record names a
// delivery until it revokes first, so the recovery there is removing the
// directory by hand, then floor --rebuild, whose cost is said.
func damagedScopeRecovery(uid string) string {
	return fmt.Sprintf("remove keystore/%s/%s/ by hand, which recovers only a user who never delivered (the owner loses their values and re-puts them); sudo k3sm keys rm-scope user/%s --yes does the same for such a user. For a user who did, the owner's next put refuses to mint over the floor, and rm-scope refuses a scope with deliveries: root removes keystore/%s/%s/ by hand, then runs sudo k3sm keys floor --rebuild, which drops the removed scope's floor keys and rewrites the floor from what is on disk, and so lowers every record's floor, every user's, to the sequence on disk now, and then sudo k3sm doctor", userScopesName, uid, uid, userScopesName, uid)
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
		var pin scopePin
		if err == nil {
			var underNext bool
			underNext, pin, err = openScopeKeyEither(r, userScopePrefix+uid, old, next)
			committed = committed || underNext
		}
		if err != nil {
			return fmt.Errorf("the scope key of user/%s does not open, and a rewrap would leave it sealed under a master that no longer exists. Root must restore keystore/%s/%s/ from a backup, or %s, then run rewrap again: %w", uid, userScopesName, uid, damagedScopeRecovery(uid), err)
		}
		out = append(out, planned{scope: uid, pin: pin})
		return nil
	})
	return out, committed, err
}

// scopePin is what a scope.key held when Rewrap planned it: a fingerprint
// of its K_u (never K_u itself), its generation and its created time.
type scopePin struct {
	ku         [sha256.Size]byte
	generation [generationSize]byte
	created    int64
}

// pinScopeKey pins r, whose K_u is ku.
func pinScopeKey(r record, ku []byte) scopePin {
	return scopePin{ku: sha256.Sum256(ku), generation: r.generation, created: r.created}
}

// check refuses, as ErrCorrupt, a scope.key r holding ku that is not
// the one p pinned at the plan: a record swapped in since, even one that
// opens under the new W, would carry another K_u past the swap.
func (p scopePin) check(r record, ku []byte) error {
	if pinScopeKey(r, ku) != p {
		return fmt.Errorf("%w: %s holds another key, generation or created time than when this rewrap planned it", ErrCorrupt, scopeKeyName)
	}
	return nil
}

// openScopeKeyEither opens r under old's W and, failing that and with next
// set, under next's, reporting whether it opened only under next's, and
// pins what it holds.
func openScopeKeyEither(r record, scope string, old keys, next *keys) (bool, scopePin, error) {
	pt, err := r.open(old.wrap, scope)
	defer func() { clear(pt) }()
	if err == nil {
		return false, pinScopeKey(r, pt), nil
	}
	if next == nil || !errors.Is(err, ErrCorrupt) {
		return false, scopePin{}, err
	}
	pt, err = r.open(next.wrap, scope)
	if err != nil {
		return false, scopePin{}, err
	}
	return true, pinScopeKey(r, pt), nil
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
// scope.key.new beside it removed. Either way the scope.key must still hold
// the K_u, generation and created time p pinned at the plan (ErrCorrupt).
func (s *FileStore) commitScopeKey(root *os.Root, p planned, old, next keys) error {
	uid := p.scope
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
			if err == nil {
				err = p.pin.check(r, npt)
			}
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
		if err := p.pin.check(r, pt); err != nil {
			return err
		}
		b, fi, err := readFile(dir, scopeKeyName+newSuffix, int64(maxScopeKeyRecordSize))
		if err != nil {
			return fmt.Errorf("%w: %s%s: %w", ErrCorrupt, scopeKeyName, newSuffix, err)
		}
		if err := s.checkOwned(fi, fileMode); err != nil {
			return fmt.Errorf("%w: %s%s: %w", ErrCorrupt, scopeKeyName, newSuffix, err)
		}
		// Renamed in, a second link would keep a copy the store does not
		// know of, which readScopeKeyRecord then refuses.
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
			return fmt.Errorf("%w: %s%s has more than one link; root must remove it, then run rewrap again", ErrCorrupt, scopeKeyName, newSuffix)
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
