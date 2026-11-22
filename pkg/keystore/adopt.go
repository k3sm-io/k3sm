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
	"fmt"
	"io/fs"
	"math"
	"slices"
)

// This file is the recovery of an orphaned version: docs/design/keystore.md
// § "Rotation and rollback", "Adopting an orphaned version". A rotation that
// crashes between its version write and its pointer flip leaves a sealed
// version above the pointer, which for oauth holds the only copy of the
// provider's new refresh token. Nothing unlinks it; Orphan shows it and an
// attended Adopt makes it current.

// OrphanInfo is what Orphan reports about an entry's orphaned version, next
// to its current one. It carries metadata only, never a value.
type OrphanInfo struct {
	// Current is the version the current pointer names, and Seq the
	// pointer's sequence.
	Current Version
	Seq     uint64
	// Orphan is the lowest version above Current that authenticates as this
	// entry's. A version file has no pointer sequence of its own: its
	// version number is its place in the entry's history, and Adopt gives
	// it the pointer sequence Seq+1, the one its own rotation would have.
	Orphan Version
	// Others are the further authenticated versions above Orphan, in
	// increasing order. A crashed rotation leaves only Current+1, so any
	// here means an older pointer was copied back, and Adopt refuses.
	Others []uint64
}

// sealedAbove returns, in increasing order, the versions of e above cur
// whose files open, under k, as this entry's sealed record of the version
// their name says. A file that does not authenticate (a true orphan) is
// left out; any other read error is returned.
func sealedAbove(ctx context.Context, e *entry, k keys, cur uint64) ([]uint64, error) {
	names, err := readDirNames(e.root, maxDirNames)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for i, n := range names {
		if err := loopCtx(ctx, i); err != nil {
			return nil, err
		}
		v, ok := parseVersionName(n)
		if !ok || v <= cur {
			continue
		}
		_, pt, err := e.openRecord(k, n, false, v)
		clear(pt) // only whether it opens is wanted
		switch {
		case err == nil:
			out = append(out, v)
		case !errors.Is(err, ErrCorrupt):
			return nil, fmt.Errorf("check the orphaned %s: %w", n, err)
		}
	}
	slices.Sort(out)
	return out, nil
}

// orphanError is the refusal for v, a sealed version of e above cur, the
// version its pointer names. A crashed rotation leaves only cur+1, so a
// version further out can only be behind a copied-back pointer. For oauth
// the refusal says not to delete the file: it may hold the only valid
// refresh token.
func orphanError(e *entry, oauth bool, v, cur uint64) error {
	file := versionName(v)
	keep := ""
	if oauth {
		keep = "; do not delete the file: it may hold the only valid refresh token"
	}
	if v > cur+1 {
		return fmt.Errorf("%w: %w: version %d, above the version %d the current pointer names, is a sealed version of this entry; "+
			"a crashed rotation leaves only version %d, so an older current pointer was copied back over a newer one: "+
			"restore the newer current pointer from backup%s; nothing was removed", ErrCorrupt, ErrOrphanVersion, v, cur, cur+1, keep)
	}
	remedy := fmt.Sprintf("inspect with `k3sm keys adopt %s`", qualified(e.name))
	if oauth {
		remedy += keep
	} else {
		remedy += fmt.Sprintf(", which promotes it, or remove %s to discard it", file)
	}
	return fmt.Errorf("%w: %w: version %d, above the version %d the current pointer names, is a sealed version of this entry; "+
		"either a rotation crashed before its pointer flip, or an older current pointer was copied back over a newer one "+
		"(then restoring the newer pointer from backup, or adopting, makes it current again): %s; nothing was removed",
		ErrCorrupt, ErrOrphanVersion, v, cur, remedy)
}

// qualified is the CLI's form of a system entry name.
func qualified(name string) string { return "system/" + name }

// Orphan reports the lowest version of name above its current one that
// authenticates as this entry's, next to the current one: their versions,
// kinds and created times, and the pointer's sequence. It never opens a
// value for the caller. An entry with no such version is ErrVersionNotFound.
func (s *FileStore) Orphan(ctx context.Context, name string) (OrphanInfo, error) {
	var info OrphanInfo
	err := s.read(ctx, name, func(e *entry, k keys, fl floor) error {
		cur, seq, _, err := e.checkedRange(k, fl)
		if err != nil {
			return err
		}
		curV, val, err := e.version(k, cur)
		clear(val)
		if err != nil {
			return err
		}
		above, err := sealedAbove(ctx, e, k, cur)
		if err != nil {
			return err
		}
		if len(above) == 0 {
			return fmt.Errorf("%w: no sealed version lies above the current version %d", ErrVersionNotFound, cur)
		}
		orphan, val, err := e.version(k, above[0])
		clear(val)
		if err != nil {
			return err
		}
		info = OrphanInfo{Current: curV, Seq: seq, Orphan: orphan, Others: above[1:]}
		return nil
	})
	if err != nil {
		return OrphanInfo{}, err
	}
	return info, nil
}

// Adopt makes version of name, an orphan a crashed rotation left, current:
// it seals a pointer naming it at the next sequence, raises the floor, and
// for oauth keeps the retention rule (the current version and one previous)
// and unlinks the versions below it. It refuses unless version is exactly
// the one after the current version, it authenticates under this entry's
// generation, it is of the entry's kind, and no other sealed version lies
// above the current one. It is attended and root-only, as Rotate is: the
// floor is root's. A failure after the pointer flip returns the adopted
// version with an error matching ErrCommitted.
//
// Adopting is right for both causes an orphan has: after a crashed rotation
// it completes the flip the crash interrupted, and behind a copied-back
// pointer it rewrites the newer pointer that was replaced.
func (s *FileStore) Adopt(ctx context.Context, name string, version uint64) (Version, error) {
	v, err := s.adopt(ctx, name, version)
	if err != nil {
		// v is the committed version when err is ErrCommitted.
		return v, fmt.Errorf("adopt %s version %d: %w", name, version, err)
	}
	return v, nil
}

func (s *FileStore) adopt(ctx context.Context, name string, version uint64) (Version, error) {
	if err := s.checkConfig(); err != nil {
		return Version{}, err
	}
	if err := checkName(name); err != nil {
		return Version{}, err
	}
	if err := s.checkFloorWritable(); err != nil {
		return Version{}, err
	}
	root, done, err := s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, err
	}
	defer done()
	fdir, fl, err := s.lockFloor(ctx)
	if err != nil {
		return Version{}, err
	}
	defer fdir.unlock()
	e, err := openEntry(root, name, fl)
	if err != nil {
		return Version{}, err
	}
	defer e.close()
	k, err := s.loadMasterLocked()
	if err != nil {
		return Version{}, err
	}
	if fl, err = s.syncFloor(ctx, root, fdir, fl, k); err != nil {
		return Version{}, err
	}
	cur, seq, low, err := e.checkedRange(k, fl)
	if err != nil {
		return Version{}, err
	}
	if cur == math.MaxUint64 || version != cur+1 {
		return Version{}, fmt.Errorf("%w: only version %d, the one after the current version %d, can be adopted", ErrVersionNotFound, cur+1, cur)
	}
	old, val, err := e.version(k, cur)
	clear(val)
	if err != nil {
		return Version{}, err
	}
	above, err := sealedAbove(ctx, e, k, cur)
	if err != nil {
		return Version{}, err
	}
	if !slices.Contains(above, version) {
		return Version{}, fmt.Errorf("%w: version %d does not authenticate as a sealed version of this entry", ErrVersionNotFound, version)
	}
	if len(above) > 1 {
		return Version{}, fmt.Errorf("%w: versions %v lie above the current version %d, and a crashed rotation leaves only version %d: an older current pointer was copied back; restore the newer one from backup", ErrCorrupt, above, cur, version)
	}
	orphan, val, err := e.version(k, version)
	clear(val)
	if err != nil {
		return Version{}, err
	}
	if orphan.Kind != old.Kind {
		return Version{}, fmt.Errorf("%w: version %d is %s, but %s is %s", ErrKindMismatch, version, orphan.Kind, name, old.Kind)
	}
	if cur >= maxVersion || seq == math.MaxUint64 {
		return Version{}, fmt.Errorf("%w: the pointer is at the last version or sequence", ErrCorrupt)
	}
	if err := fl.room(name, floorEntry{Generation: hex.EncodeToString(e.generation[:]), Seq: seq + 1}); err != nil {
		return Version{}, err
	}
	newLow := low
	if old.Kind == KindOAuth {
		newLow = cur
	}
	ptr := record{kind: kindPointer, name: name, generation: e.generation, created: s.now().Unix()}
	if err := ptr.seal(k.seal, k.scope, rangePlaintext(version, seq+1, newLow), s.rand); err != nil {
		return Version{}, err
	}
	flipped, err := s.commitPointer(e, ptr.marshal())
	if !flipped {
		return Version{}, err
	}
	if err != nil {
		return orphan, committedf(err, "version %d is current, but syncing its directory failed", version)
	}
	if _, err := fdir.update(func(fl floor) bool { return fl.raise(name, e.generation, seq+1) }); err != nil {
		return orphan, committedf(err, "version %d is current, but recording its floor failed (the next keys verb records it)", version)
	}
	if newLow > low {
		if err := s.step("prune " + name); err != nil {
			return orphan, committedf(err, "version %d is current, but pruning the versions below %d failed (the next write prunes them)", version, newLow)
		}
		if err := discardOrphans(ctx, e, k, newLow, version); err != nil {
			return orphan, committedf(err, "version %d is current, but pruning the versions below %d failed (the next write prunes them)", version, newLow)
		}
	}
	return orphan, nil
}
