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
	"log/slog"
	"math"
	"slices"
	"time"

	"k3sm.io/k3sm/pkg/keystore/typed"
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
	// entry's. It carries the orphan's identity, which covers its record
	// digest: pass it to Adopt, which refuses a file replaced since. A version file has no pointer sequence of its own: its
	// version number is its place in the entry's history, and Adopt gives
	// it the pointer sequence Seq+1, the one its own rotation would have.
	Orphan Version
	// Others are the further authenticated versions above Orphan, in
	// increasing order. A crashed rotation leaves only Current+1, so any
	// here means an older pointer was copied back, and Adopt refuses.
	Others []uint64
	// CurrentIssuedAt and OrphanIssuedAt are the issue times sealed in
	// each side's envelope: a token's issuedAt, an oauth pair's
	// accessIssuedAt. Unlike Created they are authenticated. They are the
	// zero time for a kind that seals none (ssh, ed25519, opaque) and for an
	// envelope that does not decode.
	CurrentIssuedAt time.Time
	OrphanIssuedAt  time.Time
}

// sealedIssuedAt is the issue time sealed in val, a version of kind: a
// token's issuedAt, an oauth pair's accessIssuedAt, the zero time for any
// other kind or an envelope that does not decode. It decodes through the
// typed read path and clears every secret the decode copied out, so only
// the time leaves.
func sealedIssuedAt(kind Kind, val []byte) time.Time {
	ck, ok := credentialKind(kind)
	if !ok {
		return time.Time{}
	}
	env, err := typed.Decode(ck, val)
	if err != nil {
		return time.Time{}
	}
	clear(env.RefreshToken)
	clear(env.Credential.Value)
	clear(env.Credential.Seed)
	clear(env.Credential.AccessToken)
	switch kind {
	case KindToken:
		return env.Credential.IssuedAt
	case KindOAuth:
		return env.Credential.AccessIssuedAt
	}
	return time.Time{}
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

// readAbove is every read's check for what lies above cur, the version e's
// pointer names (docs/design/keystore.md § "Adopting an orphaned
// version"). Its cost is bounded: it lists the directory once and opens
// only the version after cur. A version file numbered further out is
// refused by its name alone, as ErrCorrupt: a crashed rotation never
// leaves one. The file at cur+1 that authenticates as this entry's is
// ErrOrphanVersion. One whose kind this build does not know is refused by
// name too, never read as a newer k3sm's record: nothing newer writes above
// the pointer. One that does not authenticate is a true orphan, which the
// next Rotate discards, and does not stop the read.
func readAbove(ctx context.Context, e *entry, k keys, cur uint64) error {
	names, err := readDirNames(e.root, maxDirNames)
	if err != nil {
		return err
	}
	next := false
	for i, n := range names {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		v, ok := parseVersionName(n)
		if !ok || v <= cur {
			continue
		}
		if v-cur > 1 {
			return fmt.Errorf("%w: %s lies above the current version %d, and a crashed rotation leaves only version %d: "+
				"an older current pointer was copied back, or the file was put there; restore the newer pointer from backup, or remove %s",
				ErrCorrupt, n, cur, cur+1, n)
		}
		next = true
	}
	if !next {
		return nil
	}
	file := versionName(cur + 1)
	_, pt, err := e.openRecord(k, file, false, cur+1)
	clear(pt) // only whether it opens is wanted
	switch {
	case err == nil:
		return fmt.Errorf("%w: version %d is above the current version %d: inspect it with `k3sm keys adopt %s`",
			ErrOrphanVersion, cur+1, cur, qualified(e.name))
	case errors.Is(err, ErrKindUnsupported):
		return fmt.Errorf("%w: %s, above the current version %d, is not a version of this entry: remove %s", ErrCorrupt, file, cur, file)
	case errors.Is(err, ErrCorrupt):
		return nil
	}
	return fmt.Errorf("check %s above the current version: %w", file, err)
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

// logger is the store's logger: its log seam, or slog.Default().
func (s *FileStore) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}
	return slog.Default()
}

// qualified is the CLI's form of a system entry name.
func qualified(name string) string { return "system/" + name }

// Orphan reports the lowest version of name above its current one that
// authenticates as this entry's, next to the current one: their versions,
// kinds, created times and sealed issue times, and the pointer's sequence. It never opens a
// value for the caller. An entry with no such version is ErrVersionNotFound.
func (s *FileStore) Orphan(ctx context.Context, name string) (OrphanInfo, error) {
	var info OrphanInfo
	err := s.read(ctx, name, func(e *entry, k keys, fl floor) error {
		cur, seq, _, err := e.checkedRange(k, fl)
		if err != nil {
			return err
		}
		curV, val, err := e.version(k, cur)
		if err != nil {
			clear(val)
			return err
		}
		curAt := sealedIssuedAt(curV.Kind, val)
		clear(val)
		above, err := sealedAbove(ctx, e, k, cur)
		if err != nil {
			return err
		}
		if len(above) == 0 {
			return fmt.Errorf("%w: no sealed version lies above the current version %d", ErrVersionNotFound, cur)
		}
		orphan, val, err := e.version(k, above[0])
		if err != nil {
			clear(val)
			return err
		}
		orphanAt := sealedIssuedAt(orphan.Kind, val)
		clear(val)
		info = OrphanInfo{Current: curV, Seq: seq, Orphan: orphan, Others: above[1:], CurrentIssuedAt: curAt, OrphanIssuedAt: orphanAt}
		return nil
	})
	if err != nil {
		return OrphanInfo{}, err
	}
	return info, nil
}

// Adopt makes orphan, the Version Orphan reported for name (an orphan a
// crashed rotation left), current:
// it seals a pointer naming it at the next sequence, raises the floor, and
// for oauth keeps the retention rule (the current version and one previous)
// and unlinks the versions below it. It refuses unless version is exactly
// the one after the current version, it authenticates under this entry's
// generation, it is of the entry's kind, and no other sealed version lies
// above the current one. It refuses with ErrVersionStale when the file at
// that version is no longer the record Orphan reported: its identity covers
// the record digest, so an orphan replaced after it was inspected is never
// adopted in its place. It is attended and root-only, as Rotate is: the
// floor is root's. A failure after the pointer flip returns the adopted
// version with an error matching ErrCommitted; one whose floor write drops a
// tombstone returns it with a committed ErrTombstoneEvicted (Committed).
//
// Adopting is right for both causes an orphan has: after a crashed rotation
// it completes the flip the crash interrupted, and behind a copied-back
// pointer it rewrites the newer pointer that was replaced.
//
// A successful Adopt logs one Info line with the entry name, the old and
// adopted versions and the adopted record's digest, never a value.
func (s *FileStore) Adopt(ctx context.Context, name string, orphan Version) (Version, error) {
	version := orphan.Version
	v, err := s.adopt(ctx, name, orphan)
	if err != nil {
		// v is the committed version when err is Committed, and zero
		// otherwise.
		return v, fmt.Errorf("adopt %s version %d: %w", name, version, err)
	}
	return v, nil
}

func (s *FileStore) adopt(ctx context.Context, name string, want Version) (Version, error) {
	version := want.Version
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
	if err := fdir.mergePending(); err != nil {
		return Version{}, err
	}
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
	// The orphan must be the exact record Orphan reported, not another
	// sealed record of the same version put there since (a failed
	// attempt's file copied over its retry): its identity covers the
	// record's digest.
	if want.identity == ([identitySize]byte{}) || orphan.identity != want.identity {
		return Version{}, fmt.Errorf("%w: the file at version %d is not the orphan that was inspected (record digest %s now); inspect it again with `k3sm keys adopt %s`",
			ErrVersionStale, version, orphan.RecordDigest(), qualified(name))
	}
	if orphan.Kind != old.Kind {
		return Version{}, fmt.Errorf("%w: version %d is %s, but %s is %s", ErrKindMismatch, version, orphan.Kind, name, old.Kind)
	}
	// The next sequence is above the floor's high-water mark, when a floor
	// merge set one, as Rotate's is.
	base := max(seq, fl[name].HighWater)
	if cur >= versionLimit(old.Kind) || base == math.MaxUint64 {
		return Version{}, fmt.Errorf("%w: the pointer is at the last version or sequence", ErrCorrupt)
	}
	nextSeq := base + 1
	if err := fl.room(name, floorEntry{Generation: hex.EncodeToString(e.generation[:]), Seq: nextSeq}); err != nil {
		return Version{}, err
	}
	newLow := low
	if old.Kind == KindOAuth {
		newLow = cur
	}
	ptr := record{kind: kindPointer, name: name, generation: e.generation, created: s.now().Unix()}
	if err := ptr.seal(k.seal, k.scope, rangePlaintext(version, nextSeq, newLow), s.rand); err != nil {
		return Version{}, err
	}
	flipped, err := s.commitPointer(e, ptr.marshal())
	if !flipped {
		return Version{}, err
	}
	if err != nil {
		return orphan, committedf(err, "version %d is current, but syncing its directory failed", version)
	}
	if _, err := fdir.update(func(fl floor) bool { return fl.raise(name, e.generation, nextSeq) }); err != nil {
		return orphan, committedf(err, "version %d is current, but recording its floor failed (the next keys verb records it)", version)
	}
	// A tombstone the floor write dropped is reported with the version
	// (evicted), committed, as Rotate reports it.
	ev := evicted(fdir, nil, nil)
	if newLow > low {
		if err := s.step("prune " + name); err != nil {
			return orphan, committedf(err, "version %d is current, but pruning the versions below %d failed (the next write prunes them)%s", version, newLow, alsoEvicted(ev))
		}
		if err := discardOrphans(ctx, e, k, newLow, version); err != nil {
			return orphan, committedf(err, "version %d is current, but pruning the versions below %d failed (the next write prunes them)%s", version, newLow, alsoEvicted(ev))
		}
	}
	// Metadata only: the name, the version numbers and the record digest,
	// which reveals nothing about the value.
	s.logger().Info("keystore: adopted an orphaned version",
		"entry", name, "oldVersion", old.Version, "version", orphan.Version, "recordDigest", orphan.RecordDigest())
	return orphan, ev
}
