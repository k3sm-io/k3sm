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
	"math"
	"os"

	keyentry "k3sm.io/apis/keystore/entry"
)

// This file is the user scope's rotate: docs/design/keystore.md § "Rotation
// and rollback", "Quotas", "The user-scope floor" (write order) and "Per-uid
// fairness" (the revocation class). A rotate writes the next version and
// flips the pointer to it at the next sequence, then appends the floor
// line, then the audit line: the record, the pointer, the floor line, as a
// put; and, as a revocation, commit first, then audit. Every version is
// kept (a user entry is raw, opaque or ed25519, never oauth), so nothing
// is pruned, and nothing points the pointer back at an existing version: a
// rotate from a version writes that version's value forward as a new one.

// Rotate seals value as the next version of input, of the kind the entry
// already has. It is refused with ErrQuota past the scope's quota, and,
// like a put, in a scope the start step quarantined. A rotate that finds
// no entry changes nothing: it is charged like any line and refused past
// the caller's share. One that goes ahead is in the revocation class: past
// the share or the hard cap its lines draw on the uid's socket margin.
//
// A failure before the pointer flip leaves the old version current and
// removes the version it wrote; a crash there leaves that version above the
// pointer, which the next rotate refuses (ErrOrphanVersion), as the system
// scope's does. A failure after the flip returns the new version with an
// error matching ErrCommitted, and so does an audit line that fails after
// it: the rotation stands, and is counted unaudited (UnauditedOps).
func (u *UserScope) Rotate(ctx context.Context, input string, value []byte) (Version, error) {
	return u.rotateOp(ctx, input, func(e *entry, uk keys, old Version) ([]byte, error) {
		if err := checkValue(old.Kind, value); err != nil {
			return nil, err
		}
		return value, nil
	})
}

// RotateFrom writes the value of version from of input forward as its next
// version: the socket's rotate with from_version. Version 0, or one above
// the current version, is ErrVersionNotFound; a source version of another
// kind is ErrKindMismatch. Otherwise it is Rotate.
func (u *UserScope) RotateFrom(ctx context.Context, input string, from uint64) (Version, error) {
	var val []byte
	defer func() { clear(val) }() // sealed by then, or refused
	return u.rotateOp(ctx, input, func(e *entry, uk keys, old Version) ([]byte, error) {
		if from == 0 || from > old.Version {
			return nil, ErrVersionNotFound
		}
		src, v, err := e.version(uk, from)
		val = v
		if err != nil {
			return nil, err
		}
		if src.Kind != old.Kind {
			return nil, fmt.Errorf("%w: version %d is %s, but the entry is %s", ErrKindMismatch, from, src.Kind, old.Kind)
		}
		return val, nil
	})
}

// rotateOp is Rotate and RotateFrom over next, which returns the value the
// rotation seals; it audits a refusal before the lock briefly.
func (u *UserScope) rotateOp(ctx context.Context, input string, next nextValue) (Version, error) {
	name, err := u.own("rotate", input)
	if err != nil {
		u.auditBriefly(ctx, auditLine{op: "rotate", name: auditPlaceholder}, err)
		return Version{}, fail("rotate", err)
	}
	if err := u.quarantineErr(); err != nil {
		u.auditBriefly(ctx, auditLine{op: "rotate", name: name}, err)
		return Version{}, fail("rotate", err)
	}
	v, err := u.rotate(ctx, name, next)
	if err != nil {
		if Committed(err) {
			return v, fail("rotate", err)
		}
		return Version{}, fail("rotate", err)
	}
	return v, nil
}

// rotate does the work under the exclusive lock, then appends its audit
// line before releasing it: the new version and its fingerprint when the
// rotation committed, the refusal's result otherwise.
func (u *UserScope) rotate(ctx context.Context, name string, next nextValue) (v Version, err error) {
	if err := u.s.checkConfig(); err != nil {
		return Version{}, err
	}
	root, done, err := u.s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return Version{}, fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return Version{}, err
	}
	defer done()
	defer func() { // before done: the line is appended under the lock
		committed := err == nil || Committed(err)
		l := auditLine{op: "rotate", name: name, revoke: committed}
		if committed {
			l.version, l.fingerprint = v.Version, v.Fingerprint
		}
		err = u.keepAuditFailure("rotate", err, u.appendAudit(l, err))
	}()
	return u.rotateBody(ctx, root, name, next)
}

// rotateBody is rotate's work under the lock.
func (u *UserScope) rotateBody(ctx context.Context, root *os.Root, name string, next nextValue) (Version, error) {
	k, err := u.masterForWrite()
	if err != nil {
		return Version{}, err
	}
	uk, entries, err := u.openScope(root, func() (keys, error) { return k, nil })
	if errors.Is(err, errNoScopeKey) {
		// No scope, so no entry: a rotate that changes nothing.
		if aerr := u.s.admit(u.uid, false); aerr != nil {
			return Version{}, aerr
		}
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = entries.Close() }() // writes are fsynced
	if names := u.s.lostLines.names(u.scope); len(names) > 0 {
		u.catchUpLostIn(entries, uk, names)
	}
	e, err := openUserEntry(entries, name)
	if errors.Is(err, ErrNotFound) {
		// Only a rotate that revokes is in the class (docs/design/keystore.md
		// § "Per-uid fairness"): this one is charged like any line.
		if aerr := u.s.admit(u.uid, false); aerr != nil {
			return Version{}, aerr
		}
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, err
	}
	defer e.close()
	// The floor judges the pointer first: a copied-back, buried or tainted
	// entry is refused before anything is written, and its floor line is
	// then one the floor takes.
	if _, err := u.flooredPointer(e, uk); err != nil {
		return Version{}, err
	}
	cur, seq, err := e.pointer(uk)
	if err != nil {
		return Version{}, err
	}
	// The current version is opened, not only named: the new version takes
	// its kind, and a rotation over a version that does not open would hide
	// the damage behind a new one.
	old, oldVal, err := e.version(uk, cur)
	clear(oldVal)
	if err != nil {
		return Version{}, err
	}
	value, err := next(e, uk, old)
	if err != nil {
		return Version{}, err
	}
	if cur >= versionLimit(old.Kind) || seq == math.MaxUint64 {
		return Version{}, fmt.Errorf("%w: the pointer is at the last version or sequence", ErrCorrupt)
	}
	base, err := u.deliveriesBytes(root)
	if err != nil {
		return Version{}, err
	}
	if err := checkScopeQuota(entries, name, value, base); err != nil {
		return Version{}, err
	}
	if err := discardOrphans(ctx, e, uk, 1, cur); err != nil {
		if errors.Is(err, ErrOrphanVersion) {
			// The scope's owner cannot adopt it (root's verb) or reach
			// the file: its remedy is rm, then put. The orphan is kept,
			// never discarded here, as discardOrphans keeps it.
			return Version{}, fmt.Errorf("%w: %w: %s holds a sealed version above its current one, left by a crashed rotation or a copied-back pointer; nothing was removed: rm the entry, then put its value again", ErrCorrupt, ErrOrphanVersion, keyentry.Entry{Scope: keyentry.ScopeUser, UID: u.uid, Name: name})
		}
		return Version{}, err
	}
	// A rotation revokes the value it replaces: past the share or the hard
	// cap its lines draw on the uid's socket margin, and only that margin
	// running out refuses it.
	if err := u.s.admit(u.uid, true); err != nil {
		return Version{}, err
	}
	return u.commitRotation(e, uk, old, cur, seq, value)
}

// commitRotation writes version cur+1 sealing value, flips the pointer to
// it at seq+1, then appends the floor line.
func (u *UserScope) commitRotation(e *entry, uk keys, old Version, cur, seq uint64, value []byte) (Version, error) {
	nv, nseq := cur+1, seq+1
	created := u.s.now().Unix()
	rec := record{kind: byte(old.Kind), name: e.name, version: nv, generation: e.generation, created: created}
	if err := rec.seal(uk.seal, uk.scope, value, u.s.rand); err != nil {
		return Version{}, err
	}
	// Renamed into place, then the directory synced, so every failure
	// after the rename and before the flip removes it below.
	if err := u.s.renameInto(e.root, versionName(nv), rec.marshal(), u.s.uid, u.s.gid, fileMode); err != nil {
		return Version{}, err
	}
	err := u.s.step("sync " + versionName(nv))
	if err == nil {
		err = syncDir(e.root)
	}
	ptr := record{kind: kindPointer, name: e.name, generation: e.generation, created: created}
	if err == nil {
		err = ptr.seal(uk.seal, uk.scope, pointerPlaintext(nv, nseq), u.s.rand)
	}
	flipped := false
	if err == nil {
		flipped, err = u.s.commitPointer(e, ptr.marshal())
	}
	if !flipped {
		// Nothing committed: the version just written is removed, best
		// effort; one left behind is refused by the next rotate, never
		// promoted.
		if e.root.Remove(versionName(nv)) == nil {
			_ = syncDir(e.root) // best effort, as above
		}
		return Version{}, err
	}
	committed := versionOf(rec, value, uk.fingerprint)
	if err != nil {
		// The floor lags the pointer by one, which a read accepts; the next
		// operation on the scope catches the line up.
		u.s.lostLines.note(u.scope, e.name)
		return committed, committedf(err, "version %d is current, but syncing its directory failed", nv)
	}
	if err := u.s.step("floor " + e.name); err != nil {
		u.s.lostLines.note(u.scope, e.name)
		return committed, committedf(err, "version %d is current, but its floor line was not written", nv)
	}
	if err := u.s.userFloor.append(u.scope, e.name, e.generation, nseq, true); err != nil {
		u.s.lostLines.note(u.scope, e.name)
		return committed, committedf(err, "version %d is current, but its floor line was not written", nv)
	}
	return committed, nil
}
