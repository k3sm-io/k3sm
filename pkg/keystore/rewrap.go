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
	"crypto/hmac"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

// This file is Rewrap: docs/design/keystore.md § "Rewrap". It re-seals every
// record under a new master in two phases, records first and the master last,
// so a crash at any step leaves every record readable (under the master, or
// under master.next by the reader's rule in keys.open) and a rerun completes
// it.

// newSuffix names the sibling a record is re-sealed into before it is renamed
// over the record: "<file>.new".
const newSuffix = ".new"

// Rewrap re-seals every record (every committed version and the current
// pointer of every entry) under newMaster, then swaps the master to it.
// newMaster must be 32 bytes: empty is ErrMasterMissing, any other length a
// plain error.
//
// It never adopts a key it was not given without saying so. A master.next an
// interrupted Rewrap (or anyone else) left, under which no record is live
// yet, is discarded with every .new, and newMaster goes live. Once some record
// is live under it, or its swap over the master is half done, discarding it
// would orphan that record, so Rewrap completes it instead and returns
// ErrRewrapResumed: the master is then that key, and Rewrap must run again to
// retire it.
//
// It refuses, writing nothing, while the name reserved for user scopes exists
// in the entries' directory (ErrScopeUnsupported), while the floor cannot be
// written, and while any entry does not open: an entry List reports with Err
// would otherwise be left sealed under a master that no longer exists, so it
// is removed (rm) or restored first. An interrupted Put is not an entry and is
// not re-sealed; the next Put of its name discards it. A version above the one
// the pointer names, which a Rotate interrupted before its flip leaves, is not
// committed and is not re-sealed either; the next Rotate discards it.
func (s *FileStore) Rewrap(ctx context.Context, newMaster []byte) error {
	if err := s.rewrap(ctx, newMaster); err != nil {
		return fmt.Errorf("rewrap: %w", err)
	}
	return nil
}

func (s *FileStore) rewrap(ctx context.Context, newMaster []byte) error {
	if err := s.checkConfig(); err != nil {
		return err
	}
	if len(newMaster) == 0 {
		return ErrMasterMissing
	}
	if len(newMaster) != masterSize {
		return fmt.Errorf("the new master is %d bytes, want %d", len(newMaster), masterSize)
	}
	if err := s.checkFloorWritable(); err != nil {
		return err
	}
	root, err := s.openDir(s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the keystore holds nothing to rewrap: %w", err)
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }() // every write below is fsynced
	// Checked before the lock too, whose first acquisition creates .lock, so
	// the refusal writes nothing at all; and again under it.
	if err := refuseUserScopes(root); err != nil {
		return err
	}
	unlock, err := s.lock(ctx, root, true)
	if err != nil {
		return err
	}
	defer unlock()
	if err := refuseUserScopes(root); err != nil {
		return err
	}
	fdir, fl, err := s.lockFloor(ctx)
	if err != nil {
		return err
	}
	defer fdir.unlock()
	mroot, err := s.openMasterDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrMasterMissing
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	defer func() { _ = mroot.Close() }() // every write below is fsynced
	// A crash between the two master renames left the swap half done: this
	// run completes it, and with it the interrupted Rewrap, and says so.
	done, err := s.finishSwap(mroot)
	if err != nil {
		return err
	}
	k, err := s.loadMaster()
	if err != nil {
		return err
	}
	if done {
		return resumed(k, newMaster)
	}
	// Like every root verb, it raises the floor first. Rewrap records nothing
	// new in it, so a floor too full to raise does not stop it.
	if synced, err := s.syncFloor(ctx, root, fdir, fl, k); err == nil {
		fl = synced
	} else if !errors.Is(err, errFloorFull) {
		return err
	}
	old := k
	old.next = nil
	next, plan, resuming, err := s.prepareNext(ctx, root, mroot, fl, old, newMaster)
	if err != nil {
		return err
	}
	if err := s.sealNew(ctx, root, fl, plan, old, next); err != nil {
		return err
	}
	if err := s.commitNew(ctx, root, fl, plan, old, next); err != nil {
		return err
	}
	if err := s.swapMaster(mroot, next); err != nil {
		return err
	}
	if resuming {
		return resumed(next, newMaster)
	}
	return nil
}

// resumed is ErrRewrapResumed, unless the key a resumed Rewrap completed, now
// the master, is newMaster after all.
func resumed(live keys, newMaster []byte) error {
	k, err := deriveKeys(newMaster, live.scope)
	if err != nil {
		return err
	}
	if hmac.Equal(k.seal, live.seal) {
		return nil
	}
	return ErrRewrapResumed
}

// refuseUserScopes is ErrScopeUnsupported when the name reserved for user
// scopes exists in the entries' directory, whatever its type: a symlink is not
// followed, and a dangling one counts.
func refuseUserScopes(root *os.Root) error {
	_, err := root.Lstat(userScopesName)
	if err == nil {
		return ErrScopeUnsupported
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("check for %s: %w", userScopesName, err)
	}
	return nil
}

// prepareNext is step 2. It returns the keys every record is to be sealed
// under, the plan of every entry (see rewrapPlan), and whether those keys are
// an interrupted Rewrap's that it resumes rather than newMaster's.
//
// A master.next that agrees with its fingerprint is resumed only when some
// record is already live under it: discarding it would orphan that record.
// Otherwise nothing is committed to it, whoever wrote it, so it is discarded
// with every .new (discardNext) and newMaster is written in its place.
//
// A master.next that does not agree (or a master.next.sha256 left without
// one) is discarded only when no .new file exists anywhere and every record
// still opens under the live master: step 3 had not started, so nothing was
// sealed under it. Otherwise it is ErrMasterUntrusted, since records may be
// sealed under it already, and minting a new key would orphan them. The
// second condition goes beyond the .new check alone: after step 4 renamed
// every .new in, none is left, but the records are under master.next.
//
// With nothing to resume, every record must open under the live master before
// master.next is written, so a Rewrap over an entry that does not open writes
// nothing.
func (s *FileStore) prepareNext(ctx context.Context, root, mroot *os.Root, fl floor, old keys, newMaster []byte) (keys, []planned, bool, error) {
	raw, err := s.readNext(mroot)
	if err == nil {
		k, derr := deriveKeys(raw, s.scope)
		clear(raw)
		if derr != nil {
			return keys{}, nil, false, derr
		}
		plan, committed, perr := rewrapPlan(ctx, root, fl, old, &k)
		if perr != nil {
			return keys{}, nil, false, perr
		}
		if committed {
			return k, plan, true, nil
		}
		if err := s.discardNext(ctx, root, mroot); err != nil {
			return keys{}, nil, false, err
		}
		err = fs.ErrNotExist
	}
	bad := !errors.Is(err, fs.ErrNotExist)
	if !bad {
		_, lerr := mroot.Lstat(masterNextFingerprintName)
		if lerr == nil {
			bad, err = true, fmt.Errorf("%s is present without %s", masterNextFingerprintName, masterNextName)
		} else if !errors.Is(lerr, fs.ErrNotExist) {
			return keys{}, nil, false, lerr
		}
	}
	found, ferr := anyNew(ctx, root)
	if ferr != nil {
		return keys{}, nil, false, ferr
	}
	if found {
		return keys{}, nil, false, fmt.Errorf("%w: %s is missing or does not match its fingerprint, and records were already re-sealed under it: restore the master directory and keystore/ from one matched backup (%w)", ErrMasterUntrusted, masterNextName, err)
	}
	plan, _, perr := rewrapPlan(ctx, root, fl, old, nil)
	if perr != nil {
		if bad {
			return keys{}, nil, false, fmt.Errorf("%w: %s does not match its fingerprint, and a record does not open under the live master, so it may be sealed under %s: restore the master directory and keystore/ from one matched backup (%w; %w)", ErrMasterUntrusted, masterNextName, masterNextName, err, perr)
		}
		return keys{}, nil, false, perr
	}
	next, err := deriveKeys(newMaster, s.scope)
	if err != nil {
		return keys{}, nil, false, err
	}
	if hmac.Equal(next.seal, old.seal) {
		return keys{}, nil, false, errors.New("the new master is the live one")
	}
	// The stale fingerprint goes first, so an interruption never leaves one
	// that vouches for a key that was not written; the rename of master.next
	// replaces a stale one.
	if err := mroot.Remove(masterNextFingerprintName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return keys{}, nil, false, fmt.Errorf("remove the stale %s: %w", masterNextFingerprintName, err)
	}
	if err := s.writeFile(mroot, masterNextName, newMaster); err != nil {
		return keys{}, nil, false, err
	}
	if err := s.writeFile(mroot, masterNextFingerprintName, []byte(masterFingerprint(newMaster))); err != nil {
		return keys{}, nil, false, err
	}
	return next, plan, false, nil
}

// discardNext removes a master.next under which nothing is committed: every
// .new first, then its fingerprint, then master.next itself, each directory
// fsynced. An interruption leaves either a master.next that agrees, with
// fewer .new files and still nothing committed, or one with no fingerprint
// and no .new, which the next run discards as one that does not agree.
func (s *FileStore) discardNext(ctx context.Context, root, mroot *os.Root) error {
	err := eachEntryDir(ctx, root, func(e *entry, files []string) error {
		removed := false
		for _, f := range files {
			if !strings.HasSuffix(f, newSuffix) {
				continue
			}
			if err := e.root.Remove(f); err != nil {
				return err
			}
			removed = true
		}
		if !removed {
			return nil
		}
		return syncDir(e.root)
	})
	if err != nil {
		return err
	}
	for _, n := range []string{masterNextFingerprintName, masterNextName} {
		if err := mroot.Remove(n); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("discard %s: %w", n, err)
		}
	}
	return syncDir(mroot)
}

// eachEntryDir calls fn with every entry directory in root and its names. A
// name that is not an entry name, gone, or not a directory is skipped.
func eachEntryDir(ctx context.Context, root *os.Root, fn func(e *entry, files []string) error) error {
	names, err := readDirNames(root, maxDirNames)
	if err != nil {
		return err
	}
	for i, name := range names {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		if checkName(name) != nil {
			continue
		}
		e, err := openEntryDirRaw(root, name)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCorrupt) {
			continue // gone, or not a directory: it holds nothing
		}
		if err != nil {
			return err
		}
		files, err := readDirNames(e.root, maxDirNames)
		if err == nil {
			err = fn(e, files)
		}
		e.close()
		if err != nil {
			return err
		}
	}
	return nil
}

// anyNew reports whether any entry directory holds a .new file: whether step 3
// of some Rewrap had started.
func anyNew(ctx context.Context, root *os.Root) (bool, error) {
	found := false
	err := eachEntryDir(ctx, root, func(_ *entry, files []string) error {
		for _, f := range files {
			if strings.HasSuffix(f, newSuffix) {
				found = true
			}
		}
		return nil
	})
	return found, err
}

// planned is one entry a Rewrap re-seals: its name and the version its
// pointer names, so its records are v1 to vcur and current.
type planned struct {
	name string
	cur  uint64
}

// rewrapPlan lists, sorted by name, every entry with the version its pointer
// names, and refuses unless every one of their records opens under old or,
// when next is set, under next. It also reports whether any record opens only
// under next: whether a commit under next had begun. A directory that is not
// an entry (an interrupted Put) is left out; one that List would report with
// Err refuses the Rewrap, which would otherwise leave it sealed under a master
// that no longer exists.
func rewrapPlan(ctx context.Context, root *os.Root, fl floor, old keys, next *keys) ([]planned, bool, error) {
	names, err := readDirNames(root, maxDirNames)
	if err != nil {
		return nil, false, err
	}
	sort.Strings(names)
	var (
		out       []planned
		committed bool
	)
	for i, name := range names {
		if err := loopCtx(ctx, i); err != nil {
			return nil, false, err
		}
		if checkName(name) != nil {
			continue
		}
		cur, underNext, err := planEntry(ctx, root, name, fl, old, next)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("entry %q does not open, and a rewrap would leave it sealed under a master that no longer exists: remove it with rm, or restore it, first: %w", name, err)
		}
		committed = committed || underNext
		out = append(out, planned{name, cur})
	}
	return out, committed, nil
}

// planEntry opens name's pointer, checked against the floor, and every
// version it covers, each under old
// or, failing that and with next set, under next, and reports whether any
// opened only under next.
func planEntry(ctx context.Context, root *os.Root, name string, fl floor, old keys, next *keys) (uint64, bool, error) {
	e, err := openEntry(root, name, fl)
	if err != nil {
		return 0, false, err
	}
	defer e.close()
	both := old
	both.next = next
	underNext := false
	// either runs open under old, then under both keys when that does not
	// authenticate, noting a record that opened only then.
	either := func(open func(keys) error) error {
		err := open(old)
		if err != nil && next != nil && errors.Is(err, ErrCorrupt) {
			if err = open(both); err == nil {
				underNext = true
			}
		}
		return err
	}
	var cur uint64
	// The pointer is the floor-checked one: a copied-back pointer readers
	// refuse is refused here too, never re-sealed as it is.
	if err := either(func(k keys) (err error) { cur, _, err = e.checkedPointer(k, fl); return err }); err != nil {
		return 0, false, err
	}
	for n := uint64(1); n <= cur; n++ {
		if err := loopCtx(ctx, int(n)); err != nil {
			return 0, false, err
		}
		if err := either(func(k keys) error { _, _, err := e.version(k, n); return err }); err != nil {
			return 0, false, fmt.Errorf("version %d: %w", n, err)
		}
	}
	return cur, underNext, nil
}

// eachRecord calls fn for every record of an entry whose pointer names cur:
// each version file, then the pointer.
func eachRecord(ctx context.Context, cur uint64, fn func(file string, pointer bool, version uint64) error) error {
	for n := uint64(1); n <= cur; n++ {
		if err := loopCtx(ctx, int(n)); err != nil {
			return err
		}
		if err := fn(versionName(n), false, n); err != nil {
			return err
		}
	}
	return fn(currentName, true, 0)
}

// sealNew is step 3: every record that still opens under old is re-sealed
// under next, with a fresh nonce and its plaintext, kind, name, version,
// generation and created time unchanged, into its fsynced .new sibling; the
// record itself is left alone. A record that opens only under next was
// already moved by an interrupted step 4 and is skipped.
func (s *FileStore) sealNew(ctx context.Context, root *os.Root, fl floor, plan []planned, old, next keys) error {
	for i, p := range plan {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		e, err := openEntry(root, p.name, fl)
		if err != nil {
			return err
		}
		err = eachRecord(ctx, p.cur, func(file string, pointer bool, version uint64) error {
			r, pt, err := e.openRecord(old, file, pointer, version)
			if err != nil {
				if !errors.Is(err, ErrCorrupt) {
					return err
				}
				_, _, err = e.openRecord(next, file, pointer, version)
				return err
			}
			defer clear(pt)
			moved := record{kind: r.kind, name: r.name, version: r.version, generation: r.generation, created: r.created}
			if err := moved.seal(next.seal, next.scope, pt, s.rand); err != nil {
				return err
			}
			return s.writeFile(e.root, file+newSuffix, moved.marshal())
		})
		e.close()
		if err != nil {
			return fmt.Errorf("entry %q: %w", p.name, err)
		}
	}
	return nil
}

// commitNew is step 4: once every record is under next or has its .new,
// each .new, which must open under next as the record it replaces, is renamed
// over its record, the pointer last in each entry, and the entry's directory
// fsynced. A .new beside a record already under next is removed. A record
// that opens under neither stops the Rewrap before the master is swapped.
func (s *FileStore) commitNew(ctx context.Context, root *os.Root, fl floor, plan []planned, old, next keys) error {
	for i, p := range plan {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		e, err := openEntry(root, p.name, fl)
		if err != nil {
			return err
		}
		err = eachRecord(ctx, p.cur, func(file string, pointer bool, version uint64) error {
			_, _, err := e.openRecord(old, file, pointer, version)
			if err == nil {
				if _, _, err := e.openRecord(next, file+newSuffix, pointer, version); err != nil {
					return err
				}
				if err := e.root.Rename(file+newSuffix, file); err != nil {
					return err
				}
				return s.step("rename " + p.name + "/" + file)
			}
			if !errors.Is(err, ErrCorrupt) {
				return err
			}
			if _, _, err := e.openRecord(next, file, pointer, version); err != nil {
				return err
			}
			if err := e.root.Remove(file + newSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return nil
		})
		if err == nil {
			err = syncDir(e.root)
		}
		e.close()
		if err != nil {
			return fmt.Errorf("entry %q: %w", p.name, err)
		}
	}
	return nil
}

// swapMaster is step 5: master.next is renamed over master, then
// master.next.sha256 over master.sha256, each rename fsynced. Content goes
// first: after a crash between the two, master holds the new key and matches
// master.next.sha256, which readMaster trusts and finishSwap completes.
// master.next is read again first, so the key the records were sealed under
// is the one that becomes the master.
func (s *FileStore) swapMaster(mroot *os.Root, next keys) error {
	raw, err := s.readNext(mroot)
	if err != nil {
		return err
	}
	k, err := deriveKeys(raw, s.scope)
	clear(raw)
	if err != nil {
		return err
	}
	if !hmac.Equal(k.seal, next.seal) {
		return fmt.Errorf("%w: %s changed during the rewrap", ErrMasterUntrusted, masterNextName)
	}
	for _, r := range [][2]string{{masterNextName, masterName}, {masterNextFingerprintName, masterFingerprintName}} {
		if err := mroot.Rename(r[0], r[1]); err != nil {
			return err
		}
		if err := syncDir(mroot); err != nil {
			return err
		}
		if err := s.step("rename " + r[0]); err != nil {
			return err
		}
	}
	return nil
}
