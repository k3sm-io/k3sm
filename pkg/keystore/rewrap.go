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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
// retire it. A Rewrap whose master.next was replaced or removed after some
// record moved under its key is completed by a rerun with that same key.
//
// Each user scope's scope.key is re-sealed under the new master's
// scope-wrap key W in the same two phases, as one more record; every other
// user record stays sealed under its scope key, byte for byte unchanged
// (docs/design/keystore.md § "User scope", "Rewrap of scope keys").
//
// It refuses, writing nothing, while .user, or a scope directory in it, is
// not a directory it can trust, or a scope.key does not open
// (ErrCorrupt), while the floor cannot be written, and while any entry does
// not open: an entry List reports with Err
// would otherwise be left sealed under a master that no longer exists, so it
// is removed (rm) or restored first. An interrupted Put is not an entry and is
// not re-sealed; the next Put of its name discards it. A version above the one
// the pointer names, which a Rotate interrupted before its flip leaves, is not
// committed and is not re-sealed either; the next Rotate discards it.
//
// Every error it returns before it first writes master.next from newMaster
// also matches ErrRewrapNotStarted: nothing was then sealed under newMaster
// by this call. That covers the config, size, floor-writable, lock, .user,
// master and live-key refusals, an empty keystore, the floor raise, and a
// plan refused because an entry does not open, as well as ErrRewrapResumed
// (the run completed another key). An error after that write never matches
// it, whatever its cause.
//
// An error while it completes an earlier rewrap under that rewrap's key,
// once it has advanced it (a record renamed in, or the master swap moved),
// matches ErrRewrapResumeFailed instead, and never ErrRewrapNotStarted: the
// earlier key, not newMaster, finishes it.
func (s *FileStore) Rewrap(ctx context.Context, newMaster []byte) error {
	var p rewrapProgress
	if err := s.rewrap(ctx, newMaster, &p); err != nil {
		switch {
		case p.resuming && !errors.Is(err, ErrRewrapResumed):
			return fmt.Errorf("rewrap: %w (%w)", err, ErrRewrapResumeFailed)
		case !p.started:
			return fmt.Errorf("rewrap: %w (%w)", err, ErrRewrapNotStarted)
		}
		return fmt.Errorf("rewrap: %w", err)
	}
	return nil
}

// rewrapProgress is how far a Rewrap got, which decides the marker its error
// carries.
type rewrapProgress struct {
	// started is set just before Rewrap first writes master.next from the key
	// it was given, or resumes a rewrap under that same key.
	started bool
	// resuming is set once Rewrap is completing an earlier rewrap under
	// another key: from the plan that resumes it, or from a half-done master
	// swap it moved on.
	resuming bool
}

// rewrap is Rewrap. It records its progress in p.
func (s *FileStore) rewrap(ctx context.Context, newMaster []byte, p *rewrapProgress) error {
	started := &p.started
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
	// keystore-lock first, then .lock: the one order of § Concurrency.
	fdir, fl, err := s.lockFloor(ctx)
	if err != nil {
		return err
	}
	defer fdir.unlock()
	root, err := s.openDir(s.dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the keystore holds nothing to rewrap: %w", err)
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }() // every write below is fsynced
	unlock, err := s.lock(ctx, root, true)
	if err != nil {
		return err
	}
	defer unlock()
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
		// done with an error: the swap moved, then its sync or step failed.
		if done {
			p.resuming = true
			return fmt.Errorf("%w (%w)", err, ErrRewrapSwapUnsynced)
		}
		return err
	}
	k, err := s.loadMaster()
	if err != nil {
		return err
	}
	if done {
		return resumed(k, newMaster)
	}
	// A new master equal to the live one is refused here, before the floor
	// raise and before any master.next is discarded, so it writes nothing.
	if err := refuseLive(k, newMaster); err != nil {
		return err
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
	next, plan, resuming, err := s.prepareNext(ctx, root, mroot, fl, old, newMaster, started)
	if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrMasterUntrusted) {
		k, p, ok, aerr := s.adoptSupplied(ctx, root, mroot, fl, old, newMaster, started)
		if aerr != nil {
			return aerr
		}
		if ok {
			next, plan, resuming, err = k, p, false, nil
		}
	}
	if err != nil {
		return err
	}
	defer next.wipe()
	if resuming {
		// A master.next of newMaster's own is this caller's rewrap, resumed
		// with its key; any other is an earlier rewrap's.
		if resumed(next, newMaster) == nil {
			*started = true
		} else {
			p.resuming = true
		}
	}
	if err := s.sealNew(ctx, root, fl, plan, old, next); err != nil {
		return err
	}
	if err := s.commitNew(ctx, root, fl, plan, old, next); err != nil {
		return err
	}
	if err := s.checkScopesPlanned(ctx, root, plan, next); err != nil {
		return err
	}
	if swapped, err := s.swapMaster(mroot, next); err != nil {
		// A swap that went through and then failed (its last sync or step)
		// left the rewrap complete: under the earlier key on a resume, under
		// newMaster otherwise.
		if swapped {
			return fmt.Errorf("%w (%w)", err, ErrRewrapSwapUnsynced)
		}
		return err
	}
	if resuming {
		return resumed(next, newMaster)
	}
	return nil
}

// InterruptedRewrap reports the fingerprint, SHA-256 of the key, that an
// interrupted Rewrap recorded in master.next.sha256, with ok set, or ok unset
// when no Rewrap left one: no entries' directory, no master directory, or no
// master.next.sha256. It reads under the shared lock and writes nothing. A
// fingerprint file that is not the service user's, not mode 0600 or does not
// parse is ErrMasterUntrusted.
//
// The record is the only evidence of which key a crashed Rewrap was sealing
// under, so a caller that would hand Rewrap a key it did not mint itself
// checks that key against it first: a key no Rewrap recorded is no recovery.
func (s *FileStore) InterruptedRewrap(ctx context.Context) (fingerprint [sha256.Size]byte, ok bool, err error) {
	fp, ok, err := s.interruptedRewrap(ctx)
	if err != nil {
		return fp, false, fmt.Errorf("check for an interrupted rewrap: %w", err)
	}
	return fp, ok, nil
}

func (s *FileStore) interruptedRewrap(ctx context.Context) ([sha256.Size]byte, bool, error) {
	var fp [sha256.Size]byte
	if err := s.checkConfig(); err != nil {
		return fp, false, err
	}
	_, done, err := s.openLocked(ctx, false, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fp, false, nil
	}
	if err != nil {
		return fp, false, err
	}
	defer done()
	mroot, err := s.openMasterDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return fp, false, nil
	}
	if err != nil {
		return fp, false, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	defer func() { _ = mroot.Close() }() // read-only; nothing to flush
	recorded, fi, err := readFile(mroot, masterNextFingerprintName, fingerprintFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return fp, false, nil
	}
	if err != nil {
		return fp, false, fmt.Errorf("%w: %s: %w", ErrMasterUntrusted, masterNextFingerprintName, err)
	}
	if err := s.checkOwned(fi, fileMode); err != nil {
		return fp, false, fmt.Errorf("%w: %s: %w", ErrMasterUntrusted, masterNextFingerprintName, err)
	}
	if fi.Mode().Perm() != fileMode {
		return fp, false, fmt.Errorf("%w: %s: mode %04o, want %04o", ErrMasterUntrusted, masterNextFingerprintName, fi.Mode().Perm(), fileMode)
	}
	hexFP, nl := strings.CutSuffix(string(recorded), "\n")
	n, derr := hex.Decode(fp[:], []byte(hexFP))
	if !nl || derr != nil || n != sha256.Size || len(hexFP) != hex.EncodedLen(sha256.Size) {
		return [sha256.Size]byte{}, false, fmt.Errorf("%w: %s is not a hex SHA-256 and a newline", ErrMasterUntrusted, masterNextFingerprintName)
	}
	return fp, true, nil
}

// RecordsSealedUnder reports whether the keystore holds records a Rewrap to
// key already committed: every record opens under the live master or under
// key, and at least one only under key. That is the state a Rewrap leaves
// when it is interrupted after renaming records in and its master.next is
// then replaced or removed, and Rewrap(key) completes it. A key no Rewrap
// sealed under, the live master included, reports false. It reads under the
// shared lock and writes nothing.
func (s *FileStore) RecordsSealedUnder(ctx context.Context, key []byte) (bool, error) {
	ok, err := s.recordsSealedUnder(ctx, key)
	if err != nil {
		return false, fmt.Errorf("check for records sealed under the key: %w", err)
	}
	return ok, nil
}

func (s *FileStore) recordsSealedUnder(ctx context.Context, key []byte) (bool, error) {
	if err := s.checkConfig(); err != nil {
		return false, err
	}
	if len(key) != masterSize {
		return false, fmt.Errorf("the key is %d bytes, want %d", len(key), masterSize)
	}
	root, done, err := s.openLocked(ctx, false, false)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer done()
	fdir, fl, err := s.openFloor()
	if err != nil {
		return false, err
	}
	_ = fdir.Close() // read-only; nothing to flush
	old, err := s.loadMaster()
	if err != nil {
		return false, err
	}
	old.next = nil
	k, err := deriveMasterKeys(key, s.scope)
	if err != nil {
		return false, err
	}
	defer k.wipe()
	_, committed, err := s.rewrapPlan(ctx, root, fl, old, &k)
	if errors.Is(err, ErrCorrupt) {
		// Some record opens under neither key: not a Rewrap to key.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return committed, nil
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

// wipe clears the key material k derived, once nothing will seal or open
// under it again.
func (k *keys) wipe() {
	clear(k.seal)
	clear(k.fingerprint)
	clear(k.wrap)
}

// refuseLive refuses a newMaster that is the live master k.
func refuseLive(k keys, newMaster []byte) error {
	nk, err := deriveKeys(newMaster, k.scope)
	if err != nil {
		return err
	}
	defer nk.wipe()
	if hmac.Equal(nk.seal, k.seal) {
		return errors.New("the new master is the live one")
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
func (s *FileStore) prepareNext(ctx context.Context, root, mroot *os.Root, fl floor, old keys, newMaster []byte, started *bool) (keys, []planned, bool, error) {
	raw, err := s.readNext(mroot)
	if err == nil {
		k, derr := deriveMasterKeys(raw, s.scope)
		clear(raw)
		if derr != nil {
			return keys{}, nil, false, derr
		}
		plan, committed, perr := s.rewrapPlan(ctx, root, fl, old, &k)
		if perr != nil {
			k.wipe()
			return keys{}, nil, false, perr
		}
		if committed {
			return k, plan, true, nil
		}
		k.wipe()
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
	found, ferr := s.anyNew(ctx, root)
	if ferr != nil {
		return keys{}, nil, false, ferr
	}
	if found {
		return keys{}, nil, false, fmt.Errorf("%w: %s is missing or does not match its fingerprint, and records were already re-sealed under it: restore the master directory and keystore/ from one matched backup (%w)", ErrMasterUntrusted, masterNextName, err)
	}
	plan, _, perr := s.rewrapPlan(ctx, root, fl, old, nil)
	if perr != nil {
		if bad {
			return keys{}, nil, false, fmt.Errorf("%w: %s does not match its fingerprint, and a record does not open under the live master, so it may be sealed under %s: restore the master directory and keystore/ from one matched backup (%w; %w)", ErrMasterUntrusted, masterNextName, masterNextName, err, perr)
		}
		return keys{}, nil, false, perr
	}
	*started = true
	if err := s.writeNext(mroot, newMaster); err != nil {
		return keys{}, nil, false, err
	}
	next, err := deriveMasterKeys(newMaster, s.scope)
	if err != nil {
		return keys{}, nil, false, err
	}
	return next, plan, false, nil
}

// adoptSupplied is the recovery for records already sealed under newMaster
// itself, which a master.next replaced or removed during a Rewrap (by the
// service user, who owns the master directory) leaves behind: the caller's
// key then exists only as the caller's input, and prepareNext refuses. When
// every record opens under old or newMaster, and some only under newMaster,
// master.next and its fingerprint are written again from newMaster and it
// returns the keys to resume under, ok set. Otherwise it writes nothing and
// reports !ok, and the caller keeps prepareNext's refusal. A record under any
// third key fails the plan, so this never orphans one.
func (s *FileStore) adoptSupplied(ctx context.Context, root, mroot *os.Root, fl floor, old keys, newMaster []byte, started *bool) (keys, []planned, bool, error) {
	k, err := deriveMasterKeys(newMaster, s.scope)
	if err != nil {
		return keys{}, nil, false, err
	}
	plan, committed, err := s.rewrapPlan(ctx, root, fl, old, &k)
	if err != nil && !errors.Is(err, ErrCorrupt) {
		// Not "a record does not open": a cancelled ctx, an I/O error or a
		// listing bound. Report it as itself, never as the refusal that
		// tells the operator to restore from a backup.
		k.wipe()
		return keys{}, nil, false, err
	}
	if err != nil || !committed {
		k.wipe()
		return keys{}, nil, false, nil
	}
	*started = true
	if err := s.writeNext(mroot, newMaster); err != nil {
		k.wipe()
		return keys{}, nil, false, err
	}
	return k, plan, true, nil
}

// writeNext writes key as master.next, then its fingerprint.
func (s *FileStore) writeNext(mroot *os.Root, key []byte) error {
	// The stale fingerprint goes first, so an interruption never leaves one
	// that vouches for a key that was not written; the rename of master.next
	// replaces a stale one. This is defence in depth: without it, a crash
	// between the two writes would leave master.next beside a fingerprint it
	// does not match, which the next run already treats as a master.next that
	// does not agree. Removing it first means no fingerprint ever names a key
	// other than the one written beside it.
	if err := mroot.Remove(masterNextFingerprintName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the stale %s: %w", masterNextFingerprintName, err)
	}
	if err := s.writeFile(mroot, masterNextName, key); err != nil {
		return err
	}
	return s.writeFile(mroot, masterNextFingerprintName, []byte(masterFingerprint(key)))
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
	err = s.eachScopeDir(ctx, root, func(_ string, dir *os.Root) error {
		err := dir.Remove(scopeKeyName + newSuffix)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return syncDir(dir)
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

// anyNew reports whether any entry directory holds a .new file, or any user
// scope a scope.key.new: whether step 3 of some Rewrap had started.
func (s *FileStore) anyNew(ctx context.Context, root *os.Root) (bool, error) {
	found := false
	err := eachEntryDir(ctx, root, func(_ *entry, files []string) error {
		for _, f := range files {
			if strings.HasSuffix(f, newSuffix) {
				found = true
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	err = s.eachScopeDir(ctx, root, func(_ string, dir *os.Root) error {
		_, err := dir.Lstat(scopeKeyName + newSuffix)
		if err == nil {
			found = true
			return nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
	return found, err
}

// planned is one entry a Rewrap re-seals: its name and the version its
// pointer names, so its records are v1 to vcur and current.
type planned struct {
	name string
	cur  uint64
	// scope, when set, makes this the scope.key of the user scope whose
	// directory is .user/<scope> (rewrapscope.go), and name and cur unused.
	scope string
	// pin is, for a scope, what its scope.key held when it was planned,
	// which its commit and the final check require it still holds.
	pin scopePin
}

// rewrapPlan lists, sorted by name, every entry with the version its pointer
// names, and refuses unless every one of their records opens under old or,
// when next is set, under next. It also reports whether any record opens only
// under next: whether a commit under next had begun. A directory that is not
// an entry (an interrupted Put) is left out; one that List would report with
// Err refuses the Rewrap, which would otherwise leave it sealed under a master
// that no longer exists.
func (s *FileStore) rewrapPlan(ctx context.Context, root *os.Root, fl floor, old keys, next *keys) ([]planned, bool, error) {
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
		out = append(out, planned{name: name, cur: cur})
	}
	scopes, underNext, err := s.planScopes(ctx, root, old, next)
	if err != nil {
		return nil, false, err
	}
	return append(out, scopes...), committed || underNext, nil
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
		if err := either(func(k keys) error {
			_, pt, err := e.version(k, n)
			defer clear(pt)
			return err
		}); err != nil {
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
		if p.scope != "" {
			if err := s.sealScopeKey(root, p.scope, old, next); err != nil {
				return err
			}
			continue
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
				_, npt, err := e.openRecord(next, file, pointer, version)
				defer clear(npt)
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
// each .new, which must open under next as the record it replaces and hold
// its plaintext, kind and created time (else ErrCorrupt, and it is not
// renamed), is renamed
// over its record, the pointer last in each entry, and the entry's directory
// fsynced. A .new beside a record already under next is removed. A record
// that opens under neither stops the Rewrap before the master is swapped.
func (s *FileStore) commitNew(ctx context.Context, root *os.Root, fl floor, plan []planned, old, next keys) error {
	for i, p := range plan {
		if err := loopCtx(ctx, i); err != nil {
			return err
		}
		if p.scope != "" {
			if err := s.commitScopeKey(root, p, old, next); err != nil {
				return err
			}
			continue
		}
		e, err := openEntry(root, p.name, fl)
		if err != nil {
			return err
		}
		err = eachRecord(ctx, p.cur, func(file string, pointer bool, version uint64) error {
			r, pt, err := e.openRecord(old, file, pointer, version)
			if err == nil {
				defer clear(pt)
				nr, npt, err := e.openRecord(next, file+newSuffix, pointer, version)
				if err != nil {
					return err
				}
				same := nr.kind == r.kind && nr.created == r.created && bytes.Equal(npt, pt)
				clear(npt)
				if !same {
					return fmt.Errorf("%w: %s%s does not hold the record it replaces", ErrCorrupt, file, newSuffix)
				}
				if err := e.root.Rename(file+newSuffix, file); err != nil {
					return err
				}
				return s.step("rename " + p.name + "/" + file)
			}
			if !errors.Is(err, ErrCorrupt) {
				return err
			}
			_, npt, err := e.openRecord(next, file, pointer, version)
			defer clear(npt)
			if err != nil {
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
// master.next is read again first, and master read back after its rename,
// so the key the records were sealed under is the one that becomes the
// master; otherwise it stops with ErrMasterUntrusted before the fingerprint
// rename.
// It reports swapped once the second rename is made, with or without an
// error after it.
func (s *FileStore) swapMaster(mroot *os.Root, next keys) (swapped bool, err error) {
	raw, err := s.readNext(mroot)
	if err != nil {
		return false, err
	}
	k, err := deriveKeys(raw, s.scope)
	clear(raw)
	if err != nil {
		return false, err
	}
	if !hmac.Equal(k.seal, next.seal) {
		return false, fmt.Errorf("%w: %s changed during the rewrap", ErrMasterUntrusted, masterNextName)
	}
	for _, r := range [][2]string{{masterNextName, masterName}, {masterNextFingerprintName, masterFingerprintName}} {
		if err := mroot.Rename(r[0], r[1]); err != nil {
			return false, err
		}
		// After the second rename the swap is complete: a later error is
		// reported with swapped set.
		swapped = r[1] == masterFingerprintName
		if err := syncDir(mroot); err != nil {
			return swapped, err
		}
		if r[1] == masterName {
			if err := s.checkMasterIs(mroot, next); err != nil {
				return false, err
			}
		}
		if err := s.step("rename " + r[0]); err != nil {
			return swapped, err
		}
	}
	return true, nil
}

// checkMasterIs refuses, as ErrMasterUntrusted, a master file that is not the
// key k was derived from.
func (s *FileStore) checkMasterIs(mroot *os.Root, k keys) error {
	raw, err := s.readKeyFile(mroot, masterName)
	if err != nil {
		return fmt.Errorf("%w: read the master back after its rename: %w", ErrMasterUntrusted, err)
	}
	got, err := deriveKeys(raw, s.scope)
	clear(raw)
	if err != nil {
		return err
	}
	if !hmac.Equal(got.seal, k.seal) {
		return fmt.Errorf("%w: %s changed during the swap", ErrMasterUntrusted, masterName)
	}
	return nil
}
