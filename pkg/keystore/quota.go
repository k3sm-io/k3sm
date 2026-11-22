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
	"slices"
	"strings"
)

// This file is the user scope's entry quotas and its rm:
// docs/design/keystore.md § "User scope", "Quotas". A scope holds at most
// 256 entries and 16 MiB of sealed records (the entries' files, generation
// files included, and the deliveries record); past either, put answers
// ErrQuota, and rm, which frees every version of an entry, still works.
// (The delivery bound is the delivery record's: deliveries.go.)

const (
	// maxScopeEntries is the most entries one user scope holds.
	maxScopeEntries = 256
	// maxScopeBytes is the most sealed record bytes one user scope holds:
	// every file in every entry directory, version records and pointers.
	maxScopeBytes = 16 << 20
)

// checkScopeQuota refuses, as ErrQuota, a put of value as name into
// entries when name is new and the scope already holds maxScopeEntries
// entries, or when its sealed records (every file in every entry
// directory), base (the deliveries record's size) and the new entry's
// files (version 1, its pointer and its generation file) would pass
// maxScopeBytes.
func checkScopeQuota(entries *os.Root, name string, value []byte, base int64) error {
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return err
	}
	count := 0
	exists := false
	total := base
	for _, n := range names {
		if checkName(n) != nil {
			continue
		}
		exists = exists || n == name
		count++
		size, err := entryBytes(entries, n)
		if err != nil {
			return err
		}
		total += size
	}
	// The count bounds new names: an existing name is the caller's
	// ErrExists (or a Rotate's version), never ErrQuota.
	if !exists && count >= maxScopeEntries {
		return fmt.Errorf("%w: the scope holds %d entries, at most %d", ErrQuota, count, maxScopeEntries)
	}
	add := int64(headerSize+len(name)+len(value)+tagSize) + int64(headerSize+len(currentName)+pointerSize+tagSize) + generationFileSize
	if total+add > maxScopeBytes {
		return fmt.Errorf("%w: the scope's sealed records would be %d bytes with its deliveries record, over %d; rm an entry rotated often, then put it again", ErrQuota, total+add, maxScopeBytes)
	}
	return nil
}

// deliveriesBytes is the size of the scope's deliveries record, which the
// byte budget counts.
func (u *UserScope) deliveriesBytes(root *os.Root) (int64, error) {
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return 0, err
	}
	defer func() { _ = dir.Close() }() // read-only
	fi, err := dir.Lstat(deliveriesName)
	if err != nil {
		return 0, fmt.Errorf("check for %s: %w", deliveriesName, err)
	}
	return fi.Size(), nil
}

// entryBytes sums the sizes of the regular files in entries/name, without
// following a symlink. A name that is not a directory counts nothing.
func entryBytes(entries *os.Root, name string) (int64, error) {
	e, err := openEntryDirRaw(entries, name)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCorrupt) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer e.close()
	files, err := readDirNames(e.root, maxDirNames)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, f := range files {
		fi, err := e.root.Lstat(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if fi.Mode().IsRegular() {
			total += fi.Size()
		}
	}
	return total, nil
}

// Delete removes input and every version of it from the caller's scope:
// rm. It is never refused for a quota, since it is how room is made, and,
// as a revocation, never for a GeneratedUID lookup that ran and failed or
// timed out, or a Rewrap half done (a lookup refused for capacity, where
// none ran, refuses it retryably: errLookupNotRun): it only removes files, so it needs neither W nor
// K_u, and opens no record. A lookup that answers a real GeneratedUID other
// than the one scope.key is bound to is ErrScopeOwnerChanged: the uid was
// reused, and its new holder must not delete the former owner's values. The scope must still have its scope.key, as every user
// verb's scope must. An entry directory without a current pointer, which
// the user scope reads as damage, is removed too.
//
// As a revocation it commits first and audits after: a failed append is
// reported (errCommitted) and the removal stands.
func (u *UserScope) Delete(ctx context.Context, input string) error {
	name, err := u.own("rm", input)
	if err != nil {
		u.auditBriefly(ctx, auditLine{op: "rm", name: auditPlaceholder}, err)
		return fail("rm", err)
	}
	if err := u.delete(ctx, name); err != nil {
		return fail("rm", err)
	}
	return nil
}

// delete commits, then appends its audit line before it releases the store
// lock (auditSink).
func (u *UserScope) delete(ctx context.Context, name string) (err error) {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	root, done, err := u.s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return err
	}
	defer done()
	defer func() { // before done: the line is appended under the lock
		l := auditLine{op: "rm", name: name, revoke: err == nil || errors.Is(err, errCommitted)}
		if aerr := u.appendAudit(l, err); err == nil {
			err = aerr
		}
	}()
	return u.deleteBody(root, name)
}

// deleteBody is delete's work under the lock.
func (u *UserScope) deleteBody(root *os.Root, name string) error {
	entries, gen, err := u.openEntriesForRevoke(root)
	if err != nil {
		return err
	}
	defer func() { _ = entries.Close() }() // every removal is fsynced
	// Only a real, different answer refuses; a lookup that ran and failed
	// or timed out is no answer, and rm goes ahead. One refused for
	// capacity, where no lookup ran, refuses rm, retryably: going ahead on
	// it would let a burst of stuck lookups stand in for the owner check.
	live, err := lookupGeneratedUID(u.uid)
	switch {
	case errors.Is(err, errLookupNotRun):
		return err
	case err == nil && live != gen:
		return fmt.Errorf("%w: uid %d", ErrScopeOwnerChanged, u.uid)
	}
	fi, err := entries.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		// An rm that removes nothing is not in the revocation class.
		if err := u.s.admit(u.uid, false); err != nil {
			return err
		}
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := u.s.admit(u.uid, true); err != nil {
		return err
	}
	var buryErr error
	if fi.IsDir() {
		// The tombstones first, under the lock and before any removal, so an
		// rm that fails part way, and a copy of the tree put back after it,
		// are refused as deleted (docs/design/keystore.md § "The user-scope
		// floor"). The generation file is not authenticated, so rm buries
		// every generation it can name: the floor's live ones for the name,
		// the generation file's and the pointer header's. A floor that cannot
		// take a line does not stop the revocation: it is reported as after a
		// commit, as is a disagreement between the three.
		e, err := openEntryDirRaw(entries, name)
		if err != nil {
			return err
		}
		buryErr = u.buryAll(e, name)
		// Then the pointer, so a crash leaves a directory the user scope
		// reads as damage, never an older entry; RemoveAll removes a symlink
		// itself, never what it names.
		err = e.root.RemoveAll(currentName)
		if err == nil {
			err = syncDir(e.root)
		}
		e.close()
		if err != nil {
			return err
		}
		if err := u.s.step("delete " + name); err != nil {
			return err
		}
	}
	if err := entries.RemoveAll(name); err != nil {
		return err
	}
	if err := syncDir(entries); err != nil {
		return err
	}
	if buryErr != nil {
		return fmt.Errorf("%w, but %w", errCommitted, buryErr)
	}
	return nil
}

// buryAll buries, for rm, every generation of name it can find: those the
// user-scope floor holds a live line for, the one e's generation file holds
// and the one e's pointer header carries, parsed without a key. A source
// that cannot be read adds nothing, since a tree a crashed Put left has no
// pointer; one that reads and disagrees with another is reported, after
// every generation is buried, as is a floor that did not take a line and an
// entry with no generation to bury at all.
func (u *UserScope) buryAll(e *entry, name string) error {
	var (
		gens    [][generationSize]byte
		sources []string
		errs    []error // the floor's: a tombstone unwritten
	)
	add := func(source string, g [generationSize]byte) {
		sources = append(sources, fmt.Sprintf("%s %x", source, g[:]))
		if !slices.Contains(gens, g) {
			gens = append(gens, g)
		}
	}
	live, err := u.s.userFloor.liveGens(u.scope, name)
	if err != nil {
		errs = append(errs, fmt.Errorf("read the floor's generations: %w", err))
	}
	for _, g := range live {
		add("the floor", g)
	}
	if g, err := readGeneration(e.root); err == nil {
		add("the generation file", g)
	}
	if g, ok := pointerHeaderGeneration(e.root, name); ok {
		add("the pointer header", g)
	}
	if len(gens) == 0 {
		errs = append(errs, errors.New("no generation to bury: the floor holds none for the name and neither the generation file nor the pointer header reads"))
	}
	for _, g := range gens {
		if err := u.s.userFloor.bury(u.scope, name, g); err != nil {
			errs = append(errs, err)
		}
	}
	var out []error
	if len(errs) > 0 {
		out = append(out, fmt.Errorf("with its tombstone unwritten: the user-scope floor did not take it: %w", errors.Join(errs...)))
	}
	if len(gens) > 1 {
		out = append(out, fmt.Errorf("the entry's generations disagree (%s), so its tree was altered; rm buried every one it could write", strings.Join(sources, ", ")))
	}
	return errors.Join(out...)
}

// pointerHeaderGeneration is the generation in the header of dir's current
// pointer, read without a key and so unauthenticated, when the file parses
// as a pointer record of name.
func pointerHeaderGeneration(dir *os.Root, name string) ([generationSize]byte, bool) {
	b, _, err := readFile(dir, currentName, maxRecordSize)
	if err != nil {
		return [generationSize]byte{}, false
	}
	r, err := parseRecord(b)
	if err != nil || r.kind != kindPointer || r.name != name {
		return [generationSize]byte{}, false
	}
	return r.generation, true
}

// openEntriesForRevoke opens the scope's entries/ for an rm: the scope
// directory must hold a scope.key the store trusts, which is not opened. It
// returns the generation the scope.key record carries.
func (u *UserScope) openEntriesForRevoke(root *os.Root) (*os.Root, [generationSize]byte, error) {
	var zero [generationSize]byte
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return nil, zero, err
	}
	defer func() { _ = dir.Close() }() // nothing is written in the scope directory
	r, err := u.s.readScopeKeyRecord(dir)
	if err != nil {
		return nil, zero, err
	}
	entries, err := u.s.openSubdir(dir, scopeEntriesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, zero, fmt.Errorf("%w: the scope has a scope key and no entries/ directory", ErrScopeAbsent)
	}
	if err != nil {
		return nil, zero, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err)
	}
	return entries, r.generation, nil
}
