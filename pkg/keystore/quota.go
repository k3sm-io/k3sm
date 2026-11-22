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
	absent := errors.Is(err, fs.ErrNotExist)
	if err != nil && !absent {
		return err
	}
	// The floor's live generations for the name, first and in every branch:
	// whatever stands at the name, or nothing, rm buries them, so a retried
	// rm closes the window one whose burial failed left open. A floor that
	// cannot be read refuses the rm before anything is written or removed.
	floorLive, err := u.s.userFloor.liveGens(u.scope, name)
	if err != nil {
		if aerr := u.s.admit(u.uid, false); aerr != nil {
			return aerr
		}
		return fmt.Errorf("rm refused, nothing removed: read the user-scope floor's generations for the name: %w", err)
	}
	if absent && len(floorLive) == 0 {
		// An rm that removes and buries nothing is not in the revocation class.
		if err := u.s.admit(u.uid, false); err != nil {
			return err
		}
		return ErrNotFound
	}
	if err := u.s.admit(u.uid, true); err != nil {
		return err
	}
	b := newBurial(name, floorLive)
	if absent {
		// No tree: only the floor's generations to bury, and nothing to
		// remove. The rm is idempotent and retryable.
		return b.bury(u)
	}
	if !fi.IsDir() {
		// A file or a symlink at the name is no entry the store wrote: bury,
		// then remove it (RemoveAll removes a symlink itself, never what it
		// names), and report the shape after the commit. With no generation
		// to bury it is refused, nothing removed.
		if len(b.gens) == 0 {
			return errRmNoGeneration
		}
		if err := b.bury(u); err != nil {
			return err
		}
		if err := entries.RemoveAll(name); err != nil {
			return err
		}
		if err := syncDir(entries); err != nil {
			return err
		}
		return fmt.Errorf("%w, but the entry's name held %s, not a directory, so its tree was altered; rm buried the floor's live generations and removed it", errCommitted, shapeOf(fi))
	}
	// The tombstones first, under the lock and before any removal, so an rm
	// that fails part way, and a copy of the tree put back after it, are
	// refused as deleted (docs/design/keystore.md § "The user-scope floor").
	// The generation file is not authenticated, so rm buries every
	// generation it can name: the floor's live ones for the name, the
	// generation file's, the pointer header's and each version record
	// header's. A floor that does not take a line refuses the rm before
	// anything is removed; a disagreement between the sources is reported
	// after the commit.
	e, err := u.openEntryForRm(entries, name)
	if err != nil {
		// The tree cannot be read for its generations: bury the floor's live
		// ones first, so a copy put back is refused, then report the open's
		// error with the tree left standing. A floor that does not take a
		// tombstone refuses the rm.
		if berr := b.bury(u); berr != nil {
			return berr
		}
		if len(b.gens) > 0 {
			return fmt.Errorf("%w, but the entry's directory could not be opened, so its tree stays; rm buried the floor's live generations: %w", errCommitted, err)
		}
		return err
	}
	b.addTree(e, name)
	if len(b.gens) == 0 {
		e.close()
		return errRmNoGeneration
	}
	if err := b.bury(u); err != nil {
		e.close()
		return err
	}
	// Then the pointer, so a crash leaves a directory the user scope reads
	// as damage, never an older entry; RemoveAll removes a symlink itself,
	// never what it names.
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
	if err := entries.RemoveAll(name); err != nil {
		return err
	}
	if err := syncDir(entries); err != nil {
		return err
	}
	if rerr := b.report(); rerr != nil {
		return fmt.Errorf("%w, but %w", errCommitted, rerr)
	}
	return nil
}

// errRmNoGeneration refuses an rm, before anything is removed, when no
// source names a generation to bury: the floor holds none live for the
// name, and neither the generation file nor a record header reads.
// Removing the tree then would leave nothing to refuse a copy of it put
// back.
var errRmNoGeneration = fmt.Errorf("%w: rm refused, nothing removed: no generation to bury: the user-scope floor holds none live for the name and neither the generation file nor a record header reads; root can run sudo k3sm keys floor --rebuild, which records the entry's generation, then rm again, or remove the entry's directory by hand", ErrCorrupt)

// openEntryForRm opens name's directory for an rm, through the entryOpen
// seam when it is set.
func (u *UserScope) openEntryForRm(entries *os.Root, name string) (*entry, error) {
	if u.s.entryOpen != nil {
		if err := u.s.entryOpen(name); err != nil {
			return nil, err
		}
	}
	return openEntryDirRaw(entries, name)
}

// shapeOf names what fi, which is not a directory, is.
func shapeOf(fi fs.FileInfo) string {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return "a symlink"
	case fi.Mode().IsRegular():
		return "a file"
	}
	return "a special file"
}

// maxTreeGenerations caps the distinct generations, beyond the floor's live
// ones, that one rm buries on the word of the tree alone: the generation
// file's, the pointer header's and the v<N> headers', none authenticated.
// Without it a tree-writer could plant a v<N> per generation and spend the
// floor's revocation headroom through one rm.
const maxTreeGenerations = 4

// burial is the generations rm buries for one name, and the source that
// named each.
type burial struct {
	name    string
	gens    [][generationSize]byte
	sources []string
	// floor is the floor's live generations, and pointer the pointer
	// header's, when it read.
	floor   [][generationSize]byte
	pointer *[generationSize]byte
	// capped is set when the tree named more than maxTreeGenerations
	// generations beyond floor: gens is then floor and pointer alone.
	capped bool
}

func newBurial(name string, live [][generationSize]byte) *burial {
	b := &burial{name: name, floor: live}
	for _, g := range live {
		b.add("the floor", g)
	}
	return b
}

// treeOnly is how many of gens the floor does not hold live.
func (b *burial) treeOnly() int {
	return len(b.gens) - len(b.floor)
}

func (b *burial) add(source string, g [generationSize]byte) {
	b.sources = append(b.sources, fmt.Sprintf("%s %x", source, g[:]))
	if !slices.Contains(b.gens, g) {
		b.gens = append(b.gens, g)
	}
}

// addTree adds the generations e's tree names: its generation file's, its
// pointer header's and each v<N> record header's, the headers parsed
// without a key. A source that does not read or parse adds nothing, since a
// tree a crashed Put left has no pointer.
//
// Past maxTreeGenerations distinct generations beyond the floor's live ones
// it stops reading and keeps only the floor's and the pointer header's
// (capped).
func (b *burial) addTree(e *entry, name string) {
	if g, ok := headerGeneration(e.root, currentName, name, true); ok {
		b.pointer = &g
	}
	defer func() {
		if b.treeOnly() <= maxTreeGenerations {
			return
		}
		b.capped, b.gens, b.sources = true, nil, nil
		for _, g := range b.floor {
			b.add("the floor", g)
		}
		if b.pointer != nil {
			b.add("the pointer header", *b.pointer)
		}
	}()
	if g, err := readGeneration(e.root); err == nil {
		b.add("the generation file", g)
	}
	if b.pointer != nil {
		b.add("the pointer header", *b.pointer)
	}
	files, err := readDirNames(e.root, maxDirNames)
	if err != nil {
		return
	}
	var vs []uint64
	for _, f := range files {
		if n, ok := parseVersionName(f); ok {
			vs = append(vs, n)
		}
	}
	slices.Sort(vs)
	for _, n := range vs {
		if b.treeOnly() > maxTreeGenerations {
			return
		}
		if g, ok := headerGeneration(e.root, versionName(n), name, false); ok {
			b.add(versionName(n)+"'s header", g)
		}
	}
}

// bury appends a tombstone for every generation, and refuses, before the
// caller removes anything, when the floor did not take one: the rm is then
// retryable, and the tree stays.
func (b *burial) bury(u *UserScope) error {
	var errs []error
	for _, g := range b.gens {
		if err := u.s.userFloor.bury(u.scope, b.name, g); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("rm refused, nothing removed: the user-scope floor did not take its tombstone: %w", errors.Join(errs...))
	}
	return nil
}

// report is what rm reports after its commit: generations that disagree,
// since the tree was altered. An rm with no generation to bury never
// commits (errRmNoGeneration).
func (b *burial) report() error {
	if b.capped {
		return fmt.Errorf("the entry's tree named more than %d generations beyond the floor's live ones, so it was altered; rm buried the floor's live generations and the pointer header's, and removed it", maxTreeGenerations)
	}
	if len(b.gens) > 1 {
		return fmt.Errorf("the entry's generations disagree (%s), so its tree was altered; rm buried every one", strings.Join(b.sources, ", "))
	}
	return nil
}

// headerGeneration is the generation in the header of dir's file, read
// without a key and so unauthenticated, when the file parses as a record of
// name: a pointer record when pointer is set, else a version record.
func headerGeneration(dir *os.Root, file, name string, pointer bool) ([generationSize]byte, bool) {
	b, _, err := readFile(dir, file, maxRecordSize)
	if err != nil {
		return [generationSize]byte{}, false
	}
	r, err := parseRecord(b)
	if err != nil || (r.kind == kindPointer) != pointer || r.name != name {
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
