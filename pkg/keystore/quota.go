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
	// MaxScopeEntries is maxScopeEntries for the socket, which sizes a
	// list reply to hold a full scope.
	MaxScopeEntries = maxScopeEntries
	// maxScopeBytes is the most sealed record bytes one user scope holds:
	// every file in every entry directory, version records and pointers.
	maxScopeBytes = 16 << 20
)

// checkScopeQuota refuses, as ErrQuota, a put of value as name into
// entries when name is new and the scope already holds maxScopeEntries
// entries, or when its sealed records (every file in every entry
// directory), base (the deliveries record's size) and the new entry's
// files (version 1, its pointer and its generation file) would pass
// maxScopeBytes. It walks the scope; a user put or rotate judges the
// scope's usage figure instead (usage.go, judgeScopeQuota).
func checkScopeQuota(entries *os.Root, name string, value []byte, base int64) error {
	used, err := walkScopeEntries(entries, nil)
	if err != nil {
		return err
	}
	return judgeScopeQuota(used, name, value, base)
}

// walkScopeEntries is every entry name in entries with its sealed bytes
// (entryBytes); lstat, when set, is called before each file's Lstat, where
// a test counts the walk.
func walkScopeEntries(entries *os.Root, lstat func()) (map[string]int64, error) {
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return nil, err
	}
	used := make(map[string]int64, len(names))
	for _, n := range names {
		if checkName(n) != nil {
			continue
		}
		size, err := entryBytes(entries, n, lstat)
		if err != nil {
			return nil, err
		}
		used[n] = size
	}
	return used, nil
}

// judgeScopeQuota is checkScopeQuota's judgement on used, every entry
// name with its sealed bytes: no file is read.
func judgeScopeQuota(used map[string]int64, name string, value []byte, base int64) error {
	total := base
	for _, size := range used {
		total += size
	}
	_, exists := used[name]
	count := len(used)
	// The count bounds new names: an existing name is the caller's
	// ErrExists (or a Rotate's version), never ErrQuota.
	if !exists && count >= maxScopeEntries {
		return fmt.Errorf("%w: the scope holds %d entries, at most %d", ErrQuota, count, maxScopeEntries)
	}
	add := entryWriteBytes(name, value)
	if total+add > maxScopeBytes {
		return fmt.Errorf("%w: the scope's sealed records would be %d bytes with its deliveries record, over %d", ErrQuota, total+add, maxScopeBytes)
	}
	return nil
}

// entryWriteBytes is what a put of value as name writes in the entry's
// directory: version 1, its pointer and its generation file.
func entryWriteBytes(name string, value []byte) int64 {
	return int64(headerSize+len(name)+len(value)+tagSize) + int64(headerSize+len(currentName)+pointerSize+tagSize) + generationFileSize
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
// following a symlink; lstat, when set, is called before each file's
// Lstat. A name that is not a directory counts nothing.
func entryBytes(entries *os.Root, name string, lstat func()) (int64, error) {
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
		if lstat != nil {
			lstat()
		}
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
// reported (ErrCommitted) and the removal stands.
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
	u = u.withGUID()
	unlockUID, err := u.s.usage.lockUID(ctx, u.uid, u.s.lockWait)
	if err != nil {
		return err
	}
	defer unlockUID()
	root, done, err := u.s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return err
	}
	defer done()
	defer func() { // the scope's figure: the entry removed, or recomputed
		if err == nil {
			u.s.usage.update(u.uid, func(m map[string]int64) { delete(m, name) })
		} else if !errors.Is(err, ErrNotFound) {
			u.s.usage.forget(u.uid)
		}
	}()
	defer func() { // before done: the line is appended under the lock
		l := auditLine{op: "rm", name: name, revoke: err == nil || Committed(err)}
		err = u.keepAuditFailure("rm", err, u.appendAudit(l, err))
	}()
	return u.deleteBody(root, name)
}

// deleteBody is delete's work under the lock.
func (u *UserScope) deleteBody(root *os.Root, name string) error {
	// A scope.key that cannot be read refuses the rm before anything is
	// written; entries/ that cannot be opened (entErr) is judged after the
	// owner check, below.
	entries, gen, entErr, err := u.openEntriesForRevoke(root)
	if err != nil {
		return err
	}
	if entries != nil {
		defer func() { _ = entries.Close() }() // every removal is fsynced
	}
	// Only a real, different answer refuses; a lookup that ran and failed
	// or timed out is no answer, and rm goes ahead. One refused for
	// capacity, where no lookup ran, refuses rm, retryably: going ahead on
	// it would let a burst of stuck lookups stand in for the owner check.
	live, err := u.liveGUID()
	switch {
	case errors.Is(err, errLookupNotRun):
		return err
	case err == nil && live != gen:
		return fmt.Errorf("%w: uid %d", ErrScopeOwnerChanged, u.uid)
	}
	if entErr != nil {
		// The scope is the owner's and entries/ cannot be opened (missing,
		// or not what the store made): bury the floor's live generations
		// for the name first, so a tree put back is refused, then report it.
		return u.buryThen(name, entErr)
	}
	fi, err := entries.Lstat(name)
	absent := errors.Is(err, fs.ErrNotExist)
	if err != nil && !absent {
		// The name cannot be judged: bury, then report the Lstat's error.
		return u.buryThen(name, err)
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
		err := entries.RemoveAll(name)
		if err == nil {
			err = syncDir(entries)
		}
		if err != nil {
			return fmt.Errorf("%w: rm buried the floor's live generations, so the name is refused as deleted, but what stood there was not removed: %w", errCommitted, err)
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
	if g, ok := u.authenticatedGeneration(root, e); ok {
		b.addAuthenticated(g)
	}
	b.addTree(e, name)
	if len(b.gens) == 0 {
		sealed := holdsSealed(e.root)
		e.close()
		if sealed {
			return errRmNoGeneration
		}
		// Nothing sealed stands (a crash between the put's mkdir and its
		// generation write): no copy of it could be served, so there is
		// nothing to bury and it is removed.
		err := entries.RemoveAll(name)
		if err == nil {
			err = syncDir(entries)
		}
		return err
	}
	if err := b.bury(u); err != nil {
		e.close()
		return err
	}
	// Then the pointer, so a crash leaves a directory the user scope reads
	// as damage, never an older entry; RemoveAll removes a symlink itself,
	// never what it names. A removal that fails from here on is after the
	// commit: the tombstones are written, so the entry is refused as
	// deleted whatever of its tree stays.
	err = e.root.RemoveAll(currentName)
	if err == nil {
		err = syncDir(e.root)
	}
	e.close()
	if err == nil {
		err = u.s.step("delete " + name)
	}
	if err == nil {
		err = entries.RemoveAll(name)
	}
	if err == nil {
		err = syncDir(entries)
	}
	if err != nil {
		return fmt.Errorf("%w: rm buried the entry's generations, so it is refused as deleted, but its tree was not fully removed: %w", errCommitted, err)
	}
	if rerr := b.report(); rerr != nil {
		return fmt.Errorf("%w, but %w", errCommitted, rerr)
	}
	return nil
}

// buryThen buries the floor's live generations for name, then returns
// cause: wrapped in errCommitted when it buried any, so the rm is audited as
// a revocation, and alone when the floor holds none live. A floor that
// cannot be read, or that does not take a tombstone, refuses the rm with
// nothing written.
func (u *UserScope) buryThen(name string, cause error) error {
	floorLive, err := u.s.userFloor.liveGens(u.scope, name)
	if err != nil {
		if aerr := u.s.admit(u.uid, false); aerr != nil {
			return aerr
		}
		return fmt.Errorf("rm refused, nothing removed: read the user-scope floor's generations for the name: %w (and: %w)", err, cause)
	}
	if len(floorLive) == 0 {
		if err := u.s.admit(u.uid, false); err != nil {
			return err
		}
		return cause
	}
	if err := u.s.admit(u.uid, true); err != nil {
		return err
	}
	if err := newBurial(name, floorLive).bury(u); err != nil {
		return err
	}
	return fmt.Errorf("%w, but nothing was removed; rm buried the floor's live generations: %w", errCommitted, cause)
}

// errRmNoGeneration refuses an rm, before anything is removed, when no
// source names a generation to bury: the floor holds none live for the
// name, and neither the generation file nor a record header reads.
// Removing the tree then would leave nothing to refuse a copy of it put
// back.
var errRmNoGeneration = fmt.Errorf("%w: rm refused, nothing removed: no generation to bury: the user-scope floor holds none live for the name and neither the generation file nor a record header reads; root can remove the entry's directory by hand, or run sudo k3sm keys floor --rebuild, which records the entry's generation, so rm can bury it", ErrCorrupt)

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

// holdsSealed reports whether dir may hold a sealed record: a current
// pointer or a v<N> version file, or names it cannot list.
func holdsSealed(dir *os.Root) bool {
	names, err := readDirNames(dir, maxDirNames)
	if err != nil {
		return true
	}
	for _, n := range names {
		if _, ok := parseVersionName(n); ok || n == currentName {
			return true
		}
	}
	return false
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

// userBurial is the generations rm buries for one name, and the source that
// named each.
type userBurial struct {
	name    string
	gens    [][generationSize]byte
	sources []string
	// floor is the floor's live generations, authed the generation the
	// pointer authenticates under K_u, and pointer the pointer header's,
	// when each read.
	floor   [][generationSize]byte
	authed  *[generationSize]byte
	pointer *[generationSize]byte
	// capped is set when the tree named more than maxTreeGenerations
	// generations beyond floor: gens is then floor and pointer alone.
	capped bool
}

func newBurial(name string, live [][generationSize]byte) *userBurial {
	b := &userBurial{name: name, floor: live}
	for _, g := range live {
		b.add("the floor", g)
	}
	return b
}

// treeOnly is how many of gens only the tree names: neither the floor holds
// it live nor the authenticated pointer carries it.
func (b *userBurial) treeOnly() int {
	n := len(b.floor)
	if b.authed != nil && !slices.Contains(b.floor, *b.authed) {
		n++
	}
	return len(b.gens) - n
}

// addAuthenticated adds the generation the entry's pointer authenticates
// under K_u. It is no tree claim, so maxTreeGenerations does not count it,
// and the reservation covers it with the rest.
func (b *userBurial) addAuthenticated(g [generationSize]byte) {
	b.authed = &g
	b.add("the authenticated pointer", g)
}

// authenticatedGeneration is the generation e's pointer authenticates under
// the scope's K_u, when the master loads, the scope.key opens under W (with
// no GeneratedUID check, as for any revocation) and the pointer
// authenticates. It is best effort: rm needs neither W nor K_u, so a key
// that does not load only leaves the burial to the floor and the tree.
func (u *UserScope) authenticatedGeneration(root *os.Root, e *entry) ([generationSize]byte, bool) {
	k, err := u.s.loadMaster()
	if err != nil {
		return [generationSize]byte{}, false
	}
	o, err := u.openScopeForRevoke(root, k)
	if err != nil {
		return [generationSize]byte{}, false
	}
	defer o.close()
	g, _, ok := authenticatedPointer(&entry{root: e.root, name: e.name}, o.uk)
	return g, ok
}

func (b *userBurial) add(source string, g [generationSize]byte) {
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
func (b *userBurial) addTree(e *entry, name string) {
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
		if b.authed != nil {
			b.add("the authenticated pointer", *b.authed)
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

// bury appends a tombstone for every generation, the one a reader serves
// (served) first. The file-backed floor takes them as one write
// (buryAll): everything the burial needs is judged and reserved for the
// whole buffer, and a refusal, or a write that fails or lands short before
// its first whole tombstone, refuses the rm with nothing committed,
// retryable, and the tree stays; short bytes are a torn tail the reader
// skips. A write that fails after whole tombstones landed has revoked the
// entry: it is reported after the commit (errCommitted), as below. Any other floor takes them
// one by one: a first tombstone it does not take refuses the rm with
// nothing written, and once any has landed the entry is revoked, so a later
// one that fails is reported after the commit (errCommitted): the rm is
// audited as a revocation, the tree stays, and a retry buries the rest.
func (b *userBurial) bury(u *UserScope) error {
	order := b.ordered()
	if ff, ok := u.s.userFloor.(*fileFloorLog); ok {
		err := ff.buryAll(u.scope, b.name, order)
		var landed *linesLanded
		switch {
		case err == nil:
			return nil
		case errors.As(err, &landed) && landed.unsynced:
			// The tombstones are visible, so every reader holds them in
			// force, but the fsync failed: a crash could lose them, so a
			// retry makes them durable.
			return fmt.Errorf("%w, but the user-scope floor's fsync failed after %d of the entry's %d tombstones were visible, %s, and its tree stays; durability uncertain; run rm again: %w", errCommitted, landed.lines, len(order), b.landedWhat(order[:min(landed.lines, len(order))]), err)
		case errors.As(err, &landed):
			// Whole tombstones landed before the write failed: they are in
			// force, so the rm committed.
			return fmt.Errorf("%w, but only in part: the user-scope floor took %d of the entry's %d tombstones before its write failed, %s, and its tree stays; run rm again to bury the rest: %w", errCommitted, landed.lines, len(order), b.landedWhat(order[:min(landed.lines, len(order))]), err)
		}
		return fmt.Errorf("rm refused, nothing removed: the user-scope floor did not take its tombstones, or could not make them durable; run rm again: %w", err)
	}
	var (
		took [][generationSize]byte
		errs []error
	)
	for _, g := range order {
		if err := u.s.userFloor.bury(u.scope, b.name, g); err != nil {
			errs = append(errs, err)
			continue
		}
		took = append(took, g)
	}
	switch {
	case len(errs) == 0:
		return nil
	case len(took) > 0:
		return fmt.Errorf("%w, but only in part: the user-scope floor took %d of the entry's %d tombstones and not the rest, %s, and its tree stays; run rm again to bury the rest: %w", errCommitted, len(took), len(order), b.landedWhat(took), errors.Join(errs...))
	}
	return fmt.Errorf("rm refused, nothing removed: the user-scope floor did not take its tombstone: %w", errors.Join(errs...))
}

// served is the generation a reader serves for the entry: the one its
// pointer authenticates under K_u, or, with none, the pointer header's; nil
// when neither was read.
func (b *userBurial) served() *[generationSize]byte {
	if b.authed != nil {
		return b.authed
	}
	return b.pointer
}

// ordered is gens with the generation a reader serves first (served), so
// the line a reader serves is the first a burial records.
func (b *userBurial) ordered() [][generationSize]byte {
	first := b.served()
	if first == nil || !slices.Contains(b.gens, *first) {
		return b.gens
	}
	out := [][generationSize]byte{*first}
	for _, g := range b.gens {
		if g != *first {
			out = append(out, g)
		}
	}
	return out
}

// landedWhat says what a partial burial whose tombstones for took landed
// revoked: the entry, refused as deleted, when the served generation's
// tombstone is among them, and otherwise only the generations it names.
func (b *userBurial) landedWhat(took [][generationSize]byte) string {
	if s := b.served(); s != nil && slices.Contains(took, *s) {
		return "so the entry is refused as deleted"
	}
	names := make([]string, len(took))
	for i, g := range took {
		names[i] = hex.EncodeToString(g[:])
	}
	return fmt.Sprintf("so only generation(s) %s are buried, not one a reader is known to serve", strings.Join(names, ", "))
}

// report is what rm reports after its commit: generations that disagree,
// since the tree was altered. An rm with no generation to bury never
// commits (errRmNoGeneration).
func (b *userBurial) report() error {
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
// returns the generation the scope.key record carries. err is a scope
// directory or scope.key that cannot be read; entErr, with entries nil, is
// an entries/ that cannot be opened once the scope.key has read.
func (u *UserScope) openEntriesForRevoke(root *os.Root) (entries *os.Root, gen [generationSize]byte, entErr, err error) {
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return nil, gen, nil, err
	}
	defer func() { _ = dir.Close() }() // nothing is written in the scope directory
	r, err := u.s.readScopeKeyRecord(dir)
	if err != nil {
		return nil, gen, nil, err
	}
	entries, err = u.s.openSubdir(dir, scopeEntriesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, r.generation, fmt.Errorf("%w: the scope has a scope key and no entries/ directory", ErrScopeAbsent), nil
	}
	if err != nil {
		return nil, r.generation, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err), nil
	}
	return entries, r.generation, nil, nil
}
