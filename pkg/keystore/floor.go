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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strconv"
	"syscall"
)

// This file is the pointer floor (docs/design/keystore.md § "Pointer sequence
// and floor"): per entry, the generation and the highest pointer sequence the
// store has committed, kept in keystore-floor.json under the data root. The
// data root is root:wheel 0755 and the file root:wheel 0644, so the service
// user can read the floor but cannot replace it, which is what lets the floor
// refuse a previously valid current pointer copied back over the live one.

const (
	// floorName is the floor file, directly under the data root.
	floorName = "keystore-floor.json"
	// floorFileMode is the floor file's mode: root writes it, everyone reads.
	floorFileMode fs.FileMode = 0o644
	// floorLockName is the floor's lock file, directly under the data root:
	// root:wheel 0600, so only root can open it, and so only root can hold
	// the lock every floor write takes.
	floorLockName = "keystore-lock"
	// floorLockMode is the floor lock file's mode.
	floorLockMode fs.FileMode = 0o600
	// floorFormat is the floor file's format version.
	floorFormat = 1
	// maxFloorSize bounds a floor read, and every floor write refuses a
	// result over it (errFloorFull), so a written floor always reads back. An
	// entry costs under 400 bytes (a 253-byte name, a 32-character generation
	// and a sequence), so this holds some ten thousand entries.
	maxFloorSize = 4 << 20
	// minFloorEntrySize is the fewest bytes an entry adds to the floor file:
	// a one-character name at sequence 1, and the comma before it.
	minFloorEntrySize = len(`,"a":{"generation":"`) + 2*generationSize + len(`","seq":1}`)
	// maxFloorEntries is the most entries a floor file under maxFloorSize can
	// hold. A keystore with more cannot have them all recorded.
	maxFloorEntries = maxFloorSize / minFloorEntrySize
	// maxTombstoneSize is the most of the floor file its tombstones may take:
	// the "tombstones" object, with the comma before it. Live entries may use
	// all of maxFloorSize, and tombstones only this much of what they leave;
	// every floor write prunes tombstones, oldest first, to fit both (prune).
	// A tombstone costs under 330 bytes, so this holds some 3,500 of the
	// longest names and some 16,000 short ones.
	maxTombstoneSize = 1 << 20
	// maxBuriedPerName is the most generations the floor keeps buried for
	// one name. A Delete that buries one more drops the name's oldest, and
	// that drop is a prune like any other (prune). It is a backstop, high
	// enough that the tombstone budget (maxTombstoneSize), which prunes
	// oldest first across every name, is the main eviction: churning one
	// name pushes out its own burials only after 64 deletions.
	//
	// This cap and maxTombstoneSize may only ever be raised, never lowered:
	// parseFloor refuses a floor over either, so a lower one would make a
	// floor an earlier release wrote refuse every root verb.
	maxBuriedPerName = 64
	// maxDeleteSeq is the highest delete sequence a floor may hold, 2^53 (an
	// integer every JSON reader keeps exact). A delete sequence only orders
	// burials, so bury renumbers them, order kept, before one would pass it:
	// the sequence never wraps.
	maxDeleteSeq uint64 = 1 << 53
)

// The floor's limits as the code reads them. Each is its production
// constant above, and nothing but a test changes one: a test lowers them
// (setFloorLimits, setSeam) so it can reach a limit without writing
// megabytes or planting a hundred thousand files, and restores them when it
// ends. A test that lowers one does not run in parallel.
var (
	// floorSizeLimit is maxFloorSize.
	floorSizeLimit = maxFloorSize
	// floorEntriesLimit is maxFloorEntries: floorSizeLimit over
	// minFloorEntrySize.
	floorEntriesLimit = maxFloorEntries
	// tombstoneSizeLimit is maxTombstoneSize.
	tombstoneSizeLimit = maxTombstoneSize
	// buriedPerNameLimit is maxBuriedPerName.
	buriedPerNameLimit = maxBuriedPerName
	// floorDirNamesBound bounds syncFloor's listing of keystore/. It is
	// maxDirNames.
	floorDirNamesBound = maxDirNames
)

var (
	// errFloorUntrusted refuses a floor, or a data root holding it, that the
	// service user could have written. It is about every entry, so it fails the
	// whole call.
	errFloorUntrusted = errors.New("the keystore floor is not trusted: keystore-floor.json must be a regular file, and it and the data root holding it must be owned by root and not group- or other-writable")
	// errFloorNotWritable refuses a verb that changes the keystore when this
	// process cannot write the floor, before it changes anything.
	errFloorNotWritable = errors.New("the keystore floor cannot be written by this process: a keys verb that changes the keystore runs as root")
	// errFloorMalformed refuses a floor file that does not parse, or that is
	// not the system scope's. It matches ErrCorrupt, with its own advice.
	errFloorMalformed error = &floorMalformedError{}
	// errFloorFull refuses a floor write whose result would be larger than
	// maxFloorSize, before anything is written, so the floor on disk stays
	// the last one that fit and still reads.
	errFloorFull = fmt.Errorf("the keystore floor is full: recording this change would make keystore-floor.json larger than %d bytes; delete entries that are no longer used to make room", maxFloorSize)
)

// floor is the recorded floor, by entry name: each name's live record, its
// buried generations, or both. A nil floor is an absent file: nothing is
// checked against it.
type floor map[string]floorEntry

// floorEntry is one name's record in the floor: a live record (Generation
// and Seq set) and up to maxBuriedPerName buried generations, each the
// generation of an entry of that name a Delete removed (docs/design/
// keystore.md § "Pointer sequence and floor", "A deleted entry put back is
// refused"). A record with no live record holds at least one burial, and a
// live generation is never also buried. Buried is never written in place:
// add, dropOldest and renumber each give the entry a new slice, so a copy of
// a floorEntry never sees another's burials change.
type floorEntry struct {
	// Generation is the live entry's generation, hex, or "" with no live
	// record.
	Generation string
	// Seq is the highest pointer sequence committed for the live entry, or 0
	// with no live record.
	Seq uint64
	// HighWater is 0, or a sequence above Seq: the highest pointer sequence
	// of this generation that a floor merge set aside, the moved-aside
	// floor's own record of it when a restore put back an older copy. A
	// pointer of the generation above Seq and at or below HighWater is a
	// copy of that abandoned history and is refused (check); a Rotate seals
	// its next sequence above HighWater, and the raise to it clears it.
	HighWater uint64
	// Buried holds the name's buried generations, oldest (lowest Deleted)
	// first: at most maxBuriedPerName of them, and nil for none.
	Buried []burial
}

// burial is one buried generation, as the floor file encodes it in the
// tombstones object. Deleted is its delete sequence, which orders burials
// for pruning: one more than the highest in the floor when it was buried.
type burial struct {
	Generation string `json:"generation"`
	Deleted    uint64 `json:"deleted"`
}

// live reports whether e holds a live record.
func (e floorEntry) live() bool { return e.Seq != 0 }

// burials is e's buried generations, oldest first.
func (e floorEntry) burials() []burial {
	return e.Buried[:len(e.Buried):len(e.Buried)]
}

// buries reports whether e records g, hex, as buried.
func (e floorEntry) buries(g string) bool {
	for _, b := range e.burials() {
		if b.Generation == g {
			return true
		}
	}
	return false
}

// add buries b after e's burials. When e already holds maxBuriedPerName, its
// oldest is dropped to make room, and returned.
func (e *floorEntry) add(b burial) (burial, bool) {
	bs := e.burials()
	if len(bs) < buriedPerNameLimit {
		e.Buried = append(slices.Clone(bs), b)
		return burial{}, false
	}
	dropped := bs[0]
	e.Buried = append(slices.Clone(bs[1:]), b)
	return dropped, true
}

// dropOldest removes e's oldest burial.
func (e *floorEntry) dropOldest() {
	if len(e.Buried) <= 1 {
		e.Buried = nil
		return
	}
	e.Buried = slices.Clone(e.Buried[1:])
}

// liveEntry is the encoding of a live record in the floor file.
type liveEntry struct {
	Generation string `json:"generation"`
	Seq        uint64 `json:"seq"`
	// HighWater is floorEntry.HighWater, left out when 0.
	HighWater uint64 `json:"highwater,omitempty"`
}

// floorFile is the floor's encoding. Scope names the scope whose entries it
// records, always scopeSystem: the floor is the system store's. Tombstones
// maps a name to its buried generations, oldest first, and is written only
// when the floor buries one, so a floor with none has no tombstones field.
type floorFile struct {
	Version    int                  `json:"version"`
	Scope      string               `json:"scope"`
	Entries    map[string]liveEntry `json:"entries"`
	Tombstones map[string][]burial  `json:"tombstones,omitempty"`
}

// pruned is one burial a floor write dropped: by prune, or by bury at the
// per-name cap.
type pruned struct {
	name, generation string
}

// logPruned logs, at Warn, the burials a floor write dropped: how many, and
// the names they were under. Each name's old copy put back is accepted again
// unless a live entry of another generation refuses it.
func logPruned(ps []pruned) {
	if len(ps) == 0 {
		return
	}
	var names []string
	for _, p := range ps {
		names = append(names, p.name)
	}
	sort.Strings(names)
	names = slices.Compact(names)
	slog.Warn("keystore floor: dropped the oldest deleted generations to stay within its bounds; an old copy of those deleted entries put back is no longer refused as deleted",
		"count", len(ps), "names", names)
}

// floorMalformedError is errFloorMalformed's type. It matches ErrCorrupt
// but carries its own text, because the fix is not a restore from backup.
type floorMalformedError struct{}

func (*floorMalformedError) Error() string {
	return "the keystore floor does not parse. Removing keystore-floor.json turns replay protection off until a root keys verb rebuilds it, and the rebuild records whatever pointers are under keystore/ as current, an older copy put back included. It also discards every deletion the floor recorded, so every deleted entry, a key revoked by deleting it included, is accepted again if a copy of it is put back: remove it as root only once those pointers are known to be current, then run any sudo k3sm keys verb to rebuild it"
}

func (*floorMalformedError) Unwrap() error { return ErrCorrupt }

// marshalFloor encodes fl as the floor file, newline-terminated.
func marshalFloor(fl floor) ([]byte, error) {
	f := floorFile{Version: floorFormat, Scope: scopeSystem, Entries: map[string]liveEntry{}}
	for name, e := range fl {
		if e.live() {
			f.Entries[name] = liveEntry{Generation: e.Generation, Seq: e.Seq, HighWater: e.HighWater}
		}
		if bs := e.burials(); len(bs) > 0 {
			if f.Tombstones == nil {
				f.Tombstones = map[string][]burial{}
			}
			f.Tombstones[name] = bs
		}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// deadSize is the length of fl's tombstones object, with the comma before
// it: nothing when fl buries nothing.
func (fl floor) deadSize() int {
	names, sum := 0, 0
	for name, e := range fl {
		if bs := e.burials(); len(bs) > 0 {
			names++
			sum += buriedSize(name, bs)
		}
	}
	return tombstonesSize(names, sum)
}

// liveSize is the length fl's encoding would have with no tombstones: what
// its live entries need, since every burial can be pruned to make room.
func (fl floor) liveSize() int {
	n := len(`{"version":`) + len(strconv.Itoa(floorFormat)) + len(`,"scope":"`) + len(scopeSystem) + len(`","entries":{}}`) + 1
	live := 0
	for name, e := range fl {
		if e.live() {
			n += floorEntrySize(name, e)
			live++
		}
	}
	if live > 0 {
		n += live - 1 // the commas between entries
	}
	return n
}

// liveCount is how many live records fl holds.
func (fl floor) liveCount() int {
	n := 0
	for _, e := range fl {
		if e.live() {
			n++
		}
	}
	return n
}

// burialSize is the length of one burial in the floor's encoding, without
// the comma that separates it from the one before.
func burialSize(b burial) int {
	return len(`{"generation":"","deleted":}`) + len(b.Generation) + len(strconv.FormatUint(b.Deleted, 10))
}

// buriedSize is the length of name's burials bs in the tombstones object,
// without the comma that separates the name from the one before.
func buriedSize(name string, bs []burial) int {
	n := len(`"":[]`) + len(name) + len(bs) - 1
	for _, b := range bs {
		n += burialSize(b)
	}
	return n
}

// tombstonesSize is the length of the tombstones object, with the comma
// before it, holding names names whose buriedSize sums to sum: nothing for
// none, since marshalFloor then leaves the field out.
func tombstonesSize(names, sum int) int {
	if names == 0 {
		return 0
	}
	return len(`,"tombstones":{}`) + sum + names - 1
}

// floorEntrySize is the length of name's live record e in the floor's
// encoding, without the comma that separates it from the one before.
func floorEntrySize(name string, e floorEntry) int {
	n := len(`"":{"generation":"`) + len(name) + len(e.Generation) + len(`","seq":}`) + len(strconv.FormatUint(e.Seq, 10))
	if e.HighWater != 0 {
		n += len(`,"highwater":`) + len(strconv.FormatUint(e.HighWater, 10))
	}
	return n
}

// grow is how many bytes recording the live record e for name would add to
// fl's live entries' encoding (liveSize). Burials count as nothing: prune
// makes room by them.
func (fl floor) grow(name string, e floorEntry) int {
	if old, ok := fl[name]; ok && old.live() {
		return floorEntrySize(name, e) - floorEntrySize(name, old)
	}
	if fl.liveCount() == 0 {
		return floorEntrySize(name, e)
	}
	return floorEntrySize(name, e) + 1
}

// room refuses, as errFloorFull, recording e for name when the floor's live
// entries would then be larger than maxFloorSize. Burials do not count: the
// write prunes them to make room, so a burial never refuses a Put or a
// Rotate. A verb asks it before it writes anything, so a full floor refuses
// the verb rather than a write after its entry files.
func (fl floor) room(name string, e floorEntry) error {
	if n := fl.liveSize() + fl.grow(name, e); n > floorSizeLimit {
		return fmt.Errorf("%w (%d bytes)", errFloorFull, n)
	}
	return nil
}

// prune drops burials, oldest first (the lowest Deleted, then by name),
// until the tombstones fit in maxTombstoneSize and the whole floor in
// maxFloorSize, and returns what it dropped. It never removes a live record,
// and a name left with neither is removed. A pruned burial loses its
// refusal: an old copy of that deleted entry put back under its name is
// accepted again, unless a live record of another generation refuses it.
func (fl floor) prune() []pruned {
	type at struct {
		name    string
		deleted uint64
	}
	var all []at
	names, sum := 0, 0
	for name, e := range fl {
		bs := e.burials()
		if len(bs) == 0 {
			continue
		}
		names++
		sum += buriedSize(name, bs)
		for _, b := range bs {
			all = append(all, at{name, b.Deleted})
		}
	}
	live := fl.liveSize()
	if t := tombstonesSize(names, sum); t <= tombstoneSizeLimit && live+t <= floorSizeLimit {
		return nil
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].deleted != all[j].deleted {
			return all[i].deleted < all[j].deleted
		}
		return all[i].name < all[j].name
	})
	var out []pruned
	for _, a := range all {
		if t := tombstonesSize(names, sum); t <= tombstoneSizeLimit && live+t <= floorSizeLimit {
			break
		}
		// A name's burials are oldest first, and so is this walk, so the
		// name's oldest is the one at hand.
		e := fl[a.name]
		bs := e.burials()
		oldest := bs[0]
		if len(bs) == 1 {
			sum -= len(`"":[]`) + len(a.name) + burialSize(oldest)
			names--
		} else {
			sum -= burialSize(oldest) + 1
		}
		e.dropOldest()
		if !e.live() && len(e.burials()) == 0 {
			delete(fl, a.name)
		} else {
			fl[a.name] = e
		}
		out = append(out, pruned{name: a.name, generation: oldest.Generation})
	}
	return out
}

// staleError refuses a current pointer the floor rules out. It matches
// ErrCorrupt but carries its own text, because ErrCorrupt's advice to restore
// from backup is the opposite of the fix: an older copy is what produced it.
//
// A completed Delete buries the deleted generation, so an older copy of the
// deleted entry put back is refused (deleted), after a new Put of the name
// too, until the burial is pruned; then a live entry of another generation
// still refuses it (generation) (docs/design/keystore.md § "Pointer
// sequence and floor").
type staleError struct {
	name       string
	seq, floor uint64
	generation bool
	deleted    bool
	// abandoned is set when seq is above the floor's and at or below its
	// high-water mark (highWater): a copy of the history a restore set
	// aside.
	abandoned bool
	highWater uint64
	// liveOther is set with deleted when the floor also records a live
	// entry of the name under another generation: that entry's directory
	// is missing, and rm would delete it.
	liveOther bool
}

func (e *staleError) Error() string {
	switch {
	case e.deleted && e.liveOther:
		// The safe action first: the live entry's directory put back is
		// accepted. rm is not safe here: it buries the live record.
		return fmt.Sprintf("keystore entry %q: the entry directory belongs to a generation of this entry that the floor records as deleted, and the floor records a live entry of this name under another generation, whose directory is missing; an older copy of a deleted entry was put back in its place. Put the live entry's directory back as keystore/%s in place of this one: that copy is accepted. Do not run k3sm keys rm system/%s: it would delete the live entry, and its key with it. Do not restore from backup", e.name, e.name, e.name)
	case e.deleted:
		// The safe default first: rm removes the copy and keeps the burial.
		// The restore with the floor saved beside the backup is only the
		// deliberate case, and it revives every deletion since. Never
		// removing the floor, which discards every burial.
		return fmt.Sprintf("keystore entry %q: the entry directory belongs to a generation of this entry that the floor records as deleted; an older copy of a deleted entry was put back. If you did not put this directory back, remove it with sudo k3sm keys rm system/%s --yes: the floor stays as it is and keeps the entry deleted. Do not restore from backup. Only to bring the deleted entry back on purpose, restore that backup together with the keystore-floor.json saved with it, as \"Backing Up and Restoring\" in docs/user/keys.md describes; that brings back every key deleted since the backup, not only this one", e.name, e.name)
	case e.abandoned:
		return fmt.Sprintf("keystore entry %q: the current pointer (sequence %d) belongs to the history of this entry that a restore set aside: the floor merge recorded sequences above %d and up to %d as replaced by the restored copy, so this is a copy of the entry from before the restore. Put the restored copy of keystore/%s back if you still have it: that copy is accepted. Do not restore from backup", e.name, e.seq, e.floor, e.highWater, e.name)
	case e.generation:
		return fmt.Sprintf("keystore entry %q: the current pointer belongs to another generation of this entry than the recorded floor; an older copy of a deleted entry was put back after a newer put of the name, or a delete and the put after it were both interrupted. Put the directory of the generation the floor records back as keystore/%s if you still have it: that copy is accepted. Do not restore from backup. If the older copy was deliberate, follow \"Restoring an older keystore/\" in docs/user/backup-restore.md", e.name, e.name)
	}
	return fmt.Sprintf("keystore entry %q: the current pointer (sequence %d) is older than the recorded floor (sequence %d); an older copy of this entry was put back. Put the newer copy of keystore/%s back if you still have it: that copy is accepted. Do not restore from backup. If the older copy was deliberate, follow \"Restoring an older keystore/\" in docs/user/backup-restore.md", e.name, e.seq, e.floor, e.name)
}

func (e *staleError) Unwrap() error { return ErrCorrupt }

// check refuses a pointer of name at generation gen and sequence seq when
// the floor buries gen for name, or records a live entry for name of another
// generation or at a higher sequence. It also refuses seq above the live
// record's sequence and at or below its high-water mark: a copy of the
// history a floor merge set aside.
func (fl floor) check(name string, gen [generationSize]byte, seq uint64) error {
	if err := fl.buried(name, gen); err != nil {
		return err
	}
	f, ok := fl[name]
	if !ok || !f.live() {
		return nil
	}
	if f.Generation != hex.EncodeToString(gen[:]) {
		return &staleError{name: name, seq: seq, floor: f.Seq, generation: true}
	}
	if seq < f.Seq {
		return &staleError{name: name, seq: seq, floor: f.Seq}
	}
	if seq > f.Seq && seq <= f.HighWater {
		return &staleError{name: name, seq: seq, floor: f.Seq, abandoned: true, highWater: f.HighWater}
	}
	return nil
}

// buried refuses (a staleError, matching ErrCorrupt) an entry directory of
// name at generation gen when the floor buries gen for name: an older copy
// of a deleted entry put back.
func (fl floor) buried(name string, gen [generationSize]byte) error {
	if f := fl[name]; f.buries(hex.EncodeToString(gen[:])) {
		// A live generation is never also buried, so a live record is of
		// another generation.
		return &staleError{name: name, deleted: true, liveOther: f.live()}
	}
	return nil
}

// raise is Raise applied to fl: it records seq for name at generation gen
// when the floor has no live record for name (none at all, or only burials:
// a Put that crashed before its floor write), or a lower sequence of the
// same generation (the maximum of the two), and reports whether it changed
// anything. A live record of another generation is left alone: readers
// refuse that pointer, and only a Put, which mints a new generation,
// replaces it (set). A buried gen is never raised: that is a deleted entry,
// and neither is a seq at or below the live record's high-water mark: that
// is a copy of the history a floor merge set aside, which check refuses. A
// raise above the mark clears it. The name's burials are kept.
func (fl floor) raise(name string, gen [generationSize]byte, seq uint64) bool {
	g := hex.EncodeToString(gen[:])
	f := fl[name]
	if f.buries(g) || (f.live() && (f.Generation != g || f.Seq >= seq || seq <= f.HighWater)) {
		return false
	}
	f.Generation, f.Seq, f.HighWater = g, seq, 0
	fl[name] = f
	return true
}

// set is Put applied to fl: it records sequence 1 for name at generation
// gen and reports whether it changed anything. A live record of another
// generation, which only a Delete interrupted before its floor write leaves
// (or an entry directory moved away while the Put ran), is buried first, as
// that Delete would have (bury), so its copy stays refused after the new
// generation is deleted too; set returns the generation it buried ("" for
// none) and what that dropped. The name's burials are kept: a Put never
// lowers what the floor refuses. The live record of the same generation is
// left alone: it can only be higher, raised since. A buried gen is never
// recorded live; a Put mints a fresh generation, so it never asks.
func (fl floor) set(name string, gen [generationSize]byte) (bool, string, []pruned) {
	g := hex.EncodeToString(gen[:])
	f := fl[name]
	if f.buries(g) || (f.live() && f.Generation == g) {
		return false, "", nil
	}
	var buried string
	var dropped []pruned
	if f.live() {
		var gs []string
		gs, dropped = fl.bury(name, nil)
		if len(gs) > 0 {
			buried = gs[0]
		}
		f = fl[name]
	}
	f.Generation, f.Seq, f.HighWater = g, 1, 0
	fl[name] = f
	return true, buried, dropped
}

// bury is Delete applied to fl. It buries the generation the floor records
// live for name, root's own record, whatever the deleted directory claimed,
// and dirGen, the deleted directory's generation, when it is another one.
// The caller passes dirGen only when the directory's pointer authenticated
// under it with the master (a Put that crashed after its pointer, before
// its floor write, or a directory of another generation than the floor's
// live record), and nil otherwise: a generation file alone is the service
// user's to write, so a planted one never buries anything and never pushes a
// real burial out. A generation already buried is not buried again. bury
// never removes or replaces a burial except that, at maxBuriedPerName, the
// name's oldest is dropped to make room. It returns the generations it
// buried, the live one first (none for no change), and what it dropped.
// Each new burial's delete sequence is one more than the highest in the
// floor (renumber keeps that under maxDeleteSeq).
func (fl floor) bury(name string, dirGen *[generationSize]byte) ([]string, []pruned) {
	f := fl[name]
	var gs []string
	if f.live() && !f.buries(f.Generation) {
		// A live generation that is also buried is not reachable from a
		// floor parseFloor accepts.
		gs = append(gs, f.Generation)
	}
	if dirGen != nil {
		if g := hex.EncodeToString(dirGen[:]); g != f.Generation && !f.buries(g) {
			gs = append(gs, g)
		}
	}
	if len(gs) == 0 {
		return nil, nil
	}
	var out []pruned
	for _, g := range gs {
		last := fl.lastDeleted()
		if last >= maxDeleteSeq {
			last = fl.renumber()
		}
		// Read after renumber, which rewrites the name's own burials in fl.
		f = fl[name]
		f.Generation, f.Seq, f.HighWater = "", 0, 0
		if dropped, ok := f.add(burial{Generation: g, Deleted: last + 1}); ok {
			out = append(out, pruned{name: name, generation: dropped.Generation})
		}
		fl[name] = f
	}
	return gs, out
}

// lastDeleted is the highest delete sequence in fl, or 0 for none.
func (fl floor) lastDeleted() uint64 {
	var last uint64
	for _, e := range fl {
		if bs := e.burials(); len(bs) > 0 {
			last = max(last, bs[len(bs)-1].Deleted)
		}
	}
	return last
}

// renumber gives fl's burials the delete sequences 1 to n in their order
// (by Deleted, then by name) and returns n. Only the order of delete
// sequences means anything, so this changes no refusal and no prune order.
func (fl floor) renumber() uint64 {
	type at struct {
		name    string
		i       int
		deleted uint64
	}
	var all []at
	for name, e := range fl {
		for i, b := range e.burials() {
			all = append(all, at{name, i, b.Deleted})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].deleted != all[j].deleted {
			return all[i].deleted < all[j].deleted
		}
		return all[i].name < all[j].name
	})
	// Each name gets a new slice before its first rewrite, so no copy of
	// its entry sees the new sequences.
	fresh := map[string]bool{}
	for n, a := range all {
		e := fl[a.name]
		if !fresh[a.name] {
			e.Buried = slices.Clone(e.Buried)
			fresh[a.name] = true
		}
		e.Buried[a.i].Deleted = uint64(n + 1)
		fl[a.name] = e
	}
	return uint64(len(all))
}

// openFloor opens the data root and reads the floor in it, both judged on
// the opened descriptor: owned by root (floorUID) and not group- or
// other-writable, and the file regular and not a symlink. An absent file is a
// nil floor; an absent data root is an error, since every install has one.
// The caller closes the returned root.
func (s *FileStore) openFloor() (*os.Root, floor, error) {
	if s.dataRoot == "" {
		return nil, nil, errors.New("the keystore floor needs the data root, and none is configured")
	}
	named, err := os.Lstat(s.dataRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	if !named.IsDir() {
		return nil, nil, fmt.Errorf("%w: %s is not a directory (mode %s)", errFloorUntrusted, s.dataRoot, named.Mode())
	}
	dir, err := os.OpenRoot(s.dataRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	fl, err := s.readFloor(dir, named)
	if err != nil {
		_ = dir.Close() // abandoned; nothing was written
		return nil, nil, err
	}
	return dir, fl, nil
}

// readFloor checks dir (which Lstat saw as named) and reads the floor in it.
func (s *FileStore) readFloor(dir *os.Root, named fs.FileInfo) (floor, error) {
	opened, err := dir.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("the keystore floor: %w", err)
	}
	if !os.SameFile(named, opened) {
		return nil, fmt.Errorf("%w: %s changed while it was opened", errFloorUntrusted, s.dataRoot)
	}
	if err := s.floorOwned(opened); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, s.dataRoot, err)
	}
	b, fi, err := readFile(dir, floorName, int64(floorSizeLimit))
	if errors.Is(err, fs.ErrNotExist) {
		// An absent floor switches the check off, so absent must mean no
		// name at all: a dangling symlink also fails the open as not found.
		if _, lerr := dir.Lstat(floorName); !errors.Is(lerr, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s is present but cannot be opened: %v", errFloorUntrusted, floorName, err)
		}
		return nil, nil
	}
	if errors.Is(err, errBadFile) {
		return nil, fmt.Errorf("%w: %w", errFloorUntrusted, err)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", floorName, err)
	}
	if err := s.floorOwned(fi); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorName, err)
	}
	return parseFloor(b)
}

// floorOwned refuses fi unless root (floorUID) owns it and its mode grants
// no write to group or others.
func (s *FileStore) floorOwned(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return errors.New("owner unknown")
	}
	if int64(st.Uid) != int64(s.floorUID) {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, s.floorUID)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("mode %04o is group- or other-writable", perm)
	}
	return nil
}

// parseFloor decodes a floor file, refusing anything a root verb would not
// have written. encoding/json matches a field name in any case and keeps the
// last of a duplicate key, so what it decodes is encoded again and must be
// the bytes it read, with or without marshalFloor's trailing newline: one
// encoding per floor, and no file with two answers for one field. A name's
// burials must be oldest first with distinct delete sequences across the
// floor, at most maxBuriedPerName of them, none of the live generation, none
// above maxDeleteSeq, and all of them within maxTombstoneSize. A live
// record's highwater, written only when set, must be above its seq.
func parseFloor(b []byte) (floor, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f floorFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %w", errFloorMalformed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: data after the floor object", errFloorMalformed)
	}
	if f.Version != floorFormat {
		return nil, fmt.Errorf("%w: format version %d, want %d", errFloorMalformed, f.Version, floorFormat)
	}
	if f.Scope != scopeSystem {
		return nil, fmt.Errorf("%w: scope %q, want %q", errFloorMalformed, f.Scope, scopeSystem)
	}
	fl := floor{}
	for name, e := range f.Entries {
		if !floorGeneration(name, e.Generation) || e.Seq == 0 || (e.HighWater != 0 && e.HighWater <= e.Seq) {
			return nil, fmt.Errorf("%w: entry %q", errFloorMalformed, name)
		}
		fl[name] = floorEntry{Generation: e.Generation, Seq: e.Seq, HighWater: e.HighWater}
	}
	seen := map[uint64]bool{}
	for name, bs := range f.Tombstones {
		if len(bs) == 0 || len(bs) > buriedPerNameLimit {
			return nil, fmt.Errorf("%w: tombstone %q holds %d generations, want 1 to %d", errFloorMalformed, name, len(bs), buriedPerNameLimit)
		}
		e := fl[name]
		e.Buried = make([]burial, 0, len(bs))
		var prev uint64
		for _, t := range bs {
			if !floorGeneration(name, t.Generation) || t.Deleted <= prev || t.Deleted > maxDeleteSeq || seen[t.Deleted] ||
				e.buries(t.Generation) || (e.live() && e.Generation == t.Generation) {
				return nil, fmt.Errorf("%w: tombstone %q", errFloorMalformed, name)
			}
			seen[t.Deleted], prev = true, t.Deleted
			e.Buried = append(e.Buried, t)
		}
		fl[name] = e
	}
	if n := fl.deadSize(); n > tombstoneSizeLimit {
		return nil, fmt.Errorf("%w: tombstones take %d bytes, over %d", errFloorMalformed, n, tombstoneSizeLimit)
	}
	canon, err := marshalFloor(fl)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFloorMalformed, err)
	}
	if !bytes.Equal(b, canon) && !bytes.Equal(b, canon[:len(canon)-1]) {
		return nil, fmt.Errorf("%w: not in the form a keys verb writes (a duplicate or differently cased key, reordered fields or extra whitespace)", errFloorMalformed)
	}
	return fl, nil
}

// floorGeneration reports whether name is a name put accepts and gen the
// canonical hex of a generation.
func floorGeneration(name, gen string) bool {
	g, err := hex.DecodeString(gen)
	return checkName(name) == nil && err == nil && len(g) == generationSize && hex.EncodeToString(g) == gen
}

// floorLock is the floor held under its lock, which every floor write
// takes: lock is keystore-lock in the data root, opened O_RDONLY|O_NOFOLLOW|
// O_NONBLOCK, judged on that descriptor, flocked, and checked again after the
// flock to be the file at that name; locked the data root's
// info, judged on its own descriptor; and root the os.Root the floor is read
// and written through, checked to be the same directory.
//
// Lock order: a verb that writes the floor (Put, Rotate, Delete, RaiseFloor,
// Rewrap) takes keystore-lock first and the store's .lock (openLocked)
// second, each with the bounded wait lockWait, and releases them in reverse;
// readers take only .lock, and no verb takes .lock before keystore-lock, so
// two verbs never wait on each other's lock. keystore-lock comes first
// because only root can hold it: Delete buries under it before it touches
// .lock, which the service user owns and can hold or replace. keystore-lock
// also defends the floor against a writer under a swapped .lock, which .lock
// does not serialize with.
//
// keystore-lock is root:wheel 0600 and refused unless it is a regular file
// owned by root (floorUID) that grants no group or other access, so only
// root can open it and only root can hold the lock. The data root itself is
// root:wheel 0755, and a flock any local process takes on it blocks nothing:
// the lock is not taken there.
type floorLock struct {
	s      *FileStore
	lock   *os.File
	locked fs.FileInfo
	root   *os.Root
	// dropped is every burial a prune dropped in a write made under this
	// lock, so a verb checks them all, not only its own (evicted).
	dropped []pruned
}

// openDataRoot opens the data root without following a symlink and judges
// it on that descriptor: owned by root (floorUID), not group- or
// other-writable, and writable by this process, which a verb that changes
// the keystore must be before it changes anything (errFloorNotWritable).
func (s *FileStore) openDataRoot() (*os.File, fs.FileInfo, error) {
	if s.dataRoot == "" {
		return nil, nil, errors.New("the keystore floor needs the data root, and none is configured")
	}
	dir, err := os.OpenFile(s.dataRoot, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return nil, nil, fmt.Errorf("%w: %s is not a directory: %w", errFloorUntrusted, s.dataRoot, err)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	fi, err := dir.Stat()
	if err == nil {
		if oerr := s.floorOwned(fi); oerr != nil {
			err = fmt.Errorf("%w: %s: %w", errFloorUntrusted, s.dataRoot, oerr)
		}
	}
	if err == nil {
		err = s.floorWritable(fi)
	}
	if err != nil {
		_ = dir.Close() // abandoned; nothing was written
		return nil, nil, err
	}
	return dir, fi, nil
}

// floorWritable refuses fi, the data root, unless this process can create
// and rename files in it: as root, or as its owner with the owner's write
// bit. floorOwned already refuses group and other write, so no one else can.
// It asks the process's own euid, not the euid seam, which stands for the
// creator of the store's directories.
func (s *FileStore) floorWritable(fi fs.FileInfo) error {
	euid := os.Geteuid()
	if euid == 0 {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil || int64(st.Uid) != int64(euid) || fi.Mode().Perm()&0o200 == 0 {
		return fmt.Errorf("%w: %s is mode %04o, and this process is uid %d", errFloorNotWritable, s.dataRoot, fi.Mode().Perm(), euid)
	}
	return nil
}

// checkFloorWritable is openDataRoot's checks alone, which every verb that
// changes the keystore makes first, before it takes .lock (which creates the
// entries' directory on a first Put).
func (s *FileStore) checkFloorWritable() error {
	dir, _, err := s.openDataRoot()
	if err != nil {
		return err
	}
	return dir.Close()
}

// lockFloor takes the floor lock, keystore-lock, waiting at most lockWait
// or until ctx is done, and reads the floor under it. The data root is
// opened and judged by openDataRoot, and the lock file by openFloorLock
// through that same directory. The caller takes .lock after it, never
// before (the lock order above), and releases the returned lock with unlock.
func (s *FileStore) lockFloor(ctx context.Context) (*floorLock, floor, error) {
	f, fi, lockRoot, err := s.openFloorLock()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = lockRoot.Close() }() // only Lstats through it
	l := &floorLock{s: s, lock: f, locked: fi}
	if err := s.flockWait(ctx, f, syscall.LOCK_EX); err != nil {
		l.unlock()
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	s.dataRootLocked()
	if err := recheckFloorLock(lockRoot, f); err != nil {
		l.unlock()
		return nil, nil, err
	}
	if l.root, err = os.OpenRoot(s.dataRoot); err != nil {
		l.unlock()
		return nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	fl, err := l.read()
	if err != nil {
		l.unlock()
		return nil, nil, err
	}
	return l, fl, nil
}

// recheckFloorLock refuses (errFloorUntrusted) the flocked keystore-lock f
// unless the name, Lstat'd again through root, the data root f was opened in,
// is still the file f holds: a name replaced after the open would let two
// writers lock different files. The link count is not judged: macOS lets any
// local user hard-link a file it cannot read (it has no protected_hardlinks),
// so refusing a second link would let anyone block every floor verb, and a
// link elsewhere is the same inode, which changes nothing about the lock.
func recheckFloorLock(root *os.Root, f *os.File) error {
	held, err := f.Stat()
	if err != nil {
		return fmt.Errorf("the keystore floor: %w", err)
	}
	named, err := root.Lstat(floorLockName)
	if err != nil {
		return fmt.Errorf("%w: %s was replaced while it was locked: %w", errFloorUntrusted, floorLockName, err)
	}
	if !os.SameFile(held, named) {
		return fmt.Errorf("%w: %s was replaced while it was locked", errFloorUntrusted, floorLockName)
	}
	return nil
}

// openFloorLock opens keystore-lock in the data root, creating it root:wheel
// 0600 if it is absent, and returns it with the data root's info and the
// os.Root it was opened through, which the caller closes. The data
// root is judged by openDataRoot and opened as an os.Root that must be the
// directory judged. The file is created O_CREAT|O_EXCL|O_NOFOLLOW (exclusive
// for the reason lock gives for .lock, and owned only if this call made it),
// then opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK (flock needs no write access,
// as for .lock) and refused (errFloorUntrusted)
// unless, on that descriptor, it is a regular file owned by root (floorUID)
// with no group or other access.
func (s *FileStore) openFloorLock() (*os.File, fs.FileInfo, *os.Root, error) {
	dir, fi, err := s.openDataRoot()
	if err != nil {
		return nil, nil, nil, err
	}
	_ = dir.Close() // judged; read-only
	root, err := os.OpenRoot(s.dataRoot)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("the keystore floor: %w", err)
	}
	f, err := s.openFloorLockIn(root, fi)
	if err != nil {
		_ = root.Close() // only opened through
		return nil, nil, nil, err
	}
	return f, fi, root, nil
}

// openFloorLockIn is openFloorLock's work inside root, the data root opened,
// which must be the directory fi describes.
func (s *FileStore) openFloorLockIn(root *os.Root, fi fs.FileInfo) (*os.File, error) {
	opened, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("the keystore floor: %w", err)
	}
	if !os.SameFile(fi, opened) {
		return nil, fmt.Errorf("%w: %s changed while it was opened", errFloorUntrusted, s.dataRoot)
	}
	if c, err := root.OpenFile(floorLockName, os.O_RDONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, floorLockMode); err == nil {
		err = s.ownAs(c, uint32(s.floorUID), uint32(s.floorGID), floorLockMode)
		if cerr := c.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", floorLockName, err)
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create %s: %w", floorLockName, err)
	}
	f, lfi, err := openRegular(root, floorLockName, os.O_RDONLY, 0)
	if errors.Is(err, errBadFile) || errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.ELOOP) || errors.Is(err, fs.ErrNotExist) {
		// Not found after the create is a dangling symlink, which the
		// exclusive create refuses as present.
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorLockName, err)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", floorLockName, err)
	}
	if err := s.floorLockOwned(lfi); err != nil {
		_ = f.Close() // refused; nothing written
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorLockName, err)
	}
	return f, nil
}

// floorLockOwned refuses fi, keystore-lock, unless floorOwned accepts it
// (owned by root, not group- or other-writable) and it grants no group or
// other access at all: one who could open it could hold the lock.
func (s *FileStore) floorLockOwned(fi fs.FileInfo) error {
	if err := s.floorOwned(fi); err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode %04o is group- or other-accessible", perm)
	}
	return nil
}

// mergePending refuses (errMergePending) while the restore's moved-aside
// floor, keystore-floor.json.pre-restore, is in the data root, looked up
// through l.root under the lock. Every verb that changes the keystore asks
// it before it writes anything; MergeFloor, which clears it, does not, and
// RaiseFloor writes nothing instead. Any answer but not found refuses too.
func (l *floorLock) mergePending() error {
	_, err := l.root.Lstat(floorPreRestoreName)
	switch {
	case err == nil:
		return errMergePending
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return fmt.Errorf("%w (looking for it: %w)", errMergePending, err)
}

// read reads the floor through l.root, refused unless l.root is still the
// directory the lock is held on.
func (l *floorLock) read() (floor, error) {
	return l.s.readFloor(l.root, l.locked)
}

// update re-reads the floor under the lock, applies op to what it read, and
// writes the result if op reports a change, returning the floor as it now
// is. A change is pruned (prune) before it is written, so tombstones never
// take a live entry's room, and what the prune dropped is logged once the
// write is done (logPruned). The lock is held through the rename and the directory fsync. op sees
// a non-nil floor; an absent file it leaves unchanged stays absent.
func (l *floorLock) update(op func(floor) bool) (floor, error) {
	fl, _, err := l.updatePruned(op)
	return fl, err
}

// updatePruned is update, also returning what the prune dropped.
func (l *floorLock) updatePruned(op func(floor) bool) (floor, []pruned, error) {
	fl, err := l.read()
	if err != nil {
		return nil, nil, err
	}
	absent := fl == nil
	if absent {
		fl = floor{}
	}
	if !op(fl) {
		if absent {
			return nil, nil, nil
		}
		return fl, nil, nil
	}
	dropped := fl.prune()
	b, err := marshalFloor(fl)
	if err != nil {
		return nil, nil, err
	}
	if len(b) > floorSizeLimit {
		return nil, nil, fmt.Errorf("%w (%d bytes)", errFloorFull, len(b))
	}
	if err := l.s.writeFileAs(l.root, floorName, b, uint32(l.s.floorUID), uint32(l.s.floorGID), floorFileMode); err != nil {
		return nil, nil, err
	}
	logPruned(dropped)
	l.dropped = append(l.dropped, dropped...)
	return fl, dropped, nil
}

// unlock releases the floor lock and closes what lockFloor opened.
func (l *floorLock) unlock() {
	if l.root != nil {
		_ = l.root.Close() // writes are fsynced by update
	}
	_ = syscall.Flock(int(l.lock.Fd()), syscall.LOCK_UN) // the close below releases it regardless
	_ = l.lock.Close()
}

// loopEvery is how many iterations a loop over a directory's names (up to
// maxDirNames of them) runs between checks of its context.
const loopEvery = 64

// loopCtx is ctx's error at every loopEvery-th iteration i, the first
// included, so a loop that opens or removes a file per name stops soon after
// its context is done.
func loopCtx(ctx context.Context, i int) error {
	if i%loopEvery != 0 {
		return nil
	}
	return ctx.Err()
}

// syncFloor is how Put, Rotate and RaiseFloor begin, and Delete when the
// master opens (with none, Delete raises nothing): it raises each entry's floor
// to the sequence of its authenticated current pointer and writes the floor
// file if that changed anything. That closes the window a crash between a
// pointer flip and its floor write leaves (the floor one behind), and it is
// also how an absent floor file is rebuilt. An entry whose pointer does not
// open, or that the floor already rules out, is left as it is: the verb that
// reads it reports it. The caller holds the exclusive lock and l.
//
// It stops with ctx's error, writing nothing, when ctx is done (see loopCtx).
//
// The floor never grows past maxFloorSize: a keystore with more entries than
// a floor can hold is refused (errFloorFull) before any is raised, and a raise
// that would take the floor over the size is left out, so that entry's floor
// stays where it was, behind its pointer, which readers accept.
func (s *FileStore) syncFloor(ctx context.Context, entries *os.Root, l *floorLock, fl floor, k keys) (floor, error) {
	names, err := readDirNames(entries, floorDirNamesBound)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	type raised struct {
		name string
		gen  [generationSize]byte
		seq  uint64
	}
	var found []raised
	for i, name := range names {
		if err := loopCtx(ctx, i); err != nil {
			return nil, err
		}
		if checkName(name) != nil {
			continue
		}
		e, err := openEntry(entries, name, fl)
		if err != nil {
			continue
		}
		_, seq, err := e.pointer(k)
		e.close()
		if err == nil {
			found = append(found, raised{name, e.generation, seq})
		}
	}
	if len(found) > floorEntriesLimit {
		return nil, fmt.Errorf("%w: the keystore holds %d entries, and the floor can hold at most %d", errFloorFull, len(found), floorEntriesLimit)
	}
	return l.update(func(fl floor) bool {
		changed := false
		// Sized by the live entries alone: update prunes tombstones to fit.
		size, live := fl.liveSize(), fl.liveCount()
		for _, r := range found {
			old, had := fl[r.name]
			if !fl.raise(r.name, r.gen, r.seq) {
				continue
			}
			raised := fl[r.name]
			if had {
				fl[r.name] = old
			} else {
				delete(fl, r.name)
			}
			replaces := had && old.live()
			grow := floorEntrySize(r.name, raised)
			switch {
			case replaces:
				grow -= floorEntrySize(r.name, old)
			case live > 0:
				grow++ // the comma before it
			}
			if size+grow > floorSizeLimit {
				continue // left where it was: see above
			}
			fl[r.name] = raised
			size += grow
			if !replaces {
				live++
			}
			changed = true
		}
		return changed
	})
}
