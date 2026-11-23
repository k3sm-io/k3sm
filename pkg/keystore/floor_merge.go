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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// floorPreRestoreName is the live floor as the restore recipe moves it
// aside, directly under the data root. While it is there the restore is
// unfinished: the merge has not run.
const floorPreRestoreName = floorName + ".pre-restore"

// errMergePending refuses a verb that changes the keystore while the
// restore's moved-aside floor is in the data root: the merge has not run, so
// the restored floor still lacks every deletion since the backup.
var errMergePending = errors.New("a restore is unfinished: keystore-floor.json.pre-restore, the floor moved aside before it, is still in the data root, and the deletions it records are not merged yet. Run sudo k3sm keys floor merge on it first, as docs/user/keys.md describes (it renames the file when it is done); this verb changes nothing until then")

// MergePending returns errMergePending while the restore's moved-aside
// floor, keystore-floor.json.pre-restore, is in the data root: the merge has
// not run, so the restored floor lacks every deletion since the backup, and
// a reader that publishes a value (the delivery reconciler) must not. Any
// answer but not found counts as pending. It takes no lock and writes
// nothing; with no data root configured there is no floor, and it is nil.
func (s *FileStore) MergePending() error {
	if s.dataRoot == "" {
		return nil
	}
	_, err := os.Lstat(filepath.Join(s.dataRoot, floorPreRestoreName))
	switch {
	case err == nil:
		return errMergePending
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return fmt.Errorf("%w (looking for it: %w)", errMergePending, err)
}

// MergeReport is what MergeFloor did with the moved-aside floor's burials.
type MergeReport struct {
	// Merged is how many burials the live floor gained from the moved-aside
	// floor's, BuriedLive's included.
	Merged int
	// AlreadyPresent is how many the live floor already buried.
	AlreadyPresent int
	// BuriedLive names, sorted, each entry whose generation the moved-aside
	// floor buries and the live floor held live: the merge buried it, so a
	// key revoked by deleting it since the backup stays refused.
	BuriedLive []string
	// Kept names, sorted, each entry the keep set named that the merge
	// would otherwise have buried a generation of: its restored live
	// generation, or the moved-aside floor's live one when the restored
	// floor holds no live record of the name. A restored live record is
	// left as restored, the entry restored on purpose, and keeps only its
	// own generation: the moved-aside one is retired regardless. A name
	// the restored floor does not record gets the moved-aside live record,
	// at its sequence, fenced one past it (fenceMark).
	Kept []string
	// Recorded names, sorted, each of Kept the restored floor held no live
	// record of, whose moved-aside live generation the merge recorded: an
	// entry the backup does not hold, not a revoked one brought back.
	Recorded []string
	// Retired names, sorted, each entry whose moved-aside live generation
	// the merge buried: each one the restored floor does not hold live,
	// under another generation or not at all. Choosing the backup retired
	// it, so its directory put back is refused.
	Retired []string
	// Fenced names, sorted, each entry whose generation the restored floor
	// holds live at a lower sequence than the moved-aside floor did: the
	// merge set the live record's high-water mark to the moved-aside
	// sequence, so a copy of the abandoned history, which would otherwise
	// outrank the restored entry, is refused until a Rotate seals above it.
	Fenced []string
	// Unverified names, sorted, each entry the restored floor holds live
	// under the moved-aside floor's live generation whose restored pointer
	// did not authenticate under the master, or authenticated more than one
	// sequence above the restored record: its sequence is left as the
	// restored floor records it, so a restored pointer above that record is
	// inside the fence.
	Unverified []string
	// Dropped names, sorted and with repeats, each burial the write dropped
	// to stay within the floor's caps (the per-name cap and the tombstone
	// budget): a copy of it put back is accepted again. Each is one the live
	// floor held before the merge: a merge that would drop one it adds is
	// refused.
	Dropped []string
	// RetiredByRestore and DeletedSinceRestore split BuriedLive in an undo
	// (MergeOptions.Undo), by the retired record the restore's merge left:
	// the names it retired, which --keep brings back, and the others,
	// deleted since the restore, which stay deleted. Both are nil in a
	// merge that is no undo.
	RetiredByRestore    []string
	DeletedSinceRestore []string
	// MovedAside is the name in pre-restore.d (planted-<unix>) the merge
	// renamed what it found at the store's Dir to, with the restored tree
	// staged: the recipe leaves Dir absent, so whatever is there was
	// planted. In a dry run it is the name the merge would use, and nothing
	// is moved. MovedAsideType is that object's file type ("directory",
	// "symlink", ...). Both are empty when Dir was absent.
	MovedAside     string
	MovedAsideType string
	// AlreadyMerged is set when the live floor already held every burial
	// and fence the input records: the merge wrote nothing and only renamed
	// the input, as a rerun after a failed rename does.
	AlreadyMerged bool
	// AsideUnverified names, sorted, each entry the moved-aside floor holds
	// live whose pointer in the moved-aside tree (pre-restore.d/keystore)
	// did not authenticate under the master, or with the tree staged and
	// no master to load: its fence is one past the moved-aside floor's
	// record and mark, not past a pointer above them.
	AsideUnverified []string
	// raised is how many restored live records the merge raised to their
	// authenticated restored pointer before fencing.
	raised int
	// recorded is how many kept names the restored floor did not record
	// the merge wrote a live record of the moved-aside generation for.
	recorded int
	// overRaise names, sorted, each entry whose authenticated restored
	// pointer was more than one sequence above the restored record, so the
	// merge did not raise to it (also in Unverified).
	overRaise []string
	// renumbered is set when the merge renumbered guard-era burials back
	// below guardEraSeq, which is a change to write.
	renumbered bool
}

// MergeOptions is what a floor merge is asked to do beyond the merge itself.
type MergeOptions struct {
	// Keep holds entry names, each checked as a name is, whose restored
	// generation the merge keeps live (Kept).
	Keep []string
	// AcceptDrops lets a merge whose write would drop a deletion since the
	// backup (one it carries over, or one rm wrote under the guard) go on:
	// the write prunes oldest first as every floor write does, and each
	// burial dropped is reported (Dropped).
	AcceptDrops bool
	// DryRun makes the merge on a copy only and returns its report: what
	// it would merge, keep, retire, fence and drop. It writes nothing and
	// renames nothing, and a merge that would be refused is refused with
	// that report.
	DryRun bool
	// Undo marks the reverse merge of an undo: it reads the newest retired
	// record the restore's merge left (readRetired), refusing when there is
	// none, reports the buried-live names it retired apart from those
	// deleted since (classifyUndo), and refuses a keep of one deleted since.
	Undo bool
}

// MergeFloor merges every burial the data root's
// keystore-floor.json.pre-restore records (the live floor the restore recipe
// moved aside) into the live floor, which a restore has just replaced with
// the one saved beside the backup, so the deletions recorded after the
// backup survive the restore (docs/design/keystore.md § "Pointer sequence
// and floor", "Restoring with the saved floor"). It takes no path: the
// guard file is the only input, read under keystore-lock through the data
// root the lock judged, as the floor is (a regular file, never followed,
// owned by root and not group- or other-writable, under maxFloorSize), and
// parsed by parseFloor. The name must still be that file when the merge
// writes and when it renames it, so a guard file replaced during the merge
// refuses it. It refuses, writing nothing, a merge onto an absent live floor
// and one from a file equal to the live floor (checkMergeInput).
// Under keystore-lock alone (§ Concurrency; it writes nothing
// under keystore/, so it never takes keystore/.lock) it adds each burial the live floor lacks, in the order the file buried them.
// A generation the live floor holds live is buried too (BuriedLive): it was
// deleted after the backup, so the merge fails closed, unless opts.Keep names
// the entry, whose restored generation then stays live (Kept). Each live
// generation of the moved-aside floor that the live floor does not hold live
// is buried as well (Retired), unless keep names the entry and the live
// floor holds no live record of it: keep keeps one generation, the
// restored one, never a second, moved-aside one. A keep name the merge does
// not keep (it matched nothing) refuses the merge, with nothing written. The write is pruned as every
// floor write is, and each burial it drops is logged at Warn and reported;
// a write that would drop a burial the merge adds itself is refused before
// it is made (mergeLoses), as errFloorFull, with nothing written and the
// input not renamed.
// Once the floor is written, the input is renamed to
// keystore-floor.json.merged-<unix> beside it (renameMerged), which clears
// the guard the restore's keystore-floor.json.pre-restore sets on every verb
// that changes the keystore (errMergePending); a failed rename is reported
// with the report, as committed (Committed).
func (s *FileStore) MergeFloor(ctx context.Context, opts MergeOptions) (MergeReport, error) {
	r, err := s.mergeFloor(ctx, opts)
	if err != nil {
		if Committed(err) || opts.DryRun {
			return r, fmt.Errorf("merge the floor: %w", err)
		}
		return MergeReport{}, fmt.Errorf("merge the floor: %w", err)
	}
	return r, nil
}

func (s *FileStore) mergeFloor(ctx context.Context, opts MergeOptions) (MergeReport, error) {
	var r MergeReport
	if err := s.checkConfig(); err != nil {
		return r, err
	}
	if s.dataRoot == "" {
		return r, errors.New("the floor merge needs the data root, and none is configured")
	}
	kept := map[string]bool{}
	for _, name := range opts.Keep {
		if err := checkName(name); err != nil {
			return r, fmt.Errorf("keep: %w", err)
		}
		kept[name] = true
	}
	if err := s.checkFloorWritable(); err != nil {
		return r, err
	}
	fdir, live, err := s.lockFloor(ctx)
	if err != nil {
		return r, err
	}
	defer fdir.unlock()
	// The input is read under keystore-lock, so a rerun sees the floor the
	// earlier merge wrote and the input as it is now.
	in, err := s.readGuard(fdir)
	if err != nil {
		return r, err
	}
	if named, err := fdir.root.Lstat(floorName); err == nil && os.SameFile(named, in.info) {
		return r, errMergeLiveFloor
	}
	if err := s.step("merge read"); err != nil {
		return r, err
	}
	from := in.fl
	if live == nil {
		return r, checkMergeInput(live, from, kept)
	}
	liveBytes, err := marshalFloor(live)
	if err != nil {
		return r, err
	}
	liveSum := sha256Hex(liveBytes)
	// The pending retired record is the merge's commit marker: every first
	// run writes it, with the input's sha256 and the floor it writes, before
	// the floor. A record of this input whose floor is the live one is a
	// rerun: the floor is written, and is never planned again (a prune an
	// --accept-drops run made would be undone and another made); a record
	// whose base is the live floor is a first run that stopped before the
	// floor's write. No record is a first run: nothing is written.
	pending, err := s.readPendingRetired(fdir)
	if err != nil {
		return r, err
	}
	rerun := false
	var gone map[floorBurial]bool
	if pending != nil {
		// What an rm under the guard dropped since the record was written,
		// which the floor may lack (recordRmDropped).
		if gone, err = s.rmDroppedOf(fdir, *pending); err != nil {
			return r, err
		}
		switch {
		case pending.Input != in.sum:
			return r, fmt.Errorf("%s, the record a merge writes before the floor, is of another input than keystore-floor.json.pre-restore (input sha256 %s, the file's %s): the file was replaced after a merge of another one began. Nothing is written; put back the floor that merge read, or inspect both files", retiredPendingName, pending.Input, in.sum)
		case pending.Floor == liveSum:
			rerun = true
		case pending.Base == liveSum:
		default:
			// rm is never refused while a merge is pending, so the live
			// floor may be the recorded one plus burials rm added since.
			rerun, err = pendingSince(*pending, live, gone)
			var nw *notWrittenError
			switch {
			case errors.As(err, &nw):
				return r, fmt.Errorf("keystore-floor.json (sha256 %s) is neither the floor this merge recorded writing (%s) nor the one it read (%s), in %s, with only rm's burials added since: %w. The merge did not write the floor, and it does not plan a merge over a floor changed by anything but rm, so nothing is written. Inspect keystore-floor.json against the record", liveSum, pending.Floor, pending.Base, retiredPendingName, err)
			case err != nil:
				return r, fmt.Errorf("%w: keystore-floor.json (sha256 %s) is neither the floor this merge recorded writing (%s) nor the one it read (%s), in %s, nor either of them with only burials added since (%w): it changed after the merge wrote it, and the merge never plans a written merge again, so nothing more is done. Inspect keystore-floor.json against the record", errCommitted, liveSum, pending.Floor, pending.Base, retiredPendingName, err)
			}
		}
	}
	var undo retiredRecord
	if opts.Undo && !rerun {
		// In an undo the live floor is the first merge's input: only the
		// record of that merge is read.
		raw, _, err := readFile(fdir.root, floorName, int64(floorSizeLimit))
		if err != nil {
			return r, err
		}
		if undo, err = s.readRetired(fdir, sha256Hex(raw)); err != nil {
			return r, err
		}
	}
	finish := func(err error) error {
		if err == nil || !rerun || Committed(err) {
			return err
		}
		return committedShape(err)
	}
	st, err := s.openStaging(fdir)
	if err != nil {
		return r, finish(err)
	}
	defer st.close()
	// Something at the store's Dir while the tree is staged was planted:
	// the recipe leaves Dir absent. The merge moves it aside into
	// pre-restore.d before the tree moves in (moveTargetAside); a dry run
	// only names where.
	var planted string
	if st.staged && st.targetExists {
		if planted, err = s.plantedName(st); err != nil {
			return r, finish(err)
		}
	}
	moveAside := func(r *MergeReport) error {
		if planted == "" {
			return nil
		}
		r.MovedAside, r.MovedAsideType = planted, st.targetType
		if opts.DryRun {
			return nil
		}
		return s.moveTargetAside(st, planted)
	}
	// The staged tree's shape is judged read-only before anything is read
	// from it or planned, so a dry run refuses what the merge refuses.
	if st.staged {
		if err := s.checkStaged(st); err != nil {
			return r, finish(err)
		}
	}
	if rerun {
		return s.finishRerun(st, in, live, *pending, gone, opts.DryRun, moveAside)
	}
	// A keep of a name rm deleted after the restore would bring back what
	// the operator revoked under the guard.
	if after := keptAfterRm(live, kept); len(after) > 0 {
		return MergeReport{}, fmt.Errorf("--keep names %s, deleted with keys rm after the restore: the live floor records that deletion, made while this merge was pending, and a keep would bring the entry back. Nothing is written; run the merge again without it", strings.Join(after, ", "))
	}
	ptrs, unverified, aside, asideUnverified, err := s.stagedPointers(ctx, st, live, from)
	if err != nil {
		return r, err
	}
	// A dry run on a copy (planMerge): an input whose every burial and fence
	// the live floor already holds writes nothing to the floor.
	plan := planMerge(live, from, kept, ptrs, aside)
	pr := plan.r
	if unmatched := unmatchedKeep(kept, pr.Kept); len(unmatched) > 0 {
		return MergeReport{}, fmt.Errorf("--keep names %s, which the merge would not delete: it keeps an entry only when the floor moved aside records its restored generation as deleted, or holds a newer generation of a name the restored floor does not record. Nothing is written; check the names and run the merge again without them", strings.Join(unmatched, ", "))
	}
	if opts.Undo {
		if err := classifyUndo(&pr, undo, from); err != nil {
			return MergeReport{}, err
		}
	}
	changes := pr.changes()
	mergedBytes := liveBytes
	if changes {
		if mergedBytes, err = marshalFloor(plan.merged); err != nil {
			return r, err
		}
		if !st.staged {
			return r, errNotStaged
		}
		if err := checkMergeInput(live, from, kept); err != nil {
			return r, err
		}
	} else {
		pr.AlreadyMerged, pr.Dropped, plan.dropped = true, nil, nil
	}
	pr.Unverified, pr.AsideUnverified = unionNames(unverified, pr.Unverified), asideUnverified
	// As Put and Rotate ask room before they write: a merge whose write
	// would drop any burial is refused, with nothing written and the input
	// left where it is, so the guard stays, unless opts.AcceptDrops says
	// so; and a write that would drop the burial of a generation it buries
	// live is refused whatever opts says (planMerge, mergeLoss.refusal).
	var refused error
	if changes {
		refused = plan.loss.refusal(opts.AcceptDrops)
	}
	if opts.DryRun {
		_ = moveAside(&pr) // a dry run moves nothing
		return pr, refused
	}
	if refused != nil {
		return r, refused
	}
	if changes && len(mergedBytes) > floorSizeLimit {
		return r, fmt.Errorf("%w (%d bytes)", errFloorFull, len(mergedBytes))
	}
	// The guard file must still be the file read: one replaced since is
	// not merged.
	if err := in.same(); err != nil {
		return r, err
	}
	// What was planted at Dir goes aside before anything is written: a
	// failure here leaves the floor unwritten.
	var moved MergeReport
	if err := moveAside(&moved); err != nil {
		return r, fmt.Errorf("%w; nothing is merged, run the merge again", err)
	}
	// The commit marker, written before the floor: what the merge retires,
	// buries live, keeps and drops, so an undo can tell them apart from
	// later deletions, and the floor it writes, so a rerun finishes this
	// merge instead of planning another. A first run that stopped before
	// the floor's write keeps the sets the record holds (unionRecord).
	rec := retiredRecord{Input: in.sum, Retired: pr.Retired, BuriedLive: pr.BuriedLive, Kept: pr.Kept, Recorded: pr.Recorded, Dropped: pr.Dropped}
	if pending != nil {
		rec = unionRecord(*pending, rec)
	}
	rec.setFloors(liveBytes, mergedBytes)
	if err := s.writeRetiredPending(fdir, rec); err != nil {
		return r, fmt.Errorf("write %s: %w; nothing is merged, run the merge again", retiredPendingName, err)
	}
	var removed []string
	if st.staged {
		// The staged tree is handed to the service user before the floor
		// is written: a failure here leaves the floor unwritten.
		if err := s.chownStaged(st); err != nil {
			return r, err
		}
		// Each staged entry whose generation the merged floor refuses (rm
		// under the guard buried it while its files were staged, out of
		// its reach, the merge buries it live or from the moved-aside
		// floor, or the write drops its burial) has its staged directory
		// removed before the tree moves into place, so none is left for a
		// later prune of its burial to bring back. A name --keep keeps is
		// live. A failure here leaves the floor unwritten.
		names, err := s.refusedStaged(st, plan.merged, plan.dropped)
		if err != nil {
			return r, err
		}
		if removed, err = s.removeStaged(st, names); err != nil {
			return r, err
		}
	}
	// Only keystore-lock: the merge writes the root-owned floor and nothing
	// under keystore/, so it takes no keystore/.lock, which the service user
	// can hold or replace to stop it. Readers need no .lock against it
	// either: the floor is replaced by an atomic rename. The bytes written
	// are the plan's, the floor the record names.
	if changes {
		if err := s.writeFileAs(fdir.root, floorName, mergedBytes, uint32(s.floorUID), uint32(s.floorGID), floorFileMode); err != nil {
			if len(removed) > 0 {
				return MergeReport{}, fmt.Errorf("%w; the floor is not written, but the staged directories of %s, which the merged floor refuses, were removed from %s/%s; run the merge again", err, strings.Join(removed, ", "), preRestoreDirName, stagedTreeName)
			}
			return MergeReport{}, err
		}
		logPruned(plan.dropped)
	}
	r = pr
	for _, name := range unverified {
		slog.Warn("keystore floor: the restored pointer of this entry did not authenticate under the master, so the merge left its recorded sequence as the restored floor holds it: a pointer below it is refused, one at it is accepted, and one above it is accepted unless the merge fenced the entry, when one above it and at or below the fence is refused until a Rotate seals above the fence", "name", name)
	}
	for _, name := range r.overRaise {
		slog.Warn("keystore floor: the restored pointer of this entry is more than one sequence above the restored floor's record, more than a crash leaves, so the merge did not raise the record to it: that pointer is refused while it is at or below the fence the merge set, until a Rotate seals above the fence, and accepted above it; the record's own sequence stays accepted", "name", name)
	}
	for _, name := range asideUnverified {
		slog.Warn("keystore floor: the moved-aside tree's pointer of this entry did not authenticate under the master, so the merge fenced it one past the moved-aside floor's record, not past that pointer", "name", name)
	}
	r.MovedAside, r.MovedAsideType = moved.MovedAside, moved.MovedAsideType
	for _, name := range r.BuriedLive {
		slog.Warn("keystore floor: the moved-aside floor records the restored generation of this entry as deleted, so the merge buried it and removed its restored directory; in an undo --keep brings back a version the first merge retired", "name", name)
	}
	if st.staged {
		if err := s.moveStaged(st); err != nil {
			return r, movedErr(err)
		}
	}
	if err := s.renameMerged(in); err != nil {
		return r, fmt.Errorf("%w: the merge is written, but its input was not renamed, so the verbs that change the keystore still refuse; run the same merge again, which writes nothing more and renames it: %w", errCommitted, err)
	}
	return r, nil
}

// movedErr is the committed error of a failed moveStaged, on a merge whose
// floor is written.
func movedErr(err error) error {
	if errors.Is(err, errMovedNotSynced) {
		return fmt.Errorf("%w: the merge is written and the restored keystore/ is moved into place, but %w, so the move may not survive a crash and the input is not renamed; run the same merge again, which writes nothing more and renames it", errCommitted, err)
	}
	return fmt.Errorf("%w: the merge is written, but the restored keystore/ is still staged in pre-restore.d/restored: %w; run the same merge again, which writes nothing more and moves it into place", errCommitted, err)
}

// finishRerun is a rerun of a merge whose floor is written (rec, the
// pending retired record, names the live floor): it never plans the floor
// again, only finishes the steps after it, the staged tree's handover and
// move and the input's rename, and reports from rec, already merged. A
// staged entry whose burial an rm under the guard dropped (gone) has its
// directory removed with the ones the floor refuses. Every failure is
// committed.
func (s *FileStore) finishRerun(st *mergeStaging, in *mergeInput, live floor, rec retiredRecord, gone map[floorBurial]bool, dryRun bool, moveAside func(*MergeReport) error) (MergeReport, error) {
	r := MergeReport{AlreadyMerged: true, Retired: rec.Retired, BuriedLive: rec.BuriedLive, Kept: rec.Kept, Recorded: rec.Recorded, Dropped: rec.Dropped}
	for name, e := range in.fl {
		for _, b := range e.burials() {
			if live[name].buries(b.Generation) {
				r.AlreadyPresent++
			}
		}
	}
	if dryRun {
		_ = moveAside(&r) // a dry run moves nothing
		return r, nil
	}
	if st.staged {
		if err := moveAside(&r); err != nil {
			return r, committedShape(err)
		}
		if err := s.chownStaged(st); err != nil {
			return r, committedShape(err)
		}
		names, err := s.refusedStaged(st, live, goneDrops(gone))
		if err != nil {
			return r, committedShape(err)
		}
		if _, err := s.removeStaged(st, names); err != nil {
			return r, committedShape(err)
		}
		if err := s.moveStaged(st); err != nil {
			return r, movedErr(err)
		}
	}
	if err := s.renameMerged(in); err != nil {
		return r, fmt.Errorf("%w: the merge is written, but its input was not renamed, so the verbs that change the keystore still refuse; run the same merge again, which writes nothing more and renames it: %w", errCommitted, err)
	}
	return r, nil
}

// pendingSince judges a live floor that is neither of rec's floors byte for
// byte. It is a rerun of the written merge (true) when live is the floor
// rec records writing plus only what rm adds (buriedSince), and a first
// run that stopped before its floor write (false) when live is the floor
// rec records reading plus only rm's burials under the guard (rmSince).
// gone is each burial an rm under the guard dropped (rmDroppedOf): either
// floor may lack it. Anything else is an error: committed when live is not
// the floor read with only what rm adds or what anything else adds (the
// merge may have written it), and errNotWritten when it is the floor read
// with a change rm does not make (the merge never wrote its floor).
func pendingSince(rec retiredRecord, live floor, gone map[floorBurial]bool) (bool, error) {
	written, err := recordFloor(rec.Written, rec.Floor)
	if err != nil {
		return false, err
	}
	werr := buriedSince(written, live, gone)
	if werr == nil {
		return true, nil
	}
	read, err := recordFloor(rec.Read, rec.Base)
	if err != nil {
		return false, err
	}
	if rmSince(read, live, gone) {
		return false, nil
	}
	if rerr := buriedSince(read, live, gone); rerr == nil {
		return false, &notWrittenError{written: werr}
	}
	return false, werr
}

// notWrittenError is pendingSince's answer for a live floor that holds
// everything the floor the merge read refuses, but not what the floor it
// recorded writing refuses, and that differs from the floor read by more
// than rm's burials: the merge's floor write never happened, and something
// other than rm changed the floor since it read it.
type notWrittenError struct{ written error }

func (e *notWrittenError) Error() string {
	return fmt.Sprintf("it is the floor this merge read, changed since by more than rm's burials (against the floor it recorded writing: %v)", e.written)
}

// buriedSince reports how now differs from old by more than burials added:
// a burial of old gone from now or numbered lower, a live record of old
// with another generation, a lower sequence, or a higher one inside old's
// fence, or gone without its generation buried, or a live record now that
// old does not hold. A burial of old in gone, the burials an rm under the
// guard dropped, may be missing from now, and so may the burial of a live
// generation of old rm buried. nil means now refuses everything old
// refuses, except for gone.
func buriedSince(old, now floor, gone map[floorBurial]bool) error {
	for _, name := range slices.Sorted(maps.Keys(old)) {
		o, n := old[name], now[name]
		for _, b := range o.burials() {
			i := slices.IndexFunc(n.burials(), func(x burial) bool { return x.Generation == b.Generation })
			switch {
			case i < 0 && gone[floorBurial{name, b.Generation}]:
			case i < 0:
				return fmt.Errorf("the burial of %s generation %s is gone", name, b.Generation)
			case n.Buried[i].Deleted < b.Deleted:
				return fmt.Errorf("the burial of %s generation %s is numbered lower", name, b.Generation)
			}
		}
		switch {
		case !o.live():
		case !n.live():
			if !n.buries(o.Generation) && !gone[floorBurial{name, o.Generation}] {
				return fmt.Errorf("the live record of %s is gone and its generation not buried", name)
			}
		case n.Generation != o.Generation:
			return fmt.Errorf("the live record of %s holds another generation", name)
		case !fenceKept(o, n):
			return fmt.Errorf("the live record of %s is lowered or moved inside its fence", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(now)) {
		if now[name].live() && !old[name].live() {
			return fmt.Errorf("%s is live and was not", name)
		}
	}
	return nil
}

// fenceKept reports whether the live record n, of o's generation, refuses
// every pointer o refuses: the same sequence with a high-water mark at or
// above o's, or a sequence above both o's sequence and its mark. A
// sequence raised into o's fence (above o.Seq, at or below o.HighWater)
// would accept a copy of the history the fence refuses.
func fenceKept(o, n floorEntry) bool {
	return (n.Seq == o.Seq && n.HighWater >= o.HighWater) || n.Seq > max(o.Seq, o.HighWater)
}

// rmSince reports whether now is old plus only what rm writes under the
// guard: burials numbered above guardEraSeq, each live record of old kept
// as it is or buried, and no burial of old gone but those in gone, the
// burials rm dropped.
func rmSince(old, now floor, gone map[floorBurial]bool) bool {
	if buriedSince(old, now, gone) != nil {
		return false
	}
	for name, n := range now {
		o := old[name]
		if n.live() && (n.Generation != o.Generation || n.Seq != o.Seq || n.HighWater != o.HighWater) {
			return false
		}
		for _, b := range n.burials() {
			if !o.buries(b.Generation) && b.Deleted <= guardEraSeq {
				return false
			}
		}
	}
	return true
}

// goneDrops is gone as the burials a write dropped, sorted, for
// refusedStaged.
func goneDrops(gone map[floorBurial]bool) []pruned {
	out := make([]pruned, 0, len(gone))
	for b := range gone {
		out = append(out, pruned{name: b.name, generation: b.generation})
	}
	slices.SortFunc(out, func(a, b pruned) int {
		return strings.Compare(a.name+"\x00"+a.generation, b.name+"\x00"+b.generation)
	})
	return out
}

// keptAfterRm is each name in keep, sorted, whose burial in live is a
// guard-era one (numbered above guardEraSeq): an rm run after the restore,
// while the merge was pending, deleted it.
func keptAfterRm(live floor, keep map[string]bool) []string {
	set := map[string]bool{}
	for name := range keep {
		for _, b := range live[name].burials() {
			if b.Deleted > guardEraSeq {
				set[name] = true
			}
		}
	}
	return sortedNames(set)
}

// floorBurial is one burial by name and generation.
type floorBurial struct{ name, generation string }

// guardEra is each burial in fl above guardEraSeq: one a Delete wrote while
// a restore was unfinished.
func (fl floor) guardEra() map[floorBurial]bool {
	out := map[floorBurial]bool{}
	for name, e := range fl {
		for _, b := range e.burials() {
			if b.Deleted > guardEraSeq {
				out[floorBurial{name, b.Generation}] = true
			}
		}
	}
	return out
}

// renumberGuard renumbers fl's burials, order kept: those in guarded from
// guardEraSeq+1, the others from 1, and returns how many others there are.
// Burials the merge adds then fit between the two, below every guard-era
// one.
func (fl floor) renumberGuard(guarded map[floorBurial]bool) uint64 {
	fl.renumber()
	var below uint64
	for name, e := range fl {
		bs := slices.Clone(e.burials())
		for i := range bs {
			if !guarded[floorBurial{name, bs[i].Generation}] {
				below++
			}
		}
		e.Buried = bs
		fl[name] = e
	}
	// renumber gave 1..n in order; move the guard-era ones up by
	// guardEraSeq and close the gaps below.
	type at struct {
		name string
		i    int
		d    uint64
	}
	var lo, hi []at
	for name, e := range fl {
		for i, b := range e.burials() {
			if guarded[floorBurial{name, b.Generation}] {
				hi = append(hi, at{name, i, b.Deleted})
			} else {
				lo = append(lo, at{name, i, b.Deleted})
			}
		}
	}
	for _, set := range [][]at{lo, hi} {
		sort.Slice(set, func(i, j int) bool { return set[i].d < set[j].d })
	}
	for n, a := range lo {
		fl[a.name].Buried[a.i].Deleted = uint64(n + 1)
	}
	for n, a := range hi {
		fl[a.name].Buried[a.i].Deleted = guardEraSeq + uint64(n+1)
	}
	return below
}

// mergePlan is a merge decided on in-memory floors, before anything is
// written: its report (Dropped included), the floor the write would hold
// after its prune, every burial the write would drop, at the per-name cap
// and in the prune, and what those drops lose.
type mergePlan struct {
	r       MergeReport
	merged  floor
	dropped []pruned
	loss    mergeLoss
}

// planMerge is mergeFloor's decision logic, on a copy of live: mergeFenced
// of from into it, then the prune every floor write makes. It writes
// nothing and reads nothing but its arguments.
func planMerge(live, from floor, keep map[string]bool, ptrs, aside map[string]uint64) mergePlan {
	merged := maps.Clone(live)
	r, capDropped := merged.mergeFenced(from, keep, ptrs, aside)
	l := mergeLoses(live, merged, capDropped, r.BuriedLive)
	dropped := append(slices.Clone(capDropped), merged.prune()...)
	r.Dropped = nil
	for _, p := range dropped {
		r.Dropped = append(r.Dropped, p.name)
	}
	sort.Strings(r.Dropped)
	return mergePlan{r: r, merged: merged, dropped: dropped, loss: l}
}

// mergeLoss is what mergeLoses found: the names whose burial the write
// would drop, and which of the floor's caps drops them.
type mergeLoss struct {
	// names is each entry with a burial lost, sorted and without repeats.
	names []string
	// capNames is each of them whose burial the per-name cap drops.
	capNames []string
	// buriedLive is each entry whose restored generation the merge buried
	// live and whose burial of it the write would drop: the name would end
	// with neither a live record nor that burial, so the restored copy
	// would be live again with nothing refusing it.
	buriedLive []string
	// tombstones is the size the merged floor's tombstones would take before
	// the prune, when it is over the tombstone budget, or 0.
	tombstones int
}

// mergeLoses finds each burial of the merge that took live to merged that
// the write would drop: at the per-name cap (capDropped, what merge
// returned) or in the write's prune, run here on a copy. Every drop counts,
// a burial the restored floor held included: each is a recorded deletion
// whose copy put back would be accepted again. buriedLive names the entries
// the merge cleared to no live record (BuriedLive): a drop of that burial
// is one no --accept-drops makes. A fence is a high-water mark on a live
// record, which no prune removes.
func mergeLoses(live, merged floor, capDropped []pruned, buriedLive []string) mergeLoss {
	cleared := func(p pruned) bool {
		f := live[p.name]
		return slices.Contains(buriedLive, p.name) && f.live() && f.Generation == p.generation
	}
	var l mergeLoss
	names, capNames, lost := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range capDropped {
		names[p.name], capNames[p.name] = true, true
		if cleared(p) {
			lost[p.name] = true
		}
	}
	for _, p := range maps.Clone(merged).prune() {
		names[p.name] = true
		if cleared(p) {
			lost[p.name] = true
		}
	}
	l.names, l.capNames, l.buriedLive = sortedNames(names), sortedNames(capNames), sortedNames(lost)
	if t := merged.deadSize(); t > tombstoneSizeLimit {
		l.tombstones = t
	}
	return l
}

// refusal is the error refusing a merge that would lose l, or nil: a
// buried-live burial lost refuses whatever acceptDrops says; any other drop
// refuses unless acceptDrops.
func (l mergeLoss) refusal(acceptDrops bool) error {
	if len(l.buriedLive) > 0 {
		return fmt.Errorf("%w: the keystore floor cannot hold the merge without dropping the deletion recorded for %s, an entry the backup holds that was deleted since: the merge clears its restored record, so with the deletion dropped the restored copy would be accepted again with nothing refusing it, and --accept-drops never drops that one. Nothing is written, and the floor moved aside is left in place, so the restore stays unfinished. Delete each of those entries first with sudo k3sm keys rm system/<name> --yes, which runs while the merge is pending and records its own deletion, then run the merge again", errFloorFull, strings.Join(l.buriedLive, ", ")+",")
	}
	if len(l.names) > 0 && !acceptDrops {
		return l.err()
	}
	return nil
}

// err is the refusal of a merge that would lose l, naming what binds: when
// only the floor's size does, keys rm makes room (each rm frees a live
// record); when the tombstone budget or the per-name cap does, rm adds a
// burial and cannot help, so it names --accept-drops and what it costs.
func (l mergeLoss) err() error {
	lost := strings.Join(l.names, ", ")
	if len(l.capNames) == 0 && l.tombstones == 0 {
		return fmt.Errorf("%w: the merge would drop the deletions recorded for %s to keep keystore-floor.json within its %d-byte size, so a copy of each would be accepted again. Nothing is written, and the floor moved aside is left in place, so the restore stays unfinished. To make room, delete each entry that is no longer needed with sudo k3sm keys rm system/<name> --yes, which runs while the merge is pending, then run the merge again", errFloorFull, lost, floorSizeLimit)
	}
	var why []string
	if l.tombstones > 0 {
		why = append(why, fmt.Sprintf("the tombstone budget binds: the deletions would take %d bytes, over the %d-byte budget", l.tombstones, tombstoneSizeLimit))
	}
	if len(l.capNames) > 0 {
		why = append(why, fmt.Sprintf("the per-name cap of %d deletions binds for %s", buriedPerNameLimit, strings.Join(l.capNames, ", ")))
	}
	return &mergeFullError{msg: fmt.Sprintf("the keystore floor cannot hold the merge: it would drop the deletions recorded for %s, so a copy of each would be accepted again: %s. Deleting more entries cannot make room, since each deletion records one more. Nothing is written, and the floor moved aside is left in place, so the restore stays unfinished. To finish it anyway, run sudo k3sm keys floor merge --accept-drops: it drops the oldest deletions to fit, those among them, prints each one it drops, exits 4 and finishes the restore; a copy of each dropped entry put back is accepted again", lost, strings.Join(why, "; and "))}
}

// mergeFullError is a merge refused because the tombstone budget or the
// per-name cap binds. It matches errFloorFull, with its own advice: the
// floor-full text's "delete entries" cannot help there.
type mergeFullError struct{ msg string }

func (e *mergeFullError) Error() string { return e.msg }

// Is matches errFloorFull.
func (e *mergeFullError) Is(target error) bool { return target == errFloorFull }

// changes reports whether the merge r reports has anything to commit: a
// change to the floor (floorChanges) or a name kept, so a kept-only first
// run writes its retired record.
func (r MergeReport) changes() bool {
	return r.floorChanges() || len(r.Kept) > 0
}

// floorChanges reports whether the merge r reports changed the floor. A
// keep repeated by a second merge of the same input changes nothing in it:
// a rerun keeps the name again and writes nothing.
func (r MergeReport) floorChanges() bool {
	return r.Merged > 0 || len(r.Retired) > 0 || len(r.Fenced) > 0 || r.raised > 0 || r.recorded > 0 || r.renumbered
}

// errMergeLiveFloor refuses a merge whose input is the data root's live
// floor itself, the same inode under the guard file's name.
var errMergeLiveFloor = errors.New("keystore-floor.json.pre-restore is the live floor itself: merging it changes nothing. It must be the floor moved aside before the restore")

// errGuardNoFloor refuses a Delete while a restore is unfinished and the
// live floor is absent.
var errGuardNoFloor = errors.New("a restore is unfinished (keystore-floor.json.pre-restore is in the data root) and the live floor is absent: install the saved keystore-floor.json first, with install -o root -g wheel -m 0644 as docs/user/keys.md describes; nothing is deleted until then")

// maxMergedTries bounds how many seconds renameMerged tries past now for a
// free keystore-floor.json.merged-<unix>.
const maxMergedTries = 8

// errNoGuard refuses a merge when the data root holds no
// keystore-floor.json.pre-restore: no restore is unfinished.
var errNoGuard = errors.New("there is nothing to merge: keystore-floor.json.pre-restore, the floor the restore recipe moves aside, is not in the data root. The merge reads only that file; move the live floor aside under that name as docs/user/keys.md describes")

// renameMerged renames the merged input in, through the data root the lock
// judged, to keystore-floor.json.merged-<unix>, which clears the guard
// (errMergePending) and records which file was merged, and the pending
// retired record, when there is one, to the same name with .retired. The name must still
// be the file read, and a name taken is never replaced: the first second
// from now with both names free is used.
func (s *FileStore) renameMerged(in *mergeInput) error {
	if err := in.same(); err != nil {
		return err
	}
	// The first second from now with neither name taken, so a merge made
	// in the same second as an earlier one (an undo right after its
	// restore) still sorts after it; a name taken is never replaced.
	var to string
	for at, tries := s.now().Unix(), 0; ; at, tries = at+1, tries+1 {
		if tries == maxMergedTries {
			return fmt.Errorf("%s%d and the %d seconds after it are all taken", mergedPrefix, at-maxMergedTries, maxMergedTries)
		}
		to = fmt.Sprintf("%s%d", mergedPrefix, at)
		free := true
		for _, n := range []string{to, to + retiredSuffix} {
			if _, err := in.dir.Lstat(n); !errors.Is(err, fs.ErrNotExist) {
				free = false
			}
		}
		if free {
			break
		}
	}
	// The retired record goes first: renamed after the input, a failure
	// would leave it pending with no guard left to rerun the merge on.
	switch _, err := in.dir.Lstat(retiredPendingName); {
	case err == nil:
		if err := in.dir.Rename(retiredPendingName, to+retiredSuffix); err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	// The rm-dropped record is of this merge only: with the guard cleared
	// no rm writes under it, and no rerun reads it.
	if err := in.dir.Remove(rmDroppedName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := in.dir.Rename(in.base, to); err != nil {
		return err
	}
	return syncDir(in.dir)
}

// checkMergeInput refuses a merge of from into live, the floor read under
// keystore-lock, that cannot be the restore's: an absent live floor (the
// saved floor was never put back, and merging into nothing would write the
// moved-aside floor's burials alone, with no live records), and a from equal
// to live (the same floor merged into itself: parseFloor accepts one
// encoding per floor, so equal floors are byte-identical files, up to the
// trailing newline), and a merge that would retire every live record of
// from: live neither holds live nor buries any of their generations (an rm
// under the guard buries one), keep names none of them, and from buries no
// generation live holds live, which is a live floor that is not from's
// backup.
func checkMergeInput(live, from floor, keep map[string]bool) error {
	if live == nil {
		return errors.New("the live keystore floor is absent, so there is nothing to merge into: restore the saved keystore-floor.json first, with install -o root -g wheel -m 0644 as docs/user/keys.md describes, then run the merge again")
	}
	if floorsSame(live, from) {
		return errors.New("keystore-floor.json.pre-restore is the live floor itself, byte for byte: merging it changes nothing. It must be the floor moved aside before the restore")
	}
	asideLive, shared := 0, false
	for name, a := range from {
		if !a.live() {
			continue
		}
		asideLive++
		if f := live[name]; keep[name] || (f.live() && f.Generation == a.Generation) || f.buries(a.Generation) {
			shared = true
		}
	}
	// A restored live generation the moved-aside floor buries (deleted and
	// put again since the backup) ties the two floors as well.
	for name, f := range live {
		if f.live() && from[name].buries(f.Generation) {
			shared = true
		}
	}
	if asideLive > 0 && !shared {
		return fmt.Errorf("the merge would retire every entry: the live floor holds none of the %d entries the floor moved aside holds live, so it is most likely not the floor saved with this backup. Nothing is written. Put back the keystore-floor.json saved with the backup, as docs/user/keys.md describes, and run the merge again; to keep an entry the backup does not hold, name it with --keep system/<name>", asideLive)
	}
	return nil
}

// floorsSame reports whether a and b encode to the same floor file.
func floorsSame(a, b floor) bool {
	ab, aerr := marshalFloor(a)
	bb, berr := marshalFloor(b)
	return aerr == nil && berr == nil && bytes.Equal(ab, bb)
}

// mergeInput is the floor file a merge reads: the parsed floor, the file's
// info, its base name, and the data root it was read through, which the
// floor lock owns and closes.
type mergeInput struct {
	fl floor
	// sum is the sha256 of the file's bytes, which the retired record
	// carries as its input.
	sum  string
	info fs.FileInfo
	dir  *os.Root
	base string
}

// same refuses unless the input's name is still the file read.
func (in *mergeInput) same() error {
	named, err := in.dir.Lstat(in.base)
	if err != nil {
		return fmt.Errorf("%s changed during the merge: %w", in.base, err)
	}
	if !os.SameFile(named, in.info) {
		return fmt.Errorf("%s was replaced during the merge: nothing more is done; run the merge again", in.base)
	}
	return nil
}

// readGuard reads and parses the data root's keystore-floor.json.pre-restore
// through l.root, the directory the lock judged, as the live floor is read:
// a regular file, never followed, owned by root (floorUID), not group- or
// other-writable, and at most maxFloorSize. An absent file is errNoGuard.
func (s *FileStore) readGuard(l *floorLock) (*mergeInput, error) {
	named, err := l.root.Lstat(floorPreRestoreName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoGuard
	}
	if err != nil {
		return nil, err
	}
	// os.Root resolves a symlink it is asked to open, so it is refused by
	// name first; the open below is O_NOFOLLOW, so one swapped in after this
	// fails it.
	if !named.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s has mode %s", errFloorUntrusted, floorPreRestoreName, named.Mode())
	}
	b, fi, err := readFile(l.root, floorPreRestoreName, int64(floorSizeLimit))
	if errors.Is(err, errBadFile) {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorPreRestoreName, err)
	}
	if err != nil {
		return nil, err
	}
	if err := s.floorOwned(fi); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, floorPreRestoreName, err)
	}
	fl, err := parseFloor(b)
	if err != nil {
		return nil, err
	}
	return &mergeInput{fl: fl, sum: sha256Hex(b), info: fi, dir: l.root, base: floorPreRestoreName}, nil
}

// mergeFenced adds to fl every burial in from that fl lacks, oldest (lowest
// Deleted) first, each at one more than the highest delete sequence in fl,
// so the merged burials keep their order and stay newer than fl's own. A
// generation fl holds live under the name is buried as well, its live record
// cleared (BuriedLive), unless keep names the entry (Kept); fl's other live
// records are kept. Then, by name, each live generation in from that fl
// neither holds live nor buries is buried after them (Retired), unless keep
// names the entry and fl holds no live record of it (keep keeps the restored
// generation, never a second one), which records from's live record in fl,
// at its sequence and fenced (fenceMark). A live generation in from that fl holds
// live at a sequence at or below from's gets a high-water mark (below)
// (Fenced). At maxBuriedPerName, add drops the name's oldest, returned. It
// does not prune: update does.
//
// ptrs is the authenticated restored pointer sequence of each name it
// fences (restoredPointers), or nil. A restored live record one below
// its pointer, and not at or below its own high-water mark, is raised to the
// pointer first (counted in raised), so a restored entry whose saved floor
// lagged its pointer by the one sequence a crash leaves is never inside the
// fence. A pointer further above the record is not raised to: the name is
// reported in Unverified, and the fence covers that pointer. The fence mark is one above the higher of the moved-aside
// record's sequence and mark, so a pre-restore pointer one past a moved-aside
// floor that lagged it is refused too; at the sequence limit it saturates.
//
// Each fence mark is also above aside[name], the authenticated pointer
// sequence of the moved-aside tree's entry (stagedPointers), or nil: a
// moved-aside floor that lagged its own pointer by any number of sequences
// still fences above that pointer.
func (fl floor) mergeFenced(from floor, keep map[string]bool, ptrs, aside map[string]uint64) (MergeReport, []pruned) {
	type at struct {
		name string
		b    burial
	}
	var all []at
	for name, e := range from {
		for _, b := range e.burials() {
			all = append(all, at{name, b})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].b.Deleted != all[j].b.Deleted {
			return all[i].b.Deleted < all[j].b.Deleted
		}
		return all[i].name < all[j].name
	})
	var r MergeReport
	var out []pruned
	// last is the highest delete sequence below the guard-era burials (rm
	// run under the guard), kept as each burial lands. The burials the merge
	// adds are older in real time than the guard-era ones, so they are
	// numbered below them: the guard-era burials are moved to just above
	// guardEraSeq first, the others renumbered from 1, so the added ones fit
	// between, and every burial is renumbered from 1 at the end, order kept.
	guarded := fl.guardEra()
	last := fl.lastDeleted()
	// A floor numbered into the guard band with no guard-era burial left (a
	// band an earlier merge or Delete left) is renumbered too, so what the
	// merge adds stays below guardEraSeq.
	band := len(guarded) > 0 || last >= guardEraSeq
	if band {
		last = fl.renumberGuard(guarded)
	}
	add := func(name, g string) {
		if last >= maxDeleteSeq {
			last = fl.renumber()
		}
		last++
		// Read after renumber, which rewrites the name's own burials in fl.
		f := fl[name]
		if f.live() && f.Generation == g {
			f.Generation, f.Seq, f.HighWater = "", 0, 0
		}
		if dropped, ok := f.insert(burial{Generation: g, Deleted: last}); ok {
			out = append(out, pruned{name: name, generation: dropped.Generation})
		}
		fl[name] = f
	}
	kept, buriedLive, fenced, overRaise, recorded := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range all {
		f := fl[a.name]
		switch {
		case f.live() && f.Generation == a.b.Generation:
			if keep[a.name] {
				kept[a.name] = true
				continue
			}
			buriedLive[a.name] = true
		case f.buries(a.b.Generation):
			r.AlreadyPresent++
			continue
		}
		add(a.name, a.b.Generation)
		r.Merged++
	}
	names := make([]string, 0, len(from))
	for name := range from {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		a, f := from[name], fl[name]
		switch {
		case a.live() && f.live() && f.Generation == a.Generation:
			// The same generation, restored at an older sequence: the
			// moved-aside history above it, and one past it, must never
			// outrank it.
			if p := ptrs[name]; p > f.Seq && p > f.HighWater {
				if p-f.Seq > 1 {
					// More than the one-sequence lag a crash leaves: not
					// raised to, and inside the fence below.
					overRaise[name] = true
				} else {
					f.Seq, f.HighWater = p, 0
					fl[name] = f
					r.raised++
				}
			}
			hw := fenceMark(a, aside[name])
			if keep[name] && f.Seq == a.Seq && f.HighWater == hw {
				// The record a keep of a name the restored floor did not
				// record wrote (below): a rerun keeps it again.
				kept[name], recorded[name] = true, true
				continue
			}
			if hw > f.Seq && hw > f.HighWater {
				f.HighWater = hw
				fl[name] = f
				fenced[name] = true
			}
			continue
		case !a.live(), f.buries(a.Generation):
			continue
		case keep[name] && !f.live():
			// keep keeps the restored generation, never a second one: a
			// name the restored floor holds live has the moved-aside live
			// generation retired whatever keep says. With no live record,
			// the moved-aside one is recorded, fenced one past it, so an
			// older copy of that generation, or one from the history
			// above the moved-aside record, is refused.
			f.Generation, f.Seq, f.HighWater = a.Generation, a.Seq, 0
			if hw := fenceMark(a, aside[name]); hw > a.Seq {
				f.HighWater = hw
			}
			fl[name] = f
			kept[name], recorded[name] = true, true
			r.recorded++
			continue
		}
		add(name, a.Generation)
		r.Retired = append(r.Retired, name)
	}
	r.BuriedLive, r.Kept, r.Fenced, r.Recorded = sortedNames(buriedLive), sortedNames(kept), sortedNames(fenced), sortedNames(recorded)
	r.Unverified, r.overRaise = sortedNames(overRaise), sortedNames(overRaise)
	if band {
		fl.renumber()
		r.renumbered = true
	}
	return r, out
}

// fenceMark is the high-water mark a merge fences a live record of a's
// generation at: one above the highest of a's sequence, its mark and p, the
// moved-aside tree's authenticated pointer sequence (0 for none), saturating
// at the sequence limit.
func fenceMark(a floorEntry, p uint64) uint64 {
	hw := max(a.Seq, a.HighWater, p)
	if hw < math.MaxUint64 {
		hw++
	}
	return hw
}

// unmatchedKeep is each name in keep that kept, the names the merge kept,
// lacks, sorted: a keep name that matched nothing, most likely a typo.
func unmatchedKeep(keep map[string]bool, kept []string) []string {
	var out []string
	for name := range keep {
		if !slices.Contains(kept, name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// stagedPointers authenticates, under the master, the pointers the merge
// reads from pre-restore.d, never from the store's Dir. From the staged tree
// (restored, root's ditto of the backup), the current pointer of each entry
// live (the floor read under keystore-lock) holds live under the generation
// from holds live too: the names a fence can apply to. It returns each
// authenticated pointer's sequence by name and, sorted, each candidate whose
// pointer did not authenticate (no staged tree, no master, no entry, another
// generation, or a refused record). From the moved-aside tree (keystore),
// the current pointer of each entry from holds live, under from's
// generation: the fence goes above it (mergeFenced); with that tree present,
// each of those names whose pointer did not authenticate (no master, no
// entry, another generation, or a refused record) is returned, sorted, in
// asideUnverified. With pre-restore.d present but the moved-aside tree
// absent, each of those names is in asideUnverified too: no pointer of it
// authenticated, so its fence is one past the moved-aside floor's record. It takes no
// keystore/.lock (see mergeFloor) and writes nothing; it stops with ctx's
// error.
func (s *FileStore) stagedPointers(ctx context.Context, st *mergeStaging, live, from floor) (ptrs map[string]uint64, unverified []string, aside map[string]uint64, asideUnverified []string, err error) {
	var names, asideNames []string
	for name, a := range from {
		if !a.live() {
			continue
		}
		asideNames = append(asideNames, name)
		if f := live[name]; f.live() && f.Generation == a.Generation {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	sort.Strings(asideNames)
	if len(names) == 0 && len(asideNames) == 0 {
		return nil, nil, nil, nil, nil
	}
	k, kerr := s.loadMaster()
	if kerr == nil {
		defer k.wipe()
	}
	if len(names) > 0 {
		staged, terr := st.tree(stagedTreeName)
		if terr != nil {
			return nil, nil, nil, nil, terr
		}
		if staged == nil || kerr != nil {
			unverified = names
		} else {
			ptrs, unverified, err = treePointers(ctx, staged, k, live, names)
			_ = staged.Close() // read-only
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}
	}
	if len(asideNames) > 0 {
		tree, terr := st.tree(asideTreeName)
		if terr != nil {
			return nil, nil, nil, nil, terr
		}
		switch {
		case tree == nil && st.dir == nil:
			// No pre-restore.d at all: nothing is staged, and a merge that
			// would change the floor is refused (errNotStaged).
		case tree == nil:
			// pre-restore.d holds no moved-aside tree, so no pointer of
			// these live entries authenticates: their fence is one past
			// the moved-aside floor's record, not past a pointer.
			asideUnverified = asideNames
		case kerr != nil:
			_ = tree.Close() // read-only
			asideUnverified = asideNames
		default:
			aside, asideUnverified, err = treePointers(ctx, tree, k, from, asideNames)
			_ = tree.Close() // read-only
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}
	}
	return ptrs, unverified, aside, asideUnverified, nil
}

// treePointers is the authenticated pointer sequence of each of names in
// tree whose generation is the one fl records live, and, sorted, each name
// whose pointer did not authenticate.
func treePointers(ctx context.Context, tree *os.Root, k keys, fl floor, names []string) (map[string]uint64, []string, error) {
	ptrs := map[string]uint64{}
	var unverified []string
	for i, name := range names {
		if err := loopCtx(ctx, i); err != nil {
			return nil, nil, err
		}
		e, err := openEntry(tree, name, fl)
		if err != nil {
			unverified = append(unverified, name)
			continue
		}
		_, seq, perr := e.pointer(k)
		same := hex.EncodeToString(e.generation[:]) == fl[name].Generation
		e.close()
		if perr != nil || !same {
			unverified = append(unverified, name)
			continue
		}
		ptrs[name] = seq
	}
	return ptrs, unverified, nil
}

// unionNames is the names in a or b, sorted and without repeats, or nil for
// none.
func unionNames(a, b []string) []string {
	set := map[string]bool{}
	for _, n := range append(slices.Clone(a), b...) {
		set[n] = true
	}
	return sortedNames(set)
}

// sortedNames is set's names, sorted, or nil for none.
func sortedNames(set map[string]bool) []string {
	var out []string
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
