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
	// floor holds no live record of the name. It is left as restored, the
	// entry restored on purpose; a restored live record keeps only its own
	// generation, and the moved-aside one is retired regardless.
	Kept []string
	// Retired is how many live generations of the moved-aside floor the
	// merge buried: each one the restored floor does not hold live, under
	// another generation or not at all. Choosing the backup retired it, so
	// its directory put back is refused.
	Retired int
	// Fenced names, sorted, each entry whose generation the restored floor
	// holds live at a lower sequence than the moved-aside floor did: the
	// merge set the live record's high-water mark to the moved-aside
	// sequence, so a copy of the abandoned history, which would otherwise
	// outrank the restored entry, is refused until a Rotate seals above it.
	Fenced []string
	// Unverified names, sorted, each entry the restored floor holds live
	// under the moved-aside floor's live generation whose restored pointer
	// did not authenticate under the master: its sequence is left as the
	// restored floor records it, so a restored pointer above that record is
	// inside the fence.
	Unverified []string
	// Dropped names, sorted and with repeats, each burial the write dropped
	// to stay within the floor's caps (the per-name cap and the tombstone
	// budget): a copy of it put back is accepted again.
	Dropped []string
	// AlreadyMerged is set when the live floor already held every burial
	// and fence the input records: the merge wrote nothing and only renamed
	// the input, as a rerun after a failed rename does.
	AlreadyMerged bool
	// raised is how many restored live records the merge raised to their
	// authenticated restored pointer before fencing.
	raised int
}

// MergeFloor merges every burial the floor file at path records (the live
// floor moved aside before a restore) into the live floor, which a restore
// has just replaced with the one saved beside the backup, so the deletions
// recorded after the backup survive the restore (docs/design/keystore.md §
// "Pointer sequence and floor", "Restoring with the saved floor"). The file
// is read as the floor is, judged on its descriptor (a regular file owned by
// root and not group- or other-writable, under maxFloorSize) and parsed by
// parseFloor. It refuses, writing nothing, a merge onto an absent live floor,
// from a file older than the live floor or equal to it (checkMergeInput).
// Under keystore-lock alone (§ Concurrency; it writes nothing
// under keystore/, so it never takes keystore/.lock) it adds each burial the live floor lacks, in the order the file buried them.
// A generation the live floor holds live is buried too (BuriedLive): it was
// deleted after the backup, so the merge fails closed, unless keep names
// the entry, whose restored generation then stays live (Kept). Each live
// generation of the moved-aside floor that the live floor does not hold live
// is buried as well (Retired), unless keep names the entry and the live
// floor holds no live record of it: keep keeps one generation, the
// restored one, never a second, moved-aside one. keep holds
// entry names, each checked as a name is; a name the merge does not keep
// (it matched nothing) refuses the merge, with nothing written. The write is pruned as every
// floor write is, and each burial it drops is logged at Warn and reported.
// Once the floor is written, the input is renamed to
// keystore-floor.json.merged-<unix> beside it (renameMerged), which clears
// the guard the restore's keystore-floor.json.pre-restore sets on every verb
// that changes the keystore (errMergePending); a failed rename is reported
// with the report, as committed (Committed).
func (s *FileStore) MergeFloor(ctx context.Context, path string, keep []string) (MergeReport, error) {
	r, err := s.mergeFloor(ctx, path, keep)
	if err != nil {
		if Committed(err) {
			return r, fmt.Errorf("merge the floor: %w", err)
		}
		return MergeReport{}, fmt.Errorf("merge the floor: %w", err)
	}
	return r, nil
}

func (s *FileStore) mergeFloor(ctx context.Context, path string, keep []string) (MergeReport, error) {
	var r MergeReport
	if err := s.checkConfig(); err != nil {
		return r, err
	}
	kept := map[string]bool{}
	for _, name := range keep {
		if err := checkName(name); err != nil {
			return r, fmt.Errorf("keep: %w", err)
		}
		kept[name] = true
	}
	if s.dataRoot != "" && path == filepath.Join(s.dataRoot, floorName) {
		return r, errMergeLiveFloor
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
	in, err := s.readFloorAt(path)
	if err != nil {
		return r, err
	}
	defer in.close()
	if named, err := fdir.root.Lstat(floorName); err == nil && os.SameFile(named, in.info) {
		return r, errMergeLiveFloor
	}
	from := in.fl
	if live == nil {
		return r, checkMergeInput(live, from)
	}
	ptrs, unverified, err := s.restoredPointers(ctx, live, from)
	if err != nil {
		return r, err
	}
	// A dry run on a copy: an input whose every burial and fence the live
	// floor already holds (a rerun after a failed rename) writes nothing
	// and is only renamed, whatever its newest deletion.
	probe := maps.Clone(live)
	pr, _ := probe.merge(from, kept, ptrs)
	if unmatched := unmatchedKeep(kept, pr.Kept); len(unmatched) > 0 {
		return MergeReport{}, fmt.Errorf("--keep names %s, which the merge would not delete: it keeps an entry only when the floor moved aside records its restored generation as deleted, or holds a newer generation of a name the restored floor does not record. Nothing is written; check the names and run the merge again without them", strings.Join(unmatched, ", "))
	}
	if !pr.changes() {
		pr.AlreadyMerged, pr.Unverified = true, unverified
		if err := s.renameMerged(in); err != nil {
			return MergeReport{}, err
		}
		return pr, nil
	}
	if err := checkMergeInput(live, from); err != nil {
		return r, err
	}
	// Only keystore-lock: the merge writes the root-owned floor and nothing
	// under keystore/, so it takes no keystore/.lock, which the service user
	// can hold or replace to stop it. Readers need no .lock against it
	// either: the floor is replaced by an atomic rename.
	var capDropped []pruned
	_, dropped, err := fdir.updatePruned(func(fl floor) bool {
		r, capDropped = fl.merge(from, kept, ptrs)
		return r.changes()
	})
	if err != nil {
		return MergeReport{}, err
	}
	for _, p := range append(capDropped, dropped...) {
		r.Dropped = append(r.Dropped, p.name)
	}
	sort.Strings(r.Dropped)
	logPruned(capDropped)
	r.Unverified = unverified
	for _, name := range r.Unverified {
		slog.Warn("keystore floor: the restored pointer of this entry did not authenticate under the master, so the merge left its recorded sequence as the restored floor holds it; a restored pointer above that is refused until a Rotate", "name", name)
	}
	for _, name := range r.BuriedLive {
		slog.Warn("keystore floor: the moved-aside floor records the restored generation of this entry as deleted, so the merge buried it and the restored entry is refused; rm removes its directory", "name", name)
	}
	if err := s.renameMerged(in); err != nil {
		return r, fmt.Errorf("%w: the merge is written, but its input was not renamed, so the verbs that change the keystore still refuse; run the same merge again, which writes nothing more and renames it: %w", errCommitted, err)
	}
	return r, nil
}

// changes reports whether the merge r reports changed the floor.
func (r MergeReport) changes() bool {
	return r.Merged > 0 || r.Retired > 0 || len(r.Fenced) > 0 || r.raised > 0
}

// errMergeLiveFloor refuses a merge whose input is the data root's live
// floor, by name or by inode.
var errMergeLiveFloor = errors.New("the floor file to merge is the live floor itself: merging it changes nothing. Name the floor moved aside before the restore, keystore-floor.json.pre-restore")

// renameMerged renames the merged input in, through the directory
// descriptor readFloorAt judged, to keystore-floor.json.merged-<unix> in
// that directory, which clears the guard (errMergePending) when it is the
// data root's keystore-floor.json.pre-restore and records which file was
// merged. The name must still be the file read, and the new name must not
// exist: a file there is never replaced.
func (s *FileStore) renameMerged(in *mergeInput) error {
	named, err := in.dir.Lstat(in.base)
	if err != nil {
		return err
	}
	if !os.SameFile(named, in.info) {
		return fmt.Errorf("%s was replaced during the merge", in.base)
	}
	to := fmt.Sprintf("%s.merged-%d", floorName, s.now().Unix())
	if _, err := in.dir.Lstat(to); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s already exists", to)
	}
	if err := in.dir.Rename(in.base, to); err != nil {
		return err
	}
	return syncDir(in.dir)
}

// checkMergeInput refuses a merge of from into live, the floor read under
// keystore-lock, that cannot be the restore's: an absent live floor (the
// saved floor was never put back, and merging into nothing would write the
// moved-aside floor's burials alone, with no live records), a from whose
// highest delete sequence is below live's (from is older than the floor it
// would merge into: the restored floor, most likely, not the one moved
// aside), and a from equal to live (the same floor merged into itself:
// parseFloor accepts one encoding per floor, so equal floors are
// byte-identical files, up to the trailing newline).
func checkMergeInput(live, from floor) error {
	if live == nil {
		return errors.New("the live keystore floor is absent, so there is nothing to merge into: restore the saved keystore-floor.json first, with install -o root -g wheel -m 0644 as docs/user/keys.md describes, then run the merge again")
	}
	if a, l := from.lastDeleted(), live.lastDeleted(); a < l {
		return fmt.Errorf("the floor file to merge records deletions older than the live floor's (its newest deletion is %d, the live floor's %d): it is not the floor moved aside before the restore, which is never older than the restored one. Check that you named keystore-floor.json.pre-restore, not the restored floor", a, l)
	}
	if floorsSame(live, from) {
		return errors.New("the floor file to merge is the live floor itself, byte for byte: merging it changes nothing. Name the floor moved aside before the restore, keystore-floor.json.pre-restore")
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
// info, its base name, and the directory it was judged in, kept open so the
// rename goes through the same descriptor.
type mergeInput struct {
	fl   floor
	info fs.FileInfo
	dir  *os.Root
	base string
}

// close closes the input's directory; the rename is fsynced by renameMerged.
func (in *mergeInput) close() { _ = in.dir.Close() }

// readFloorAt reads and parses the floor file at path, returning it with
// the file's info and its judged directory, which the caller closes, judged as the live
// floor is: a regular file, not a symlink, owned by root (floorUID), not
// group- or other-writable, and at most maxFloorSize, in a directory owned
// by root and not group- or other-writable, judged on its descriptor. An absent file is an
// error: the merge has nothing to merge.
func (s *FileStore) readFloorAt(path string) (*mergeInput, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("the floor file to merge must be an absolute, clean path")
	}
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = dir.Close() // refused; nothing written
		}
	}()
	// The directory is judged on the opened descriptor as the data root
	// is: one another user could write lets them swap the file in.
	opened, err := dir.Stat(".")
	if err != nil {
		return nil, err
	}
	if err := s.floorOwned(opened); err != nil {
		return nil, fmt.Errorf("%w: the directory holding the floor file to merge: %w", errFloorUntrusted, err)
	}
	base := filepath.Base(path)
	// os.Root resolves a symlink it is asked to open, so it is refused by
	// name first; the open below is O_NOFOLLOW, so one swapped in after this
	// fails it.
	if named, err := dir.Lstat(base); err == nil && !named.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: the floor file to merge has mode %s", errFloorUntrusted, named.Mode())
	}
	b, fi, err := readFile(dir, base, int64(floorSizeLimit))
	if errors.Is(err, errBadFile) {
		return nil, fmt.Errorf("%w: the floor file to merge: %w", errFloorUntrusted, err)
	}
	if err != nil {
		return nil, err
	}
	if err := s.floorOwned(fi); err != nil {
		return nil, fmt.Errorf("%w: the floor file to merge: %w", errFloorUntrusted, err)
	}
	fl, err := parseFloor(b)
	if err != nil {
		return nil, err
	}
	ok = true
	return &mergeInput{fl: fl, info: fi, dir: dir, base: base}, nil
}

// merge adds to fl every burial in from that fl lacks, oldest (lowest
// Deleted) first, each at one more than the highest delete sequence in fl,
// so the merged burials keep their order and stay newer than fl's own. A
// generation fl holds live under the name is buried as well, its live record
// cleared (BuriedLive), unless keep names the entry (Kept); fl's other live
// records are kept. Then, by name, each live generation in from that fl
// neither holds live nor buries is buried after them (Retired), unless keep
// names the entry and fl holds no live record of it (keep keeps the restored
// generation, never a second one). A live generation in from that fl holds
// live at a sequence at or below from's gets a high-water mark (below)
// (Fenced). At maxBuriedPerName, add drops the name's oldest, returned. It
// does not prune: update does.
//
// ptrs is the authenticated restored pointer sequence of each name it
// fences (restoredPointers), or nil. A restored live record below
// its pointer, and not at or below its own high-water mark, is raised to the
// pointer first (counted in raised), so the restored entry is never inside
// the fence. The fence mark is one above the higher of the moved-aside
// record's sequence and mark, so a pre-restore pointer one past a moved-aside
// floor that lagged it is refused too; at the sequence limit it saturates.
func (fl floor) merge(from floor, keep map[string]bool, ptrs map[string]uint64) (MergeReport, []pruned) {
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
	// last is the highest delete sequence in fl, kept as each burial lands.
	last := fl.lastDeleted()
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
		if dropped, ok := f.add(burial{Generation: g, Deleted: last}); ok {
			out = append(out, pruned{name: name, generation: dropped.Generation})
		}
		fl[name] = f
	}
	kept, buriedLive, fenced := map[string]bool{}, map[string]bool{}, map[string]bool{}
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
				f.Seq, f.HighWater = p, 0
				fl[name] = f
				r.raised++
			}
			hw := max(a.Seq, a.HighWater)
			if hw < math.MaxUint64 {
				hw++
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
			// generation retired whatever keep says.
			kept[name] = true
			continue
		}
		add(name, a.Generation)
		r.Retired++
	}
	r.BuriedLive, r.Kept, r.Fenced = sortedNames(buriedLive), sortedNames(kept), sortedNames(fenced)
	return r, out
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

// restoredPointers authenticates, under the master, the current pointer of
// each entry live (the floor read under keystore-lock) holds live under the
// generation from holds live too: the names a fence can apply to. It returns
// each authenticated pointer's sequence by name, and, sorted, each candidate
// whose pointer did not authenticate (no master, no entry, another
// generation, or a refused record). It takes no keystore/.lock (see
// mergeFloor) and writes nothing; it stops with ctx's error.
func (s *FileStore) restoredPointers(ctx context.Context, live, from floor) (map[string]uint64, []string, error) {
	var names []string
	for name, a := range from {
		if f := live[name]; a.live() && f.live() && f.Generation == a.Generation {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil, nil
	}
	sort.Strings(names)
	entries, err := s.openDir(s.dir, false)
	if err != nil {
		return nil, names, nil
	}
	defer func() { _ = entries.Close() }() // read-only
	k, err := s.loadMaster()
	if err != nil {
		return nil, names, nil
	}
	defer k.wipe()
	ptrs := map[string]uint64{}
	var unverified []string
	for i, name := range names {
		if err := loopCtx(ctx, i); err != nil {
			return nil, nil, err
		}
		e, err := openEntry(entries, name, live)
		if err != nil {
			unverified = append(unverified, name)
			continue
		}
		_, seq, perr := e.pointer(k)
		same := hex.EncodeToString(e.generation[:]) == live[name].Generation
		e.close()
		if perr != nil || !same {
			unverified = append(unverified, name)
			continue
		}
		ptrs[name] = seq
	}
	return ptrs, unverified, nil
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
