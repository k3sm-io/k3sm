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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
)

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
	// Kept names, sorted, each entry the keep set named whose live
	// generation the merge would otherwise have buried: it stays live, the
	// entry restored on purpose.
	Kept []string
	// Dropped names, sorted and with repeats, each burial the write dropped
	// to stay within the floor's caps (the per-name cap and the tombstone
	// budget): a copy of it put back is accepted again.
	Dropped []string
}

// MergeFloor merges every burial the floor file at path records (the live
// floor moved aside before a restore) into the live floor, which a restore
// has just replaced with the one saved beside the backup, so the deletions
// recorded after the backup survive the restore (docs/design/keystore.md §
// "Pointer sequence and floor", "Restoring with the saved floor"). The file
// is read as the floor is, judged on its descriptor (a regular file owned by
// root and not group- or other-writable, under maxFloorSize) and parsed by
// parseFloor. Under keystore-lock and then keystore/.lock (§ Concurrency) it
// adds each burial the live floor lacks, in the order the file buried them.
// A generation the live floor holds live is buried too (BuriedLive): it was
// deleted after the backup, so the merge fails closed, unless keep names
// the entry, whose restored generation then stays live (Kept). keep holds
// entry names, each checked as a name is. The write is pruned as every
// floor write is, and each burial it drops is logged at Warn and reported.
func (s *FileStore) MergeFloor(ctx context.Context, path string, keep []string) (MergeReport, error) {
	r, err := s.mergeFloor(ctx, path, keep)
	if err != nil {
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
	from, err := s.readFloorAt(path)
	if err != nil {
		return r, err
	}
	if err := s.checkFloorWritable(); err != nil {
		return r, err
	}
	fdir, _, err := s.lockFloor(ctx)
	if err != nil {
		return r, err
	}
	defer fdir.unlock()
	_, done, err := s.openLocked(ctx, false, true)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// No entries directory, so no .lock to take.
	case err != nil:
		return r, err
	default:
		defer done()
	}
	var capDropped []pruned
	_, dropped, err := fdir.updatePruned(func(fl floor) bool {
		r, capDropped = fl.merge(from, kept)
		return r.Merged > 0
	})
	if err != nil {
		return MergeReport{}, err
	}
	for _, p := range append(capDropped, dropped...) {
		r.Dropped = append(r.Dropped, p.name)
	}
	sort.Strings(r.Dropped)
	logPruned(capDropped)
	for _, name := range r.BuriedLive {
		slog.Warn("keystore floor: the moved-aside floor records the restored generation of this entry as deleted, so the merge buried it and the restored entry is refused; rm removes its directory", "name", name)
	}
	return r, nil
}

// readFloorAt reads and parses the floor file at path, judged as the live
// floor is: a regular file, not a symlink, owned by root (floorUID), not
// group- or other-writable, and at most maxFloorSize. An absent file is an
// error: the merge has nothing to merge.
func (s *FileStore) readFloorAt(path string) (floor, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("the floor file to merge must be an absolute, clean path")
	}
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }() // read-only
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
	return fl, nil
}

// merge adds to fl every burial in from that fl lacks, oldest (lowest
// Deleted) first, each at one more than the highest delete sequence in fl,
// so the merged burials keep their order and stay newer than fl's own. A
// generation fl holds live under the name is buried as well, its live record
// cleared (BuriedLive), unless keep names the entry (Kept); fl's other live
// records are kept. At maxBuriedPerName, add drops the name's oldest,
// returned. It does not prune: update does.
func (fl floor) merge(from floor, keep map[string]bool) (MergeReport, []pruned) {
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
			f.Generation, f.Seq = "", 0
		}
		if dropped, ok := f.add(burial{Generation: g, Deleted: last}); ok {
			out = append(out, pruned{name: name, generation: dropped.Generation})
		}
		fl[name] = f
		r.Merged++
	}
	kept, buriedLive := map[string]bool{}, map[string]bool{}
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
	}
	r.BuriedLive, r.Kept = sortedNames(buriedLive), sortedNames(kept)
	return r, out
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
