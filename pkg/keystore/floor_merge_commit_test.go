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
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// failStepOnce makes s's next step named name fail once.
func failStepOnce(s *FileStore, name string) {
	fail := true
	s.step = func(n string) error {
		if n == name && fail {
			fail = false
			return errors.New("injected")
		}
		return nil
	}
}

// readRecordFile parses the retired record at name in s's data root.
func readRecordFile(t *testing.T, s *FileStore, name string) retiredRecord {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.dataRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := parseRetired(b)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// mergedRecords is each keystore-floor.json.merged-<unix>.retired in s's
// data root.
func mergedRecords(t *testing.T, s *FileStore) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(s.dataRoot, mergedPrefix+"*"+retiredSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// dropsSetup is a live floor and a moved-aside one whose merge drops the
// oldest burials it adds (name-00 first) to fit the tombstone budget.
func dropsSetup(t *testing.T, s *FileStore, server string) {
	t.Helper()
	putFloorFile(t, server, floor{"keep": {Generation: mgen(2), Seq: 1}})
	aside := floor{"keep": {Generation: mgen(2), Seq: 1}}
	for i := range 40 {
		aside[fmt.Sprintf("name-%02d", i)] = floorEntry{Buried: []burial{{Generation: mgen(100 + i), Deleted: uint64(i + 1)}}}
	}
	// Each is retired, a burial more, which takes the merged floor over
	// the tombstone budget.
	for i := range 10 {
		aside[fmt.Sprintf("ret-%02d", i)] = floorEntry{Generation: mgen(300 + i), Seq: 1}
	}
	writeAsideFloor(t, server, aside)
	setFloorLimits(t, smallFloorSize, 3100)
}

// TestFloorMergeRerunAfterAcceptDrops (U192): a committed --accept-drops
// merge whose tree move failed prunes burials it added; a rerun, with or
// without the flag, never plans the floor again (the pending retired record
// names the floor written), so it leaves the floor bytes identical, finishes
// the move and reports the first run's drops.
func TestFloorMergeRerunAfterAcceptDrops(t *testing.T) {
	ctx := context.Background()
	for _, again := range []bool{true, false} {
		t.Run(fmt.Sprintf("rerun accept-drops %v", again), func(t *testing.T) {
			s, server := newTestStore(t)
			dropsSetup(t, s, server)
			stageTree(t, s)
			failStepOnce(s, "merge tree rename")
			r, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: true})
			if !Committed(err) || len(r.Dropped) == 0 {
				t.Fatalf("MergeFloor --accept-drops with the move failing = %+v, %v; want committed with drops", r, err)
			}
			written, err := os.ReadFile(floorPath(server))
			if err != nil {
				t.Fatal(err)
			}
			r2, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: again})
			if err != nil || !r2.AlreadyMerged || !slices.Equal(r2.Dropped, r.Dropped) {
				t.Fatalf("rerun = %+v, %v; want already merged with the first run's drops %v", r2, err, r.Dropped)
			}
			if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, written) {
				t.Fatalf("the floor after the rerun differs from the one the first run wrote:\n%s\nwant\n%s", after, written)
			}
			if s.MergePending() != nil {
				t.Fatal("the rerun left the guard")
			}
		})
	}
}

// TestFloorMergeKeptOnlyWritesRecord (U192): a first run whose only change
// is a --keep writes its retired record, renamed with the input, naming the
// kept entry.
func TestFloorMergeKeptOnlyWritesRecord(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	putFloorFile(t, server, floor{"a": {Generation: mgen(1), Seq: 1}})
	writeAsideFloor(t, server, floor{"a": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
	r, err := mergeStaged(t, s, ctx, MergeOptions{Keep: []string{"a"}})
	if err != nil || !slices.Equal(r.Kept, []string{"a"}) {
		t.Fatalf("kept-only merge = %+v, %v; want a kept", r, err)
	}
	recs := mergedRecords(t, s)
	if len(recs) != 1 {
		t.Fatalf("retired records after a kept-only merge: %v, want one", recs)
	}
	if rec := readRecordFile(t, s, filepath.Base(recs[0])); !slices.Equal(rec.Kept, []string{"a"}) {
		t.Fatalf("the record = %+v, want a kept", rec)
	}
}

// TestFloorMergePointerOnlyRefusalNotCommitted (U192): a first run whose
// only change is raising a restored record to its authenticated pointer,
// with the staged tree refused, writes nothing and says so: it is not
// reported as committed.
func TestFloorMergePointerOnlyRefusalNotCommitted(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v1"))
	mustRotate(t, s, "k", "v2")
	mustRotate(t, s, "k", "v3")
	// The restored floor lags k's pointer (3) by one; the moved-aside
	// floor is older still, so with no pointer the merge changes nothing.
	fl := floorOf(t, server)
	e := fl["k"]
	e.Seq, e.HighWater = 2, 0
	fl["k"] = e
	putFloorFile(t, server, fl)
	e.Seq = 1
	aside := maps.Clone(fl)
	aside["k"] = e
	writeAsideFloor(t, server, aside)
	stageTree(t, s)
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if p := planMerge(fl, aside, nil, nil, nil); p.r.changes() {
		t.Fatalf("the plan with no pointer = %+v, want no change", p.r)
	}
	if p := planMerge(fl, aside, nil, map[string]uint64{"k": 3}, nil); p.r.raised != 1 || p.r.Merged+len(p.r.Fenced)+len(p.r.Retired) != 0 {
		t.Fatalf("the plan = %+v, want a raise only", p.r)
	}
	writeStaged(t, s, "k/bogus", nil)
	_, err = s.MergeFloor(ctx, MergeOptions{})
	if err == nil || Committed(err) || !strings.Contains(err.Error(), "nothing is written") {
		t.Fatalf("pointer-only merge with the staged tree refused: %v; want a refusal, not committed, saying nothing is written", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, before) {
		t.Fatal("the refused merge wrote the floor")
	}
}

// TestFloorMergeRerunKeepsRetiredSets (U192): an rm under the guard before
// the merge is merged; once the merge is written (its tree move failed) an
// rm still succeeds, and the rerun keeps its burial, writes no floor and
// keeps the first run's retired sets in the record renamed with the input.
func TestFloorMergeRerunKeepsRetiredSets(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "other", KindOpaque, []byte("v"))
	mustPut(t, s, "third", KindOpaque, []byte("v"))
	aside := floorOf(t, server)
	aside["late"] = floorEntry{Generation: mgen(9), Seq: 1}
	writeAsideFloor(t, server, aside)
	stageTree(t, s)
	if err := s.Delete(ctx, "other"); err != nil {
		t.Fatalf("Delete under the guard: %v", err)
	}
	failStepOnce(s, "merge tree rename")
	r, err := s.MergeFloor(ctx, MergeOptions{})
	if !Committed(err) || !slices.Equal(r.Retired, []string{"late"}) {
		t.Fatalf("MergeFloor with the move failing = %+v, %v; want committed with late retired", r, err)
	}
	if rec := readRecordFile(t, s, retiredPendingName); !slices.Equal(rec.Retired, []string{"late"}) {
		t.Fatalf("the pending record = %+v, want late retired", rec)
	}
	if err := s.Delete(ctx, "third"); err != nil {
		t.Fatalf("Delete with the merge written but not finished: %v, want it to succeed", err)
	}
	written, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.MergeFloor(ctx, MergeOptions{})
	if err != nil || !r.AlreadyMerged || !slices.Equal(r.Retired, []string{"late"}) {
		t.Fatalf("rerun = %+v, %v; want already merged reporting late retired", r, err)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, written) {
		t.Fatal("the rerun changed the floor")
	}
	recs := mergedRecords(t, s)
	if len(recs) != 1 {
		t.Fatalf("retired records: %v, want one", recs)
	}
	if rec := readRecordFile(t, s, filepath.Base(recs[0])); !slices.Equal(rec.Retired, []string{"late"}) {
		t.Fatalf("the record after the rerun = %+v, want the first run's late retired", rec)
	}
}

// TestFloorMergeRerunFloorChanged (U192): a pending record whose floor is
// neither the live one nor the one the merge read fails closed, committed,
// and changes nothing.
func TestFloorMergeRerunFloorChanged(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	dropsSetup(t, s, server)
	stageTree(t, s)
	failStepOnce(s, "merge tree rename")
	if _, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: true}); !Committed(err) {
		t.Fatalf("first run: %v, want committed", err)
	}
	fl := floorOf(t, server)
	fl["extra"] = floorEntry{Generation: mgen(7), Seq: 1}
	putFloorFile(t, server, fl)
	changed, _ := os.ReadFile(floorPath(server))
	_, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: true})
	if !Committed(err) || !strings.Contains(err.Error(), "never plans a written merge again") {
		t.Fatalf("rerun on a changed floor: %v, want a committed refusal", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, changed) {
		t.Fatal("the refused rerun wrote the floor")
	}
}

// TestFloorMergeUndoRecord (U192): --undo reads only the retired record
// whose input is the live floor: a stale record of another merge is
// refused, the matching one is used, and a record named for a later second
// (a clock stepped back) is never chosen for its name.
func TestFloorMergeUndoRecord(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	putFloorFile(t, server, floor{"a": {Generation: mgen(1), Seq: 1}})
	live, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	write := func(at int, input string, retired ...string) {
		b, err := marshalRetired(emptyFloors(t, retiredRecord{Input: input, Retired: retired}))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.dataRoot, fmt.Sprintf("%s%d%s", mergedPrefix, at, retiredSuffix)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func() (retiredRecord, error) {
		fdir, _, err := s.lockFloor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer fdir.unlock()
		return s.readRetired(fdir, sha256Hex(live))
	}
	write(2000, sha256Hex([]byte("an earlier cycle's input")), "stale")
	if _, err := read(); err == nil || !strings.Contains(err.Error(), "none of the 1") {
		t.Fatalf("readRetired with only a stale record: %v, want it refused", err)
	}
	// The matching record is named for an earlier second than the stale
	// one, as a clock stepped back between the merges leaves it.
	write(1000, sha256Hex(live), "mine")
	rec, err := read()
	if err != nil || !slices.Equal(rec.Retired, []string{"mine"}) {
		t.Fatalf("readRetired = %+v, %v; want the matching record", rec, err)
	}
}

// TestFloorMergeAbsentAsideTree (U192): with pre-restore.d present but no
// moved-aside tree in it, each entry the moved-aside floor holds live is
// reported unverified; with none live, nothing is.
func TestFloorMergeAbsentAsideTree(t *testing.T) {
	ctx := context.Background()
	t.Run("live entries", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("v"))
		aside := floorOf(t, server)
		aside["late"] = floorEntry{Generation: mgen(9), Seq: 1}
		writeAsideFloor(t, server, aside)
		r, err := mergeStaged(t, s, ctx, MergeOptions{DryRun: true})
		if err != nil || !slices.Equal(r.AsideUnverified, []string{"k", "late"}) {
			t.Fatalf("dry run with no moved-aside tree = %+v, %v; want k and late unverified", r, err)
		}
	})
	t.Run("no live entries", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("v"))
		writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
		r, err := mergeStaged(t, s, ctx, MergeOptions{DryRun: true})
		if err != nil || len(r.AsideUnverified) != 0 {
			t.Fatalf("dry run with no live moved-aside entry = %+v, %v; want nothing unverified", r, err)
		}
	})
}

// TestFloorMergeRerunAfterMoveNotUnverified (U192): a rerun after the tree
// moved into place but the input's rename failed reports no name
// unverified: it reads no staged pointer.
func TestFloorMergeRerunAfterMoveNotUnverified(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	at := s.now().Unix()
	var taken []string
	for i := range maxMergedTries + 2 {
		p := fmt.Sprintf("%s.merged-%d", floorPath(server), at+int64(i))
		if err := os.WriteFile(p, []byte("earlier\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		taken = append(taken, p)
	}
	r, err := s.MergeFloor(ctx, MergeOptions{})
	if !Committed(err) || len(r.Fenced) != 1 {
		t.Fatalf("MergeFloor with the merged names taken = %+v, %v; want committed with k fenced", r, err)
	}
	for _, p := range taken {
		remove(t, p)
	}
	r, err = s.MergeFloor(ctx, MergeOptions{})
	if err != nil || !r.AlreadyMerged || len(r.Unverified) != 0 || len(r.AsideUnverified) != 0 {
		t.Fatalf("rerun after the move = %+v, %v; want already merged with nothing unverified", r, err)
	}
}

// TestFloorMergeRemovedStagedNamed (U192): a refusal after the merge
// removed staged directories the merged floor refuses names them and never
// says nothing is written.
func TestFloorMergeRemovedStagedNamed(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("v"))
	mustPut(t, s, "b", KindOpaque, []byte("v"))
	live := floorOf(t, server)
	aside := floor{}
	for i, n := range []string{"a", "b"} {
		aside[n] = floorEntry{Buried: []burial{{Generation: live[n].Generation, Deleted: uint64(i + 1)}}}
	}
	writeAsideFloor(t, server, aside)
	stageTree(t, s)
	failStepOnce(s, "merge remove staged b")
	_, err := s.MergeFloor(ctx, MergeOptions{})
	if err == nil || Committed(err) || !strings.Contains(err.Error(), "staged directories of a") || strings.Contains(err.Error(), "nothing is written") {
		t.Fatalf("MergeFloor failing after removing a: %v; want a refusal naming a, never \"nothing is written\"", err)
	}
}

// TestFloorMergeMoveSyncCommitted (U192): a directory fsync that fails
// after the staged tree's rename is returned, committed.
func TestFloorMergeMoveSyncCommitted(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	orig := syncMovedDir
	t.Cleanup(func() { syncMovedDir = orig })
	syncMovedDir = func(*os.File) error { return errors.New("injected") }
	_, err := s.MergeFloor(ctx, MergeOptions{})
	if !Committed(err) || !errors.Is(err, errMovedNotSynced) {
		t.Fatalf("MergeFloor with the fsync after the move failing: %v, want committed", err)
	}
	syncMovedDir = orig
	if r, err := s.MergeFloor(ctx, MergeOptions{}); err != nil || !r.AlreadyMerged {
		t.Fatalf("rerun = %+v, %v; want already merged", r, err)
	}
}

// TestFloorMergeRemovesAsideBuriedStaged (U192): a burial the merge adds
// from the moved-aside floor for the generation staged under a name the
// restored floor holds no live record of removes that staged directory.
func TestFloorMergeRemovesAsideBuriedStaged(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "other", KindOpaque, []byte("v"))
	live := floorOf(t, server)
	gen := live["k"].Generation
	delete(live, "k")
	putFloorFile(t, server, live)
	aside := floorOf(t, server)
	aside["k"] = floorEntry{Buried: []burial{{Generation: gen, Deleted: 1}}}
	writeAsideFloor(t, server, aside)
	stageTree(t, s)
	if _, err := s.MergeFloor(ctx, MergeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "k")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("k's directory after the merge: %v, want it removed", err)
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "other")); err != nil {
		t.Fatalf("other's directory after the merge: %v, want it moved into place", err)
	}
}

// TestFloorMergeRemovesDroppedStaged (U192): the staged directory of a
// generation whose burial --accept-drops pruned is removed, so a copy of it
// is not moved into place.
func TestFloorMergeRemovesDroppedStaged(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	dropsSetup(t, s, server)
	stageTree(t, s)
	if err := os.Mkdir(stagePath(s, stagedTreeName, "name-00"), 0o700); err != nil {
		t.Fatal(err)
	}
	giveToService(t, stagePath(s, stagedTreeName, "name-00"))
	writeStaged(t, s, "name-00/"+generationName, []byte(mgen(100)+"\n"))
	r, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: true})
	if err != nil && !Committed(err) || !slices.Contains(r.Dropped, "name-00") {
		t.Fatalf("MergeFloor --accept-drops = %+v, %v; want name-00 dropped", r, err)
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "name-00")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("name-00's directory after the merge: %v, want it removed", err)
	}
}

// TestFloorMergeRefusesTwoDevices (U192): pre-restore.d on another device
// than the keystore's directory is refused before anything is written.
func TestFloorMergeRefusesTwoDevices(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	orig := statDev
	t.Cleanup(func() { statDev = orig })
	parent := filepath.Dir(s.dir)
	statDev = func(f *os.File) (uint64, error) {
		if f.Name() == parent {
			return 1, nil
		}
		return 2, nil
	}
	before, _ := os.ReadFile(floorPath(server))
	if _, err := s.MergeFloor(ctx, MergeOptions{}); err == nil || !strings.Contains(err.Error(), "different devices") {
		t.Fatalf("MergeFloor across devices: %v, want it refused", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, before) {
		t.Fatal("the refused merge wrote the floor")
	}
}
