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
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The tests for burials rm writes while a restore is unfinished (guard-era
// burials) under a floor merge that has to prune: the merge never drops one
// silently, and --accept-drops is the exit when rm cannot make room.

// guardEraSetup puts entry k and entry other, takes the restored floor, and
// writes a moved-aside floor holding it plus n burials of fresh names, then
// deletes k under the guard. It returns the store, the server dir, k's
// generation and the moved-aside floor.
func guardEraSetup(t *testing.T, n int) (*FileStore, string, string, floor) {
	t.Helper()
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "other", KindOpaque, []byte("v"))
	gen := generationOf(t, server, "k")
	aside := maps.Clone(floorOf(t, server))
	for i := range n {
		aside[fmt.Sprintf("gone-%02d", i)] = floorEntry{Buried: []burial{{Generation: mgen(100 + i), Deleted: uint64(i + 1)}}}
	}
	writeAsideFloor(t, server, aside)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete under the guard: %v", err)
	}
	return s, server, gen, aside
}

// TestGuardEraBurialSurvivesPressuredMerge (U192): a burial rm wrote under
// the guard is newer than every burial the merge carries from the floor
// moved aside, so a merge whose write must prune drops the merged ones
// first and never the guard-era one.
func TestGuardEraBurialSurvivesPressuredMerge(t *testing.T) {
	ctx := context.Background()
	s, server, gen, aside := guardEraSetup(t, 20)
	// A tombstone budget one byte short of the merged floor's: the write
	// has to drop one burial.
	probe := floorOf(t, server)
	probe.merge(aside, nil, nil)
	setFloorLimits(t, smallFloorSize, probe.deadSize()-1)
	_, err := s.MergeFloor(ctx, MergeOptions{})
	if !errors.Is(err, errFloorFull) {
		t.Fatalf("MergeFloor that must drop a merged burial: %v, want errFloorFull", err)
	}
	if fl := floorOf(t, server); !fl["k"].buries(gen) {
		t.Fatalf("k after the refused merge = %+v, want the guard-era burial of %s kept", fl["k"], gen)
	}
	r, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: true})
	if err != nil || len(r.Dropped) != 1 || r.Dropped[0] != "gone-00" {
		t.Fatalf("MergeFloor --accept-drops = %+v, %v; want the oldest merged burial, gone-00's, dropped", r, err)
	}
	fl := floorOf(t, server)
	if !fl["k"].buries(gen) {
		t.Fatalf("k after the pressured merge = %+v, want the guard-era burial of %s kept", fl["k"], gen)
	}
	for _, b := range fl["k"].burials() {
		if b.Deleted > guardEraSeq {
			t.Fatalf("k's burial %+v after the merge, want every burial renumbered below guardEraSeq", b)
		}
	}
	if err := s.MergePending(); err != nil {
		t.Fatalf("MergePending after --accept-drops: %v, want the guard cleared", err)
	}
}

// TestGuardEraTombstoneBudget (U192): with the tombstone budget binding
// (a floor size far above it), a merge that would drop a deletion since the
// backup is refused naming the budget and --accept-drops, not keys rm; an
// rm under the guard cannot help, and the next merge is refused the same
// way; --accept-drops then writes it, reports each burial dropped (the
// oldest merged ones, never the guard-era ones) and clears the guard.
func TestGuardEraTombstoneBudget(t *testing.T) {
	ctx := context.Background()
	s, server, gen, aside := guardEraSetup(t, 20)
	probe := floorOf(t, server)
	probe.merge(aside, nil, nil)
	setFloorLimits(t, smallFloorSize, probe.deadSize()-1)
	refused := func(when string) {
		t.Helper()
		_, err := s.MergeFloor(ctx, MergeOptions{})
		if !errors.Is(err, errFloorFull) || !strings.Contains(err.Error(), "tombstone budget binds") || !strings.Contains(err.Error(), "--accept-drops") || strings.Contains(err.Error(), "keys rm") {
			t.Fatalf("MergeFloor %s: %v, want errFloorFull naming the tombstone budget and --accept-drops, not keys rm", when, err)
		}
		if err := s.MergePending(); err == nil {
			t.Fatalf("MergePending %s: nil, want the guard in place", when)
		}
	}
	refused("over the budget")
	if err := s.Delete(ctx, "other"); err != nil {
		t.Fatalf("Delete under the guard: %v", err)
	}
	otherGen := floorOf(t, server)["other"].burials()[0].Generation
	refused("after an rm under the guard")
	r, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: true})
	if err != nil || len(r.Dropped) == 0 {
		t.Fatalf("MergeFloor --accept-drops = %+v, %v; want it written with drops reported", r, err)
	}
	fl := floorOf(t, server)
	if !fl["k"].buries(gen) || !fl["other"].buries(otherGen) {
		t.Fatalf("after --accept-drops k = %+v, other = %+v; want both guard-era burials kept", fl["k"], fl["other"])
	}
	for _, name := range r.Dropped {
		if !strings.HasPrefix(name, "gone-") {
			t.Fatalf("dropped %v, want only merged burials dropped", r.Dropped)
		}
	}
	if err := s.MergePending(); err != nil {
		t.Fatalf("MergePending after --accept-drops: %v, want the guard cleared", err)
	}
}

// TestGuardEraBurialPerNameCap (U192): at the per-name cap the merge drops
// the name's oldest, and a burial rm wrote under the guard is the newest:
// the merge refuses rather than drop a burial it adds, naming the per-name
// cap and --accept-drops, not keys rm, which cannot help.
func TestGuardEraBurialPerNameCap(t *testing.T) {
	ctx := context.Background()
	setSeam(t, &buriedPerNameLimit, smallBuriedPerName)
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "other", KindOpaque, []byte("v"))
	gen := generationOf(t, server, "k")
	aside := maps.Clone(floorOf(t, server))
	e := aside["k"]
	for i := range smallBuriedPerName {
		e.Buried = append(e.Buried, burial{Generation: mgen(100 + i), Deleted: uint64(i + 1)})
	}
	aside["k"] = e
	writeAsideFloor(t, server, aside)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete under the guard: %v", err)
	}
	_, err := s.MergeFloor(ctx, MergeOptions{})
	if !errors.Is(err, errFloorFull) || !strings.Contains(err.Error(), "per-name cap") || !strings.Contains(err.Error(), "--accept-drops") || strings.Contains(err.Error(), "keys rm") {
		t.Fatalf("MergeFloor at the per-name cap: %v, want errFloorFull naming the per-name cap and --accept-drops, not keys rm", err)
	}
	if fl := floorOf(t, server); !fl["k"].buries(gen) {
		t.Fatalf("k after the refused merge = %+v, want the guard-era burial kept", fl["k"])
	}
	r, err := s.MergeFloor(ctx, MergeOptions{AcceptDrops: true})
	if err != nil || len(r.Dropped) != 1 || r.Dropped[0] != "k" {
		t.Fatalf("MergeFloor --accept-drops at the cap = %+v, %v; want one of k's merged burials dropped", r, err)
	}
	fl := floorOf(t, server)
	if !fl["k"].buries(gen) || fl["k"].buries(mgen(100)) {
		t.Fatalf("k after --accept-drops = %+v, want the guard-era burial kept and the oldest merged one dropped", fl["k"])
	}
}

// TestPendingMergeDeleteNeedsLiveFloor (U192): with the guard set and the
// live floor absent (the saved floor not put back yet), Delete refuses,
// naming the install, and writes no floor: a floor it created would hold
// its burial alone, and the merge would take it for the restored one.
func TestPendingMergeDeleteNeedsLiveFloor(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	if err := os.Rename(floorPath(server), floorPath(server)+".pre-restore"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "k"); err == nil || !strings.Contains(err.Error(), "install the saved keystore-floor.json first") {
		t.Fatalf("Delete with the guard set and no live floor: %v, want a refusal naming the install", err)
	}
	if _, err := os.Lstat(floorPath(server)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live floor after the refused Delete: %v, want it still absent", err)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); err != nil {
		t.Fatalf("k's directory after the refused Delete: %v, want it left", err)
	}
}

// TestMergeFloorRefusesRetiringEverything (U192): a merge onto a live floor
// that holds none of the moved-aside floor's live records live would retire
// every one of them, so it is refused, writing nothing, unless --keep
// covers one of them.
func TestMergeFloorRefusesRetiringEverything(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	putFloorFile(t, server, floor{"x": {Generation: mgen(9), Seq: 1}})
	writeAsideFloor(t, server, floor{"a": {Generation: mgen(1), Seq: 1}, "b": {Generation: mgen(2), Seq: 1}})
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeFloor(ctx, MergeOptions{}); err == nil || !strings.Contains(err.Error(), "would retire every entry") {
		t.Fatalf("MergeFloor retiring every moved-aside live record: %v, want a refusal", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); string(after) != string(before) {
		t.Fatalf("floor after the refused merge changed: %s", after)
	}
	r, err := s.MergeFloor(ctx, MergeOptions{Keep: []string{"a"}})
	if err != nil || !slices.Equal(r.Retired, []string{"b"}) || !slices.Equal(r.Kept, []string{"a"}) {
		t.Fatalf("MergeFloor keeping a = %+v, %v; want a kept and b retired", r, err)
	}
}
