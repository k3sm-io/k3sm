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

// TestPendingMergeDeleteMakesRoom (U192): a merge refused because the floor
// size binds names keys rm and leaves the guard in place, and rm still runs
// under it. Each burial rm writes then is a guard-era one, numbered above
// guardEraSeq, which the merge keeps like the deletions it carries over: a
// live record freed costs a burial, so the merge run again is still
// refused, and --accept-drops writes it, dropping only burials it carries
// over, keeping every guard-era one, and clears the guard.
func TestPendingMergeDeleteMakesRoom(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	const live, gone, removed = 40, 20, 12
	for i := range live {
		mustPut(t, s, fmt.Sprintf("e-%02d", i), KindOpaque, []byte("v"))
	}
	restored := floorOf(t, server)
	// The moved-aside floor holds every restored entry, one deletion, and
	// live generations the restored floor lacks, each retired by the merge.
	aside := maps.Clone(restored)
	aside["old"] = floorEntry{Buried: []burial{{Generation: mgen(1), Deleted: 1}}}
	for i := range gone {
		aside[fmt.Sprintf("gone-%02d", i)] = floorEntry{Generation: mgen(100 + i), Seq: 1}
	}
	writeAsideFloor(t, server, aside)
	probe := maps.Clone(restored)
	probe.merge(aside, nil, nil)
	b, err := marshalFloor(probe)
	if err != nil {
		t.Fatal(err)
	}
	// A floor a little smaller than the merged one: the merge has to drop
	// burials it adds, and there are no others to drop.
	size := len(b) - 200
	setFloorLimits(t, size, size)
	_, err = mergeStaged(t, s, ctx, MergeOptions{})
	if !errors.Is(err, errFloorFull) || !strings.Contains(err.Error(), "sudo k3sm keys rm system/<name> --yes") || !strings.Contains(err.Error(), "run the merge again") {
		t.Fatalf("MergeFloor over a full floor: %v, want errFloorFull naming keys rm and running the merge again", err)
	}
	for i := range removed {
		if err := s.Delete(ctx, fmt.Sprintf("e-%02d", i)); err != nil {
			t.Fatalf("Delete with a merge pending: %v, want nil", err)
		}
	}
	gens := map[string]string{}
	for name, e := range floorOf(t, server) {
		for _, b := range e.burials() {
			if b.Deleted <= guardEraSeq {
				t.Fatalf("%s's burial %+v under the guard, want it above guardEraSeq", name, b)
			}
			gens[name] = b.Generation
		}
	}
	if len(gens) != removed {
		t.Fatalf("guard-era burials %v, want one per rm", gens)
	}
	if _, err := mergeStaged(t, s, ctx, MergeOptions{}); !errors.Is(err, errFloorFull) {
		t.Fatalf("MergeFloor after the deletes: %v, want it still refused: each rm's burial is kept", err)
	}
	r, err := mergeStaged(t, s, ctx, MergeOptions{AcceptDrops: true})
	if err != nil {
		t.Fatalf("MergeFloor --accept-drops after the deletes: %v", err)
	}
	if err := s.MergePending(); err != nil {
		t.Fatalf("MergePending after the merge: %v, want the guard cleared", err)
	}
	fl := floorOf(t, server)
	for name, g := range gens {
		if !fl[name].buries(g) || slices.Contains(r.Dropped, name) {
			t.Errorf("%s after the merge = %+v (dropped %v), want its guard-era burial kept", name, fl[name], r.Dropped)
		}
	}
	for i := range gone {
		name := fmt.Sprintf("gone-%02d", i)
		if !fl[name].buries(mgen(100+i)) && !slices.Contains(r.Dropped, name) {
			t.Errorf("%s after the merge = %+v, want its moved-aside generation buried or reported dropped", name, fl[name])
		}
	}
	mustCurrent(t, s, fmt.Sprintf("e-%02d", removed), "v")
}

// TestPendingMergeDeleteBurialSurvivesMerge (U192): an rm run while the
// merge is pending buries the restored generation, and the merge keeps that
// burial, so a copy of the deleted entry put back after it is refused.
func TestPendingMergeDeleteBurialSurvivesMerge(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	mustPut(t, s, "other", KindOpaque, []byte("two"))
	gen := generationOf(t, server, "k")
	old := saveEntry(t, server, "k", generationName, "v1", currentName)
	giveToService(t, old, filepath.Join(old, generationName), filepath.Join(old, "v1"), filepath.Join(old, currentName))
	aside := floorOf(t, server)
	aside["gone"] = floorEntry{Buried: []burial{{Generation: mgen(1), Deleted: 1}}}
	writeAsideFloor(t, server, aside)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete with a merge pending: %v, want nil", err)
	}
	if _, err := mergeStaged(t, s, ctx, MergeOptions{}); err != nil {
		t.Fatalf("MergeFloor after the delete: %v", err)
	}
	if fl := floorOf(t, server); !fl["k"].buries(gen) || fl["k"].live() {
		t.Fatalf("k after the merge = %+v, want generation %s buried and no live record", fl["k"], gen)
	}
	putBack(t, server, old, "k")
	if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "records as deleted") {
		t.Fatalf("Current of the put-back copy: %v, want ErrCorrupt naming the burial", err)
	}
	mustCurrent(t, s, "other", "two")
}

// TestPendingMergeDeleteKeepsPutRefused (U192): an rm under the guard does
// not lift it for the other verbs: Put, Rotate and Rewrap still refuse,
// naming keys floor merge, and the floor moved aside stays where it is.
func TestPendingMergeDeleteKeepsPutRefused(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	mustPut(t, s, "j", KindOpaque, []byte("one"))
	path := writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
	if err := s.Delete(ctx, "j"); err != nil {
		t.Fatalf("Delete with a merge pending: %v, want nil", err)
	}
	for verb, run := range map[string]func() error{
		"Put":    func() error { _, err := s.Put(ctx, "n", KindOpaque, []byte("v")); return err },
		"Rotate": func() error { _, err := s.Rotate(ctx, "k", []byte("two")); return err },
		"Rewrap": func() error { return s.Rewrap(ctx, rewrapKey(1)) },
	} {
		if err := run(); !errors.Is(err, errMergePending) || !strings.Contains(err.Error(), "keys floor merge") {
			t.Errorf("%s after a Delete with a merge pending: %v, want errMergePending naming keys floor merge", verb, err)
		}
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the floor moved aside after the Delete: %v, want it in place", err)
	}
}
