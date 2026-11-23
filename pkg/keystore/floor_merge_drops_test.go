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
	"strings"
	"testing"
)

// buriedLiveSetup puts entry k and entry other, and writes a moved-aside
// floor that buries k's restored generation (k deleted since the backup)
// and holds n entries live that the restored floor does not record, which
// the merge retires after it buries k, then sets the tombstone budget one
// byte short of the merged floor's, so the write's prune would drop k's
// burial first. It returns the store, the server dir and k's generation.
func buriedLiveSetup(t *testing.T, n int) (*FileStore, string, string) {
	t.Helper()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "other", KindOpaque, []byte("v"))
	gen := generationOf(t, server, "k")
	restored := floorOf(t, server)
	aside := maps.Clone(restored)
	aside["k"] = floorEntry{Buried: []burial{{Generation: gen, Deleted: 1}}}
	for i := range n {
		aside[fmt.Sprintf("new-%02d", i)] = floorEntry{Generation: mgen(100 + i), Seq: 1}
	}
	writeAsideFloor(t, server, aside)
	probe := maps.Clone(restored)
	probe.merge(aside, nil, nil)
	setFloorLimits(t, smallFloorSize, probe.deadSize()-1)
	return s, server, gen
}

// TestMergeFloorNeverDropsBuriedLive (U192): a merge whose write would drop
// the burial of a restored generation it buried live (deleted since the
// backup) is refused with and without --accept-drops, the dry run too,
// naming the entry and keys rm, with nothing written: the restored copy
// would otherwise be live again with nothing refusing it. An rm of the
// entry under the guard then lets --accept-drops go on.
func TestMergeFloorNeverDropsBuriedLive(t *testing.T) {
	ctx := context.Background()
	s, server, gen := buriedLiveSetup(t, 20)
	before := floorOf(t, server)
	for _, opts := range []MergeOptions{{}, {AcceptDrops: true}, {AcceptDrops: true, DryRun: true}, {DryRun: true}} {
		_, err := mergeStaged(t, s, ctx, opts)
		if !errors.Is(err, errFloorFull) || !strings.Contains(err.Error(), "k3sm keys rm") || !strings.Contains(err.Error(), "recorded for k,") {
			t.Fatalf("MergeFloor %+v dropping a buried-live burial: %v, want errFloorFull naming k and keys rm", opts, err)
		}
		if opts.AcceptDrops && !strings.Contains(err.Error(), "--accept-drops never drops") {
			t.Fatalf("MergeFloor %+v: %v, want it to say --accept-drops never drops it", opts, err)
		}
	}
	if !floorsEqual(floorOf(t, server), before) || s.MergePending() == nil {
		t.Fatal("a refused merge wrote the floor or cleared the guard")
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete under the guard: %v", err)
	}
	r, err := mergeStaged(t, s, ctx, MergeOptions{AcceptDrops: true})
	if err != nil {
		t.Fatalf("MergeFloor --accept-drops after rm: %+v, %v", r, err)
	}
	if fl := floorOf(t, server); !fl["k"].buries(gen) {
		t.Fatalf("k after the merge = %+v, want its rm burial kept", fl["k"])
	}
}

// TestMergeFloorRefusesDroppingRestoredBurials (U192): without
// --accept-drops a merge whose write would drop any burial is refused,
// one the restored floor already held included, with nothing written;
// --accept-drops writes it and reports the drop.
func TestMergeFloorRefusesDroppingRestoredBurials(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	own := floor{"keep": {Generation: mgen(2), Seq: 1}}
	for i := range 10 {
		own[fmt.Sprintf("old-%02d", i)] = floorEntry{Buried: []burial{{Generation: mgen(200 + i), Deleted: uint64(i + 1)}}}
	}
	putFloorFile(t, server, own)
	aside := floor{"keep": {Generation: mgen(2), Seq: 1}}
	for i := range 40 {
		aside[fmt.Sprintf("name-%02d", i)] = floorEntry{Buried: []burial{{Generation: mgen(100 + i), Deleted: uint64(i + 1)}}}
	}
	writeAsideFloor(t, server, aside)
	setFloorLimits(t, smallFloorSize, 3100)
	before := floorOf(t, server)
	for _, dry := range []bool{true, false} {
		r, err := mergeStaged(t, s, ctx, MergeOptions{DryRun: dry})
		if !errors.Is(err, errFloorFull) || !strings.Contains(err.Error(), "old-00") {
			t.Fatalf("MergeFloor (dry run %v) dropping a restored burial: %+v, %v; want errFloorFull naming old-00", dry, r, err)
		}
	}
	if !floorsEqual(floorOf(t, server), before) || s.MergePending() == nil {
		t.Fatal("a refused merge wrote the floor or cleared the guard")
	}
	r, err := mergeStaged(t, s, ctx, MergeOptions{AcceptDrops: true})
	if err != nil || len(r.Dropped) == 0 || r.Dropped[0] != "old-00" {
		t.Fatalf("MergeFloor --accept-drops = %+v, %v; want old-00 dropped", r, err)
	}
}
