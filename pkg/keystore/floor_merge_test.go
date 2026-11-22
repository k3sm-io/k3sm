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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The tests for MergeFloor, which carries the moved-aside floor's burials
// into the floor a restore put back (docs/design/keystore.md § "Pointer
// sequence and floor", gate row U192).

// mgen is the hex generation numbered i.
func mgen(i int) string { return fmt.Sprintf("%032x", i) }

// TestFloorMergeSemantics (U192): merge adds every burial the restored
// floor lacks, in the moved-aside floor's order and newer than the restored
// floor's own; counts the ones already present; buries a generation the
// restored floor holds live (reported), unless keep names it (reported
// apart); and keeps every other live record.
func TestFloorMergeSemantics(t *testing.T) {
	restored := floor{
		"live":  {Generation: mgen(1), Seq: 3},
		"other": {Generation: mgen(2), Seq: 1},
		"dead":  {Buried: []burial{{Generation: mgen(3), Deleted: 1}}},
	}
	aside := floor{
		"live":    {Buried: []burial{{Generation: mgen(1), Deleted: 5}}},
		"other":   {Generation: mgen(9), Seq: 1, Buried: []burial{{Generation: mgen(4), Deleted: 2}}},
		"dead":    {Buried: []burial{{Generation: mgen(3), Deleted: 3}}},
		"revoked": {Buried: []burial{{Generation: mgen(5), Deleted: 4}, {Generation: mgen(6), Deleted: 6}}},
	}
	kept := floor{}
	for name, e := range restored {
		kept[name] = e
	}
	r, dropped := restored.merge(aside, nil)
	if r.Merged != 4 || r.AlreadyPresent != 1 || !slices.Equal(r.BuriedLive, []string{"live"}) || len(r.Kept) != 0 || len(dropped) != 0 {
		t.Fatalf("merge = %+v, dropped %v; want 4 merged, 1 present, live buried, none kept or dropped", r, dropped)
	}
	if e := restored["live"]; e.live() || !e.buries(mgen(1)) {
		t.Errorf("live after the merge = %+v, want its live generation buried", e)
	}
	r, _ = kept.merge(aside, map[string]bool{"live": true})
	if r.Merged != 3 || len(r.BuriedLive) != 0 || !slices.Equal(r.Kept, []string{"live"}) {
		t.Fatalf("merge keeping live = %+v; want 3 merged, live kept", r)
	}
	if e := kept["live"]; e.Generation != mgen(1) || e.Seq != 3 || len(e.burials()) != 0 {
		t.Errorf("live after the merge keeping it = %+v, want its live record kept and nothing buried", e)
	}
	if e := restored["other"]; e.Generation != mgen(2) || !e.buries(mgen(4)) || e.buries(mgen(9)) {
		t.Errorf("other after the merge = %+v, want its live record kept and only the burial merged", e)
	}
	bs := restored["revoked"].burials()
	if len(bs) != 2 || bs[0].Generation != mgen(5) || bs[1].Generation != mgen(6) || bs[0].Deleted <= 1 || bs[1].Deleted <= bs[0].Deleted {
		t.Errorf("revoked after the merge = %+v, want both generations in order, newer than the restored floor's", bs)
	}
	b, err := marshalFloor(restored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseFloor(b); err != nil {
		t.Fatalf("the merged floor does not parse: %v", err)
	}
}

// TestFloorMergeCapsAndPrune (U192): a merge past the per-name cap drops the
// name's oldest, and a merge past the tombstone budget is pruned oldest
// first; MergeFloor reports and logs every burial dropped.
func TestFloorMergeCapsAndPrune(t *testing.T) {
	setSeam(t, &buriedPerNameLimit, smallBuriedPerName)
	restored := floor{"n": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}}
	aside := floor{"n": {}}
	var bs []burial
	for i := range smallBuriedPerName {
		bs = append(bs, burial{Generation: mgen(10 + i), Deleted: uint64(i + 1)})
	}
	aside["n"] = floorEntry{Buried: bs}
	r, dropped := restored.merge(aside, nil)
	if r.Merged != smallBuriedPerName || len(dropped) != 1 || dropped[0].generation != mgen(1) {
		t.Fatalf("merge past the cap = %+v, dropped %v; want %d merged and the restored floor's own burial dropped", r, dropped, smallBuriedPerName)
	}

	ctx := context.Background()
	s, server := newTestStore(t)
	own := floor{"keep": {Generation: mgen(2), Seq: 1}}
	for i := range 10 {
		own[fmt.Sprintf("old-%02d", i)] = floorEntry{Buried: []burial{{Generation: mgen(200 + i), Deleted: uint64(i + 1)}}}
	}
	putFloorFile(t, server, own)
	aside = floor{}
	for i := range 40 {
		aside[fmt.Sprintf("name-%02d", i)] = floorEntry{Buried: []burial{{Generation: mgen(100 + i), Deleted: uint64(i + 1)}}}
	}
	path := writeAsideFloor(t, server, aside)
	// The moved-aside floor fits the budget alone; with the restored
	// floor's own burials it does not.
	setFloorLimits(t, smallFloorSize, 3100)
	buf := captureWarn(t)
	got, err := s.MergeFloor(ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Merged != 40 || len(got.Dropped) == 0 {
		t.Fatalf("MergeFloor over the budget = %+v, want 40 merged and some dropped", got)
	}
	if !slices.Contains(got.Dropped, "old-00") || slices.Contains(got.Dropped, "name-39") {
		t.Errorf("dropped = %v, want the oldest dropped first and the newest kept", got.Dropped)
	}
	fl := readFloorFile(t, server)
	for _, name := range got.Dropped {
		if len(fl[name].burials()) != 0 {
			t.Errorf("%s reported dropped but still buried", name)
		}
	}
	if got := buf.String(); !strings.Contains(got, "level=WARN") || !strings.Contains(got, "dropped the oldest") {
		t.Errorf("log = %q, want a Warn for the dropped burials", buf)
	}
	if e := fl["keep"]; e.Generation != mgen(2) || e.Seq != 1 {
		t.Errorf("keep after the merge = %+v, want its live record kept", e)
	}
}

// TestFloorMergeRefusesUntrusted (U192): the moved-aside file is parsed by
// parseFloor and judged as the floor is, so a malformed or symlinked one is
// refused and the live floor is left as it was.
func TestFloorMergeRefusesUntrusted(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(filepath.Dir(server), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":1,"scope":"system","entries":{},"tombstones":{"k":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeFloor(ctx, bad, nil); !errors.Is(err, ErrCorrupt) {
		t.Errorf("MergeFloor of a malformed floor: %v, want ErrCorrupt", err)
	}
	link := filepath.Join(filepath.Dir(server), "link.json")
	if err := os.Symlink(floorPath(server), link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeFloor(ctx, link, nil); !errors.Is(err, errFloorUntrusted) {
		t.Errorf("MergeFloor of a symlink: %v, want errFloorUntrusted", err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || string(after) != string(before) {
		t.Errorf("floor after the refused merges changed: %s, %v", after, err)
	}
}

// writeAsideFloor writes fl as a moved-aside floor file beside the live one
// and returns its path.
func writeAsideFloor(t *testing.T, server string, fl floor) string {
	t.Helper()
	b, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	p := floorPath(server) + ".pre-restore"
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// readFloorFile parses the live floor file.
func readFloorFile(t *testing.T, server string) floor {
	t.Helper()
	b, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	fl, err := parseFloor(b)
	if err != nil {
		t.Fatal(err)
	}
	return fl
}

// TestFloorMergeBuriesRevokedLive (U192): a generation the moved-aside floor
// buries and the restored floor holds live (a key revoked since the backup)
// is buried by the merge, never left live.
func TestFloorMergeBuriesRevokedLive(t *testing.T) {
	restored := floor{"n": {Generation: mgen(1), Seq: 3}}
	aside := floor{"n": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}}
	restored.merge(aside, nil)
	if e := restored["n"]; e.live() || !e.buries(mgen(1)) {
		t.Fatalf("n after the merge = %+v, want its restored live generation buried", e)
	}
}

// TestMergeFloorKeep (U192): MergeFloor with a keep set leaves that entry's
// restored generation live and reports it, buries the others' revoked live
// generations, and refuses a keep name that is not a valid name.
func TestMergeFloorKeep(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	putFloorFile(t, server, floor{"a": {Generation: mgen(1), Seq: 1}, "b": {Generation: mgen(2), Seq: 1}})
	path := writeAsideFloor(t, server, floor{
		"a": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}},
		"b": {Buried: []burial{{Generation: mgen(2), Deleted: 2}}},
	})
	if _, err := s.MergeFloor(ctx, path, []string{"Bad Name"}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("MergeFloor with an invalid keep name: %v, want ErrInvalidName", err)
	}
	r, err := s.MergeFloor(ctx, path, []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Kept, []string{"a"}) || !slices.Equal(r.BuriedLive, []string{"b"}) {
		t.Fatalf("MergeFloor keeping a = %+v, want a kept and b buried", r)
	}
	fl := readFloorFile(t, server)
	if e := fl["a"]; e.Generation != mgen(1) || e.buries(mgen(1)) {
		t.Errorf("a after the merge = %+v, want it live", e)
	}
	if e := fl["b"]; e.live() || !e.buries(mgen(2)) {
		t.Errorf("b after the merge = %+v, want it buried", e)
	}
}
