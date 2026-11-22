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
// floor's own; counts the ones already present; never buries a generation
// the restored floor holds live (reported); and keeps every live record.
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
	r, dropped := restored.merge(aside)
	if r.Merged != 3 || r.AlreadyPresent != 1 || !slices.Equal(r.SkippedLive, []string{"live"}) || len(dropped) != 0 {
		t.Fatalf("merge = %+v, dropped %v; want 3 merged, 1 present, live skipped, none dropped", r, dropped)
	}
	if e := restored["live"]; e.Generation != mgen(1) || e.Seq != 3 || len(e.burials()) != 0 {
		t.Errorf("live after the merge = %+v, want its live record kept and nothing buried", e)
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
	r, dropped := restored.merge(aside)
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
	got, err := s.MergeFloor(ctx, path)
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
	if _, err := s.MergeFloor(ctx, bad); !errors.Is(err, ErrCorrupt) {
		t.Errorf("MergeFloor of a malformed floor: %v, want ErrCorrupt", err)
	}
	link := filepath.Join(filepath.Dir(server), "link.json")
	if err := os.Symlink(floorPath(server), link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeFloor(ctx, link); !errors.Is(err, errFloorUntrusted) {
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
