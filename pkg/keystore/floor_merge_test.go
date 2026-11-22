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
	"encoding/hex"
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
	r, dropped := restored.merge(aside, nil, nil)
	if r.Merged != 4 || r.AlreadyPresent != 1 || !slices.Equal(r.BuriedLive, []string{"live"}) || len(r.Kept) != 0 || len(dropped) != 0 {
		t.Fatalf("merge = %+v, dropped %v; want 4 merged, 1 present, live buried, none kept or dropped", r, dropped)
	}
	if e := restored["live"]; e.live() || !e.buries(mgen(1)) {
		t.Errorf("live after the merge = %+v, want its live generation buried", e)
	}
	r, _ = kept.merge(aside, map[string]bool{"live": true}, nil)
	if r.Merged != 3 || len(r.BuriedLive) != 0 || !slices.Equal(r.Kept, []string{"live"}) {
		t.Fatalf("merge keeping live = %+v; want 3 merged, live kept", r)
	}
	if e := kept["live"]; e.Generation != mgen(1) || e.Seq != 3 || len(e.burials()) != 0 {
		t.Errorf("live after the merge keeping it = %+v, want its live record kept and nothing buried", e)
	}
	if e := restored["other"]; e.Generation != mgen(2) || !e.buries(mgen(4)) || !e.buries(mgen(9)) || !slices.Equal(r.Retired, []string{"other"}) {
		t.Errorf("other after the merge = %+v (retired %v), want its live record kept, the burial merged and the aside's live generation retired", e, r.Retired)
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
	r, dropped := restored.merge(aside, nil, nil)
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
	restored.merge(aside, nil, nil)
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

// TestFloorMergeRetiresAsideLive (U192): a live generation in the
// moved-aside floor that the restored floor does not hold live, under
// another generation or not at all, is buried (counted as retired). keep
// spares it only when the restored floor holds no live record of the name:
// keep keeps the restored generation, never a second, moved-aside one. One
// the restored floor holds live at a lower
// sequence is left live, with the moved-aside sequence as its high-water
// mark (fenced), so the abandoned history above it is refused.
func TestFloorMergeRetiresAsideLive(t *testing.T) {
	restored := floor{
		"other": {Generation: mgen(1), Seq: 1},
		"same":  {Generation: mgen(3), Seq: 1},
		"kept":  {Generation: mgen(5), Seq: 1},
		"gone":  {Buried: []burial{{Generation: mgen(7), Deleted: 1}}},
	}
	aside := floor{
		"other": {Generation: mgen(2), Seq: 4},
		"same":  {Generation: mgen(3), Seq: 2},
		"kept":  {Generation: mgen(6), Seq: 1},
		"new":   {Generation: mgen(4), Seq: 1},
		"gone":  {Generation: mgen(7), Seq: 1},
		"spare": {Generation: mgen(8), Seq: 1},
	}
	r, _ := restored.merge(aside, map[string]bool{"kept": true, "spare": true}, nil)
	if !slices.Equal(r.Retired, []string{"kept", "new", "other"}) || !slices.Equal(r.Kept, []string{"spare"}) {
		t.Fatalf("merge = %+v; want kept, new and other retired and only spare kept", r)
	}
	if e := restored["other"]; e.Generation != mgen(1) || !e.buries(mgen(2)) {
		t.Errorf("other after the merge = %+v, want its live record kept and the aside's buried", e)
	}
	if e := restored["new"]; e.live() || !e.buries(mgen(4)) {
		t.Errorf("new after the merge = %+v, want the aside's generation buried", e)
	}
	if e := restored["same"]; e.Generation != mgen(3) || e.Seq != 1 || e.HighWater != 3 || len(e.burials()) != 0 || !slices.Equal(r.Fenced, []string{"same"}) {
		t.Errorf("same after the merge = %+v (fenced %v), want it live at seq 1 with high-water 3 (one past the moved-aside seq 2), nothing buried", e, r.Fenced)
	}
	if e := restored["kept"]; e.Generation != mgen(5) || !e.buries(mgen(6)) || len(e.burials()) != 1 {
		t.Errorf("kept after the merge = %+v, want its restored generation live and the aside's buried", e)
	}
	if e := restored["spare"]; e.Generation != mgen(8) || e.Seq != 1 || e.HighWater != 2 || len(e.burials()) != 0 {
		t.Errorf("spare after the merge = %+v, want the aside's generation recorded live at its seq 1, fenced at 2", e)
	}
	if e := restored["gone"]; len(e.burials()) != 1 {
		t.Errorf("gone after the merge = %+v, want its one burial", e)
	}
}

// TestFloorMergeRefusesUntrustedPlace (U192): the moved-aside file and the
// directory holding it are judged as the floor and the data root are: a
// parent directory group- or other-writable, a file another uid owns (the
// floorUID seam stands in for root) and a mode-0666 file are each refused,
// and the live floor is left as it was.
func TestFloorMergeRefusesUntrustedPlace(t *testing.T) {
	ctx := context.Background()
	aside := floor{"k": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}}
	plant := func(t *testing.T, dirMode, fileMode os.FileMode) string {
		t.Helper()
		b, err := marshalFloor(aside)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		p := filepath.Join(dir, "keystore-floor.json.pre-restore")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		for path, mode := range map[string]os.FileMode{p: fileMode, dir: dirMode} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	for _, tc := range []struct {
		name              string
		dirMode, fileMode os.FileMode
		otherOwner        bool
		want              string
	}{
		{"a trusted place is merged", 0o755, 0o644, false, ""},
		{"a group-writable parent", 0o775, 0o644, false, "the directory holding the floor file to merge"},
		{"an other-writable parent", 0o757, 0o644, false, "the directory holding the floor file to merge"},
		{"a file another uid owns", 0o755, 0o644, true, "owned by uid"},
		{"a mode-0666 file", 0o755, 0o666, false, "the floor file to merge: mode 0666"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			putFloorFile(t, server, floor{"live": {Generation: mgen(9), Seq: 1}})
			path := plant(t, tc.dirMode, tc.fileMode)
			before, err := os.ReadFile(floorPath(server))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if tc.otherOwner {
				// As root the config pins floorUID to 0, so hand the file to
				// the service user; non-root, move the expected owner instead.
				if asRoot() {
					giveToService(t, path)
				} else {
					s.floorUID++
				}
			}
			_, err = s.MergeFloor(ctx, path, nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("MergeFloor from a trusted place: %v", err)
				}
				return
			}
			if !errors.Is(err, errFloorUntrusted) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("MergeFloor: %v, want errFloorUntrusted naming %q", err, tc.want)
			}
			if after, _ := os.ReadFile(floorPath(server)); string(after) != string(before) {
				t.Errorf("floor after the refused merge changed: %s", after)
			}
		})
	}
}

// TestMergeFloorRefusesDroppingItsOwnBurials (U192): a merge whose write
// would prune a burial it adds itself (a merged or retired generation, or a
// revoked live one it buries) is refused before anything is written, as
// errFloorFull, and its input is left in place, so the guard stays.
func TestMergeFloorRefusesDroppingItsOwnBurials(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	putFloorFile(t, server, floor{"keep": {Generation: mgen(2), Seq: 1}, "revoked": {Generation: mgen(3), Seq: 1}})
	aside := floor{"revoked": {Buried: []burial{{Generation: mgen(3), Deleted: 1}}}}
	for i := range 40 {
		aside[fmt.Sprintf("name-%02d", i)] = floorEntry{Generation: mgen(100 + i), Seq: 1}
	}
	path := writeAsideFloor(t, server, aside)
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	// The moved-aside floor parses under the tombstone budget, but its
	// live generations, each retired by the merge, take the burials over it.
	setFloorLimits(t, smallFloorSize, 1000)
	r, err := s.MergeFloor(ctx, path, nil)
	if !errors.Is(err, errFloorFull) || Committed(err) {
		t.Fatalf("MergeFloor dropping its own burials = %+v, %v; want errFloorFull, not committed", r, err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || string(after) != string(before) {
		t.Errorf("floor after the refused merge changed: %s, %v", after, err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the input after the refused merge: %v, want it left in place", err)
	}
	if err := s.MergePending(); !errors.Is(err, errMergePending) {
		t.Errorf("MergePending after the refused merge = %v, want the guard in place", err)
	}
}

// TestFloorMergeKeepRecordsAsideLive (U192): --keep on a name the restored
// floor does not record writes a live record of the moved-aside generation
// at its sequence, fenced one past the higher of its sequence and mark, so
// an older copy of that generation is refused and the copy at the recorded
// sequence is read; a rerun keeps the name again and changes nothing.
func TestFloorMergeKeepRecordsAsideLive(t *testing.T) {
	restored := floor{"other": {Generation: mgen(1), Seq: 1}}
	aside := floor{"spare": {Generation: mgen(8), Seq: 4, HighWater: 6}}
	keep := map[string]bool{"spare": true}
	r, _ := restored.merge(aside, keep, nil)
	if !slices.Equal(r.Kept, []string{"spare"}) || !r.changes() {
		t.Fatalf("merge keeping spare = %+v (changes %v), want spare kept and the floor changed", r, r.changes())
	}
	e := restored["spare"]
	if e.Generation != mgen(8) || e.Seq != 4 || e.HighWater != 7 {
		t.Fatalf("spare after the merge = %+v, want generation %s at seq 4, fenced at 7", e, mgen(8))
	}
	var gen [generationSize]byte
	copy(gen[:], mustHex(t, mgen(8)))
	if err := restored.check("spare", gen, 3); !errors.Is(err, ErrCorrupt) {
		t.Errorf("check of an older copy of the kept generation = %v, want it refused", err)
	}
	if err := restored.check("spare", gen, 7); !errors.Is(err, ErrCorrupt) {
		t.Errorf("check of a copy inside the fence = %v, want it refused", err)
	}
	if err := restored.check("spare", gen, 4); err != nil {
		t.Errorf("check of the kept generation at its recorded seq = %v, want it read", err)
	}
	b, err := marshalFloor(restored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseFloor(b); err != nil {
		t.Fatalf("the merged floor does not parse: %v", err)
	}
	again, _ := restored.merge(aside, keep, nil)
	if !slices.Equal(again.Kept, []string{"spare"}) || again.changes() {
		t.Errorf("rerun keeping spare = %+v, want spare kept and nothing changed", again)
	}
}

// mustHex decodes the hex string h.
func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
