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
	"maps"
	"slices"
	"testing"
)

// TestPlanMergeKeepTwiceWritesNothing (U192): a keep merged twice keeps
// the name again ("a rerun keeps it again and writes nothing"): the second
// plan reports the same Kept and Recorded, counts as a change (changes, so a
// kept-only first run writes its record), and changes nothing in the floor
// (floorChanges), its result the floor the first plan wrote. Both a keep of
// a name the restored floor does not record and a keep of a restored
// generation the moved-aside floor buries are checked.
func TestPlanMergeKeepTwiceWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name        string
		live, aside floor
		keep        string
	}{
		{
			name:  "recorded",
			live:  floor{},
			aside: floor{"d": {Generation: mgen(0), Seq: 4}},
			keep:  "d",
		},
		{
			name:  "buried",
			live:  floor{"a": {Generation: mgen(1), Seq: 1}},
			aside: floor{"a": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}},
			keep:  "a",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keep := map[string]bool{tc.keep: true}
			once := planMerge(tc.live, tc.aside, keep, nil, nil)
			if !slices.Equal(once.r.Kept, []string{tc.keep}) || !once.r.changes() {
				t.Fatalf("the first merge = %+v, want %s kept and counted as a change", once.r, tc.keep)
			}
			again := planMerge(once.merged, tc.aside, keep, nil, nil)
			if !slices.Equal(again.r.Kept, once.r.Kept) || !slices.Equal(again.r.Recorded, once.r.Recorded) {
				t.Errorf("the second merge kept %v, recorded %v; want %v, %v again", again.r.Kept, again.r.Recorded, once.r.Kept, once.r.Recorded)
			}
			if !again.r.changes() {
				t.Errorf("the second merge = %+v, want its keep counted as a change", again.r)
			}
			if again.r.floorChanges() || !floorsEqual(again.merged, once.merged) || len(again.dropped) != 0 {
				t.Errorf("the second merge = %+v (floor changes %v), dropped %v; want the floor the first wrote, nothing more", again.r, again.r.floorChanges(), again.dropped)
			}
		})
	}
}

// TestFuzzRmReportsCapEviction (U192): the reverse-merge oracle's rm since
// the restore, at the per-name cap, drops the name's oldest burial, a
// guard-era one before the merge, and fuzzRm returns it, as Delete reports
// it evicted; the merge and the reverse merge drop nothing, and the reverse
// merge keeps every burial the rm left and the rm's own.
func TestFuzzRmReportsCapEviction(t *testing.T) {
	setSeam(t, &buriedPerNameLimit, smallBuriedPerName)
	live := floor{"b": {Generation: mgen(3), Seq: 4, Buried: []burial{
		{Generation: mgen(1), Deleted: guardEraSeq + 1},
		{Generation: mgen(2), Deleted: guardEraSeq + 2},
		{Generation: mgen(7), Deleted: guardEraSeq + 3},
		{Generation: mgen(0), Deleted: guardEraSeq + 4},
	}}}
	from := floor{}
	p := planMerge(live, from, nil, nil, nil)
	if len(p.dropped) != 0 || len(p.merged["b"].burials()) != smallBuriedPerName {
		t.Fatalf("the merge = %+v, dropped %v; want every guard-era burial kept", p.merged, p.dropped)
	}
	m := maps.Clone(p.merged)
	name, gen, lost := fuzzRm(m)
	if name != "b" || gen != mgen(3) {
		t.Fatalf("fuzzRm buried %s %s, want b %s", name, gen, mgen(3))
	}
	if want := (floorBurial{"b", mgen(1)}); len(lost) != 1 || !lost[want] {
		t.Fatalf("fuzzRm lost %v, want only %v, the oldest burial at the per-name cap", lost, want)
	}
	rev := planMerge(from, m, nil, nil, nil)
	if len(rev.dropped) != 0 {
		t.Fatalf("the reverse merge dropped %v, want nothing", rev.dropped)
	}
	for _, b := range m["b"].burials() {
		if !rev.merged["b"].buries(b.Generation) {
			t.Errorf("the reverse merge lost b's burial of %s", b.Generation)
		}
	}
	if !rev.merged["b"].buries(gen) {
		t.Errorf("the reverse merge lost the rm's burial of b %s", gen)
	}
}
