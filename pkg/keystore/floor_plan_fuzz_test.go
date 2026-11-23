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
	"sort"
	"testing"
)

// planNames are the entry names fuzzFloor draws from: few, so the two
// floors of a merge share names often.
var planNames = []string{"a", "b", "c", "d", "e"}

// fuzzFloor builds a floor from b, three bytes an operation: a live record
// (generation, sequence and high-water mark from the bytes) or a burial,
// numbered in order, above guardEraSeq when guard allows it and the bytes
// ask. It returns nil when the result is not a floor parseFloor accepts
// under the limits in force.
func fuzzFloor(b []byte, guard bool) floor {
	fl := floor{}
	var seq, guardSeq uint64 = 0, guardEraSeq
	for i := 0; i+2 < len(b); i += 3 {
		op, x, y := b[i], b[i+1], b[i+2]
		name := planNames[int(op)%len(planNames)]
		e := fl[name]
		g := mgen(int(x % 8))
		switch (op / 8) % 2 {
		case 0:
			e.Generation, e.Seq, e.HighWater = g, uint64(y%5)+1, 0
			if y >= 128 {
				e.HighWater = e.Seq + uint64(y%3) + 1
			}
		default:
			if e.buries(g) {
				continue
			}
			var d uint64
			if guard && y%2 == 1 {
				guardSeq++
				d = guardSeq
			} else {
				seq++
				d = seq
			}
			e.Buried = append(slices.Clone(e.Buried), burial{Generation: g, Deleted: d})
			sort.Slice(e.Buried, func(i, j int) bool { return e.Buried[i].Deleted < e.Buried[j].Deleted })
		}
		fl[name] = e
	}
	for name, e := range fl {
		if e.live() && e.buries(e.Generation) {
			e.Generation, e.Seq, e.HighWater = "", 0, 0
		}
		if !e.live() && len(e.burials()) == 0 {
			delete(fl, name)
			continue
		}
		fl[name] = e
	}
	enc, err := marshalFloor(fl)
	if err != nil {
		return nil
	}
	if _, err := parseFloor(enc); err != nil {
		return nil
	}
	return fl
}

// FuzzPlanMerge (U192) drives mergeFloor's decision logic, planMerge, on
// in-memory floors under a small per-name cap and a tombstone budget from
// the input, and checks its oracles: a merge allowed without AcceptDrops
// drops no burial at all, so never one it adds or a guard-era one; no
// burial of an allowed merge is above guardEraSeq unless it is guard-era,
// with guard-era burials in the live floor or none; a merge
// allowed leaves no name it cleared with neither a live record nor a
// burial; no raise passes the restored record's sequence plus one; merging
// the result again changes nothing in the floor and keeps the same names; and a reverse merge (the undo) of the
// result into the moved-aside floor, after an rm since the restore, keeps
// every guard-era deletion and that one, each the rm's write did not evict.
func FuzzPlanMerge(f *testing.F) {
	f.Add([]byte{0, 1, 1, 8, 2, 1, 9, 3, 1}, []byte{8, 1, 0, 1, 4, 2}, []byte{2, 0}, uint8(0), uint16(4096), false)
	f.Add([]byte{0, 1, 1, 1, 2, 1, 2, 3, 200, 8, 4, 1, 10, 5, 1}, []byte{8, 1, 0, 9, 2, 0, 3, 6, 1, 4, 7, 2}, []byte{1, 2, 3}, uint8(1), uint16(120), true)
	f.Add([]byte{0, 1, 1, 8, 2, 0, 8, 3, 0, 8, 4, 0, 8, 5, 0, 9, 6, 1}, []byte{8, 1, 0, 8, 6, 0, 8, 7, 0, 1, 0, 3}, []byte{}, uint8(0), uint16(90), true)
	f.Fuzz(func(t *testing.T, liveB, fromB, ptrB []byte, keepMask uint8, budget uint16, acceptDrops bool) {
		setSeam(t, &buriedPerNameLimit, smallBuriedPerName)
		setFloorLimits(t, smallFloorSize, 64+int(budget)%smallTombstoneSize)
		live, from := fuzzFloor(liveB, true), fuzzFloor(fromB, false)
		if live == nil || from == nil {
			return
		}
		keep := map[string]bool{}
		ptrs := map[string]uint64{}
		for i, name := range planNames {
			if keepMask&(1<<i) != 0 {
				keep[name] = true
			}
			if i < len(ptrB) {
				ptrs[name] = uint64(ptrB[i] % 8)
			}
		}
		before := maps.Clone(live)
		guarded := live.guardEra()
		p := planMerge(live, from, keep, ptrs, nil)
		if !floorsEqual(live, before) {
			t.Fatal("planMerge changed the live floor it was given")
		}
		refused := p.loss.refusal(acceptDrops)
		if refusal := p.loss.refusal(false); refusal == nil && len(p.dropped) > 0 {
			t.Fatalf("a merge allowed without AcceptDrops drops %v", p.dropped)
		}
		for _, d := range p.dropped {
			if (!before[d.name].buries(d.generation) || guarded[floorBurial(d)]) && p.loss.refusal(false) == nil {
				t.Fatalf("a merge allowed without AcceptDrops drops %s %s, a burial it adds or a guard-era one", d.name, d.generation)
			}
		}
		if refused != nil {
			return
		}
		// The guard band holds only guard-era burials, whether the live
		// floor holds any or none.
		for name, e := range p.merged {
			for _, b := range e.burials() {
				if b.Deleted > guardEraSeq && !guarded[floorBurial{name, b.Generation}] {
					t.Fatalf("the merge numbered %s's burial %+v above guardEraSeq, and it is not guard-era", name, b)
				}
			}
		}
		for _, name := range p.r.BuriedLive {
			if e := p.merged[name]; !e.live() && len(e.burials()) == 0 {
				t.Fatalf("the merge cleared %s and left it with neither a record nor a burial", name)
			}
			if !p.merged[name].buries(before[name].Generation) {
				t.Fatalf("the merge cleared %s and dropped its burial of %s", name, before[name].Generation)
			}
		}
		for name, was := range before {
			now := p.merged[name]
			if was.live() && now.live() && now.Generation == was.Generation && now.Seq > was.Seq+1 {
				t.Fatalf("the merge raised %s from seq %d to %d, more than one", name, was.Seq, now.Seq)
			}
		}
		if len(p.dropped) == 0 {
			again := planMerge(p.merged, from, keep, ptrs, nil)
			// A rerun keeps each kept name again and writes nothing
			// (docs/design/keystore.md): the same Kept, no floor change.
			if again.r.floorChanges() || !slices.Equal(again.r.Kept, p.r.Kept) || len(again.dropped) != 0 || !floorsEqual(again.merged, p.merged) {
				t.Fatalf("merging twice = %+v, dropped %v; want the result of merging once", again.r, again.dropped)
			}
		}
		// The undo: an rm since the restore, then the merged floor merged
		// back into the moved-aside one.
		m := maps.Clone(p.merged)
		rmd, rmGen, lost := fuzzRm(m)
		rev := planMerge(from, m, nil, nil, nil)
		if len(rev.dropped) > 0 {
			return
		}
		// A burial the rm's own write dropped is gone before the reverse
		// merge, a drop Delete reports (ErrTombstoneEvicted), not the merge's.
		for b := range guarded {
			if !lost[b] && !rev.merged[b.name].buries(b.generation) {
				t.Fatalf("the reverse merge lost the guard-era deletion of %s %s", b.name, b.generation)
			}
		}
		if rmd != "" && !lost[floorBurial{rmd, rmGen}] && !rev.merged[rmd].buries(rmGen) {
			t.Fatalf("the reverse merge lost the deletion of %s %s made since the restore", rmd, rmGen)
		}
	})
}

// fuzzRm is the oracle's rm since the restore: it buries the first name m
// holds live, as Delete does with no guard pending, and returns that name,
// the generation buried and each burial the write dropped, at the per-name
// cap or in the prune, which Delete reports as evicted. With no live name it
// changes nothing and returns "".
func fuzzRm(m floor) (name, gen string, lost map[floorBurial]bool) {
	lost = map[floorBurial]bool{}
	for _, n := range planNames {
		if m[n].live() {
			name = n
			break
		}
	}
	if name == "" {
		return "", "", lost
	}
	gen = m[name].Generation
	_, capped := m.bury(name, nil)
	for _, p := range append(capped, m.prune()...) {
		lost[floorBurial{p.name, p.generation}] = true
	}
	return name, gen, lost
}
