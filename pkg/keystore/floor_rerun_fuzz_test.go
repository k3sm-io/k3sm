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
	"encoding/hex"
	"testing"
)

// FuzzRerunPredicates (U192) drives pendingSince, and through it
// buriedSince and rmSince, on fuzzed floors: the floor a merge recorded
// (both read and written), a live floor carrying guard-era burials, and a
// set of burials an rm under the guard dropped. Its oracle: when the live
// floor is accepted, every pointer the live floor's check accepts the
// recorded floor's accepts too, except a generation the rm-dropped set
// lists and a name whose live record rm buried (no Put runs under the
// guard to put another generation there).
func FuzzRerunPredicates(f *testing.F) {
	f.Add([]byte{0, 1, 1, 8, 2, 1}, []byte{0, 1, 1, 8, 2, 1, 9, 3, 1}, uint64(0))
	f.Add([]byte{0, 1, 200}, []byte{0, 1, 2}, uint64(0))
	f.Add([]byte{0, 1, 1, 8, 2, 1}, []byte{8, 1, 1}, uint64(1<<2))
	f.Fuzz(func(t *testing.T, oldB, nowB []byte, goneMask uint64) {
		setSeam(t, &buriedPerNameLimit, smallBuriedPerName)
		setSmallFloorLimits(t)
		old, now := fuzzFloor(oldB, false), fuzzFloor(nowB, true)
		if old == nil || now == nil {
			return
		}
		gone := map[floorBurial]bool{}
		for i, name := range planNames {
			for j := range 8 {
				if goneMask&(1<<(i*8+j)) != 0 {
					gone[floorBurial{name, mgen(j)}] = true
				}
			}
		}
		ob, err := marshalFloor(old)
		if err != nil {
			t.Fatal(err)
		}
		var rec retiredRecord
		rec.setFloors(ob, ob)
		if _, err := pendingSince(rec, now, gone); err != nil {
			return
		}
		for _, name := range planNames {
			if old[name].live() && !now[name].live() {
				continue // rm buried it
			}
			for j := range 8 {
				if gone[floorBurial{name, mgen(j)}] {
					continue
				}
				var gen [generationSize]byte
				if _, err := hex.Decode(gen[:], []byte(mgen(j))); err != nil {
					t.Fatal(err)
				}
				for seq := uint64(1); seq <= 12; seq++ {
					if now.check(name, gen, seq) == nil && old.check(name, gen, seq) != nil {
						t.Fatalf("the accepted live floor %+v accepts %s generation %s at %d, which the recorded floor %+v refuses", now[name], name, mgen(j), seq, old[name])
					}
				}
			}
		}
	})
}

// TestBuriedSinceFence (U192): a live record raised above the recorded
// sequence but inside its fence, keeping the fence's mark, is refused: it
// would accept a pointer of the abandoned history the recorded fence
// refuses.
func TestBuriedSinceFence(t *testing.T) {
	old := floor{"k": {Generation: mgen(1), Seq: 1, HighWater: 5}}
	for _, tc := range []struct {
		name string
		now  floorEntry
		ok   bool
	}{
		{"unchanged", floorEntry{Generation: mgen(1), Seq: 1, HighWater: 5}, true},
		{"mark raised", floorEntry{Generation: mgen(1), Seq: 1, HighWater: 7}, true},
		{"sealed above the fence", floorEntry{Generation: mgen(1), Seq: 6}, true},
		{"inside the fence, mark kept", floorEntry{Generation: mgen(1), Seq: 3, HighWater: 5}, false},
		{"mark lowered", floorEntry{Generation: mgen(1), Seq: 1, HighWater: 4}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := buriedSince(old, floor{"k": tc.now}, nil); (err == nil) != tc.ok {
				t.Fatalf("buriedSince to %+v = %v, want accepted %v", tc.now, err, tc.ok)
			}
		})
	}
}
