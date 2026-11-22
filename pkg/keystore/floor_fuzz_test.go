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
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// FuzzParseFloor drives the floor file's decoder. The floor is root-owned,
// but it is the one file under the data root the keystore parses, and a
// restore or a stray copy can put any bytes there, so the decoder must refuse
// anything a root verb would not have written, as errFloorMalformed (which
// matches ErrCorrupt), and
// never panic. A tombstone is held to the same rules as an entry. What it accepts must be a floor every check can rely on, and
// must encode back to the same floor, byte for byte. The seeds are committed under
// testdata/fuzz/FuzzParseFloor.
func FuzzParseFloor(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		fl, err := parseFloor(b)
		if err != nil {
			if !errors.Is(err, errFloorMalformed) || !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parseFloor error %v is not errFloorMalformed and ErrCorrupt", err)
			}
			if fl != nil {
				t.Fatalf("parseFloor returned %v with its error", fl)
			}
			return
		}
		if fl == nil {
			t.Fatal("parseFloor accepted a floor and returned nil")
		}
		for name, e := range fl {
			if err := checkName(name); err != nil {
				t.Fatalf("accepted entry name %q: %v", name, err)
			}
			checkFloorEntry(t, name, e)
		}
		if n := fl.deadSize(); n > maxTombstoneSize {
			t.Fatalf("accepted tombstones of %d bytes", n)
		}
		again, err := marshalFloor(fl)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, again) && !bytes.Equal(b, again[:len(again)-1]) {
			t.Fatalf("parseFloor accepted %q, which is not its encoding %q", b, again)
		}
		back, err := parseFloor(again)
		if err != nil || !floorsEqual(back, fl) {
			t.Fatalf("the accepted floor does not encode back: %v, %v != %v", err, back, fl)
		}
	})
}

// FuzzMergeFloor drives merge over any two floors parseFloor accepts (the
// restored one and the moved-aside one) and any keep set (keep, split at
// commas, so a seed names several), followed by the prune its write makes,
// and checks: it never panics; it never un-buries, so each of the restored
// floor's burials is still buried or reported dropped; every burial it adds
// names a generation the moved-aside floor buries or holds live; a live
// record is buried only when the moved-aside floor buries its generation and
// keep does not name it; its counts add up; the result encodes to bytes that
// parse back to it. And it is complete: every moved-aside burial ends up
// buried or reported dropped, unless keep kept it as the restored live
// generation; every moved-aside live generation ends up buried, reported
// dropped, kept (keep names it and the restored floor holds the name not
// live), or live already; and, when nothing was dropped, a second merge of
// the same floors adds nothing. The seeds are committed under
// testdata/fuzz/FuzzMergeFloor.
func FuzzMergeFloor(f *testing.F) {
	type key struct{ name, gen string }
	f.Fuzz(func(t *testing.T, restoredB, asideB []byte, keep string) {
		restored, err := parseFloor(restoredB)
		if err != nil {
			return
		}
		aside, err := parseFloor(asideB)
		if err != nil {
			return
		}
		before := maps.Clone(restored)
		keepSet := map[string]bool{}
		for _, k := range strings.Split(keep, ",") {
			keepSet[k] = true
		}
		r, d := restored.merge(aside, keepSet)
		d = append(d, restored.prune()...)
		dropped := map[key]bool{}
		for _, x := range d {
			dropped[key{x.name, x.generation}] = true
		}
		for name, e := range before {
			for _, b := range e.burials() {
				if !restored[name].buries(b.Generation) && !dropped[key{name, b.Generation}] {
					t.Fatalf("merge un-buried %s %s without reporting it", name, b.Generation)
				}
			}
			if !e.live() || restored[name].Generation == e.Generation {
				continue
			}
			if keepSet[name] || !aside[name].buries(e.Generation) {
				t.Fatalf("merge cleared %s's live record %+v, which the moved-aside floor does not bury or keep names", name, e)
			}
		}
		added := 0
		for name, e := range restored {
			for _, b := range e.burials() {
				if before[name].buries(b.Generation) {
					continue
				}
				if !aside[name].buries(b.Generation) && aside[name].Generation != b.Generation {
					t.Fatalf("merge buried %s %s, which the moved-aside floor does not name", name, b.Generation)
				}
				added++
			}
		}
		for k := range dropped {
			if !before[k.name].buries(k.gen) {
				added++ // added by the merge, then dropped
			}
		}
		if added != r.Merged+r.Retired {
			t.Fatalf("merge reports %d merged and %d retired, and added %d burials", r.Merged, r.Retired, added)
		}
		b, err := marshalFloor(restored)
		if err != nil {
			t.Fatal(err)
		}
		back, err := parseFloor(b)
		if err != nil || !floorsEqual(back, restored) {
			t.Fatalf("the merged floor does not parse back: %v", err)
		}
		for name, a := range aside {
			was, now := before[name], restored[name]
			gone := func(g string) bool { return now.buries(g) || dropped[key{name, g}] }
			for _, b := range a.burials() {
				if keepSet[name] && was.live() && was.Generation == b.Generation {
					if now.Generation != b.Generation {
						t.Fatalf("merge kept %s %s and then cleared it: %+v", name, b.Generation, now)
					}
					continue
				}
				if !gone(b.Generation) {
					t.Fatalf("merge left the moved-aside burial %s %s neither buried nor reported dropped: %+v", name, b.Generation, now)
				}
			}
			if !a.live() || gone(a.Generation) || (now.live() && now.Generation == a.Generation) {
				continue
			}
			if !keepSet[name] || was.live() || !slices.Contains(r.Kept, name) {
				t.Fatalf("merge left the moved-aside live generation %s %s neither buried, dropped, kept nor live: %+v", name, a.Generation, now)
			}
		}
		// The fence: a restored live record of the moved-aside floor's live
		// generation ends at or past one above the moved-aside record, so a
		// pre-restore pointer one past a lagging moved-aside floor is
		// refused. A record at the sequence limit saturates there.
		for name, a := range aside {
			now := restored[name]
			if !a.live() || !now.live() || now.Generation != a.Generation {
				continue
			}
			want := max(a.Seq, a.HighWater)
			if want < math.MaxUint64 {
				want++
			}
			if got := max(now.Seq, now.HighWater); got < want {
				t.Fatalf("merge left %s at seq %d, high-water %d; the moved-aside record %+v wants at least %d", name, now.Seq, now.HighWater, a, want)
			}
		}
		if len(d) == 0 {
			if r2, d2 := restored.merge(aside, keepSet); r2.Merged+r2.Retired != 0 || len(r2.Fenced) != 0 || len(d2) != 0 {
				t.Fatalf("a second merge of the same floors = %+v, dropped %v; want nothing added", r2, d2)
			}
		}
	})
}

// TestParseFloorStrict: parseFloor accepts only the bytes marshalFloor
// writes, with or without its trailing newline. encoding/json alone would
// take a duplicate key's last value and match a field name in any case, so
// a floor with two answers for one field, or a key a root verb never writes,
// is refused.
func TestParseFloorStrict(t *testing.T) {
	const gen = "0123456789abcdef0123456789abcdef"
	good := floor{"a": {Generation: gen, Seq: 1}, "b": {Generation: gen, Seq: 2}}
	canon, err := marshalFloor(good)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{canon, canon[:len(canon)-1]} {
		if fl, err := parseFloor(b); err != nil || !floorsEqual(fl, good) {
			t.Fatalf("parseFloor(%q) = %v, %v; want %v", b, fl, err, good)
		}
	}
	for name, b := range map[string]string{
		"duplicate key":       `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":1},"a":{"generation":"` + gen + `","seq":2}}}`,
		"duplicate scope":     `{"version":1,"scope":"user/501","scope":"system","entries":{}}`,
		"duplicate version":   `{"version":2,"version":1,"scope":"system","entries":{}}`,
		"duplicate seq":       `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":9,"seq":1}}}`,
		"case-variant key":    `{"Version":1,"scope":"system","entries":{}}`,
		"case-variant field":  `{"version":1,"scope":"system","entries":{"a":{"Generation":"` + gen + `","seq":1}}}`,
		"null entries":        `{"version":1,"scope":"system","entries":null}`,
		"whitespace":          `{"version": 1,"scope":"system","entries":{}}`,
		"unsorted entries":    `{"version":1,"scope":"system","entries":{"b":{"generation":"` + gen + `","seq":1},"a":{"generation":"` + gen + `","seq":1}}}`,
		"fractional seq":      `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":1.0}}}`,
		"two newlines":        string(canon) + "\n",
		"a carriage return":   string(canon[:len(canon)-1]) + "\r\n",
		"reordered fields":    `{"scope":"system","version":1,"entries":{}}`,
		"escaped scope":       `{"version":1,"scope":"\u0073ystem","entries":{}}`,
		"trailing whitespace": string(canon[:len(canon)-1]) + " ",
	} {
		if fl, err := parseFloor([]byte(b)); !errors.Is(err, errFloorMalformed) || fl != nil {
			t.Errorf("%s: parseFloor(%q) = %v, %v; want errFloorMalformed", name, b, fl, err)
		}
	}
}

// floorsEqual reports whether a and b hold the same names with equal
// records.
func floorsEqual(a, b floor) bool { return maps.EqualFunc(a, b, entriesEqual) }

// entriesEqual reports whether x and y are the same record: the same live
// part and the same burials in the same order.
func entriesEqual(x, y floorEntry) bool {
	return x.Generation == y.Generation && x.Seq == y.Seq && x.HighWater == y.HighWater && slices.Equal(x.Buried, y.Buried)
}

// checkFloorEntry fails t unless e, name's record, is one every check can
// rely on: a live record (a canonical generation and a sequence) or none,
// at least one burial when there is no live record, at most
// buriedPerNameLimit burials of canonical generations, oldest first, none of
// them the live generation and every delete sequence in 1 to maxDeleteSeq,
// and a high-water mark only on a live record, above its sequence.
func checkFloorEntry(t *testing.T, name string, e floorEntry) {
	t.Helper()
	canonical := func(g string) bool {
		b, err := hex.DecodeString(g)
		return err == nil && len(b) == generationSize && hex.EncodeToString(b) == g
	}
	bs := e.burials()
	if e.live() != (e.Generation != "") || (e.live() && !canonical(e.Generation)) {
		t.Fatalf("record %q has live part %q at sequence %d", name, e.Generation, e.Seq)
	}
	if e.HighWater != 0 && (!e.live() || e.HighWater <= e.Seq) {
		t.Fatalf("record %q has high-water mark %d at sequence %d", name, e.HighWater, e.Seq)
	}
	if !e.live() && len(bs) == 0 {
		t.Fatalf("record %q has sequence 0 and buries nothing", name)
	}
	if len(bs) > buriedPerNameLimit {
		t.Fatalf("record %q holds %d burials, over %d", name, len(bs), buriedPerNameLimit)
	}
	var prev uint64
	for _, b := range bs {
		if !canonical(b.Generation) || b.Generation == e.Generation || b.Deleted <= prev || b.Deleted > maxDeleteSeq {
			t.Fatalf("record %q has burials %+v", name, bs)
		}
		prev = b.Deleted
	}
}

// TestFloorOpsProperty drives random sequences of set, raise, bury, prune,
// merge of a random moved-aside floor with a random keep set, and a lift of
// every delete sequence to end at maxDeleteSeq (so the next bury or merge
// renumbers), each followed by the prune every floor write makes, and checks
// after every step: no record has sequence 0 without a burial; a buried
// generation leaves only by a drop bury, set, merge or prune reports, so a
// merge never un-buries and every drop is reported; no burial appears but by
// bury, set or a merge naming it; a kept name's live record survives the
// merge; and the floor encodes to bytes that parse back to it, within the
// caps. The "full" runs start from live entries that leave the
// tombstones about 1 KiB, so the prune drops burials too. It lowers the
// floor's limits (setSmallFloorLimits), so a full floor is a few dozen
// entries.
func TestFloorOpsProperty(t *testing.T) {
	setSmallFloorLimits(t)
	names := []string{"a", "b", "c", strings.Repeat("n", maxNameLen)}
	var gens [][generationSize]byte
	for i := range 12 {
		var g [generationSize]byte
		g[0], g[15] = byte(i+1), byte(i*7)
		gens = append(gens, g)
	}
	type key struct{ name, gen string }
	for run := range 24 {
		full := run%12 == 11
		rng := rand.New(rand.NewPCG(uint64(run), 0x6b33736d))
		fl := floor{}
		if full {
			e := floorEntry{Generation: strings.Repeat("ab", generationSize), Seq: 1}
			for i, size := 0, fl.liveSize(); size < floorSizeLimit-1024; i++ {
				name := fmt.Sprintf("fill-%s-%06d", strings.Repeat("f", 200), i)
				size += floorEntrySize(name, e) + 1
				fl[name] = e
			}
		}
		want := map[key]bool{}
		prunes := 0
		steps := 400
		if full {
			steps = 80
		}
		for step := range steps {
			name := names[rng.IntN(len(names))]
			gen := gens[rng.IntN(len(gens))]
			var dropped []pruned
			op := ""
			switch rng.IntN(6) {
			case 0:
				op = "set"
				_, g, d := fl.set(name, gen)
				if g != "" {
					want[key{name, g}] = true
				}
				dropped = d
			case 1:
				op = "raise"
				fl.raise(name, gen, uint64(rng.IntN(5)+1))
			case 2:
				op = "bury"
				var dir *[generationSize]byte
				if rng.IntN(2) == 0 {
					dir = &gen
				}
				gs, d := fl.bury(name, dir)
				for _, g := range gs {
					want[key{name, g}] = true
				}
				dropped = d
			case 3:
				op = "prune"
				dropped = fl.prune()
			case 4:
				// Lift every delete sequence, order kept, so the highest
				// is maxDeleteSeq and the next bury renumbers.
				op = "lift"
				if last := fl.lastDeleted(); last > 0 {
					for n, e := range fl {
						e.Buried = slices.Clone(e.Buried)
						for i := range e.burials() {
							e.Buried[i].Deleted += maxDeleteSeq - last
						}
						fl[n] = e
					}
				}
			case 5:
				// Merge a random moved-aside floor, keeping a random name:
				// every burial it adds names a generation the moved-aside
				// floor buries or holds live, a kept name's live record is
				// never buried, and what it drops is reported with the
				// prune's below.
				op = "merge"
				from := floor{}
				for range rng.IntN(4) + 1 {
					n := names[rng.IntN(len(names))]
					g := gens[rng.IntN(len(gens))]
					gh := hex.EncodeToString(g[:])
					e := from[n]
					switch {
					case e.Generation == gh || e.buries(gh):
					case rng.IntN(3) == 0:
						e.Generation, e.Seq = gh, uint64(rng.IntN(5)+1)
					case len(e.burials()) < buriedPerNameLimit:
						e.Buried = append(slices.Clone(e.burials()), burial{Generation: gh, Deleted: uint64(rng.IntN(50) + 1)})
					}
					if e.live() || len(e.burials()) > 0 {
						from[n] = e
					}
				}
				keep := map[string]bool{names[rng.IntN(len(names))]: rng.IntN(2) == 0}
				before := maps.Clone(fl)
				_, d := fl.merge(from, keep)
				named := func(name, g string) bool { return from[name].buries(g) || from[name].Generation == g }
				for name, e := range fl {
					for _, b := range e.burials() {
						if k := (key{name, b.Generation}); !want[k] {
							if !named(name, b.Generation) {
								t.Fatalf("run %d step %d (merge): buried %s %s, which the moved-aside floor does not name", run, step, name, b.Generation)
							}
							want[k] = true
						}
					}
				}
				for _, x := range d {
					// A burial the merge added and then dropped at the cap.
					if k := (key{x.name, x.generation}); !want[k] && named(x.name, x.generation) {
						want[k] = true
					}
				}
				for name := range keep {
					if b := before[name]; keep[name] && b.live() && fl[name].Generation != b.Generation {
						t.Fatalf("run %d step %d (merge): kept %s's live record %+v is now %+v", run, step, name, b, fl[name])
					}
				}
				dropped = d
			}
			more := fl.prune()
			prunes += len(more)
			dropped = append(dropped, more...)
			for _, d := range dropped {
				if !want[key{d.name, d.generation}] {
					t.Fatalf("run %d step %d (%s): dropped %+v, which was not buried", run, step, op, d)
				}
				delete(want, key{d.name, d.generation})
			}
			for k := range want {
				if !fl[k.name].buries(k.gen) {
					t.Fatalf("run %d step %d (%s): %s's buried %s is gone, and no drop reported it", run, step, op, k.name, k.gen)
				}
			}
			n := 0
			for name, e := range fl {
				checkFloorEntry(t, name, e)
				for _, b := range e.burials() {
					if !want[key{name, b.Generation}] {
						t.Fatalf("run %d step %d (%s): %s buries %s, which no bury added", run, step, op, name, b.Generation)
					}
					n++
				}
			}
			if n != len(want) {
				t.Fatalf("run %d step %d (%s): %d burials, want %d", run, step, op, n, len(want))
			}
			if fl.deadSize() > tombstoneSizeLimit || fl.size() > floorSizeLimit {
				t.Fatalf("run %d step %d (%s): tombstones %d bytes, floor %d", run, step, op, fl.deadSize(), fl.size())
			}
			if full && step%25 != 0 {
				continue
			}
			b, err := marshalFloor(fl)
			if err != nil {
				t.Fatal(err)
			}
			if len(b) != fl.size() {
				t.Fatalf("run %d step %d (%s): size %d, encoding %d bytes", run, step, op, fl.size(), len(b))
			}
			back, err := parseFloor(b)
			if err != nil || !floorsEqual(back, fl) {
				t.Fatalf("run %d step %d (%s): the floor does not read back: %v", run, step, op, err)
			}
		}
		if full && prunes == 0 {
			t.Fatalf("run %d: a full run pruned nothing", run)
		}
	}
}

// TestDeleteSequenceNeverWraps: a bury when the floor's highest delete
// sequence is maxDeleteSeq renumbers every burial, order kept, so the new
// one is the highest and the floor still parses; below it, nothing is
// renumbered.
func TestDeleteSequenceNeverWraps(t *testing.T) {
	g := func(b byte) string { return strings.Repeat(fmt.Sprintf("%02x", b), generationSize) }
	a := floorEntry{Buried: []burial{{Generation: g(1), Deleted: maxDeleteSeq - 5}, {Generation: g(2), Deleted: maxDeleteSeq}}}
	// b, the name buried, already holds burials of its own, which the
	// renumber moves too.
	b := floorEntry{Generation: g(3), Seq: 2, Buried: []burial{{Generation: g(5), Deleted: maxDeleteSeq - 7}, {Generation: g(6), Deleted: maxDeleteSeq - 2}}}
	fl := floor{"a": a, "b": b}
	fl["c"] = floorEntry{Buried: []burial{{Generation: g(4), Deleted: maxDeleteSeq - 1}}}
	if got, _ := fl.bury("b", nil); len(got) != 1 || got[0] != g(3) {
		t.Fatalf("bury b buried %q", got)
	}
	// In delete order: b g5, a g1, b g6, c g4, a g2, then the new b g3.
	if bs := fl["a"].burials(); bs[0].Deleted != 2 || bs[1].Deleted != 5 {
		t.Fatalf("a after the renumber = %+v, want 2 and 5", bs)
	}
	if bs := fl["c"].burials(); bs[0].Deleted != 4 {
		t.Fatalf("c after the renumber = %+v, want 4", bs)
	}
	wantB := []burial{{Generation: g(5), Deleted: 1}, {Generation: g(6), Deleted: 3}, {Generation: g(3), Deleted: 6}}
	if bs := fl["b"].burials(); !slices.Equal(bs, wantB) || fl["b"].live() {
		t.Fatalf("b after the bury = %+v, want %+v and no live record", fl["b"], wantB)
	}
	enc, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseFloor(enc)
	if err != nil {
		t.Fatalf("the renumbered floor does not parse: %v", err)
	}
	if !floorsEqual(back, fl) {
		t.Fatalf("the renumbered floor reads back as %+v, want %+v", back, fl)
	}
	// One below the cap: the new burial takes maxDeleteSeq itself.
	fl = floor{"a": {Buried: []burial{{Generation: g(1), Deleted: maxDeleteSeq - 1}}}, "b": {Generation: g(3), Seq: 1}}
	fl.bury("b", nil)
	if fl["a"].Buried[0].Deleted != maxDeleteSeq-1 || fl["b"].Buried[0].Deleted != maxDeleteSeq {
		t.Fatalf("floor after a bury below the cap = %+v", fl)
	}
}
