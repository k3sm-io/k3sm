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
	"math/rand/v2"
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
		if err != nil || !maps.Equal(back, fl) {
			t.Fatalf("the accepted floor does not encode back: %v, %v != %v", err, back, fl)
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
		if fl, err := parseFloor(b); err != nil || !maps.Equal(fl, good) {
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

// checkFloorEntry fails t unless e, name's record, is one every check can
// rely on: a live record (a canonical generation and a sequence) or none,
// at least one burial when there is no live record, at most
// maxBuriedPerName burials of canonical generations, oldest first, none of
// them the live generation and every delete sequence in 1 to maxDeleteSeq.
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
	if !e.live() && len(bs) == 0 {
		t.Fatalf("record %q has sequence 0 and buries nothing", name)
	}
	for i := len(bs); i < len(e.Buried); i++ {
		if e.Buried[i] != (burial{}) {
			t.Fatalf("record %q has a burial after its last: %+v", name, e.Buried)
		}
	}
	var prev uint64
	for _, b := range bs {
		if !canonical(b.Generation) || b.Generation == e.Generation || b.Deleted <= prev || b.Deleted > maxDeleteSeq {
			t.Fatalf("record %q has burials %+v", name, bs)
		}
		prev = b.Deleted
	}
}

// TestFloorOpsProperty drives random sequences of set, raise, bury and
// prune, each followed by the prune every floor write makes, and checks
// after every step: no record has sequence 0 without a burial; a buried
// generation leaves only by a drop bury or prune reports; no burial appears
// but by bury; and the floor encodes to bytes that parse back to it, within
// the caps. The "full" runs start from live entries that leave the
// tombstones about 1 KiB, so the prune drops burials too.
func TestFloorOpsProperty(t *testing.T) {
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
			for i, size := 0, fl.liveSize(); size < maxFloorSize-1024; i++ {
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
			switch rng.IntN(4) {
			case 0:
				op = "set"
				fl.set(name, gen)
			case 1:
				op = "raise"
				fl.raise(name, gen, uint64(rng.IntN(5)+1))
			case 2:
				op = "bury"
				var dir *[generationSize]byte
				if rng.IntN(2) == 0 {
					dir = &gen
				}
				g, d := fl.bury(name, dir)
				if g != "" {
					want[key{name, g}] = true
				}
				dropped = d
			case 3:
				op = "prune"
				dropped = fl.prune()
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
			if fl.deadSize() > maxTombstoneSize || fl.size() > maxFloorSize {
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
			if err != nil || !maps.Equal(back, fl) {
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
	var a floorEntry
	a.Buried[0] = burial{Generation: g(1), Deleted: maxDeleteSeq - 5}
	a.Buried[1] = burial{Generation: g(2), Deleted: maxDeleteSeq}
	fl := floor{"a": a, "b": {Generation: g(3), Seq: 2}}
	fl["c"] = floorEntry{Buried: [maxBuriedPerName]burial{{Generation: g(4), Deleted: maxDeleteSeq - 1}}}
	if got, _ := fl.bury("b", nil); got != g(3) {
		t.Fatalf("bury b buried %q", got)
	}
	if bs := fl["a"].burials(); bs[0].Deleted != 1 || bs[1].Deleted != 3 {
		t.Fatalf("a after the renumber = %+v, want 1 and 3", bs)
	}
	if bs := fl["c"].burials(); bs[0].Deleted != 2 {
		t.Fatalf("c after the renumber = %+v, want 2", bs)
	}
	if bs := fl["b"].burials(); len(bs) != 1 || bs[0].Deleted != 4 || fl["b"].live() {
		t.Fatalf("b after the bury = %+v, want buried at 4", fl["b"])
	}
	b, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseFloor(b); err != nil {
		t.Fatalf("the renumbered floor does not parse: %v", err)
	}
	// One below the cap: the new burial takes maxDeleteSeq itself.
	fl = floor{"a": {Buried: [maxBuriedPerName]burial{{Generation: g(1), Deleted: maxDeleteSeq - 1}}}, "b": {Generation: g(3), Seq: 1}}
	fl.bury("b", nil)
	if fl["a"].Buried[0].Deleted != maxDeleteSeq-1 || fl["b"].Buried[0].Deleted != maxDeleteSeq {
		t.Fatalf("floor after a bury below the cap = %+v", fl)
	}
}
