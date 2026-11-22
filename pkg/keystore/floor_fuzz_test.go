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
	"maps"
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
