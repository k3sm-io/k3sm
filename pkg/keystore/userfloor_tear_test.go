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
	"strings"
	"testing"
)

// Every two-bit flip of a tombstone line, read as a skipped line, taints
// the line's true key or is unrecovered: no pair of flips that changes a
// separator or the checksum's shape and also the scope or name can taint
// another key alone.
func TestEveryTwoBitTombstoneFlipTaintsTrueKeyOrUnrecovered(t *testing.T) {
	k := floorKey{"user/1001", "gone", guid(0x51)}
	tomb, err := tombLine(k.scope, k.name, k.gen)
	if err != nil {
		t.Fatal(err)
	}
	body := tomb[:len(tomb)-1]
	nbits := 8 * len(body)
	wrong, cases := 0, 0
	p := append([]byte(nil), body...)
	for a := range nbits {
		p[a/8] ^= 1 << (a % 8)
		for b := a + 1; b < nbits; b++ {
			p[b/8] ^= 1 << (b % 8)
			cases++
			var st logState
			st.taintLine(0, p)
			if !st.tainted(k) && !st.unrecovered {
				wrong++
				if wrong <= 5 {
					t.Errorf("%q: neither taints %+v nor is unrecovered", p, k)
				}
			}
			p[b/8] ^= 1 << (b % 8)
		}
		p[a/8] ^= 1 << (a % 8)
	}
	t.Logf("%d of %d two-bit flips neither taint the true key nor are unrecovered", wrong, cases)
	if wrong > 0 {
		t.Fail()
	}
}

// tearWitness is couldBeTear's oracle, by search rather than by field: a
// line in the grammar that starts with p, built by completing p's last
// field with each of a few suffixes and the fields after it with fixed
// ones, or false when none parses.
func tearWitness(p []byte) ([]byte, bool) {
	f := bytes.Split(p, []byte{' '})
	if len(f) > 5 {
		return nil, false
	}
	last := len(f) - 1
	fill := []string{"user/1001", "a", strings.Repeat("0", 2*generationSize), "1"}
	var suffixes []string
	switch last {
	case 0:
		for m := range maxUIDDigits + 1 {
			suffixes = append(suffixes, strings.Repeat("0", m), strings.Repeat("9", m))
		}
		for _, u := range []uint32{minScopeUID, maxScopeUID, 1001} {
			if s := userScopeOf(u); strings.HasPrefix(s, string(f[0])) {
				suffixes = append(suffixes, s[len(f[0]):])
			}
		}
	case 1:
		suffixes = []string{"", "a"}
		if strings.HasPrefix(deliveriesFloorName, string(f[1])) {
			suffixes = append(suffixes, deliveriesFloorName[len(f[1]):])
		}
	case 2:
		suffixes = []string{strings.Repeat("0", max(0, 2*generationSize-len(f[2])))}
	case 3:
		suffixes = []string{"", "0", "1", "m", "rm"}
	case 4:
		suffixes = []string{""}
	}
	for _, sfx := range suffixes {
		fields := make([]string, 4)
		for i := range 4 {
			switch {
			case i < last:
				fields[i] = string(f[i])
			case i == last:
				fields[i] = string(f[i]) + sfx
			default:
				fields[i] = fill[i]
			}
		}
		body := []byte(strings.Join(fields, " "))
		cand := appendFloorCRC(body)
		if _, err := parseFloorLine(cand); err == nil && bytes.HasPrefix(cand, p) {
			return cand, true
		}
	}
	return nil, false
}

// couldBeTearLines is a valid line of each shape, for the tear oracle.
func couldBeTearLines(t testing.TB) [][]byte {
	t.Helper()
	var out [][]byte
	for _, c := range []struct {
		scope, name string
		seq         uint64
		tomb        bool
	}{
		{"user/1001", "token", 123, false},
		{"user/501", deliveriesFloorName, 18446744073709551615, false},
		{"user/2147483647", strings.Repeat("n", maxNameLen), 0, true},
		{"user/600", "a-b.c", 0, false},
		{"user/999999", "x", 0, true},
	} {
		var l []byte
		var err error
		if c.tomb {
			l, err = tombLine(c.scope, c.name, guid(0x5D))
		} else {
			l, err = floorLine(c.scope, c.name, guid(0x5D), c.seq)
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, l[:len(l)-1])
	}
	return out
}

// Every prefix of every valid line could be a tear, and every one-byte
// change of such a prefix could be one exactly when the oracle finds a
// line in the grammar that starts with it.
func TestCouldBeTearMatchesOracle(t *testing.T) {
	for _, l := range couldBeTearLines(t) {
		for n := 0; n <= len(l); n++ {
			if !couldBeTear(l[:n]) {
				t.Fatalf("%q, a prefix of a valid line: couldBeTear false", l[:n])
			}
			checkTearOracle(t, l[:n])
		}
	}
}

// checkTearOracle fails unless couldBeTear(p) agrees with the oracle.
func checkTearOracle(t testing.TB, p []byte) {
	t.Helper()
	w, ok := tearWitness(p)
	if got := couldBeTear(p); got != ok {
		t.Fatalf("%q: couldBeTear %v, the oracle %v (witness %q)", p, got, ok, w)
	}
}

// FuzzCouldBeTear checks couldBeTear against the search oracle on prefixes
// of valid lines with bytes changed, and on arbitrary bytes.
func FuzzCouldBeTear(f *testing.F) {
	for _, l := range couldBeTearLines(f) {
		f.Add(l, uint16(len(l)), uint16(0), byte(0))
		f.Add(l, uint16(12), uint16(10), byte(' '))
	}
	f.Add([]byte("user/1"), uint16(6), uint16(0), byte(0))
	f.Fuzz(func(t *testing.T, line []byte, cut, at uint16, x byte) {
		if len(line) > maxLogLine {
			return
		}
		p := append([]byte(nil), line[:min(int(cut), len(line))]...)
		if len(p) > 0 {
			p[int(at)%len(p)] ^= x
		}
		if bytes.IndexByte(p, '\n') >= 0 {
			if couldBeTear(p) {
				t.Fatalf("%q, with a newline: couldBeTear true", p)
			}
			return
		}
		checkTearOracle(t, p)
	})
}

// FuzzBurialFlips flips at most two bits of a committed three-tombstone
// burial buffer, closed by the next append, and reads each damaged line as
// the floor does: every buried key is buried by its whole tombstone,
// tainted, or the floor is unrecovered.
func FuzzBurialFlips(f *testing.F) {
	f.Add(uint16(60), byte(0), uint16(0), byte(0))
	f.Add(uint16(5), byte(1), uint16(70), byte(2))
	f.Add(uint16(40), byte(3), uint16(41), byte(5))
	_, keys, buf := burialKeys(f)
	f.Fuzz(func(t *testing.T, a uint16, ab byte, b uint16, bb byte) {
		p := append([]byte(nil), buf...)
		p[int(a)%len(p)] ^= 1 << (ab % 8)
		if b != 0 {
			p[int(b)%len(p)] ^= 1 << (bb % 8)
		}
		st := readBurial(p)
		for _, k := range keys {
			if !st.buried[k] && !st.tainted(k) && !st.unrecovered {
				t.Fatalf("%q: %+v neither buried, tainted nor unrecovered", p, k)
			}
		}
	})
}

// burialState is what readBurial learns of a buffer's lines.
type burialState struct {
	logState
	buried map[floorKey]bool
}

// readBurial reads buf, an append buffer closed by the next append's
// newline, line by line as the floor's reader does: a line that parses
// buries its tombstone's key, any other non-empty line is taintLine's.
func readBurial(buf []byte) *burialState {
	st := &burialState{buried: map[floorKey]bool{}}
	off := int64(0)
	for _, line := range bytes.Split(append(append([]byte(nil), buf...), '\n'), []byte{'\n'}) {
		if len(line) > 0 {
			if r, err := parseFloorLine(line); err == nil {
				if r.tomb {
					st.buried[r.key] = true
				}
			} else {
				st.taintLine(off, line)
			}
		}
		off += int64(len(line)) + 1
	}
	return st
}

// The readBurial model agrees with the floor on the exhaustive buffer test:
// no single-bit flip leaves a buried key unrefused.
func TestReadBurialEverySingleFlip(t *testing.T) {
	_, keys, buf := burialKeys(t)
	for i := range buf {
		for bit := range 8 {
			p := append([]byte(nil), buf...)
			p[i] ^= 1 << bit
			st := readBurial(p)
			for _, k := range keys {
				if !st.buried[k] && !st.tainted(k) && !st.unrecovered {
					t.Fatalf("byte %d bit %d: %+v neither buried, tainted nor unrecovered", i, bit, k)
				}
			}
		}
	}
}
