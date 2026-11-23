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
	"errors"
	"strings"
	"testing"
)

// burialKeys are three known keys, a live line each in the floor, and
// burialBuffer the one append that buries all three: "\n" and three
// tombstones, each with its newline.
func burialKeys(t testing.TB) (live []byte, keys []floorKey, buf []byte) {
	t.Helper()
	keys = []floorKey{
		{"user/1001", "gone", guid(0x51)},
		{"user/1001", "also", guid(0x52)},
		{"user/2147483647", strings.Repeat("n", 40), guid(0x53)},
	}
	buf = []byte{'\n'}
	for i, k := range keys {
		l, err := floorLine(k.scope, k.name, k.gen, uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		live = append(live, l...)
		tomb, err := tombLine(k.scope, k.name, k.gen)
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, tomb...)
	}
	return live, keys, buf
}

// Every single-bit flip of a three-tombstone burial buffer, its leading
// and interior newlines included, closed by the next append, keeps every
// buried known generation refused: a copy-back of any of them is never
// served. A flipped interior newline merges two tombstones into one line
// that cannot be a tear, so it is corrected (both recovered keys tainted)
// or refuses every generation as unrecovered.
func TestEveryBurialBufferFlipRefusesEveryBuried(t *testing.T) {
	s, _, _ := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	live, keys, buf := burialKeys(t)
	closer, err := floorLine("user/1002", "other", guid(0x11), 1)
	if err != nil {
		t.Fatal(err)
	}
	base := append(readLog(t, s, userFloorLogName), live...)
	served := 0
	for i := range buf {
		for bit := range 8 {
			p := append([]byte(nil), buf...)
			p[i] ^= 1 << bit
			b := append(append(append(append([]byte(nil), base...), p...), '\n'), closer...)
			setFloorBytes(t, s, b)
			for _, k := range keys {
				if _, err := ff.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) && !errors.Is(err, errFloorBuried) {
					served++
					t.Errorf("byte %d bit %d: %s %s, buried and known: %v, want errFloorDegraded or errFloorBuried", i, bit, k.scope, k.name, err)
				}
			}
		}
	}
	t.Logf("%d of %d (flip, buried key) cases serve a buried generation", served, 8*len(buf)*len(keys))
}
