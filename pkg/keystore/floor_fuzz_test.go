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
	"encoding/json"
	"errors"
	"maps"
	"testing"
)

// FuzzParseFloor drives the floor file's decoder. The floor is root-owned,
// but it is the one file under the data root the keystore parses, and a
// restore or a stray copy can put any bytes there, so the decoder must refuse
// anything a root verb would not have written, as errFloorMalformed, and
// never panic. What it accepts must be a floor every check can rely on, and
// must encode back to the same floor. The seeds are committed under
// testdata/fuzz/FuzzParseFloor.
func FuzzParseFloor(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		fl, err := parseFloor(b)
		if err != nil {
			if !errors.Is(err, errFloorMalformed) {
				t.Fatalf("parseFloor error %v is not errFloorMalformed", err)
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
			g, err := hex.DecodeString(e.Generation)
			if err != nil || len(g) != generationSize || hex.EncodeToString(g) != e.Generation {
				t.Fatalf("accepted generation %q for %q", e.Generation, name)
			}
			if e.Seq == 0 {
				t.Fatalf("accepted sequence 0 for %q", name)
			}
		}
		again, err := json.Marshal(floorFile{Version: floorFormat, Entries: fl})
		if err != nil {
			t.Fatal(err)
		}
		back, err := parseFloor(again)
		if err != nil || !maps.Equal(back, fl) {
			t.Fatalf("the accepted floor does not encode back: %v, %v != %v", err, back, fl)
		}
	})
}
