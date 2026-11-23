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
	"fmt"
	"testing"
)

// FuzzDeleteUnderGuardAtLimit (U192): a Delete under the guard numbers its
// burial above guardEraSeq whatever the floor's highest delete sequence,
// and when that would pass the sequence limit the renumber keeps the guard
// band: every earlier guard-era burial stays above guardEraSeq, every other
// one stays below it, order kept, none past maxDeleteSeq. The seeds put the
// highest sequence at guardEraSeq (2^52) and one short of the limit
// (2^53-1).
func FuzzDeleteUnderGuardAtLimit(f *testing.F) {
	f.Add(guardEraSeq, uint8(3))
	f.Add(maxDeleteSeq-1, uint8(3))
	f.Fuzz(func(t *testing.T, last uint64, n uint8) {
		if last < 2 || last > maxDeleteSeq {
			return
		}
		fl := floor{
			"old": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}},
			"top": {Buried: []burial{{Generation: mgen(2), Deleted: last}}},
		}
		topGuarded := last > guardEraSeq
		var names []string
		for i := range int(n%8) + 1 {
			name := fmt.Sprintf("k%d", i)
			fl[name] = floorEntry{Generation: mgen(10 + i), Seq: 1}
			if gs, _ := fl.buryAbove(name, nil, guardEraSeq); len(gs) != 1 {
				t.Fatalf("bury %s under the guard buried %v, want one generation", name, gs)
			}
			names = append(names, name)
			if d := fl["old"].burials()[0].Deleted; d > guardEraSeq {
				t.Fatalf("old's burial at %d after bury %d, want it below guardEraSeq", d, i)
			}
			if d := fl["top"].burials()[0].Deleted; (d > guardEraSeq) != topGuarded {
				t.Fatalf("top's burial at %d after bury %d, want guard-era %v", d, i, topGuarded)
			}
			prev := fl["top"].burials()[0].Deleted
			if !topGuarded {
				prev = guardEraSeq
			}
			for _, k := range names {
				d := fl[k].burials()[0].Deleted
				if d <= prev || d > maxDeleteSeq {
					t.Fatalf("%s's burial at %d after bury %d, want it above %d and the guard band, at most maxDeleteSeq", k, d, i, prev)
				}
				prev = d
			}
			b, err := marshalFloor(fl)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseFloor(b); err != nil {
				t.Fatalf("the floor after bury %d does not parse: %v", i, err)
			}
		}
	})
}

// TestDeleteRenormalisesStaleBand (U192): a Delete with no guard pending on
// a floor holding a burial above guardEraSeq (a band left behind with no
// keystore-floor.json.pre-restore) renumbers every burial back below it,
// order kept, so the next guard tells its burials apart again.
func TestDeleteRenormalisesStaleBand(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	fl := floorOf(t, server)
	fl["stale"] = floorEntry{Buried: []burial{{Generation: mgen(1), Deleted: guardEraSeq + 7}}}
	putFloorFile(t, server, fl)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	after := floorOf(t, server)
	stale, k := after["stale"].burials(), after["k"].burials()
	if len(stale) != 1 || len(k) != 1 || stale[0].Deleted > guardEraSeq || k[0].Deleted > guardEraSeq || stale[0].Deleted >= k[0].Deleted {
		t.Fatalf("after the Delete stale = %+v, k = %+v; want both below guardEraSeq, stale first", stale, k)
	}
}
