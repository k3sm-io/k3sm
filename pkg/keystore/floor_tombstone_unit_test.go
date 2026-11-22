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
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
)

// The tombstone's bound, pruning and encoding: docs/design/keystore.md §
// "Pointer sequence and floor", "A deleted entry put back is refused", gate
// row U192.

// TestTombstonePrune (U192): tombstones take at most maxTombstoneSize of the
// floor and only what live entries leave of maxFloorSize; prune removes them
// oldest first (lowest delete sequence) and never a live entry, and size is
// the encoding's length with tombstones in it.
func TestTombstonePrune(t *testing.T) {
	gen := strings.Repeat("ab", generationSize)
	t.Run("the tombstone budget", func(t *testing.T) {
		fl := floor{"live": {Generation: gen, Seq: 3}}
		n := 0
		for fl.size()-fl.liveSize() <= maxTombstoneSize {
			name := fmt.Sprintf("t-%s-%06d", strings.Repeat("x", 200), n)
			fl[name] = floorEntry{Generation: gen, Seq: 1}
			if !fl.bury(name, nil) {
				t.Fatalf("bury %s changed nothing", name)
			}
			n++
		}
		fl.prune()
		if got := fl.size() - fl.liveSize(); got > maxTombstoneSize {
			t.Fatalf("tombstones after prune take %d bytes, want at most %d", got, maxTombstoneSize)
		}
		if fl["live"].Seq != 3 {
			t.Fatalf("the live entry after prune = %+v", fl["live"])
		}
		// The oldest went: delete sequence 1 is gone and the newest stays.
		var lowest, highest uint64 = 1 << 63, 0
		for _, e := range fl {
			if e.Deleted != 0 {
				lowest, highest = min(lowest, e.Deleted), max(highest, e.Deleted)
			}
		}
		if lowest == 1 || highest != uint64(n) {
			t.Fatalf("after prune the delete sequences span %d to %d, want the oldest pruned and %d kept", lowest, highest, n)
		}
		b, err := marshalFloor(fl)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != fl.size() {
			t.Fatalf("size %d, encoding %d bytes", fl.size(), len(b))
		}
		if back, err := parseFloor(b); err != nil || !maps.Equal(back, fl) {
			t.Fatalf("the pruned floor does not read back: %v", err)
		}
	})
	t.Run("live entries take the room first", func(t *testing.T) {
		fl := floor{}
		e := floorEntry{Generation: gen, Seq: 1}
		for i := 0; fl.liveSize() < maxFloorSize-4096; i++ {
			fl[fmt.Sprintf("l-%s-%06d", strings.Repeat("y", 200), i)] = e
		}
		live := maps.Clone(fl)
		for i := range 64 {
			fl[fmt.Sprintf("t-%03d", i)] = floorEntry{Generation: gen, Deleted: uint64(i + 1)}
		}
		if fl.size() <= maxFloorSize {
			t.Fatalf("setup: floor of %d bytes is not over the cap", fl.size())
		}
		fl.prune()
		if fl.size() > maxFloorSize {
			t.Fatalf("floor after prune is %d bytes, over %d", fl.size(), maxFloorSize)
		}
		for name, e := range live {
			if fl[name] != e {
				t.Fatalf("prune touched the live entry %s", name)
			}
		}
		if _, ok := fl["t-063"]; !ok {
			t.Fatal("prune removed the newest tombstone while older ones could go")
		}
		if _, ok := fl["t-000"]; ok {
			t.Fatal("prune kept the oldest tombstone")
		}
	})
}

// TestTombstoneNeverRefusesPut (U192): a floor full only because of its
// tombstones refuses no Put and no Rotate: the write prunes the oldest
// tombstone and records the live entry. A Delete over a full floor still
// runs.
func TestTombstoneNeverRefusesPut(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	gen := strings.Repeat("cd", generationSize)
	keep := floor{"k": floorOf(t, server)["k"], "old": {Generation: gen, Deleted: 1}, "older": {Generation: gen, Deleted: 2}}
	fillFloor(t, server, keep, maxFloorSize)
	if _, err := s.Put(ctx, "new", KindOpaque, []byte("new")); err != nil {
		t.Fatalf("Put over a floor full of tombstones: %v", err)
	}
	fl := floorOf(t, server)
	if fl["new"].Seq != 1 {
		t.Fatalf("floor new = %+v, want sequence 1", fl["new"])
	}
	if _, ok := fl["old"]; ok {
		t.Fatal("the oldest tombstone was kept, want it pruned first")
	}
	if fl.size() > maxFloorSize {
		t.Fatalf("floor is %d bytes", fl.size())
	}
	mustRotate(t, s, "k", "two")
	if err := s.Delete(ctx, "new"); err != nil {
		t.Fatalf("Delete over a full floor: %v", err)
	}
	if fl := floorOf(t, server); fl["k"].Seq != 2 || fl.size() > maxFloorSize {
		t.Fatalf("floor k after the Delete = %+v, size %d", fl["k"], fl.size())
	}
	// The live entries alone not fitting is still errFloorFull.
	fillFloor(t, server, floor{"k": floorOf(t, server)["k"]}, maxFloorSize)
	if _, err := s.Put(ctx, "more", KindOpaque, []byte("x")); !errors.Is(err, errFloorFull) {
		t.Fatalf("Put over a floor full of live entries: %v, want errFloorFull", err)
	}
}

// TestParseFloorTombstones (U192): a floor with no tombstones field, the
// shape every earlier build wrote, parses as a floor with no tombstones; a
// floor with tombstones parses and encodes back byte for byte; a tombstone
// is parsed as strictly as an entry.
func TestParseFloorTombstones(t *testing.T) {
	const gen = "0123456789abcdef0123456789abcdef"
	old := `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":4}}}` + "\n"
	fl, err := parseFloor([]byte(old))
	if err != nil || !maps.Equal(fl, floor{"a": {Generation: gen, Seq: 4}}) {
		t.Fatalf("parseFloor(old floor) = %v, %v", fl, err)
	}
	if again, err := marshalFloor(fl); err != nil || string(again) != old {
		t.Fatalf("the old floor encodes as %q, %v; want it unchanged", again, err)
	}
	withTomb := `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":4}},"tombstones":{"b":{"generation":"` + gen + `","deleted":2},"c":{"generation":"` + gen + `","deleted":1}}}` + "\n"
	want := floor{"a": {Generation: gen, Seq: 4}, "b": {Generation: gen, Deleted: 2}, "c": {Generation: gen, Deleted: 1}}
	fl, err = parseFloor([]byte(withTomb))
	if err != nil || !maps.Equal(fl, want) {
		t.Fatalf("parseFloor(tombstones) = %v, %v; want %v", fl, err, want)
	}
	if again, err := marshalFloor(fl); err != nil || string(again) != withTomb || len(again) != fl.size() {
		t.Fatalf("the floor with tombstones encodes as %q, %v", again, err)
	}
	onlyTomb := `{"version":1,"scope":"system","entries":{},"tombstones":{"b":{"generation":"` + gen + `","deleted":1}}}`
	if _, err := parseFloor([]byte(onlyTomb)); err != nil {
		t.Fatalf("parseFloor(only a tombstone): %v", err)
	}
	head := `{"version":1,"scope":"system","entries":{},"tombstones":`
	for name, b := range map[string]string{
		"empty tombstones":       head + `{}}`,
		"null tombstones":        head + `null}`,
		"deleted zero":           head + `{"b":{"generation":"` + gen + `","deleted":0}}}`,
		"a seq in a tombstone":   head + `{"b":{"generation":"` + gen + `","deleted":1,"seq":1}}}`,
		"an unknown field":       head + `{"b":{"generation":"` + gen + `","deleted":1,"x":1}}}`,
		"an uppercase gen":       head + `{"b":{"generation":"` + strings.ToUpper(gen) + `","deleted":1}}}`,
		"a short gen":            head + `{"b":{"generation":"abcd","deleted":1}}}`,
		"a bad name":             head + `{"B/x":{"generation":"` + gen + `","deleted":1}}}`,
		"a duplicate tombstone":  head + `{"b":{"generation":"` + gen + `","deleted":1},"b":{"generation":"` + gen + `","deleted":2}}}`,
		"deleted in an entry":    `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":1,"deleted":1}}}`,
		"tombstones first":       `{"version":1,"scope":"system","tombstones":{"b":{"generation":"` + gen + `","deleted":1}},"entries":{}}`,
		"live and tombstoned":    `{"version":1,"scope":"system","entries":{"b":{"generation":"` + gen + `","seq":1}},"tombstones":{"b":{"generation":"` + gen + `","deleted":1}}}`,
		"unsorted tombstones":    head + `{"c":{"generation":"` + gen + `","deleted":1},"b":{"generation":"` + gen + `","deleted":2}}}`,
		"case-variant tombstone": `{"version":1,"scope":"system","entries":{},"Tombstones":{"b":{"generation":"` + gen + `","deleted":1}}}`,
	} {
		if fl, err := parseFloor([]byte(b)); !errors.Is(err, errFloorMalformed) || fl != nil {
			t.Errorf("%s: parseFloor(%q) = %v, %v; want errFloorMalformed", name, b, fl, err)
		}
	}
}
