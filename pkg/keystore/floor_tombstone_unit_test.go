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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"testing"
)

// The tombstone's bound, pruning and encoding: docs/design/keystore.md §
// "Pointer sequence and floor", "A deleted entry put back is refused", gate
// row U192.

// buriedEntry is a record with no live entry that buries gen once per
// delete sequence in deleted, oldest first.
func buriedEntry(gen string, deleted ...uint64) floorEntry {
	var e floorEntry
	for i, d := range deleted {
		e.Buried[i] = burial{Generation: gen, Deleted: d}
	}
	return e
}

// TestTombstonePrune (U192): tombstones take at most maxTombstoneSize of the
// floor and only what live entries leave of maxFloorSize; prune removes them
// oldest first (lowest delete sequence) and never a live entry, and size is
// the encoding's length with tombstones in it.
func TestTombstonePrune(t *testing.T) {
	gen := strings.Repeat("ab", generationSize)
	t.Run("the tombstone budget", func(t *testing.T) {
		fl := floor{"live": {Generation: gen, Seq: 3}}
		n := 0
		for fl.deadSize() <= maxTombstoneSize {
			name := fmt.Sprintf("t-%s-%06d", strings.Repeat("x", 200), n)
			fl[name] = floorEntry{Generation: gen, Seq: 1}
			if g, _ := fl.bury(name, nil); g != gen {
				t.Fatalf("bury %s buried %q, want the live generation", name, g)
			}
			n++
		}
		if got := fl.prune(); len(got) == 0 || len(got) >= n {
			t.Fatalf("prune dropped %d of %d burials", len(got), n)
		}
		if got := fl.deadSize(); got > maxTombstoneSize {
			t.Fatalf("tombstones after prune take %d bytes, want at most %d", got, maxTombstoneSize)
		}
		if fl["live"].Seq != 3 {
			t.Fatalf("the live entry after prune = %+v", fl["live"])
		}
		// The oldest went: delete sequence 1 is gone and the newest stays.
		var lowest, highest uint64 = 1 << 63, 0
		for _, e := range fl {
			for _, b := range e.burials() {
				lowest, highest = min(lowest, b.Deleted), max(highest, b.Deleted)
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
			fl[fmt.Sprintf("t-%03d", i)] = buriedEntry(gen, uint64(i+1))
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
	keep := floor{"k": floorOf(t, server)["k"], "old": buriedEntry(gen, 1), "older": buriedEntry(gen, 2)}
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

// TestParseFloorTombstones (U192): a floor with no tombstones field parses
// as a floor that buries nothing; a floor with tombstones, a name with a live
// entry and burials included, parses and encodes back byte for byte; a
// burial is parsed as strictly as an entry, and the bounds hold on read.
func TestParseFloorTombstones(t *testing.T) {
	const gen = "0123456789abcdef0123456789abcdef"
	const gen2 = "fedcba9876543210fedcba9876543210"
	old := `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":4}}}` + "\n"
	fl, err := parseFloor([]byte(old))
	if err != nil || !maps.Equal(fl, floor{"a": {Generation: gen, Seq: 4}}) {
		t.Fatalf("parseFloor(old floor) = %v, %v", fl, err)
	}
	if again, err := marshalFloor(fl); err != nil || string(again) != old {
		t.Fatalf("the old floor encodes as %q, %v; want it unchanged", again, err)
	}
	withTomb := `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":4}},"tombstones":{"a":[{"generation":"` + gen2 + `","deleted":3}],"b":[{"generation":"` + gen + `","deleted":2}],"c":[{"generation":"` + gen + `","deleted":1},{"generation":"` + gen2 + `","deleted":4}]}}` + "\n"
	a := floorEntry{Generation: gen, Seq: 4}
	a.Buried[0] = burial{Generation: gen2, Deleted: 3}
	c := buriedEntry(gen, 1)
	c.Buried[1] = burial{Generation: gen2, Deleted: 4}
	want := floor{"a": a, "b": buriedEntry(gen, 2), "c": c}
	fl, err = parseFloor([]byte(withTomb))
	if err != nil || !maps.Equal(fl, want) {
		t.Fatalf("parseFloor(tombstones) = %v, %v; want %v", fl, err, want)
	}
	if again, err := marshalFloor(fl); err != nil || string(again) != withTomb || len(again) != fl.size() {
		t.Fatalf("the floor with tombstones encodes as %q, %v", again, err)
	}
	onlyTomb := `{"version":1,"scope":"system","entries":{},"tombstones":{"b":[{"generation":"` + gen + `","deleted":1}]}}`
	if _, err := parseFloor([]byte(onlyTomb)); err != nil {
		t.Fatalf("parseFloor(only a tombstone): %v", err)
	}
	head := `{"version":1,"scope":"system","entries":{},"tombstones":`
	one := func(g string, d uint64) string { return fmt.Sprintf(`{"generation":%q,"deleted":%d}`, g, d) }
	var nine []string
	for i := range maxBuriedPerName + 1 {
		nine = append(nine, one(fmt.Sprintf("%032x", i), uint64(i+1)))
	}
	for name, b := range map[string]string{
		"empty tombstones":          head + `{}}`,
		"null tombstones":           head + `null}`,
		"an empty list":             head + `{"b":[]}}`,
		"a null list":               head + `{"b":null}}`,
		"an object, not a list":     head + `{"b":` + one(gen, 1) + `}}`,
		"deleted zero":              head + `{"b":[` + one(gen, 0) + `]}}`,
		"deleted past the cap":      head + `{"b":[` + one(gen, maxDeleteSeq+1) + `]}}`,
		"deleted at MaxUint64":      head + `{"b":[{"generation":"` + gen + `","deleted":18446744073709551615}]}}`,
		"a seq in a tombstone":      head + `{"b":[{"generation":"` + gen + `","deleted":1,"seq":1}]}}`,
		"an unknown field":          head + `{"b":[{"generation":"` + gen + `","deleted":1,"x":1}]}}`,
		"an uppercase gen":          head + `{"b":[` + one(strings.ToUpper(gen), 1) + `]}}`,
		"a short gen":               head + `{"b":[` + one("abcd", 1) + `]}}`,
		"a bad name":                head + `{"B/x":[` + one(gen, 1) + `]}}`,
		"a duplicate tombstone":     head + `{"b":[` + one(gen, 1) + `],"b":[` + one(gen, 2) + `]}}`,
		"a generation buried twice": head + `{"b":[` + one(gen, 1) + `,` + one(gen, 2) + `]}}`,
		"burials newest first":      head + `{"b":[` + one(gen, 2) + `,` + one(gen2, 1) + `]}}`,
		"a delete sequence reused":  head + `{"b":[` + one(gen, 1) + `],"c":[` + one(gen, 1) + `]}}`,
		"over the per-name cap":     head + `{"b":[` + strings.Join(nine, ",") + `]}}`,
		"deleted in an entry":       `{"version":1,"scope":"system","entries":{"a":{"generation":"` + gen + `","seq":1,"deleted":1}}}`,
		"tombstones first":          `{"version":1,"scope":"system","tombstones":{"b":[` + one(gen, 1) + `]},"entries":{}}`,
		"live and buried":           `{"version":1,"scope":"system","entries":{"b":{"generation":"` + gen + `","seq":1}},"tombstones":{"b":[` + one(gen, 1) + `]}}`,
		"unsorted tombstones":       head + `{"c":[` + one(gen, 1) + `],"b":[` + one(gen, 2) + `]}}`,
		"case-variant tombstone":    `{"version":1,"scope":"system","entries":{},"Tombstones":{"b":[` + one(gen, 1) + `]}}`,
	} {
		if fl, err := parseFloor([]byte(b)); !errors.Is(err, errFloorMalformed) || fl != nil {
			t.Errorf("%s: parseFloor(%q) = %v, %v; want errFloorMalformed", name, b, fl, err)
		}
	}
	// Tombstones over maxTombstoneSize are refused on read, even inside
	// maxFloorSize.
	big := floor{}
	for i := 0; big.deadSize() <= maxTombstoneSize; i++ {
		big[fmt.Sprintf("t-%s-%06d", strings.Repeat("z", 200), i)] = buriedEntry(gen, uint64(i+1))
	}
	b, err := marshalFloor(big)
	if err != nil {
		t.Fatal(err)
	}
	if fl, err := parseFloor(b); !errors.Is(err, errFloorMalformed) || fl != nil {
		t.Errorf("parseFloor(tombstones of %d bytes) = %v; want errFloorMalformed", big.deadSize(), err)
	}
}

// captureWarn sends the default slog logger to a buffer for the rest of
// the test and returns it.
func captureWarn(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestPruneLogsAtWarn (U192): every burial a floor write drops is logged at
// Warn with the count and the names: the per-name cap's drop, and the
// floor's prune. A Delete whose own new burial the same write prunes says
// so.
func TestPruneLogsAtWarn(t *testing.T) {
	ctx := context.Background()
	t.Run("the per-name cap", func(t *testing.T) {
		s, _ := newTestStore(t)
		buf := captureWarn(t)
		for range maxBuriedPerName {
			mustPut(t, s, "k", KindOpaque, []byte("v"))
			if err := s.Delete(ctx, "k"); err != nil {
				t.Fatal(err)
			}
		}
		if buf.Len() != 0 {
			t.Fatalf("logged before the cap: %s", buf)
		}
		mustPut(t, s, "k", KindOpaque, []byte("v"))
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		if got := buf.String(); !strings.Contains(got, "level=WARN") || !strings.Contains(got, "count=1") || !strings.Contains(got, "names=[k]") {
			t.Fatalf("log at the per-name cap = %q, want a Warn with count=1 and names=[k]", got)
		}
	})
	t.Run("Delete's own burial pruned", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("v"))
		fillFloor(t, server, floor{"k": floorOf(t, server)["k"]}, maxFloorSize)
		buf := captureWarn(t)
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatalf("Delete over a full floor: %v", err)
		}
		got := buf.String()
		if !strings.Contains(got, "level=WARN") || !strings.Contains(got, "count=1") || !strings.Contains(got, "names=[k]") {
			t.Fatalf("log of the prune = %q, want a Warn with count=1 and names=[k]", got)
		}
		if !strings.Contains(got, "the burial this delete wrote was pruned") {
			t.Fatalf("log = %q, want the Delete to say its own burial was pruned", got)
		}
	})
}
