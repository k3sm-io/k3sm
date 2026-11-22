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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests for the floor's high-water mark, which a floor merge sets on a
// restored live generation so the history the restore set aside, at higher
// sequences, never outranks it (docs/design/keystore.md § "Restoring with
// the saved floor", gate row U192).

// TestFloorHighWaterEncoding (U192): a live record's high-water mark is
// written as "highwater" after "seq" only when set, parses back, is counted
// by floorEntrySize, and a mark at or below seq, or written as 0, is refused.
func TestFloorHighWaterEncoding(t *testing.T) {
	g := mgen(1)
	fl := floor{"k": {Generation: g, Seq: 5, HighWater: 9}, "plain": {Generation: g, Seq: 2}}
	b, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	want := `"k":{"generation":"` + g + `","seq":5,"highwater":9}`
	if !strings.Contains(string(b), want) || strings.Count(string(b), "highwater") != 1 {
		t.Fatalf("floor encoding %s, want %s and no other highwater", b, want)
	}
	back, err := parseFloor(b)
	if err != nil || !floorsEqual(back, fl) {
		t.Fatalf("parseFloor of the encoding = %v, %v; want %v", back, err, fl)
	}
	if got, want := fl.liveSize(), len(b); got != want {
		t.Errorf("liveSize = %d, want the encoding's %d bytes", got, want)
	}
	for name, s := range map[string]string{
		"at seq":       `{"version":1,"scope":"system","entries":{"k":{"generation":"` + g + `","seq":5,"highwater":5}}}`,
		"below seq":    `{"version":1,"scope":"system","entries":{"k":{"generation":"` + g + `","seq":5,"highwater":4}}}`,
		"written as 0": `{"version":1,"scope":"system","entries":{"k":{"generation":"` + g + `","seq":5,"highwater":0}}}`,
		"before seq":   `{"version":1,"scope":"system","entries":{"k":{"generation":"` + g + `","highwater":9,"seq":5}}}`,
	} {
		if _, err := parseFloor([]byte(s)); !errors.Is(err, errFloorMalformed) {
			t.Errorf("%s: parseFloor = %v, want errFloorMalformed", name, err)
		}
	}
}

// TestFloorHighWaterCheckRaise (U192): check refuses a pointer of the live
// generation above seq and at or below the mark, and accepts one above it;
// raise never raises into the mark and clears it when it raises above; a
// Put of a new generation and a burial clear it.
func TestFloorHighWaterCheckRaise(t *testing.T) {
	var g [generationSize]byte
	hg := hex.EncodeToString(g[:])
	fl := floor{"k": {Generation: hg, Seq: 5, HighWater: 9}}
	for seq, ok := range map[uint64]bool{4: false, 5: true, 6: false, 9: false, 10: true} {
		err := fl.check("k", g, seq)
		var stale *staleError
		if (err == nil) != ok {
			t.Errorf("check(seq %d) = %v, want ok=%v", seq, err, ok)
		}
		if seq >= 6 && seq <= 9 && (!errors.As(err, &stale) || !stale.abandoned) {
			t.Errorf("check(seq %d) = %v, want the abandoned-history refusal", seq, err)
		}
	}
	if fl.raise("k", g, 9) || fl["k"].Seq != 5 {
		t.Fatalf("raise to 9 under the mark changed the floor: %+v", fl["k"])
	}
	if !fl.raise("k", g, 10) || fl["k"].Seq != 10 || fl["k"].HighWater != 0 {
		t.Fatalf("raise to 10 = %+v, want seq 10 and the mark cleared", fl["k"])
	}
	fl = floor{"k": {Generation: hg, Seq: 5, HighWater: 9}}
	var other [generationSize]byte
	other[0] = 1
	if changed, _, _ := fl.set("k", other); !changed || fl["k"].HighWater != 0 {
		t.Errorf("set of a new generation = %+v, want the mark cleared", fl["k"])
	}
	fl = floor{"k": {Generation: hg, Seq: 5, HighWater: 9}}
	fl.bury("k", nil)
	if e := fl["k"]; e.live() || e.HighWater != 0 {
		t.Errorf("bury = %+v, want no live record and no mark", e)
	}
}

// copyEntryDir copies the entry directory from to to, a new directory, each
// file and the directory given to the service user as the store expects.
func copyEntryDir(t *testing.T, from, to string) {
	t.Helper()
	names, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(to, 0o700); err != nil {
		t.Fatal(err)
	}
	giveToService(t, to)
	for _, n := range names {
		p := filepath.Join(to, n.Name())
		copyFile(t, filepath.Join(from, n.Name()), p)
		giveToService(t, p)
	}
}

// replaceEntryDir replaces server's entry directory for name with a copy of
// from.
func replaceEntryDir(t *testing.T, server, name, from string) {
	t.Helper()
	dir := filepath.Join(server, "keystore", name)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	copyEntryDir(t, from, dir)
}

// TestFloorMergeFencesAbandonedHistory (U192): an entry backed up at
// sequence 5 and rotated to 9 before the restore is restored at 5. The merge
// sets the restored record's high-water mark to 9, so a copy of the seq-9
// entry put back is refused, by the merge's mark before the next Rotate and
// by the Rotate's sequence after it (which is above 9), and the restored
// entry is read and rotated as usual.
func TestFloorMergeFencesAbandonedHistory(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v1"))
	for i := 2; i <= 5; i++ {
		mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
	}
	tmp := t.TempDir()
	backup := filepath.Join(tmp, "backup")
	copyEntryDir(t, filepath.Join(server, "keystore", "k"), backup)
	backupFloor, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	for i := 6; i <= 9; i++ {
		mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
	}
	if got := floorOf(t, server)["k"].Seq; got != 9 {
		t.Fatalf("floor before the restore at seq %d, want 9", got)
	}
	late := filepath.Join(tmp, "late")
	copyEntryDir(t, filepath.Join(server, "keystore", "k"), late)

	// The restore: the live floor moved aside, the backup put back.
	aside := floorPath(server) + ".pre-restore"
	if err := os.Rename(floorPath(server), aside); err != nil {
		t.Fatal(err)
	}
	replaceEntryDir(t, server, "k", backup)
	if err := os.WriteFile(floorPath(server), backupFloor, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := s.MergeFloor(ctx, aside, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Fenced) != 1 || r.Fenced[0] != "k" {
		t.Fatalf("MergeFloor = %+v, want k fenced", r)
	}
	if e := floorOf(t, server)["k"]; e.Seq != 5 || e.HighWater != 9 {
		t.Fatalf("floor after the merge = %+v, want seq 5 and high-water 9", e)
	}
	mustCurrent(t, s, "k", "v5")

	refused := func(t *testing.T, abandoned bool) {
		t.Helper()
		replaceEntryDir(t, server, "k", late)
		var stale *staleError
		if _, _, err := s.Current(ctx, "k"); !errors.As(err, &stale) || stale.abandoned != abandoned {
			t.Fatalf("Current over the seq-9 copy: %v, want a floor refusal (abandoned=%v)", err, abandoned)
		}
		if err := s.RaiseFloor(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Current(ctx, "k"); !errors.As(err, &stale) {
			t.Fatalf("Current over the seq-9 copy after RaiseFloor: %v, want the floor refusal still", err)
		}
	}
	t.Run("before the rotate", func(t *testing.T) { refused(t, true) })
	replaceEntryDir(t, server, "k", backup)
	mustRotate(t, s, "k", "after")
	if e := floorOf(t, server)["k"]; e.Seq != 10 || e.HighWater != 0 {
		t.Fatalf("floor after the rotate = %+v, want seq 10 and no mark", e)
	}
	mustCurrent(t, s, "k", "after")
	t.Run("after the rotate", func(t *testing.T) { refused(t, false) })
}
