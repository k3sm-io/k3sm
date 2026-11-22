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
	"slices"
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
	r, err := s.MergeFloor(ctx, MergeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Fenced) != 1 || r.Fenced[0] != "k" {
		t.Fatalf("MergeFloor = %+v, want k fenced", r)
	}
	if e := floorOf(t, server)["k"]; e.Seq != 5 || e.HighWater != 10 {
		t.Fatalf("floor after the merge = %+v, want seq 5 and high-water 10 (one past the moved-aside seq 9)", e)
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
	if e := floorOf(t, server)["k"]; e.Seq != 11 || e.HighWater != 0 {
		t.Fatalf("floor after the rotate = %+v, want seq 11 and no mark", e)
	}
	mustCurrent(t, s, "k", "after")
	t.Run("after the rotate", func(t *testing.T) { refused(t, false) })
}

// writeFloorAt writes fl to path as the floor is written, mode 0644.
func writeFloorAt(t *testing.T, path string, fl floor) {
	t.Helper()
	b, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFloorMergeFenceLaggingFloors: either floor can lag its pointer by one
// (a crash between the pointer flip and the floor write). A moved-aside
// floor one behind its pointer still fences that pointer: the mark is one
// past the moved-aside floor's record. A restored floor one behind its
// pointer has the restored pointer, authenticated under the master,
// recorded before the fence, so the restored entry is never inside it; one
// that does not authenticate is left as it is and reported.
func TestFloorMergeFenceLaggingFloors(t *testing.T) {
	ctx := context.Background()
	t.Run("a moved-aside floor one behind its pointer", func(t *testing.T) {
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
		for i := 6; i <= 10; i++ {
			mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
		}
		late := filepath.Join(tmp, "late")
		copyEntryDir(t, filepath.Join(server, "keystore", "k"), late)
		// The floor write after the pointer flip to 10 never landed.
		fl := floorOf(t, server)
		e := fl["k"]
		e.Seq = 9
		fl["k"] = e
		aside := floorPath(server) + ".pre-restore"
		writeFloorAt(t, aside, fl)
		if err := os.Remove(floorPath(server)); err != nil {
			t.Fatal(err)
		}
		replaceEntryDir(t, server, "k", backup)
		if err := os.WriteFile(floorPath(server), backupFloor, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := s.MergeFloor(ctx, MergeOptions{}); err != nil {
			t.Fatal(err)
		}
		if e := floorOf(t, server)["k"]; e.Seq != 5 || e.HighWater != 10 {
			t.Fatalf("floor after the merge = %+v, want seq 5 and high-water 10", e)
		}
		mustCurrent(t, s, "k", "v5")
		replaceEntryDir(t, server, "k", late)
		var stale *staleError
		if _, _, err := s.Current(ctx, "k"); !errors.As(err, &stale) || !stale.abandoned {
			t.Fatalf("Current over the pre-restore seq-10 copy: %v, want it refused as abandoned", err)
		}
	})
	restoreLagging := func(t *testing.T, master bool) (*FileStore, string, MergeReport) {
		t.Helper()
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("v1"))
		for i := 2; i <= 5; i++ {
			mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
		}
		backupFloor, err := os.ReadFile(floorPath(server))
		if err != nil {
			t.Fatal(err)
		}
		// The backup's entry is one rotate past the floor saved with it.
		mustRotate(t, s, "k", "v6")
		tmp := t.TempDir()
		backup := filepath.Join(tmp, "backup")
		copyEntryDir(t, filepath.Join(server, "keystore", "k"), backup)
		for i := 7; i <= 9; i++ {
			mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
		}
		aside := floorPath(server) + ".pre-restore"
		if err := os.Rename(floorPath(server), aside); err != nil {
			t.Fatal(err)
		}
		replaceEntryDir(t, server, "k", backup)
		if err := os.WriteFile(floorPath(server), backupFloor, 0o644); err != nil {
			t.Fatal(err)
		}
		if !master {
			if err := os.WriteFile(filepath.Join(s.masterDir, masterName), make([]byte, 32), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		r, err := s.MergeFloor(ctx, MergeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return s, server, r
	}
	t.Run("a restored floor one behind its pointer", func(t *testing.T) {
		s, server, r := restoreLagging(t, true)
		if e := floorOf(t, server)["k"]; e.Seq != 6 || e.HighWater != 10 {
			t.Fatalf("floor after the merge = %+v, want seq 6 (the restored pointer) and high-water 10", e)
		}
		if len(r.Unverified) != 0 {
			t.Fatalf("MergeFloor = %+v, want nothing unverified", r)
		}
		mustCurrent(t, s, "k", "v6")
	})
	t.Run("a restored pointer that does not authenticate", func(t *testing.T) {
		_, server, r := restoreLagging(t, false)
		if e := floorOf(t, server)["k"]; e.Seq != 5 || e.HighWater != 10 {
			t.Fatalf("floor after the merge = %+v, want seq 5 left as is and high-water 10", e)
		}
		if !slices.Equal(r.Unverified, []string{"k"}) {
			t.Fatalf("MergeFloor = %+v, want k reported unverified", r)
		}
	})
}
