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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests for Delete's order: it buries the floor's live record before it
// touches the entry's tree, so a removal the service user makes fail, or a
// crash during it, leaves the entry already deleted (docs/design/keystore.md
// § "Pointer sequence and floor", gate row G23).

// TestDeleteFaultAfterBurial (G23): a fault after the burial and before the
// removal fails the Delete with an error saying the entry is already deleted
// and its directory left behind; the entry is refused as deleted, and a
// retried rm removes the directory without changing the floor.
func TestDeleteFaultAfterBurial(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	gen := generationOf(t, server, "k")
	restore := crashAt(s, "remove k")
	err := s.Delete(ctx, "k")
	restore()
	if err == nil || !strings.Contains(err.Error(), "already deleted") || !strings.Contains(err.Error(), "left behind") {
		t.Fatalf("Delete through a fault after the burial: %v, want the already-deleted, left-behind error", err)
	}
	if ts := tombstonesOf(t, server); len(ts["k"]) != 1 || ts["k"][0].Generation != gen {
		t.Fatalf("tombstones after the fault = %+v, want k's generation %s", ts, gen)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); err != nil {
		t.Fatalf("entry directory after the fault: %v, want it left behind", err)
	}
	_, _, err = s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of the entry left behind", err)

	// The retried rm clears the directory with no floor change.
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("retried Delete: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry directory after the retried Delete: %v, want it gone", err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("floor after the retried Delete = %s, %v; want it unchanged, %s", after, err, before)
	}
}

// TestDeleteBuriesPastPlantedNames (G23): more names under keystore/ than a
// directory read takes, which the service user can plant, make the sync of
// the other entries' floors fail; the Delete still buries from the floor
// alone and removes the entry. It lowers the sync's bound to smallDirNames,
// so it plants smallDirNames+1 names; TestFloorProductionLimits plants
// maxDirNames+1.
func TestDeleteBuriesPastPlantedNames(t *testing.T) {
	setSeam(t, &floorDirNamesBound, smallDirNames)
	deleteBuriesPastPlantedNames(t)
}

// deleteBuriesPastPlantedNames is TestDeleteBuriesPastPlantedNames at the
// sync's bound as it stands, floorDirNamesBound: it plants one name more.
func deleteBuriesPastPlantedNames(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	gen := generationOf(t, server, "k")
	old := saveEntry(t, server, "k", generationName, "v1", currentName)
	ks := filepath.Join(server, "keystore")
	for i := range floorDirNamesBound + 1 {
		f, err := os.Create(filepath.Join(ks, fmt.Sprintf("planted-%06d", i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete with too many planted names: %v, want the burial to land", err)
	}
	if ts := tombstonesOf(t, server); len(ts["k"]) != 1 || ts["k"][0].Generation != gen {
		t.Fatalf("tombstones = %+v, want k's generation %s", ts, gen)
	}
	putBack(t, server, old, "k")
	_, _, err := s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of the copy put back", err)
}

// TestDeleteBuriesAuthenticatedDirectoryGeneration (G23, U192): when the
// directory under the name has another generation than the floor's live
// record and its pointer authenticates under it with the master, Delete
// buries both, the floor's live generation first, so a copy of either put
// back is refused as deleted. A decoy whose pointer does not authenticate
// under its generation file still buries only the floor's live one.
func TestDeleteBuriesAuthenticatedDirectoryGeneration(t *testing.T) {
	ctx := context.Background()
	files := []string{generationName, "v1", currentName}
	other := strings.Repeat("11", generationSize)
	t.Run("authenticated", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		mustPut(t, s, "other", KindOpaque, []byte("one"))
		gen := generationOf(t, server, "k")
		old := saveEntry(t, server, "k", files...)
		start := floorOf(t, server)
		putFloorFile(t, server, floor{"k": {Generation: other, Seq: 1}, "other": start["other"]})
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		ts := tombstonesOf(t, server)["k"]
		if len(ts) != 2 || ts[0].Generation != other || ts[1].Generation != gen {
			t.Fatalf("tombstones of k = %+v, want the floor's live %s, then the directory's %s", ts, other, gen)
		}
		putBack(t, server, old, "k")
		_, _, err := s.Current(ctx, "k")
		refusedAsDeleted(t, "Current of the authenticated directory put back", err)
	})
	t.Run("a decoy generation file", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		gen := generationOf(t, server, "k")
		writeFile(t, entryPath(server, "k", generationName), strings.Repeat("dd", generationSize)+"\n")
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		if ts := tombstonesOf(t, server)["k"]; len(ts) != 1 || ts[0].Generation != gen {
			t.Fatalf("tombstones of k = %+v, want only the floor's live %s", ts, gen)
		}
	})
}

// TestPerNameCapIsBackstop (U192): a name keeps 64 buried generations, so
// the tombstone budget, not the per-name cap, is the main eviction; the
// 65th burial drops the name's oldest and reports it.
func TestPerNameCapIsBackstop(t *testing.T) {
	fl := floor{}
	var first string
	for i := range 65 {
		g := fmt.Sprintf("%032x", i+1)
		if i == 0 {
			first = g
		}
		fl["k"] = floorEntry{Generation: g, Seq: 1, Buried: fl["k"].Buried}
		_, dropped := fl.bury("k", nil)
		switch {
		case i < 64 && len(dropped) != 0:
			t.Fatalf("burial %d dropped %+v, want all of the first 64 kept", i+1, dropped)
		case i == 64 && (len(dropped) != 1 || dropped[0].generation != first):
			t.Fatalf("burial 65 dropped %+v, want the oldest, %s", dropped, first)
		}
	}
	if n := len(fl["k"].burials()); n != 64 {
		t.Fatalf("k holds %d burials, want 64", n)
	}
}

// TestDeleteWithoutMasterWarnsUnrecorded (U192): a master-less Delete of a
// directory with a current pointer under a name the floor records nothing
// live for buries nothing, and logs at Warn that its generation is not
// recorded, naming the remedy: rerun rm with the master. A master-less
// Delete of a name the floor records live does not log it.
func TestDeleteWithoutMasterWarnsUnrecorded(t *testing.T) {
	ctx := context.Background()
	const residual = "rerun rm with the master"
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	mustPut(t, s, "live", KindOpaque, []byte("one"))
	remove(t, filepath.Join(server, "cred", "keystore-master", masterName))
	buf := captureWarn(t)
	if err := s.Delete(ctx, "live"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), residual) {
		t.Fatalf("a master-less Delete of a recorded name logged %q", buf)
	}
	putFloorFile(t, server, floor{})
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "level=WARN") || !strings.Contains(got, residual) || !strings.Contains(got, "name=k") {
		t.Fatalf("log of a master-less Delete with no record = %q, want a Warn naming k and %q", got, residual)
	}
}

// TestDeleteReportsEvictedTombstone (U192): when the floor is at its
// tombstone budget and the write that buries a Delete's generation prunes
// that very burial, Delete removes the entry but fails with
// ErrTombstoneEvicted: a copy of the entry put back is accepted again.
func TestDeleteReportsEvictedTombstone(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	old := saveEntry(t, server, "k", generationName, "v1", currentName)
	setFloorLimits(t, smallFloorSize, 10) // smaller than one burial
	err := s.Delete(ctx, "k")
	if !errors.Is(err, ErrTombstoneEvicted) || !strings.Contains(err.Error(), "tombstone budget") {
		t.Fatalf("Delete whose burial is pruned in the same write: %v, want ErrTombstoneEvicted", err)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry after the evicting Delete: %v, want it removed", err)
	}
	if ts := tombstonesOf(t, server); len(ts["k"]) != 0 {
		t.Fatalf("tombstones = %+v, want k's evicted", ts)
	}
	putBack(t, server, old, "k")
	if _, _, err := s.Current(ctx, "k"); err != nil {
		t.Fatalf("Current of the copy put back after the eviction: %v, want it accepted, as the error warned", err)
	}
}

// TestDeleteWarnsUnrecordedWithMaster (U192): with the master loaded, a
// Delete that buries nothing (no live record, and a pointer that does not
// authenticate) logs at Warn that the generation is not recorded, as a
// master-less one does.
func TestDeleteWarnsUnrecordedWithMaster(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	putFloorFile(t, server, floor{})
	writeFile(t, filepath.Join(server, "keystore", "k", currentName), "not a sealed pointer")
	buf := captureWarn(t)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "level=WARN") || !strings.Contains(got, "name=k") || !strings.Contains(got, "does not authenticate under the master") {
		t.Fatalf("log of a Delete that buried nothing with the master = %q, want a Warn naming k and that its pointer does not authenticate", got)
	}
}
