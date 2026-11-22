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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The tests for the floor's tombstone, through the store's verbs:
// docs/design/keystore.md § "Pointer sequence and floor", "A deleted entry
// put back is refused", gate rows G23 and U192.

// rawTombstone is a tombstone as the floor file encodes it, read without the
// store's decoder.
type rawTombstone struct {
	Generation string `json:"generation"`
	Deleted    uint64 `json:"deleted"`
}

// tombstonesOf reads the tombstones object of the floor file under server,
// as JSON, without the store's decoder: each name's buried generations,
// oldest first. An absent file or field is none.
func tombstonesOf(t *testing.T, server string) map[string][]rawTombstone {
	t.Helper()
	b, err := os.ReadFile(floorPath(server))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Tombstones map[string][]rawTombstone `json:"tombstones"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Tombstones
}

// generationOf is the hex generation in name's generation file.
func generationOf(t *testing.T, server, name string) string {
	t.Helper()
	b, err := os.ReadFile(entryPath(server, name, generationName))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(b), "\n")
}

// saveEntry copies name's files into a directory beside the store and
// returns it, so the test can put the entry back after a Delete.
func saveEntry(t *testing.T, server, name string, files ...string) string {
	t.Helper()
	old := filepath.Join(server, "old-"+name)
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		copyFile(t, entryPath(server, name, f), filepath.Join(old, f))
	}
	return old
}

// putBack renames the saved directory old into place as name's entry.
func putBack(t *testing.T, server, old, name string) {
	t.Helper()
	if err := os.Rename(old, filepath.Join(server, "keystore", name)); err != nil {
		t.Fatal(err)
	}
}

// TestTombstoneRefusesPutBack (G23): a completed Delete leaves a tombstone of
// the deleted generation, and an old copy of the entry put back before any
// new Put of the name is refused by every reader and verb, never recorded in
// the floor, and removed by rm, which keeps the tombstone. A put-back copy
// with no current is damage, not an interrupted Put.
func TestTombstoneRefusesPutBack(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	mustRotate(t, s, "k", "two")
	mustPut(t, s, "live", KindOpaque, []byte("live"))
	gen := generationOf(t, server, "k")
	old := saveEntry(t, server, "k", generationName, "v1", "v2", currentName)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	ts := tombstonesOf(t, server)
	if len(ts["k"]) != 1 || ts["k"][0].Generation != gen || ts["k"][0].Deleted == 0 {
		t.Fatalf("tombstones after the Delete = %+v, want k's generation %s", ts, gen)
	}
	floorBefore, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	putBack(t, server, old, "k")

	refused := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "records as deleted") || strings.Contains(err.Error(), "restore it from backup") {
			t.Errorf("%s of the put-back entry: %v, want ErrCorrupt naming the tombstone", what, err)
		}
	}
	_, _, err = s.Current(ctx, "k")
	refused("Current", err)
	_, _, err = s.Get(ctx, "k", 1)
	refused("Get", err)
	_, err = s.Rotate(ctx, "k", []byte("three"))
	refused("Rotate", err)
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "k" {
		t.Fatalf("List = %+v, want k and live", list)
	}
	refused("List", list[0].Err)
	if list[1].Err != nil {
		t.Fatalf("List live: %v", list[1].Err)
	}
	refused("Rewrap", s.Rewrap(ctx, rewrapKey(7)))
	if _, err := s.Put(ctx, "k", KindOpaque, []byte("new")); !errors.Is(err, ErrExists) || !strings.Contains(err.Error(), "records as deleted") {
		t.Errorf("Put over the put-back entry: %v, want ErrExists naming the tombstone", err)
	}
	if err := s.RaiseFloor(ctx); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || string(after) != string(floorBefore) {
		t.Fatalf("floor after RaiseFloor = %s, %v; want it unchanged, %s", after, err, floorBefore)
	}
	mustCurrent(t, s, "live", "live")

	// rm removes the put-back entry and keeps the tombstone.
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete of the put-back entry: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("put-back entry after Delete: %v, want it gone", err)
	}
	if got := tombstonesOf(t, server)["k"]; !slices.Equal(got, ts["k"]) {
		t.Fatalf("tombstone after the second Delete = %+v, want %+v kept", got, ts["k"])
	}

	// A copy with no current, in the shape a crashed Put leaves.
	mustPut(t, s, "p", KindOpaque, []byte("one"))
	old = saveEntry(t, server, "p", generationName, "v1")
	if err := s.Delete(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	putBack(t, server, old, "p")
	_, _, err = s.Current(ctx, "p")
	refused("Current with no current", err)
	if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNotFound) {
		t.Errorf("Current with no current: %v, want damage, not an interrupted put", err)
	}
	list, err = s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range list {
		if e.Name == "p" {
			found = true
			refused("List with no current", e.Err)
		}
	}
	if !found {
		t.Errorf("List = %+v, want the put-back p with Err", list)
	}
	if _, err := s.Put(ctx, "p", KindOpaque, []byte("new")); !errors.Is(err, ErrExists) {
		t.Errorf("Put over the put-back p: %v, want ErrExists", err)
	}
	if err := s.Delete(ctx, "p"); err != nil {
		t.Fatalf("Delete of the put-back p: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "p")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("put-back p after Delete: %v, want it gone", err)
	}
}

// TestTombstoneKeptByPut (U192): a Put of a deleted name mints a new
// generation and records it live at sequence 1 beside the name's buried
// generation, which it keeps, so the deleted copy is still refused as
// deleted. rm of an absent name writes no floor.
func TestTombstoneKeptByPut(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	old := saveEntry(t, server, "k", generationName, "v1", currentName)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	buried := tombstonesOf(t, server)["k"]
	if len(buried) != 1 {
		t.Fatal("no tombstone after the Delete")
	}
	floorBefore, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete of an absent name: %v, want ErrNotFound", err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || string(after) != string(floorBefore) {
		t.Fatalf("floor after rm of an absent name = %s, %v; want it unchanged", after, err)
	}
	mustPut(t, s, "k", KindOpaque, []byte("two"))
	if ts := tombstonesOf(t, server); len(ts) != 1 || !slices.Equal(ts["k"], buried) {
		t.Fatalf("tombstones after the Put = %+v, want k's kept, %+v", ts, buried)
	}
	if f := floorOf(t, server)["k"]; f.Generation != generationOf(t, server, "k") || f.Seq != 1 {
		t.Fatalf("floor after the Put = %+v, want the new generation at sequence 1", f)
	}
	// The old copy over the new entry is refused as deleted.
	if err := os.RemoveAll(filepath.Join(server, "keystore", "k")); err != nil {
		t.Fatal(err)
	}
	putBack(t, server, old, "k")
	_, _, err = s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of the old copy after the new Put", err)
}

// TestDeleteWithoutMasterTombstones (U192): Delete needs no master to write
// its tombstone: with the floor present, over an absent floor file (which it
// writes holding only the tombstone), and for a generation file that does
// not read, whose tombstone takes the floor's recorded generation.
func TestDeleteWithoutMasterTombstones(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	mustPut(t, s, "b", KindOpaque, []byte("b"))
	mustPut(t, s, "c", KindOpaque, []byte("c"))
	genA, genB, genC := generationOf(t, server, "a"), generationOf(t, server, "b"), generationOf(t, server, "c")
	remove(t, filepath.Join(server, "cred", "keystore-master", masterName))

	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete without the master: %v", err)
	}
	if ts := tombstonesOf(t, server); len(ts["a"]) != 1 || ts["a"][0].Generation != genA || ts["a"][0].Deleted != 1 {
		t.Fatalf("tombstones = %+v, want a's generation at delete sequence 1", ts)
	}

	// A generation file that does not read: the floor's generation.
	writeFile(t, entryPath(server, "c", generationName), "garbage\n")
	if err := s.Delete(ctx, "c"); err != nil {
		t.Fatalf("Delete of c without the master: %v", err)
	}
	if ts := tombstonesOf(t, server); len(ts["c"]) != 1 || ts["c"][0].Generation != genC || ts["c"][0].Deleted != 2 {
		t.Fatalf("tombstones = %+v, want c's recorded generation at delete sequence 2", ts)
	}

	// An absent floor file: Delete writes one holding the tombstone.
	remove(t, floorPath(server))
	if err := s.Delete(ctx, "b"); err != nil {
		t.Fatalf("Delete of b without the master or a floor: %v", err)
	}
	if ts := tombstonesOf(t, server); len(ts) != 1 || len(ts["b"]) != 1 || ts["b"][0].Generation != genB {
		t.Fatalf("tombstones = %+v, want only b's", ts)
	}
}

// copyEntryAs copies the saved entry directory old to a new directory beside
// the store, named dst, with its generation file replaced by gen when gen is
// set, and returns it: an attacker's planted copy.
func copyEntryAs(t *testing.T, server, old, dst, gen string, files ...string) string {
	t.Helper()
	d := filepath.Join(server, dst)
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		copyFile(t, filepath.Join(old, f), filepath.Join(d, f))
	}
	if gen != "" {
		writeFile(t, filepath.Join(d, generationName), gen+"\n")
	}
	return d
}

// refusedAsDeleted fails t unless err refuses a put-back copy as a deleted
// generation.
func refusedAsDeleted(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "records as deleted") {
		t.Fatalf("%s: %v, want ErrCorrupt naming the deleted generation", what, err)
	}
}

// TestTombstoneSurvivesPlantedGeneration (G23): a directory planted under a
// deleted name with another generation in its generation file, removed by
// root's rm, never replaces the tombstone, so the original deleted copy put
// back afterwards is still refused.
func TestTombstoneSurvivesPlantedGeneration(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	files := []string{generationName, "v1", currentName}
	// 1. The real entry, and a copy of it.
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	old := saveEntry(t, server, "k", files...)
	// 2. Root deletes it: the tombstone records its generation.
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	// 3. A copy with a changed generation file is planted under the name.
	planted := copyEntryAs(t, server, old, "planted", strings.Repeat("ee", generationSize), files...)
	putBack(t, server, planted, "k")
	// 4. Root runs rm on it.
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete of the planted copy: %v", err)
	}
	// 5. The original deleted copy put back is still refused.
	putBack(t, server, old, "k")
	_, _, err := s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of the original copy after the planted rm", err)
}

// TestTombstonesKeptAcrossRecreate (G23, U192): a Put of a deleted name does
// not clear the name's buried generations. The first deleted copy is refused
// while the re-created entry is live, and after it is deleted too.
func TestTombstonesKeptAcrossRecreate(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	files := []string{generationName, "v1", currentName}
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	g1 := saveEntry(t, server, "k", files...)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, "k", KindOpaque, []byte("two"))
	g2 := copyEntryAs(t, server, filepath.Join(server, "keystore", "k"), "g2", "", files...)

	// G1 over the live G2.
	if err := os.Rename(filepath.Join(server, "keystore", "k"), filepath.Join(server, "live-k")); err != nil {
		t.Fatal(err)
	}
	g1copy := copyEntryAs(t, server, g1, "g1-copy", "", files...)
	putBack(t, server, g1copy, "k")
	_, _, err := s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of G1 while G2 is live", err)
	if err := os.RemoveAll(filepath.Join(server, "keystore", "k")); err != nil {
		t.Fatal(err)
	}
	putBack(t, server, filepath.Join(server, "live-k"), "k")
	mustCurrent(t, s, "k", "two")

	// G2 deleted: both of its predecessors stay refused.
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	putBack(t, server, g1, "k")
	_, _, err = s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of G1 after G2 is deleted", err)
	if err := os.RemoveAll(filepath.Join(server, "keystore", "k")); err != nil {
		t.Fatal(err)
	}
	putBack(t, server, g2, "k")
	_, _, err = s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of G2 after it is deleted", err)
}

// TestDeleteBuriesFloorGeneration (G23): rm of a decoy directory swapped in
// under a live name buries the generation the floor records live, not the
// decoy's, so the real entry put back afterwards is refused.
func TestDeleteBuriesFloorGeneration(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	files := []string{generationName, "v1", currentName}
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	real := saveEntry(t, server, "k", files...)
	// The decoy: the same files under another generation.
	writeFile(t, entryPath(server, "k", generationName), strings.Repeat("dd", generationSize)+"\n")
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete of the decoy: %v", err)
	}
	putBack(t, server, real, "k")
	_, _, err := s.Current(ctx, "k")
	refusedAsDeleted(t, "Current of the real entry after the decoy rm", err)
}

// TestBuriedErrorPointsToRestore: the refusal of a put-back copy of a
// deleted entry, from a reader and from Put, points to the same-backup
// restore recipe in docs/user/keys.md, and suggests neither rm of the entry
// nor removing the floor, which would discard every burial.
func TestBuriedErrorPointsToRestore(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	files := []string{generationName, "v1", currentName}
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	old := saveEntry(t, server, "k", files...)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	putBack(t, server, old, "k")
	_, _, rerr := s.Current(ctx, "k")
	_, perr := s.Put(ctx, "k", KindOpaque, []byte("new"))
	for what, err := range map[string]error{"Current": rerr, "Put": perr} {
		if err == nil {
			t.Fatalf("%s of the put-back copy succeeded", what)
		}
		msg := err.Error()
		if !strings.Contains(msg, `"Backing Up and Restoring" in docs/user/keys.md`) {
			t.Errorf("%s: %q, want it to point to the same-backup restore in docs/user/keys.md", what, msg)
		}
		for _, bad := range []string{"rm ", "backup-restore.md", "Restoring an older", "remov"} {
			if strings.Contains(msg, bad) {
				t.Errorf("%s: %q suggests %q", what, msg, bad)
			}
		}
	}
}

// crashAt makes s's step seam fail at the step named at, as a crash there
// would, until the returned function restores it.
func crashAt(s *FileStore, at string) func() {
	old := s.step
	s.step = func(name string) error {
		if name == at {
			return errors.New("crash at " + at)
		}
		return old(name)
	}
	return func() { s.step = old }
}

// TestDeleteBuriesWithDirectoryGone (G23): a Delete that finds no entry
// directory under a name the floor records live buries that live
// generation, root's own record, and succeeds; only a name with no live
// record is ErrNotFound. So the directory hidden during rm, or left gone by
// a Delete that crashed before its floor write and was run again, is
// refused when it is put back. A Put over the live record such a crash
// leaves buries it first.
func TestDeleteBuriesWithDirectoryGone(t *testing.T) {
	ctx := context.Background()
	files := []string{generationName, "v1", currentName}
	t.Run("the directory hidden during rm", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		hidden := filepath.Join(server, "hidden-k")
		if err := os.Rename(filepath.Join(server, "keystore", "k"), hidden); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatalf("Delete with the directory hidden: %v, want the deletion recorded", err)
		}
		putBack(t, server, hidden, "k")
		_, _, err := s.Current(ctx, "k")
		refusedAsDeleted(t, "Current of the directory moved back", err)
	})
	t.Run("the keystore directory hidden during rm", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		ks, hidden := filepath.Join(server, "keystore"), filepath.Join(server, "hidden-keystore")
		if err := os.Rename(ks, hidden); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatalf("Delete with keystore/ hidden: %v, want the deletion recorded", err)
		}
		if err := s.Delete(ctx, "other"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Delete of a name with no record, keystore/ hidden: %v, want ErrNotFound", err)
		}
		if err := os.Rename(hidden, ks); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.Current(ctx, "k")
		refusedAsDeleted(t, "Current after keystore/ moved back", err)
	})
	t.Run("a crash before the floor write, then rm again", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		old := saveEntry(t, server, "k", files...)
		restore := crashAt(s, "bury k")
		if err := s.Delete(ctx, "k"); err == nil {
			t.Fatal("Delete through the crash seam succeeded")
		}
		restore()
		if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("entry after the crashed Delete: %v, want it gone", err)
		}
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatalf("Delete run again: %v, want the deletion recorded", err)
		}
		putBack(t, server, old, "k")
		_, _, err := s.Current(ctx, "k")
		refusedAsDeleted(t, "Current of the copy after the rerun rm", err)
	})
	t.Run("a crashed Delete, a Put, then a Delete", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		g1 := saveEntry(t, server, "k", files...)
		restore := crashAt(s, "bury k")
		if err := s.Delete(ctx, "k"); err == nil {
			t.Fatal("Delete through the crash seam succeeded")
		}
		restore()
		mustPut(t, s, "k", KindOpaque, []byte("two"))
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		putBack(t, server, g1, "k")
		_, _, err := s.Current(ctx, "k")
		refusedAsDeleted(t, "Current of G1 after G2 is deleted", err)
	})
	t.Run("a decoy in place of the directory", func(t *testing.T) {
		for _, decoy := range []string{"symlink", "interrupted put"} {
			t.Run(decoy, func(t *testing.T) {
				s, server := newTestStore(t)
				mustPut(t, s, "k", KindOpaque, []byte("one"))
				hidden := filepath.Join(server, "hidden-k")
				at := filepath.Join(server, "keystore", "k")
				if err := os.Rename(at, hidden); err != nil {
					t.Fatal(err)
				}
				switch decoy {
				case "symlink":
					if err := os.Symlink("elsewhere", at); err != nil {
						t.Fatal(err)
					}
				default:
					if err := os.Mkdir(at, 0o700); err != nil {
						t.Fatal(err)
					}
					writeFile(t, filepath.Join(at, generationName), strings.Repeat("ee", generationSize)+"\n")
				}
				if err := s.Delete(ctx, "k"); err != nil {
					t.Fatalf("Delete of the decoy: %v, want the deletion recorded", err)
				}
				putBack(t, server, hidden, "k")
				_, _, err := s.Current(ctx, "k")
				refusedAsDeleted(t, "Current of the directory moved back", err)
			})
		}
	})
	t.Run("no live record", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(floorPath(server))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Delete of a buried name with no directory: %v, want ErrNotFound", err)
		}
		if after, err := os.ReadFile(floorPath(server)); err != nil || string(after) != string(before) {
			t.Fatalf("floor after rm of a gone name = %s, %v; want it unchanged", after, err)
		}
	})
}
