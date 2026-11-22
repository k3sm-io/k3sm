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
// as JSON, without the store's decoder; an absent file or field is none.
func tombstonesOf(t *testing.T, server string) map[string]rawTombstone {
	t.Helper()
	b, err := os.ReadFile(floorPath(server))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Tombstones map[string]rawTombstone `json:"tombstones"`
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
	if ts["k"].Generation != gen || ts["k"].Deleted == 0 {
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
	if got := tombstonesOf(t, server)["k"]; got != ts["k"] {
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

// TestTombstoneClearedByPut (U192): a Put of a deleted name mints a new
// generation and replaces the tombstone with a live entry at sequence 1, and
// that live entry's generation still refuses the deleted copy. rm of an
// absent name writes no floor.
func TestTombstoneClearedByPut(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	old := saveEntry(t, server, "k", generationName, "v1", currentName)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok := tombstonesOf(t, server)["k"]; !ok {
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
	if ts := tombstonesOf(t, server); len(ts) != 0 {
		t.Fatalf("tombstones after the Put = %+v, want none", ts)
	}
	if f := floorOf(t, server)["k"]; f.Generation != generationOf(t, server, "k") || f.Seq != 1 {
		t.Fatalf("floor after the Put = %+v, want the new generation at sequence 1", f)
	}
	if b, err := os.ReadFile(floorPath(server)); err != nil || strings.Contains(string(b), "tombstones") {
		t.Fatalf("floor after the Put = %s, %v; want no tombstones field", b, err)
	}
	// The old copy over the new entry is refused by the generation.
	if err := os.RemoveAll(filepath.Join(server, "keystore", "k")); err != nil {
		t.Fatal(err)
	}
	putBack(t, server, old, "k")
	if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Current of the old copy after the new Put: %v, want ErrCorrupt", err)
	}
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
	if ts := tombstonesOf(t, server); ts["a"].Generation != genA || ts["a"].Deleted != 1 {
		t.Fatalf("tombstones = %+v, want a's generation at delete sequence 1", ts)
	}

	// A generation file that does not read: the floor's generation.
	writeFile(t, entryPath(server, "c", generationName), "garbage\n")
	if err := s.Delete(ctx, "c"); err != nil {
		t.Fatalf("Delete of c without the master: %v", err)
	}
	if ts := tombstonesOf(t, server); ts["c"].Generation != genC || ts["c"].Deleted != 2 {
		t.Fatalf("tombstones = %+v, want c's recorded generation at delete sequence 2", ts)
	}

	// An absent floor file: Delete writes one holding the tombstone.
	remove(t, floorPath(server))
	if err := s.Delete(ctx, "b"); err != nil {
		t.Fatalf("Delete of b without the master or a floor: %v", err)
	}
	if ts := tombstonesOf(t, server); len(ts) != 1 || ts["b"].Generation != genB {
		t.Fatalf("tombstones = %+v, want only b's", ts)
	}
}
