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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMergeFloorIgnoresEntryLock (U192): the merge writes only the
// root-owned floor under keystore-lock and never takes keystore/.lock, which
// the service user can hold or replace, so a held .lock leaves the merge's
// burials written. A .lock replaced by a directory is no file the keystore
// writes, so the staged tree's shape check refuses it, naming it, with
// nothing written: the merge still never waits on it.
func TestMergeFloorIgnoresEntryLock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		plant   func(t *testing.T, lock string)
		refused bool
	}{
		{"held", func(t *testing.T, lock string) {
			held, err := os.Open(lock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = held.Close() })
			if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"replaced by a directory", func(t *testing.T, lock string) {
			remove(t, lock)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			giveToService(t, lock)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, server := newTestStore(t)
			mustPut(t, s, "k", KindOpaque, []byte("one"))
			s.lockWait = 200 * time.Millisecond
			writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
			tc.plant(t, filepath.Join(server, "keystore", lockName))
			r, err := mergeStaged(t, s, ctx, MergeOptions{})
			if tc.refused {
				if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), lockName) {
					t.Fatalf("MergeFloor under a %s .lock = %+v, %v; want the staged tree refused naming %s", tc.name, r, err, lockName)
				}
				if fl := readFloorFile(t, server); fl["gone"].buries(mgen(1)) {
					t.Fatalf("floor after the refused merge = %+v, want nothing written", fl)
				}
				return
			}
			if err != nil || r.Merged != 1 {
				t.Fatalf("MergeFloor under a %s .lock = %+v, %v; want 1 merged", tc.name, r, err)
			}
			if fl := readFloorFile(t, server); !fl["gone"].buries(mgen(1)) {
				t.Fatalf("floor after the merge = %+v, want gone's burial", fl)
			}
		})
	}
}

// TestMergeFloorRefusesWrongInput (U192): the merge refuses, writing
// nothing, onto an absent live floor (the saved floor was never put back),
// from a guard file that is the live floor's own inode (a hard link) and
// from a guard file equal to the live floor.
func TestMergeFloorRefusesWrongInput(t *testing.T) {
	ctx := context.Background()
	aside := floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 3}}}}
	for _, tc := range []struct {
		name string
		live floor // nil: no live floor file
		want string
	}{
		{"an absent live floor", nil, "restore the saved keystore-floor.json first"},
		{"the live floor's own inode", floor{"x": {Buried: []burial{{Generation: mgen(2), Deleted: 7}}}}, "is the live floor itself"},
		// With a live record, a merge of the floor into itself would fence
		// it, so only the byte-for-byte check refuses it.
		{"the live floor itself", floor{"gone": aside["gone"], "k": {Generation: mgen(4), Seq: 2}}, "the live floor itself, byte for byte"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			if tc.live != nil {
				putFloorFile(t, server, tc.live)
			}
			in := aside
			if tc.name == "the live floor itself" {
				in = tc.live
			}
			path := writeAsideFloor(t, server, in)
			if tc.name == "the live floor's own inode" {
				// A hard link: refused outright, never renamed.
				remove(t, path)
				if err := os.Link(floorPath(server), path); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(floorPath(server))
			_, err := mergeStaged(t, s, ctx, MergeOptions{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("MergeFloor: %v, want a refusal saying %q", err, tc.want)
			}
			after, aerr := os.ReadFile(floorPath(server))
			if tc.live == nil {
				if !errors.Is(aerr, fs.ErrNotExist) {
					t.Fatalf("live floor after the refusal: %v, want it still absent", aerr)
				}
				return
			}
			if string(after) != string(before) {
				t.Fatalf("live floor after the refusal = %s, want %s", after, before)
			}
		})
	}
}

// TestPendingMergeGuard (U192): while keystore-floor.json.pre-restore is in
// the data root, a restore is unfinished, so Put, Rotate and Rewrap refuse,
// naming keys floor merge, and RaiseFloor writes nothing (Delete runs:
// TestPendingMergeDeleteMakesRoom); a
// successful merge renames its input to keystore-floor.json.merged-<unix>,
// which clears the guard.
func TestPendingMergeGuard(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	path := writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	for verb, run := range map[string]func() error{
		"Put":    func() error { _, err := s.Put(ctx, "n", KindOpaque, []byte("v")); return err },
		"Rotate": func() error { _, err := s.Rotate(ctx, "k", []byte("two")); return err },
		"Rewrap": func() error { return s.Rewrap(ctx, rewrapKey(1)) },
	} {
		if err := run(); !errors.Is(err, errMergePending) || !strings.Contains(err.Error(), "keys floor merge") {
			t.Errorf("%s with a merge pending: %v, want errMergePending naming keys floor merge", verb, err)
		}
	}
	if err := s.RaiseFloor(ctx); err != nil {
		t.Errorf("RaiseFloor with a merge pending: %v, want nil", err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || string(after) != string(before) {
		t.Fatalf("floor after the refused verbs = %s, %v; want it unchanged", after, err)
	}
	mustCurrent(t, s, "k", "one")
	at := time.Unix(1795370000, 0)
	s.now = func() time.Time { return at }
	if _, err := mergeStaged(t, s, ctx, MergeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the merged input after the merge: %v, want it renamed", err)
	}
	if _, err := os.Lstat(floorPath(server) + ".merged-1795370000"); err != nil {
		t.Fatalf("the renamed input: %v", err)
	}
	mustPut(t, s, "n", KindOpaque, []byte("v"))
	mustRotate(t, s, "k", "two")
}

// TestEvictionReportedCommitted (U192): every verb whose floor write evicts
// a tombstone reports it as committed and ErrTombstoneEvicted: a Rotate and
// a RaiseFloor whose write pruned one, and a Delete whose burial evicted one
// and whose tree removal then failed (here on a .lock replaced by a
// directory), which is deleted all the same.
func TestEvictionReportedCommitted(t *testing.T) {
	ctx := context.Background()
	committedEvicted := func(t *testing.T, what string, err error) {
		t.Helper()
		if !Committed(err) || !errors.Is(err, ErrTombstoneEvicted) {
			t.Fatalf("%s: %v, want a committed ErrTombstoneEvicted", what, err)
		}
	}
	t.Run("Delete with its tree left behind", func(t *testing.T) {
		setSeam(t, &buriedPerNameLimit, smallBuriedPerName)
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		e := floorOf(t, server)["k"]
		for i := range smallBuriedPerName {
			e.Buried = append(e.Buried, burial{Generation: mgen(100 + i), Deleted: uint64(i + 1)})
		}
		putFloorFile(t, server, floor{"k": e})
		lock := filepath.Join(server, "keystore", lockName)
		remove(t, lock)
		if err := os.Mkdir(lock, 0o700); err != nil {
			t.Fatal(err)
		}
		err := s.Delete(ctx, "k")
		committedEvicted(t, "Delete at the cap under a .lock directory", err)
		if !strings.Contains(err.Error(), "already deleted") {
			t.Fatalf("Delete: %v, want it to say the entry is already deleted", err)
		}
	})
	for _, verb := range []string{"Rotate", "RaiseFloor"} {
		t.Run(verb, func(t *testing.T) {
			setSmallFloorLimits(t)
			s, server := newTestStore(t)
			mustPut(t, s, "k", KindOpaque, []byte("one"))
			// Rotate from seq 9 to 10, one byte more, over a floor whose
			// tombstones fill the rest, prunes the oldest.
			for i := 2; i <= 9; i++ {
				mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
			}
			gen := strings.Repeat("cd", generationSize)
			live := floorOf(t, server)["k"]
			if verb == "RaiseFloor" {
				// The floor one behind the pointer, as a crash before the
				// floor write leaves it: the raise to 10 grows it a byte.
				mustRotate(t, s, "k", "v10")
				live.Seq = 9
			}
			fillFloor(t, server, floor{"k": live, "old": buriedEntry(gen, 1)}, floorSizeLimit)
			var err error
			if verb == "Rotate" {
				var v Version
				v, err = s.Rotate(ctx, "k", []byte("v10"))
				if v.Version != 10 {
					t.Errorf("Rotate over a full floor = %+v, want version 10", v)
				}
			} else {
				err = s.RaiseFloor(ctx)
			}
			committedEvicted(t, verb+" over a floor full of tombstones", err)
			if fl := floorOf(t, server); fl["k"].Seq != 10 {
				t.Fatalf("floor k = %+v, want seq 10", fl["k"])
			}
		})
	}
}

// TestMergeFloorRefusesUnmatchedKeep (U192): a keep name that matched
// nothing, an entry the merge would not have buried, refuses the merge with
// nothing written.
func TestMergeFloorRefusesUnmatchedKeep(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	putFloorFile(t, server, floor{"a": {Generation: mgen(1), Seq: 1}})
	path := writeAsideFloor(t, server, floor{"a": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mergeStaged(t, s, ctx, MergeOptions{Keep: []string{"a", "typo"}}); err == nil || !strings.Contains(err.Error(), "typo") {
		t.Fatalf("MergeFloor keeping an unmatched name: %v, want a refusal naming it", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); string(after) != string(before) {
		t.Fatalf("floor after the refusal = %s, want %s", after, before)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the input after the refusal: %v, want it left in place", err)
	}
}

// TestMergeFloorCommittedRerun (U192): a merge whose write landed but whose
// rename failed (here the merged name is taken, the clock seam pinning it)
// returns its full report as committed, leaves the guard, and a rerun of the
// same input, read again under keystore-lock, writes nothing, renames the
// input and reports it already merged, which clears the guard. A rerun is
// already merged even when the input's newest deletion is below the live
// floor's, which a Delete since the first merge raises.
func TestMergeFloorCommittedRerun(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	path := writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
	at := time.Unix(1795370000, 0)
	s.now = func() time.Time { return at }
	taken := floorPath(server) + ".merged-1795370000"
	if err := os.WriteFile(taken, []byte("earlier\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := mergeStaged(t, s, ctx, MergeOptions{})
	if !Committed(err) || r.Merged != 1 {
		t.Fatalf("MergeFloor with the merged name taken = %+v, %v; want the report, committed", r, err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the input after the failed rename: %v, want it still there", err)
	}
	if _, err := s.Put(ctx, "n", KindOpaque, []byte("v")); !errors.Is(err, errMergePending) {
		t.Fatalf("Put after the failed rename: %v, want the guard still set", err)
	}
	merged, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Second)
	r, err = mergeStaged(t, s, ctx, MergeOptions{})
	if err != nil || !r.AlreadyMerged || r.Merged != 0 || r.AlreadyPresent != 1 {
		t.Fatalf("the rerun = %+v, %v; want it already merged", r, err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || string(after) != string(merged) {
		t.Fatalf("the floor after the rerun = %s, %v; want it unchanged", after, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the input after the rerun: %v, want it renamed", err)
	}
	mustPut(t, s, "n", KindOpaque, []byte("v"))

	t.Run("an input older than the live floor", func(t *testing.T) {
		if err := s.Delete(ctx, "n"); err != nil {
			t.Fatal(err)
		}
		writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
		at = at.Add(time.Second)
		r, err := mergeStaged(t, s, ctx, MergeOptions{})
		if err != nil || !r.AlreadyMerged {
			t.Fatalf("the rerun after a Delete = %+v, %v; want it already merged", r, err)
		}
	})
}

// TestMergePending (U192): MergePending reports errMergePending while
// keystore-floor.json.pre-restore is in the data root, and nil once it is
// gone.
func TestMergePending(t *testing.T) {
	s, server := newTestStore(t)
	if err := s.MergePending(); err != nil {
		t.Fatalf("MergePending with no restore: %v", err)
	}
	path := writeAsideFloor(t, server, floor{"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}}})
	if err := s.MergePending(); !errors.Is(err, errMergePending) {
		t.Fatalf("MergePending with the moved-aside floor in place: %v, want errMergePending", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.MergePending(); err != nil {
		t.Fatalf("MergePending after the merge: %v", err)
	}
}

// TestDeleteNotFoundReportsEviction (U192): a Delete of a name with nothing
// recorded and nothing under it still raises the other entries' floors
// first, and a raise whose write prunes a burial is committed: the answer is
// ErrNotFound, reported with the eviction as committed, and as not deleted
// (DeleteDone).
func TestDeleteNotFoundReportsEviction(t *testing.T) {
	ctx := context.Background()
	setSmallFloorLimits(t)
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	for i := 2; i <= 10; i++ {
		mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
	}
	// The floor one behind the pointer: the raise to 10 grows it a byte.
	live := floorOf(t, server)["k"]
	live.Seq = 9
	fillFloor(t, server, floor{"k": live, "old": buriedEntry(strings.Repeat("cd", generationSize), 1)}, floorSizeLimit)
	err := s.Delete(ctx, "absent")
	if !errors.Is(err, ErrNotFound) || !errors.Is(err, ErrTombstoneEvicted) || !Committed(err) || DeleteDone(err) {
		t.Fatalf("Delete of an absent name over a pruning raise: %v, want a committed ErrTombstoneEvicted with ErrNotFound, not done", err)
	}
	if fl := floorOf(t, server); fl["k"].Seq != 10 {
		t.Fatalf("floor k = %+v, want seq 10", fl["k"])
	}
}
