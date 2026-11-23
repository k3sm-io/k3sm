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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capSetup is a live floor whose k holds a live record and the per-name
// cap of burials, and a moved-aside floor whose merge adds one burial
// elsewhere, so an rm of k under the guard drops k's oldest burial at the
// cap.
func capSetup(t *testing.T, s *FileStore, server string) {
	t.Helper()
	setSeam(t, &buriedPerNameLimit, smallBuriedPerName)
	k := floorEntry{Generation: mgen(50), Seq: 1}
	for i := range smallBuriedPerName {
		k.Buried = append(k.Buried, burial{Generation: mgen(10 + i), Deleted: uint64(i + 1)})
	}
	putFloorFile(t, server, floor{"keep": {Generation: mgen(2), Seq: 1}, "k": k})
	writeAsideFloor(t, server, floor{
		"keep": {Generation: mgen(2), Seq: 1},
		"k":    {Generation: mgen(50), Seq: 1},
		"gone": {Buried: []burial{{Generation: mgen(1), Deleted: 1}}},
	})
}

// commitThenRm runs setup, a merge whose floor write commits and whose tree
// move fails, so the guard stays, then an rm of name under the guard, which
// must drop a burial the written floor holds (ErrTombstoneEvicted).
func commitThenRm(t *testing.T, setup func(*testing.T, *FileStore, string), opts MergeOptions, name string) (*FileStore, string) {
	t.Helper()
	ctx := context.Background()
	s, server := newTestStore(t)
	setup(t, s, server)
	stageTree(t, s)
	failStepOnce(s, "merge tree rename")
	if _, err := s.MergeFloor(ctx, opts); !Committed(err) {
		t.Fatalf("first run: %v, want committed with the tree move failing", err)
	}
	if err := s.Delete(ctx, name); !errors.Is(err, ErrTombstoneEvicted) || !DeleteDone(err) {
		t.Fatalf("Delete %s under the guard: %v, want it done with ErrTombstoneEvicted", name, err)
	}
	if _, err := os.Lstat(filepath.Join(s.dataRoot, rmDroppedName)); err != nil {
		t.Fatalf("the rm-dropped record after the Delete: %v, want it written", err)
	}
	return s, server
}

// TestFloorMergeRerunAfterRmPrune (U192): an rm under a pending merge whose
// floor is written drops a burial that floor holds, at the per-name cap or
// in the prune at the tombstone budget (certain after --accept-drops). The
// rerun accepts the floor written plus rm's burials minus what the
// rm-dropped record lists, finishes the merge and clears the guard. A
// burial gone that the record does not list, and a record that is not in
// its one encoding or is group-writable, still refuse the rerun.
func TestFloorMergeRerunAfterRmPrune(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *FileStore, string)
		opts  MergeOptions
		rm    string
	}{
		{"per-name cap", capSetup, MergeOptions{}, "k"},
		{"tombstone budget", dropsSetup, MergeOptions{AcceptDrops: true}, "keep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := commitThenRm(t, tc.setup, tc.opts, tc.rm)
			r, err := s.MergeFloor(ctx, MergeOptions{})
			if err != nil || !r.AlreadyMerged {
				t.Fatalf("rerun after the rm = %+v, %v; want it already merged", r, err)
			}
			if err := s.MergePending(); err != nil {
				t.Fatalf("MergePending after the rerun: %v, want the guard cleared", err)
			}
			if _, err := os.Lstat(filepath.Join(s.dataRoot, rmDroppedName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the rm-dropped record after the merge: %v, want it removed", err)
			}
			if fl := floorOf(t, server); fl[tc.rm].live() {
				t.Fatalf("%s after the merge = %+v, want it deleted", tc.rm, fl[tc.rm])
			}
		})
		t.Run(tc.name+": an unlisted burial gone still refuses", func(t *testing.T) {
			s, server := commitThenRm(t, tc.setup, tc.opts, tc.rm)
			fl := floorOf(t, server)
			removed := false
			for name, e := range fl {
				if name != tc.rm && len(e.burials()) > 0 {
					e.Buried = nil
					if !e.live() {
						delete(fl, name)
					} else {
						fl[name] = e
					}
					removed = true
					break
				}
			}
			if !removed {
				t.Fatal("no burial to remove")
			}
			putFloorFile(t, server, fl)
			if _, err := s.MergeFloor(ctx, MergeOptions{}); !Committed(err) || !strings.Contains(err.Error(), "is gone") {
				t.Fatalf("rerun with an unlisted burial gone: %v, want a committed refusal naming it", err)
			}
			if s.MergePending() == nil {
				t.Fatal("the refused rerun cleared the guard")
			}
		})
		t.Run(tc.name+": a tampered record refuses", func(t *testing.T) {
			for what, tamper := range map[string]func(string) error{
				"another encoding": func(p string) error {
					b, err := os.ReadFile(p)
					if err != nil {
						return err
					}
					return os.WriteFile(p, append([]byte(" "), b...), floorFileMode)
				},
				"group-writable": func(p string) error { return os.Chmod(p, 0o664) },
			} {
				s, _ := commitThenRm(t, tc.setup, tc.opts, tc.rm)
				if err := tamper(filepath.Join(s.dataRoot, rmDroppedName)); err != nil {
					t.Fatal(err)
				}
				if _, err := s.MergeFloor(ctx, MergeOptions{}); err == nil || !strings.Contains(err.Error(), rmDroppedName) {
					t.Fatalf("rerun with the record %s: %v, want it refused naming %s", what, err, rmDroppedName)
				}
				if s.MergePending() == nil {
					t.Fatalf("the rerun with the record %s cleared the guard", what)
				}
			}
		})
	}
}

// TestPendingSinceReadFloorNotCommitted (U192): a live floor that is the
// floor a first run read, changed since by more than rm's burials, is
// refused without claiming the merge wrote the floor.
func TestPendingSinceReadFloorNotCommitted(t *testing.T) {
	read := floor{"a": {Generation: mgen(1), Seq: 1}}
	written := floor{"a": {Generation: mgen(1), Seq: 1}, "gone": {Buried: []burial{{Generation: mgen(2), Deleted: 1}}}}
	rb, err := marshalFloor(read)
	if err != nil {
		t.Fatal(err)
	}
	wb, err := marshalFloor(written)
	if err != nil {
		t.Fatal(err)
	}
	var rec retiredRecord
	rec.setFloors(rb, wb)
	// A burial numbered below guardEraSeq is not one rm writes under the
	// guard.
	live := floor{"a": {Generation: mgen(1), Seq: 1}, "x": {Buried: []burial{{Generation: mgen(3), Deleted: 1}}}}
	_, err = pendingSince(rec, live, nil)
	var nw *notWrittenError
	if !errors.As(err, &nw) {
		t.Fatalf("pendingSince on the read floor changed = %v, want notWrittenError", err)
	}
}
