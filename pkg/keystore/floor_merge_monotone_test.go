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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestFloorMergeRerunAfterDelete (U192): rm is never refused while a merge
// is pending. After a first run whose floor write landed and whose tree move
// failed, rm of a staged entry succeeds; the rerun accepts the live floor,
// the written one plus that burial, finishes from the record without
// writing the floor, keeps the burial and removes the entry's staged
// directory before the tree moves into place.
func TestFloorMergeRerunAfterDelete(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "third", KindOpaque, []byte("v"))
	gen := floorOf(t, server)["third"].Generation
	aside := floorOf(t, server)
	aside["late"] = floorEntry{Generation: mgen(9), Seq: 1}
	writeAsideFloor(t, server, aside)
	stageTree(t, s)
	failStepOnce(s, "merge tree rename")
	if _, err := s.MergeFloor(ctx, MergeOptions{}); !Committed(err) {
		t.Fatalf("first run with the move failing: %v, want committed", err)
	}
	if err := s.Delete(ctx, "third"); err != nil {
		t.Fatalf("Delete with the merge written but not finished: %v, want it to succeed", err)
	}
	if _, err := os.Lstat(stagePath(s, stagedTreeName, "third")); err != nil {
		t.Fatalf("third's staged directory after the rm: %v, want it still staged", err)
	}
	deleted, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.MergeFloor(ctx, MergeOptions{})
	if err != nil || !r.AlreadyMerged || !slices.Equal(r.Retired, []string{"late"}) {
		t.Fatalf("rerun after the rm = %+v, %v; want already merged reporting late retired", r, err)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, deleted) {
		t.Fatalf("the rerun wrote the floor:\n%s\nwant\n%s", after, deleted)
	}
	if !floorOf(t, server)["third"].buries(gen) {
		t.Fatal("the rerun lost the burial the rm added")
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "third")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("third's directory after the rerun: %v, want its staged directory removed", err)
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "k")); err != nil {
		t.Fatalf("k's directory after the rerun: %v, want it moved into place", err)
	}
	if s.MergePending() != nil {
		t.Fatal("the rerun left the guard")
	}
}

// TestFloorMergeDeleteBeforeFloorWrite (U192): rm after a first run that
// wrote its record and stopped before the floor write succeeds, and the
// rerun, finding the floor it read plus that burial, merges and keeps it.
func TestFloorMergeDeleteBeforeFloorWrite(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "third", KindOpaque, []byte("v"))
	gen := floorOf(t, server)["third"].Generation
	aside := floorOf(t, server)
	aside["late"] = floorEntry{Generation: mgen(9), Seq: 1}
	writeAsideFloor(t, server, aside)
	stageTree(t, s)
	failStepOnce(s, "write "+floorName)
	if _, err := s.MergeFloor(ctx, MergeOptions{}); err == nil || Committed(err) {
		t.Fatalf("first run with the floor write failing: %v, want an uncommitted failure", err)
	}
	if _, err := os.Lstat(filepath.Join(s.dataRoot, retiredPendingName)); err != nil {
		t.Fatalf("the pending record: %v, want it written", err)
	}
	if err := s.Delete(ctx, "third"); err != nil {
		t.Fatalf("Delete with the record pending: %v, want it to succeed", err)
	}
	r, err := s.MergeFloor(ctx, MergeOptions{})
	if err != nil || !slices.Equal(r.Retired, []string{"late"}) {
		t.Fatalf("rerun = %+v, %v; want late retired", r, err)
	}
	if !floorOf(t, server)["third"].buries(gen) {
		t.Fatal("the rerun lost the burial the rm added")
	}
	if s.MergePending() != nil {
		t.Fatal("the rerun left the guard")
	}
}

// TestFloorMergeRerunNonMonotone (U192): a live floor that differs from the
// written one by more than added burials (a burial removed, a sequence
// lowered, a live record of another generation) fails closed, committed,
// and nothing is written.
func TestFloorMergeRerunNonMonotone(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		spoil func(fl floor)
	}{
		{"a removed burial", func(fl floor) {
			delete(fl, "gone")
		}},
		{"a lowered pointer", func(fl floor) {
			e := fl["k"]
			e.Seq = 2
			fl["k"] = e
		}},
		{"another live generation", func(fl floor) {
			e := fl["k"]
			e.Generation = mgen(77)
			fl["k"] = e
		}},
		{"a lowered burial", func(fl floor) {
			e := fl["gone"]
			e.Buried = []burial{{Generation: mgen(3), Deleted: e.Buried[0].Deleted - 1}}
			fl["gone"] = e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			putFloorFile(t, server, floor{
				"k":    {Generation: mgen(1), Seq: 5},
				"gone": {Buried: []burial{{Generation: mgen(3), Deleted: 7}}},
			})
			writeAsideFloor(t, server, floor{
				"k":    {Generation: mgen(1), Seq: 5},
				"gone": {Buried: []burial{{Generation: mgen(3), Deleted: 7}}},
				"late": {Generation: mgen(9), Seq: 1},
			})
			stageTree(t, s)
			failStepOnce(s, "merge tree rename")
			if _, err := s.MergeFloor(ctx, MergeOptions{}); !Committed(err) {
				t.Fatalf("first run: %v, want committed", err)
			}
			fl := floorOf(t, server)
			tc.spoil(fl)
			putFloorFile(t, server, fl)
			changed, _ := os.ReadFile(floorPath(server))
			_, err := s.MergeFloor(ctx, MergeOptions{})
			if !Committed(err) || !strings.Contains(err.Error(), "never plans a written merge again") {
				t.Fatalf("rerun on a floor with %s: %v, want a committed refusal", tc.name, err)
			}
			if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, changed) {
				t.Fatal("the refused rerun wrote the floor")
			}
		})
	}
}
