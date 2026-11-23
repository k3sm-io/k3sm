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
	"os"
	"slices"
	"strings"
	"testing"
)

// TestMergeFloorRefusesKeepAfterRm (U192): --keep of a name the operator
// deleted with keys rm after the restore, while the merge was pending, is
// refused, naming why, and nothing is written: the keep would otherwise
// record the moved-aside generation live and bring the entry back.
func TestMergeFloorRefusesKeepAfterRm(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	putFloorFile(t, server, floor{"k": {Generation: mgen(1), Seq: 1}, "other": {Generation: mgen(3), Seq: 1}})
	writeAsideFloor(t, server, floor{"k": {Generation: mgen(2), Seq: 1}, "other": {Generation: mgen(3), Seq: 1}})
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete under the guard: %v", err)
	}
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	_, err = mergeStaged(t, s, ctx, MergeOptions{Keep: []string{"k"}})
	if err == nil || !strings.Contains(err.Error(), "deleted with keys rm after the restore") {
		t.Fatalf("MergeFloor --keep k after rm k: %v, want it refused naming the rm", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, before) {
		t.Fatal("the refused merge wrote the floor")
	}
	if s.MergePending() == nil {
		t.Fatal("the refused merge cleared the guard")
	}
}

// TestClassifyUndoDeletedSince (U192): in an undo, a name the restore's
// merge retired that the undo's input buries under a generation the
// record's written floor does not bury was deleted with keys rm after the
// restore: it is reported deleted since, and --keep of it is refused.
func TestClassifyUndoDeletedSince(t *testing.T) {
	read := floor{"k": {Generation: mgen(1), Seq: 1}}
	written := floor{"k": {Generation: mgen(2), Seq: 1, Buried: []burial{{Generation: mgen(1), Deleted: 1}}}}
	rb, err := marshalFloor(read)
	if err != nil {
		t.Fatal(err)
	}
	wb, err := marshalFloor(written)
	if err != nil {
		t.Fatal(err)
	}
	rec := retiredRecord{Retired: []string{"k"}}
	rec.setFloors(rb, wb)
	// The undo's input: k's generation 2 deleted with rm after the restore.
	from := floor{"k": {Buried: []burial{{Generation: mgen(1), Deleted: 1}, {Generation: mgen(2), Deleted: 2}}}}
	r := MergeReport{BuriedLive: []string{"k"}}
	if err := classifyUndo(&r, rec, from); err != nil {
		t.Fatal(err)
	}
	if len(r.RetiredByRestore) != 0 || !slices.Equal(r.DeletedSinceRestore, []string{"k"}) {
		t.Fatalf("classifyUndo = retired %v, deleted since %v; want k deleted since", r.RetiredByRestore, r.DeletedSinceRestore)
	}
	kept := MergeReport{Kept: []string{"k"}}
	if err := classifyUndo(&kept, rec, from); err == nil || !strings.Contains(err.Error(), "keys rm deleted it after the restore") {
		t.Fatalf("classifyUndo with --keep k = %v, want it refused", err)
	}
}
