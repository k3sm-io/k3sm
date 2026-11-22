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
	"testing"
)

// TestMergeFloorReadsOnlyTheGuardFile (U192): the merge reads only the data
// root's keystore-floor.json.pre-restore and takes no path, so the backup's
// saved floor, or a copy of the moved-aside floor anywhere else, is never
// its input: with no guard file it refuses, naming the file, and the live
// floor is left as it was. A guard file replaced by another inode during
// the merge is refused too, nothing written and the replacement not
// renamed.
func TestMergeFloorReadsOnlyTheGuardFile(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	aside := floorOf(t, server)
	aside["gone"] = floorEntry{Buried: []burial{{Generation: mgen(1), Deleted: 1}}}
	guard := writeAsideFloor(t, server, aside)
	b, err := os.ReadFile(guard)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(guard), "copy.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(guard, filepath.Join(filepath.Dir(guard), "saved-keystore-floor.json")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeFloor(ctx, MergeOptions{}); !errors.Is(err, errNoGuard) {
		t.Errorf("MergeFloor with no guard file: %v, want errNoGuard", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); string(after) != string(before) {
		t.Errorf("floor after the refused merge changed: %s", after)
	}

	t.Run("a guard file replaced during the merge", func(t *testing.T) {
		writeAsideFloor(t, server, aside)
		s.step = func(name string) error {
			if name != "merge read" {
				return nil
			}
			// Another inode under the guard file's name, same bytes.
			tmp := guard + ".new"
			if err := os.WriteFile(tmp, b, 0o644); err != nil {
				return err
			}
			return os.Rename(tmp, guard)
		}
		t.Cleanup(func() { s.step = func(string) error { return nil } })
		if _, err := s.MergeFloor(ctx, MergeOptions{}); err == nil || Committed(err) {
			t.Fatalf("MergeFloor over a replaced guard file: %v, want a refusal, not committed", err)
		}
		if after, _ := os.ReadFile(floorPath(server)); string(after) != string(before) {
			t.Errorf("floor after the refused merge changed: %s", after)
		}
		if _, err := os.Lstat(guard); err != nil {
			t.Errorf("the replacement guard file: %v, want it left in place", err)
		}
	})
}
