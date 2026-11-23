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
	"os"
	"strings"
	"testing"
)

// failTreeMove makes s's next tree move fail once, as a crash between the
// floor write and the move leaves the data root, and checks that the merge is
// committed.
func failTreeMove(t *testing.T, s *FileStore) {
	t.Helper()
	fail := true
	s.step = func(name string) error {
		if name == "merge tree rename" && fail {
			fail = false
			return errors.New("injected")
		}
		return nil
	}
	if _, err := s.MergeFloor(context.Background(), MergeOptions{}); !Committed(err) {
		t.Fatalf("MergeFloor with the move failing: %v, want committed", err)
	}
}

// wantCommittedWording fails t unless err is committed, says the merge is
// written and never that nothing is.
func wantCommittedWording(t *testing.T, what string, err error) {
	t.Helper()
	if !Committed(err) || !strings.Contains(err.Error(), "the merge is written") || strings.Contains(strings.ToLower(err.Error()), "nothing is written") {
		t.Fatalf("%s: %v; want committed wording, never \"nothing is written\"", what, err)
	}
}

// TestFloorMergeRerunCommittedWording (U192): a rerun after a committed
// merge (exit 5) finds the floor already written, so a refusal of the staged
// tree's shape, dry run included, and a failure to move a planted target
// aside are committed, worded so, never "nothing is written"; a rerun with
// the target planted and the move aside working completes.
func TestFloorMergeRerunCommittedWording(t *testing.T) {
	ctx := context.Background()
	t.Run("shape", func(t *testing.T) {
		s, server := newTestStore(t)
		stageRecipe(t, s, server, 0)
		failTreeMove(t, s)
		writeStaged(t, s, "k/bogus", nil)
		for _, dry := range []bool{true, false} {
			_, err := s.MergeFloor(ctx, MergeOptions{DryRun: dry})
			wantCommittedWording(t, fmt.Sprintf("rerun (dry run %v) with a misshaped staged tree", dry), err)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("rerun: %v, want ErrCorrupt too", err)
			}
		}
	})
	t.Run("target", func(t *testing.T) {
		s, server := newTestStore(t)
		stageRecipe(t, s, server, 0)
		failTreeMove(t, s)
		if err := os.Symlink(t.TempDir(), s.dir); err != nil {
			t.Fatal(err)
		}
		s.step = func(name string) error {
			if name == "merge move aside" {
				return errors.New("injected")
			}
			return nil
		}
		_, err := s.MergeFloor(ctx, MergeOptions{})
		wantCommittedWording(t, "rerun with the move aside failing", err)
		s.step = func(string) error { return nil }
		r, err := s.MergeFloor(ctx, MergeOptions{})
		if err != nil || !r.AlreadyMerged || r.MovedAside == "" {
			t.Fatalf("rerun: %+v, %v; want already merged with the symlink moved aside", r, err)
		}
		mustCurrent(t, s, "k", "v1")
	})
}
