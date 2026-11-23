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
	"os"
	"strings"
	"testing"
)

// TestFloorMergeStagedNodeBudget (U192): a staged tree with more nodes
// than the walk takes in all is refused by the read-only check, as
// ErrCorrupt naming the budget, before any node is handed to the service
// user and before the floor is written.
func TestFloorMergeStagedNodeBudget(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	// The tree's own directory, k's directory and its first file: k's
	// other files are past the budget.
	setSeam(t, &stagedNodeLimit, 3)
	var handed []string
	s.step = func(name string) error {
		if strings.HasPrefix(name, "merge chown ") {
			handed = append(handed, name)
		}
		return nil
	}
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.MergeFloor(ctx, MergeOptions{})
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "nodes the walk takes") {
		t.Fatalf("MergeFloor over a tree past the node budget: %v, want ErrCorrupt naming the budget", err)
	}
	if len(handed) > 0 {
		t.Fatalf("the refused merge handed over %v, want nothing", handed)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, before) {
		t.Fatal("the refused merge wrote the floor")
	}
	if s.MergePending() == nil {
		t.Fatal("the refused merge cleared the guard")
	}
}

// TestStagedHoldsUserScopes (U192): the merge reports a staged tree that
// holds a user scope's directory under .user, whose deletions since the
// backup the system floor does not carry over, and not one without.
func TestStagedHoldsUserScopes(t *testing.T) {
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	st := openTestStaging(t, s)
	if got, err := st.holdsUserScopes(); err != nil || got {
		t.Fatalf("holdsUserScopes without .user = %v, %v; want false", got, err)
	}
	if err := os.MkdirAll(stagePath(s, stagedTreeName, userScopesName, "501"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := st.holdsUserScopes(); err != nil || !got {
		t.Fatalf("holdsUserScopes with .user/501 = %v, %v; want true", got, err)
	}
}
