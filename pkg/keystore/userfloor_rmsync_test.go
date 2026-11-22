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

// A burial whose write landed whole and whose fsync failed is not known
// durable: it counts as no tombstone landed, so the rm is refused with
// nothing removed and says to run it again, never reported committed.
func TestRmBurialSyncFailureRefuses(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog).log
	fl.fsync = func(*os.File) error { return errors.New("injected fsync failure") }
	err := u.Delete(ctx, "user/1001/token")
	fl.fsync = nil
	if err == nil || errors.Is(err, errCommitted) {
		t.Fatalf("rm whose burial fsync failed: %v, want a refusal", err)
	}
	for _, want := range []string{"nothing removed", "run rm again"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal %q does not say %q", err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")); err != nil {
		t.Fatalf("the refused rm removed the tree: %v", err)
	}
}
