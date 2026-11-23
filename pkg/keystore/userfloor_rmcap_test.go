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
	"strings"
	"testing"
)

// A planted tree of 50 v<N> records, each header naming a distinct
// generation, cannot make one rm bury 50: past maxTreeGenerations the rm
// buries the floor's live generations and the pointer header's, removes the
// tree, and reports it altered after the commit.
func TestUserRmCapsTreeGenerations(t *testing.T) {
	ctx := context.Background()
	s, u, dir, saved := rmShapeSetup(t)
	b, err := os.ReadFile(filepath.Join(dir, versionName(1)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		r.version = uint64(i + 2)
		r.generation = guid(byte(0x30 + i))
		p := filepath.Join(dir, versionName(r.version))
		if err := os.WriteFile(p, r.marshal(), 0o600); err != nil {
			t.Fatal(err)
		}
		giveToService(t, p)
	}
	before := bytes.Count(readLog(t, s, userFloorLogName), []byte(" rm "))
	err = u.Delete(ctx, "user/1001/token")
	if !errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "altered") {
		t.Fatalf("rm of a tree naming 50 generations: %v, want the alteration reported after the commit", err)
	}
	if got := bytes.Count(readLog(t, s, userFloorLogName), []byte(" rm ")) - before; got != 1 {
		t.Fatalf("rm wrote %d tombstones, want 1: the floor's live generation, which the pointer header names too", got)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the tree is still there: %v", err)
	}
	copyBack(t, saved, dir)
	_, _, err = u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
}
