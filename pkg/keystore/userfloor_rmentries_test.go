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
	"path/filepath"
	"regexp"
	"testing"
)

// U20: an rm whose scope.key reads and whose owner check passes, but whose
// entries/ is missing, buries the floor's live generations for the name
// first, then returns ErrScopeAbsent; the tree put back is refused as
// deleted.
// tombSuffix matches a floor whose last line is a tombstone: the marker,
// then its checksum.
var tombSuffix = regexp.MustCompile(` rm [0-9a-f]{8}\n$`)

func TestUserRmMissingEntriesBuriesFirst(t *testing.T) {
	ctx := context.Background()
	s, u, dir, _ := rmShapeSetup(t)
	entries := filepath.Dir(dir)
	aside := filepath.Join(t.TempDir(), "entries")
	if err := os.Rename(entries, aside); err != nil {
		t.Fatal(err)
	}
	err := u.Delete(ctx, "user/1001/token")
	if !errors.Is(err, ErrScopeAbsent) || !errors.Is(err, errCommitted) {
		t.Fatalf("rm with entries/ missing: %v, want ErrScopeAbsent after the burial", err)
	}
	if !bytes.Contains(readLog(t, s, userFloorLogName), []byte(" token ")) || !tombSuffix.Match(readLog(t, s, userFloorLogName)) {
		t.Fatalf("rm with entries/ missing wrote no tombstone:\n%s", readLog(t, s, userFloorLogName))
	}
	if err := os.Rename(aside, entries); err != nil {
		t.Fatal(err)
	}
	_, _, err = u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
}

// An rm whose scope.key cannot be read is refused: nothing buried.
func TestUserRmUnreadableScopeKeyBuriesNothing(t *testing.T) {
	ctx := context.Background()
	s, u, dir, _ := rmShapeSetup(t)
	key := filepath.Join(filepath.Dir(filepath.Dir(dir)), scopeKeyName)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	before := readLog(t, s, userFloorLogName)
	if err := u.Delete(ctx, "user/1001/token"); err == nil || errors.Is(err, errCommitted) {
		t.Fatalf("rm with no scope.key: %v, want a refusal", err)
	}
	if got := readLog(t, s, userFloorLogName); !bytes.Equal(got, before) {
		t.Fatalf("rm with no scope.key wrote to the floor:\n%s", got[len(before):])
	}
}
