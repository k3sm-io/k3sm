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

var errInjectedOpen = errors.New("injected entry open failure")

// An rm whose entry directory cannot be opened buries the floor's live
// generations first, then returns the open's error: the tree stays, and is
// refused as deleted.
func TestUserRmOpenFailureBuriesFirst(t *testing.T) {
	ctx := context.Background()
	s, u, dir, _ := rmShapeSetup(t)
	s.entryOpen = func(string) error { return errInjectedOpen }
	if err := u.Delete(ctx, "user/1001/token"); !errors.Is(err, errInjectedOpen) {
		t.Fatalf("rm with its entry open failing: %v, want the open's error", err)
	}
	if _, err := os.Lstat(dir); err != nil {
		t.Fatalf("the tree was removed: %v", err)
	}
	s.entryOpen = nil
	_, _, err := u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
}

// With the entry open failing and the floor refusing the tombstone, rm is
// refused: nothing buried and nothing removed.
func TestUserRmOpenFailureRefusedWithoutTombstone(t *testing.T) {
	ctx := context.Background()
	s, u, dir, _ := rmShapeSetup(t)
	s.entryOpen = func(string) error { return errInjectedOpen }
	fl := s.userFloor.(*fileFloorLog).log
	fl.freeSpace = func(int) (uint64, error) { return 0, nil }
	err := u.Delete(ctx, "user/1001/token")
	if err == nil || errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "nothing removed") {
		t.Fatalf("rm with its entry open and its tombstone failing: %v, want a refusal", err)
	}
	s.entryOpen, fl.freeSpace = nil, nil
	if _, err := os.Lstat(dir); err != nil {
		t.Fatalf("the tree was removed: %v", err)
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current after the refused rm: %v, want the entry served", err)
	}
}

// An rm with no generation to bury (no live floor line, a generation file
// that does not read and no record header that parses, though a record
// file stands) refuses with the named remedy and removes nothing.
func TestUserRmNoGenerationRefusesFirst(t *testing.T) {
	ctx := context.Background()
	s, u, dir, _ := rmShapeSetup(t)
	var kept []byte
	for _, l := range bytes.SplitAfter(readLog(t, s, userFloorLogName), []byte{'\n'}) {
		if !bytes.Contains(l, []byte(" token ")) {
			kept = append(kept, l...)
		}
	}
	if err := os.WriteFile(filepath.Join(s.dataRoot, userFloorLogName), kept, logMode); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{generationName, currentName} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, versionName(1)), []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := u.Delete(ctx, "user/1001/token")
	if !errors.Is(err, errRmNoGeneration) || errors.Is(err, errCommitted) {
		t.Fatalf("rm with no generation to bury: %v, want errRmNoGeneration before any removal", err)
	}
	if !strings.Contains(err.Error(), "floor --rebuild") || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("the refusal %q names no remedy", err)
	}
	if _, err := os.Lstat(dir); err != nil {
		t.Fatalf("the tree was removed: %v", err)
	}
}

// An entry directory with nothing sealed in it, which a crash between the
// put's mkdir and its generation write leaves, holds nothing a copy put
// back could be served from: rm removes it rather than refusing with
// errRmNoGeneration.
func TestUserRmRemovesUnsealedEntryDir(t *testing.T) {
	ctx := context.Background()
	_, server, u := fileLogScope(t)
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "crashed")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	giveToService(t, dir)
	if err := u.Delete(ctx, "user/1001/crashed"); err != nil {
		t.Fatalf("rm of an entry directory with nothing sealed in it: %v, want it removed", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the directory is still there: %v", err)
	}
}
