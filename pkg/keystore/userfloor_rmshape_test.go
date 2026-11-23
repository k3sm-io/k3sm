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

// rmShapeSetup is fileLogScope with user/1001/token's tree saved aside: it
// returns the store, the entry's directory and the saved copy.
func rmShapeSetup(t *testing.T) (*FileStore, *UserScope, string, string) {
	t.Helper()
	s, server, u := fileLogScope(t)
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	saved := filepath.Join(t.TempDir(), "token")
	copyTree(t, dir, saved)
	return s, u, dir, saved
}

// copyBack removes whatever stands at dir and restores the saved tree.
func copyBack(t *testing.T, saved, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	restoreTree(t, saved, dir)
}

// U20: rm buries every live floor generation whatever stands at the name.
// The entry directory replaced by a file, then by a symlink: each time rm
// removes it, reports the odd shape after the commit, and the original tree
// copied back is refused as deleted.
func TestUserRmNonDirectoryBuries(t *testing.T) {
	for _, shape := range []string{"file", "symlink"} {
		t.Run(shape, func(t *testing.T) {
			ctx := context.Background()
			_, u, dir, saved := rmShapeSetup(t)
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			switch shape {
			case "file":
				if err := os.WriteFile(dir, []byte("not an entry\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				giveToService(t, dir)
			case "symlink":
				if err := os.Symlink(saved, dir); err != nil {
					t.Fatal(err)
				}
			}
			err := u.Delete(ctx, "user/1001/token")
			if !errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "not a directory") {
				t.Fatalf("rm of a %s at the entry's name: %v, want the shape reported after the commit", shape, err)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the %s is still there: %v", shape, err)
			}
			copyBack(t, saved, dir)
			_, _, err = u.Current(ctx, "user/1001/token")
			checkUserDeleted(t, "current", err)
		})
	}
}

// An rm whose burial failed removes nothing; a retry after the tree is gone
// (a crash, or a tree-writer moving it away) still buries the floor's live
// generations and succeeds, so the copy-back is refused, and an rm of a name
// the floor holds nothing live for is ErrNotFound.
func TestUserRmRetryAfterTreeGoneBuries(t *testing.T) {
	ctx := context.Background()
	s, u, dir, saved := rmShapeSetup(t)
	fl := s.userFloor.(*fileFloorLog).log
	fl.freeSpace = func(int) (uint64, error) { return 0, nil }
	if err := u.Delete(ctx, "user/1001/token"); err == nil || errors.Is(err, errCommitted) {
		t.Fatalf("rm with its burial failing: %v, want a refusal", err)
	}
	fl.freeSpace = nil
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm retried after the tree is gone: %v, want it to bury and succeed", err)
	}
	copyBack(t, saved, dir)
	_, _, err := u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete(ctx, "user/1001/token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rm of a buried, absent name: %v, want ErrNotFound", err)
	}
}

// The generation file and the pointer both rewritten to name another
// generation, with the floor's live line for the real one lost (a crash
// between the pointer and the floor line): the v1 record's header still
// names the real generation, rm buries it, and the copy-back is refused.
func TestUserRmBuriesVersionHeaderGeneration(t *testing.T) {
	ctx := context.Background()
	s, u, dir, saved := rmShapeSetup(t)
	floorPath := filepath.Join(s.dataRoot, logsDirName, userFloorLogName)
	var kept []byte
	for _, l := range bytes.SplitAfter(readLog(t, s, userFloorLogName), []byte{'\n'}) {
		if !bytes.Contains(l, []byte(" token ")) {
			kept = append(kept, l...)
		}
	}
	if err := os.WriteFile(floorPath, kept, logMode); err != nil {
		t.Fatal(err)
	}
	fake := guid(0x5C)
	genPath := filepath.Join(dir, generationName)
	if err := os.Remove(genPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(genPath, []byte(strings.Repeat("5c", generationSize)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, genPath)
	curPath := filepath.Join(dir, currentName)
	b, err := os.ReadFile(curPath)
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	r.generation = fake
	if err := os.Remove(curPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(curPath, r.marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, curPath)
	err = u.Delete(ctx, "user/1001/token")
	if !errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("rm of a tree with its generation file and pointer rewritten: %v, want the mismatch reported after the commit", err)
	}
	copyBack(t, saved, dir)
	_, _, err = u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
}
