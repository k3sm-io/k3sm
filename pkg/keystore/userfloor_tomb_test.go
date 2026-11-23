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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// restoreTree copies the directory src over dst, each file and directory at
// its own mode, as a restore with cp -Rp does: into dst when it exists.
func restoreTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			if err := os.MkdirAll(to, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(to, fi.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(to, b, fi.Mode().Perm()); err != nil {
			return err
		}
		giveToService(t, to)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// checkUserDeleted asserts err is the refusal of a buried generation: it
// says the entry was deleted and to put it again, and names floor --rebuild
// only as the last resort.
func checkUserDeleted(t *testing.T, op string, err error) {
	t.Helper()
	var del *userDeletedError
	if !errors.Is(err, ErrCorrupt) || !errors.As(err, &del) {
		t.Fatalf("%s of an entry copied back after rm: %v, want the deleted refusal", op, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "was deleted") || !strings.Contains(msg, "put it again") || !strings.Contains(msg, "last resort") {
		t.Fatalf("%s: the message %q does not say the entry was deleted and to put it again", op, msg)
	}
}

// U20: an entry tree copied back after rm is refused as deleted, by Current
// and List: rm buries the generation in the user-scope floor.
func TestUserFloorRefusesCopyBackAfterRm(t *testing.T) {
	ctx := context.Background()
	_, server, u := fileLogScope(t)
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	saved := filepath.Join(t.TempDir(), "token")
	copyTree(t, dir, saved)
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatal(err)
	}
	restoreTree(t, saved, dir)
	_, _, err := u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
	es, err := u.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 {
		t.Fatalf("list %+v", es)
	}
	checkUserDeleted(t, "list", es[0].Err)
}

// A Put of the name after rm gets a fresh generation, which no tombstone
// buries.
func TestUserPutAfterRmServed(t *testing.T) {
	ctx := context.Background()
	_, _, u := fileLogScope(t)
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatal(err)
	}
	userPut(t, u, "user/1001/token", "again")
	if _, v, err := u.Current(ctx, "user/1001/token"); err != nil || string(v) != "again" {
		t.Fatalf("current after rm and put: %q, %v", v, err)
	}
}

// rm buries before it removes: an rm whose removal fails after the pointer
// is gone leaves the generation buried, so the old current copied back is
// refused as deleted.
func TestUserRmBuriesBeforeRemoval(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	saved := filepath.Join(t.TempDir(), "token")
	copyTree(t, dir, saved)
	s.step = failAt("delete token")
	if err := u.Delete(ctx, "user/1001/token"); err == nil {
		t.Fatal("rm with its removal failing succeeded")
	}
	s.step = func(string) error { return nil }
	restoreTree(t, saved, dir)
	_, _, err := u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
}

// An absent floor refuses an rm, which removes nothing: rm buries before
// it removes, and a tree removed with no tombstone could be copied back and
// served. Once the floor is back the rm goes ahead.
func TestUserRmAbsentFloorRemovesNothing(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	floorPath := filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName)
	saved, err := os.ReadFile(floorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(floorPath); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	err = u.Delete(ctx, "user/1001/token")
	if err == nil || errors.Is(err, errCommitted) || !errors.Is(err, errLogMissing) {
		t.Fatalf("rm with no floor: %v, want a refusal naming the missing floor", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, currentName)); err != nil {
		t.Fatalf("the entry's pointer after a refused rm: %v, want it kept", err)
	}
	if err := os.WriteFile(floorPath, saved, logMode); err != nil {
		t.Fatal(err)
	}
	giveToService(t, floorPath)
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm with the floor back: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the entry is still there: %v", err)
	}
}

// rm does not trust the generation file, which a tree-writer without the
// master can swap to another valid value: it buries the generation the floor
// holds a live line for and the one the pointer header carries as well, so
// the original tree copied back is still refused as deleted, and rm reports
// the mismatch after removing the tree.
func TestUserRmSwappedGenerationStillBuries(t *testing.T) {
	ctx := context.Background()
	_, server, u := fileLogScope(t)
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	saved := filepath.Join(t.TempDir(), "token")
	copyTree(t, dir, saved)
	genPath := filepath.Join(dir, generationName)
	if err := os.Remove(genPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(genPath, []byte(strings.Repeat("ab", generationSize)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, genPath)
	err := u.Delete(ctx, "user/1001/token")
	if !errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("rm of an entry with a swapped generation file: %v, want the mismatch reported after the commit", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the entry is still there: %v", err)
	}
	restoreTree(t, saved, dir)
	_, _, err = u.Current(ctx, "user/1001/token")
	checkUserDeleted(t, "current", err)
}
