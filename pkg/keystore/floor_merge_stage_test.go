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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// merge is mergeFenced with no moved-aside tree pointers.
func (fl floor) merge(from floor, keep map[string]bool, ptrs map[string]uint64) (MergeReport, []pruned) {
	return fl.mergeFenced(from, keep, ptrs, nil)
}

// stagePath is s's pre-restore.d, or the tree name inside it.
func stagePath(s *FileStore, name ...string) string {
	return filepath.Join(append([]string{s.dataRoot, preRestoreDirName}, name...)...)
}

// stageTree stages s's keystore/ as the restore recipe does: a root-only
// pre-restore.d (made if absent) and the tree in it as restored, moved from
// the store's Dir, or an empty one when Dir is absent. A tree already staged
// is left. Failures are reported with Errorf, so a goroutine may call it.
func stageTree(tb testing.TB, s *FileStore) {
	tb.Helper()
	if err := os.Mkdir(stagePath(s), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		tb.Errorf("stage: %v", err)
		return
	}
	if _, err := os.Lstat(stagePath(s, stagedTreeName)); err == nil {
		return
	}
	err := os.Rename(s.dir, stagePath(s, stagedTreeName))
	if errors.Is(err, fs.ErrNotExist) {
		if err = os.Mkdir(stagePath(s, stagedTreeName), 0o700); err == nil {
			giveToService(tb, stagePath(s, stagedTreeName))
		}
	}
	if err != nil && !errors.Is(err, fs.ErrExist) {
		tb.Errorf("stage: %v", err)
	}
}

// unstageTree puts a tree a refused or dry-run merge left staged back at
// the store's Dir, and removes pre-restore.d once it is empty, so the test
// goes on as before the recipe staged anything.
func unstageTree(tb testing.TB, s *FileStore) {
	tb.Helper()
	if _, err := os.Lstat(s.dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.Rename(stagePath(s, stagedTreeName), s.dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			tb.Errorf("unstage: %v", err)
		}
	}
	_ = os.Remove(stagePath(s)) // only when empty
}

// mergeStaged is MergeFloor run as the restore recipe leaves the data root:
// s's keystore/ staged in pre-restore.d (stageTree), and put back after a
// merge that did not move it (unstageTree).
func mergeStaged(tb testing.TB, s *FileStore, ctx context.Context, opts MergeOptions) (MergeReport, error) {
	tb.Helper()
	stageTree(tb, s)
	defer unstageTree(tb, s)
	return s.MergeFloor(ctx, opts)
}

// stageRecipe sets s's data root up as the restore recipe leaves it after a
// backup of k at seq 1, k rotated to seq 4 since, and the restore: the live
// floor moved aside (asideSeq, when nonzero, overrides its record of k, a
// floor that lagged its pointer), the live keystore/ in pre-restore.d as
// keystore, the backup's in pre-restore.d as restored, and the backup's
// floor in place. It returns the seq-4 copy of k's directory.
func stageRecipe(t *testing.T, s *FileStore, server string, asideSeq uint64) string {
	t.Helper()
	mustPut(t, s, "k", KindOpaque, []byte("v1"))
	tmp := t.TempDir()
	backup := filepath.Join(tmp, "backup")
	copyEntryDir(t, filepath.Join(server, "keystore", "k"), backup)
	backupFloor, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 4; i++ {
		mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
	}
	late := filepath.Join(tmp, "late")
	copyEntryDir(t, filepath.Join(server, "keystore", "k"), late)
	aside := readFloorFile(t, server)
	if asideSeq != 0 {
		e := aside["k"]
		e.Seq = asideSeq
		aside["k"] = e
	}
	writeAsideFloor(t, server, aside)
	remove(t, floorPath(server))
	if err := os.Mkdir(stagePath(s), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(s.dir, stagePath(s, asideTreeName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stagePath(s, stagedTreeName), 0o700); err != nil {
		t.Fatal(err)
	}
	giveToService(t, stagePath(s, stagedTreeName))
	copyEntryDir(t, backup, stagePath(s, stagedTreeName, "k"))
	if err := os.WriteFile(floorPath(server), backupFloor, 0o644); err != nil {
		t.Fatal(err)
	}
	return late
}

// TestFloorMergeRefusesExistingTarget (U192): with the restored tree staged,
// anything at the store's Dir no longer refuses the merge: the merge renames
// it aside into the root-only pre-restore.d as planted-<unix>, out of the
// service user's reach, reports it, and goes on. A pointer the service user
// planted there one past the restored record is never read, and a symlink
// there is never written through. A dry run reports the move and makes none.
func TestFloorMergeRefusesExistingTarget(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		typ   fs.FileMode
		plant func(t *testing.T, s *FileStore, late, elsewhere string)
	}{
		{"a planted pointer one past the restored record", fs.ModeDir, func(t *testing.T, s *FileStore, late, _ string) {
			if err := os.Mkdir(s.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			giveToService(t, s.dir)
			copyEntryDir(t, late, filepath.Join(s.dir, "k"))
		}},
		{"a symlink", fs.ModeSymlink, func(t *testing.T, s *FileStore, _, elsewhere string) {
			if err := os.Symlink(elsewhere, s.dir); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			late := stageRecipe(t, s, server, 0)
			elsewhere := t.TempDir()
			tc.plant(t, s, late, elsewhere)
			before, err := os.ReadFile(floorPath(server))
			if err != nil {
				t.Fatal(err)
			}
			r, err := s.MergeFloor(ctx, MergeOptions{DryRun: true})
			if err != nil || !strings.HasPrefix(r.MovedAside, plantedPrefix) {
				t.Fatalf("dry run with %s at Dir: %+v, %v; want the move aside reported", tc.name, r, err)
			}
			if fi, err := os.Lstat(s.dir); err != nil || fi.Mode().Type() != tc.typ {
				t.Fatalf("Dir after the dry run: %v, %v; want the planted object left", fi, err)
			}
			if after, err := os.ReadFile(floorPath(server)); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("live floor after the dry run = %s, %v; want it unchanged", after, err)
			}
			r, err = s.MergeFloor(ctx, MergeOptions{})
			if err != nil || !strings.HasPrefix(r.MovedAside, plantedPrefix) || len(r.Fenced) != 1 {
				t.Fatalf("MergeFloor with %s at Dir: %+v, %v; want it moved aside and k fenced", tc.name, r, err)
			}
			fi, err := os.Lstat(stagePath(s, r.MovedAside))
			if err != nil || fi.Mode().Type() != tc.typ {
				t.Fatalf("pre-restore.d/%s after the merge: %v, %v; want the planted object there", r.MovedAside, fi, err)
			}
			if names, err := os.ReadDir(elsewhere); err != nil || len(names) != 0 {
				t.Fatalf("symlink target after the merge holds %v, %v; want nothing written through it", names, err)
			}
			if fi, err := os.Lstat(s.dir); err != nil || !fi.IsDir() {
				t.Fatalf("Dir after the merge: %v, %v; want the restored tree moved in", fi, err)
			}
			if _, err := os.Lstat(floorPath(server) + ".pre-restore"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("guard after the merge: %v, want it renamed", err)
			}
			mustCurrent(t, s, "k", "v1")
		})
	}
}

// TestFloorMergeFencesAboveAsidePointer (U192): a moved-aside floor that
// lagged its own entry's pointer by more than one (floor at seq 2, pointer
// at 4) is fenced above that authenticated pointer, read from the
// moved-aside tree in pre-restore.d, so the seq-4 copy put back after the
// merge is refused.
func TestFloorMergeFencesAboveAsidePointer(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	late := stageRecipe(t, s, server, 2)
	if _, err := s.MergeFloor(ctx, MergeOptions{}); err != nil {
		t.Fatal(err)
	}
	if e := floorOf(t, server)["k"]; e.Seq != 1 || e.HighWater != 5 {
		t.Fatalf("k after the merge = %+v, want seq 1 fenced at 5, one past the moved-aside pointer", e)
	}
	mustCurrent(t, s, "k", "v1")
	replaceEntryDir(t, server, "k", late)
	var stale *staleError
	if _, _, err := s.Current(ctx, "k"); !errors.As(err, &stale) {
		t.Fatalf("Current over the seq-4 copy: %v, want it refused by the fence", err)
	}
}

// TestFloorMergeMovesStagedTree (U192): the merge writes the floor, hands
// the staged tree to the service user through descriptors, and moves it to
// the store's Dir; a failed move after the floor write is committed, the
// tree left staged and the guard in place, and a rerun moves it and renames
// the guard.
func TestFloorMergeMovesStagedTree(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	fail := true
	s.step = func(name string) error {
		if name == "merge tree rename" && fail {
			fail = false
			return errors.New("injected")
		}
		return nil
	}
	r, err := s.MergeFloor(ctx, MergeOptions{})
	if !Committed(err) || len(r.Fenced) != 1 {
		t.Fatalf("MergeFloor with the move failing: %+v, %v; want committed with k fenced", r, err)
	}
	if e := floorOf(t, server)["k"]; e.HighWater != 5 {
		t.Fatalf("k after the committed merge = %+v, want the fence written", e)
	}
	if _, err := os.Lstat(s.dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Dir after the failed move: %v, want it absent", err)
	}
	if _, err := os.Lstat(floorPath(server) + ".pre-restore"); err != nil {
		t.Fatalf("guard after the failed move: %v, want it left", err)
	}
	r, err = s.MergeFloor(ctx, MergeOptions{})
	if err != nil || !r.AlreadyMerged {
		t.Fatalf("rerun: %+v, %v; want already merged", r, err)
	}
	if _, err := os.Lstat(stagePath(s, stagedTreeName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("staged tree after the rerun: %v, want it moved", err)
	}
	if _, err := os.Lstat(floorPath(server) + ".pre-restore"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("guard after the rerun: %v, want it renamed", err)
	}
	uid, _ := serviceIDs(t)
	for _, p := range []string{s.dir, filepath.Join(s.dir, "k"), filepath.Join(s.dir, "k", generationName)} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != uid {
			t.Fatalf("%s owned by %d after the move, want the service user %d", p, st.Uid, uid)
		}
	}
	mustCurrent(t, s, "k", "v1")
}

// TestFloorMergeNeedsStagedTree (U192): a merge that would change the floor
// with no tree staged in pre-restore.d refuses, nothing written.
func TestFloorMergeNeedsStagedTree(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	remove(t, stagePath(s, stagedTreeName, "k", generationName))
	if err := os.RemoveAll(stagePath(s, stagedTreeName)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeFloor(ctx, MergeOptions{}); !errors.Is(err, errNotStaged) {
		t.Fatalf("MergeFloor with nothing staged: %v, want errNotStaged", err)
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, before) {
		t.Fatal("live floor changed by the refused merge")
	}
}

// TestFloorMergeRemovesGuardBuriedStaged (U192): an rm under the guard
// buries the restored entry while its files are staged in
// pre-restore.d/restored, out of rm's reach; the merge removes that entry's
// staged directory before it moves the tree into place, so no second rm is
// needed, and leaves every other entry.
func TestFloorMergeRemovesGuardBuriedStaged(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	mustPut(t, s, "other", KindOpaque, []byte("v"))
	writeAsideFloor(t, server, floorOf(t, server))
	stageTree(t, s)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete under the guard: %v", err)
	}
	if _, err := os.Lstat(stagePath(s, stagedTreeName, "k")); err != nil {
		t.Fatalf("k's staged directory after the rm: %v, want it still staged", err)
	}
	if _, err := s.MergeFloor(ctx, MergeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "k")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("k's directory after the merge: %v, want it removed", err)
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "other")); err != nil {
		t.Fatalf("other's directory after the merge: %v, want it moved into place", err)
	}
}

// TestFloorMergeAsideUnverified (U192): a moved-aside pointer that does not
// authenticate, or a master that does not load for the moved-aside tree, is
// reported (AsideUnverified), dry run and merge alike: the fence is then one
// past the moved-aside floor's record, not past a pointer.
func TestFloorMergeAsideUnverified(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, s *FileStore, server string)
	}{
		{"a pointer that does not authenticate", func(t *testing.T, s *FileStore, _ string) {
			p := stagePath(s, asideTreeName, "k", currentName)
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 0xff
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"no master", func(t *testing.T, _ *FileStore, server string) {
			if err := os.Rename(masterPath(server, masterName), masterPath(server, masterName+".aside")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			stageRecipe(t, s, server, 0)
			tc.spoil(t, s, server)
			for _, dry := range []bool{true, false} {
				r, err := s.MergeFloor(ctx, MergeOptions{DryRun: dry})
				if err != nil || !slices.Equal(r.AsideUnverified, []string{"k"}) {
					t.Fatalf("MergeFloor (dry run %v) with %s: %+v, %v; want k's moved-aside pointer unverified", dry, tc.name, r, err)
				}
			}
		})
	}
}

// TestFloorMergeSyncsStagedTree (U192): the merge fsyncs every file and
// directory of the staged tree before it renames the tree into place, so a
// crash after the rename leaves no truncated key file.
func TestFloorMergeSyncsStagedTree(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	want := map[string]bool{}
	root := stagePath(s, stagedTreeName)
	if err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		want[rel] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	synced, renamed := map[string]bool{}, false
	old := syncStaged
	t.Cleanup(func() { syncStaged = old })
	syncStaged = func(f *os.File) error {
		if renamed {
			t.Errorf("%s fsynced after the tree's rename", f.Name())
		}
		synced[f.Name()] = true
		return old(f)
	}
	s.step = func(name string) error {
		if name == "merge tree rename" {
			renamed = true
		}
		return nil
	}
	if _, err := s.MergeFloor(ctx, MergeOptions{}); err != nil {
		t.Fatal(err)
	}
	for rel := range want {
		if !synced[rel] {
			t.Errorf("%s was not fsynced before the rename (synced %v)", rel, synced)
		}
	}
}
