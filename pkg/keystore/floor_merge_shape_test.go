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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// openTestStaging opens s's pre-restore.d as openStaging does, without the
// floor lock, for a test of the staged-tree walk alone.
func openTestStaging(t *testing.T, s *FileStore) *mergeStaging {
	t.Helper()
	root, err := os.OpenRoot(stagePath(s))
	if err != nil {
		t.Fatal(err)
	}
	f, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	st := &mergeStaging{dir: root, dirF: f, staged: true}
	t.Cleanup(st.close)
	return st
}

// wantShapeRefused checks that both the read-only walk and the handover
// refuse s's staged tree as ErrCorrupt naming want, and that the handover
// changed the owner of nothing it walked before the refusal it names.
func wantShapeRefused(t *testing.T, s *FileStore, want string) {
	t.Helper()
	st := openTestStaging(t, s)
	if err := s.checkStaged(st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkStaged: %v, want ErrCorrupt naming %q", err, want)
	}
	if err := s.chownStaged(st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
		t.Fatalf("chownStaged: %v, want ErrCorrupt naming %q", err, want)
	}
}

// writeStaged writes a file at rel inside s's staged tree, handed to the
// service user.
func writeStaged(t *testing.T, s *FileStore, rel string, data []byte) string {
	t.Helper()
	p := stagePath(s, stagedTreeName, rel)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, p)
	return p
}

// TestChownStagedRefusesShape (U192): the merge hands over only a tree in
// the keystore's shape. Each tree below is refused by the read-only walk
// and by the handover, naming the path inside the tree.
func TestChownStagedRefusesShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, s *FileStore)
		want  string
	}{
		{"a top-level name that is no entry name", func(t *testing.T, s *FileStore) {
			writeStaged(t, s, "Bad_Name", nil)
		}, "Bad_Name"},
		{"an unexpected name in an entry", func(t *testing.T, s *FileStore) {
			writeStaged(t, s, "k/notes.txt", nil)
		}, "k/notes.txt"},
		{"a version past the limit", func(t *testing.T, s *FileStore) {
			writeStaged(t, s, "k/v65537", nil)
		}, "k/v65537"},
		{"a directory inside an entry", func(t *testing.T, s *FileStore) {
			p := stagePath(s, stagedTreeName, "k", "v9")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			giveToService(t, p)
		}, "k/v9"},
		{"a symlink", func(t *testing.T, s *FileStore) {
			if err := os.Symlink("/etc/passwd", stagePath(s, stagedTreeName, "k", "v9")); err != nil {
				t.Fatal(err)
			}
		}, "k/v9"},
		{"a FIFO", func(t *testing.T, s *FileStore) {
			if err := syscall.Mkfifo(stagePath(s, stagedTreeName, "k", "v9"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "k/v9"},
		{"a socket", func(t *testing.T, s *FileStore) {
			// A socket's path is bounded: bind it in a short directory and
			// rename it into place.
			dir, err := os.MkdirTemp("", "ks")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.RemoveAll(dir) }()
			fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = syscall.Close(fd) }()
			if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: filepath.Join(dir, "s")}); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, "s"), stagePath(s, stagedTreeName, "k", "v9")); err != nil {
				t.Fatal(err)
			}
		}, "k/v9"},
		{"a second hard link", func(t *testing.T, s *FileStore) {
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			giveToService(t, outside)
			if err := os.Link(outside, stagePath(s, stagedTreeName, "k", "v9")); err != nil {
				t.Fatal(err)
			}
		}, "k/v9"},
		{"a setuid file", func(t *testing.T, s *FileStore) {
			p := writeStaged(t, s, "k/v9", nil)
			if err := os.Chmod(p, 0o600|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
		}, "k/v9"},
		{"a sticky directory", func(t *testing.T, s *FileStore) {
			if err := os.Chmod(stagePath(s, stagedTreeName, "k"), 0o700|os.ModeSticky); err != nil {
				t.Fatal(err)
			}
		}, "k"},
		{"a file over its size cap", func(t *testing.T, s *FileStore) {
			writeStaged(t, s, "k/"+generationName, bytes.Repeat([]byte{'a'}, generationFileSize+1))
		}, "k/generation"},
		{"a file with a flag", func(t *testing.T, s *FileStore) {
			p := writeStaged(t, s, "k/v9", nil)
			if err := setFlags(p, 0x40 /* UF_HIDDEN */); err != nil {
				t.Fatal(err)
			}
		}, "k/v9"},
		{"a tree deeper than the keystore", func(t *testing.T, s *FileStore) {
			p := stagePath(s, stagedTreeName, userScopesName, "501", scopeEntriesName, "k", "x", "y")
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			for ; p != stagePath(s, stagedTreeName); p = filepath.Dir(p) {
				giveToService(t, p)
			}
		}, userScopesName + "/501/entries/k/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server := newTestStore(t)
			stageRecipe(t, s, server, 0)
			tc.plant(t, s)
			wantShapeRefused(t, s, tc.want)
		})
	}
}

// setFlags sets path's file flags (chflags) without following it.
func setFlags(path string, flags int) error {
	return syscall.Chflags(path, flags)
}

// TestChownStagedRefusesACL (U192): a file with an extended ACL is refused,
// so no grant set on the backup reaches the live keystore.
func TestChownStagedRefusesACL(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Log("extended ACLs are read on darwin only")
		return
	}
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	p := writeStaged(t, s, "k/v9", nil)
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read", p).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v: %s", err, out)
	}
	wantShapeRefused(t, s, "k/v9")
}

// TestChownStagedRefusesForeignOwner (U192): a file owned by anyone but the
// service user (or the unknown owner an ownership-ignoring volume reports)
// is refused, root included: a root-owned single-link file in the staged
// tree is exactly what a copied hard link to a root file looks like.
func TestChownStagedRefusesForeignOwner(t *testing.T) {
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	if asRoot() {
		p := stagePath(s, stagedTreeName, "k", "v9")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		wantShapeRefused(t, s, "k/v9")
		if fi, err := os.Lstat(p); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("root-owned file after the refusal: %v, %v; want it still root's", fi, err)
		}
		remove(t, p)
	}
	// Non-root, the running user owns every file: a service user that is
	// someone else makes each one foreign, the tree itself first.
	s.uid = otherUID(t)
	wantShapeRefused(t, s, "owned by uid")
}

// TestChownStagedRecheckSeam (U192): a node swapped after the read-only walk
// is judged again on the descriptor the handover changes, and a link made
// to a file between its checks and its fchown is caught by the fstat after
// it, with the file's owner and mode put back.
func TestChownStagedRecheckSeam(t *testing.T) {
	t.Run("swapped for a hard link before the handover", func(t *testing.T) {
		s, server := newTestStore(t)
		stageRecipe(t, s, server, 0)
		st := openTestStaging(t, s)
		if err := s.checkStaged(st); err != nil {
			t.Fatal(err)
		}
		gen := stagePath(s, stagedTreeName, "k", generationName)
		outside := filepath.Join(t.TempDir(), "outside")
		copyFile(t, gen, outside)
		giveToService(t, outside)
		remove(t, gen)
		if err := os.Link(outside, gen); err != nil {
			t.Fatal(err)
		}
		if err := s.chownStaged(st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "k/generation") {
			t.Fatalf("chownStaged over a swapped-in hard link: %v, want ErrCorrupt naming k/generation", err)
		}
	})
	t.Run("linked between the checks and the fchown", func(t *testing.T) {
		s, server := newTestStore(t)
		stageRecipe(t, s, server, 0)
		gen := stagePath(s, stagedTreeName, "k", generationName)
		if err := os.Chmod(gen, 0o640); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "link")
		s.step = func(name string) error {
			if name == "merge chown k/generation" {
				return os.Link(gen, link)
			}
			return nil
		}
		st := openTestStaging(t, s)
		if err := s.chownStaged(st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "k/generation") {
			t.Fatalf("chownStaged with a link made at the seam: %v, want ErrCorrupt naming k/generation", err)
		}
		if fi, err := os.Lstat(gen); err != nil || fi.Mode().Perm() != 0o640 {
			t.Fatalf("k/generation after the refusal: %v, %v; want its mode 0640 put back", fi, err)
		}
	})
}

// TestChownStagedNameBound (U192): a directory in the staged tree holding
// more names than the walk accepts is refused.
func TestChownStagedNameBound(t *testing.T) {
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	old := stagedNameLimit
	stagedNameLimit = 3
	t.Cleanup(func() { stagedNameLimit = old })
	for _, n := range []string{"v7", "v8", "v9"} {
		writeStaged(t, s, "k/"+n, nil)
	}
	wantShapeRefused(t, s, "more than 3 names")
}

// TestChownStagedSetsModes (U192): the handover sets the modes Put writes,
// 0700 on each directory and 0600 on each file, and accepts a user scope's
// files and a writeFile temporary file.
func TestChownStagedSetsModes(t *testing.T) {
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	scope := stagePath(s, stagedTreeName, userScopesName, "501")
	if err := os.MkdirAll(filepath.Join(scope, scopeEntriesName, "u"), 0o755); err != nil {
		t.Fatal(err)
	}
	giveToService(t, filepath.Dir(scope), scope, filepath.Join(scope, scopeEntriesName), filepath.Join(scope, scopeEntriesName, "u"))
	for _, rel := range []string{userScopesName + "/501/" + scopeKeyName, userScopesName + "/501/" + deliveriesName, userScopesName + "/501/entries/u/" + currentName, "k/." + currentName + ".00112233445566aa.tmp", "k/v1" + newSuffix} {
		p := writeStaged(t, s, rel, nil)
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st := openTestStaging(t, s)
	if err := s.checkStaged(st); err != nil {
		t.Fatalf("checkStaged: %v", err)
	}
	if err := s.chownStaged(st); err != nil {
		t.Fatalf("chownStaged: %v", err)
	}
	err := filepath.Walk(stagePath(s, stagedTreeName), func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(0o600)
		if fi.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s is mode %04o after the handover, want %04o", p, fi.Mode().Perm(), want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestFloorMergeShapeDryRunParity (U192): a dry run refuses the tree the
// real run refuses, with the same error, and neither writes the floor.
func TestFloorMergeShapeDryRunParity(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	writeStaged(t, s, "k/notes.txt", nil)
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		if _, err := s.MergeFloor(ctx, MergeOptions{DryRun: dry}); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "k/notes.txt") {
			t.Fatalf("MergeFloor (dry run %v) over an unexpected name: %v, want ErrCorrupt naming it", dry, err)
		}
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("live floor after the refused merges = %s, %v; want it unchanged", after, err)
	}
}

// TestFloorMergeRemovesBuriedLiveStaged (U192): the merge removes the staged
// directory of every entry it buries live, not only those rm buried under
// the guard, so a later prune that drops the burial brings nothing back. A
// name --keep keeps is not buried live, and its directory moves into place.
func TestFloorMergeRemovesBuriedLiveStaged(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(map[bool]string{false: "buried live", true: "kept"}[keep], func(t *testing.T) {
			ctx := context.Background()
			s, server := newTestStore(t)
			mustPut(t, s, "k", KindOpaque, []byte("v"))
			mustPut(t, s, "other", KindOpaque, []byte("v"))
			live := floorOf(t, server)
			aside := floor{"other": live["other"], "k": {Buried: []burial{{Generation: live["k"].Generation, Deleted: 1}}}}
			writeAsideFloor(t, server, aside)
			stageTree(t, s)
			var opts MergeOptions
			if keep {
				opts.Keep = []string{"k"}
			}
			r, err := s.MergeFloor(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(s.dir, "other")); err != nil {
				t.Fatalf("other's directory after the merge: %v, want it moved into place", err)
			}
			if keep {
				if len(r.BuriedLive) != 0 {
					t.Fatalf("MergeFloor keeping k: %+v, want nothing buried live", r)
				}
				mustCurrent(t, s, "k", "v")
				return
			}
			if len(r.BuriedLive) != 1 || r.BuriedLive[0] != "k" {
				t.Fatalf("MergeFloor: %+v, want k buried live", r)
			}
			if _, err := os.Lstat(filepath.Join(s.dir, "k")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("k's directory after the merge: %v, want it removed", err)
			}
			// A prune that drops k's burial, as the tombstone budget does.
			fl := floorOf(t, server)
			delete(fl, "k")
			putFloorFile(t, server, fl)
			if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Current k after its burial was pruned: %v, want ErrNotFound", err)
			}
			if _, err := os.Lstat(filepath.Join(s.dir, "k")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("k's directory after the prune: %v, want it still absent", err)
			}
		})
	}
}
