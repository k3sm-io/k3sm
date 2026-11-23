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

	"golang.org/x/sys/unix"
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
	if err := s.checkStaged(context.Background(), st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkStaged: %v, want ErrCorrupt naming %q", err, want)
	}
	if err := s.chownStaged(context.Background(), st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
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
		if err := s.checkStaged(context.Background(), st); err != nil {
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
		if err := s.chownStaged(context.Background(), st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "k/generation") {
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
		if err := s.chownStaged(context.Background(), st); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "k/generation") {
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
	if err := s.checkStaged(context.Background(), st); err != nil {
		t.Fatalf("checkStaged: %v", err)
	}
	if err := s.chownStaged(context.Background(), st); err != nil {
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

// emptyFloors is rec with the empty floor as both the floor read and the
// floor written.
func emptyFloors(t testing.TB, rec retiredRecord) retiredRecord {
	t.Helper()
	b, err := marshalFloor(floor{})
	if err != nil {
		t.Fatal(err)
	}
	rec.setFloors(b, b)
	return rec
}

// TestParseRetired (U192): the retired record parses only in the one
// encoding a merge writes, its floors each the floor file its sha256 names.
func TestParseRetired(t *testing.T) {
	sum := sha256Hex(nil)
	good, err := marshalRetired(emptyFloors(t, retiredRecord{Input: sum, Retired: []string{"a", "b"}, Dropped: []string{"d", "d"}}))
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := parseRetired(good); err != nil || len(rec.Retired) != 2 || len(rec.BuriedLive) != 0 || len(rec.Dropped) != 2 {
		t.Fatalf("parseRetired(%s) = %+v, %v; want a and b retired and d dropped twice", good, rec, err)
	}
	otherFloor := func(written bool) retiredRecord {
		rec := emptyFloors(t, retiredRecord{Input: sum})
		b, err := marshalFloor(floor{"a": {Generation: mgen(1), Seq: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if written {
			rec.Written = bytes.TrimSuffix(b, []byte("\n"))
		} else {
			rec.Read = bytes.TrimSuffix(b, []byte("\n"))
		}
		return rec
	}
	notFloor := emptyFloors(t, retiredRecord{Input: sum})
	notFloor.Written, notFloor.Floor = []byte(`{}`), sha256Hex([]byte("{}\n"))
	for _, bad := range []retiredRecord{
		emptyFloors(t, retiredRecord{Input: ""}),
		emptyFloors(t, retiredRecord{Input: strings.ToUpper(sum)}),
		emptyFloors(t, retiredRecord{Input: sum, Kept: []string{"a", "a"}}),
		emptyFloors(t, retiredRecord{Input: sum, Dropped: []string{"b", "a"}}),
		{Input: sum, Base: sum, Floor: sum},
		otherFloor(false),
		otherFloor(true),
		notFloor,
	} {
		b, err := marshalRetired(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseRetired(b); !errors.Is(err, ErrCorrupt) {
			t.Errorf("parseRetired(%s): %v, want ErrCorrupt", b, err)
		}
	}
	for _, bad := range []string{
		`{"retired":["b","a"],"buriedLive":[]}` + "\n",
		`{"retired":["a","a"],"buriedLive":[]}` + "\n",
		`{"retired":["Bad"],"buriedLive":[]}` + "\n",
		`{"retired":[],"buriedLive":[],"x":1}` + "\n",
		`{"retired":[],"buriedLive":[]}`,
		`{"buriedLive":[],"retired":[]}` + "\n",
		`{"retired":[],"buriedLive":[]}{}` + "\n",
	} {
		if _, err := parseRetired([]byte(bad)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("parseRetired(%q): %v, want ErrCorrupt", bad, err)
		}
	}
}

// TestOpenStagingRefusesACL (U192): pre-restore.d with an extended ACL is
// refused, dry run included, nothing written: its mode is what keeps the
// service user out of the staged tree, and an ACL entry grants past it.
func TestOpenStagingRefusesACL(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Log("extended ACLs are read on darwin only")
		return
	}
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow list,search", stagePath(s)).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v: %s", err, out)
	}
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		if _, err := s.MergeFloor(context.Background(), MergeOptions{DryRun: dry}); !errors.Is(err, errFloorUntrusted) || !strings.Contains(err.Error(), "extended ACL") {
			t.Fatalf("MergeFloor (dry run %v) with an ACL on pre-restore.d: %v, want it refused naming the ACL", dry, err)
		}
	}
	if after, _ := os.ReadFile(floorPath(server)); !bytes.Equal(after, before) {
		t.Fatal("live floor changed by the refused merge")
	}
}

// wellFormedDropped is a persisted pre-frame refusal count in its format.
func wellFormedDropped() []byte {
	d := newPreFrameDropped()
	d.uids[preFrameKey{preFrameClassLogin, 501}] = 3
	d.others[preFrameClassSystemHigh] = 2
	return encodePreFrameDropped(d)
}

// droppedTempName is a temporary-file name writeFile gives
// PreFrameDroppedName.
var droppedTempName = tempName(PreFrameDroppedName, [tempSuffixSize]byte{1, 2, 3, 4, 5, 6, 7, 8})

// TestStagedPreFrameDroppedAccepted: the persisted pre-frame refusal
// count, and its temporary file, at the top of a staged keystore/ are in
// the keystore's shape when well formed, so a backup taken while the
// server keeps one restores.
func TestStagedPreFrameDroppedAccepted(t *testing.T) {
	for _, name := range []string{PreFrameDroppedName, droppedTempName} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			stageRecipe(t, s, server, 0)
			writeStaged(t, s, name, wellFormedDropped())
			st := openTestStaging(t, s)
			if err := s.checkStaged(context.Background(), st); err != nil {
				t.Fatalf("checkStaged: %v", err)
			}
			if err := s.chownStaged(context.Background(), st); err != nil {
				t.Fatalf("chownStaged: %v", err)
			}
		})
	}
}

// TestStagedPreFrameDroppedRefused: a staged persisted count, or its
// temporary file, is refused by the read-only walk and the handover when
// it is over its size cap, a symlink, a FIFO, hard-linked, at another
// mode, or does not parse.
func TestStagedPreFrameDroppedRefused(t *testing.T) {
	for _, name := range []string{PreFrameDroppedName, droppedTempName} {
		for _, tc := range []struct {
			name  string
			plant func(t *testing.T, s *FileStore, p string)
		}{
			{"over the cap", func(t *testing.T, s *FileStore, p string) {
				b := append(wellFormedDropped(), bytes.Repeat([]byte("1 login 1\n"), maxPreFrameDroppedSize/10+1)...)
				writeStaged(t, s, name, b)
			}},
			{"a symlink", func(t *testing.T, s *FileStore, p string) {
				if err := os.Symlink("/etc/passwd", p); err != nil {
					t.Fatal(err)
				}
			}},
			{"a FIFO", func(t *testing.T, s *FileStore, p string) {
				if err := syscall.Mkfifo(p, 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{"hard-linked", func(t *testing.T, s *FileStore, p string) {
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, wellFormedDropped(), 0o600); err != nil {
					t.Fatal(err)
				}
				giveToService(t, outside)
				if err := os.Link(outside, p); err != nil {
					t.Fatal(err)
				}
			}},
			{"another mode", func(t *testing.T, s *FileStore, p string) {
				writeStaged(t, s, name, wellFormedDropped())
				if err := os.Chmod(p, 0o400); err != nil {
					t.Fatal(err)
				}
			}},
			{"malformed", func(t *testing.T, s *FileStore, p string) {
				writeStaged(t, s, name, []byte(preFrameDroppedHeader+"501 login 0\n"))
			}},
			{"no header", func(t *testing.T, s *FileStore, p string) {
				writeStaged(t, s, name, []byte("501 login 1\n"))
			}},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				s, server := newTestStore(t)
				stageRecipe(t, s, server, 0)
				tc.plant(t, s, stagePath(s, stagedTreeName, name))
				wantShapeRefused(t, s, name)
			})
		}
	}
}

// TestStagedPreFrameDroppedUnknownOwner: the persisted pre-frame refusal
// count, and its temporary file, take the owner rule of every other staged
// file: the service user or the unknown owner (uid 99) a volume that
// ignores ownership reports, so a backup copied off such a volume restores.
// Any other owner is still refused. Non-root the file cannot be given to
// uid 99, so the owner judge (judgeStaged) reads the file's real stat with
// its owner set; root also walks a tree with the file at uid 99.
func TestStagedPreFrameDroppedUnknownOwner(t *testing.T) {
	for _, name := range []string{PreFrameDroppedName, droppedTempName} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			stageRecipe(t, s, server, 0)
			p := writeStaged(t, s, name, wellFormedDropped())
			kind, maxSize, ok := stagedChild(stagedTree, name)
			if !ok {
				t.Fatalf("stagedChild(%q) refuses the name", name)
			}
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			var st unix.Stat_t
			if err := unix.Fstat(int(f.Fd()), &st); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				uid  uint32
				want bool
			}{{s.uid, true}, {unknownUID, true}, {otherUID(t), false}} {
				st.Uid = tc.uid
				err := s.judgeStaged(int(f.Fd()), name, &st, kind, maxSize)
				if tc.want && err != nil {
					t.Errorf("judgeStaged owned by uid %d: %v, want it accepted", tc.uid, err)
				}
				if !tc.want && (!errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "owned by uid")) {
					t.Errorf("judgeStaged owned by uid %d: %v, want ErrCorrupt naming the owner", tc.uid, err)
				}
			}
			if !asRoot() {
				return
			}
			if err := os.Lchown(p, unknownUID, unknownUID); err != nil {
				t.Fatal(err)
			}
			st2 := openTestStaging(t, s)
			if err := s.checkStaged(context.Background(), st2); err != nil {
				t.Fatalf("checkStaged with %s at uid %d: %v", name, unknownUID, err)
			}
			if err := s.chownStaged(context.Background(), st2); err != nil {
				t.Fatalf("chownStaged with %s at uid %d: %v", name, unknownUID, err)
			}
		})
	}
}
