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
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The tests for Rotate and the pointer floor: docs/design/keystore.md §
// "Pointer sequence and floor" and § "Rotation and rollback", gate rows G5
// to G9.

func mustRotate(t *testing.T, s *FileStore, name, value string) Version {
	t.Helper()
	v, err := s.Rotate(context.Background(), name, []byte(value))
	if err != nil {
		t.Fatalf("Rotate %s: %v", name, err)
	}
	return v
}

func mustCurrent(t *testing.T, s *FileStore, name, want string) {
	t.Helper()
	if _, val, err := s.Current(context.Background(), name); err != nil || string(val) != want {
		t.Fatalf("Current %s = %q, %v; want %q", name, val, err, want)
	}
}

// floorOf reads the floor file under server's data root as the store does.
func floorOf(t *testing.T, server string) floor {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(server), floorName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	fl, err := parseFloor(b)
	if err != nil {
		t.Fatal(err)
	}
	return fl
}

func floorPath(server string) string { return filepath.Join(filepath.Dir(server), floorName) }

func entryPath(server, name, file string) string {
	return filepath.Join(server, "keystore", name, file)
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	if v := mustRotate(t, s, "k", "two"); v.Version != 2 || v.Kind != KindOpaque {
		t.Fatalf("first Rotate = %+v, want version 2, opaque", v)
	}
	mustRotate(t, s, "k", "three")
	mustCurrent(t, s, "k", "three")
	for n, want := range map[uint64]string{1: "one", 2: "two", 3: "three"} {
		if _, val, err := s.Get(ctx, "k", n); err != nil || string(val) != want {
			t.Errorf("Get %d = %q, %v; want %q", n, val, err, want)
		}
	}
	if _, _, err := s.Get(ctx, "k", 4); !errors.Is(err, ErrVersionNotFound) {
		t.Errorf("Get 4: %v, want ErrVersionNotFound", err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 || len(list[0].Versions) != 3 || list[0].Current.Version != 3 {
		t.Fatalf("List = %+v, %v; want one entry at version 3 of 3", list, err)
	}
	// Put writes sequence 1 and every Rotate the previous plus one.
	if f := floorOf(t, server)["k"]; f.Seq != 3 {
		t.Errorf("floor after two rotations = %+v, want sequence 3", f)
	}

	t.Run("keeps the kind and validates the value against it", func(t *testing.T) {
		seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
		mustPut(t, s, "signer", KindEd25519, seed)
		if _, err := s.Rotate(ctx, "signer", []byte("short")); err == nil {
			t.Fatal("Rotate stored an Ed25519 value of the wrong length")
		}
		v, err := s.Rotate(ctx, "signer", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)))
		if err != nil || v.Kind != KindEd25519 || v.Version != 2 {
			t.Fatalf("Rotate signer = %+v, %v; want Ed25519 version 2", v, err)
		}
	})
	t.Run("refuses", func(t *testing.T) {
		if _, err := s.Rotate(ctx, "absent", []byte("x")); !errors.Is(err, ErrNotFound) {
			t.Errorf("Rotate of an absent name: %v, want ErrNotFound", err)
		}
		if _, err := s.Rotate(ctx, "Bad", []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Rotate of an invalid name: %v, want ErrInvalidName", err)
		}
		empty, _ := newTestStore(t)
		if _, err := empty.Rotate(ctx, "k", []byte("x")); !errors.Is(err, ErrNotFound) {
			t.Errorf("Rotate in an empty keystore: %v, want ErrNotFound", err)
		}
	})
}

// TestFloorRefusesCopiedBackPointer is G5: a current pointer that once was
// valid, copied back over the live one, still authenticates, and the floor
// refuses it with its own message; with nothing recorded for the name it is
// accepted.
func TestFloorRefusesCopiedBackPointer(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*FileStore, string) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		copyFile(t, entryPath(server, "k", currentName), filepath.Join(server, "old-current"))
		mustRotate(t, s, "k", "two")
		copyFile(t, filepath.Join(server, "old-current"), entryPath(server, "k", currentName))
		return s, server
	}

	t.Run("refused", func(t *testing.T) {
		s, _ := setup(t)
		_, _, err := s.Current(ctx, "k")
		var stale *staleError
		if !errors.Is(err, ErrCorrupt) || !errors.As(err, &stale) {
			t.Fatalf("Current over a copied-back pointer: %v, want a floor refusal matching ErrCorrupt", err)
		}
		msg := err.Error()
		for _, want := range []string{"older than the recorded floor", "sequence 1", "sequence 2", "Do not restore from backup", "Restoring an older keystore/"} {
			if !strings.Contains(msg, want) {
				t.Errorf("refusal %q does not say %q", msg, want)
			}
		}
		if strings.Contains(msg, "restore it from backup") {
			t.Errorf("refusal %q carries ErrCorrupt's advice to restore from backup", msg)
		}
		if _, _, err := s.Get(ctx, "k", 1); !errors.As(err, &stale) {
			t.Errorf("Get over a copied-back pointer: %v, want the floor refusal", err)
		}
		if list, err := s.List(ctx); err != nil || len(list) != 1 || !errors.As(list[0].Err, &stale) {
			t.Errorf("List over a copied-back pointer = %+v, %v; want the entry with the floor refusal", list, err)
		}
		// A Rotate must not write a new version over it either.
		if _, err := s.Rotate(ctx, "k", []byte("three")); !errors.As(err, &stale) {
			t.Errorf("Rotate over a copied-back pointer: %v, want the floor refusal", err)
		}
		// Nor may the next root verb raise the floor to it, or lower the floor.
		if err := s.RaiseFloor(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Current(ctx, "k"); !errors.As(err, &stale) {
			t.Errorf("Current after RaiseFloor: %v, want the floor refusal still", err)
		}
	})
	t.Run("accepted with no floor entry for the name", func(t *testing.T) {
		s, server := setup(t)
		writeFile(t, floorPath(server), `{"version":1,"scope":"system","entries":{}}`)
		mustCurrent(t, s, "k", "one")
	})
	t.Run("accepted with no floor file", func(t *testing.T) {
		s, server := setup(t)
		remove(t, floorPath(server))
		mustCurrent(t, s, "k", "one")
	})
	t.Run("another generation is refused", func(t *testing.T) {
		// An old copy of a deleted entry, put back over the entry re-created
		// under its name, opens on its own: the generation check (G4) does not
		// see it, because every file in it is of the old generation. The
		// floor does.
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("old"))
		old := filepath.Join(server, "old-entry")
		if err := os.Mkdir(old, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{generationName, "v1", currentName} {
			copyFile(t, entryPath(server, "k", f), filepath.Join(old, f))
		}
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		mustPut(t, s, "k", KindOpaque, []byte("new"))
		if err := os.RemoveAll(filepath.Join(server, "keystore", "k")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(old, filepath.Join(server, "keystore", "k")); err != nil {
			t.Fatal(err)
		}
		// The deleted generation stays buried after the new Put, so that is
		// the refusal.
		var stale *staleError
		_, _, err := s.Current(ctx, "k")
		if !errors.As(err, &stale) || !stale.deleted {
			t.Fatalf("Current over an old generation: %v, want the floor's deleted refusal", err)
		}
		// With its burial gone (pruned), the live record of the new
		// generation still refuses it: the generation refusal, which names
		// its case, a put-back after a newer Put.
		live := floorOf(t, server)["k"]
		putFloorFile(t, server, floor{"k": {Generation: live.Generation, Seq: live.Seq}})
		_, _, err = s.Current(ctx, "k")
		if !errors.As(err, &stale) || !stale.generation {
			t.Fatalf("Current over a pruned generation: %v, want the floor's generation refusal", err)
		}
		if msg := err.Error(); !strings.Contains(msg, "after a newer put of the name") {
			t.Errorf("generation refusal %q does not say the put-back followed a newer put", msg)
		}
	})
}

// TestFloorTrust is G6: the floor, and the data root holding it, are judged
// on the opened descriptor, and a floor the service user could have written
// is refused, never read as absent.
func TestFloorTrust(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		damage func(t *testing.T, s *FileStore, server string)
		want   error
	}{
		{"group-writable", func(t *testing.T, _ *FileStore, server string) { chmod(t, floorPath(server), 0o664) }, errFloorUntrusted},
		{"other-writable", func(t *testing.T, _ *FileStore, server string) { chmod(t, floorPath(server), 0o646) }, errFloorUntrusted},
		{"not owned by root", func(t *testing.T, s *FileStore, server string) {
			// As root, the floor is handed to another user; a store run as
			// root may name no owner but root. Non-root, the store names an
			// owner other than the floor's.
			if asRoot() {
				if err := os.Lchown(floorPath(server), int(otherUID(t)), 0); err != nil {
					t.Fatal(err)
				}
				return
			}
			s.floorUID++
		}, errFloorUntrusted},
		{"a symlink", func(t *testing.T, _ *FileStore, server string) {
			copyFile(t, floorPath(server), floorPath(server)+".real")
			replaceWithSymlink(t, floorPath(server), floorName+".real")
		}, errFloorUntrusted},
		{"a dangling symlink", func(t *testing.T, _ *FileStore, server string) {
			replaceWithSymlink(t, floorPath(server), "nowhere")
		}, errFloorUntrusted},
		{"a FIFO", func(t *testing.T, _ *FileStore, server string) { replaceWithFIFO(t, floorPath(server)) }, errFloorUntrusted},
		{"in a group-writable data root", func(t *testing.T, _ *FileStore, server string) {
			chmod(t, filepath.Dir(server), 0o770)
		}, errFloorUntrusted},
		{"malformed", func(t *testing.T, _ *FileStore, server string) { writeFile(t, floorPath(server), "{") }, errFloorMalformed},
		{"an unknown field", func(t *testing.T, _ *FileStore, server string) {
			writeFile(t, floorPath(server), `{"version":1,"scope":"system","entries":{},"extra":1}`)
		}, errFloorMalformed},
		{"another format", func(t *testing.T, _ *FileStore, server string) {
			writeFile(t, floorPath(server), `{"version":2,"scope":"system","entries":{}}`)
		}, errFloorMalformed},
		{"a bad generation", func(t *testing.T, _ *FileStore, server string) {
			writeFile(t, floorPath(server), `{"version":1,"scope":"system","entries":{"k":{"generation":"zz","seq":1}}}`)
		}, errFloorMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "k", KindOpaque, []byte("v"))
			c.damage(t, s, server)
			if _, _, err := s.Current(ctx, "k"); !errors.Is(err, c.want) {
				t.Errorf("Current: %v, want %v", err, c.want)
			}
			if _, err := s.List(ctx); !errors.Is(err, c.want) {
				t.Errorf("List: %v, want %v", err, c.want)
			}
			if _, err := s.Rotate(ctx, "k", []byte("w")); !errors.Is(err, c.want) {
				t.Errorf("Rotate: %v, want %v", err, c.want)
			}
			if _, err := s.Put(ctx, "other", KindOpaque, []byte("w")); !errors.Is(err, c.want) {
				t.Errorf("Put: %v, want %v", err, c.want)
			}
			if err := s.Delete(ctx, "k"); !errors.Is(err, c.want) {
				t.Errorf("Delete: %v, want %v", err, c.want)
			}
		})
	}
	t.Run("written root-owned and not shared", func(t *testing.T) {
		s, server := newTestStore(t)
		var owners []int
		s.chown = func(f *os.File, uid, gid int) error {
			if strings.Contains(f.Name(), floorName) {
				owners = append(owners, uid, gid)
			}
			return f.Chown(uid, gid)
		}
		s.floorUID, s.floorGID = floorIDs()
		mustPut(t, s, "k", KindOpaque, []byte("v"))
		fi, err := os.Lstat(floorPath(server))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != floorFileMode {
			t.Errorf("floor mode %s, want %s", fi.Mode(), floorFileMode)
		}
		if len(owners) != 2 || owners[0] != s.floorUID || owners[1] != s.floorGID {
			t.Errorf("floor chowned to %v, want %d:%d", owners, s.floorUID, s.floorGID)
		}
		if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != s.floorUID {
			t.Errorf("floor owned by %d, want %d", st.Uid, s.floorUID)
		}
	})
}

// TestFloorRaised is G7: every mutating verb records its pointer's sequence,
// every root verb begins by raising the floor to the pointers, and a floor
// one behind its pointer (a crash after the flip, before the floor write) is
// accepted and then raised.
func TestFloorRaised(t *testing.T) {
	ctx := context.Background()
	gen := func(t *testing.T, server, name string) string {
		t.Helper()
		b, err := os.ReadFile(entryPath(server, name, generationName))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}

	t.Run("by every mutating verb", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		if f := floorOf(t, server)["k"]; f.Seq != 1 || f.Generation != gen(t, server, "k") {
			t.Fatalf("floor after Put = %+v, want sequence 1 at the entry's generation", f)
		}
		mustRotate(t, s, "k", "two")
		if f := floorOf(t, server)["k"]; f.Seq != 2 {
			t.Fatalf("floor after Rotate = %+v, want sequence 2", f)
		}
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		if f := floorOf(t, server)["k"]; len(f.burials()) == 0 || f.live() {
			t.Fatalf("floor after Delete = %+v, want the deleted entry's tombstone", f)
		}
	})
	t.Run("a Rotate crash after the flip", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		copyFile(t, entryPath(server, "k", currentName), filepath.Join(server, "seq1"))
		mustRotate(t, s, "k", "two")
		copyFile(t, entryPath(server, "k", currentName), filepath.Join(server, "seq2"))
		s.step = failAt("write " + floorName)
		if _, err := s.Rotate(ctx, "k", []byte("three")); err == nil || !strings.Contains(err.Error(), "version 3 is current") {
			t.Fatalf("Rotate through a crash at the floor write: %v, want the committed-but-unrecorded error", err)
		}
		s.step = func(string) error { return nil }
		if f := floorOf(t, server)["k"]; f.Seq != 2 {
			t.Fatalf("floor after the crash = %+v, want sequence 2, one behind", f)
		}
		// One behind is accepted.
		mustCurrent(t, s, "k", "three")
		// Until a root verb raises it, the sequence-2 pointer is not refused:
		// that is the window the raise closes.
		copyFile(t, entryPath(server, "k", currentName), filepath.Join(server, "seq3"))
		copyFile(t, filepath.Join(server, "seq2"), entryPath(server, "k", currentName))
		mustCurrent(t, s, "k", "two")
		copyFile(t, filepath.Join(server, "seq3"), entryPath(server, "k", currentName))
		// Nothing raises the floor on read: a read verb calls RaiseFloor.
		mustCurrent(t, s, "k", "three")
		if _, err := s.List(ctx); err != nil {
			t.Fatal(err)
		}
		if f := floorOf(t, server)["k"]; f.Seq != 2 {
			t.Fatalf("floor after Current and List = %+v, want sequence 2: reads do not raise it", f)
		}
		if err := s.RaiseFloor(ctx); err != nil {
			t.Fatal(err)
		}
		if f := floorOf(t, server)["k"]; f.Seq != 3 {
			t.Fatalf("floor after RaiseFloor = %+v, want sequence 3", f)
		}
		copyFile(t, filepath.Join(server, "seq2"), entryPath(server, "k", currentName))
		var stale *staleError
		if _, _, err := s.Current(ctx, "k"); !errors.As(err, &stale) {
			t.Fatalf("Current over the sequence-2 pointer after the raise: %v, want the floor refusal", err)
		}
	})
	t.Run("a Put crash after the pointer", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		s.step = failAt("write " + floorName)
		if _, err := s.Put(ctx, "k", KindOpaque, []byte("one")); err == nil || !strings.Contains(err.Error(), "the entry is stored") {
			t.Fatalf("Put through a crash at the floor write: %v, want the stored-but-unrecorded error", err)
		}
		s.step = func(string) error { return nil }
		mustCurrent(t, s, "k", "one")
		if _, ok := floorOf(t, server)["k"]; ok {
			t.Fatal("the floor records a Put that crashed before its floor write")
		}
		// The start of the next mutating verb, here a Put of another name,
		// records it.
		mustPut(t, s, "b", KindOpaque, []byte("b"))
		if f := floorOf(t, server)["k"]; f.Seq != 1 || f.Generation != gen(t, server, "k") {
			t.Fatalf("floor after the next Put = %+v, want k at sequence 1", f)
		}
	})
	t.Run("an absent floor is rebuilt", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		mustPut(t, s, "b", KindOpaque, []byte("b"))
		mustRotate(t, s, "a", "a2")
		remove(t, floorPath(server))
		mustCurrent(t, s, "a", "a2")
		if err := s.RaiseFloor(ctx); err != nil {
			t.Fatal(err)
		}
		fl := floorOf(t, server)
		if fl["a"].Seq != 2 || fl["b"].Seq != 1 || len(fl) != 2 {
			t.Fatalf("rebuilt floor = %+v, want a at 2 and b at 1", fl)
		}
	})
	t.Run("Delete raises the others without the master", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		mustPut(t, s, "b", KindOpaque, []byte("b"))
		remove(t, filepath.Join(server, "cred", "keystore-master", masterName))
		if err := s.Delete(ctx, "a"); err != nil {
			t.Fatalf("Delete without the master: %v", err)
		}
		if fl := floorOf(t, server); len(fl) != 2 || fl["b"].Seq != 1 || fl["a"].Buried[0].Deleted != 1 {
			t.Fatalf("floor = %+v, want b live and a's tombstone", fl)
		}
	})
	t.Run("nothing to raise", func(t *testing.T) {
		s, server := newTestStore(t)
		if err := s.RaiseFloor(ctx); err != nil {
			t.Fatalf("RaiseFloor on a keystore that does not exist: %v", err)
		}
		if fl := floorOf(t, server); fl != nil {
			t.Fatalf("RaiseFloor wrote a floor for an empty keystore: %+v", fl)
		}
	})
}

// TestRotateCrashAtEveryStep is G8: Rotate writes the next version, then the
// pointer, then the floor, and a crash at any step before the pointer's
// rename leaves the old version current.
func TestRotateCrashAtEveryStep(t *testing.T) {
	ctx := context.Background()
	var steps []string
	{
		s, _ := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("one"))
		s.step = func(name string) error { steps = append(steps, name); return nil }
		mustRotate(t, s, "k", "two")
	}
	want := "write v2,write current,write " + floorName
	if strings.Join(steps, ",") != want {
		t.Fatalf("Rotate steps = %v, want %s", steps, want)
	}
	for _, step := range steps[:2] { // the floor write comes after the flip (TestFloorRaised)
		t.Run(step, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "k", KindOpaque, []byte("one"))
			s.step = failAt(step)
			if _, err := s.Rotate(ctx, "k", []byte("two")); err == nil {
				t.Fatal("Rotate succeeded through a crash")
			}
			s.step = func(string) error { return nil }
			mustCurrent(t, s, "k", "one")
			if _, _, err := s.Get(ctx, "k", 2); !errors.Is(err, ErrVersionNotFound) {
				t.Errorf("Get 2 after the crash: %v, want ErrVersionNotFound", err)
			}
			list, err := s.List(ctx)
			if err != nil || len(list) != 1 || list[0].Err != nil || list[0].Current.Version != 1 || len(list[0].Versions) != 1 {
				t.Errorf("List after the crash = %+v, %v; want k at version 1 of 1", list, err)
			}
			if f := floorOf(t, server)["k"]; f.Seq != 1 {
				t.Errorf("floor after the crash = %+v, want sequence 1", f)
			}
		})
	}
}

// TestRotateRetryDiscardsOrphan is G9: a Rotate interrupted after writing
// its version but before the flip leaves an orphan holding the value it was
// given; the retry discards it and seals its own value.
func TestRotateRetryDiscardsOrphan(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	s.step = failAt("write current")
	if _, err := s.Rotate(ctx, "k", []byte("A")); err == nil {
		t.Fatal("Rotate succeeded through a crash")
	}
	s.step = func(string) error { return nil }
	orphan, err := os.ReadFile(entryPath(server, "k", "v2"))
	if err != nil {
		t.Fatalf("the interrupted Rotate left no v2: %v", err)
	}
	// An orphan further out, as a second interrupted attempt could not leave
	// but a stray copy could, is discarded too.
	copyFile(t, entryPath(server, "k", "v2"), entryPath(server, "k", "v7"))

	v := mustRotate(t, s, "k", "B")
	if v.Version != 2 {
		t.Fatalf("retried Rotate made version %d, want 2", v.Version)
	}
	mustCurrent(t, s, "k", "B")
	if _, val, err := s.Get(ctx, "k", 2); err != nil || string(val) != "B" {
		t.Fatalf("Get 2 = %q, %v; want the retry's value B", val, err)
	}
	if now, err := os.ReadFile(entryPath(server, "k", "v2")); err != nil || bytes.Equal(now, orphan) {
		t.Fatalf("v2 still holds the orphan (%v)", err)
	}
	if _, err := os.Lstat(entryPath(server, "k", "v7")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v7 survived the retry: %v", err)
	}
	if f := floorOf(t, server)["k"]; f.Seq != 2 {
		t.Fatalf("floor = %+v, want sequence 2", f)
	}
}

func TestParseVersionName(t *testing.T) {
	for n, want := range map[string]uint64{"v1": 1, "v12": 12, "v18446744073709551615": 1<<64 - 1} {
		if v, ok := parseVersionName(n); !ok || v != want {
			t.Errorf("parseVersionName(%q) = %d, %v; want %d", n, v, ok, want)
		}
	}
	for _, n := range []string{"v0", "v01", "v", "v-1", "v+1", "current", "generation", "x1", "v18446744073709551616", ".v2.00.tmp"} {
		if v, ok := parseVersionName(n); ok {
			t.Errorf("parseVersionName(%q) = %d, want not a version", n, v)
		}
	}
}

// TestFloorCheck pins the rule a reader applies, case by case.
func TestFloorCheck(t *testing.T) {
	var g, other [generationSize]byte
	other[0] = 1
	hg := hex.EncodeToString(g[:])
	fl := floor{"k": {Generation: hg, Seq: 5}}
	for _, c := range []struct {
		name string
		gen  [generationSize]byte
		seq  uint64
		ok   bool
	}{
		{"k", g, 5, true}, {"k", g, 6, true}, {"k", g, 4, false}, {"k", other, 9, false}, {"absent", g, 1, true},
	} {
		if err := fl.check(c.name, c.gen, c.seq); (err == nil) != c.ok {
			t.Errorf("check(%s, seq %d) = %v, want ok=%v", c.name, c.seq, err, c.ok)
		}
	}
	if err := floor(nil).check("k", g, 1); err != nil {
		t.Errorf("an absent floor refused: %v", err)
	}
	if fl.raise("k", g, 4) || fl.raise("k", other, 9) || !fl.raise("k", g, 7) || fl["k"].Seq != 7 {
		t.Errorf("raise lowered, crossed a generation or did not raise: %+v", fl)
	}
}

// TestCommittedBeforeDecodesGeneration: the floor and the generation file are
// compared as generation bytes, not as text, so a generation file in
// upper-case hex, which every reader decodes to the same generation, is still
// the entry the floor records: one that lost its pointer, not an interrupted
// Put to discard.
func TestCommittedBeforeDecodesGeneration(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	b, err := os.ReadFile(entryPath(server, "a", generationName))
	if err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(string(b))
	if upper == string(b) {
		t.Fatalf("generation %q has no letter to upper-case; the test needs one", b)
	}
	writeFile(t, entryPath(server, "a", generationName), upper)
	mustCurrent(t, s, "a", "a")

	remove(t, entryPath(server, "a", currentName))
	if _, _, err := s.Current(ctx, "a"); !errors.Is(err, errLostPointer) {
		t.Fatalf("Current with the pointer gone: %v, want the lost-pointer refusal", err)
	}
	if _, err := s.Put(ctx, "a", KindOpaque, []byte("b")); !errors.Is(err, ErrExists) {
		t.Fatalf("Put over the lost pointer: %v, want ErrExists", err)
	}
}

// TestFloorScope: the floor file names the scope it belongs to, "system",
// and is parsed strictly: a missing or other scope, or any field the format
// does not have, is ErrCorrupt (errFloorMalformed), for the reads and the
// write verbs alike.
func TestFloorScope(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	b, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"scope":"system"`) {
		t.Fatalf("the floor file %s does not name the system scope", b)
	}
	fl := floorOf(t, server)
	k := fmt.Sprintf(`"entries":{"k":{"generation":%q,"seq":1}}`, fl["k"].Generation)
	for name, body := range map[string]string{
		"a missing scope":        `{"version":1,` + k + `}`,
		"a user scope":           `{"version":1,"scope":"user/501",` + k + `}`,
		"an empty scope":         `{"version":1,"scope":"",` + k + `}`,
		"an unknown field":       `{"version":1,"scope":"system",` + k + `,"extra":1}`,
		"an unknown entry field": `{"version":1,"scope":"system","entries":{"k":{"generation":"` + fl["k"].Generation + `","seq":1,"x":1}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			writeFile(t, floorPath(server), body)
			if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrCorrupt) || !errors.Is(err, errFloorMalformed) {
				t.Errorf("Current: %v, want ErrCorrupt (errFloorMalformed)", err)
			}
			if _, err := s.List(ctx); !errors.Is(err, ErrCorrupt) {
				t.Errorf("List: %v, want ErrCorrupt", err)
			}
			if _, err := s.Rotate(ctx, "k", []byte("w")); !errors.Is(err, ErrCorrupt) {
				t.Errorf("Rotate: %v, want ErrCorrupt", err)
			}
		})
	}
	t.Run("the system scope", func(t *testing.T) {
		writeFile(t, floorPath(server), `{"version":1,"scope":"system",`+k+`}`)
		mustCurrent(t, s, "k", "v")
	})
}

// TestFloorMalformedAdvice: a floor that does not parse is refused with
// advice that says what removing it costs, never a bare "delete the file":
// with no floor the stale-pointer check is off, the rebuild trusts whatever
// pointers are there, and every deleted entry, revoked keys included, is
// accepted again if put back.
func TestFloorMalformedAdvice(t *testing.T) {
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	writeFile(t, floorPath(server), "{")
	_, _, err := s.Current(context.Background(), "k")
	if !errors.Is(err, errFloorMalformed) {
		t.Fatalf("Current over a malformed floor: %v, want errFloorMalformed", err)
	}
	msg := err.Error()
	for _, want := range []string{"turns replay protection off", "known to be current", "rebuild", "discards every deletion the floor recorded", "a key revoked by deleting it included, is accepted again"} {
		if !strings.Contains(msg, want) {
			t.Errorf("malformed-floor advice %q does not say %q", msg, want)
		}
	}
	if strings.Contains(msg, "restore it from backup") {
		t.Errorf("malformed-floor advice %q carries ErrCorrupt's advice to restore from backup", msg)
	}
}
