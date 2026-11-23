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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// newTestStore returns a FileStore over a fresh server work dir, owned by the
// service user (serviceIDs), in a data root owned by the floor's owner
// (floorIDs), with the work dir path for tests that inspect the files.
func newTestStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	uid, gid := serviceIDs(t)
	data := t.TempDir()
	server := filepath.Join(data, "server")
	if err := os.Mkdir(server, 0o700); err != nil {
		t.Fatal(err)
	}
	giveToService(t, server)
	// keystore-logs/, root's 0755, as install makes it.
	if err := os.Mkdir(filepath.Join(data, logsDirName), logsDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(data, logsDirName), logsDirMode); err != nil {
		t.Fatal(err)
	}
	// Each log's own directory, root's 0755, as install makes it.
	for _, d := range []string{floorDirName, auditDirName} {
		p := filepath.Join(data, logsDirName, d)
		if err := os.Mkdir(p, logsDirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, logsDirMode); err != nil {
			t.Fatal(err)
		}
	}
	// The audit archives' directory, root's 0700, as install makes it.
	archives := filepath.Join(data, logsDirName, auditDirName, archivesDirName)
	if err := os.Mkdir(archives, archivesDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archives, archivesDirMode); err != nil {
		t.Fatal(err)
	}
	// Non-root, a test cannot create a root-owned file, so the test user
	// stands in for root as the floor's owner.
	floorUID, floorGID := floorIDs()
	s := New(Config{
		Dir:       filepath.Join(server, "keystore"),
		MasterDir: filepath.Join(server, "cred", "keystore-master"),
		UID:       uid,
		GID:       gid,
		DataRoot:  data,
		FloorUID:  floorUID,
		FloorGID:  floorGID,
	})
	s.userFloor, s.auditSink = &memFloor{}, &memAudit{}
	return s, server
}

func mustPut(t *testing.T, s *FileStore, name string, kind Kind, value []byte) Version {
	t.Helper()
	v, err := s.Put(context.Background(), name, kind, value)
	if err != nil {
		t.Fatalf("Put %s: %v", name, err)
	}
	return v
}

func TestPutCurrentGet(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	seed := bytes.Repeat([]byte{3}, ed25519.SeedSize)

	for _, tt := range []struct {
		name  string
		kind  Kind
		value []byte
	}{
		{"token", KindOpaque, []byte("s3cret\n")},
		{"signer", KindEd25519, seed},
		{"signer-expanded", KindEd25519, ed25519.NewKeyFromSeed(seed)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			put := mustPut(t, s, tt.name, tt.kind, tt.value)
			want := Version{Name: tt.name, Version: 1, Kind: tt.kind, Created: time.Unix(now.Unix(), 0).UTC(), Fingerprint: put.Fingerprint, identity: put.identity, digest: put.digest}
			if put != want || put.Fingerprint == "" || put.identity == ([identitySize]byte{}) {
				t.Fatalf("Put = %+v, want %+v", put, want)
			}
			if loc := put.Created.Location(); loc != time.UTC {
				t.Fatalf("Put Created is in %v, want UTC", loc)
			}
			cur, val, err := s.Current(ctx, tt.name)
			if err != nil || cur != put || !bytes.Equal(val, tt.value) {
				t.Fatalf("Current = %+v %q %v, want %+v %q", cur, val, err, put, tt.value)
			}
			got, val, err := s.Get(ctx, tt.name, 1)
			if err != nil || got != put || !bytes.Equal(val, tt.value) {
				t.Fatalf("Get 1 = %+v %q %v", got, val, err)
			}
			if loc := got.Created.Location(); loc != time.UTC {
				t.Fatalf("Get Created is in %v, want UTC", loc)
			}
			for _, v := range []uint64{0, 2} {
				if _, _, err := s.Get(ctx, tt.name, v); !errors.Is(err, ErrVersionNotFound) {
					t.Fatalf("Get %d: %v, want ErrVersionNotFound", v, err)
				}
			}
		})
	}
	a, _, errA := s.Current(ctx, "signer")
	b, _, errB := s.Current(ctx, "signer-expanded")
	if errA != nil || errB != nil || a.Fingerprint != b.Fingerprint {
		t.Fatalf("a seed and its expanded key: fingerprints %q, %q (%v, %v), want equal", a.Fingerprint, b.Fingerprint, errA, errB)
	}
}

func TestPutRefuses(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "dup", KindOpaque, []byte("d"))
	if _, err := s.Put(ctx, "dup", KindOpaque, []byte("e")); !errors.Is(err, ErrExists) {
		t.Fatalf("second Put: %v, want ErrExists", err)
	}
	for _, bad := range []string{"", "..", ".lock", "a/b", "Dup"} {
		if _, err := s.Put(ctx, bad, KindOpaque, []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Put %q: %v, want ErrInvalidName", bad, err)
		}
	}
	for _, tt := range []struct {
		kind  Kind
		value []byte
	}{{KindEd25519, []byte("short")}, {KindOpaque, nil}, {KindUnknown, []byte("x")}} {
		if _, err := s.Put(ctx, "v", tt.kind, tt.value); err == nil {
			t.Fatalf("Put %s %q succeeded", tt.kind, tt.value)
		}
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "v")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused value left an entry directory: %v", err)
	}
}

func TestNotFound(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	check := func(when string) {
		t.Helper()
		if _, _, err := s.Current(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: Current: %v, want ErrNotFound", when, err)
		}
		if _, _, err := s.Get(ctx, "nope", 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: Get: %v, want ErrNotFound", when, err)
		}
		if err := s.Delete(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: Delete: %v, want ErrNotFound", when, err)
		}
	}
	check("no keystore directory")
	if got, err := s.List(ctx); err != nil || len(got) != 0 {
		t.Fatalf("List with no keystore = %+v %v, want empty", got, err)
	}
	mustPut(t, s, "other", KindOpaque, []byte("o"))
	check("with another entry")
}

// TestDeleteThenPutRefusesReplayedRecord is gate row G4: after Delete and a
// new Put of the same name, the old entry's v1 restored over the new one
// fails to open, because the new entry has a new generation.
func TestDeleteThenPutRefusesReplayedRecord(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	v1 := filepath.Join(server, "keystore", "k", "v1")
	mustPut(t, s, "k", KindOpaque, []byte("old secret"))
	old, err := os.ReadFile(v1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	mustPut(t, s, "k", KindOpaque, []byte("new secret"))
	if err := os.WriteFile(v1, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, val, err := s.Current(ctx, "k"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Current over a replayed v1 = %q %v, want ErrCorrupt", val, err)
	}
	if _, val, err := s.Get(ctx, "k", 1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get 1 over a replayed v1 = %q %v, want ErrCorrupt", val, err)
	}
}

// TestRecordMovedBetweenEntries: a record copied into another entry is
// refused, whether its header still names its old place or was edited to
// name the new one (then the associated data refuses it).
func TestRecordMovedBetweenEntries(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "aa", KindOpaque, []byte("a value"))
	mustPut(t, s, "bb", KindOpaque, []byte("b value"))
	ks := filepath.Join(server, "keystore")
	moved, err := os.ReadFile(filepath.Join(ks, "aa", "v1"))
	if err != nil {
		t.Fatal(err)
	}
	gen, err := os.ReadFile(filepath.Join(ks, "bb", generationName))
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecord(moved)
	if err != nil {
		t.Fatal(err)
	}
	edited := r
	edited.name = "bb"
	if _, err := hex.Decode(edited.generation[:], bytes.TrimSuffix(gen, []byte("\n"))); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"as is": moved, "header edited": edited.marshal()} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(ks, "bb", "v1"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, val, err := s.Get(ctx, "bb", 1); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Get = %q %v, want ErrCorrupt", val, err)
			}
		})
	}
}

// TestMasterMint is gate row G10: the master is minted only by the first Put,
// from the store's entropy source, never over existing entries, and never
// from a caller's value.
func TestMasterMint(t *testing.T) {
	ctx := context.Background()
	master := func(server string) string { return filepath.Join(server, "cred", "keystore-master", masterName) }

	t.Run("the first put mints it, later puts keep it", func(t *testing.T) {
		s, server := newTestStore(t)
		if _, err := os.Lstat(filepath.Dir(master(server))); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("the master directory exists before the first Put")
		}
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		first, err := os.ReadFile(master(server))
		if err != nil || len(first) != masterSize {
			t.Fatalf("master after the first Put = %d bytes, %v", len(first), err)
		}
		mustPut(t, s, "b", KindOpaque, []byte("b"))
		if second, _ := os.ReadFile(master(server)); !bytes.Equal(first, second) {
			t.Fatal("a second Put replaced the master")
		}
	})

	t.Run("minted from the entropy source", func(t *testing.T) {
		s, server := newTestStore(t)
		want := bytes.Repeat([]byte{0xC3}, masterSize)
		s.rand = io.MultiReader(bytes.NewReader(want), rand.Reader)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		if got, _ := os.ReadFile(master(server)); !bytes.Equal(got, want) {
			t.Fatalf("master = %x, want the entropy source's first %d bytes", got, masterSize)
		}
	})

	t.Run("never over existing entries", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		if err := os.Remove(master(server)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); !errors.Is(err, ErrMasterMissing) {
			t.Fatalf("Put with entries and no master: %v, want ErrMasterMissing", err)
		}
		if _, _, err := s.Current(ctx, "a"); !errors.Is(err, ErrMasterMissing) {
			t.Fatalf("Current with no master: %v, want ErrMasterMissing", err)
		}
		if _, err := s.List(ctx); !errors.Is(err, ErrMasterMissing) {
			t.Fatalf("List with no master: %v, want ErrMasterMissing", err)
		}
		if _, err := os.Lstat(master(server)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("a master was minted over existing entries")
		}
	})

	t.Run("never over existing entries when the fingerprint is missing", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		before, err := os.ReadFile(master(server))
		if err != nil {
			t.Fatal(err)
		}
		fp := filepath.Join(filepath.Dir(master(server)), masterFingerprintName)
		remove(t, fp)
		// A sound master without its fingerprint is minted over only with
		// keystore/ empty; with an entry it is ErrMasterUntrusted.
		if _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); !errors.Is(err, ErrMasterUntrusted) || !errors.Is(err, errFingerprintMissing) {
			t.Fatalf("Put with entries and no fingerprint: %v, want ErrMasterUntrusted (fingerprint missing)", err)
		}
		if after, _ := os.ReadFile(master(server)); !bytes.Equal(after, before) {
			t.Fatal("a master was minted over existing entries")
		}
		if _, err := os.Lstat(fp); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the refused Put wrote a fingerprint: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(server, "keystore", "b")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the refused Put created its entry: %v", err)
		}
	})

	t.Run("an interrupted mint is minted again", func(t *testing.T) {
		s, server := newTestStore(t)
		s.step = failAt("write " + masterFingerprintName)
		if _, err := s.Put(ctx, "a", KindOpaque, []byte("a")); err == nil {
			t.Fatal("Put succeeded through a failed fingerprint write")
		}
		s.step = func(string) error { return nil }
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		if _, err := os.ReadFile(master(server)); err != nil {
			t.Fatal(err)
		}
	})

	// With no entries left, a master that fails a check of its own is still
	// refused, with or without its fingerprint file: only an absent master, or
	// a sound one missing its fingerprint, is minted over.
	for _, tt := range []struct {
		name   string
		damage func(t *testing.T, dir string)
	}{
		{"fingerprint mismatch", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, masterFingerprintName), strings.Repeat("0", 64)+"\n")
		}},
		{"mode 0644, no fingerprint", func(t *testing.T, dir string) {
			chmod(t, filepath.Join(dir, masterName), 0o644)
			remove(t, filepath.Join(dir, masterFingerprintName))
		}},
		{"short, no fingerprint", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, masterName), "short")
			remove(t, filepath.Join(dir, masterFingerprintName))
		}},
		{"symlink, no fingerprint", func(t *testing.T, dir string) {
			copyFile(t, filepath.Join(dir, masterName), filepath.Join(dir, "copy"))
			replaceWithSymlink(t, filepath.Join(dir, masterName), "copy")
			remove(t, filepath.Join(dir, masterFingerprintName))
		}},
	} {
		t.Run("not replaced: "+tt.name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			if err := s.Delete(ctx, "a"); err != nil {
				t.Fatal(err)
			}
			tt.damage(t, filepath.Dir(master(server)))
			before, _ := os.Lstat(master(server))
			if _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); !errors.Is(err, ErrMasterUntrusted) {
				t.Fatalf("Put over a damaged master: %v, want ErrMasterUntrusted", err)
			}
			if after, _ := os.Lstat(master(server)); !os.SameFile(before, after) {
				t.Fatal("a master that failed its check was replaced")
			}
		})
	}
}

// TestMasterTrust is gate row G11: the master is opened without following a
// symlink and judged on the open descriptor; a wrong mode, owner, size or
// fingerprint, or an untrusted directory, is ErrMasterUntrusted.
func TestMasterTrust(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		damage func(t *testing.T, s *FileStore, dir string)
	}{
		{"mode 0644", func(t *testing.T, _ *FileStore, dir string) { chmod(t, filepath.Join(dir, masterName), 0o644) }},
		{"mode 0400", func(t *testing.T, _ *FileStore, dir string) { chmod(t, filepath.Join(dir, masterName), 0o400) }},
		{"symlink to a valid copy", func(t *testing.T, _ *FileStore, dir string) {
			m := filepath.Join(dir, masterName)
			copyFile(t, m, filepath.Join(dir, "copy"))
			replaceWithSymlink(t, m, "copy")
		}},
		{"fingerprint mismatch", func(t *testing.T, _ *FileStore, dir string) {
			writeFile(t, filepath.Join(dir, masterFingerprintName), strings.Repeat("0", 64)+"\n")
		}},
		{"fingerprint missing", func(t *testing.T, _ *FileStore, dir string) { remove(t, filepath.Join(dir, masterFingerprintName)) }},
		// The fingerprint is rewritten to match, so only the size check can
		// refuse it.
		{"short, with a matching fingerprint", func(t *testing.T, _ *FileStore, dir string) {
			writeFile(t, filepath.Join(dir, masterName), "short")
			writeFile(t, filepath.Join(dir, masterFingerprintName), masterFingerprint([]byte("short")))
		}},
		{"directory mode 0755", func(t *testing.T, _ *FileStore, dir string) { chmod(t, dir, 0o755) }},
		{"cred mode 0755", func(t *testing.T, _ *FileStore, dir string) { chmod(t, filepath.Dir(dir), 0o755) }},
		{"master is a FIFO", func(t *testing.T, _ *FileStore, dir string) { replaceWithFIFO(t, filepath.Join(dir, masterName)) }},
		{"directory is a symlink", func(t *testing.T, _ *FileStore, dir string) {
			if err := os.Rename(dir, dir+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(dir)+".real", dir); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			tt.damage(t, s, filepath.Join(server, "cred", "keystore-master"))
			if _, _, err := within(t, func() (Version, []byte, error) { return s.Current(ctx, "a") }); !errors.Is(err, ErrMasterUntrusted) {
				t.Fatalf("Current: %v, want ErrMasterUntrusted", err)
			}
		})
	}

	// A test cannot give a file to another user, so the owner case judges the
	// master file alone: its directory is opened as the test user, and the
	// store that reads it expects another uid. Only the check on the file's
	// own descriptor can refuse it.
	t.Run("owner of the file", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		dir, err := os.OpenRoot(filepath.Join(server, "cred", "keystore-master"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = dir.Close() }()
		if _, err := s.readMaster(dir); err != nil {
			t.Fatalf("readMaster as the owner: %v", err)
		}
		other := *s
		other.uid++
		if _, err := other.readMaster(dir); !errors.Is(err, ErrMasterUntrusted) {
			t.Fatalf("readMaster as another uid: %v, want ErrMasterUntrusted", err)
		}
	})
}

// within runs fn and fails the test if it does not return within five
// seconds: a read that blocks (on a FIFO, say) must fail, not hang the suite.
// The bound is a watchdog that fires only when the test is already failing,
// so it cannot make a passing run flaky.
func within(t *testing.T, fn func() (Version, []byte, error)) (Version, []byte, error) {
	t.Helper()
	type result struct {
		v   Version
		val []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, val, err := fn()
		done <- result{v, val, err}
	}()
	watchdog, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case r := <-done:
		return r.v, r.val, r.err
	case <-watchdog.Done():
		t.Fatal("the read blocked for five seconds")
		return Version{}, nil, nil
	}
}

// TestFIFORefused is part of gate row G14 (never a hang): a FIFO planted at
// any file the store reads is refused at once, not waited on.
func TestFIFORefused(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"v1", currentName, generationName} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			replaceWithFIFO(t, filepath.Join(server, "keystore", "a", name))
			if _, _, err := within(t, func() (Version, []byte, error) { return s.Current(ctx, "a") }); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Current: %v, want ErrCorrupt", err)
			}
			_, _, err := within(t, func() (Version, []byte, error) {
				got, err := s.List(ctx)
				if err == nil && (len(got) != 1 || !errors.Is(got[0].Err, ErrCorrupt)) {
					err = fmt.Errorf("List = %+v, want the entry marked ErrCorrupt", got)
				}
				return Version{}, nil, err
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCredSymlinkRefused: a first Put does not follow cred/ through a symlink,
// so a root-run verb never creates the master directory outside the store.
func TestCredSymlinkRefused(t *testing.T) {
	s, server := newTestStore(t)
	outside := filepath.Join(filepath.Dir(server), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(server, "cred")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(context.Background(), "a", KindOpaque, []byte("a")); !errors.Is(err, ErrMasterUntrusted) {
		t.Fatalf("Put with cred/ a symlink: %v, want ErrMasterUntrusted", err)
	}
	if names, _ := os.ReadDir(outside); len(names) != 0 {
		t.Fatalf("the Put created %v outside the store", names)
	}
}

// TestDeleteCorruptEntry: an entry List marks corrupt can still be deleted,
// whatever inside it is damaged.
func TestDeleteCorruptEntry(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{generationName, "v1", currentName} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			writeFile(t, filepath.Join(server, "keystore", "a", name), "garbage")
			if got, err := s.List(ctx); err != nil || len(got) != 1 || got[0].Err == nil {
				t.Fatalf("List = %+v %v, want the entry marked", got, err)
			}
			if err := s.Delete(ctx, "a"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, _, err := s.Current(ctx, "a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Current after Delete: %v, want ErrNotFound", err)
			}
		})
	}
}

// TestDeletePlantedNonDirectory: a symlink or a regular file planted at an
// entry name is removed by Delete, unlinked without being followed, so the
// entry a symlink names is untouched.
func TestDeletePlantedNonDirectory(t *testing.T) {
	ctx := context.Background()
	for name, plant := range map[string]func(t *testing.T, p string){
		"symlink to another entry": func(t *testing.T, p string) {
			if err := os.Symlink("a", p); err != nil {
				t.Fatal(err)
			}
		},
		"regular file": func(t *testing.T, p string) { writeFile(t, p, "planted") },
	} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			ks := filepath.Join(server, "keystore")
			before := dirContents(t, filepath.Join(ks, "a"))
			p := filepath.Join(ks, "b")
			plant(t, p)
			if got, err := s.List(ctx); err != nil || len(got) != 2 || !errors.Is(got[1].Err, ErrCorrupt) {
				t.Fatalf("List = %+v %v, want b marked ErrCorrupt", got, err)
			}
			if err := s.Delete(ctx, "b"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("after Delete: %v, want the name gone", err)
			}
			if after := dirContents(t, filepath.Join(ks, "a")); !maps.Equal(after, before) {
				t.Fatalf("Delete changed the entry a symlink named: %q, was %q", after, before)
			}
			if _, val, err := s.Current(ctx, "a"); err != nil || string(val) != "a" {
				t.Fatalf("Current a = %q %v", val, err)
			}
		})
	}
}

// TestDeleteDirectoryAtCurrent: a non-empty directory planted at an entry's
// current is removed with the entry, not left to fail every retried Delete,
// and the entry's floor is removed with it, as a normal Delete removes it.
func TestDeleteDirectoryAtCurrent(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	cur := filepath.Join(server, "keystore", "a", currentName)
	remove(t, cur)
	if err := os.Mkdir(cur, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(cur, "x"), "planted")
	if _, ok := floorOf(t, server)["a"]; !ok {
		t.Fatal("no floor entry for a before Delete")
	}
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if f := floorOf(t, server)["a"]; len(f.burials()) == 0 {
		t.Fatalf("floor entry for a after Delete = %+v, want it replaced by a tombstone", f)
	}
	if _, err := os.Lstat(filepath.Join(server, "keystore", "a")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("entry directory after Delete: %v, want it gone", err)
	}
	if _, _, err := s.Current(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Current after Delete: %v, want ErrNotFound", err)
	}
}

// TestConfigRefused: a zero service uid, a negative FloorUID or FloorGID, an
// empty, relative or unclean Dir, MasterDir or DataRoot, or a MasterDir at or
// inside Dir makes every operation fail closed, before anything is created.
func TestConfigRefused(t *testing.T) {
	ctx := context.Background()
	for name, edit := range map[string]func(c *Config){
		"zero uid":                   func(c *Config) { c.UID = 0 },
		"negative FloorUID":          func(c *Config) { c.FloorUID = -1 },
		"negative FloorGID":          func(c *Config) { c.FloorGID = -1 },
		"empty Dir":                  func(c *Config) { c.Dir = "" },
		"empty MasterDir":            func(c *Config) { c.MasterDir = "" },
		"nothing set at all":         func(c *Config) { *c = Config{} },
		"Dir with a trailing /":      func(c *Config) { c.Dir += "/" },
		"relative MasterDir":         func(c *Config) { c.MasterDir = filepath.Join("cred", "keystore-master") },
		"MasterDir inside Dir":       func(c *Config) { c.MasterDir = filepath.Join(c.Dir, "keystore-master") },
		"MasterDir equal to Dir":     func(c *Config) { c.MasterDir = c.Dir },
		"relative Dir":               func(c *Config) { c.Dir = "keystore" },
		"MasterDir with a dot-dot":   func(c *Config) { c.MasterDir = filepath.Join(c.Dir, "..") + "/../server/cred/keystore-master" },
		"empty DataRoot":             func(c *Config) { c.DataRoot = "" },
		"relative DataRoot":          func(c *Config) { c.DataRoot = "data" },
		"DataRoot with a trailing /": func(c *Config) { c.DataRoot += "/" },
		"DataRoot with a dot-dot":    func(c *Config) { c.DataRoot = filepath.Join(c.Dir, "..", "..") + "/server/.." },
	} {
		t.Run(name, func(t *testing.T) {
			uid, gid := serviceIDs(t)
			server := filepath.Join(t.TempDir(), "server")
			if err := os.Mkdir(server, 0o700); err != nil {
				t.Fatal(err)
			}
			giveToService(t, server)
			// A relative path resolves inside server, where the check below
			// would see anything it created.
			t.Chdir(server)
			cfg := Config{
				Dir:       filepath.Join(server, "keystore"),
				MasterDir: filepath.Join(server, "cred", "keystore-master"),
				UID:       uid,
				GID:       gid,
				DataRoot:  filepath.Dir(server),
			}
			edit(&cfg)
			s := New(cfg)
			ops := map[string]error{}
			_, ops["Put"] = s.Put(ctx, "a", KindOpaque, []byte("a"))
			_, _, ops["Current"] = s.Current(ctx, "a")
			_, _, ops["Get"] = s.Get(ctx, "a", 1)
			_, ops["List"] = s.List(ctx)
			ops["Delete"] = s.Delete(ctx, "a")
			_, ops["Rotate"] = s.Rotate(ctx, "a", []byte("b"))
			ops["RaiseFloor"] = s.RaiseFloor(ctx)
			for op, err := range ops {
				if !errors.Is(err, errInvalidConfig) {
					t.Errorf("%s: %v, want errInvalidConfig", op, err)
				}
			}
			if names, _ := os.ReadDir(server); len(names) != 0 {
				t.Fatalf("created %v", names)
			}
		})
	}
}

// TestConfigRootFloorRefused: a process whose effective uid is 0, through the
// euid seam, refuses a store whose floor owner is not root, before anything
// is created; a non-root process accepts any non-negative owner, which is how
// a non-root test names itself.
func TestConfigRootFloorRefused(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name               string
		euid               int
		floorUID, floorGID int
		refused            bool
	}{
		{"root with a non-root floor uid", 0, 501, 0, true},
		{"root with a non-root floor gid", 0, 0, 20, true},
		{"root with a root floor", 0, 0, 0, false},
		{"non-root naming another owner", 501, 502, 20, false},
		{"non-root naming root", 501, 0, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := filepath.Join(t.TempDir(), "server")
			s := New(Config{
				Dir:       filepath.Join(server, "keystore"),
				MasterDir: filepath.Join(server, "cred", "keystore-master"),
				UID:       501,
				GID:       20,
				DataRoot:  filepath.Dir(server),
				FloorUID:  tt.floorUID,
				FloorGID:  tt.floorGID,
			})
			s.euid = func() int { return tt.euid }
			err := s.checkConfig()
			if got := errors.Is(err, errInvalidConfig); got != tt.refused {
				t.Fatalf("checkConfig: %v, want refused %v", err, tt.refused)
			}
			if !tt.refused {
				return
			}
			ops := map[string]error{}
			_, ops["Put"] = s.Put(ctx, "a", KindOpaque, []byte("a"))
			_, _, ops["Current"] = s.Current(ctx, "a")
			_, ops["List"] = s.List(ctx)
			ops["Delete"] = s.Delete(ctx, "a")
			_, ops["Rotate"] = s.Rotate(ctx, "a", []byte("b"))
			ops["RaiseFloor"] = s.RaiseFloor(ctx)
			ops["Rewrap"] = s.Rewrap(ctx, make([]byte, 32))
			for op, err := range ops {
				if !errors.Is(err, errInvalidConfig) || !strings.Contains(err.Error(), "must be root") {
					t.Errorf("%s: %v, want errInvalidConfig naming root's floor", op, err)
				}
			}
			if _, err := os.Stat(server); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the refused store created %s: %v", server, err)
			}
		})
	}
}

// TestReadErrorIsNotCorrupt: a file that cannot be read for want of
// permission is reported as that, not as ErrCorrupt, whose fix (restore from
// backup) would be the wrong one.
func TestReadErrorIsNotCorrupt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 file")
	}
	ctx := context.Background()
	for _, name := range []string{"v1", currentName, generationName} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "a", KindOpaque, []byte("a"))
			p := filepath.Join(server, "keystore", "a", name)
			chmod(t, p, 0)
			t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
			_, _, err := s.Current(ctx, "a")
			if err == nil || errors.Is(err, ErrCorrupt) || !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("Current: %v, want a permission error that is not ErrCorrupt", err)
			}
		})
	}
}

// TestLockBoundedWait is gate row G14: a held lock gives a timeout error
// after the bound, never a hang, and a cancelled context ends the wait, for
// every verb that takes it, Rotate and Rewrap included.
//
// Each case runs in a testing/synctest bubble, whose clock moves only while
// every goroutine in it is blocked, so the store waits its production bound
// (lockTimeout) in bubble time, at once, and no assertion reads the wall
// clock. A wait that never ended would show as the bubble's deadlock panic or
// the test binary's timeout.
func TestLockBoundedWait(t *testing.T) {
	setup := func(t *testing.T) (*FileStore, string) {
		t.Helper()
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		if s.lockWait != lockTimeout {
			t.Fatalf("lockWait = %v, want the production bound %v", s.lockWait, lockTimeout)
		}
		return s, server
	}
	hold := func(t *testing.T, server string, how int) {
		t.Helper()
		f, err := os.OpenFile(filepath.Join(server, "keystore", lockName), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if err := syscall.Flock(int(f.Fd()), how); err != nil {
			t.Fatal(err)
		}
	}
	// bounded checks fn gives errLockTimeout once the bound has passed, and
	// not before, in bubble time.
	bounded := func(t *testing.T, s *FileStore, op string, fn func() error) {
		t.Helper()
		start := time.Now()
		err := fn()
		if took := time.Since(start); !errors.Is(err, errLockTimeout) || took < s.lockWait || took > s.lockWait+time.Second {
			t.Fatalf("%s under a held lock: %v after %v of bubble time, want errLockTimeout after %v", op, err, took, s.lockWait)
		}
	}

	t.Run("exclusive holder blocks reads and writes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := t.Context()
			s, server := setup(t)
			hold(t, server, syscall.LOCK_EX)
			bounded(t, s, "Put", func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err })
			bounded(t, s, "Current", func() error { _, _, err := s.Current(ctx, "a"); return err })
			bounded(t, s, "List", func() error { _, err := s.List(ctx); return err })
			bounded(t, s, "Delete", func() error { return s.Delete(ctx, "a") })
			bounded(t, s, "Rotate", func() error { _, err := s.Rotate(ctx, "a", []byte("b")); return err })
			bounded(t, s, "Rewrap", func() error { return s.Rewrap(ctx, rewrapKey(1)) })
		})
	})
	t.Run("shared holder blocks only writes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := t.Context()
			s, server := setup(t)
			hold(t, server, syscall.LOCK_SH)
			bounded(t, s, "Put", func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err })
			bounded(t, s, "Rotate", func() error { _, err := s.Rotate(ctx, "a", []byte("b")); return err })
			bounded(t, s, "Rewrap", func() error { return s.Rewrap(ctx, rewrapKey(1)) })
			if _, _, err := s.Current(ctx, "a"); err != nil {
				t.Fatalf("Current under a shared lock: %v", err)
			}
		})
	})
	t.Run("a cancelled context ends the wait", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, server := setup(t)
			hold(t, server, syscall.LOCK_EX)
			s.lockWait = time.Minute
			for op, fn := range map[string]func(ctx context.Context) error{
				"Put":    func(ctx context.Context) error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err },
				"Rotate": func(ctx context.Context) error { _, err := s.Rotate(ctx, "a", []byte("b")); return err },
				"Rewrap": func(ctx context.Context) error { return s.Rewrap(ctx, rewrapKey(1)) },
			} {
				cctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				start := time.Now()
				err := fn(cctx)
				took := time.Since(start)
				cancel()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("%s: %v, want the context's error", op, err)
				}
				if took >= s.lockWait {
					t.Fatalf("%s waited %v of bubble time, want the context's 50ms, not the lock bound", op, took)
				}
			}
		})
	})
}

// TestDirectoryOwnerRefused: the store's directories must be owned by the
// service uid. A store whose uid differs from the owner, as a chown that did
// not take leaves (the chown seam does nothing), refuses the directory rather
// than use it, on a read and on a first Put.
func TestDirectoryOwnerRefused(t *testing.T) {
	ctx := context.Background()
	other := otherUID(t)
	noChown := func(*os.File, int, int) error { return nil }

	s, _ := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	foreign := New(Config{Dir: s.dir, MasterDir: s.masterDir, UID: other, GID: s.gid, DataRoot: s.dataRoot, FloorUID: s.floorUID, FloorGID: s.floorGID})
	foreign.chown = noChown
	// The existing directories were handed to the service user; the fresh
	// store's first directory stays its creator's, the running user's.
	want := fmt.Sprintf("owned by uid %d, want %d", s.uid, other)
	if _, _, err := foreign.Current(ctx, "a"); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Current: %v, want a refusal %q", err, want)
	}
	if _, err := foreign.List(ctx); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("List: %v, want a refusal %q", err, want)
	}

	fresh, freshServer := newTestStore(t)
	fresh.uid = other
	fresh.chown = noChown
	want = fmt.Sprintf("owned by uid %d, want %d", os.Geteuid(), other)
	if _, err := fresh.Put(ctx, "a", KindOpaque, []byte("a")); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("first Put: %v, want a refusal %q", err, want)
	}
	if _, err := os.Lstat(filepath.Join(freshServer, "cred")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the refused Put went on to create cred/: %v", err)
	}
}

// TestLockExcludes is part of gate row G14: two operations that overlap
// do not interleave. A Put is held at its v1 write, inside the exclusive
// lock; a Current started then waits, in a synctest bubble's time, for as long
// as the Put holds it, and reads the committed entry once the Put releases.
func TestLockExcludes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		s, _ := newTestStore(t)
		mustPut(t, s, "seed", KindOpaque, []byte("seed"))
		entered, release := make(chan struct{}), make(chan struct{})
		s.step = func(name string) error {
			if name == "write v1" {
				close(entered)
				<-release
			}
			return nil
		}
		putDone := make(chan error, 1)
		go func() {
			_, err := s.Put(ctx, "a", KindOpaque, []byte("a"))
			putDone <- err
		}()
		<-entered

		type read struct {
			val []byte
			err error
		}
		readDone := make(chan read, 1)
		go func() {
			_, val, err := s.Current(ctx, "a")
			readDone <- read{val, err}
		}()
		// Half the lock bound passes in bubble time, so the reader retries
		// throughout it; synctest.Wait then returns once the reader is durably
		// blocked in its next retry wait, and it must not have run.
		held := time.NewTimer(s.lockWait / 2)
		<-held.C
		synctest.Wait()
		select {
		case r := <-readDone:
			t.Fatalf("Current ran while the Put held the lock: %q %v", r.val, r.err)
		default:
		}

		close(release)
		if err := <-putDone; err != nil {
			t.Fatalf("Put: %v", err)
		}
		if r := <-readDone; r.err != nil || string(r.val) != "a" {
			t.Fatalf("Current after the Put released = %q %v, want the committed value", r.val, r.err)
		}
	})
}

// TestConcurrentOperations runs writers and readers together under -race;
// the lock serialises them and every write lands.
//
// The entries' directory is made first: it is created before the lock can be
// taken, and a new directory must be empty before it is handed over, so two
// first operations racing to create it, running as the service user as the
// tests do, can find each other's lock file in it. Root creating it is not
// exposed: another process cannot open it until it is handed over.
func TestConcurrentOperations(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	if err := s.mkdirOwned(filepath.Join(server, "keystore")); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, 3*n)
	for i := range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := s.Put(ctx, fmt.Sprintf("k%d", i), KindOpaque, []byte{byte(i)})
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, err := s.List(ctx)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List(ctx)
	if err != nil || len(got) != n {
		t.Fatalf("List = %d entries, %v; want %d", len(got), err, n)
	}
}

// TestOwnership is gate row G15: every file and directory the store creates
// is handed to the service user, on its descriptor, at the layout's modes.
func TestOwnership(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	var (
		mu        sync.Mutex
		owned     []os.FileInfo
		lockOwned bool
	)
	s.chown = func(f *os.File, uid, gid int) error {
		// The floor and its lock, keystore-lock, both in the data root, are
		// the files handed to their own owner, root (floorIDs), rather than
		// the service user.
		wantUID, wantGID := int(s.uid), int(s.gid)
		base := filepath.Base(f.Name())
		if strings.Contains(base, floorName) || base == floorLockName {
			wantUID, wantGID = s.floorUID, s.floorGID
		}
		if base == floorLockName && uid == wantUID && gid == wantGID {
			mu.Lock()
			lockOwned = true
			mu.Unlock()
		}
		if uid != int(wantUID) || gid != int(wantGID) {
			return fmt.Errorf("chown to %d:%d, want %d:%d", uid, gid, wantUID, wantGID)
		}
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		mu.Lock()
		owned = append(owned, fi)
		mu.Unlock()
		return f.Chown(uid, gid)
	}
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	mustPut(t, s, "b", KindEd25519, bytes.Repeat([]byte{1}, ed25519.SeedSize))
	if err := s.Delete(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatal(err)
	}

	var seen int
	for _, top := range []string{filepath.Join(server, "cred"), filepath.Join(server, "keystore")} {
		err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			seen++
			want := fileMode
			if fi.IsDir() {
				want = dirMode
			}
			if fi.Mode().Perm() != want || !(fi.IsDir() || fi.Mode().IsRegular()) {
				t.Errorf("%s: mode %s, want %04o", p, fi.Mode(), want)
			}
			if st := fi.Sys().(*syscall.Stat_t); st.Uid != s.uid || st.Gid != s.gid {
				t.Errorf("%s: owner %d:%d, want %d:%d", p, st.Uid, st.Gid, s.uid, s.gid)
			}
			for _, o := range owned {
				if os.SameFile(o, fi) {
					return nil
				}
			}
			t.Errorf("%s was never handed to the service user", p)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !lockOwned {
		t.Errorf("%s was never handed to the floor's owner %d:%d", floorLockName, s.floorUID, s.floorGID)
	}
	// cred, keystore-master, master, master.sha256, keystore, .lock, a,
	// a/generation, a/v1, a/current.
	if seen != 10 {
		t.Fatalf("walked %d paths, want 10", seen)
	}
}

// TestListMarksCorruptEntry is the library half of gate row G16: List returns
// every entry, marks one that cannot be opened with Err (and nothing else),
// and leaves the healthy ones intact.
func TestListMarksCorruptEntry(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	for _, n := range []string{"aa", "bb", "cc", "dd"} {
		mustPut(t, s, n, KindOpaque, []byte(n))
	}
	ks := filepath.Join(server, "keystore")
	flipLastByte(t, filepath.Join(ks, "bb", currentName))
	flipLastByte(t, filepath.Join(ks, "cc", "v1"))
	writeFile(t, filepath.Join(ks, "dd", generationName), "not hex\n")
	// An interrupted Put and a stray directory are not entries.
	if err := os.Mkdir(filepath.Join(ks, "ee"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(ks, "Stray"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var names []string
	for _, e := range got {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "aa,bb,cc,dd" {
		t.Fatalf("List names = %v, want aa,bb,cc,dd", names)
	}
	if e := got[0]; e.Err != nil || e.Current.Version != 1 || len(e.Versions) != 1 || e.Current != e.Versions[0] {
		t.Fatalf("healthy entry = %+v", e)
	}
	for _, e := range got[1:] {
		if !errors.Is(e.Err, ErrCorrupt) || e.Current != (Version{}) || e.Versions != nil {
			t.Fatalf("corrupt entry %s = %+v, want only Err (ErrCorrupt)", e.Name, e)
		}
	}
}

// TestPointerVersionBound: a pointer that authenticates but names a version
// past maxVersion is ErrCorrupt on its own entry, never an allocation sized by
// it, and List still returns the healthy entries.
func TestPointerVersionBound(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "aa", KindOpaque, []byte("a"))
	mustPut(t, s, "bb", KindOpaque, []byte("b"))
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(server, "keystore", "bb")
	gen, err := os.ReadFile(filepath.Join(dir, generationName))
	if err != nil {
		t.Fatal(err)
	}
	ptr := record{kind: kindPointer, name: "bb", created: 1}
	if _, err := hex.Decode(ptr.generation[:], bytes.TrimSpace(gen)); err != nil {
		t.Fatal(err)
	}
	if err := ptr.seal(k.seal, k.scope, pointerPlaintext(1<<62, 1), rand.Reader); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, currentName), string(ptr.marshal()))

	got, err := s.List(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("List = %+v %v, want both entries", got, err)
	}
	if e := got[0]; e.Name != "aa" || e.Err != nil || e.Current.Version != 1 {
		t.Fatalf("healthy entry = %+v", e)
	}
	if e := got[1]; e.Name != "bb" || !errors.Is(e.Err, ErrCorrupt) || e.Versions != nil {
		t.Fatalf("entry with a pointer past maxVersion = %+v, want only Err (ErrCorrupt)", e)
	}
	if _, _, err := s.Current(ctx, "bb"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Current: %v, want ErrCorrupt", err)
	}
	if _, _, err := s.Get(ctx, "bb", 1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get 1: %v, want ErrCorrupt", err)
	}
}

// TestReadDirNamesBound: a directory is listed in batches, whole up to the
// limit, and one holding more names than the limit fails closed.
func TestReadDirNamesBound(t *testing.T) {
	dir := t.TempDir()
	const n = 2*dirBatch + 3 // past two batch boundaries
	for i := range n {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("f%d", i)), "")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if names, err := readDirNames(root, n); err != nil || len(names) != n {
		t.Fatalf("readDirNames at the limit = %d names, %v; want %d", len(names), err, n)
	}
	for _, max := range []int{n - 1, dirBatch, 1} {
		if names, err := readDirNames(root, max); err == nil || names != nil {
			t.Fatalf("readDirNames with %d names over a limit of %d = %d names, %v; want an error", n, max, len(names), err)
		}
	}
}

// TestScopeBindsRecords: a record sealed by the system store does not open
// in a store of another scope over the same files and master, and a store
// whose scope checkScope refuses fails closed, creating nothing.
func TestScopeBindsRecords(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	// The test-only seam: a second store over the same directories, under a
	// scope New does not construct.
	u501 := New(Config{Dir: s.dir, MasterDir: s.masterDir, UID: s.uid, GID: s.gid, DataRoot: s.dataRoot, FloorUID: s.floorUID, FloorGID: s.floorGID})
	u501.scope = "user/501"
	if _, _, err := u501.Current(ctx, "a"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Current under user/501: %v, want ErrCorrupt", err)
	}
	if got, err := u501.List(ctx); err != nil || len(got) != 1 || !errors.Is(got[0].Err, ErrCorrupt) {
		t.Fatalf("List under user/501 = %+v %v, want the entry marked ErrCorrupt", got, err)
	}
	if _, val, err := s.Current(ctx, "a"); err != nil || string(val) != "a" {
		t.Fatalf("Current under system = %q %v", val, err)
	}

	bad, badServer := newTestStore(t)
	bad.scope = "user"
	if _, err := bad.Put(ctx, "a", KindOpaque, []byte("a")); !errors.Is(err, errInvalidScope) {
		t.Fatalf("Put under an invalid scope: %v, want errInvalidScope", err)
	}
	if _, err := os.Lstat(filepath.Join(badServer, "cred")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a Put under an invalid scope created cred/: %v", err)
	}
}

// TestMintCountsReservedUserName: ".user" in the entries' directory, the name
// reserved for user scopes, counts as an entry for the first-Put mint guard,
// whatever its type, so a Put with the master missing returns ErrMasterMissing
// and mints nothing.
func TestMintCountsReservedUserName(t *testing.T) {
	for name, plant := range map[string]func(t *testing.T, p string){
		"directory": func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"file": func(t *testing.T, p string) { writeFile(t, p, "") },
		"symlink": func(t *testing.T, p string) {
			if err := os.Symlink("nowhere", p); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			ks := filepath.Join(server, "keystore")
			if err := os.Mkdir(ks, 0o700); err != nil {
				t.Fatal(err)
			}
			plant(t, filepath.Join(ks, userScopesName))
			giveToService(t, ks, filepath.Join(ks, userScopesName))
			if _, err := s.Put(context.Background(), "a", KindOpaque, []byte("a")); !errors.Is(err, ErrMasterMissing) {
				t.Fatalf("Put with only %s present: %v, want ErrMasterMissing", userScopesName, err)
			}
			if _, err := os.Lstat(filepath.Join(server, "cred", "keystore-master", masterName)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the Put minted a master: %v", err)
			}
		})
	}
}

// TestEntryWithNoPointer: a directory with no current pointer is an
// interrupted Put only when it holds generation and at most v1 (temporary
// files aside). Anything more is damage: List reports it, Put refuses it and
// touches nothing, and Delete clears it.
func TestEntryWithNoPointer(t *testing.T) {
	ctx := context.Background()
	// setup stores "a" and then leaves its directory in the shape under test.
	// A Put that crashed before its pointer never recorded a floor, so the
	// interrupted-put cases also take "a" out of the floor; the cases where a
	// committed entry lost its pointer keep it.
	setup := func(t *testing.T, shape func(dir string)) (*FileStore, string) {
		t.Helper()
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("old"))
		dir := filepath.Join(server, "keystore", "a")
		remove(t, filepath.Join(dir, currentName))
		shape(dir)
		return s, dir
	}
	unrecorded := func(dir string) {
		writeFile(t, filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(dir))), floorName), `{"version":1,"scope":"system","entries":{}}`)
	}
	files := func(t *testing.T, dir string) string {
		t.Helper()
		des, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, de := range des {
			names = append(names, de.Name())
		}
		return strings.Join(names, ",")
	}

	for name, shape := range map[string]func(dir string){
		"generation and v1": unrecorded,
		"generation only":   func(dir string) { remove(t, filepath.Join(dir, "v1")); unrecorded(dir) },
		"empty":             func(dir string) { remove(t, filepath.Join(dir, "v1")); remove(t, filepath.Join(dir, generationName)) },
		"a leftover temporary file": func(dir string) {
			writeFile(t, filepath.Join(dir, "."+currentName+".0123456789abcdef.tmp"), "half a write")
			unrecorded(dir)
		},
		"generation and a temporary file, as a crash while writing v1 leaves": func(dir string) {
			remove(t, filepath.Join(dir, "v1"))
			writeFile(t, filepath.Join(dir, ".v1.0123456789abcdef.tmp"), "half a write")
			unrecorded(dir)
		},
		// Without a floor file the two cannot be told apart, and the rule
		// falls back to the shape.
		"no floor file": func(dir string) {
			remove(t, filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(dir))), floorName))
		},
		// A floor of another generation is what an interrupted Delete leaves
		// for the name before the Put that crashed here.
		"a floor of another generation": func(dir string) {
			writeFile(t, filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(dir))), floorName),
				`{"version":1,"scope":"system","entries":{"a":{"generation":"00000000000000000000000000000000","seq":3}}}`)
		},
	} {
		t.Run("interrupted put: "+name, func(t *testing.T) {
			s, dir := setup(t, shape)
			if got, err := s.List(ctx); err != nil || len(got) != 0 {
				t.Fatalf("List = %+v %v, want no entry", got, err)
			}
			if _, _, err := s.Current(ctx, "a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Current: %v, want ErrNotFound", err)
			}
			if _, _, err := s.Get(ctx, "a", 1); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get: %v, want ErrNotFound", err)
			}
			// Delete removes the directory, which may hold a sealed v1. With
			// no live record for the name it answers ErrNotFound, since there
			// is no entry; a live record (an interrupted Delete's, or one whose
			// directory a decoy replaced) it buries, and succeeds.
			server := filepath.Dir(filepath.Dir(dir))
			live := floorOf(t, server)["a"]
			err := s.Delete(ctx, "a")
			switch {
			case live.live() && err != nil:
				t.Fatalf("Delete over a live record: %v, want it buried", err)
			case live.live() && !floorOf(t, server)["a"].buries(live.Generation):
				t.Fatalf("floor a after Delete = %+v, want %s buried", floorOf(t, server)["a"], live.Generation)
			case !live.live() && !errors.Is(err, ErrNotFound):
				t.Fatalf("Delete: %v, want ErrNotFound", err)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("directory after Delete: %v, want it gone", err)
			}
			mustPut(t, s, "a", KindOpaque, []byte("new"))
			if _, val, err := s.Current(ctx, "a"); err != nil || string(val) != "new" {
				t.Fatalf("Current after the Put = %q %v, want the new value", val, err)
			}
		})
	}

	for name, shape := range map[string]func(dir string){
		"v1 and v2": func(dir string) { copyFile(t, filepath.Join(dir, "v1"), filepath.Join(dir, "v2")) },
		"v1 without generation": func(dir string) {
			remove(t, filepath.Join(dir, generationName))
		},
		"v2 without v1": func(dir string) {
			copyFile(t, filepath.Join(dir, "v1"), filepath.Join(dir, "v2"))
			remove(t, filepath.Join(dir, "v1"))
		},
		// The floor records this generation, so the pointer was committed:
		// the one-version entry that lost it is told apart from a crashed Put.
		"lost pointer, generation and v1": func(string) {},
		"lost pointer, generation only":   func(dir string) { remove(t, filepath.Join(dir, "v1")) },
		"lost pointer, renamed to a temporary name": func(dir string) {
			writeFile(t, filepath.Join(dir, "."+currentName+".0123456789abcdef.tmp"), "the old pointer")
		},
		// Only a regular file of the exact shape writeFile creates is a
		// temporary file.
		"a directory named like a temporary file": func(dir string) {
			if err := os.Mkdir(filepath.Join(dir, "."+currentName+".0123456789abcdef.tmp"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink named like a temporary file": func(dir string) {
			if err := os.Symlink("v1", filepath.Join(dir, "."+currentName+".0123456789abcdef.tmp")); err != nil {
				t.Fatal(err)
			}
		},
		"a dot file that is not the writer's shape": func(dir string) {
			writeFile(t, filepath.Join(dir, ".x.tmp"), "x")
		},
	} {
		t.Run("damage: "+name, func(t *testing.T) {
			s, dir := setup(t, shape)
			before := files(t, dir)

			got, err := s.List(ctx)
			if err != nil || len(got) != 1 || got[0].Name != "a" {
				t.Fatalf("List = %+v %v, want the entry returned", got, err)
			}
			if e := got[0]; !errors.Is(e.Err, ErrCorrupt) || e.Current != (Version{}) || e.Versions != nil {
				t.Fatalf("entry = %+v, want only Err (ErrCorrupt)", e)
			}
			if _, _, err := s.Current(ctx, "a"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Current: %v, want ErrCorrupt", err)
			}
			if _, _, err := s.Get(ctx, "a", 1); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Get: %v, want ErrCorrupt", err)
			}
			if _, err := s.Put(ctx, "a", KindOpaque, []byte("new")); !errors.Is(err, ErrExists) {
				t.Fatalf("Put: %v, want ErrExists", err)
			}
			if after := files(t, dir); after != before {
				t.Fatalf("Put changed the directory: %s, was %s", after, before)
			}

			if err := s.Delete(ctx, "a"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("directory after Delete: %v, want it gone", err)
			}
			mustPut(t, s, "a", KindOpaque, []byte("new"))
		})
	}
}

// TestMkdirSyncsParent: every directory a Put creates has its parent fsynced
// before its own step, so a power loss cannot keep what is written under it
// while losing its name; and a failed parent fsync fails the Put there, with
// that directory's step never reached and nothing written after it.
func TestMkdirSyncsParent(t *testing.T) {
	ctx := context.Background()
	// parentOf maps each directory a first Put creates to its parent.
	parentOf := map[string]string{"keystore": "server", "cred": "server", "keystore-master": "cred", "k": "keystore"}
	t.Run("order", func(t *testing.T) {
		var events []string
		setSyncDir(t, func(root *os.Root) error {
			events = append(events, "fsync "+filepath.Base(root.Name()))
			return fsyncDir(root)
		})
		s, _ := newTestStore(t)
		s.step = func(name string) error { events = append(events, name); return nil }
		mustPut(t, s, "k", KindOpaque, []byte("x"))
		seen := 0
		for i, ev := range events {
			dir, ok := strings.CutPrefix(ev, "mkdir ")
			if !ok {
				continue
			}
			seen++
			if want := "fsync " + parentOf[dir]; i == 0 || events[i-1] != want {
				t.Errorf("%s not directly after %s: %v", ev, want, events)
			}
		}
		if seen != len(parentOf) {
			t.Fatalf("saw %d mkdir steps, want %d: %v", seen, len(parentOf), events)
		}
	})
	// Each case fails the nth fsync of the parent, the one that precedes dir.
	for _, tc := range []struct {
		dir string
		nth int
	}{{"keystore", 1}, {"cred", 2}, {"keystore-master", 1}, {"k", 1}} {
		t.Run("fail before "+tc.dir, func(t *testing.T) {
			parent := parentOf[tc.dir]
			n := 0
			setSyncDir(t, func(root *os.Root) error {
				if filepath.Base(root.Name()) == parent {
					if n++; n == tc.nth {
						return errors.New("injected fsync failure")
					}
				}
				return fsyncDir(root)
			})
			s, _ := newTestStore(t)
			var steps []string
			s.step = func(name string) error { steps = append(steps, name); return nil }
			v, err := s.Put(ctx, "k", KindOpaque, []byte("x"))
			if err == nil || !strings.Contains(err.Error(), "injected fsync failure") || v != (Version{}) {
				t.Fatalf("Put = %+v %v, want the injected fsync failure and no version", v, err)
			}
			if slices.Contains(steps, "mkdir "+tc.dir) {
				t.Fatalf("steps %v reached mkdir %s past its failed parent fsync", steps, tc.dir)
			}
			if slices.Contains(steps, "write current") {
				t.Fatalf("steps %v went on to write the pointer", steps)
			}
			setSyncDir(t, fsyncDir)
			if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Current after the failed Put: %v, want ErrNotFound", err)
			}
			if got, err := s.List(ctx); err != nil || len(got) != 0 {
				t.Fatalf("List after the failed Put = %+v %v, want no entry", got, err)
			}
			mustPut(t, s, "k", KindOpaque, []byte("retried"))
		})
	}
}

// setSyncDir replaces the syncDir seam for the rest of t.
func setSyncDir(t *testing.T, fn func(*os.Root) error) {
	t.Helper()
	old := syncDir
	syncDir = fn
	t.Cleanup(func() { syncDir = old })
}

// TestPutCrashAtEveryStep injects a crash at each durable step of a Put, then
// checks the name is not an entry and a retried Put stores the retried value.
func TestPutCrashAtEveryStep(t *testing.T) {
	ctx := context.Background()
	var steps []string
	{
		s, _ := newTestStore(t)
		s.step = func(name string) error { steps = append(steps, name); return nil }
		mustPut(t, s, "k", KindOpaque, []byte("x"))
	}
	// The steps come in this order, each directory's mkdir before anything
	// written into it; that each parent is fsynced before its directory's
	// step is TestMkdirSyncsParent's to check.
	want := "mkdir keystore,mkdir cred,mkdir keystore-master,write master,write master.sha256,mkdir k,write generation,write v1,write current,sync current,write keystore-floor.json"
	if strings.Join(steps, ",") != want {
		t.Fatalf("Put steps = %v, want %s", steps, want)
	}
	// What a reader sees after a crash at each step. The entry is never there
	// before its pointer is, and Current opens the entry before the master,
	// so every step reads as ErrNotFound and none as ErrMasterMissing.
	afterCrash := map[string]error{
		"mkdir keystore":        ErrNotFound,
		"mkdir cred":            ErrNotFound,
		"mkdir keystore-master": ErrNotFound,
		"write master":          ErrNotFound,
		"write master.sha256":   ErrNotFound,
		"mkdir k":               ErrNotFound,
		"write generation":      ErrNotFound,
		"write v1":              ErrNotFound,
		"write current":         ErrNotFound,
	}
	others := []error{ErrMasterMissing, ErrMasterUntrusted, ErrCorrupt, ErrExists}
	for _, step := range steps {
		if step == "sync current" || step == "write "+floorName {
			continue // after the pointer: the entry is committed (TestCommitPointReported)
		}
		t.Run(step, func(t *testing.T) {
			want, ok := afterCrash[step]
			if !ok {
				t.Fatalf("no expected error for step %q", step)
			}
			s, _ := newTestStore(t)
			s.step = failAt(step)
			if _, err := s.Put(ctx, "k", KindOpaque, []byte("first")); err == nil || !strings.Contains(err.Error(), "injected crash at "+step) {
				t.Fatalf("Put through a crash at %s: %v, want the injected crash", step, err)
			}
			s.step = func(string) error { return nil }
			_, _, err := s.Current(ctx, "k")
			if !errors.Is(err, want) {
				t.Fatalf("Current after the crash: %v, want %v", err, want)
			}
			for _, other := range others {
				if errors.Is(err, other) {
					t.Fatalf("Current after the crash: %v, which is also %v", err, other)
				}
			}
			if got, err := s.List(ctx); err != nil || len(got) != 0 {
				t.Fatalf("List after the crash = %+v %v, want no entry", got, err)
			}
			mustPut(t, s, "k", KindOpaque, []byte("retried"))
			if _, val, err := s.Current(ctx, "k"); err != nil || string(val) != "retried" {
				t.Fatalf("Current after the retry = %q %v", val, err)
			}
		})
	}
	t.Run("delete", func(t *testing.T) {
		s, _ := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("first"))
		s.step = failAt("delete k")
		if err := s.Delete(ctx, "k"); err == nil {
			t.Fatal("Delete succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		// The Delete buried the entry before it removed anything, so what the
		// interrupted Delete left is a deleted entry without its pointer,
		// refused as deleted, which a retried Delete clears, not a crashed
		// Put that would hide the sealed v1 from rm until the next Put.
		if _, _, err := s.Current(ctx, "k"); !errors.Is(err, errNoPointer) || !strings.Contains(err.Error(), "records as deleted") {
			t.Fatalf("Current after an interrupted Delete: %v, want the refusal of a deleted entry", err)
		}
		if _, err := s.Put(ctx, "k", KindOpaque, []byte("again")); !errors.Is(err, ErrExists) {
			t.Fatalf("Put over an interrupted Delete: %v, want ErrExists", err)
		}
		// The retried rm removes the generation and sealed v1 the crash left.
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatalf("retried Delete: %v", err)
		}
		if err := s.Delete(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Delete after the retried Delete: %v, want ErrNotFound", err)
		}
		if _, err := os.Lstat(filepath.Join(s.dir, "k")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("entry directory after the retried Delete: %v, want it gone", err)
		}
		mustPut(t, s, "k", KindOpaque, []byte("again"))
	})
}

// TestRefusesSymlinks: neither the entries' directory nor an entry directory
// is followed through a symlink.
func TestRefusesSymlinks(t *testing.T) {
	ctx := context.Background()
	t.Run("entries directory", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		ks := filepath.Join(server, "keystore")
		if err := os.Rename(ks, ks+".real"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("keystore.real", ks); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); err == nil {
			t.Fatal("Put wrote through a symlinked keystore directory")
		}
		if _, _, err := s.Current(ctx, "a"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("Current through a symlinked keystore directory: %v, want a refusal", err)
		}
	})
	t.Run("entry directory", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "a", KindOpaque, []byte("a"))
		if err := os.Symlink("a", filepath.Join(server, "keystore", "b")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Current(ctx, "b"); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Current through a symlinked entry: %v, want ErrCorrupt", err)
		}
	})
}

// TestCreateEntryRefusesSwappedDirectory: a new entry directory replaced by a
// symlink to another entry between its mkdir and its open is refused, and
// nothing is written through it into the other entry.
func TestCreateEntryRefusesSwappedDirectory(t *testing.T) {
	s, server := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	ks := filepath.Join(server, "keystore")
	before := dirContents(t, filepath.Join(ks, "a"))
	s.entryMade = func(name string) {
		p := filepath.Join(ks, name)
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := os.Symlink("a", p); err != nil {
			t.Error(err)
		}
	}
	if _, err := s.Put(context.Background(), "b", KindOpaque, []byte("b")); err == nil {
		t.Fatal("Put wrote into a directory swapped in after its mkdir")
	}
	if after := dirContents(t, filepath.Join(ks, "a")); !maps.Equal(after, before) {
		t.Fatalf("the other entry changed: %q, was %q", after, before)
	}
}

// TestMkdirRefusesSwappedDirectory: a directory rename-swapped into the name
// between a mkdir and the Lstat that takes its identity, or one not owned by
// the euid that made it, is refused as ErrCorrupt before anything is chowned,
// and the directory found there is left as it was. It covers the entries'
// directory, made by path through mkdirOwned, and an entry directory, made by
// mkdirAt.
//
// The swap comes before the Lstat, so the identity check sees the swapped-in
// directory and each case is caught by one later check: the symlink by the
// no-follow open, the same-owner non-empty directory by the emptiness check
// alone, and the empty directory by the owner check alone. The test runs as
// the one user that both creates and swaps, so for that case the euid seam
// reports another creator once the swap is made, as root creating a directory
// the service user swaps is.
func TestMkdirRefusesSwappedDirectory(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{"keystore", "b"} {
		for _, tt := range []struct {
			name       string
			files      []string
			symlink    bool
			otherOwner bool
		}{
			{"a same-owner non-empty directory", []string{"v1"}, false, false},
			{"an empty directory owned by another user", nil, false, true},
			{"a symlink to a directory", []string{"v1"}, true, false},
		} {
			t.Run(target+": "+tt.name, func(t *testing.T) {
				s, server := newTestStore(t)
				at := filepath.Join(server, "keystore")
				if target != "keystore" {
					mustPut(t, s, "a", KindOpaque, []byte("a"))
					at = filepath.Join(at, target)
				}
				// The decoy is a directory at 0755 beside the store.
				decoy := filepath.Join(filepath.Dir(server), "decoy")
				if err := os.Mkdir(decoy, 0o755); err != nil {
					t.Fatal(err)
				}
				chmod(t, decoy, 0o755)
				for _, f := range tt.files {
					writeFile(t, filepath.Join(decoy, f), "decoy "+f)
				}
				before := dirContents(t, decoy)
				from, real := decoy, at // what is renamed in, and where the decoy ends up
				if tt.symlink {
					from, real = decoy+".link", decoy
					if err := os.Symlink(decoy, from); err != nil {
						t.Fatal(err)
					}
				}
				swapped := false
				s.euid = func() int {
					if swapped && tt.otherOwner {
						return os.Geteuid() + 1
					}
					return os.Geteuid()
				}
				s.dirMade = func(name string) {
					if name != target {
						return
					}
					if err := os.Remove(at); err != nil {
						t.Error(err)
					}
					if err := os.Rename(from, at); err != nil {
						t.Error(err)
					}
					swapped = true
				}
				var chowned []string
				s.chown = chownedExceptFloorLock(&chowned)

				if _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("Put over a directory swapped in after its mkdir: %v, want ErrCorrupt", err)
				}
				if len(chowned) != 0 {
					t.Fatalf("chowned %v", chowned)
				}
				if after := dirContents(t, real); !maps.Equal(after, before) {
					t.Fatalf("the swapped-in directory changed: %q, was %q", after, before)
				}
				if fi, err := os.Stat(real); err != nil || fi.Mode().Perm() != 0o755 {
					t.Fatalf("the swapped-in directory = %v %v, want its mode 0755 untouched", fi, err)
				}
			})
		}
	}
	t.Run("a directory not owned by its creator", func(t *testing.T) {
		s, server := newTestStore(t)
		s.euid = func() int { return os.Geteuid() + 1 }
		var chowned []string
		s.chown = chownedExceptFloorLock(&chowned)
		if _, err := s.Put(ctx, "a", KindOpaque, []byte("a")); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Put: %v, want ErrCorrupt", err)
		}
		if len(chowned) != 0 {
			t.Fatalf("chowned %v", chowned)
		}
		if _, err := os.Stat(filepath.Join(server, "cred")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the refused Put went on to create cred/: %v", err)
		}
	})
}

// chownedExceptFloorLock is a chown seam that records each file it is asked
// to chown in *chowned, except keystore-lock: root's own lock file, which a
// write verb creates under the data root before it touches keystore/ (the
// lock order), and which is never in a tree the service user controls.
func chownedExceptFloorLock(chowned *[]string) func(f *os.File, uid, gid int) error {
	return func(f *os.File, uid, gid int) error {
		if filepath.Base(f.Name()) != floorLockName {
			*chowned = append(*chowned, f.Name())
		}
		return nil
	}
}

// dirContents maps each name in dir to its content.
func dirContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, de := range des {
		b, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[de.Name()] = string(b)
	}
	return out
}

func failAt(step string) func(string) error {
	return func(name string) error {
		if name == step {
			return fmt.Errorf("injected crash at %s", step)
		}
		return nil
	}
}

func chmod(t *testing.T, p string, m fs.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceWithSymlink(t *testing.T, p, target string) {
	t.Helper()
	remove(t, p)
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

func flipLastByte(t *testing.T, p string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceWithFIFO(t *testing.T, p string) {
	t.Helper()
	remove(t, p)
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
}
