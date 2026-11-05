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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// newTestStore returns a FileStore over a fresh server work dir, owned by the
// test user, with the work dir path for tests that inspect the files.
func newTestStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	server := filepath.Join(t.TempDir(), "server")
	if err := os.Mkdir(server, 0o700); err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Dir:       filepath.Join(server, "keystore"),
		MasterDir: filepath.Join(server, "cred", "keystore-master"),
		UID:       uint32(os.Getuid()),
		GID:       uint32(os.Getgid()),
	})
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
			want := Version{Name: tt.name, Version: 1, Kind: tt.kind, Created: time.Unix(now.Unix(), 0), Fingerprint: put.Fingerprint}
			if put != want || put.Fingerprint == "" {
				t.Fatalf("Put = %+v, want %+v", put, want)
			}
			cur, val, err := s.Current(ctx, tt.name)
			if err != nil || cur != put || !bytes.Equal(val, tt.value) {
				t.Fatalf("Current = %+v %q %v, want %+v %q", cur, val, err, put, tt.value)
			}
			got, val, err := s.Get(ctx, tt.name, 1)
			if err != nil || got != put || !bytes.Equal(val, tt.value) {
				t.Fatalf("Get 1 = %+v %q %v", got, val, err)
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
	select {
	case r := <-done:
		return r.v, r.val, r.err
	case <-time.After(5 * time.Second):
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
// within the bound, never a hang, and a cancelled context ends the wait.
func TestLockBoundedWait(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	s.lockWait = 200 * time.Millisecond
	hold := func(t *testing.T, how int) {
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
	bounded := func(t *testing.T, op string, fn func() error) {
		t.Helper()
		start := time.Now()
		err := fn()
		if took := time.Since(start); !errors.Is(err, errLockTimeout) || took < s.lockWait || took > 5*s.lockWait {
			t.Fatalf("%s under a held lock: %v after %v, want errLockTimeout after about %v", op, err, took, s.lockWait)
		}
	}

	t.Run("exclusive holder blocks reads and writes", func(t *testing.T) {
		hold(t, syscall.LOCK_EX)
		bounded(t, "Put", func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err })
		bounded(t, "Current", func() error { _, _, err := s.Current(ctx, "a"); return err })
		bounded(t, "List", func() error { _, err := s.List(ctx); return err })
		bounded(t, "Delete", func() error { return s.Delete(ctx, "a") })
	})
	t.Run("shared holder blocks only writes", func(t *testing.T) {
		hold(t, syscall.LOCK_SH)
		bounded(t, "Put", func() error { _, err := s.Put(ctx, "b", KindOpaque, []byte("b")); return err })
		if _, _, err := s.Current(ctx, "a"); err != nil {
			t.Fatalf("Current under a shared lock: %v", err)
		}
	})
	t.Run("a cancelled context ends the wait", func(t *testing.T) {
		hold(t, syscall.LOCK_EX)
		s.lockWait = time.Minute
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := s.Put(cctx, "b", KindOpaque, []byte("b")); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Put: %v, want the context's error", err)
		}
	})
}

// TestConcurrentOperations runs writers and readers together under -race;
// the lock serialises them and every write lands.
func TestConcurrentOperations(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
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
		mu    sync.Mutex
		owned []os.FileInfo
	)
	s.chown = func(f *os.File, uid, gid int) error {
		if uid != int(s.uid) || gid != int(s.gid) {
			return fmt.Errorf("chown to %d:%d, want %d:%d", uid, gid, s.uid, s.gid)
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
	want := "write master,write master.sha256,write generation,write v1,write current"
	if strings.Join(steps, ",") != want {
		t.Fatalf("Put steps = %v, want %s", steps, want)
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			s, _ := newTestStore(t)
			s.step = failAt(step)
			if _, err := s.Put(ctx, "k", KindOpaque, []byte("first")); err == nil {
				t.Fatal("Put succeeded through a crash")
			}
			s.step = func(string) error { return nil }
			if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrMasterMissing) {
				t.Fatalf("Current after the crash: %v, want ErrNotFound", err)
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
		if _, _, err := s.Current(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Current after an interrupted Delete: %v, want ErrNotFound", err)
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
