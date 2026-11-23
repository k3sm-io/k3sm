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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rewrapKey is a 32-byte master made of b, so a test can tell which key the
// master file holds.
func rewrapKey(b byte) []byte { return bytes.Repeat([]byte{b}, masterSize) }

// rewrapValues are the values seedRewrap stores, by entry and version.
type rewrapValues map[string][][]byte

// seedRewrap stores "a" (Ed25519, one version) and "b" (opaque, two
// versions), and returns their values.
func seedRewrap(t *testing.T, s *FileStore) rewrapValues {
	t.Helper()
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	mustPut(t, s, "a", KindEd25519, seed)
	mustPut(t, s, "b", KindOpaque, []byte("one"))
	mustRotate(t, s, "b", "two")
	return rewrapValues{"a": {seed}, "b": {[]byte("one"), []byte("two")}}
}

// checkRewrapValues reads every version of every entry and its current
// version through the store's readers, and lists the store: nothing may be
// unreadable, whatever state a Rewrap left.
func checkRewrapValues(t *testing.T, s *FileStore, want rewrapValues) {
	t.Helper()
	ctx := context.Background()
	for name, vals := range want {
		for i, val := range vals {
			if _, got, err := s.Get(ctx, name, uint64(i+1)); err != nil || !bytes.Equal(got, val) {
				t.Fatalf("Get %s %d = %q, %v; want %q", name, i+1, got, err, val)
			}
		}
		if _, got, err := s.Current(ctx, name); err != nil || !bytes.Equal(got, vals[len(vals)-1]) {
			t.Fatalf("Current %s = %q, %v; want %q", name, got, err, vals[len(vals)-1])
		}
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != len(want) {
		t.Fatalf("List = %+v, %v; want %d entries", list, err, len(want))
	}
	for _, e := range list {
		if e.Err != nil {
			t.Fatalf("List %s: %v", e.Name, e.Err)
		}
	}
}

// recordNonces maps each record file of every entry under server to the nonce
// it was sealed with.
func recordNonces(t *testing.T, server string) map[string][nonceSize]byte {
	t.Helper()
	out := map[string][nonceSize]byte{}
	ks := filepath.Join(server, "keystore")
	entries, err := os.ReadDir(ks)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if checkName(e.Name()) != nil {
			continue
		}
		files, err := os.ReadDir(filepath.Join(ks, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if _, ok := parseVersionName(f.Name()); !ok && f.Name() != currentName {
				continue
			}
			b, err := os.ReadFile(filepath.Join(ks, e.Name(), f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			r, err := parseRecord(b)
			if err != nil {
				t.Fatalf("%s/%s: %v", e.Name(), f.Name(), err)
			}
			out[e.Name()+"/"+f.Name()] = r.nonce
		}
	}
	return out
}

func masterPath(server, name string) string {
	return filepath.Join(server, "cred", "keystore-master", name)
}

// checkMasterIs checks the master pair holds key, and that no file of an
// unfinished Rewrap is left: no master.next pair, and no .new record.
func checkMasterIs(t *testing.T, server string, key []byte) {
	t.Helper()
	if got, err := os.ReadFile(masterPath(server, masterName)); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("master = %x, %v; want %x", got, err, key)
	}
	if got, err := os.ReadFile(masterPath(server, masterFingerprintName)); err != nil || string(got) != masterFingerprint(key) {
		t.Fatalf("master.sha256 = %q, %v; want %q", got, err, masterFingerprint(key))
	}
	for _, n := range []string{masterNextName, masterNextFingerprintName} {
		if _, err := os.Lstat(masterPath(server, n)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s left behind: %v", n, err)
		}
	}
	if n := newFiles(t, server); len(n) > 0 {
		t.Fatalf(".new files left behind: %v", n)
	}
}

// newFiles lists the .new files in every entry directory under server.
func newFiles(t *testing.T, server string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(server, "keystore", "*", "*"+newSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// treeSnapshot maps every path under dir to its type, mode and content (a
// symlink's target), so a test can tell that nothing under dir changed.
func treeSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		v := fi.Mode().String()
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			v += " -> " + target
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func checkTreeUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	for p, v := range before {
		if after[p] != v {
			t.Errorf("%s changed", p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s was created", p)
		}
	}
}

// failAtCall fails the n-th call of the step seam (from 0), whatever its
// name, so a step that recurs (a .new write per entry) is crashed at each
// occurrence in turn.
func failAtCall(n int) func(string) error {
	calls := 0
	return func(name string) error {
		calls++
		if calls-1 == n {
			return fmt.Errorf("injected crash at %s", name)
		}
		return nil
	}
}

// TestRewrapChangesEveryNonce is G3's Rewrap half: Rewrap re-seals every
// record, version files and pointers alike, under a fresh nonce and the new
// master, and leaves every value, kind, version and created time unchanged.
// An Ed25519 fingerprint is a digest of the public key and survives; an opaque
// one is keyed by the master and changes.
func TestRewrapChangesEveryNonce(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	vals := seedRewrap(t, s)
	before := recordNonces(t, server)
	if len(before) != 5 {
		t.Fatalf("seeded %d records, want 5 (a: v1, current; b: v1, v2, current)", len(before))
	}
	listBefore, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldMaster, err := os.ReadFile(masterPath(server, masterName))
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	after := recordNonces(t, server)
	if len(after) != len(before) {
		t.Fatalf("after Rewrap %d records, want %d", len(after), len(before))
	}
	for p, n := range before {
		if after[p] == n {
			t.Errorf("%s kept its nonce %x across Rewrap", p, n)
		}
	}
	checkMasterIs(t, server, rewrapKey(1))
	checkRewrapValues(t, s, vals)

	// Nothing opens under the old master any more: every record moved.
	old := mustDeriveKeys(t, oldMaster, scopeSystem)
	for p := range after {
		b, err := os.ReadFile(filepath.Join(server, "keystore", p))
		if err != nil {
			t.Fatal(err)
		}
		r, err := parseRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.open(old.seal, old.scope); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s still opens under the old master: %v", p, err)
		}
	}

	listAfter, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range listAfter {
		for j, v := range e.Versions {
			was := listBefore[i].Versions[j]
			if v.Version != was.Version || v.Kind != was.Kind || !v.Created.Equal(was.Created) {
				t.Errorf("%s v%d metadata %+v, want %+v", e.Name, v.Version, v, was)
			}
			if sameFP := v.Fingerprint == was.Fingerprint; sameFP != (v.Kind == KindEd25519) {
				t.Errorf("%s v%d (%s) fingerprint unchanged = %t across Rewrap", e.Name, v.Version, v.Kind, sameFP)
			}
		}
	}

	// A wrong-length argument changes nothing: empty is ErrMasterMissing, any
	// other length a plain error.
	snap := treeSnapshot(t, filepath.Dir(server))
	if err := s.Rewrap(ctx, nil); !errors.Is(err, ErrMasterMissing) {
		t.Fatalf("Rewrap(nil): %v, want ErrMasterMissing", err)
	}
	if err := s.Rewrap(ctx, rewrapKey(2)[:masterSize-1]); err == nil || errors.Is(err, ErrMasterMissing) || errors.Is(err, ErrMasterUntrusted) {
		t.Fatalf("Rewrap with 31 bytes: %v, want a plain error", err)
	}
	if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
		t.Fatal("Rewrap to the live master succeeded")
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
}

// TestRewrapCrashAtEveryStep is G12: a crash at each durable step of a
// Rewrap leaves every record readable by the store's readers (under the old
// master, or under master.next for a record already moved), and a rerun
// completes it. A rerun reuses a master.next that agrees with its fingerprint
// rather than mint a second key; one that does not agree is discarded only
// while no .new file exists and every record still opens under the live
// master, and is refused as ErrMasterUntrusted otherwise.
func TestRewrapCrashAtEveryStep(t *testing.T) {
	ctx := context.Background()
	var steps []string
	{
		s, _ := newTestStore(t)
		seedRewrap(t, s)
		s.step = func(name string) error { steps = append(steps, name); return nil }
		if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
			t.Fatal(err)
		}
	}
	want := strings.Join([]string{
		"write " + masterNextName, "write " + masterNextFingerprintName,
		"write v1.new", "write current.new",
		"write v1.new", "write v2.new", "write current.new",
		"rename a/v1", "rename a/current",
		"rename b/v1", "rename b/v2", "rename b/current",
		"rename " + masterNextName, "rename " + masterNextFingerprintName,
	}, ",")
	if strings.Join(steps, ",") != want {
		t.Fatalf("Rewrap steps = %v, want %s", steps, want)
	}
	for i, step := range steps {
		t.Run(fmt.Sprintf("%02d %s", i, step), func(t *testing.T) {
			s, server := newTestStore(t)
			vals := seedRewrap(t, s)
			before := recordNonces(t, server)
			s.step = failAtCall(i)
			if err := s.Rewrap(ctx, rewrapKey(1)); err == nil || !strings.Contains(err.Error(), "injected crash at "+step) {
				t.Fatalf("Rewrap through a crash at %s: %v, want the injected crash", step, err)
			}
			s.step = func(string) error { return nil }
			checkRewrapValues(t, s, vals)

			// Until a record is renamed in under the first key, nothing is
			// committed to it: the rerun discards it and goes live with its own
			// key. From the first rename to the first master rename, the rerun
			// completes the first key and says so. After the second master
			// rename the first Rewrap had completed, and the rerun is a new one.
			err := s.Rewrap(ctx, rewrapKey(2))
			key := rewrapKey(2)
			if i >= 7 && i < len(steps)-1 {
				key = rewrapKey(1)
				if !errors.Is(err, ErrRewrapResumed) {
					t.Fatalf("Rewrap rerun after a commit began: %v, want ErrRewrapResumed", err)
				}
				checkUnderKey(t, server, key)
			} else if err != nil {
				t.Fatalf("Rewrap rerun: %v", err)
			}
			checkMasterIs(t, server, key)
			checkRewrapValues(t, s, vals)
			after := recordNonces(t, server)
			for p, n := range before {
				if after[p] == n {
					t.Errorf("%s kept its nonce across the resumed Rewrap", p)
				}
			}
		})
	}

	// crashAt runs a Rewrap to key 1 that crashes at step n, then damages
	// master.next.
	crashAt := func(t *testing.T, n int) (*FileStore, string, rewrapValues) {
		t.Helper()
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		s.step = failAtCall(n)
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		flipLastByte(t, masterPath(server, masterNextName))
		return s, server, vals
	}
	t.Run("a damaged master.next with no .new file is discarded", func(t *testing.T) {
		// The crash at the first .new write leaves none.
		s, server, vals := crashAt(t, 2)
		if n := newFiles(t, server); len(n) != 0 {
			t.Fatalf(".new files after the crash: %v", n)
		}
		if err := s.Rewrap(ctx, rewrapKey(2)); err != nil {
			t.Fatalf("Rewrap rerun: %v", err)
		}
		checkMasterIs(t, server, rewrapKey(2))
		checkRewrapValues(t, s, vals)
	})
	t.Run("a damaged master.next with a .new file is refused", func(t *testing.T) {
		// The crash at the second .new write leaves a/v1.new.
		s, server, vals := crashAt(t, 3)
		if n := newFiles(t, server); len(n) != 1 {
			t.Fatalf(".new files after the crash: %v, want one", n)
		}
		snap := treeSnapshot(t, filepath.Dir(server))
		if err := s.Rewrap(ctx, rewrapKey(2)); !errors.Is(err, ErrMasterUntrusted) {
			t.Fatalf("Rewrap rerun: %v, want ErrMasterUntrusted", err)
		}
		checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
		checkRewrapValues(t, s, vals)
	})
	t.Run("a damaged master.next after records moved is refused", func(t *testing.T) {
		// Every .new is renamed in, so none is left, but the records are
		// under master.next: discarding it would orphan them.
		s, server, _ := crashAt(t, 11)
		if n := newFiles(t, server); len(n) != 0 {
			t.Fatalf(".new files after the crash: %v", n)
		}
		snap := treeSnapshot(t, filepath.Dir(server))
		if err := s.Rewrap(ctx, rewrapKey(2)); !errors.Is(err, ErrMasterUntrusted) {
			t.Fatalf("Rewrap rerun: %v, want ErrMasterUntrusted", err)
		}
		checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
	})
	t.Run("an entry that does not open refuses before anything is written", func(t *testing.T) {
		s, server := newTestStore(t)
		seedRewrap(t, s)
		flipLastByte(t, entryPath(server, "b", "v1"))
		snap := treeSnapshot(t, filepath.Dir(server))
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Rewrap over a corrupt record: %v, want ErrCorrupt", err)
		}
		checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
	})
}

// TestRewrapMasterRenameCompleted is G13: a crash between the two master
// renames leaves master holding the new key, master.sha256 the old
// fingerprint and master.next.sha256 the new one. The master passes its trust
// check, a reader opens every record and writes nothing, and the next verb
// that takes the exclusive lock completes the swap; a Rewrap that does so has
// completed the interrupted one and mints no second key.
func TestRewrapMasterRenameCompleted(t *testing.T) {
	ctx := context.Background()
	interrupted := func(t *testing.T) (*FileStore, string, rewrapValues) {
		t.Helper()
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		oldFP, err := os.ReadFile(masterPath(server, masterFingerprintName))
		if err != nil {
			t.Fatal(err)
		}
		s.step = failAt("rename " + masterNextName)
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		if got, _ := os.ReadFile(masterPath(server, masterName)); !bytes.Equal(got, rewrapKey(1)) {
			t.Fatalf("master after the first rename = %x, want the new key", got)
		}
		if got, _ := os.ReadFile(masterPath(server, masterFingerprintName)); !bytes.Equal(got, oldFP) {
			t.Fatalf("master.sha256 after the first rename = %q, want the old fingerprint", got)
		}
		if _, err := os.Lstat(masterPath(server, masterNextName)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("master.next after the first rename: %v", err)
		}
		checkRewrapValues(t, s, vals)
		if _, err := os.Lstat(masterPath(server, masterNextFingerprintName)); err != nil {
			t.Fatalf("a reader completed the swap: %v", err)
		}
		return s, server, vals
	}
	t.Run("the next rewrap", func(t *testing.T) {
		s, server, vals := interrupted(t)
		if err := s.Rewrap(ctx, rewrapKey(2)); !errors.Is(err, ErrRewrapResumed) {
			t.Fatalf("Rewrap rerun: %v, want ErrRewrapResumed", err)
		}
		checkMasterIs(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
		// Run again, as the refusal says, it retires the resumed key.
		if err := s.Rewrap(ctx, rewrapKey(2)); err != nil {
			t.Fatalf("Rewrap after the resume: %v", err)
		}
		checkMasterIs(t, server, rewrapKey(2))
		checkRewrapValues(t, s, vals)
	})
	t.Run("the next rewrap, with the resumed key", func(t *testing.T) {
		s, server, vals := interrupted(t)
		if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
			t.Fatalf("Rewrap rerun with the key it resumes: %v, want nil", err)
		}
		checkMasterIs(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
	})
	t.Run("the next put", func(t *testing.T) {
		s, server, vals := interrupted(t)
		mustPut(t, s, "c", KindOpaque, []byte("c"))
		vals["c"] = [][]byte{[]byte("c")}
		checkMasterIs(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
	})
	t.Run("the next rotate", func(t *testing.T) {
		s, server, vals := interrupted(t)
		mustRotate(t, s, "b", "three")
		vals["b"] = append(vals["b"], []byte("three"))
		checkMasterIs(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
	})
}

// checkUnderKey checks every record under server opens under key alone.
func checkUnderKey(t *testing.T, server string, key []byte) {
	t.Helper()
	k := mustDeriveKeys(t, key, scopeSystem)
	for p := range recordNonces(t, server) {
		b, err := os.ReadFile(filepath.Join(server, "keystore", p))
		if err != nil {
			t.Fatal(err)
		}
		r, err := parseRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.open(k.seal, k.scope); err != nil {
			t.Errorf("%s does not open under %x: %v", p, key[:1], err)
		}
	}
}

// plantNext writes key as master.next, with the fingerprint that agrees
// with it, as a process that can write the master directory could.
func plantNext(t *testing.T, server string, key []byte) {
	t.Helper()
	writeFile(t, masterPath(server, masterNextName), string(key))
	writeFile(t, masterPath(server, masterNextFingerprintName), masterFingerprint(key))
}

// TestRewrapKeyReuse: Rewrap never adopts a key it was not given without
// saying so. A master.next under which nothing is committed yet, planted or
// left by a crash before any record was renamed in, is discarded with every
// .new, and the caller's key goes live. Once some record is live under
// master.next, Rewrap completes that key, since discarding it would orphan
// the record, and returns ErrRewrapResumed; every record then opens under the
// resumed key.
func TestRewrapKeyReuse(t *testing.T) {
	ctx := context.Background()
	t.Run("a planted master.next with nothing committed is discarded", func(t *testing.T) {
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		plantNext(t, server, rewrapKey(9))
		if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
			t.Fatalf("Rewrap: %v", err)
		}
		checkMasterIs(t, server, rewrapKey(1))
		checkUnderKey(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
	})
	t.Run("a crash before any rename leaves nothing committed", func(t *testing.T) {
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		s.step = failAtCall(6) // the last .new write: every .new but one written
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		if n := newFiles(t, server); len(n) == 0 {
			t.Fatal("the crash left no .new file")
		}
		if err := s.Rewrap(ctx, rewrapKey(2)); err != nil {
			t.Fatalf("Rewrap rerun: %v", err)
		}
		checkMasterIs(t, server, rewrapKey(2))
		checkUnderKey(t, server, rewrapKey(2))
		checkRewrapValues(t, s, vals)
	})
	t.Run("a resume after a partial commit is reported", func(t *testing.T) {
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		s.step = failAt("rename a/v1")
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		if err := s.Rewrap(ctx, rewrapKey(2)); !errors.Is(err, ErrRewrapResumed) {
			t.Fatalf("Rewrap rerun: %v, want ErrRewrapResumed", err)
		}
		checkMasterIs(t, server, rewrapKey(1))
		checkUnderKey(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
	})
}

// TestRewrapRefusesDamagedUserScopes replaces U5's refusal (U12 re-wraps
// scope keys): an empty .user directory no longer stops Rewrap, while a
// .user that is a file or a symlink, which no user scope can be, refuses it
// with ErrCorrupt, naming the path, and writes nothing.
func TestRewrapRefusesDamagedUserScopes(t *testing.T) {
	t.Run("an empty directory", func(t *testing.T) {
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		p := filepath.Join(server, "keystore", userScopesName)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		giveToService(t, p)
		if err := s.Rewrap(context.Background(), rewrapKey(1)); err != nil {
			t.Fatalf("Rewrap with an empty %s: %v", userScopesName, err)
		}
		checkMasterIs(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
	})
	for name, plant := range map[string]func(t *testing.T, p string){
		"file": func(t *testing.T, p string) { writeFile(t, p, "") },
		"symlink": func(t *testing.T, p string) {
			if err := os.Symlink("nowhere", p); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			vals := seedRewrap(t, s)
			plant(t, filepath.Join(server, "keystore", userScopesName))
			snap := treeSnapshot(t, filepath.Dir(server))
			err := s.Rewrap(context.Background(), rewrapKey(1))
			if !errors.Is(err, ErrCorrupt) || !errors.Is(err, ErrRewrapNotStarted) {
				t.Fatalf("Rewrap with %s a %s: %v, want ErrCorrupt before anything is written", userScopesName, name, err)
			}
			if !strings.Contains(err.Error(), "keystore/"+userScopesName) {
				t.Fatalf("Rewrap refusal %q does not name keystore/%s", err, userScopesName)
			}
			checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
			checkRewrapValues(t, s, vals)
		})
	}
}

// TestRewrapRefusesStalePointer: Rewrap plans by the floor-checked pointer,
// so a previously valid current copied back over the live one, which every
// reader refuses, refuses the Rewrap before anything is written, like any
// entry List reports with Err, rather than being re-sealed as it is.
func TestRewrapRefusesStalePointer(t *testing.T) {
	s, server := newTestStore(t)
	mustPut(t, s, "a", KindOpaque, []byte("one"))
	saved, err := os.ReadFile(entryPath(server, "a", currentName))
	if err != nil {
		t.Fatal(err)
	}
	mustRotate(t, s, "a", "two")
	writeFile(t, entryPath(server, "a", currentName), string(saved))
	snap := treeSnapshot(t, filepath.Dir(server))
	err = s.Rewrap(context.Background(), rewrapKey(1))
	var stale *staleError
	if !errors.As(err, &stale) || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Rewrap over a copied-back pointer: %v, want the floor's refusal", err)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
}

// sealUnder seals value as version version of entry name under key, with the
// entry's generation and the kind and created time of the record at file:
// a record that belongs exactly where file is, under key, holding value.
func sealUnder(t *testing.T, server, name, file string, key, value []byte) []byte {
	t.Helper()
	return sealEdited(t, server, name, file, key, value, func(*record) {})
}

// sealEdited is sealUnder with edit applied to the record before it is
// sealed.
func sealEdited(t *testing.T, server, name, file string, key, value []byte, edit func(*record)) []byte {
	t.Helper()
	b, err := os.ReadFile(entryPath(server, name, file))
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	g, err := os.ReadFile(entryPath(server, name, generationName))
	if err != nil {
		t.Fatal(err)
	}
	var gen [generationSize]byte
	if _, err := hex.Decode(gen[:], g[:2*generationSize]); err != nil {
		t.Fatal(err)
	}
	k := mustDeriveKeys(t, key, scopeSystem)
	out := record{kind: r.kind, name: name, version: r.version, generation: gen, created: r.created}
	edit(&out)
	if err := out.seal(k.seal, k.scope, value, rand.Reader); err != nil {
		t.Fatal(err)
	}
	return out.marshal()
}

// TestRewrapVerifiesCommit: what step 4 renames in and step 5 swaps in is
// checked first. A .new must open under the new key and hold the very record
// it replaces, or the Rewrap stops with ErrCorrupt and leaves the record; and
// the master must be the key the records were sealed under both before its
// rename (master.next read again) and after it (master read back), or the
// Rewrap stops with ErrMasterUntrusted.
func TestRewrapVerifiesCommit(t *testing.T) {
	ctx := context.Background()
	t.Run("a .new holding another value is refused", func(t *testing.T) {
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		before, err := os.ReadFile(entryPath(server, "b", "v1"))
		if err != nil {
			t.Fatal(err)
		}
		// Once step 4 has begun, b/v1.new is replaced by a record that opens
		// under the new key, in b/v1's place, holding another value.
		s.step = func(name string) error {
			if name == "rename a/v1" {
				writeFile(t, entryPath(server, "b", "v1"+newSuffix), string(sealUnder(t, server, "b", "v1", rewrapKey(1), []byte("forged"))))
			}
			return nil
		}
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Rewrap over a .new holding another value: %v, want ErrCorrupt", err)
		}
		s.step = func(string) error { return nil }
		if now, _ := os.ReadFile(entryPath(server, "b", "v1")); !bytes.Equal(now, before) {
			t.Fatal("b/v1 was replaced by the forged .new")
		}
		checkRewrapValues(t, s, vals)
	})
	t.Run("master.next replaced before the swap is refused", func(t *testing.T) {
		s, server := newTestStore(t)
		seedRewrap(t, s)
		old, err := os.ReadFile(masterPath(server, masterName))
		if err != nil {
			t.Fatal(err)
		}
		s.step = func(name string) error {
			if name == "rename b/current" {
				plantNext(t, server, rewrapKey(9))
			}
			return nil
		}
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrMasterUntrusted) {
			t.Fatalf("Rewrap with master.next replaced: %v, want ErrMasterUntrusted", err)
		}
		if now, _ := os.ReadFile(masterPath(server, masterName)); !bytes.Equal(now, old) {
			t.Fatalf("master = %x, want the old master left in place", now)
		}
	})
	t.Run("a master replaced after its rename is refused", func(t *testing.T) {
		s, server := newTestStore(t)
		seedRewrap(t, s)
		// The fsync after the first master rename stands in for a swap of
		// master between that rename and the read back.
		swapped := false
		setSyncDir(t, func(root *os.Root) error {
			if !swapped && filepath.Base(root.Name()) == "keystore-master" {
				if b, _ := os.ReadFile(masterPath(server, masterName)); bytes.Equal(b, rewrapKey(1)) {
					writeFile(t, masterPath(server, masterName), string(rewrapKey(9)))
					swapped = true
				}
			}
			return fsyncDir(root)
		})
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrMasterUntrusted) {
			t.Fatalf("Rewrap with master replaced after its rename: %v, want ErrMasterUntrusted", err)
		}
		if !swapped {
			t.Fatal("the master was never swapped")
		}
		if _, err := os.Lstat(masterPath(server, masterNextFingerprintName)); err != nil {
			t.Fatalf("the fingerprint was renamed over a master that is not the new key: %v", err)
		}
	})
}

// TestRewrapGuards pins guards that a rewrap would otherwise pass without:
// each case fails if its guard is removed. The re-read of master.next before
// the swap is pinned by TestRewrapVerifiesCommit.
func TestRewrapGuards(t *testing.T) {
	ctx := context.Background()
	t.Run("a .new that does not open under the new key is not committed", func(t *testing.T) {
		s, server := newTestStore(t)
		vals := seedRewrap(t, s)
		before, err := os.ReadFile(entryPath(server, "b", "v1"))
		if err != nil {
			t.Fatal(err)
		}
		s.step = func(name string) error {
			if name == "rename a/v1" {
				flipLastByte(t, entryPath(server, "b", "v1"+newSuffix))
			}
			return nil
		}
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Rewrap over a .new that does not open: %v, want ErrCorrupt", err)
		}
		s.step = func(string) error { return nil }
		if now, _ := os.ReadFile(entryPath(server, "b", "v1")); !bytes.Equal(now, before) {
			t.Fatal("b/v1 was replaced by a .new that does not open")
		}
		checkRewrapValues(t, s, vals)
	})

	t.Run("a master.next its fingerprint does not match is no fallback key", func(t *testing.T) {
		s, server := newTestStore(t)
		seedRewrap(t, s)
		s.step = failAt("rename a/v1") // a/v1 is live under master.next
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		if _, _, err := s.Get(ctx, "a", 1); err != nil {
			t.Fatalf("Get a 1 under the agreeing master.next: %v", err)
		}
		writeFile(t, masterPath(server, masterNextFingerprintName), masterFingerprint(rewrapKey(9)))
		if _, _, err := s.Get(ctx, "a", 1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Get a 1 with master.next unvouched for: %v, want ErrCorrupt", err)
		}
	})
}

// TestRewrapRefusesLiveMasterFirst: a new master equal to the live one is
// refused before any write: the floor is not raised, even when it is behind,
// and an uncommitted master.next is not discarded.
func TestRewrapRefusesLiveMasterFirst(t *testing.T) {
	s, server := newTestStore(t)
	seedRewrap(t, s)
	live, err := os.ReadFile(masterPath(server, masterName))
	if err != nil {
		t.Fatal(err)
	}
	// a's floor entry is dropped, so a raise would record it again.
	fl := floorOf(t, server)
	delete(fl, "a")
	putFloorFile(t, server, fl)
	floorBefore, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	plantNext(t, server, rewrapKey(9))
	if err := s.Rewrap(context.Background(), live); err == nil || !strings.Contains(err.Error(), "the new master is the live one") {
		t.Fatalf("Rewrap to the live master: %v, want its refusal", err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || !bytes.Equal(after, floorBefore) {
		t.Fatalf("the floor changed (%v): %s, want %s", err, after, floorBefore)
	}
	if got, err := os.ReadFile(masterPath(server, masterNextName)); err != nil || !bytes.Equal(got, rewrapKey(9)) {
		t.Fatalf("master.next = %x, %v; want the planted key left in place", got, err)
	}
	if _, err := os.Lstat(masterPath(server, masterNextFingerprintName)); err != nil {
		t.Fatalf("master.next.sha256 was removed: %v", err)
	}
}

// TestRewrapRecoversReplacedNext: when master.next is replaced or removed
// while a Rewrap runs, the records already moved are sealed under the
// caller's key, which no file holds any more. A rerun with that same key
// finds every record opens under the live master or that key, writes
// master.next back from it and completes the Rewrap. A rerun with any other
// key is refused.
func TestRewrapRecoversReplacedNext(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		at     string // the step the replacement happens after
		damage func(t *testing.T, server string)
	}{
		"replaced by an agreeing pair after every record moved": {"rename b/current", func(t *testing.T, server string) { plantNext(t, server, rewrapKey(9)) }},
		"replaced by an agreeing pair after one record moved":   {"rename a/v1", func(t *testing.T, server string) { plantNext(t, server, rewrapKey(9)) }},
		"replaced by one its fingerprint does not match": {"rename a/v1", func(t *testing.T, server string) {
			writeFile(t, masterPath(server, masterNextName), string(rewrapKey(9)))
		}},
		"removed with its fingerprint": {"rename b/v2", func(t *testing.T, server string) {
			for _, n := range []string{masterNextName, masterNextFingerprintName} {
				if err := os.Remove(masterPath(server, n)); err != nil {
					t.Error(err)
				}
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			vals := seedRewrap(t, s)
			s.step = func(name string) error {
				if name == tc.at {
					tc.damage(t, server)
					return fmt.Errorf("injected crash at %s", name)
				}
				return nil
			}
			if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
				t.Fatal("Rewrap succeeded through a replaced master.next")
			}
			s.step = func(string) error { return nil }
			snap := treeSnapshot(t, filepath.Dir(server))
			if err := s.Rewrap(ctx, rewrapKey(2)); err == nil {
				t.Fatal("Rewrap rerun with another key succeeded")
			}
			checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
			if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
				t.Fatalf("Rewrap rerun with the same key: %v", err)
			}
			checkMasterIs(t, server, rewrapKey(1))
			checkUnderKey(t, server, rewrapKey(1))
			checkRewrapValues(t, s, vals)
		})
	}
}

// TestFinishSwapLeavesUnmatchedFingerprint is G13's other half: a
// master.next.sha256 left with no master.next that the master does not match
// is no half-done swap. finishSwap declines it, so it is never renamed over
// master.sha256; a verb that takes the exclusive lock runs on the master as
// it was, and the fingerprint is left for Rewrap to judge.
func TestFinishSwapLeavesUnmatchedFingerprint(t *testing.T) {
	s, server := newTestStore(t)
	vals := seedRewrap(t, s)
	oldFP, err := os.ReadFile(masterPath(server, masterFingerprintName))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, masterPath(server, masterNextFingerprintName), masterFingerprint(rewrapKey(9)))
	mroot, err := s.openMasterDir(false)
	if err != nil {
		t.Fatal(err)
	}
	done, err := s.finishSwap(mroot)
	_ = mroot.Close()
	if done || err != nil {
		t.Fatalf("finishSwap over a fingerprint the master does not match = %t, %v; want false, nil", done, err)
	}
	mustPut(t, s, "c", KindOpaque, []byte("c"))
	vals["c"] = [][]byte{[]byte("c")}
	if got, _ := os.ReadFile(masterPath(server, masterFingerprintName)); !bytes.Equal(got, oldFP) {
		t.Fatalf("master.sha256 = %q, want the old fingerprint %q", got, oldFP)
	}
	if got, _ := os.ReadFile(masterPath(server, masterNextFingerprintName)); string(got) != masterFingerprint(rewrapKey(9)) {
		t.Fatalf("master.next.sha256 = %q, want it left as it was", got)
	}
	checkRewrapValues(t, s, vals)
}

// TestRewrapRemovesStaleNew: a .new beside a record already under the new
// key is removed by the commit, so a resumed Rewrap leaves none, and the next
// Rewrap, which would refuse over a .new with no master.next, runs.
func TestRewrapRemovesStaleNew(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	vals := seedRewrap(t, s)
	s.step = failAt("rename a/v1") // a/v1 is live under master.next
	if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
		t.Fatal("Rewrap succeeded through a crash")
	}
	s.step = func(string) error { return nil }
	copyFile(t, entryPath(server, "a", "v1"), entryPath(server, "a", "v1"+newSuffix))
	if err := s.Rewrap(ctx, rewrapKey(2)); !errors.Is(err, ErrRewrapResumed) {
		t.Fatalf("Rewrap rerun: %v, want ErrRewrapResumed", err)
	}
	if n := newFiles(t, server); len(n) > 0 {
		t.Fatalf(".new files left behind: %v", n)
	}
	if err := s.Rewrap(ctx, rewrapKey(2)); err != nil {
		t.Fatalf("Rewrap after the resume: %v", err)
	}
	checkMasterIs(t, server, rewrapKey(2))
	checkRewrapValues(t, s, vals)
}

// TestRewrapOverFullFloor: Rewrap records nothing new in the floor, so a
// floor with no room to raise the entries it holds does not stop it, and the
// floor is left as it was. It lowers the floor's limits
// (setSmallFloorLimits): the floor is one byte short of room for the
// smallest entry either way.
func TestRewrapOverFullFloor(t *testing.T) {
	setSmallFloorLimits(t)
	s, server := newTestStore(t)
	vals := seedRewrap(t, s)
	// Neither entry is recorded, and the floor has no room to record one.
	fillFloor(t, server, nil, floorSizeLimit-minFloorEntrySize+1)
	before, err := os.ReadFile(floorPath(server))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rewrap(context.Background(), rewrapKey(1)); err != nil {
		t.Fatalf("Rewrap over a full floor: %v", err)
	}
	if after, err := os.ReadFile(floorPath(server)); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("the floor changed (%d bytes, %v), want the %d bytes it held", len(after), err, len(before))
	}
	checkMasterIs(t, server, rewrapKey(1))
	checkRewrapValues(t, s, vals)
}

// TestRewrapCommitChecksMetadata: a .new that opens under the new key and
// holds the plaintext of the record it replaces is still refused with
// ErrCorrupt, and not renamed, when its created time or its kind differs.
func TestRewrapCommitChecksMetadata(t *testing.T) {
	for name, edit := range map[string]func(*record){
		"another created time": func(r *record) { r.created++ },
		"another kind":         func(r *record) { r.kind = byte(KindEd25519) },
	} {
		t.Run(name, func(t *testing.T) {
			s, server := newTestStore(t)
			vals := seedRewrap(t, s)
			before, err := os.ReadFile(entryPath(server, "b", "v1"))
			if err != nil {
				t.Fatal(err)
			}
			// b/v1 is opaque, holding "one": the forgery holds "one" too.
			s.step = func(name string) error {
				if name == "rename a/v1" {
					writeFile(t, entryPath(server, "b", "v1"+newSuffix), string(sealEdited(t, server, "b", "v1", rewrapKey(1), []byte("one"), edit)))
				}
				return nil
			}
			if err := s.Rewrap(context.Background(), rewrapKey(1)); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Rewrap over a .new with %s: %v, want ErrCorrupt", name, err)
			}
			s.step = func(string) error { return nil }
			if now, _ := os.ReadFile(entryPath(server, "b", "v1")); !bytes.Equal(now, before) {
				t.Fatalf("b/v1 was replaced by a .new with %s", name)
			}
			checkRewrapValues(t, s, vals)
		})
	}
}

// TestInterruptedRewrap: InterruptedRewrap reports the fingerprint a crashed
// Rewrap recorded, SHA-256 of its key, from a crash after master.next.sha256
// lands through one between the two master renames, and nothing for a store
// with no Rewrap pending. A fingerprint file it cannot trust is
// ErrMasterUntrusted. It writes nothing.
func TestInterruptedRewrap(t *testing.T) {
	ctx := context.Background()
	want := sha256.Sum256(rewrapKey(1))
	crashed := func(t *testing.T, at string) (*FileStore, string) {
		t.Helper()
		s, server := newTestStore(t)
		seedRewrap(t, s)
		s.step = failAt(at)
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		return s, server
	}
	for _, at := range []string{
		"write v1.new",
		"rename a/v1",
		"rename b/current",
		"rename " + masterNextName,
	} {
		t.Run("crash at "+at, func(t *testing.T) {
			s, server := crashed(t, at)
			snap := treeSnapshot(t, filepath.Dir(server))
			fp, ok, err := s.InterruptedRewrap(ctx)
			if err != nil || !ok || fp != want {
				t.Fatalf("InterruptedRewrap = %x, %v, %v; want %x, true, nil", fp, ok, err, want)
			}
			checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
		})
	}
	none := map[string]func(t *testing.T) *FileStore{
		"no keystore": func(t *testing.T) *FileStore { s, _ := newTestStore(t); return s },
		"entries, no rewrap": func(t *testing.T) *FileStore {
			s, _ := newTestStore(t)
			seedRewrap(t, s)
			return s
		},
		"a completed rewrap": func(t *testing.T) *FileStore {
			s, _ := newTestStore(t)
			seedRewrap(t, s)
			if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
				t.Fatal(err)
			}
			return s
		},
		"a crash before master.next.sha256 lands": func(t *testing.T) *FileStore {
			s, _ := crashed(t, "write "+masterNextFingerprintName)
			return s
		},
	}
	for name, mk := range none {
		t.Run(name, func(t *testing.T) {
			fp, ok, err := mk(t).InterruptedRewrap(ctx)
			if err != nil || ok || fp != ([sha256.Size]byte{}) {
				t.Fatalf("InterruptedRewrap = %x, %v, %v; want zero, false, nil", fp, ok, err)
			}
		})
	}
	for name, damage := range map[string]func(t *testing.T, p string){
		"not hex": func(t *testing.T, p string) {
			writeFile(t, p, strings.Repeat("z", 2*sha256.Size)+"\n")
		},
		"no newline": func(t *testing.T, p string) {
			writeFile(t, p, hex.EncodeToString(want[:])+"0")
		},
		"group readable": func(t *testing.T, p string) {
			if err := os.Chmod(p, 0o640); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			s, server := crashed(t, "write v1.new")
			p := masterPath(server, masterNextFingerprintName)
			damage(t, p)
			giveToService(t, p)
			if _, ok, err := s.InterruptedRewrap(ctx); !errors.Is(err, ErrMasterUntrusted) || ok {
				t.Fatalf("InterruptedRewrap: ok %v, %v; want ErrMasterUntrusted", ok, err)
			}
		})
	}
}

// TestRewrapNotStarted: Rewrap marks with ErrRewrapNotStarted exactly the
// errors it returns before it first writes master.next from the key it was
// given: the early refusals and a resume of another key match it; a crash
// after that write, at any later step, does not.
func TestRewrapNotStarted(t *testing.T) {
	ctx := context.Background()
	before := map[string]func(t *testing.T) (*FileStore, []byte){
		"no keystore": func(t *testing.T) (*FileStore, []byte) { s, _ := newTestStore(t); return s, rewrapKey(1) },
		"short key": func(t *testing.T) (*FileStore, []byte) {
			s, _ := newTestStore(t)
			seedRewrap(t, s)
			return s, rewrapKey(1)[:31]
		},
		"the live master": func(t *testing.T) (*FileStore, []byte) {
			s, server := newTestStore(t)
			seedRewrap(t, s)
			live, err := os.ReadFile(masterPath(server, masterName))
			if err != nil {
				t.Fatal(err)
			}
			return s, live
		},
		"a user-scope directory that is a file": func(t *testing.T) (*FileStore, []byte) {
			s, server := newTestStore(t)
			seedRewrap(t, s)
			writeFile(t, filepath.Join(server, "keystore", userScopesName), "")
			return s, rewrapKey(1)
		},
		"an entry that does not open": func(t *testing.T) (*FileStore, []byte) {
			s, server := newTestStore(t)
			seedRewrap(t, s)
			writeFile(t, filepath.Join(server, "keystore", "a", "v1"), "garbage")
			return s, rewrapKey(1)
		},
		"a resume of another key": func(t *testing.T) (*FileStore, []byte) {
			s, _ := newTestStore(t)
			seedRewrap(t, s)
			s.step = failAt("rename a/v1")
			if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
				t.Fatal("Rewrap succeeded through a crash")
			}
			s.step = func(string) error { return nil }
			return s, rewrapKey(2)
		},
	}
	for name, mk := range before {
		t.Run(name, func(t *testing.T) {
			s, key := mk(t)
			if err := s.Rewrap(ctx, key); !errors.Is(err, ErrRewrapNotStarted) {
				t.Fatalf("Rewrap = %v, want ErrRewrapNotStarted", err)
			}
		})
	}
	for _, at := range []string{"write " + masterNextName, "write v1.new", "rename a/v1", "rename " + masterNextName} {
		t.Run("crash at "+at, func(t *testing.T) {
			s, _ := newTestStore(t)
			seedRewrap(t, s)
			s.step = failAt(at)
			err := s.Rewrap(ctx, rewrapKey(1))
			if err == nil || errors.Is(err, ErrRewrapNotStarted) {
				t.Fatalf("Rewrap = %v, want an error that is not ErrRewrapNotStarted", err)
			}
		})
	}
}

// TestRewrapResumeFailed: a Rewrap that is completing an earlier rewrap
// under that rewrap's key (one interrupted at rename a/v1, or between the
// master renames), and fails once it has advanced it, matches
// ErrRewrapResumeFailed and never ErrRewrapNotStarted, at each step of the
// resume: the records it renamed in, and a half-done master swap it moved,
// are the earlier key's, which a rerun with that key's file finishes.
func TestRewrapResumeFailed(t *testing.T) {
	ctx := context.Background()
	// interrupted leaves a Rewrap to key 1 crashed at step at.
	interrupted := func(t *testing.T, at string) (*FileStore, string) {
		t.Helper()
		s, server := newTestStore(t)
		seedRewrap(t, s)
		s.step = failAt(at)
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		return s, server
	}
	for _, tc := range []struct{ first, resume string }{
		// a/v1 is live under key 1; the resume fails at its own steps.
		{"rename a/v1", "write v1.new"},
		{"rename a/v1", "rename a/current"},
		{"rename a/v1", "rename b/v2"},
		{"rename a/v1", "rename " + masterNextName},
		{"rename a/v1", "rename " + masterNextFingerprintName},
		// The master swap is half done; the resume fails as it moves it on.
		{"rename " + masterNextName, "rename " + masterNextFingerprintName},
	} {
		t.Run(tc.first+" then "+tc.resume, func(t *testing.T) {
			s, server := interrupted(t, tc.first)
			var steps []string
			s.step = func(name string) error {
				steps = append(steps, name)
				if name == tc.resume {
					return fmt.Errorf("injected crash at %s", name)
				}
				return nil
			}
			err := s.Rewrap(ctx, rewrapKey(2))
			if err == nil || !strings.Contains(err.Error(), "injected crash at "+tc.resume) {
				t.Fatalf("the resume did not fail at %s (steps %v): %v", tc.resume, steps, err)
			}
			if !errors.Is(err, ErrRewrapResumeFailed) || errors.Is(err, ErrRewrapNotStarted) {
				t.Fatalf("Rewrap failing a resume at %s = %v, want ErrRewrapResumeFailed and not ErrRewrapNotStarted", tc.resume, err)
			}
			// Only a failure after the swap's last rename has completed the
			// earlier rewrap.
			if swap := tc.resume == "rename "+masterNextFingerprintName; errors.Is(err, ErrRewrapSwapUnsynced) != swap {
				t.Fatalf("Rewrap failing a resume at %s = %v; ErrRewrapSwapUnsynced matches %v, want %v", tc.resume, err, !swap, swap)
			}
			// The earlier key finishes it: a rerun with it completes the
			// rewrap, or, when the failed step came after the last rename,
			// finds that key already live.
			s.step = func(string) error { return nil }
			if err := s.Rewrap(ctx, rewrapKey(1)); err != nil && !errors.Is(err, ErrRewrapNotStarted) {
				t.Fatalf("Rewrap with the earlier key after the failed resume: %v", err)
			}
			checkMasterIs(t, server, rewrapKey(1))
			checkUnderKey(t, server, rewrapKey(1))
		})
	}
	t.Run("a resume with the caller's own key is not another key's", func(t *testing.T) {
		s, _ := interrupted(t, "rename a/v1")
		s.step = failAt("rename b/v1")
		err := s.Rewrap(ctx, rewrapKey(1))
		if err == nil || errors.Is(err, ErrRewrapResumeFailed) || errors.Is(err, ErrRewrapNotStarted) {
			t.Fatalf("Rewrap resuming its own key, failing = %v, want neither marker", err)
		}
	})
}

// TestRewrapOwnSwapUnsynced: a Rewrap whose own master swap goes through
// and then fails (the sync or step after the second rename) matches
// ErrRewrapSwapUnsynced alone, never ErrRewrapResumeFailed or
// ErrRewrapNotStarted, and the master is the key it was given.
func TestRewrapOwnSwapUnsynced(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	seedRewrap(t, s)
	s.step = failAt("rename " + masterNextFingerprintName)
	err := s.Rewrap(ctx, rewrapKey(1))
	if !errors.Is(err, ErrRewrapSwapUnsynced) || errors.Is(err, ErrRewrapResumeFailed) || errors.Is(err, ErrRewrapNotStarted) {
		t.Fatalf("Rewrap failing after its own swap = %v, want ErrRewrapSwapUnsynced alone", err)
	}
	// The marker's text fits this run's own swap too.
	if strings.Contains(err.Error(), "earlier") {
		t.Fatalf("Rewrap failing after its own swap = %v: names an earlier rewrap", err)
	}
	checkMasterIs(t, server, rewrapKey(1))
	checkUnderKey(t, server, rewrapKey(1))
	// A crash before the second rename is not a completed swap.
	s2, _ := newTestStore(t)
	seedRewrap(t, s2)
	s2.step = failAt("rename " + masterNextName)
	if err := s2.Rewrap(ctx, rewrapKey(1)); err == nil || errors.Is(err, ErrRewrapSwapUnsynced) {
		t.Fatalf("Rewrap failing between the master renames = %v, want an error that is not ErrRewrapSwapUnsynced", err)
	}
}

// TestRecordsSealedUnder: RecordsSealedUnder reports a key that some
// committed record opens under, beside the live master, which is how a
// Rewrap whose master.next was replaced or removed is recognised, and
// reports no other key: not one never used, not the live master, not the
// key of a Rewrap that renamed nothing in. It writes nothing.
func TestRecordsSealedUnder(t *testing.T) {
	ctx := context.Background()
	crashed := func(t *testing.T, at string, damage func(server string)) (*FileStore, string) {
		t.Helper()
		s, server := newTestStore(t)
		seedRewrap(t, s)
		s.step = func(name string) error {
			if name == at {
				damage(server)
				return fmt.Errorf("injected crash at %s", name)
			}
			return nil
		}
		if err := s.Rewrap(ctx, rewrapKey(1)); err == nil {
			t.Fatal("Rewrap succeeded through a crash")
		}
		s.step = func(string) error { return nil }
		return s, server
	}
	removeNext := func(server string) {
		for _, n := range []string{masterNextName, masterNextFingerprintName} {
			if err := os.Remove(masterPath(server, n)); err != nil {
				t.Error(err)
			}
		}
	}
	for name, tc := range map[string]struct {
		at     string
		damage func(server string)
		key    []byte
		want   bool
	}{
		"removed after one record moved":   {"rename a/v1", removeNext, rewrapKey(1), true},
		"removed after every record moved": {"rename b/current", removeNext, rewrapKey(1), true},
		"replaced after one record moved":  {"rename a/v1", func(server string) { plantNext(t, server, rewrapKey(9)) }, rewrapKey(1), true},
		"another key":                      {"rename a/v1", removeNext, rewrapKey(2), false},
		"the planted key":                  {"rename a/v1", func(server string) { plantNext(t, server, rewrapKey(9)) }, rewrapKey(9), false},
		"nothing renamed in yet":           {"write v1.new", removeNext, rewrapKey(1), false},
	} {
		t.Run(name, func(t *testing.T) {
			s, server := crashed(t, tc.at, tc.damage)
			snap := treeSnapshot(t, filepath.Dir(server))
			got, err := s.RecordsSealedUnder(ctx, tc.key)
			if err != nil || got != tc.want {
				t.Fatalf("RecordsSealedUnder = %v, %v; want %v", got, err, tc.want)
			}
			checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
		})
	}
	t.Run("a clean keystore and the live master", func(t *testing.T) {
		s, server := newTestStore(t)
		seedRewrap(t, s)
		live, err := os.ReadFile(masterPath(server, masterName))
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range [][]byte{rewrapKey(1), live} {
			if got, err := s.RecordsSealedUnder(ctx, key); err != nil || got {
				t.Fatalf("RecordsSealedUnder(%x) = %v, %v; want false", key[:1], got, err)
			}
		}
	})
}
