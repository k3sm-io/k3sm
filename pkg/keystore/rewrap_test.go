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

// TestRewrapRefusesWhileUserScopesExist: the entries' directory name reserved
// for user scopes, whatever its type, makes Rewrap refuse with
// ErrScopeUnsupported, saying to upgrade, and write nothing.
func TestRewrapRefusesWhileUserScopesExist(t *testing.T) {
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
			vals := seedRewrap(t, s)
			plant(t, filepath.Join(server, "keystore", userScopesName))
			snap := treeSnapshot(t, filepath.Dir(server))
			err := s.Rewrap(context.Background(), rewrapKey(1))
			if !errors.Is(err, ErrScopeUnsupported) {
				t.Fatalf("Rewrap with %s present: %v, want ErrScopeUnsupported", userScopesName, err)
			}
			for _, want := range []string{"upgrade k3sm", "keystore/" + userScopesName, "root must remove it", filepath.Join(server, "keystore", userScopesName)} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Rewrap refusal %q does not say %q", err, want)
				}
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
	t.Run("user scopes on a store with no lock file yet create nothing", func(t *testing.T) {
		s, server := newTestStore(t)
		if err := os.Mkdir(filepath.Join(server, "keystore"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(server, "keystore", userScopesName), 0o700); err != nil {
			t.Fatal(err)
		}
		snap := treeSnapshot(t, filepath.Dir(server))
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrScopeUnsupported) {
			t.Fatalf("Rewrap: %v, want ErrScopeUnsupported", err)
		}
		checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
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

// TestRewrapUserScopesBeforeSwap: a .user created while a Rewrap runs stops
// it before the master swap with ErrScopeUnsupported. The master is left as
// it was, master.next is left agreeing, every record reads, and once .user is
// gone a rerun with the same key completes the Rewrap.
func TestRewrapUserScopesBeforeSwap(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	vals := seedRewrap(t, s)
	old, err := os.ReadFile(masterPath(server, masterName))
	if err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(server, "keystore", userScopesName)
	s.step = func(name string) error {
		if name == "rename b/current" { // the last commit step
			if err := os.Mkdir(user, 0o700); err != nil {
				t.Error(err)
			}
		}
		return nil
	}
	if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrScopeUnsupported) {
		t.Fatalf("Rewrap with %s created before the swap: %v, want ErrScopeUnsupported", userScopesName, err)
	}
	s.step = func(string) error { return nil }
	if now, _ := os.ReadFile(masterPath(server, masterName)); !bytes.Equal(now, old) {
		t.Fatalf("master = %x, want the old master left in place", now)
	}
	if got, err := os.ReadFile(masterPath(server, masterNextName)); err != nil || !bytes.Equal(got, rewrapKey(1)) {
		t.Fatalf("master.next = %x, %v; want the new key left for the rerun", got, err)
	}
	checkRewrapValues(t, s, vals)
	if err := os.Remove(user); err != nil {
		t.Fatal(err)
	}
	if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
		t.Fatalf("Rewrap rerun with the same key: %v", err)
	}
	checkMasterIs(t, server, rewrapKey(1))
	checkUnderKey(t, server, rewrapKey(1))
	checkRewrapValues(t, s, vals)
}
