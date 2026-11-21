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

			if err := s.Rewrap(ctx, rewrapKey(2)); err != nil {
				t.Fatalf("Rewrap rerun: %v", err)
			}
			// Before master.next.sha256 is written there is no agreed key to
			// resume with, so the rerun mints its own; after the second master
			// rename the first Rewrap had completed, and the rerun is a new
			// one. In between it resumes with the first key.
			key := rewrapKey(1)
			if i < 2 || i == len(steps)-1 {
				key = rewrapKey(2)
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
		if err := s.Rewrap(ctx, rewrapKey(2)); err != nil {
			t.Fatalf("Rewrap rerun: %v", err)
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
			if !strings.Contains(err.Error(), "upgrade k3sm") {
				t.Fatalf("Rewrap refusal %q does not say to upgrade k3sm", err)
			}
			checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
			checkRewrapValues(t, s, vals)
		})
	}
}
