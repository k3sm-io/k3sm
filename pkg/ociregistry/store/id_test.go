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

package store

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestEnsureIDWritesOnceAndKeepsIt covers the store id: absent on a new
// store, minted once by EnsureID as 32 hex digits in a 0600 file, stable
// across calls and reopens, the same for concurrent callers, not a
// repository, and an error when the file is not an id.
func TestEnsureIDWritesOnceAndKeepsIt(t *testing.T) {
	dir := t.TempDir()
	root, state := filepath.Join(dir, "registry"), filepath.Join(dir, "registry-state")
	s, err := Open(root, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ID(); err != nil || ok {
		t.Fatalf("ID on a new store: ok %v, %v; want none", ok, err)
	}
	if _, err := os.Lstat(filepath.Join(root, IDFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open wrote %s: %v", IDFile, err)
	}

	ids := make([]string, 8)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Go(func() {
			id, err := s.EnsureID()
			if err != nil {
				t.Error(err)
			}
			ids[i] = id
		})
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("concurrent EnsureID returned %v, want one id", ids)
		}
	}
	if _, ok := parseID([]byte(ids[0] + "\n")); !ok {
		t.Fatalf("id %q is not 32 hex digits", ids[0])
	}
	fi, err := os.Lstat(filepath.Join(root, IDFile))
	if err != nil || fi.Mode() != fileMode {
		t.Fatalf("%s: %v, %v; want a 0600 regular file", IDFile, fi, err)
	}
	ents, err := os.ReadDir(root)
	if err != nil || len(ents) != 1 {
		t.Fatalf("root holds %v, %v; want only %s (no temp file left)", ents, err, IDFile)
	}
	s2, err := Open(root, state)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok, err := s2.ID(); err != nil || !ok || id != ids[0] {
		t.Fatalf("ID after a reopen: %q %v %v, want %q", id, ok, err, ids[0])
	}
	if repos, err := s.Repositories(); err != nil || len(repos) != 0 {
		t.Fatalf("Repositories: %v, %v; want none", repos, err)
	}

	for _, body := range []string{"", "short\n", "0123456789abcdef0123456789ABCDEF\n", "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef\n\n"} {
		if err := os.WriteFile(filepath.Join(root, IDFile), []byte(body), fileMode); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.ID(); !errors.Is(err, ErrBadID) {
			t.Errorf("ID over %q: %v, want ErrBadID", body, err)
		}
		if _, err := s.EnsureID(); err == nil {
			t.Errorf("EnsureID over %q succeeded, want an error", body)
		}
	}
}
