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

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAdoptStoreOwner pins the cross-user contract: a root writer adopts the
// existing store's owner (else the directory's), and a non-root writer changes
// nothing. Privilege is faked at the geteuid/chown seams.
func TestAdoptStoreOwner(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "bootstrap-tokens.json")
	tmp := filepath.Join(dir, "bootstrap-tokens.json.tmp1")
	if err := os.WriteFile(tmp, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}

	restore := func() { geteuid = os.Geteuid; chown = os.Chown }
	defer restore()

	t.Run("non-root writer never chowns", func(t *testing.T) {
		geteuid = func() int { return 501 }
		called := false
		chown = func(string, int, int) error { called = true; return nil }
		if err := adoptStoreOwner(tmp, store); err != nil {
			t.Fatalf("adoptStoreOwner: %v", err)
		}
		if called {
			t.Fatal("a non-root writer must not chown")
		}
	})

	t.Run("root adopts the existing store's owner", func(t *testing.T) {
		if err := os.WriteFile(store, []byte("[]"), 0o600); err != nil {
			t.Fatal(err)
		}
		geteuid = func() int { return 0 }
		var gotPath string
		gotUID, gotGID := -1, -1
		chown = func(p string, uid, gid int) error { gotPath, gotUID, gotGID = p, uid, gid; return nil }
		if err := adoptStoreOwner(tmp, store); err != nil {
			t.Fatalf("adoptStoreOwner: %v", err)
		}
		if gotPath != tmp {
			t.Fatalf("chowned %q, want the temp %q", gotPath, tmp)
		}
		// The reference is the store file we just wrote as ourselves.
		if gotUID != os.Getuid() || gotGID != os.Getgid() {
			t.Fatalf("adopted %d:%d, want the store's %d:%d", gotUID, gotGID, os.Getuid(), os.Getgid())
		}
	})

	t.Run("root falls back to the directory owner for a first write", func(t *testing.T) {
		if err := os.Remove(store); err != nil {
			t.Fatal(err)
		}
		geteuid = func() int { return 0 }
		var gotPath string
		chown = func(p string, uid, gid int) error { gotPath = p; return nil }
		if err := adoptStoreOwner(tmp, store); err != nil {
			t.Fatalf("adoptStoreOwner: %v", err)
		}
		if gotPath != tmp {
			t.Fatalf("chowned %q, want the temp %q", gotPath, tmp)
		}
	})
}
