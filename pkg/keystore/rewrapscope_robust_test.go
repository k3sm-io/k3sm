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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Rewrap over a damaged user-scope tree refuses with a typed ErrCorrupt
// that names the repair, never an untyped error every retry repeats: an
// unexpected scope.key.new directory, a .user listing past the name bound,
// a planned scope gone by the commit, and a scope.key.new with a second
// link.
func TestRewrapRefusesDamagedScopeTree(t *testing.T) {
	ctx := context.Background()
	t.Run("scope.key.new is a non-empty directory", func(t *testing.T) {
		s, server, _, _ := seedScopeRewrap(t)
		p := filepath.Join(scopeDir(server, "1001"), scopeKeyName+newSuffix)
		if err := os.MkdirAll(filepath.Join(p, "x"), 0o700); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			err := s.Rewrap(ctx, rewrapKey(1))
			if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "remove") {
				t.Fatalf("Rewrap over a scope.key.new directory: %v, want ErrCorrupt naming the repair", err)
			}
		}
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
		if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
			t.Fatalf("Rewrap after the repair: %v", err)
		}
	})
	t.Run(".user lists past the name bound", func(t *testing.T) {
		setSeam(t, &scopeDirNamesBound, 4)
		s, server, _, _ := seedScopeRewrap(t)
		users := filepath.Join(server, "keystore", userScopesName)
		for i := 0; i <= scopeDirNamesBound; i++ {
			if err := os.WriteFile(filepath.Join(users, "n"+strconv.Itoa(i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err := s.Rewrap(ctx, rewrapKey(1))
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "remove") {
			t.Fatalf("Rewrap over a full .user: %v, want ErrCorrupt naming the repair", err)
		}
	})
	t.Run("a planned scope is gone at the commit", func(t *testing.T) {
		s, server, _, _ := seedScopeRewrap(t)
		old := mustMaster(t, server)
		s.step = func(name string) error {
			if name == "rename "+userScopesName+"/1001/"+scopeKeyName {
				return os.RemoveAll(scopeDir(server, "1001"))
			}
			return nil
		}
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Rewrap with a scope removed mid-run: %v, want ErrCorrupt", err)
		}
		if !bytes.Equal(mustMaster(t, server), old) {
			t.Fatal("the master was swapped past the missing scope")
		}
	})
	t.Run("scope.key.new has a second link", func(t *testing.T) {
		s, server, _, _ := seedScopeRewrap(t)
		s.step = func(name string) error {
			if name == "rename a/v1" {
				return os.Link(filepath.Join(scopeDir(server, "1001"), scopeKeyName+newSuffix), filepath.Join(server, "kept"))
			}
			return nil
		}
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "link") {
			t.Fatalf("Rewrap with a linked scope.key.new: %v, want ErrCorrupt", err)
		}
		if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeKeyName+newSuffix)); err != nil {
			t.Fatalf("the linked scope.key.new was renamed in or removed: %v", err)
		}
	})
}
