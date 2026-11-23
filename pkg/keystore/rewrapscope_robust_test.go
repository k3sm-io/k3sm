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

// Rewrap re-opens every planned scope.key under the new master's W before
// it retires the old one: a scope.key swapped back to its old copy, or
// corrupted, after its commit refuses the swap, and the old master stays.
func TestRewrapVerifiesScopeKeysBeforeSwap(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name  string
		after func(old []byte) []byte
	}{
		{"swapped back to the old copy", func(old []byte) []byte { return old }},
		{"corrupted", func(old []byte) []byte {
			b := bytes.Clone(old)
			b[len(b)-1] ^= 0xff
			return b
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, server, _, _ := seedScopeRewrap(t)
			master := mustMaster(t, server)
			key := filepath.Join(scopeDir(server, "1001"), scopeKeyName)
			old, err := os.ReadFile(key)
			if err != nil {
				t.Fatal(err)
			}
			s.step = func(name string) error {
				if name == "rename "+userScopesName+"/1001/"+scopeKeyName {
					return os.WriteFile(key, tt.after(old), 0o600)
				}
				return nil
			}
			err = s.Rewrap(ctx, rewrapKey(1))
			if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "does not open under the new master") {
				t.Fatalf("Rewrap with scope.key %s after its commit: %v, want ErrCorrupt", tt.name, err)
			}
			checkDamagedScopeRecovery(t, err)
			if !bytes.Equal(mustMaster(t, server), master) {
				t.Fatal("the master was swapped past a scope.key that does not open under it")
			}
		})
	}
}

// A directory under .user whose uid can never own a scope (below 501, the
// service uid, above 2147483647) refuses Rewrap as a stray directory to
// remove by hand; a damaged eligible scope names the real recovery.
func TestRewrapRefusesStrayScopeDirs(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"0", "500", "serviceuid", "2147483648", "4294967295"} {
		t.Run(name, func(t *testing.T) {
			s, server, _, _ := seedScopeRewrap(t)
			if name == "serviceuid" {
				name = strconv.FormatUint(uint64(s.uid), 10)
			}
			master := mustMaster(t, server)
			if err := os.Mkdir(scopeDir(server, name), 0o700); err != nil {
				t.Fatal(err)
			}
			err := s.Rewrap(ctx, rewrapKey(1))
			if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "stray directory") || !strings.Contains(err.Error(), userScopesName+"/"+name) {
				t.Fatalf("Rewrap over .user/%s: %v, want ErrCorrupt naming a stray directory", name, err)
			}
			if !bytes.Equal(mustMaster(t, server), master) {
				t.Fatal("the master was swapped past a stray directory")
			}
			if err := os.Remove(scopeDir(server, name)); err != nil {
				t.Fatal(err)
			}
			if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
				t.Fatalf("Rewrap after the stray directory is removed: %v", err)
			}
		})
	}
	t.Run("a damaged eligible scope", func(t *testing.T) {
		s, server, _, _ := seedScopeRewrap(t)
		key := filepath.Join(scopeDir(server, "1001"), scopeKeyName)
		b, err := os.ReadFile(key)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)-1] ^= 0xff
		if err := os.WriteFile(key, b, 0o600); err != nil {
			t.Fatal(err)
		}
		err = s.Rewrap(ctx, rewrapKey(1))
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Rewrap over a damaged scope.key: %v, want ErrCorrupt", err)
		}
		for _, want := range []string{"remove keystore/" + userScopesName + "/1001/", "rm-scope"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refusal %q does not say %q", err, want)
			}
		}
		if strings.Contains(err.Error(), "restore it first") {
			t.Fatalf("refusal %q still says restore it first", err)
		}
		checkDamagedScopeRecovery(t, err)
	})
}

// checkDamagedScopeRecovery asserts a damaged-scope refusal names the
// recovery that works: removing the scope by hand recovers only a user who
// never delivered (mint refuses over a floor past 1); otherwise it is
// removing it by hand then floor --rebuild, whose cost is said, since
// rm-scope refuses a scope with deliveries.
func checkDamagedScopeRecovery(t *testing.T, err error) {
	t.Helper()
	for _, want := range []string{"never delivered", "rm-scope", "sudo k3sm doctor", "floor --rebuild", "lowers every record's floor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "(its owner re-puts their values)") {
		t.Errorf("refusal %q still offers removal by hand as the recovery for every user", err)
	}
}

// Rewrap pins each scope's K_u, generation and created time from its plan
// to its commit and to the final check: a scope.key replaced after the plan
// by a record that opens under the new W but holds a different K_u refuses
// the swap, whether it lands before the scope's commit (which would read it
// as already committed) or after it.
func TestRewrapPinsScopeKeyFromPlan(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name, at string
	}{
		{"before the scope's commit", "rename b/"},
		{"after the scope's commit", "rename " + userScopesName + "/1001/" + scopeKeyName},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, server, _, _ := seedScopeRewrap(t)
			master := mustMaster(t, server)
			key := filepath.Join(scopeDir(server, "1001"), scopeKeyName)
			b, err := os.ReadFile(key)
			if err != nil {
				t.Fatal(err)
			}
			r, err := parseScopeKey(b)
			if err != nil {
				t.Fatal(err)
			}
			forged := record{kind: r.kind, name: r.name, version: r.version, generation: r.generation, created: r.created}
			nextW := hmacSHA256(rewrapKey(1), []byte(scopeWrapLabel))
			if err := forged.seal(nextW, userScopePrefix+"1001", bytes.Repeat([]byte{0x42}, scopeKeySize), s.rand); err != nil {
				t.Fatal(err)
			}
			done := false
			s.step = func(name string) error {
				if !done && strings.HasPrefix(name, tt.at) {
					done = true
					return os.WriteFile(key, forged.marshal(), 0o600)
				}
				return nil
			}
			err = s.Rewrap(ctx, rewrapKey(1))
			if !done {
				t.Fatalf("step %q was never reached", tt.at)
			}
			if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "user/1001") {
				t.Fatalf("Rewrap over a scope.key holding another K_u: %v, want ErrCorrupt naming the scope", err)
			}
			if !bytes.Equal(mustMaster(t, server), master) {
				t.Fatal("the master was swapped past a scope.key holding another K_u")
			}
		})
	}
}
