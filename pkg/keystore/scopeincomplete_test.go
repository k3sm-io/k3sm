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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A scope that lost part of itself, a scope.key with no deliveries record
// or no entries/ directory beside it, or entries with no scope.key, is
// ErrScopeAbsent and also
// ScopeIncomplete, the damage the socket logs; a uid with no scope yet is
// ErrScopeAbsent and NoScopeKey, and never ScopeIncomplete.
func TestScopeIncompleteIsNotNoScopeKey(t *testing.T) {
	ctx := context.Background()
	for _, gone := range []string{deliveriesName, scopeEntriesName, scopeKeyName} {
		t.Run(gone, func(t *testing.T) {
			s, server := newMasteredStore(t)
			fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xA2)})
			u := userScope(t, s, 1001)
			userPut(t, u, "user/1001/a", "v")
			if err := os.RemoveAll(filepath.Join(scopeDir(server, "1001"), gone)); err != nil {
				t.Fatal(err)
			}
			_, _, err := u.Current(ctx, "user/1001/a")
			if !errors.Is(err, ErrScopeAbsent) || !ScopeIncomplete(err) || NoScopeKey(err) {
				t.Fatalf("a read of a scope with no %s = %v, want ErrScopeAbsent and an incomplete scope", gone, err)
			}
			fresh, err := s.UserScope(1002)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = fresh.Current(ctx, "user/1002/a")
			if !errors.Is(err, ErrScopeAbsent) || !NoScopeKey(err) || ScopeIncomplete(err) {
				t.Fatalf("a read of a uid with no scope = %v, want ErrScopeAbsent with no scope key, not incomplete", err)
			}
		})
	}
}

// A scope directory with no scope.key and an empty entries/, what a mint
// that crashed before its scope.key leaves, is still a uid with no scope
// yet (NoScopeKey), not an incomplete scope, and the next put mints over
// it.
func TestCrashedMintIsNoScopeKey(t *testing.T) {
	ctx := context.Background()
	s, server := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/a", "v")
	if err := u.Delete(ctx, "user/1001/a"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(scopeDir(server, "1001"), scopeKeyName)); err != nil {
		t.Fatal(err)
	}
	_, _, err := u.Current(ctx, "user/1001/a")
	if !NoScopeKey(err) || ScopeIncomplete(err) {
		t.Fatalf("a read of a scope with an empty entries/ and no scope key = %v, want no scope key, not incomplete", err)
	}
}
