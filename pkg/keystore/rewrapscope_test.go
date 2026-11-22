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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// userRecords maps every file under uid 1001's scope directory but
// scope.key (and its .new) to its bytes: the records Rewrap must leave
// byte-identical.
func userRecords(t *testing.T, server string) map[string]string {
	t.Helper()
	out := map[string]string{}
	dir := scopeDir(server, "1001")
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if n := d.Name(); n == scopeKeyName || n == scopeKeyName+newSuffix {
			return nil
		}
		b, err := os.ReadFile(p)
		out[p] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// scopeKeyUnder opens uid 1001's scope.key under the scope-wrap key of
// master, returning K_u, or the error.
func scopeKeyUnder(t *testing.T, server string, master []byte) ([]byte, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseScopeKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.generation != guid(0xA1) {
		t.Fatalf("scope.key generation %x, want the bound GeneratedUID", r.generation)
	}
	return r.open(hmacSHA256(master, []byte(scopeWrapLabel)), "user/1001")
}

// seedScopeRewrap seeds the system entries of seedRewrap and uid 1001's
// scope with one entry and one delivery.
func seedScopeRewrap(t *testing.T) (*FileStore, string, *UserScope, rewrapValues) {
	t.Helper()
	s, server := newTestStore(t)
	vals := seedRewrap(t, s)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/token", "user value")
	if err := u.addDelivery(context.Background(), testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	return s, server, u, vals
}

// checkUserScopeReads reads uid 1001's entry and delivery.
func checkUserScopeReads(t *testing.T, u *UserScope) {
	t.Helper()
	ctx := context.Background()
	if _, v, err := u.Current(ctx, "user/1001/token"); err != nil || string(v) != "user value" {
		t.Fatalf("user Current: %q, %v", v, err)
	}
	if _, err := u.lookupDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("user lookupDelivery: %v", err)
	}
}

// U12: master Rewrap re-wraps every scope.key under the new W, keeping K_u
// and the bound generation, and leaves every other user record
// byte-identical. A crash at each durable step leaves the user scope
// readable (its scope.key under the old W, or under master.next's by the
// reader's rule), and a rerun completes it, as G12 does for the system
// records. A user put stays refused while master.next exists.
func TestRewrapRewrapsScopeKeysResumable(t *testing.T) {
	ctx := context.Background()
	var steps []string
	{
		s, server, u, vals := seedScopeRewrap(t)
		before := userRecords(t, server)
		old := mustMaster(t, server)
		kuOld, err := scopeKeyUnder(t, server, old)
		if err != nil {
			t.Fatal(err)
		}
		s.step = func(name string) error { steps = append(steps, name); return nil }
		if err := s.Rewrap(ctx, rewrapKey(1)); err != nil {
			t.Fatal(err)
		}
		s.step = func(string) error { return nil }
		checkMasterIs(t, server, rewrapKey(1))
		checkRewrapValues(t, s, vals)
		checkUserScopeReads(t, u)
		checkTreeUnchanged(t, before, userRecords(t, server))
		kuNew, err := scopeKeyUnder(t, server, rewrapKey(1))
		if err != nil {
			t.Fatalf("scope.key under the new W: %v", err)
		}
		if !bytes.Equal(kuNew, kuOld) {
			t.Fatal("Rewrap changed K_u; it re-seals scope.key only")
		}
		if _, err := scopeKeyUnder(t, server, old); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("scope.key still opens under the old W: %v", err)
		}
	}
	want := strings.Join([]string{
		"write " + masterNextName, "write " + masterNextFingerprintName,
		"write v1.new", "write current.new",
		"write v1.new", "write v2.new", "write current.new",
		"write " + scopeKeyName + newSuffix,
		"rename a/v1", "rename a/current",
		"rename b/v1", "rename b/v2", "rename b/current",
		"rename " + userScopesName + "/1001/" + scopeKeyName,
		"rename " + masterNextName, "rename " + masterNextFingerprintName,
	}, ",")
	if strings.Join(steps, ",") != want {
		t.Fatalf("Rewrap steps = %v, want %s", steps, want)
	}
	const firstRename = 8
	for i, step := range steps {
		t.Run(fmt.Sprintf("%02d %s", i, step), func(t *testing.T) {
			s, server, u, vals := seedScopeRewrap(t)
			before := userRecords(t, server)
			kuOld, err := scopeKeyUnder(t, server, mustMaster(t, server))
			if err != nil {
				t.Fatal(err)
			}
			s.step = failAtCall(i)
			if err := s.Rewrap(ctx, rewrapKey(1)); err == nil || !strings.Contains(err.Error(), "injected crash at "+step) {
				t.Fatalf("Rewrap through a crash at %s: %v, want the injected crash", step, err)
			}
			s.step = func(string) error { return nil }
			checkRewrapValues(t, s, vals)
			checkUserScopeReads(t, u)
			checkTreeUnchanged(t, before, userRecords(t, server))
			// Revocation goes ahead at every step, the scope.key moved
			// under master.next before the swap included (U13, U109).
			if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
				t.Fatalf("withdraw after a crash at %s: %v", step, err)
			}
			if d, err := u.lookupDelivery(ctx, testDelivery(1).uid); err != nil || !d.withdrawn {
				t.Fatalf("delivery after the withdraw: withdrawn %v, %v", d.withdrawn, err)
			}
			before = userRecords(t, server)
			_, nerr := os.Lstat(masterPath(server, masterNextName))
			_, ferr := os.Lstat(masterPath(server, masterNextFingerprintName))
			if nerr == nil || ferr == nil {
				if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, ErrRewrapInProgress) {
					t.Fatalf("user put while master.next exists: %v, want ErrRewrapInProgress", err)
				}
			}

			err = s.Rewrap(ctx, rewrapKey(2))
			key := rewrapKey(2)
			if i >= firstRename && i < len(steps)-1 {
				key = rewrapKey(1)
				if !errors.Is(err, ErrRewrapResumed) {
					t.Fatalf("Rewrap rerun after a commit began: %v, want ErrRewrapResumed", err)
				}
			} else if err != nil {
				t.Fatalf("Rewrap rerun: %v", err)
			}
			checkMasterIs(t, server, key)
			checkRewrapValues(t, s, vals)
			checkUserScopeReads(t, u)
			checkTreeUnchanged(t, before, userRecords(t, server))
			ku, err := scopeKeyUnder(t, server, key)
			if err != nil || !bytes.Equal(ku, kuOld) {
				t.Fatalf("scope.key under the final master: %v, or K_u changed", err)
			}
			if m, _ := filepath.Glob(filepath.Join(scopeDir(server, "1001"), "*"+newSuffix)); len(m) != 0 {
				t.Fatalf("left behind: %v", m)
			}
		})
	}
	t.Run("a scope.key that does not open refuses before anything is written", func(t *testing.T) {
		s, server, _, _ := seedScopeRewrap(t)
		flipLastByte(t, filepath.Join(scopeDir(server, "1001"), scopeKeyName))
		snap := treeSnapshot(t, filepath.Dir(server))
		if err := s.Rewrap(ctx, rewrapKey(1)); !errors.Is(err, ErrCorrupt) || !errors.Is(err, ErrRewrapNotStarted) {
			t.Fatalf("Rewrap over a damaged scope.key: %v, want ErrCorrupt before anything is written", err)
		}
		checkTreeUnchanged(t, snap, treeSnapshot(t, filepath.Dir(server)))
	})
}
