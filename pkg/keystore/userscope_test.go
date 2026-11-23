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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func userScope(t *testing.T, s *FileStore, uid uint32) *UserScope {
	t.Helper()
	startScopes(t, s)
	u, err := s.UserScope(uid)
	if err != nil {
		t.Fatalf("UserScope(%d): %v", uid, err)
	}
	return u
}

func userPut(t *testing.T, u *UserScope, entry string, value string) Version {
	t.Helper()
	v, err := u.Put(context.Background(), entry, KindOpaque, []byte(value))
	if err != nil {
		t.Fatalf("Put %s: %v", entry, err)
	}
	return v
}

// scopeDir is uid's scope directory under the server work dir.
func scopeDir(server, uid string) string {
	return filepath.Join(server, "keystore", userScopesName, uid)
}

// copyTree copies the directory src to dst, keeping each file's and
// directory's mode, so the copy passes the store's owner and mode checks and
// only its keys are in question.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := os.Mkdir(to, fi.Mode().Perm()); err != nil {
				return err
			}
			giveToService(t, to)
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(to, b, fi.Mode().Perm()); err != nil {
			return err
		}
		giveToService(t, to)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// U6: scope.key is a kind-0xFE record sealed under W, the scope-wrap key
// derived from the master, with the account's GeneratedUID as its
// generation, and a live GeneratedUID that differs from it refuses the scope
// with ErrScopeOwnerChanged.
func TestScopeKeyGeneratedUIDMismatch(t *testing.T) {
	ctx := context.Background()
	s, server := newMasteredStore(t)
	owner := guid(0xA1)
	table := map[uint32][generationSize]byte{1001: owner}
	fakeGUIDs(t, table)
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/token", "first value")

	b, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseScopeKey(b)
	if err != nil {
		t.Fatalf("parse scope.key: %v", err)
	}
	if r.kind != kindScopeKey || r.name != scopeKeyRecordName || r.version != scopeKeyEpoch || r.generation != owner {
		t.Fatalf("scope.key is kind %#x name %q version %d generation %x, want 0xfe, scope, 1, %x", r.kind, r.name, r.version, r.generation, owner)
	}
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.wrap, hmacSHA256(mustMaster(t, server), []byte(scopeWrapLabel))) {
		t.Fatal("the wrap key is not HMAC(M, k3sm-keystore-scope-wrap-v1)")
	}
	pt, err := r.open(k.wrap, "user/1001")
	if err != nil || len(pt) != scopeKeySize {
		t.Fatalf("scope.key under W: %d bytes, %v; want %d bytes", len(pt), err, scopeKeySize)
	}
	if _, err := r.open(k.seal, "user/1001"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("scope.key opened under the system seal key: %v", err)
	}
	if _, err := r.open(k.wrap, "user/1002"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("scope.key opened as another scope: %v", err)
	}

	// The uid now names another account: nothing in the scope opens, and
	// nothing is minted over it.
	table[1001] = guid(0xB2)
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, ErrScopeOwnerChanged) {
		t.Fatalf("Current with a changed owner: %v, want ErrScopeOwnerChanged", err)
	}
	if _, err := u.List(ctx); !errors.Is(err, ErrScopeOwnerChanged) {
		t.Fatalf("List with a changed owner: %v, want ErrScopeOwnerChanged", err)
	}
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("x")); !errors.Is(err, ErrScopeOwnerChanged) {
		t.Fatalf("Put with a changed owner: %v, want ErrScopeOwnerChanged", err)
	}
	if after, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), scopeKeyName)); err != nil || !bytes.Equal(after, b) {
		t.Fatalf("scope.key changed after a refused Put: %v", err)
	}

	// A synthesized answer is not a changed owner.
	table[1001] = synthesizedGUID(1001)
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, ErrScopeOwnerUnknown) || errors.Is(err, ErrScopeOwnerChanged) {
		t.Fatalf("Current with a synthesized GeneratedUID: %v, want ErrScopeOwnerUnknown", err)
	}

	table[1001] = owner
	if _, v, err := u.Current(ctx, "user/1001/token"); err != nil || string(v) != "first value" {
		t.Fatalf("Current with the owner back: %q, %v", v, err)
	}
}

// synthesizedGUID is the compatibility UUID the membership API makes up for
// a uid with no directory record.
func synthesizedGUID(uid uint32) [generationSize]byte {
	g := [generationSize]byte{0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC, 0xBB, 0xBB, 0xAA, 0xAA}
	g[12], g[13], g[14], g[15] = byte(uid>>24), byte(uid>>16), byte(uid>>8), byte(uid)
	return g
}

func mustMaster(t *testing.T, server string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(server, "cred", "keystore-master", masterName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// U7: the GeneratedUID lookup has one deadline, 250 ms; past it, or on an
// error or a synthesized answer, it fails closed with ErrScopeOwnerUnknown,
// and nothing in the scope opens or is minted.
func TestGeneratedUIDLookupDeadlineFailsClosed(t *testing.T) {
	if generatedUIDDeadline != 250*time.Millisecond {
		t.Fatalf("the GeneratedUID deadline is %s, want 250ms", generatedUIDDeadline)
	}
	// stall installs a lookup that answers only after the test ends, and a
	// deadline that has passed.
	stall := func(t *testing.T) *time.Duration {
		release := make(chan struct{})
		t.Cleanup(func() { close(release); waitLookupsIdle(t) })
		setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) {
			<-release
			return guid(0xA1), nil
		})
		asked := new(time.Duration)
		setSeam(t, &timerSeam, firesAt(asked))
		return asked
	}

	t.Run("past the deadline", func(t *testing.T) {
		asked := stall(t)
		if _, err := lookupGeneratedUID(1001); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("lookup past the deadline: %v, want ErrScopeOwnerUnknown", err)
		}
		if *asked != 250*time.Millisecond {
			t.Fatalf("the lookup asked for a %s deadline, want 250ms", *asked)
		}
	})
	t.Run("in error", func(t *testing.T) {
		setSeam(t, &timerSeam, neverFires)
		setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) {
			return [generationSize]byte{}, errors.New("opendirectoryd is not up")
		})
		if _, err := lookupGeneratedUID(1001); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("lookup in error: %v, want ErrScopeOwnerUnknown", err)
		}
	})
	t.Run("synthesized or zero", func(t *testing.T) {
		for _, g := range [][generationSize]byte{synthesizedGUID(48213), synthesizedGUID(0), {}} {
			fakeGUIDs(t, map[uint32][generationSize]byte{1001: g})
			if _, err := lookupGeneratedUID(1001); !errors.Is(err, ErrScopeOwnerUnknown) {
				t.Fatalf("lookup answering %x: %v, want ErrScopeOwnerUnknown", g, err)
			}
		}
	})
	t.Run("in time", func(t *testing.T) {
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
		if g, err := lookupGeneratedUID(1001); err != nil || g != guid(0xA1) {
			t.Fatalf("lookup in time: %x, %v", g, err)
		}
	})
	t.Run("no mint past the deadline", func(t *testing.T) {
		s, server := newMasteredStore(t)
		stall(t)
		u := userScope(t, s, 1001)
		if _, err := u.Put(context.Background(), "user/1001/token", KindOpaque, []byte("v")); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("Put past the deadline: %v, want ErrScopeOwnerUnknown", err)
		}
		if _, err := os.Lstat(filepath.Join(server, "keystore", userScopesName)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a Put refused for the lookup created %s: %v", userScopesName, err)
		}
	})
	t.Run("nothing opens past the deadline", func(t *testing.T) {
		s, _ := newMasteredStore(t)
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
		u := userScope(t, s, 1001)
		userPut(t, u, "user/1001/token", "v")
		stall(t)
		if _, _, err := u.Current(context.Background(), "user/1001/token"); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("Current past the deadline: %v, want ErrScopeOwnerUnknown", err)
		}
		if _, err := u.List(context.Background()); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("List past the deadline: %v, want ErrScopeOwnerUnknown", err)
		}
	})
}

// U8: a scope's records open only under its own K_u, and a copy of a
// .user/<uid>/ directory, scope.key included, opens nothing without the
// master it was wrapped under.
func TestScopeCopyWithoutMasterOpensNothing(t *testing.T) {
	ctx := context.Background()
	table := map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xB2)}
	a, serverA := newMasteredStore(t)
	fakeGUIDs(t, table)
	u501 := userScope(t, a, 1001)
	userPut(t, u501, "user/1001/token", "the value")
	u502 := userScope(t, a, 1002)
	userPut(t, u502, "user/1002/mine", "1002's value")

	// Another keystore, its own master, the same uid and owner.
	b, serverB := newMasteredStore(t)
	mustPut(t, b, "system-entry", KindOpaque, []byte("x"))
	if err := os.Mkdir(filepath.Join(serverB, "keystore", userScopesName), 0o700); err != nil {
		t.Fatal(err)
	}
	// The service user owns .user/, as the store would have made it.
	giveToService(t, filepath.Join(serverB, "keystore", userScopesName))
	copyTree(t, scopeDir(serverA, "1001"), scopeDir(serverB, "1001"))
	ub := userScope(t, b, 1001)
	if _, v, err := ub.Current(ctx, "user/1001/token"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a copied scope opened under another master: %q, %v; want ErrCorrupt", v, err)
	}
	if _, err := ub.List(ctx); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("List of a copied scope under another master: %v, want ErrCorrupt", err)
	}

	// One user's entry moved into another user's scope does not open there.
	copyTree(t, filepath.Join(scopeDir(serverA, "1001"), scopeEntriesName, "token"), filepath.Join(scopeDir(serverA, "1002"), scopeEntriesName, "token"))
	if _, v, err := u502.Current(ctx, "user/1002/token"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("1001's record opened in 1002's scope: %q, %v; want ErrCorrupt", v, err)
	}

	// Nor does one user's scope.key in another's place.
	k501, err := os.ReadFile(filepath.Join(scopeDir(serverA, "1001"), scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scopeDir(serverA, "1002"), scopeKeyName), k501, 0o600); err != nil {
		t.Fatal(err)
	}
	table[1002] = table[1001]
	if _, v, err := u502.Current(ctx, "user/1002/token"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("1001's scope.key opened as 1002's: %q, %v; want ErrCorrupt", v, err)
	}
}

// U9: equal values in two scopes have different fingerprints, so List is no
// equality oracle across users.
func TestFingerprintsDifferAcrossScopes(t *testing.T) {
	ctx := context.Background()
	s, _ := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xB2)})
	const value = "the same low-entropy value"
	sys := mustPut(t, s, "same", KindOpaque, []byte(value))
	v501 := userPut(t, userScope(t, s, 1001), "user/1001/same", value)
	v502 := userPut(t, userScope(t, s, 1002), "user/1002/same", value)
	seen := map[string]string{}
	for who, fp := range map[string]string{"system": sys.Fingerprint, "user/1001": v501.Fingerprint, "user/1002": v502.Fingerprint} {
		if fp == "" {
			t.Fatalf("%s has no fingerprint", who)
		}
		if other, dup := seen[fp]; dup {
			t.Fatalf("%s and %s share the fingerprint %s for one value", who, other, fp)
		}
		seen[fp] = who
	}
	// List shows the same per-scope fingerprint Put returned.
	l, err := userScope(t, s, 1001).List(ctx)
	if err != nil || len(l) != 1 || l[0].Current.Fingerprint != v501.Fingerprint {
		t.Fatalf("List of user/1001: %+v, %v", l, err)
	}
}

// U10: a caller naming any scope but its own user scope gets ErrNotFound,
// worded exactly as an absent entry of its own, and the answer creates
// nothing.
func TestOtherUserIsNotFound(t *testing.T) {
	ctx := context.Background()
	s, server := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xB2)})
	mustPut(t, s, "sys", KindOpaque, []byte("system value"))
	u501 := userScope(t, s, 1001)
	userPut(t, u501, "user/1001/mine", "1001's value")
	userPut(t, userScope(t, s, 1002), "user/1002/theirs", "1002's value")

	_, _, absent := u501.Current(ctx, "user/1001/absent")
	if !errors.Is(absent, ErrNotFound) {
		t.Fatalf("an absent entry of the caller's own: %v, want ErrNotFound", absent)
	}
	for _, name := range []string{"user/1002/theirs", "user/1002/absent", "system/sys", "system/absent", "user/1003/x"} {
		_, v, err := u501.Current(ctx, name)
		if !errors.Is(err, ErrNotFound) || err.Error() != absent.Error() {
			t.Fatalf("Current %s as uid 1001: %q, %v; want %q", name, v, err, absent)
		}
		if _, err := u501.Put(ctx, name, KindOpaque, []byte("v")); !errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "100") || strings.Contains(err.Error(), "theirs") {
			t.Fatalf("Put %s as uid 1001: %v, want a bare ErrNotFound", name, err)
		}
	}
	if _, err := os.Lstat(scopeDir(server, "1003")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused name created a scope: %v", err)
	}
	if _, v, err := userScope(t, s, 1002).Current(ctx, "user/1002/theirs"); err != nil || string(v) != "1002's value" {
		t.Fatalf("1002's own entry: %q, %v", v, err)
	}
}

// newMasteredStore is newTestStore with the master already minted, as a
// root put mints it: a user Put never does.
func newMasteredStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	s, server := newTestStore(t)
	mustPut(t, s, "seed", KindOpaque, []byte("minted by a root put"))
	return s, server
}
