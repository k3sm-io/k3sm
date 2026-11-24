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
	"crypto/sha256"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// countUsageLstats counts the scope usage walk's file Lstats, under the
// store lock and outside it.
func countUsageLstats(s *FileStore) (under, outside *atomic.Int64) {
	under, outside = new(atomic.Int64), new(atomic.Int64)
	s.usageLstat = func(underLock bool) {
		if underLock {
			under.Add(1)
		} else {
			outside.Add(1)
		}
	}
	return under, outside
}

// U15's cost: a rotate and a put on a scope at its byte quota are refused
// ErrQuota with no file Lstat of the scope's walk under the store lock.
// The figure is missing at first, as in a server just started: the walk
// that builds it runs before the lock, once, and the put after the rotate
// walks nothing at all.
func TestRotateAtQuotaNoFullWalk(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	server := filepath.Dir(s.dir)
	// The scope at quota: one more file in the entry's directory, of the
	// byte budget's size (sparse, so it costs no disk).
	pad := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "a", "pad")
	f, err := os.Create(pad)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxScopeBytes); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	s.usage.forget(1001) // a server just started holds no figure
	under, outside := countUsageLstats(s)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("two")); !errors.Is(err, ErrQuota) {
		t.Fatalf("a rotate at quota: %v, want ErrQuota", err)
	}
	if under.Load() != 0 {
		t.Fatalf("the rotate at quota did %d file Lstats of the scope's walk under the store lock, want none", under.Load())
	}
	if outside.Load() == 0 {
		t.Fatal("no walk built the figure before the lock")
	}
	walked := outside.Load()
	if _, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("b")); !errors.Is(err, ErrQuota) {
		t.Fatalf("a put at quota: %v, want ErrQuota", err)
	}
	if under.Load() != 0 || outside.Load() != walked {
		t.Fatalf("the put at quota walked the scope (%d under the lock, %d before it), want no walk", under.Load(), outside.Load()-walked)
	}
	// rm frees the room, and the figure follows it.
	if err := u.Delete(ctx, "user/1001/a"); err != nil {
		t.Fatalf("rm at quota: %v", err)
	}
	if _, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("b")); err != nil {
		t.Fatalf("a put after the rm: %v", err)
	}
	if under.Load() != 0 {
		t.Fatalf("the put after rm walked the scope under the lock (%d Lstats)", under.Load())
	}
}

// The figure each put, rotate and rm keeps is what a walk of the scope
// counts; a figure bound to another scope.key (one rm-scope removed, or a
// Rewrap re-sealed) is not trusted, and the scope is walked again.
func TestUsageFigureMatchesWalk(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	userPut(t, u, "user/1001/b", "bee")
	for _, v := range []string{"two", "three"} {
		if _, err := u.Rotate(ctx, "user/1001/a", []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	userPut(t, u, "user/1001/c", "sea")
	if err := u.Delete(ctx, "user/1001/b"); err != nil {
		t.Fatal(err)
	}
	figure := func() map[string]int64 {
		s.usage.mu.Lock()
		defer s.usage.mu.Unlock()
		if f := s.usage.byUID[1001]; f != nil {
			return maps.Clone(f.entries)
		}
		return nil
	}
	walk := func() map[string]int64 {
		root, err := s.openDir(s.dir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		f, err := u.walkUsage(context.Background(), root, false)
		if err != nil {
			t.Fatal(err)
		}
		return f.entries
	}
	if got, want := figure(), walk(); !maps.Equal(got, want) {
		t.Fatalf("the figure is %v, a walk counts %v", got, want)
	}
	// Bound to another scope.key: the next judgement walks under the lock.
	s.usage.mu.Lock()
	s.usage.byUID[1001].bind.key = sha256.Sum256([]byte("another scope.key"))
	s.usage.byUID[1001].entries["a"] = 0 // and stale low: never trusted
	s.usage.mu.Unlock()
	under, outside := countUsageLstats(s)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("four")); err != nil {
		t.Fatal(err)
	}
	if walked(under, outside) == 0 {
		t.Fatal("a figure bound to another scope.key was trusted: no walk")
	}
	if got, want := figure(), walk(); !maps.Equal(got, want) {
		t.Fatalf("after the re-walk the figure is %v, a walk counts %v", got, want)
	}
}

// list authenticates each entry's current version only and checks the
// others for presence: an older version removed marks the entry
// ErrCorrupt, and one present but damaged costs no record open and is left
// to the read or rotate that reaches it.
func TestUserListOpensOnlyCurrentVersion(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	for _, v := range []string{"two", "three"} {
		if _, err := u.Rotate(ctx, "user/1001/a", []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(scopeDir(filepath.Dir(s.dir), "1001"), scopeEntriesName, "a")
	// Damaged, not missing: v2's bytes replaced, its file kept.
	if err := os.WriteFile(filepath.Join(dir, versionName(2)), []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	es, err := u.List(ctx)
	if err != nil || len(es) != 1 {
		t.Fatalf("List: %+v, %v", es, err)
	}
	if e := es[0]; e.Err != nil || e.Current.Version != 3 || e.VersionCount != 3 || e.Versions != nil {
		t.Fatalf("with v2 damaged the entry is %+v, want version 3 of 3, no version list, no error", e)
	}
	if err := os.Remove(filepath.Join(dir, versionName(1))); err != nil {
		t.Fatal(err)
	}
	es, err = u.List(ctx)
	if err != nil || len(es) != 1 || !errors.Is(es[0].Err, ErrCorrupt) {
		t.Fatalf("with v1 removed: %+v, %v; want the entry marked ErrCorrupt", es, err)
	}
}

// A user rotate's orphan check looks at the version above the pointer
// only, in one Lstat (orphanAbove): a
// junk v<cur+1> is still discarded, and a file planted further up, which
// no crash or copied-back pointer leaves without v<cur+1>, is not read.
func TestUserRotateOrphanCheckReadsOnlyNextVersion(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	dir := filepath.Join(scopeDir(filepath.Dir(s.dir), "1001"), scopeEntriesName, "a")
	for _, n := range []uint64{2, 4} {
		if err := os.WriteFile(filepath.Join(dir, versionName(n)), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := u.Rotate(ctx, "user/1001/a", []byte("two")); err != nil || v.Version != 2 {
		t.Fatalf("rotate over a junk v2: %+v, %v", v, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, versionName(4))); err != nil || string(b) != "junk" {
		t.Fatalf("the rotate read past the version above its pointer: v4 is %q, %v", b, err)
	}
}
