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
	"maps"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// figureOf is a copy of uid's usage figure's entries, nil when it has none.
func figureOf(s *FileStore, uid uint32) map[string]int64 {
	s.usage.mu.Lock()
	defer s.usage.mu.Unlock()
	if f := s.usage.byUID[uid]; f != nil {
		return maps.Clone(f.entries)
	}
	return nil
}

// walkOf is what a walk of u's scope counts now.
func walkOf(t *testing.T, u *UserScope) map[string]int64 {
	t.Helper()
	root, err := u.s.openDir(u.s.dir, false)
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

// wantFigureIsWalk fails unless uid 1001's figure is what a walk counts.
func wantFigureIsWalk(t *testing.T, s *FileStore, u *UserScope) {
	t.Helper()
	if got, want := figureOf(s, 1001), walkOf(t, u); got == nil || !maps.Equal(got, want) {
		t.Fatalf("the figure is %v, a walk counts %v", got, want)
	}
}

// copyScopeDir builds a copy of the scope directory src at dst, with fresh
// inodes and the same bytes and modes, and pads entry a by extra bytes so
// a figure of src is wrong for the copy.
func copyScopeDir(t *testing.T, src, dst string, extra int64) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			if err := os.Mkdir(to, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(to, fi.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(to, b, fi.Mode().Perm()); err != nil {
			return err
		}
		return os.Chmod(to, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	pad := filepath.Join(dst, scopeEntriesName, "a", "pad")
	f, err := os.OpenFile(pad, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(extra); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// A scope tree renamed into place under the same scope.key bytes (a copy
// put back while the server was stopped) is a new entries/ directory: the
// figure kept for the old tree is not trusted, and the next judgement
// walks and counts the new tree.
func TestUsageFigureBoundToEntriesDirectory(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("two")); err != nil {
		t.Fatal(err)
	}
	wantFigureIsWalk(t, s, u)
	dir := scopeDir(filepath.Dir(s.dir), "1001")
	copyScopeDir(t, dir, dir+".copy", 4096)
	mustRename(t, dir, dir+".old")
	mustRename(t, dir+".copy", dir)
	under, outside := countUsageLstats(s)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("three")); err != nil {
		t.Fatal(err)
	}
	if walked(under, outside) == 0 {
		t.Fatal("a figure of the tree renamed away was trusted for the tree renamed into place: no walk")
	}
	wantFigureIsWalk(t, s, u)
}

// The binding holds the figure across a tree that did not change: entries/
// renamed away and back is the same directory, and the next judgement
// walks nothing.
func TestUsageFigureKeptForUnchangedTree(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("two")); err != nil {
		t.Fatal(err)
	}
	entries := filepath.Join(scopeDir(filepath.Dir(s.dir), "1001"), scopeEntriesName)
	mustRename(t, entries, entries+".away")
	mustRename(t, entries+".away", entries)
	under, outside := countUsageLstats(s)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("three")); err != nil {
		t.Fatal(err)
	}
	if n := walked(under, outside); n != 0 {
		t.Fatalf("an unchanged tree's figure was dropped: the rotate walked %d files", n)
	}
	wantFigureIsWalk(t, s, u)
}

// scope.key replaced on disk by the real path: the scope moved away and a
// put minting a fresh one at the name, then the first scope moved back.
// Each judgement after a replacement walks, and the figure it keeps is
// what a walk counts.
func TestUsageFigureScopeKeyReplacedOnDisk(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("two")); err != nil {
		t.Fatal(err)
	}
	wantFigureIsWalk(t, s, u)
	server := filepath.Dir(s.dir)
	dir := scopeDir(server, "1001")
	// The mint's judgement walks a scope with no files, so only the
	// figure it keeps shows it: the fresh entry alone, not the old a.
	moved, _ := mintAway(t, s, server, "fresh")
	wantFigureIsWalk(t, s, u)
	if _, ok := figureOf(s, 1001)["a"]; ok {
		t.Fatal("the put that minted a fresh scope.key kept the old scope's figure")
	}
	// The first scope back at the name: its scope.key differs from the
	// fresh one the figure is bound to.
	mustRename(t, dir, dir+".fresh")
	mustRename(t, moved, dir)
	under, outside := countUsageLstats(s)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("three")); err != nil {
		t.Fatal(err)
	}
	if walked(under, outside) == 0 {
		t.Fatal("a figure bound to the fresh scope.key was trusted for the first scope: no walk")
	}
	wantFigureIsWalk(t, s, u)
}

// A ctx already done takes no uid lock and runs no GeneratedUID lookup, on
// every user verb's path: put, rotate and rm (lockUID), list (auditedRead)
// and a read (readScope). The uid lock is free, so before lockUID checked
// ctx first its select picked the lock about half the time.
func TestDoneContextTakesNoUIDLockAndNoLookup(t *testing.T) {
	s, u := rotateScope(t)
	var lookups atomic.Int64
	s.generatedUID = func(uint32) ([16]byte, error) {
		lookups.Add(1)
		return guid(0xA1), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	held := func() int {
		s.usage.mu.Lock()
		defer s.usage.mu.Unlock()
		return len(s.usage.locks[1001])
	}
	for i := range 64 {
		if unlock, err := s.usage.lockUID(ctx, 1001, lockTimeout); !errors.Is(err, context.Canceled) {
			if unlock != nil {
				unlock()
			}
			t.Fatalf("lockUID with a done ctx, try %d: %v, want context.Canceled", i, err)
		}
		ops := map[string]func() error{
			"put":    func() error { _, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("b")); return err },
			"rotate": func() error { _, err := u.Rotate(ctx, "user/1001/a", []byte("two")); return err },
			"rm":     func() error { return u.Delete(ctx, "user/1001/a") },
			"list":   func() error { _, err := u.List(ctx); return err },
			"read": func() error {
				return u.read(ctx, func(*os.Root, keys) error { return nil })
			},
		}
		for op, run := range ops {
			if err := run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("%s with a done ctx, try %d: %v, want context.Canceled", op, i, err)
			}
			if n := lookups.Load(); n != 0 {
				t.Fatalf("%s with a done ctx, try %d, ran %d GeneratedUID lookups, want none", op, i, n)
			}
			if held() != 0 {
				t.Fatalf("%s with a done ctx, try %d, left the uid lock held", op, i)
			}
		}
	}
}

// The unlock s.lock returns releases once: a second call does nothing, so
// another holder's share is not released by it and the lock stays usable.
func TestStoreUnlockIdempotent(t *testing.T) {
	s, _ := newTestStore(t)
	mustPut(t, s, "seed", KindOpaque, []byte("v"))
	ctx := context.Background()
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, exclusive := range []bool{true, false} {
		a, err := s.lock(ctx, root, exclusive)
		if err != nil {
			t.Fatal(err)
		}
		a()
		a()
		// A share held by another caller survives a's second call.
		b, err := s.lock(ctx, root, false)
		if err != nil {
			t.Fatalf("a share after a double unlock (exclusive %t): %v", exclusive, err)
		}
		a()
		s.inproc.mu.Lock()
		readers, writer := s.inproc.readers, s.inproc.writer
		s.inproc.mu.Unlock()
		if readers != 1 || writer {
			t.Fatalf("after a third call of a released unlock (exclusive %t): %d readers, writer %t; want the one share", exclusive, readers, writer)
		}
		b()
		c, err := s.lock(ctx, root, true)
		if err != nil {
			t.Fatalf("the exclusive lock after double unlocks (exclusive %t): %v", exclusive, err)
		}
		c()
	}
}
