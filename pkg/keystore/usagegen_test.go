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
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A put or rotate whose ctx ends during the walk before the store lock
// returns ctx's error without taking the lock: no hold, and so no walk of
// the scope under it. Before, the uncontended lock was taken with the
// done ctx and the quota judgement walked the scope there, the figure
// being absent.
func TestDoneCtxAfterPreWalkTakesNoHold(t *testing.T) {
	ops := []struct {
		name string
		run  func(ctx context.Context, u *UserScope) error
	}{
		{"put", func(ctx context.Context, u *UserScope) error {
			_, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("b"))
			return err
		}},
		{"rotate", func(ctx context.Context, u *UserScope) error {
			_, err := u.Rotate(ctx, "user/1001/a", []byte("two"))
			return err
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			s, u := rotateScope(t)
			s.usage.forget(1001) // the walk before the lock runs
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var under, holds atomic.Int64
			s.usageLstat = func(underLock bool) {
				if underLock {
					under.Add(1)
				}
				cancel()
			}
			s.holdObserver = func(bool, time.Duration) { holds.Add(1) }
			if err := op.run(ctx, u); !errors.Is(err, context.Canceled) {
				t.Fatalf("a %s cancelled during the walk: %v, want context.Canceled", op.name, err)
			}
			if under.Load() != 0 || holds.Load() != 0 {
				t.Fatalf("a %s cancelled during the walk took %d holds and walked %d files under the lock, want none", op.name, holds.Load(), under.Load())
			}
		})
	}
}

// The in-process lock, shared or exclusive, takes nothing for a ctx
// already done, even uncontended.
func TestPrefLockDoneCtxTakesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, exclusive := range []bool{true, false} {
		l := newPrefLock()
		if err := l.acquire(ctx, exclusive, time.Second); !errors.Is(err, context.Canceled) {
			t.Fatalf("exclusive %t with ctx done: %v, want context.Canceled", exclusive, err)
		}
		l.mu.Lock()
		held := l.writer || l.readers != 0
		l.mu.Unlock()
		if held {
			t.Fatalf("exclusive %t with ctx done holds the lock", exclusive)
		}
	}
}

// The .lock flock takes nothing for a ctx already done, even uncontended:
// another descriptor then takes it exclusive at once.
func TestFlockWaitDoneCtxTakesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &FileStore{}
	if err := s.flockWaitFor(ctx, open(), syscall.LOCK_EX, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("flock with ctx done: %v, want context.Canceled", err)
	}
	if err := syscall.Flock(int(open().Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("the flock was taken with ctx done: another descriptor gets %v", err)
	}
}

// A forgetAll while an op holds the figure, or while a walk builds one,
// leaves no figure once they end: the op's confirm and the walk's set
// keep nothing taken before it.
func TestForgetAllDuringOpLeavesNoFigure(t *testing.T) {
	s, u := rotateScope(t)
	op := s.usage.begin(1001)
	s.usage.forgetAll()
	op.confirm(func(m map[string]int64) { m["b"] = 1 })
	if hasFigure(s, 1001) {
		t.Fatal("an op's confirm put back a figure taken before a forgetAll")
	}
	once := false
	s.usageLstat = func(bool) {
		if !once {
			once = true
			s.usage.forgetAll()
		}
	}
	u.prepareUsage(context.Background())
	if !once {
		t.Fatal("the walk before the lock did not run")
	}
	if hasFigure(s, 1001) {
		t.Fatal("a walk begun before a forgetAll kept its figure")
	}
}

// The store's start step, which the socket's supervisor runs on every
// listener start pass, drops every figure: a listener started again holds
// none from before it.
func TestStartUserScopesForgetsUsageFigures(t *testing.T) {
	s, _ := rotateScope(t)
	if !hasFigure(s, 1001) {
		t.Fatal("no figure after the first put")
	}
	_ = s.StartUserScopes(context.Background()) // its outcome is not what is judged
	if hasFigure(s, 1001) {
		t.Fatal("a listener start kept a usage figure from before it")
	}
}

// A user list counts a version name that is not a regular file (a
// symlink, even to a good version, or a directory) as no file: the entry
// is marked ErrCorrupt.
func TestUserListVersionNotRegularIsAbsent(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			s, u := rotateScope(t)
			for _, v := range []string{"two", "three"} {
				if _, err := u.Rotate(ctx, "user/1001/a", []byte(v)); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(scopeDir(filepath.Dir(s.dir), "1001"), scopeEntriesName, "a")
			v1 := filepath.Join(dir, versionName(1))
			if err := os.Remove(v1); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "symlink" {
				err = os.Symlink(versionName(3), v1)
			} else {
				err = os.Mkdir(v1, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			es, err := u.List(ctx)
			if err != nil || len(es) != 1 || !errors.Is(es[0].Err, ErrCorrupt) {
				t.Fatalf("with v1 a %s: %+v, %v; want the entry marked ErrCorrupt", kind, es, err)
			}
		})
	}
}
