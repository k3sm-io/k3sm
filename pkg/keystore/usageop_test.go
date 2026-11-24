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
	"fmt"
	"sync"
	"testing"
)

// hasFigure reports whether the store holds a usage figure for uid.
func hasFigure(s *FileStore, uid uint32) bool {
	s.usage.mu.Lock()
	defer s.usage.mu.Unlock()
	return s.usage.byUID[uid] != nil
}

// walked is how many file Lstats of a scope's usage walk the counters
// saw, under the store lock and before it.
func walked(under, outside interface{ Load() int64 }) int64 { return under.Load() + outside.Load() }

// failUsageStep is a step seam that, once, at the step named at, panics (panics
// set) or returns an injected error.
func failUsageStep(at string, panics bool) func(string) error {
	done := false
	return func(name string) error {
		if name != at || done {
			return nil
		}
		done = true
		if panics {
			panic("injected panic at " + name)
		}
		return errors.New("injected failure at " + name)
	}
}

// usageWrites is a put, a rotate and an rm, each with the step at its
// first write to the scope's entries.
var usageWrites = []struct {
	op, step string
	run      func(ctx context.Context, u *UserScope) error
}{
	{"put", "write v1", func(ctx context.Context, u *UserScope) error {
		_, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("b"))
		return err
	}},
	{"rotate", "write v2", func(ctx context.Context, u *UserScope) error {
		_, err := u.Rotate(ctx, "user/1001/a", []byte("two"))
		return err
	}},
	{"rm", "delete a", func(ctx context.Context, u *UserScope) error { return u.Delete(ctx, "user/1001/a") }},
}

// A panic at a put's, a rotate's or an rm's write, which the socket's
// listener recovers and serves on, leaves the uid with no usage figure:
// the next quota judgement walks the scope. Before the figure was taken
// out ahead of the write, a panicking put or rotate kept it, and an rm
// recorded the entry as removed, so the next put trusted a figure that no
// longer matched the files.
func TestUsagePanicAtWriteDropsFigure(t *testing.T) {
	for _, w := range usageWrites {
		t.Run(w.op, func(t *testing.T) {
			ctx := context.Background()
			s, u := rotateScope(t)
			if !hasFigure(s, 1001) {
				t.Fatal("no figure after the first put")
			}
			s.step = failUsageStep(w.step, true)
			func() {
				defer func() {
					if recover() == nil {
						t.Fatalf("the %s did not reach its %q step", w.op, w.step)
					}
				}()
				_ = w.run(ctx, u)
			}()
			if hasFigure(s, 1001) {
				t.Fatalf("a %s that panicked at %q kept the usage figure", w.op, w.step)
			}
			under, outside := countUsageLstats(s)
			userPut(t, u, "user/1001/c", "sea")
			if walked(under, outside) == 0 {
				t.Fatalf("the put after a %s that panicked at %q judged its quota with no walk", w.op, w.step)
			}
		})
	}
}

// A put, rotate or rm that fails at the write of v1, the sync of v<N>, or
// the delete of the entry's tree drops the figure: the next judgement
// walks.
func TestUsageFailedWriteDropsFigure(t *testing.T) {
	steps := map[string]string{"put": "write v1", "rotate": "sync v2", "rm": "delete a"}
	for _, w := range usageWrites {
		t.Run(w.op, func(t *testing.T) {
			ctx := context.Background()
			s, u := rotateScope(t)
			s.step = failUsageStep(steps[w.op], false)
			if err := w.run(ctx, u); err == nil {
				t.Fatalf("the %s with %q failing succeeded", w.op, steps[w.op])
			}
			if hasFigure(s, 1001) {
				t.Fatalf("a %s that failed at %q kept the usage figure", w.op, steps[w.op])
			}
			under, outside := countUsageLstats(s)
			userPut(t, u, "user/1001/c", "sea")
			if walked(under, outside) == 0 {
				t.Fatalf("the put after a %s that failed at %q judged its quota with no walk", w.op, steps[w.op])
			}
		})
	}
}

// failLiveGens is a user-scope floor whose live generations cannot be
// read: rm is refused with nothing removed.
type failLiveGens struct{ userFloorLog }

func (failLiveGens) liveGens(string, string) ([][generationSize]byte, error) {
	return nil, errors.New("injected floor read failure")
}

// A refusal that writes nothing to the scope's entries keeps the figure:
// the next put walks nothing. Before, every failed rm but ErrNotFound
// dropped it, so a uid refused an rm paid a walk on its next put.
func TestUsageRefusalKeepsFigure(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	lookup := func(g [generationSize]byte, err error) {
		setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) { return g, err })
	}
	refusals := []struct {
		name string
		run  func() error
		want error
	}{
		{"put of an existing name", func() error {
			_, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("again"))
			return err
		}, ErrExists},
		{"put over the quota", func() error {
			s.usage.mu.Lock()
			s.usage.byUID[1001].entries["a"] = maxScopeBytes
			s.usage.mu.Unlock()
			defer func() {
				s.usage.mu.Lock()
				s.usage.byUID[1001].entries["a"] = 0
				s.usage.mu.Unlock()
			}()
			_, err := u.Put(ctx, "user/1001/big", KindOpaque, []byte("b"))
			return err
		}, ErrQuota},
		{"rm of a name not there", func() error { return u.Delete(ctx, "user/1001/none") }, ErrNotFound},
		{"rm by a reused uid", func() error {
			lookup(guid(0xB2), nil)
			defer lookup(guid(0xA1), nil)
			return u.Delete(ctx, "user/1001/a")
		}, ErrScopeOwnerChanged},
		{"rm with no lookup run", func() error {
			lookup([generationSize]byte{}, errLookupNotRun)
			defer lookup(guid(0xA1), nil)
			return u.Delete(ctx, "user/1001/a")
		}, errLookupNotRun},
		{"rm refused, nothing removed", func() error {
			floor := s.userFloor
			s.userFloor = failLiveGens{floor}
			defer func() { s.userFloor = floor }()
			return u.Delete(ctx, "user/1001/a")
		}, nil},
	}
	for i, r := range refusals {
		err := r.run()
		if err == nil || (r.want != nil && !errors.Is(err, r.want)) {
			t.Fatalf("%s: %v, want %v", r.name, err, r.want)
		}
		if !hasFigure(s, 1001) {
			t.Fatalf("%s (%v) dropped the usage figure", r.name, err)
		}
		under, outside := countUsageLstats(s)
		userPut(t, u, fmt.Sprintf("user/1001/n%d", i), "n")
		if n := walked(under, outside); n != 0 {
			t.Fatalf("the put after %s walked the scope (%d Lstats), want none", r.name, n)
		}
	}
}

// The walk before the lock honours ctx: one cancelled during the walk
// stops it and leaves no figure.
func TestPrepareUsageHonoursContext(t *testing.T) {
	s, u := rotateScope(t)
	s.usage.forget(1001)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.usageLstat = func(bool) { cancel() }
	u.prepareUsage(ctx)
	if hasFigure(s, 1001) {
		t.Fatal("a walk whose ctx was cancelled left a figure")
	}
}

// A figure bound to another scope.key is rebuilt by the walk before the
// lock, not under it.
func TestStaleFigureRebuiltBeforeLock(t *testing.T) {
	s, u := rotateScope(t)
	s.usage.mu.Lock()
	s.usage.byUID[1001].key = sha256.Sum256([]byte("another scope.key"))
	s.usage.mu.Unlock()
	under, outside := countUsageLstats(s)
	userPut(t, u, "user/1001/b", "bee")
	if under.Load() != 0 || outside.Load() == 0 {
		t.Fatalf("a stale figure was rebuilt with %d Lstats under the lock and %d before it, want all before", under.Load(), outside.Load())
	}
}

// The order before the store lock: the uid's mutation lock, the walk,
// then the GeneratedUID lookup, so the lookup's answer is not spent
// waiting on the uid's lock or the walk.
func TestLookupAfterUIDLockAndWalk(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	for _, op := range []string{"put", "rotate"} {
		s.usage.forget(1001)
		_, outside := countUsageLstats(s)
		var lockHeld, walkDone, called bool
		setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) {
			if !called {
				called = true
				s.usage.mu.Lock()
				lockHeld = len(s.usage.locks[1001]) == 1
				s.usage.mu.Unlock()
				walkDone = outside.Load() > 0
			}
			return guid(0xA1), nil
		})
		var err error
		if op == "put" {
			_, err = u.Put(ctx, "user/1001/b", KindOpaque, []byte("b"))
		} else {
			_, err = u.Rotate(ctx, "user/1001/a", []byte("two"))
		}
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if !called || !lockHeld || !walkDone {
			t.Fatalf("%s's lookup: ran %t, under the uid's lock %t, after the walk %t; want all", op, called, lockHeld, walkDone)
		}
	}
}

// Concurrent puts of one uid, and of two uids, share the usage table
// without a data race (run with -race): each judgement reads its own copy
// of the figure.
func TestUsageConcurrentPuts(t *testing.T) {
	ctx := context.Background()
	s, _ := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xA2)})
	a := userScope(t, s, 1001)
	b, err := s.UserScope(1002)
	if err != nil {
		t.Fatal(err)
	}
	userPut(t, a, "user/1001/seed", "s")
	userPut(t, b, "user/1002/seed", "s")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 4 {
		wg.Go(func() {
			_, err := a.Put(ctx, fmt.Sprintf("user/1001/e%d", i), KindOpaque, []byte("v"))
			errs <- err
		})
		wg.Go(func() {
			_, err := b.Put(ctx, fmt.Sprintf("user/1002/e%d", i), KindOpaque, []byte("v"))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, uid := range []uint32{1001, 1002} {
		s.usage.mu.Lock()
		n := len(s.usage.byUID[uid].entries)
		s.usage.mu.Unlock()
		if n != 5 {
			t.Fatalf("uid %d's figure holds %d entries, want 5", uid, n)
		}
	}
}

// A restore's merge that moves a staged tree into place forgets every
// usage figure: the staged scopes keep their scope.key, so a figure taken
// before would still be trusted.
func TestFloorMergeForgetsUsageFigures(t *testing.T) {
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	s.usage.set(1001, &scopeUsage{entries: map[string]int64{}})
	if _, err := s.MergeFloor(context.Background(), MergeOptions{}); err != nil {
		t.Fatal(err)
	}
	if hasFigure(s, 1001) {
		t.Fatal("the merge moved a staged tree into place and kept a usage figure")
	}
}
