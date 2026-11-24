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
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// U89 (the store part): with a continuous stream of shared holds from
// other goroutines, each overlapping the next so a reader is always in, an
// exclusive request through the store lock is served within one reader's
// hold, on synctest's clock; with no writer preference it would wait out
// its whole LockWait and be refused busy.
func TestWriterPreferringLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			readers = 4
			hold    = 40 * time.Millisecond
			wait    = 2 * time.Second
		)
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		s := New(Config{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), LockWait: wait})
		ctx := context.Background()
		var (
			stop   atomic.Bool
			shared atomic.Int64
			wg     sync.WaitGroup
		)
		for i := range readers {
			wg.Go(func() {
				// Staggered, so the holds overlap and the share is never
				// empty while the stream runs.
				bubbleWait(time.Duration(i) * hold / readers)
				for !stop.Load() {
					unlock, err := s.lock(ctx, root, false)
					if err != nil {
						continue // queued behind the writer past the wait
					}
					shared.Add(1)
					bubbleWait(hold)
					unlock()
				}
			})
		}
		bubbleWait(2 * hold) // the stream is running
		asked := time.Now()
		unlock, err := s.lock(ctx, root, true)
		served := time.Since(asked)
		if err == nil {
			unlock()
		}
		stop.Store(true)
		wg.Wait()
		if err != nil {
			t.Fatalf("the exclusive request while readers stream, after %s: %v", served, err)
		}
		if served > hold {
			t.Fatalf("the exclusive request was served after %s, past one reader's %s hold", served, hold)
		}
		if shared.Load() < readers {
			t.Fatalf("only %d shared holds ran: the stream never ran", shared.Load())
		}
	})
}

// A writer that gives up on its wait no longer holds readers back.
func TestPrefLockWriterTimeoutAdmitsReaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newPrefLock()
		ctx := context.Background()
		if err := l.acquire(ctx, false, time.Second); err != nil {
			t.Fatal(err)
		}
		if err := l.acquire(ctx, true, 100*time.Millisecond); err != errLockTimeout {
			t.Fatalf("the writer behind a held share: %v, want errLockTimeout", err)
		}
		if err := l.acquire(ctx, false, 0); err != nil {
			t.Fatalf("a reader after the writer gave up: %v", err)
		}
		l.release(false)
		l.release(false)
		if err := l.acquire(ctx, true, 0); err != nil {
			t.Fatalf("the writer once the share is empty: %v", err)
		}
	})
}

// The reader side: with exclusive holds streaming from several goroutines,
// each queued behind the last, a waiting reader is handed the lock at the
// next writer's release, before the writers queued behind it, as
// sync.RWMutex hands it; without the handoff it waits out its whole wait.
func TestPrefLockAdmitsReaderUnderWriterStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			writers = 3
			hold    = 40 * time.Millisecond
			wait    = 2 * time.Second
		)
		l := newPrefLock()
		ctx := context.Background()
		var (
			stop atomic.Bool
			wg   sync.WaitGroup
			held atomic.Int64
		)
		for i := range writers {
			wg.Go(func() {
				bubbleWait(time.Duration(i) * hold / writers)
				for !stop.Load() {
					if err := l.acquire(ctx, true, wait); err != nil {
						continue
					}
					held.Add(1)
					bubbleWait(hold)
					l.release(true)
				}
			})
		}
		bubbleWait(2 * hold)
		asked := time.Now()
		err := l.acquire(ctx, false, wait)
		served := time.Since(asked)
		if err == nil {
			l.release(false)
		}
		stop.Store(true)
		wg.Wait()
		if err != nil {
			t.Fatalf("the reader while writers stream, after %s: %v", served, err)
		}
		if served > hold {
			t.Fatalf("the reader was served after %s, past one writer's %s hold", served, hold)
		}
		if held.Load() < writers {
			t.Fatalf("only %d exclusive holds ran", held.Load())
		}
	})
}

// A waiter whose context is cancelled gives up with the context's error and
// holds nothing; a writer that times out leaves no waiting writer counted.
func TestPrefLockCancelAndTimeoutLeaveNoWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newPrefLock()
		if err := l.acquire(context.Background(), true, time.Second); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 2)
		go func() { done <- l.acquire(ctx, false, time.Minute) }()
		go func() { done <- l.acquire(ctx, true, time.Minute) }()
		synctest.Wait()
		cancel()
		for range 2 {
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("a cancelled waiter: %v, want context.Canceled", err)
			}
		}
		if err := l.acquire(context.Background(), true, 10*time.Millisecond); err != errLockTimeout {
			t.Fatalf("a writer behind the held lock: %v, want errLockTimeout", err)
		}
		l.mu.Lock()
		writers, readers, queued := l.writers, l.readers, len(l.waiting)
		l.mu.Unlock()
		if writers != 0 || readers != 0 || queued != 0 {
			t.Fatalf("after the give-ups: %d writers waiting, %d readers holding, %d readers queued; want none", writers, readers, queued)
		}
		l.release(true)
		if err := l.acquire(context.Background(), false, 0); err != nil {
			t.Fatalf("a reader once the lock is free: %v", err)
		}
	})
}
