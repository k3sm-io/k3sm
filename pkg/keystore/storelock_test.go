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
				time.Sleep(time.Duration(i) * hold / readers)
				for !stop.Load() {
					unlock, err := s.lock(ctx, root, false)
					if err != nil {
						continue // queued behind the writer past the wait
					}
					shared.Add(1)
					time.Sleep(hold)
					unlock()
				}
			})
		}
		time.Sleep(2 * hold) // the stream is running
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
