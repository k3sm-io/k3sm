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

package socket

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// heldLock is a store lock another holder has: it is taken only after
// free is closed, and gives up when its ctx is done unless it ignores ctx.
type heldLock struct {
	free      chan struct{}
	ignoreCtx bool
	unlocked  atomic.Int32
}

func (l *heldLock) lock(ctx context.Context) (func(), error) {
	done := ctx.Done()
	if l.ignoreCtx {
		done = nil
	}
	select {
	case <-l.free:
		return func() { l.unlocked.Add(1) }, nil
	case <-done:
		return nil, ctx.Err()
	}
}

func TestBoundedLockWait(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ignoreCtx bool
		freeAt    time.Duration // when the holder lets go; 0 is never
		cancelAt  time.Duration // when the caller's ctx is cancelled; 0 is never
		want      error
		returnAt  time.Duration
		ran       bool
	}{
		{"held past the bound", false, 0, 0, ErrBusy, LockWait, false},
		{"lock ignores ctx, freed later", true, 5 * time.Second, 0, ErrBusy, LockWait, false},
		{"freed within the bound", false, time.Second, 0, nil, time.Second, true},
		{"caller cancels first", false, 0, time.Second, context.Canceled, time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := &heldLock{free: make(chan struct{}), ignoreCtx: tc.ignoreCtx}
				if tc.freeAt != 0 {
					time.AfterFunc(tc.freeAt, func() { close(l.free) })
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if tc.cancelAt != 0 {
					time.AfterFunc(tc.cancelAt, cancel)
				}
				start := time.Now()
				ran := false
				err := WithStoreLock(ctx, l.lock, func() error {
					ran = true
					if l.unlocked.Load() != 0 {
						t.Error("fn ran after the unlock")
					}
					return nil
				})
				if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
					t.Fatalf("WithStoreLock = %v, want %v", err, tc.want)
				}
				if got := time.Since(start); got != tc.returnAt {
					t.Fatalf("returned after %v, want %v", got, tc.returnAt)
				}
				if ran != tc.ran {
					t.Fatalf("fn ran = %v, want %v", ran, tc.ran)
				}
				advance(10 * time.Second)
				wantUnlocks := int32(0)
				if tc.freeAt != 0 {
					wantUnlocks = 1 // released by fn's end, or at once when taken late
				}
				if got := l.unlocked.Load(); got != wantUnlocks {
					t.Fatalf("unlocked %d times, want %d", got, wantUnlocks)
				}
			})
		})
	}
	t.Run("lock error is not busy", func(t *testing.T) {
		failed := errors.New("fake: open .lock failed")
		err := WithStoreLock(t.Context(), func(context.Context) (func(), error) { return nil, failed }, func() error { return nil })
		if !errors.Is(err, failed) || errors.Is(err, ErrBusy) {
			t.Fatalf("WithStoreLock = %v, want the lock's own error", err)
		}
	})
	t.Run("busy fails the request, not the connection", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := &heldLock{free: make(chan struct{})}
			h, err := NewHandler(time.Now)
			if err != nil {
				t.Fatal(err)
			}
			h.ops = map[string]opFunc{"put": func(ctx context.Context, _ []byte) error {
				return WithStoreLock(ctx, l.lock, func() error { return nil })
			}}
			s := serveWith(t, h)
			s.send(t, TypeHello, helloV1, nil)
			var hello HelloReply
			s.recv(t, TypeHello, &hello)
			start := time.Now()
			s.send(t, TypeRequest, `{"op":"put"}`, nil)
			if code := s.recvCode(t); code != CodeBusy {
				t.Fatalf("reply code %q, want %q", code, CodeBusy)
			}
			if got := time.Since(start); got != LockWait {
				t.Fatalf("busy after %v, want %v", got, LockWait)
			}
			close(l.free)
			s.send(t, TypeRequest, `{"op":"put"}`, nil)
			var reply struct{}
			s.recv(t, TypeReply, &reply)
			if err := s.finish(); err != nil {
				t.Fatalf("Serve = %v after a busy request, want nil", err)
			}
		})
	})
}
