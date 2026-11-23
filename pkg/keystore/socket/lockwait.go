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
	"fmt"
	"time"
)

// LockWait is the longest a socket operation waits for the store lock
// (docs/design/keystore.md, "Lifecycle"); past it the request fails busy,
// not the connection or the server.
const LockWait = 2 * time.Second

// ErrBusy is a store lock not taken within LockWait. The connection loop
// answers it with the busy code and keeps the connection.
var ErrBusy = errors.New("keystore socket: the store is busy")

// LockFunc takes the store lock, giving up when ctx is done, and returns
// the function that releases it.
type LockFunc func(ctx context.Context) (unlock func(), err error)

// taken is one lock call's result.
type taken struct {
	unlock func()
	err    error
}

// release releases a lock t took, if it took one.
func release(t taken) {
	if t.err == nil && t.unlock != nil {
		t.unlock()
	}
}

// WithStoreLock runs fn holding the lock lock takes, waiting at most
// LockWait for it. A wait past LockWait is ErrBusy, even when lock does not
// give up as it should: a lock taken after that is released at once. A done
// ctx is its error, and any other failure to lock is returned wrapped.
func WithStoreLock(ctx context.Context, lock LockFunc, fn func() error) error {
	waitCtx, cancel := context.WithTimeout(ctx, LockWait)
	defer cancel()
	got := make(chan taken, 1)
	go func() {
		var t taken
		defer func() {
			if v := recover(); v != nil {
				t = taken{err: fmt.Errorf("store lock panicked: %v", v)}
			}
			got <- t
		}()
		t.unlock, t.err = lock(waitCtx)
	}()
	var t taken
	timedOut := false
	select {
	case t = <-got:
	case <-waitCtx.Done():
		timedOut = true
		go func() { release(<-got) }()
	}
	if !timedOut && t.err == nil {
		defer release(t)
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if timedOut || errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
		return ErrBusy
	}
	return fmt.Errorf("store lock: %w", t.err)
}
