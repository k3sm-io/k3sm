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

package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGatedLoopStopsBeforeTheRuntimeCloses pins the eviction loop's lifecycle
// in node teardown: it does not run before open, and stop (which the node calls
// before closing the runtime, on every exit path) cancels it and returns only
// after the loop has returned, without the node's own context being cancelled.
func TestGatedLoopStopsBeforeTheRuntimeCloses(t *testing.T) {
	t.Run("stop after open waits for the running loop to return", func(t *testing.T) {
		var wg sync.WaitGroup
		g := newGatedLoop(context.Background()) // the node ctx never ends here: the errc path
		var running, returned atomic.Bool
		g.start(&wg, func(ctx context.Context) {
			running.Store(true)
			<-ctx.Done()
			time.Sleep(20 * time.Millisecond) // a loop that takes a moment to unwind
			returned.Store(true)
		})
		g.open()
		deadline := time.Now().Add(2 * time.Second)
		for !running.Load() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !running.Load() {
			t.Fatal("the loop never ran after open")
		}
		g.stop(5 * time.Second)
		if !returned.Load() {
			t.Fatal("stop returned before the loop did; the runtime would close under it")
		}
		wg.Wait()
	})

	t.Run("a loop stopped before open never runs and is not waited for in vain", func(t *testing.T) {
		var wg sync.WaitGroup
		g := newGatedLoop(context.Background())
		var ran atomic.Bool
		g.start(&wg, func(context.Context) { ran.Store(true) })
		g.stop(5 * time.Second)
		g.open() // a late open after stop must not start it
		wg.Wait()
		if ran.Load() {
			t.Error("a loop stopped before open still ran")
		}
	})

	t.Run("stop on a loop that was never started returns at once", func(t *testing.T) {
		g := newGatedLoop(context.Background())
		done := make(chan struct{})
		go func() { g.stop(time.Hour); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("stop on an unstarted loop blocked")
		}
	})
}
