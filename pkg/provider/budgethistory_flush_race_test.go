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

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"

	"k3sm.io/k3sm/internal/atomicfile"
)

var errFakeWrite = errors.New("fake write failure")

// setWrite swaps the history's file write under mu, the lock writeOnce reads
// it under.
func setWrite(h *BudgetHistory, w func(string, []byte, os.FileMode) error) {
	h.mu.Lock()
	h.write = w
	h.mu.Unlock()
}

// intentsOnDisk returns the pods of the intents the history file holds.
func intentsOnDisk(t *testing.T, dir string) map[types.UID]bool {
	t.Helper()
	st, err := readHistory(filepath.Join(dir, budgetHistoryFile))
	if err != nil {
		t.Fatal(err)
	}
	pods := make(map[types.UID]bool, len(st.Intents))
	for _, in := range st.Intents {
		pods[in.Pod] = true
	}
	return pods
}

// TestFlushWriterExitsMidWait: a flush that found the writer running, and is
// waiting for it, writes the state inline the moment the writer exits without
// having written it (its context ended while a write was in flight, and every
// write it made failed). It does not wait out budgetIntentWriteBound. Time is
// the bubble's virtual clock, so the elapsed time is exact.
//
// The fake write blocks the writer's first write until released, fails every
// write made while the writer is live, and writes for real once it has exited,
// so only flush's inline write can land.
//
// Fails-before: without flush's case on h.stopped the flush waited the full
// 250 ms and returned false with the intents not on disk.
func TestFlushWriterExitsMidWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		h := OpenBudgetHistory(dir, "fp", discardLog())
		gate := make(chan struct{})
		var calls atomic.Int32
		setWrite(h, func(path string, data []byte, mode os.FileMode) error {
			if calls.Add(1) == 1 {
				<-gate
			}
			select {
			case <-h.stopped:
				return atomicfile.Replace(path, data, mode)
			default:
				return errFakeWrite
			}
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h.start(ctx)
		h.recordIntent(types.UID("pod-1"), "app")
		synctest.Wait() // the writer is blocked in its first write

		start := time.Now()
		result := make(chan bool, 1)
		go func() { result <- h.flush(budgetIntentWriteBound) }()
		synctest.Wait() // flush is waiting on the writer
		cancel()
		h.recordIntent(types.UID("pod-2"), "app")
		close(gate)

		ok := <-result
		if elapsed := time.Since(start); elapsed >= budgetIntentWriteBound {
			t.Fatalf("flush took %v after the writer exited, want well under %v", elapsed, budgetIntentWriteBound)
		}
		if !ok {
			t.Fatal("flush reported the intent did not reach disk")
		}
		if got := intentsOnDisk(t, dir); !got["pod-1"] || !got["pod-2"] {
			t.Fatalf("the file holds intents for %v, want pod-1 and pod-2", got)
		}
	})
}

// TestFlushRacesWriterAndStop runs flushes, their inline writes included,
// against a live writer, a writer exiting on its context's end, and a
// concurrent stop, for the race detector. Every flush returns, and afterwards
// the file holds every intent recorded.
func TestFlushRacesWriterAndStop(t *testing.T) {
	const (
		rounds   = 20
		flushers = 4
		perFlush = 5
		bound    = 10 * time.Second // generous: real disk under -race
	)
	for r := range rounds {
		dir := t.TempDir()
		h := OpenBudgetHistory(dir, "fp", discardLog())
		ctx, cancel := context.WithCancel(context.Background())
		h.start(ctx)
		var wg sync.WaitGroup
		failed := make(chan string, flushers*perFlush)
		for f := range flushers {
			wg.Go(func() {
				for i := range perFlush {
					h.recordIntent(types.UID(fmt.Sprintf("pod-%d-%d", f, i)), "app")
					if !h.flush(bound) {
						failed <- fmt.Sprintf("flush %d/%d", f, i)
					}
				}
			})
		}
		wg.Go(cancel)
		wg.Go(func() {
			if !h.stop(bound) {
				failed <- "stop"
			}
		})
		wg.Wait()
		close(failed)
		for what := range failed {
			t.Errorf("round %d: %s did not reach disk in its bound", r, what)
		}
		if !h.flush(bound) {
			t.Fatalf("round %d: the closing flush did not reach disk", r)
		}
		got := intentsOnDisk(t, dir)
		for f := range flushers {
			for i := range perFlush {
				if pod := types.UID(fmt.Sprintf("pod-%d-%d", f, i)); !got[pod] {
					t.Fatalf("round %d: the file lacks the intent for %s", r, pod)
				}
			}
		}
	}
}

// TestFlushWriteFailsOrHangs: flush reports false when the write fails or
// hangs, with or without a writer, and returns within its bound. A failing
// inline write is reported at once, not retried until the bound: the fake
// fails its first write and blocks every later one, so a retry shows as a
// stall to the bound.
//
// Fails-before (inline failing): a flushPending that ignored writeOnce's
// result retried the failed write and returned only at the bound.
func TestFlushWriteFailsOrHangs(t *testing.T) {
	cases := []struct {
		name     string
		writer   bool
		hang     bool
		atBound  bool // the flush ends at the bound, not before
		maxCalls int32
	}{
		{name: "inline write fails", maxCalls: 1},
		{name: "inline write hangs", hang: true, atBound: true},
		{name: "writer's write fails", writer: true, atBound: true},
		{name: "writer's write hangs", writer: true, hang: true, atBound: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := OpenBudgetHistory(t.TempDir(), "fp", discardLog())
				release := make(chan struct{})
				var calls atomic.Int32
				setWrite(h, func(string, []byte, os.FileMode) error {
					if calls.Add(1) > 1 || tc.hang {
						<-release
					}
					return errFakeWrite
				})
				ctx, cancel := context.WithCancel(context.Background())
				if tc.writer {
					h.start(ctx)
				}
				h.recordIntent(types.UID("pod-1"), "app")
				if tc.writer {
					synctest.Wait() // the writer took the dirty signal
				}
				start := time.Now()
				ok := h.flush(budgetIntentWriteBound)
				elapsed := time.Since(start)
				close(release)
				cancel()
				if tc.writer {
					<-h.stopped
				}
				synctest.Wait()

				if ok {
					t.Fatal("flush reported success with every write failing")
				}
				if elapsed > budgetIntentWriteBound {
					t.Fatalf("flush took %v, want at most its bound %v", elapsed, budgetIntentWriteBound)
				}
				if !tc.atBound && elapsed != 0 {
					t.Fatalf("flush took %v on a failed write, want an immediate false", elapsed)
				}
				if tc.maxCalls > 0 && calls.Load() > tc.maxCalls {
					t.Fatalf("flush made %d writes, want at most %d", calls.Load(), tc.maxCalls)
				}
			})
		})
	}
}

// TestReadHistoryRefusesFIFO: a FIFO at the history path is refused as
// unrecognised, and the open does not block waiting for a writer (O_NONBLOCK).
// A watchdog bounds the wait; if it fires, a nonblocking write-side open
// releases the stuck read so the test leaks no goroutine.
func TestReadHistoryRefusesFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), budgetHistoryFile)
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := readHistory(path)
		result <- err
	}()
	watchdog := time.NewTimer(10 * time.Second)
	defer watchdog.Stop()
	select {
	case err := <-result:
		if !errors.Is(err, errBudgetHistoryFormat) {
			t.Fatalf("readHistory = %v, want errBudgetHistoryFormat", err)
		}
	case <-watchdog.C:
		if fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = unix.Close(fd) // only releases the blocked open
		}
		<-result
		t.Fatal("readHistory blocked opening a FIFO")
	}
}
