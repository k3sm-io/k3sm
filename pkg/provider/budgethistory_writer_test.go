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
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/apimachinery/pkg/types"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	"k3sm.io/k3sm/internal/atomicfile"
)

// countedHistory opens a history in dir whose file writes are counted, and
// starts its writer.
func countedHistory(t *testing.T, dir string) (*BudgetHistory, *atomic.Int64) {
	t.Helper()
	h := OpenBudgetHistory(dir, "fp", discardLog())
	if h.path == "" {
		t.Fatalf("OpenBudgetHistory(%s) degraded to memory only", dir)
	}
	var writes atomic.Int64
	h.mu.Lock()
	h.write = func(path string, data []byte, mode os.FileMode) error {
		writes.Add(1)
		return atomicfile.Replace(path, data, mode)
	}
	h.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	h.start(ctx)
	t.Cleanup(func() {
		cancel()
		<-h.stopped
	})
	return h, &writes
}

// advanceBubble lets virtual time pass inside a synctest bubble.
func advanceBubble(d time.Duration) {
	tm := time.NewTimer(d)
	defer tm.Stop()
	<-tm.C
}

// TestBudgetHistoryWritesAreRateLimited: a burst of changes (a drain, a crash
// loop) is written at most once per budgetHistoryMinWriteInterval, while the
// emergency eviction's flush and the stop are written at once.
//
// Fails-before: every change signal was written immediately, so a change right
// after a write rewrote the whole file again with no interval between them.
func TestBudgetHistoryWritesAreRateLimited(t *testing.T) {
	synctest.Test(t, testBudgetHistoryWritesAreRateLimited)
}

func testBudgetHistoryWritesAreRateLimited(t *testing.T) {
	dir := t.TempDir()
	h, writes := countedHistory(t, dir)
	rec := func(n int) {
		for range n {
			h.record("", budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, time.Now())
			synctest.Wait() // the writer sees each change on its own
		}
	}

	rec(1)
	if got := writes.Load(); got != 1 {
		t.Fatalf("writes after the first change = %d, want 1 (no wait before a first write)", got)
	}
	rec(10)
	if got := writes.Load(); got != 1 {
		t.Fatalf("writes after a burst inside the interval = %d, want still 1", got)
	}
	advanceBubble(budgetHistoryMinWriteInterval - time.Millisecond)
	synctest.Wait()
	if got := writes.Load(); got != 1 {
		t.Fatalf("writes just before the interval ends = %d, want still 1", got)
	}
	advanceBubble(time.Millisecond)
	synctest.Wait()
	if got := writes.Load(); got != 2 {
		t.Fatalf("writes once the interval ended = %d, want 2 (the burst coalesced into one)", got)
	}
	if got := fileEvictions(t, dir, budgetv1alpha1.BandBatch); got != 11 {
		t.Fatalf("the file holds evictions=%d, want 11", got)
	}

	// The emergency eviction's flush is not held by the interval.
	start := time.Now()
	h.recordIntent("uid-hog", "")
	if !h.flush(budgetIntentWriteBound) {
		t.Fatal("the emergency flush did not finish in its bound")
	}
	if took := time.Since(start); took != 0 {
		t.Fatalf("the emergency flush waited %v, want no wait", took)
	}
	if got := writes.Load(); got != 3 {
		t.Fatalf("writes after the emergency flush = %d, want 3", got)
	}

	// Nor is the stop: a change right after a write reaches disk at once.
	rec(1)
	start = time.Now()
	if !h.stop(BudgetHistoryStopBound) {
		t.Fatal("stop did not finish in its bound")
	}
	if took := time.Since(start); took != 0 {
		t.Fatalf("stop waited %v, want no wait", took)
	}
	if got := fileEvictions(t, dir, budgetv1alpha1.BandBatch); got != 12 {
		t.Fatalf("the file holds evictions=%d after stop, want 12", got)
	}
}

// TestBudgetHistoryDropsInvalidEntriesOnRead: a ring entry with an unknown
// reason, an unknown band or no time, an intent with no pod, and a classified
// termination with no time are dropped on read-back with the rest of the file
// kept, so nothing invalid is published or matched.
//
// Fails-before: the entries were read verbatim, so the unknown reason reached
// the 1 h and 24 h windows.
func TestBudgetHistoryDropsInvalidEntriesOnRead(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_000_000, 0)
	at := now.Add(-time.Minute).Unix()
	st := newHistoryState()
	st.Fingerprint = "fp"
	st.Totals[budgetv1alpha1.BandStandard] = historyTotals{KernelKills: 1}
	st.Ring = []historyEvent{
		{At: at, Band: budgetv1alpha1.BandStandard, Reason: budgetv1alpha1.CounterKernelKill},
		{At: at, Band: budgetv1alpha1.BandStandard, Reason: "made-up"},
		{At: at, Band: budgetv1alpha1.BandStandard, Reason: budgetv1alpha1.CounterUnknown},
		{At: at, Band: "gold", Reason: budgetv1alpha1.CounterEviction},
		{At: 0, Band: budgetv1alpha1.BandStandard, Reason: budgetv1alpha1.CounterEviction},
	}
	st.Intents = []killIntent{{Pod: "uid-a", Container: "c0"}, {Pod: "", Container: "c0"}}
	st.Seen = []seenExit{
		{Pod: "uid-a", Container: "c0", RestartCount: 1, FinishedAt: 2, At: at},
		{Pod: "uid-b", Container: "c0", RestartCount: 1, FinishedAt: 2, At: 0},
	}
	data, err := json.Marshal(&st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, budgetHistoryFile), data, 0o600); err != nil {
		t.Fatal(err)
	}

	h := openHistory(t, dir, "fp")
	c := bandTotals(t, h, now, budgetv1alpha1.BandStandard)
	if c.KernelKillsTotal != 1 {
		t.Fatalf("kernelKillsTotal = %d, want the stored 1 (the file was not kept)", c.KernelKillsTotal)
	}
	for _, w := range c.Windows {
		if w.Reason != budgetv1alpha1.CounterKernelKill || w.Count != 1 {
			t.Errorf("published window %+v, want only the valid kernel-kill entry", w)
		}
	}
	if len(c.Windows) != 2 {
		t.Errorf("windows = %+v, want the 1 h and 24 h kernel-kill counts only", c.Windows)
	}
	h.mu.Lock()
	ring, intents, seen := len(h.st.Ring), h.st.Intents, h.st.Seen
	h.mu.Unlock()
	if ring != 1 {
		t.Errorf("ring entries kept = %d, want 1", ring)
	}
	if len(intents) != 1 || intents[0].Pod != types.UID("uid-a") {
		t.Errorf("intents kept = %+v, want uid-a's only", intents)
	}
	if len(seen) != 1 || seen[0].Pod != types.UID("uid-a") {
		t.Errorf("seen kept = %+v, want uid-a's only", seen)
	}
}
