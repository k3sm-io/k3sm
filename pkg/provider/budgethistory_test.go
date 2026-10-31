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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	testclock "k8s.io/utils/clock/testing"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// bandTotals returns band's entry of h.Counters(now).
func bandTotals(t *testing.T, h *BudgetHistory, now time.Time, band budgetv1alpha1.Band) budgetv1alpha1.BandCounters {
	t.Helper()
	for _, c := range h.Counters(now) {
		if c.Band == band {
			return c
		}
	}
	t.Fatalf("no counters for band %s", band)
	return budgetv1alpha1.BandCounters{}
}

func windowCount(c budgetv1alpha1.BandCounters, w budgetv1alpha1.CounterWindow, r budgetv1alpha1.CounterReason) int64 {
	for _, wc := range c.Windows {
		if wc.Window == w && wc.Reason == r {
			return wc.Count
		}
	}
	return 0
}

func openHistory(t *testing.T, dir, fingerprint string) *BudgetHistory {
	t.Helper()
	h := OpenBudgetHistory(dir, fingerprint, discardLog())
	if h.path == "" {
		t.Fatalf("OpenBudgetHistory(%s) degraded to memory only", dir)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.start(ctx)
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.stopped:
		case <-time.After(10 * time.Second):
			t.Errorf("the budget history writer did not stop")
		}
	})
	return h
}

// flushHistory waits for h's state to reach disk.
func flushHistory(t *testing.T, h *BudgetHistory) {
	t.Helper()
	if !h.flush(10 * time.Second) {
		t.Fatalf("the budget history did not flush")
	}
}

// exitStatus is a runtimed status for pod id whose container c0 terminated
// with exit and reason at finishedAt.
func exitStatus(id string, exit int32, reason string, restarts int32, finishedAt time.Time) *runtimev1.PodStatus {
	cs := rtTerminated("c0", exit, restarts, finishedAt)
	cs.State.GetTerminated().Reason = reason
	return &runtimev1.PodStatus{PodId: id, Phase: runtimev1.PodPhase_POD_PHASE_RUNNING, ContainerStatuses: []*runtimev1.ContainerStatus{cs}}
}

// TestBudgetHistorySurvivesProviderRestart is the B784 gate: the eviction
// manager and the container lifecycle append to the persisted history, its
// per-band totals and windows survive a provider restart over the same work
// dir, a re-delivered exit is counted once (before and after the restart), an
// exit 137 with a persisted stop intent is not a kernel kill, and the arming
// episode count resets on a binary or policy change while the totals do not.
//
// Fails-before: there was no persisted history; the only eviction count was
// the manager's in-process map, gone on restart, and exit 137 was never
// classified.
func TestBudgetHistorySurvivesProviderRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "server", "budget")
	h := newEvictionHarness(t)
	h.r.history = openHistory(t, dir, "fp-1")
	clk := h.r.clk.(*testclock.FakeClock)

	hog := evPod("hog", nil, "", "")
	hog.Annotations = map[string]string{budgetv1alpha1.AnnotationBand: "batch"}
	hog.Spec.RestartPolicy = corev1.RestartPolicyAlways
	quiet := evPod("quiet", nil, "1Gi", "1Gi")
	quiet.Spec.RestartPolicy = corev1.RestartPolicyAlways
	h.add(hog, "2Gi")
	h.add(quiet, "200Mi")

	// The eviction manager evicts the batch pod.
	h.step(compressorAt(85))
	if ids := h.deleteIDs(); len(ids) != 1 || ids[0] != "uid-hog" {
		t.Fatalf("DeletePod ids = %v, want [uid-hog]", ids)
	}

	// The kernel kills the standard pod's container: exit 137, reason Error,
	// no k3sm stop. Delivered twice (stream, then backstop): counted once.
	t0 := clk.Now()
	kill := exitStatus("uid-quiet", 137, "Error", 0, t0)
	qt := h.r.trackByID("uid-quiet")
	h.r.buildStatus(quiet.DeepCopy(), qt, kill, nil)
	h.r.buildStatus(quiet.DeepCopy(), qt, kill, nil)

	// The lifecycle restarts it: one restart.
	waitWaiters(t, clk, 1)
	clk.Step(time.Minute)
	deadline := time.Now().Add(2 * time.Second)
	for bandTotals(t, h.r.history, clk.Now(), budgetv1alpha1.BandStandard).RestartsTotal != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("the restart was never counted")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// An OOM kill (a vm guest's) and a k3sm-initiated stop: the stop's intent is
	// persisted first, so its exit 137 is not a kernel kill.
	h.r.buildStatus(quiet.DeepCopy(), qt, exitStatus("uid-quiet", 137, oomKilledReason, 1, t0.Add(time.Second)), nil)
	h.r.recordStopIntent(quiet, "c0")

	check := func(t *testing.T, hist *BudgetHistory, now time.Time) {
		t.Helper()
		batch := bandTotals(t, hist, now, budgetv1alpha1.BandBatch)
		std := bandTotals(t, hist, now, budgetv1alpha1.BandStandard)
		if batch.KernelKillsTotal != 0 {
			t.Errorf("batch kernelKills=%d, want 0: the eviction's exit is k3sm's own", batch.KernelKillsTotal)
		}
		if batch.EvictionsTotal != 1 || std.EvictionsTotal != 0 {
			t.Errorf("evictionsTotal batch=%d standard=%d, want 1/0", batch.EvictionsTotal, std.EvictionsTotal)
		}
		if std.KernelKillsTotal != 1 || std.OOMKillsTotal != 1 || std.RestartsTotal != 1 {
			t.Errorf("standard kernelKills=%d oomKills=%d restarts=%d, want 1/1/1", std.KernelKillsTotal, std.OOMKillsTotal, std.RestartsTotal)
		}
		if batch.Tier1RefusedTotal != 0 || std.Tier1RefusedTotal != 0 {
			t.Errorf("tier1RefusedTotal must stay 0 on k3sm")
		}
		if got := windowCount(std, budgetv1alpha1.Window1h, budgetv1alpha1.CounterKernelKill); got != 1 {
			t.Errorf("standard 1h kernel-kill = %d, want 1", got)
		}
		if got := windowCount(batch, budgetv1alpha1.Window24h, budgetv1alpha1.CounterEviction); got != 1 {
			t.Errorf("batch 24h eviction = %d, want 1", got)
		}
		for _, c := range hist.Counters(now) {
			if len(c.Windows) > budgetv1alpha1.MaxWindowCounts {
				t.Errorf("%s carries %d windowed counts, over the apis bound %d", c.Band, len(c.Windows), budgetv1alpha1.MaxWindowCounts)
			}
		}
	}
	check(t, h.r.history, clk.Now())

	// The provider restarts: a new runtime over the same work dir.
	flushHistory(t, h.r.history)
	r2, _, clk2 := newRestartFake(t)
	clk2.SetTime(clk.Now().Add(2 * time.Minute))
	r2.history = openHistory(t, dir, "fp-1")
	if err := r2.CreatePod(t.Context(), quiet.DeepCopy()); err != nil {
		t.Fatalf("CreatePod after restart: %v", err)
	}
	q2 := r2.trackByID("uid-quiet")
	// The first status after the restart re-delivers the already-classified
	// kernel kill: not counted again.
	r2.buildStatus(quiet.DeepCopy(), q2, kill, nil)
	// The stop k3sm announced before the restart exits 137: its persisted intent
	// covers it.
	r2.buildStatus(quiet.DeepCopy(), q2, exitStatus("uid-quiet", 137, "Error", 2, t0.Add(2*time.Second)), nil)
	// The evicted pod's exit 137, first seen by the restarted provider: the
	// eviction's pod-wide intent, persisted before its DeletePod, covers it.
	if err := r2.CreatePod(t.Context(), hog.DeepCopy()); err != nil {
		t.Fatalf("CreatePod hog after restart: %v", err)
	}
	r2.buildStatus(hog.DeepCopy(), r2.trackByID("uid-hog"), exitStatus("uid-hog", 137, "Error", 0, t0), nil)
	check(t, r2.history, clk2.Now())

	// The windows age out; the totals never do.
	later := clk2.Now().Add(25 * time.Hour)
	if std := bandTotals(t, r2.history, later, budgetv1alpha1.BandStandard); len(std.Windows) != 0 || std.KernelKillsTotal != 1 {
		t.Errorf("after 25h: windows=%v kernelKills=%d, want none/1", std.Windows, std.KernelKillsTotal)
	}

	// The arming count persists under the same fingerprint and resets on a
	// binary or policy change; the totals stay.
	r2.history.mu.Lock()
	r2.history.st.ArmingEpisodes = 2
	r2.history.changedLocked()
	r2.history.mu.Unlock()
	flushHistory(t, r2.history)
	if got := openHistory(t, dir, "fp-1").ArmingEpisodes(); got != 2 {
		t.Errorf("armingEpisodes under the same fingerprint = %d, want 2", got)
	}
	changed := openHistory(t, dir, "fp-2")
	if got := changed.ArmingEpisodes(); got != 0 {
		t.Errorf("armingEpisodes after a fingerprint change = %d, want 0", got)
	}
	if std := bandTotals(t, changed, clk2.Now(), budgetv1alpha1.BandStandard); std.KernelKillsTotal != 1 {
		t.Errorf("a fingerprint change reset the totals: kernelKills=%d", std.KernelKillsTotal)
	}

	// The state is the node's alone: dir 0700, file 0600, and the published
	// counters name no pod.
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("history dir mode = %v (%v), want 0700", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(filepath.Join(dir, budgetHistoryFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("history file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	pub, _ := json.Marshal(changed.Counters(clk2.Now()))
	for _, s := range []string{"hog", "quiet", "default"} {
		if strings.Contains(string(pub), s) {
			t.Errorf("published counters carry %q: %s", s, pub)
		}
	}
}

func TestBandOf(t *testing.T) {
	cases := []struct {
		name string
		prio *int32
		ann  map[string]string
		want budgetv1alpha1.Band
	}{
		{"unmarked is standard", nil, nil, budgetv1alpha1.BandStandard},
		{"batch annotation", nil, map[string]string{budgetv1alpha1.AnnotationBand: "batch"}, budgetv1alpha1.BandBatch},
		{"other annotation value is standard", nil, map[string]string{budgetv1alpha1.AnnotationBand: "critical"}, budgetv1alpha1.BandStandard},
		{"system-critical priority", prio(systemCriticalPriority), nil, budgetv1alpha1.BandCritical},
		{"batch never lowers a critical pod", prio(systemCriticalPriority), map[string]string{budgetv1alpha1.AnnotationBand: "batch"}, budgetv1alpha1.BandCritical},
		{"static pod", nil, map[string]string{configSourceAnnotationKey: "file"}, budgetv1alpha1.BandCritical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := evPod("p", tc.prio, "", "")
			p.Annotations = tc.ann
			if got := bandOf(p); got != tc.want {
				t.Errorf("bandOf = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBudgetHistoryUnreadableFileStartsEmpty(t *testing.T) {
	cases := map[string]string{
		"not json":          "{",
		"unknown version":   `{"version":9,"totals":{}}`,
		"unknown band":      `{"version":1,"totals":{"gold":{"evictions":1}}}`,
		"negative total":    `{"version":1,"totals":{"batch":{"evictions":-1}}}`,
		"negative arming":   `{"version":1,"armingEpisodes":-1}`,
		"oversized file":    `{"version":1,"x":"` + strings.Repeat("a", budgetHistoryMaxBytes) + `"}`,
		"good, for control": `{"version":1,"fingerprint":"fp","totals":{"batch":{"evictions":3}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, budgetHistoryFile)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			h := openHistory(t, dir, "fp")
			got := bandTotals(t, h, time.Now(), budgetv1alpha1.BandBatch).EvictionsTotal
			aside, _ := filepath.Glob(path + ".unreadable-*")
			if name == "good, for control" {
				if got != 3 || len(aside) != 0 {
					t.Errorf("good file: evictions=%d aside=%v, want 3 and none", got, aside)
				}
				return
			}
			if got != 0 || len(aside) != 1 {
				t.Errorf("evictions=%d aside=%v, want 0 and the file moved aside", got, aside)
			}
		})
	}
}

func TestBudgetHistoryRingIsBounded(t *testing.T) {
	h := openHistory(t, t.TempDir(), "fp")
	now := time.Unix(1_000_000, 0)
	for i := 0; i < budgetHistoryRingMax+10; i++ {
		h.mu.Lock()
		h.recordLocked(budgetv1alpha1.BandBatch, budgetv1alpha1.CounterRestart, now)
		h.mu.Unlock()
	}
	h.record(budgetv1alpha1.BandBatch, budgetv1alpha1.CounterRestart, now)
	c := bandTotals(t, h, now, budgetv1alpha1.BandBatch)
	if c.RestartsTotal != budgetHistoryRingMax+11 {
		t.Errorf("restartsTotal = %d, want %d", c.RestartsTotal, budgetHistoryRingMax+11)
	}
	if got := windowCount(c, budgetv1alpha1.Window1h, budgetv1alpha1.CounterRestart); got != budgetHistoryRingMax {
		t.Errorf("1h restarts = %d, want the ring bound %d", got, budgetHistoryRingMax)
	}
}
