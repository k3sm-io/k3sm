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
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

// exitOf is a terminated container state with exit code and reason.
func exitOf(code int32, reason string) *corev1.ContainerStateTerminated {
	return &corev1.ContainerStateTerminated{ExitCode: code, Reason: reason}
}

// observe hands one exit to h, failing the test on a write error.
func observe(t *testing.T, h *BudgetHistory, pod types.UID, c string, restarts int32, finished int64, term *corev1.ContainerStateTerminated, now time.Time) {
	t.Helper()
	key := terminationKey{restartCount: restarts, exitCode: term.ExitCode, finishedAt: finished}
	if err := h.observeExit(budgetv1alpha1.BandStandard, pod, c, key, term, now); err != nil {
		t.Fatalf("observeExit: %v", err)
	}
}

func uninitiated(t *testing.T, h *BudgetHistory, now time.Time) int64 {
	t.Helper()
	return bandTotals(t, h, now, budgetv1alpha1.BandStandard).KernelKillsTotal
}

// TestBudgetHistoryIntentOutlivesASlowStop: an intent has no wall-clock
// expiry. A stop whose exit is first observed hours later (a slow restart, a
// re-delivered status after a provider restart) is still k3sm's, and each
// covered exit consumes the intent exactly once.
//
// Fails-before: the intent expired grace+5 min after it was written, so the
// 6 h late exit counted as a kernel kill; a pod intent covered every later
// 137 of the pod until it expired; a graceful exit left its container intent
// to cover the next, unrelated, SIGKILL.
func TestBudgetHistoryIntentOutlivesASlowStop(t *testing.T) {
	dir := t.TempDir()
	h := openHistory(t, dir, "fp")
	t0 := time.Unix(1_000_000, 0)

	// A container intent, its exit observed 6 h later after a restart.
	if err := h.recordIntent("uid-slow", "c0"); err != nil {
		t.Fatal(err)
	}
	h = openHistory(t, dir, "fp")
	late := t0.Add(6 * time.Hour)
	observe(t, h, "uid-slow", "c0", 0, 1, exitOf(137, "Error"), late)
	observe(t, h, "uid-slow", "c0", 0, 1, exitOf(137, "Error"), late) // re-delivered
	if got := uninitiated(t, h, late); got != 0 {
		t.Fatalf("a late exit k3sm initiated counted %d, want 0", got)
	}
	// The intent was consumed: the container's next SIGKILL is not k3sm's.
	observe(t, h, "uid-slow", "c0", 1, 2, exitOf(137, "Error"), late)
	if got := uninitiated(t, h, late); got != 1 {
		t.Fatalf("after the intent was consumed: %d, want 1", got)
	}

	// A pod intent covers each container once.
	if err := h.recordIntent("uid-pod", ""); err != nil {
		t.Fatal(err)
	}
	observe(t, h, "uid-pod", "a", 0, 10, exitOf(137, "Error"), late)
	observe(t, h, "uid-pod", "b", 0, 11, exitOf(137, "Error"), late)
	if got := uninitiated(t, h, late); got != 1 {
		t.Fatalf("the pod intent left a container uncovered: %d, want 1", got)
	}
	observe(t, h, "uid-pod", "a", 1, 12, exitOf(137, "Error"), late)
	if got := uninitiated(t, h, late); got != 2 {
		t.Fatalf("a second exit of a covered container: %d, want 2", got)
	}

	// A graceful exit consumes its container intent; a re-delivery of that exit
	// does not consume a later intent.
	if err := h.recordIntent("uid-grace", "c0"); err != nil {
		t.Fatal(err)
	}
	observe(t, h, "uid-grace", "c0", 0, 20, exitOf(143, "Error"), late)
	observe(t, h, "uid-grace", "c0", 1, 21, exitOf(137, "Error"), late)
	if got := uninitiated(t, h, late); got != 3 {
		t.Fatalf("the graceful exit left its intent for the next SIGKILL: %d, want 3", got)
	}
	if err := h.recordIntent("uid-grace", "c0"); err != nil {
		t.Fatal(err)
	}
	observe(t, h, "uid-grace", "c0", 0, 20, exitOf(143, "Error"), late) // re-delivered
	observe(t, h, "uid-grace", "c0", 2, 22, exitOf(137, "Error"), late)
	if got := uninitiated(t, h, late); got != 3 {
		t.Fatalf("a re-delivered graceful exit consumed a later intent: %d, want 3", got)
	}
}

// TestBudgetHistoryNeverPodCountedOnce: a terminated restartPolicy: Never pod
// whose kernel kill is re-delivered every hour for 25 h is counted once; its
// entries go only when the pod leaves the pod set.
//
// Fails-before: a classified termination was forgotten after 24 h, so the
// re-delivery at 25 h counted the same kill again.
func TestBudgetHistoryNeverPodCountedOnce(t *testing.T) {
	h := openHistory(t, t.TempDir(), "fp")
	t0 := time.Unix(1_000_000, 0)
	live := map[types.UID]bool{"uid-job": true}
	for i := 0; i <= 25; i++ {
		now := t0.Add(time.Duration(i) * time.Hour)
		observe(t, h, "uid-job", "main", 0, t0.UnixNano(), exitOf(137, "Error"), now)
		if err := h.retainPods(live, h.mark()); err != nil {
			t.Fatal(err)
		}
	}
	end := t0.Add(25 * time.Hour)
	if got := uninitiated(t, h, end); got != 1 {
		t.Fatalf("a Never pod's one kill counted %d times over 25 h, want 1", got)
	}

	// An intent recorded after the mark survives a prune whose pod set predates
	// it; the gone pod's entries go.
	mark := h.mark()
	if err := h.recordIntent("uid-new", ""); err != nil {
		t.Fatal(err)
	}
	if err := h.retainPods(map[types.UID]bool{}, mark); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	intents, seen := slices.Clone(h.st.Intents), len(h.st.Seen)
	h.mu.Unlock()
	if len(intents) != 1 || intents[0].Pod != "uid-new" || seen != 0 {
		t.Fatalf("after the prune: intents=%+v seen=%d, want only uid-new's intent and nothing seen", intents, seen)
	}
}

// TestPruneBudgetHistoryKeepsTrackedPods: the provider's pod set is the
// apiserver's node list united with the tracked pods.
func TestPruneBudgetHistoryKeepsTrackedPods(t *testing.T) {
	r, _ := newRuntimedFake(t)
	r.history = openHistory(t, t.TempDir(), "fp")
	pod := runtimedPod("default", "web")
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	for _, id := range []types.UID{pod.UID, "uid-listed", "uid-gone"} {
		if err := r.history.recordIntent(id, ""); err != nil {
			t.Fatal(err)
		}
	}
	r.pruneBudgetHistory(map[string]bool{"uid-listed": true}, r.history.mark())
	var got []types.UID
	for _, in := range r.history.st.Intents {
		got = append(got, in.Pod)
	}
	if !slices.Equal(got, []types.UID{pod.UID, "uid-listed"}) {
		t.Fatalf("intents after the prune = %v, want the tracked and the listed pod", got)
	}
}

// intentsFor returns the intents h holds for pod.
func intentsFor(h *BudgetHistory, pod types.UID) []killIntent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []killIntent
	for _, in := range h.st.Intents {
		if in.Pod == pod {
			out = append(out, in)
		}
	}
	return out
}

// TestStopPathsRecordIntents: every provider-initiated stop records its intent
// first, so its exit 137 is never counted as a SIGKILL k3sm did not send.
//
// Fails-before: the postStart StopContainer and the compensating delete
// recorded no intent.
func TestStopPathsRecordIntents(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		container string
		stop      func(r *runtimedRuntime, pod *corev1.Pod)
	}{
		{"postStart StopContainer", "c0", func(r *runtimedRuntime, pod *corev1.Pod) {
			_ = r.stopContainerReason(ctx, string(pod.UID), "c0", reasonFailedPostStartHook)
		}},
		{"compensating delete", "", func(r *runtimedRuntime, pod *corev1.Pod) {
			r.runCompensatingDelete(pod, string(pod.UID))
		}},
		{"pod delete", "", func(r *runtimedRuntime, pod *corev1.Pod) {
			if err := r.DeletePod(ctx, pod); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newRuntimedFake(t)
			r.history = openHistory(t, t.TempDir(), "fp")
			pod := runtimedPod("default", "web")
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			tc.stop(r, pod)
			got := intentsFor(r.history, pod.UID)
			if len(got) != 1 || got[0].Container != tc.container {
				t.Fatalf("intents = %+v, want one for container %q", got, tc.container)
			}
		})
	}
}

// TestEvictionIntentWriteIsTimeBoxed: a stalled history write does not hold
// back the emergency kill; the intent is in memory at once, so the exit is
// still classified as k3sm's in this run.
//
// Fails-before: evictPod waited on the intent's fsync before its DeletePod.
func TestEvictionIntentWriteIsTimeBoxed(t *testing.T) {
	r, _ := newRuntimedFake(t)
	r.history = openHistory(t, t.TempDir(), "fp")
	release := make(chan struct{})
	r.history.write = func(string, []byte, os.FileMode) error {
		<-release
		return nil
	}
	pod := runtimedPod("default", "hog")
	start := time.Now()
	r.recordStopIntentWithin(pod, "", 50*time.Millisecond)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the intent write held the stop for %v", d)
	}
	if got := intentsFor(r.history, pod.UID); len(got) != 1 {
		t.Fatalf("intents = %+v, want the eviction's intent in memory", got)
	}
	// The stalled write finishes; the exit is then classified against the
	// intent the eviction recorded.
	close(release)
	observe(t, r.history, pod.UID, "c0", 0, 1, exitOf(137, "Error"), time.Now())
	if got := uninitiated(t, r.history, time.Now()); got != 0 {
		t.Fatalf("the eviction's exit counted as uninitiated: %d", got)
	}
}

// TestBudgetHistoryDegradesToMemory: an unusable history dir leaves the
// provider starting, with a working in-memory history.
//
// Fails-before: OpenBudgetHistory's error failed NewRuntimed, so the node did
// not start.
func TestBudgetHistoryDegradesToMemory(t *testing.T) {
	stageExecShim(t)
	notDir := filepath.Join(t.TempDir(), "budget")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	r, err := NewRuntimed(context.Background(), RuntimedConfig{
		NodeName: "n1", Root: root, PodLogsDir: root, BudgetDir: notDir, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewRuntimed with an unusable budget dir: %v", err)
	}
	if r.history == nil || r.history.path != "" {
		t.Fatalf("history = %+v, want an in-memory history", r.history)
	}
	now := time.Now()
	if err := r.history.record(budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, now); err != nil {
		t.Fatalf("an in-memory record failed: %v", err)
	}
	if got := bandTotals(t, r.history, now, budgetv1alpha1.BandBatch).EvictionsTotal; got != 1 {
		t.Fatalf("in-memory evictions = %d, want 1", got)
	}

	// A corrupt file: the provider starts, the file is moved aside.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, budgetHistoryFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err = NewRuntimed(context.Background(), RuntimedConfig{
		NodeName: "n1", Root: root, PodLogsDir: root, BudgetDir: dir, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewRuntimed with a corrupt history: %v", err)
	}
	if r.history == nil || r.history.path == "" {
		t.Fatalf("a corrupt history did not reopen on disk: %+v", r.history)
	}
}

// TestBudgetHistoryAsidesAndOrphans: the moved-aside files are uniquely named
// and capped, and an orphaned write temp is removed on open.
func TestBudgetHistoryAsidesAndOrphans(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, budgetHistoryFile)
	// An older build's seconds-suffixed aside, the oldest of all.
	old := path + budgetHistoryAsideInfix + "1000"
	if err := os.WriteFile(old, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(dir, "."+budgetHistoryFile+".tmp-123456")
	if err := os.WriteFile(orphan, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < budgetHistoryAsideMax+2; i++ {
		if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		openHistory(t, dir, "fp")
	}
	asides, _ := filepath.Glob(path + budgetHistoryAsideInfix + "*")
	if len(asides) != budgetHistoryAsideMax {
		t.Fatalf("asides = %v, want %d", asides, budgetHistoryAsideMax)
	}
	for _, a := range asides {
		suffix := strings.TrimPrefix(a, path+budgetHistoryAsideInfix)
		if n, err := strconv.ParseInt(suffix, 10, 64); err != nil || n < 1e12 {
			t.Errorf("aside %s is not nanosecond-named", a)
		}
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("the orphaned temp survived the open: %v", err)
	}
}

// TestBudgetHistoryFullFileFitsTheReadBound: a history at every bound, with
// the longest container names, still reads back under budgetHistoryMaxBytes.
func TestBudgetHistoryFullFileFitsTheReadBound(t *testing.T) {
	st := newHistoryState()
	long := strings.Repeat("c", 63)
	uid := types.UID("00000000-0000-0000-0000-000000000000")
	for _, b := range budgetv1alpha1.Bands() {
		st.Totals[b] = historyTotals{Evictions: 1 << 62, OOMKills: 1 << 62, KernelKills: 1 << 62, Restarts: 1 << 62, MemHigh: 1 << 62, Tier1Refused: 1 << 62}
	}
	for i := 0; i < budgetHistoryRingMax; i++ {
		st.Ring = append(st.Ring, historyEvent{At: 1 << 40, Band: budgetv1alpha1.BandStandard, Reason: budgetv1alpha1.CounterKernelKill})
	}
	for i := 0; i < budgetIntentMax; i++ {
		st.Intents = append(st.Intents, killIntent{Pod: uid, Container: long, Covered: []string{long}})
	}
	for i := 0; i < budgetSeenMax; i++ {
		st.Seen = append(st.Seen, seenExit{Pod: uid, Container: long, RestartCount: 1 << 30, FinishedAt: 1 << 62, At: 1 << 40})
	}
	data, err := json.Marshal(&st)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > budgetHistoryMaxBytes {
		t.Fatalf("a full history is %d bytes, over the read bound %d", len(data), budgetHistoryMaxBytes)
	}
}
