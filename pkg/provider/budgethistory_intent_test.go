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
	"testing/synctest"
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
	h.observeExit(budgetv1alpha1.BandStandard, pod, c, key, term, now)
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
	h.recordIntent("uid-slow", "c0")
	flushHistory(t, h)
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
	h.recordIntent("uid-pod", "")
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
	h.recordIntent("uid-grace", "c0")
	observe(t, h, "uid-grace", "c0", 0, 20, exitOf(143, "Error"), late)
	observe(t, h, "uid-grace", "c0", 1, 21, exitOf(137, "Error"), late)
	if got := uninitiated(t, h, late); got != 3 {
		t.Fatalf("the graceful exit left its intent for the next SIGKILL: %d, want 3", got)
	}
	h.recordIntent("uid-grace", "c0")
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
		h.retainPods(live, h.mark())
	}
	end := t0.Add(25 * time.Hour)
	if got := uninitiated(t, h, end); got != 1 {
		t.Fatalf("a Never pod's one kill counted %d times over 25 h, want 1", got)
	}

	// An intent recorded after the mark survives a prune whose pod set predates
	// it; the gone pod's entries go.
	mark := h.mark()
	h.recordIntent("uid-new", "")
	h.retainPods(map[types.UID]bool{}, mark)
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
		r.history.recordIntent(id, "")
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
	blockWrites(r.history, release)
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
	r.history.record("", budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, now)
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

// blockWrites makes every later write of h wait until release is closed.
func blockWrites(h *BudgetHistory, release <-chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.write = func(string, []byte, os.FileMode) error {
		<-release
		return nil
	}
}

// TestBudgetHistoryStalledWriterBlocksNoHotPath: with the writer blocked
// forever, an eviction completes within its 250 ms intent wait, the post-kill
// count and the status path's classification return at once, and the memory
// state is right. The writer stops once its write is released.
//
// Fails-before: every mutation wrote the file inline, so a stalled write held
// evictPod after the kill and buildStatus on the write lock.
func TestBudgetHistoryStalledWriterBlocksNoHotPath(t *testing.T) {
	synctest.Test(t, testBudgetHistoryStalledWriterBlocksNoHotPath)
}

func testBudgetHistoryStalledWriterBlocksNoHotPath(t *testing.T) {
	h := newEvictionHarness(t)
	quiesceInBubble(t, h.r)
	h.r.history = openHistory(t, t.TempDir(), "fp")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // runs before the writer's own cleanup
	// Wedge the writer inside a write first, so every later change queues.
	blockWrites(h.r.history, release)
	h.r.history.record("", budgetv1alpha1.BandStandard, budgetv1alpha1.CounterRestart, time.Now())

	hog := evPod("hog", nil, "", "")
	hog.Annotations = map[string]string{budgetv1alpha1.AnnotationBand: "batch"}
	quiet := evPod("quiet", nil, "1Gi", "1Gi")
	h.add(hog, "2Gi")
	h.add(quiet, "200Mi")

	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := h.r.evictPod(context.Background(), hog, evictionNotice{signal: signalCompressor, message: "x"}); err != nil {
			t.Errorf("evictPod: %v", err)
		}
		qt := h.r.trackByID("uid-quiet")
		h.r.buildStatus(quiet.DeepCopy(), qt, exitStatus("uid-quiet", 137, "Error", 0, time.Unix(5000, 0)), nil)
	}()
	// In the bubble the clock moves only while every goroutine waits, so the
	// elapsed time is exactly the hot path's own waits; a hot path parked on
	// the stalled write never returns, which synctest reports as a deadlock.
	<-done
	if took := time.Since(start); took > budgetIntentWriteBound {
		t.Fatalf("the eviction and the status path took %v with a stalled writer, want at most the intent wait %v",
			took, budgetIntentWriteBound)
	}
	now := time.Now()
	batch := bandTotals(t, h.r.history, now, budgetv1alpha1.BandBatch)
	std := bandTotals(t, h.r.history, now, budgetv1alpha1.BandStandard)
	if batch.EvictionsTotal != 1 || std.KernelKillsTotal != 1 || std.RestartsTotal != 1 {
		t.Fatalf("in memory: evictions=%d kernelKills=%d restarts=%d, want 1/1/1",
			batch.EvictionsTotal, std.KernelKillsTotal, std.RestartsTotal)
	}
	if got := intentsFor(h.r.history, hog.UID); len(got) != 1 {
		t.Fatalf("the eviction's intent = %+v, want one in memory", got)
	}
}

// TestBudgetHistoryFinalFlushOnShutdown: a change made just before the
// provider's context ends reaches disk, and the writer stops.
func TestBudgetHistoryFinalFlushOnShutdown(t *testing.T) {
	synctest.Test(t, testBudgetHistoryFinalFlushOnShutdown)
}

func testBudgetHistoryFinalFlushOnShutdown(t *testing.T) {
	dir := t.TempDir()
	h := OpenBudgetHistory(dir, "fp", discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	h.start(ctx)
	h.record("", budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, time.Now())
	cancel()
	synctest.Wait()
	select {
	case <-h.stopped:
	default:
		t.Fatal("the writer did not stop on shutdown")
	}
	got := openHistory(t, dir, "fp")
	if n := bandTotals(t, got, time.Now(), budgetv1alpha1.BandBatch).EvictionsTotal; n != 1 {
		t.Fatalf("after shutdown the file holds evictions=%d, want 1", n)
	}
}

// TestBudgetHistorySelfKillCannotEvictOthers: a restartPolicy: Always pod
// that SIGKILLs itself thousands of times holds one classified-exit entry and
// at most budgetHistoryRingPerPod window entries, so another pod's earlier OOM
// kill is neither re-counted on re-delivery nor pushed out of the windows.
// Its own totals stay exact.
//
// Fails-before: every termination appended a Seen entry and a ring entry, so
// 5000 self-kills evicted the other pod's Seen entry (its re-delivered OOM
// counted twice) and its ring entry (its windows read 0).
func TestBudgetHistorySelfKillCannotEvictOthers(t *testing.T) {
	h := openHistory(t, t.TempDir(), "fp")
	t0 := time.Unix(1_000_000, 0)
	oom := func(now time.Time) {
		key := terminationKey{restartCount: 0, exitCode: 137, finishedAt: 1}
		h.observeExit(budgetv1alpha1.BandBatch, "uid-victim", "c0", key, exitOf(137, oomKilledReason), now)
	}
	oom(t0)
	const kills = 5000
	for i := 0; i < kills; i++ {
		observe(t, h, "uid-loop", "c0", int32(i), int64(i+10), exitOf(137, "Error"), t0.Add(time.Duration(i)*time.Millisecond))
	}
	now := t0.Add(10 * time.Minute)
	oom(now) // re-delivered
	batch := bandTotals(t, h, now, budgetv1alpha1.BandBatch)
	std := bandTotals(t, h, now, budgetv1alpha1.BandStandard)
	if batch.OOMKillsTotal != 1 {
		t.Errorf("the victim's OOM kill counted %d times, want 1", batch.OOMKillsTotal)
	}
	if got := windowCount(batch, budgetv1alpha1.Window1h, budgetv1alpha1.CounterOOMKill); got != 1 {
		t.Errorf("the victim's 1h OOM window = %d, want 1", got)
	}
	if got := windowCount(batch, budgetv1alpha1.Window24h, budgetv1alpha1.CounterOOMKill); got != 1 {
		t.Errorf("the victim's 24h OOM window = %d, want 1", got)
	}
	if std.KernelKillsTotal != kills {
		t.Errorf("the looping pod's total = %d, want %d (totals stay exact)", std.KernelKillsTotal, kills)
	}
	if got := windowCount(std, budgetv1alpha1.Window24h, budgetv1alpha1.CounterKernelKill); got != budgetHistoryRingPerPod {
		t.Errorf("the looping pod's 24h window = %d, want the per-pod cap %d", got, budgetHistoryRingPerPod)
	}
	h.mu.Lock()
	seen := len(h.st.Seen)
	h.mu.Unlock()
	if seen != 2 {
		t.Errorf("classified-exit entries = %d, want 2 (one per container)", seen)
	}
}

// TestStopBudgetHistoryFlushesBeforeExit: the node teardown's StopBudgetHistory
// writes the last change and stops the writer even when the provider's context
// has not ended (the run-loop-error exit), so a process that exits right after
// it loses nothing.
//
// Fails-before: nothing joined the writer, so an exit right after the context
// ended could beat the final flush.
func TestStopBudgetHistoryFlushesBeforeExit(t *testing.T) {
	dir := t.TempDir()
	r, _ := newRuntimedFake(t)
	r.history = OpenBudgetHistory(dir, "fp", discardLog())
	r.history.start(context.Background())
	r.history.record("uid-x", budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, time.Now())
	if !NewVKProvider(r, "n").StopBudgetHistory() {
		t.Fatal("StopBudgetHistory did not finish in its bound")
	}
	select {
	case <-r.history.stopped:
	default:
		t.Fatal("the writer is still running after StopBudgetHistory")
	}
	st, err := readHistory(filepath.Join(dir, budgetHistoryFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Totals[budgetv1alpha1.BandBatch].Evictions; got != 1 {
		t.Fatalf("the file holds evictions=%d after the stop, want 1", got)
	}
	if !r.StopBudgetHistory() {
		t.Fatal("a second StopBudgetHistory must report true")
	}
}
