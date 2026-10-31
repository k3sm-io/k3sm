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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/pkg/version"
)

// The budget history: the node's persisted record of evictions, OOM kills,
// SIGKILLs k3sm did not initiate, and restarts, kept so the per-band totals the
// budget publishes survive pod death and a provider restart (`launchctl
// kickstart`).
//
// It lives in the node's own work dir, <workdir>/budget/ (mode 0700), which is
// inside the protected server or agent tree and outside every path a pod can
// open. It holds three things in one file:
//
//   - per-band monotonic totals (evictions, OOM kills, SIGKILLs not initiated by
//     k3sm, restarts, memory.high events, refused tier-1 deliveries), never
//     reset;
//   - a bounded ring of recent events (time, band, reason) from which the 1 h
//     and 24 h windowed counts are derived. On disk the ring carries no pod
//     name, namespace or UID. In memory each entry this run recorded keeps its
//     pod UID so one pod holds at most budgetHistoryRingPerPod entries of the
//     last 24 h: a pod that kills itself in a loop drops its own oldest entry,
//     never another pod's, so it cannot push other pods out of the windows.
//     The windows then under-count that pod; the totals stay exact;
//   - the intent ledger: a record, written BEFORE every k3sm-initiated stop, of
//     which pod (or which container) k3sm is about to stop, so a later exit 137
//     can be told apart from a SIGKILL k3sm did not send. Beside it, the
//     identity of the latest termination classified per (pod UID, container),
//     so a re-delivered exit (the status stream and the backstop, or the first
//     status after a restart) is counted once. A newer termination of the
//     container replaces its entry in place, so the list is bounded by the
//     node's containers, not by how often one of them dies. Both hold pod UIDs;
//     neither is ever published.
//
// Intents and classified terminations live as long as their pod: an entry is
// dropped when its pod UID is in neither the provider's tracked pods nor a
// successful apiserver list of this node's pods (retainPods, driven by the
// orphan reaper's tick), never on a timer, so a slow stop or a terminated
// restartPolicy: Never pod whose exit is re-delivered a day later is still
// matched. A container intent is consumed by the one exit it covers (graceful
// or 137); a pod intent covers each container's exit once. The bounds below drop
// the oldest entry only past a size a node-wide drain stays far under.
//
// It also holds the tier-1 arming episode count with the fingerprint it was
// earned under; opening the history under a different fingerprint (a new
// binary, or a policy change once a policy exists) resets the count to 0.
//
// Counter sources on Darwin: evictionsTotal is k3sm's own evictions;
// oomKillsTotal is a container exit runtimed reports as OOMKilled (a vm guest's
// out-of-memory kill); kernelKillsTotal (the apis field name) is an exit 137
// k3sm recorded no stop intent for, that is, a SIGKILL not initiated by k3sm. A
// kernel pcontrol kill is one source, but so is any SIGKILL the pod's own
// processes send each other (`kill -9` of its main process), which k3sm cannot
// tell apart from the kernel's: the counter is a tenant-influenceable signal, an
// upper bound on kernel kills, and nothing may treat it as proof of memory
// pressure. Nothing on Darwin produces memHighEventsTotal yet, and
// tier1RefusedTotal stays 0 because k3sm delivers tier 1 through its node-side
// eviction path, which, like the kubelet's own eviction, does not consult
// PodDisruptionBudgets.
//
// No provider hot path waits on the disk. Every mutation changes the state in
// memory under the state lock and signals one writer goroutine (run), started
// with the provider's run context, which writes a snapshot of the latest state,
// so a burst of mutations coalesces into one write. Every write replaces the
// file atomically. A write failure is logged and retried; the in-memory state
// stays authoritative for this run. The one ordering guarantee is the emergency
// eviction's: it asks the writer to flush and waits up to budgetIntentWriteBound
// for its intent to reach disk before the kill. On shutdown (the provider's run
// context ending, or the node's teardown calling StopBudgetHistory) the writer
// makes one final flush and stops; the node's teardown waits at most
// budgetHistoryFinalFlushBound for that, so a change made in the last moments
// before the process exits reaches disk unless the disk is stalled past the
// bound. An unreadable or unrecognised file is moved aside (the last
// budgetHistoryAsideMax are kept) and the history starts empty: the totals then
// restart at 0, as a counter does after a reset. A history dir that cannot be
// prepared or written degrades to an in-memory history with a Warn log: the
// node runs, and its counters restart at 0 on the next provider start.

// The history file and its bounds.
const (
	budgetHistoryFile    = "history.json"
	budgetHistoryVersion = 1
	// budgetHistoryMaxBytes bounds the file read at open. The bounds below keep
	// a full file far under it (TestBudgetHistoryFullFileFitsTheReadBound).
	budgetHistoryMaxBytes = 2 << 20
	// budgetHistoryRingMax is the most events the ring keeps. A node that
	// records more than this in 24 h under-reports its 24 h windows; the
	// totals are unaffected.
	budgetHistoryRingMax = 2048
	// budgetHistoryRingPerPod is the most ring entries of the last 24 h one pod
	// holds (in this run); past it the pod's own oldest entry goes.
	budgetHistoryRingPerPod = 16
	// budgetIntentMax and budgetSeenMax bound the intent ledger and the
	// classified-termination list; past them the oldest entry goes first. Both
	// are pruned by pod lifetime, so they hold only live pods' entries: a
	// node-wide drain records one pod intent per pod, far under the bound.
	budgetIntentMax = 2048
	budgetSeenMax   = 4096
	// budgetHistoryAsideMax is how many moved-aside unreadable files are kept.
	budgetHistoryAsideMax = 3
	// budgetIntentWriteBound is how long the emergency eviction waits for its
	// intent to reach disk before it kills anyway (recordStopIntentWithin).
	budgetIntentWriteBound = 250 * time.Millisecond
	// budgetHistoryFinalFlushBound bounds the writer's final flush on shutdown,
	// and the node teardown's wait for it (StopBudgetHistory).
	budgetHistoryFinalFlushBound = 2 * time.Second
	// budgetHistoryRetryInterval is how often the writer retries a failed write.
	budgetHistoryRetryInterval = 30 * time.Second
)

// budgetHistoryAsideInfix names a moved-aside unreadable history:
// history.json.unreadable-<unix nanoseconds>.
const budgetHistoryAsideInfix = ".unreadable-"

// oomKilledReason is the container termination reason of an out-of-memory kill.
const oomKilledReason = "OOMKilled"

// errBudgetHistoryFormat marks a history file this build does not read.
var errBudgetHistoryFormat = errors.New("unrecognised budget history format")

// historyTotals are one band's monotonic totals. KernelKills keeps the apis
// name; it counts SIGKILLs not initiated by k3sm (see the file comment).
type historyTotals struct {
	Evictions    int64 `json:"evictions"`
	OOMKills     int64 `json:"oomKills"`
	KernelKills  int64 `json:"kernelKills"`
	Restarts     int64 `json:"restarts"`
	MemHigh      int64 `json:"memHigh"`
	Tier1Refused int64 `json:"tier1Refused"`
}

// historyEvent is one ring entry: when, which band, what. pod is kept in
// memory only, for the per-pod cap; it is never persisted.
type historyEvent struct {
	At     int64                        `json:"at"` // unix seconds
	Band   budgetv1alpha1.Band          `json:"band"`
	Reason budgetv1alpha1.CounterReason `json:"reason"`
	pod    types.UID
}

// killIntent records that k3sm is about to stop a pod (Container empty) or one
// of its containers. A pod intent lists the containers whose exit it already
// covered. seq orders the entry against a retainPods mark; it is not persisted
// (an entry read from disk is older than every mark).
type killIntent struct {
	Pod       types.UID `json:"pod"`
	Container string    `json:"container,omitempty"`
	Covered   []string  `json:"covered,omitempty"`
	seq       uint64
}

// seenExit is the latest classified termination of one container: the
// container and runtimed's termination identity. seq is as killIntent's.
type seenExit struct {
	Pod          types.UID `json:"pod"`
	Container    string    `json:"container"`
	RestartCount int32     `json:"restartCount"`
	FinishedAt   int64     `json:"finishedAt"` // unix nanoseconds
	At           int64     `json:"at"`         // unix seconds, when classified
	seq          uint64
}

// historyState is the persisted document.
type historyState struct {
	Version        int                                   `json:"version"`
	Fingerprint    string                                `json:"fingerprint"`
	ArmingEpisodes int64                                 `json:"armingEpisodes"`
	Totals         map[budgetv1alpha1.Band]historyTotals `json:"totals"`
	Ring           []historyEvent                        `json:"ring"`
	Intents        []killIntent                          `json:"intents"`
	Seen           []seenExit                            `json:"seen"`
}

// BudgetHistory is the node's persisted eviction, OOM and restart history. The
// zero value is not used; OpenBudgetHistory builds one. A nil *BudgetHistory
// records nothing and reports zeros, which is what a node with no work dir
// (a standalone `k3sm node`) runs with.
//
// Locking: mu guards every field below it and is held only for in-memory work,
// never across a file write. Only the writer goroutine (run) writes the file
// after open; it marshals the state under mu and writes outside it.
type BudgetHistory struct {
	path string // "" keeps the history in memory only
	log  *slog.Logger

	dirty    chan struct{} // capacity 1: a pending-write signal, coalesced
	once     sync.Once     // starts run once
	started  atomic.Bool
	quit     chan struct{} // closed by stop
	quitOnce sync.Once
	stopped  chan struct{} // closed when run returns

	mu      sync.Mutex
	st      historyState
	seq     uint64        // entry order, for retainPods marks
	gen     uint64        // bumped by every mutation
	written uint64        // the gen the file last held
	wrote   chan struct{} // closed and replaced after each successful write
	write   func(path string, data []byte, mode os.FileMode) error
}

// OpenBudgetHistory opens (creating it if needed) the history in dir, which it
// creates mode 0700. fingerprint names the binary and policy the arming count
// is valid for; a stored count earned under another fingerprint is reset. It
// never fails: a dir that cannot be prepared, an unreadable file that cannot be
// moved aside, or a file that cannot be written yields an in-memory history and
// a Warn log, so the node starts.
func OpenBudgetHistory(dir, fingerprint string, log *slog.Logger) *BudgetHistory {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &BudgetHistory{
		log: log, write: atomicfile.Replace,
		dirty: make(chan struct{}, 1), quit: make(chan struct{}), stopped: make(chan struct{}), wrote: make(chan struct{}),
	}
	memoryOnly := func(why string, err error) *BudgetHistory {
		log.Warn("budget history: keeping the history in memory only; its counters restart at 0 on the next start",
			"dir", dir, "why", why, "err", err)
		h.path = ""
		h.st = newHistoryState()
		h.st.Fingerprint = fingerprint
		return h
	}
	if err := prepareHistoryDir(dir); err != nil {
		return memoryOnly("the history dir is unusable", err)
	}
	h.path = filepath.Join(dir, budgetHistoryFile)
	// A write killed mid-flight leaves its temp beside the file; nothing else
	// writes this dir, so the reap cannot race a live write.
	if err := atomicfile.ReapOrphans(dir, budgetHistoryFile); err != nil {
		log.Warn("budget history: could not remove an orphaned temp file", "dir", dir, "err", err)
	}
	st, err := readHistory(h.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		st = newHistoryState()
	case err != nil:
		aside := h.path + budgetHistoryAsideInfix + strconv.FormatInt(time.Now().UnixNano(), 10)
		log.Warn("budget history: the stored history is unreadable; starting an empty one",
			"path", h.path, "moved_to", aside, "err", err)
		if rerr := os.Rename(h.path, aside); rerr != nil {
			return memoryOnly("the unreadable history could not be moved aside", rerr)
		}
		trimAsides(h.path, budgetHistoryAsideMax, log)
		st = newHistoryState()
	}
	if st.Fingerprint != fingerprint {
		if st.ArmingEpisodes != 0 {
			log.Warn("budget history: the binary or policy changed; resetting the tier-1 arming episodes",
				"episodes", st.ArmingEpisodes, "from", st.Fingerprint, "to", fingerprint)
		}
		st.ArmingEpisodes = 0
		st.Fingerprint = fingerprint
	}
	h.st = st
	// The one direct write, before the writer runs: it proves the file
	// writable at startup, and nothing else touches h yet.
	data, err := json.Marshal(&h.st)
	if err == nil {
		err = h.write(h.path, data, 0o600)
	}
	if err != nil {
		return memoryOnly("the history file cannot be written", err)
	}
	return h
}

// prepareHistoryDir creates dir mode 0700 and checks it is a trusted directory.
func prepareHistoryDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create budget history dir %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat budget history dir %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("budget history dir %s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("restrict budget history dir %s: %w", dir, err)
	}
	if err := atomicfile.CheckTrustedDir(dir); err != nil {
		return fmt.Errorf("budget history dir: %w", err)
	}
	return nil
}

// trimAsides removes all but the newest keep moved-aside files of path. A
// suffix in seconds (an older build's) is ordered as its nanosecond instant.
func trimAsides(path string, keep int, log *slog.Logger) {
	dir, base := filepath.Dir(path), filepath.Base(path)+budgetHistoryAsideInfix
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Warn("budget history: could not list the moved-aside files", "dir", dir, "err", err)
		return
	}
	type aside struct {
		name string
		at   int64
	}
	var found []aside
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), base)
		if !ok || !e.Type().IsRegular() {
			continue
		}
		n, err := strconv.ParseInt(rest, 10, 64)
		if err != nil || n < 0 {
			continue
		}
		if n < 1e12 {
			n *= int64(time.Second)
		}
		found = append(found, aside{e.Name(), n})
	}
	if len(found) <= keep {
		return
	}
	sort.Slice(found, func(i, j int) bool { return found[i].at > found[j].at })
	for _, a := range found[keep:] {
		if err := os.Remove(filepath.Join(dir, a.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn("budget history: could not remove an old moved-aside file", "file", a.name, "err", err)
		}
	}
}

func newHistoryState() historyState {
	return historyState{Version: budgetHistoryVersion, Totals: map[budgetv1alpha1.Band]historyTotals{}}
}

// readHistory reads and checks the history file at path. It refuses a symlink,
// a non-regular file, an oversized file, an unknown version, an unknown band
// and a negative total.
func readHistory(path string) (historyState, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return historyState{}, err
	}
	if !fi.Mode().IsRegular() {
		return historyState{}, fmt.Errorf("%w: %s is not a regular file", errBudgetHistoryFormat, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return historyState{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, budgetHistoryMaxBytes+1))
	if err != nil {
		return historyState{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > budgetHistoryMaxBytes {
		return historyState{}, fmt.Errorf("%w: %s exceeds %d bytes", errBudgetHistoryFormat, path, budgetHistoryMaxBytes)
	}
	var st historyState
	if err := json.Unmarshal(data, &st); err != nil {
		return historyState{}, fmt.Errorf("%w: %v", errBudgetHistoryFormat, err)
	}
	if st.Version != budgetHistoryVersion {
		return historyState{}, fmt.Errorf("%w: version %d", errBudgetHistoryFormat, st.Version)
	}
	if st.Totals == nil {
		st.Totals = map[budgetv1alpha1.Band]historyTotals{}
	}
	for b, t := range st.Totals {
		if !b.Valid() {
			return historyState{}, fmt.Errorf("%w: band %q", errBudgetHistoryFormat, b)
		}
		if t.Evictions < 0 || t.OOMKills < 0 || t.KernelKills < 0 || t.Restarts < 0 || t.MemHigh < 0 || t.Tier1Refused < 0 {
			return historyState{}, fmt.Errorf("%w: a negative total for band %s", errBudgetHistoryFormat, b)
		}
	}
	if st.ArmingEpisodes < 0 {
		return historyState{}, fmt.Errorf("%w: negative arming episodes", errBudgetHistoryFormat)
	}
	st.Ring = keepLast(st.Ring, budgetHistoryRingMax)
	st.Intents = keepLast(st.Intents, budgetIntentMax)
	st.Seen = keepLast(st.Seen, budgetSeenMax)
	return st, nil
}

// keepLast returns the last n elements of s.
func keepLast[T any](s []T, n int) []T {
	if len(s) > n {
		return append([]T(nil), s[len(s)-n:]...)
	}
	return s
}

// changedLocked records that the state changed and signals the writer.
// Caller holds h.mu.
func (h *BudgetHistory) changedLocked() {
	h.gen++
	h.signal()
}

// signal wakes the writer without blocking: a signal already pending covers
// this change too, because the writer snapshots the latest state.
func (h *BudgetHistory) signal() {
	if h.dirty == nil {
		return
	}
	select {
	case h.dirty <- struct{}{}:
	default:
	}
}

// start runs the writer until ctx ends or stop is called. The writer is bound
// to the FIRST start's ctx: a later call (a second Watch) is a no-op and its
// ctx is ignored. A nil or in-memory history has no writer.
func (h *BudgetHistory) start(ctx context.Context) {
	if h == nil || h.path == "" {
		return
	}
	h.once.Do(func() {
		h.started.Store(true)
		go h.run(ctx)
	})
}

// stop tells the writer to make its final flush and stop, and waits at most
// bound for it. It reports whether the writer stopped in time; a history with
// no running writer reports true.
func (h *BudgetHistory) stop(bound time.Duration) bool {
	if h == nil || !h.started.Load() {
		return true
	}
	h.quitOnce.Do(func() { close(h.quit) })
	t := time.NewTimer(bound)
	defer t.Stop()
	select {
	case <-h.stopped:
		return true
	case <-t.C:
		return false
	}
}

// run is the writer: one write per coalesced signal, a retry of a failed write
// every budgetHistoryRetryInterval, and on ctx's end one final flush bounded by
// budgetHistoryFinalFlushBound. A write in progress when ctx ends finishes
// first; run's goroutine is nobody's critical path, so a hung write delays
// only its own exit.
func (h *BudgetHistory) run(ctx context.Context) {
	defer close(h.stopped)
	retry := time.NewTicker(budgetHistoryRetryInterval)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			h.finalFlush()
			return
		case <-h.quit:
			h.finalFlush()
			return
		case <-h.dirty:
			h.writeOnce()
		case <-retry.C:
			if h.pending() {
				h.writeOnce()
			}
		}
	}
}

// finalFlush writes a pending state, waiting at most
// budgetHistoryFinalFlushBound. A write past the bound is left to finish on its
// own goroutine, which ends with the write.
func (h *BudgetHistory) finalFlush() {
	if !h.pending() {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.writeOnce()
	}()
	t := time.NewTimer(budgetHistoryFinalFlushBound)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		h.log.Warn("budget history: the final flush did not finish in time; the latest changes may be lost",
			"bound", budgetHistoryFinalFlushBound)
	}
}

// pending reports whether the file is behind the in-memory state.
func (h *BudgetHistory) pending() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.written < h.gen
}

// writeOnce writes a snapshot of the current state.
func (h *BudgetHistory) writeOnce() {
	h.mu.Lock()
	gen, write := h.gen, h.write
	data, err := json.Marshal(&h.st)
	h.mu.Unlock()
	if err == nil {
		err = write(h.path, data, 0o600)
	}
	if err != nil {
		h.log.Warn("budget history: could not write the history; retrying", "path", h.path, "err", err)
		return
	}
	h.mu.Lock()
	if gen > h.written {
		h.written = gen
	}
	close(h.wrote)
	h.wrote = make(chan struct{})
	h.mu.Unlock()
}

// flush asks the writer to write the current state and waits at most bound for
// it to reach disk. It reports whether it did; an in-memory history has
// nothing to wait for.
func (h *BudgetHistory) flush(bound time.Duration) bool {
	if h == nil || h.path == "" {
		return true
	}
	h.mu.Lock()
	target := h.gen
	h.mu.Unlock()
	h.signal()
	t := time.NewTimer(bound)
	defer t.Stop()
	for {
		h.mu.Lock()
		if h.written >= target {
			h.mu.Unlock()
			return true
		}
		wrote := h.wrote
		h.mu.Unlock()
		select {
		case <-wrote:
		case <-t.C:
			return false
		}
	}
}

// recordLocked counts one event of reason for band: the total and the ring.
// pod (empty for none) is held to budgetHistoryRingPerPod entries of the last
// 24 h; the totals count every event.
func (h *BudgetHistory) recordLocked(pod types.UID, band budgetv1alpha1.Band, reason budgetv1alpha1.CounterReason, now time.Time) {
	t := h.st.Totals[band]
	switch reason {
	case budgetv1alpha1.CounterEviction:
		t.Evictions++
	case budgetv1alpha1.CounterOOMKill:
		t.OOMKills++
	case budgetv1alpha1.CounterKernelKill:
		t.KernelKills++
	case budgetv1alpha1.CounterRestart:
		t.Restarts++
	case budgetv1alpha1.CounterMemHigh:
		t.MemHigh++
	case budgetv1alpha1.CounterTier1Refused:
		t.Tier1Refused++
	}
	h.st.Totals[band] = t
	if pod != "" {
		h.capPodRingLocked(pod, now)
	}
	h.st.Ring = keepLast(append(h.st.Ring, historyEvent{At: now.Unix(), Band: band, Reason: reason, pod: pod}), budgetHistoryRingMax)
}

// capPodRingLocked drops pod's oldest ring entries of the last 24 h until one
// more fits under budgetHistoryRingPerPod.
func (h *BudgetHistory) capPodRingLocked(pod types.UID, now time.Time) {
	cut := now.Add(-24 * time.Hour).Unix()
	n := 0
	for _, e := range h.st.Ring {
		if e.pod == pod && e.At > cut {
			n++
		}
	}
	for drop := n - (budgetHistoryRingPerPod - 1); drop > 0; drop-- {
		for i, e := range h.st.Ring {
			if e.pod == pod && e.At > cut {
				h.st.Ring = slices.Delete(h.st.Ring, i, i+1)
				break
			}
		}
	}
}

// record counts one event of pod (empty for none); the writer persists it.
func (h *BudgetHistory) record(pod types.UID, band budgetv1alpha1.Band, reason budgetv1alpha1.CounterReason, now time.Time) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recordLocked(pod, band, reason, now)
	h.changedLocked()
}

// noteIntent records in memory that k3sm is about to stop pod (container
// empty: every container of it), before the stop is issued; the writer
// persists it. It returns the intent's handle for dropIntent.
func (h *BudgetHistory) recordIntent(pod types.UID, container string) uint64 {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	h.st.Intents = keepLast(append(h.st.Intents, killIntent{Pod: pod, Container: container, seq: h.seq}), budgetIntentMax)
	h.changedLocked()
	return h.seq
}

// dropIntent removes the intent recordIntent returned id for, if it is still
// held: the stop it announced did not happen.
func (h *BudgetHistory) dropIntent(id uint64) {
	if h == nil || id == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if i := slices.IndexFunc(h.st.Intents, func(in killIntent) bool { return in.seq == id }); i >= 0 {
		h.st.Intents = slices.Delete(h.st.Intents, i, i+1)
		h.changedLocked()
	}
}

// mark returns the current entry sequence: an entry recorded after it has a
// greater seq, so retainPods keeps it whatever pod set the caller read.
func (h *BudgetHistory) mark() uint64 {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seq
}

// retainPods drops every intent and classified termination recorded at or
// before mark whose pod live does not hold; the writer persists the result.
// live is the provider's pod set read after mark was taken; an entry recorded
// after mark is kept, so a pod tracked between the read and this call keeps
// its intent.
func (h *BudgetHistory) retainPods(live map[types.UID]bool, mark uint64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	ni, ns := len(h.st.Intents), len(h.st.Seen)
	h.st.Intents = filterInPlace(h.st.Intents, func(i killIntent) bool { return i.seq > mark || live[i.Pod] })
	h.st.Seen = filterInPlace(h.st.Seen, func(s seenExit) bool { return s.seq > mark || live[s.Pod] })
	if ni != len(h.st.Intents) || ns != len(h.st.Seen) {
		h.changedLocked()
	}
}

func filterInPlace[T any](s []T, keep func(T) bool) []T {
	out := s[:0]
	for _, v := range s {
		if keep(v) {
			out = append(out, v)
		}
	}
	clear(s[len(out):])
	return out
}

// observeExit classifies one container termination of pod, once per
// termination identity: an OOMKilled exit is an OOM kill; an exit 137 with no
// intent covering the container is a SIGKILL not initiated by k3sm; anything
// else, and an exit 137 k3sm initiated, counts nothing. Every exit an intent
// covers consumes it, graceful or not: a container intent is removed, a pod
// intent marks the container covered. A graceful exit no intent covers is not
// remembered (nothing to dedupe). The classified-termination list is consulted
// before anything changes, so a re-delivered exit neither counts again nor
// consumes a later intent.
func (h *BudgetHistory) observeExit(band budgetv1alpha1.Band, pod types.UID, container string, key terminationKey, term *corev1.ContainerStateTerminated, now time.Time) {
	if h == nil || term == nil {
		return
	}
	kill := term.Reason == oomKilledReason || term.ExitCode == evictedExitCode
	h.mu.Lock()
	defer h.mu.Unlock()
	if !kill && !h.coversLocked(pod, container) {
		return
	}
	h.seq++
	entry := seenExit{Pod: pod, Container: container, RestartCount: key.restartCount, FinishedAt: key.finishedAt, At: now.Unix(), seq: h.seq}
	if i := slices.IndexFunc(h.st.Seen, func(s seenExit) bool { return s.Pod == pod && s.Container == container }); i >= 0 {
		// The container's latest classified termination: this one again, or
		// an older one re-delivered late, is not counted.
		if prev := h.st.Seen[i]; !newerTermination(key, prev) {
			return
		}
		h.st.Seen[i] = entry
	} else {
		h.st.Seen = keepLast(append(h.st.Seen, entry), budgetSeenMax)
	}
	covered := h.consumeIntentLocked(pod, container)
	switch {
	case term.Reason == oomKilledReason:
		h.recordLocked(pod, band, budgetv1alpha1.CounterOOMKill, now)
	case term.ExitCode == evictedExitCode && !covered:
		h.recordLocked(pod, band, budgetv1alpha1.CounterKernelKill, now)
	}
	h.changedLocked()
}

// newerTermination reports whether key is a later termination than prev: a
// higher restart count, or the same count and a later finish.
func newerTermination(key terminationKey, prev seenExit) bool {
	if key.restartCount != prev.RestartCount {
		return key.restartCount > prev.RestartCount
	}
	return key.finishedAt > prev.FinishedAt
}

// coversLocked reports whether an unconsumed intent covers pod's container.
func (h *BudgetHistory) coversLocked(pod types.UID, container string) bool {
	for _, in := range h.st.Intents {
		if in.Pod != pod {
			continue
		}
		if in.Container == container || (in.Container == "" && !slices.Contains(in.Covered, container)) {
			return true
		}
	}
	return false
}

// consumeIntentLocked reports whether an unconsumed intent covers pod's
// container, consuming it: a container intent is removed, a pod intent records
// the container as covered.
func (h *BudgetHistory) consumeIntentLocked(pod types.UID, container string) bool {
	for i := range h.st.Intents {
		in := &h.st.Intents[i]
		if in.Pod != pod {
			continue
		}
		switch {
		case in.Container == container:
			h.st.Intents = slices.Delete(h.st.Intents, i, i+1)
			return true
		case in.Container == "" && !slices.Contains(in.Covered, container):
			in.Covered = append(in.Covered, container)
			return true
		}
	}
	return false
}

// Counters returns every band's monotonic totals and its non-zero 1 h and
// 24 h counts per reason at now, in the apis shape, bands in Bands() order.
func (h *BudgetHistory) Counters(now time.Time) []budgetv1alpha1.BandCounters {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	type wkey struct {
		band   budgetv1alpha1.Band
		window budgetv1alpha1.CounterWindow
		reason budgetv1alpha1.CounterReason
	}
	counts := map[wkey]int64{}
	h1, h24 := now.Add(-time.Hour).Unix(), now.Add(-24*time.Hour).Unix()
	for _, e := range h.st.Ring {
		if e.At > now.Unix() {
			continue
		}
		if e.At > h24 {
			counts[wkey{e.Band, budgetv1alpha1.Window24h, e.Reason}]++
		}
		if e.At > h1 {
			counts[wkey{e.Band, budgetv1alpha1.Window1h, e.Reason}]++
		}
	}
	out := make([]budgetv1alpha1.BandCounters, 0, len(budgetv1alpha1.Bands()))
	for _, b := range budgetv1alpha1.Bands() {
		t := h.st.Totals[b]
		bc := budgetv1alpha1.BandCounters{
			Band: b, EvictionsTotal: t.Evictions, OOMKillsTotal: t.OOMKills, KernelKillsTotal: t.KernelKills,
			RestartsTotal: t.Restarts, MemHighEventsTotal: t.MemHigh, Tier1RefusedTotal: t.Tier1Refused,
		}
		for k, n := range counts {
			if k.band == b {
				bc.Windows = append(bc.Windows, budgetv1alpha1.WindowCount{Window: k.window, Reason: k.reason, Count: n})
			}
		}
		sort.Slice(bc.Windows, func(i, j int) bool {
			if bc.Windows[i].Window != bc.Windows[j].Window {
				return bc.Windows[i].Window < bc.Windows[j].Window
			}
			return bc.Windows[i].Reason < bc.Windows[j].Reason
		})
		out = append(out, bc)
	}
	return out
}

// ArmingEpisodes returns the persisted tier-1 arming episode count, valid for
// the fingerprint the history was opened with.
func (h *BudgetHistory) ArmingEpisodes() int64 {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.st.ArmingEpisodes
}

// bandOf is a pod's budget band: critical when the kubelet's isCriticalPod
// matches (which includes system-critical priority), batch only by the
// explicit budget.k3sm.io/band: batch annotation, standard otherwise. The
// annotation never lowers a critical pod.
func bandOf(pod *corev1.Pod) budgetv1alpha1.Band {
	switch {
	case pod == nil:
		return budgetv1alpha1.BandStandard
	case isCriticalPod(pod):
		return budgetv1alpha1.BandCritical
	case pod.Annotations[budgetv1alpha1.AnnotationBand] == string(budgetv1alpha1.BandBatch):
		return budgetv1alpha1.BandBatch
	default:
		return budgetv1alpha1.BandStandard
	}
}

// budgetFingerprint names the binary (and, once a policy exists, the policy)
// the tier-1 arming count is valid for.
func budgetFingerprint(binary string) string {
	return "binary=" + binary + ";policy=none"
}

// binaryIdentity is the running build as the arming fingerprint names it.
func binaryIdentity(info version.Info) string {
	id := info.Version + "@" + info.Commit
	if info.Dirty {
		id += "+dirty"
	}
	return id
}

// recordStopIntent records, before k3sm stops pod (container empty: the whole
// pod), that the stop is k3sm's. It is in memory at once and covers the exit in
// this run; the writer persists it shortly after. A provider restart in that
// window costs a later exit 137 counted as a SIGKILL k3sm did not send.
//
// It returns the intent's handle; a caller whose stop RPC fails passes it to
// r.history.dropIntent, so the exit the failed stop did not cause is
// classified without it.
func (r *runtimedRuntime) recordStopIntent(pod *corev1.Pod, container string) uint64 {
	if r.history == nil || pod == nil {
		return 0
	}
	return r.history.recordIntent(pod.UID, container)
}

// recordStopIntentWithin is recordStopIntent for the emergency eviction, which
// keeps intent-before-kill ordering on disk when the disk allows it: the intent
// is recorded in memory, then the writer is asked to flush and the call waits
// at most bound. A flush that does not finish in time is logged and the stop
// proceeds.
func (r *runtimedRuntime) recordStopIntentWithin(pod *corev1.Pod, container string, bound time.Duration) uint64 {
	if r.history == nil || pod == nil {
		return 0
	}
	id := r.history.recordIntent(pod.UID, container)
	if !r.history.flush(bound) {
		r.log.Warn("budget history: the stop intent did not reach disk in time; stopping without waiting for it",
			"pod", podKey(pod.Namespace, pod.Name), "container", container, "bound", bound)
	}
	return id
}

// StopBudgetHistory makes the budget history's writer flush and stop, waiting
// at most budgetHistoryFinalFlushBound, so a node exiting right after its
// context ends still persists its last changes. It is the node teardown's
// seam; it is idempotent and reports whether the writer stopped in time.
func (r *runtimedRuntime) StopBudgetHistory() bool {
	return r.history.stop(budgetHistoryFinalFlushBound)
}

// pruneBudgetHistory drops the history entries of pods that are gone: in
// neither listed (a successful apiserver list of this node's pods) nor the
// provider's tracked pods. mark is the history's mark taken before the list
// was read.
//
// It runs on the orphan reaper's tick, so a node with no apiserver client never
// prunes by pod lifetime. Its ledger is still bounded: budgetIntentMax and
// budgetSeenMax drop the oldest entry first, which is pruning by age at the
// caps.
func (r *runtimedRuntime) pruneBudgetHistory(listed map[string]bool, mark uint64) {
	if r.history == nil {
		return
	}
	live := make(map[types.UID]bool, len(listed))
	for id := range listed {
		live[types.UID(id)] = true
	}
	r.mu.Lock()
	for id := range r.track {
		live[types.UID(id)] = true
	}
	r.mu.Unlock()
	r.history.retainPods(live, mark)
}

// recordBudgetEvent counts one event of reason in pod's band.
func (r *runtimedRuntime) recordBudgetEvent(pod *corev1.Pod, reason budgetv1alpha1.CounterReason) {
	if r.history == nil || pod == nil {
		return
	}
	r.history.record(pod.UID, bandOf(pod), reason, r.clk.Now())
}

// observeBudgetExits hands every terminated container of rs to the history
// for classification (OOM kill, kernel kill, or k3sm's own stop).
func (r *runtimedRuntime) observeBudgetExits(pod *corev1.Pod, rs *runtimev1.PodStatus) {
	if r.history == nil || pod == nil || rs == nil {
		return
	}
	band := bandOf(pod)
	now := r.clk.Now()
	for _, list := range [][]*runtimev1.ContainerStatus{rs.GetInitContainerStatuses(), rs.GetContainerStatuses()} {
		for _, cs := range list {
			term := toContainerState(cs.GetState()).Terminated
			if term == nil {
				continue
			}
			key := terminationKey{restartCount: cs.GetRestartCount(), exitCode: term.ExitCode, finishedAt: term.FinishedAt.UnixNano()}
			r.history.observeExit(band, pod.UID, cs.GetName(), key, term, now)
		}
	}
}
