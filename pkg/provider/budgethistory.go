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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/pkg/version"
)

// The budget history: the node's persisted record of evictions, OOM kills,
// kernel kills and restarts, kept so the per-band totals the budget publishes
// survive pod death and a provider restart (`launchctl kickstart`).
//
// It lives in the node's own work dir, <workdir>/budget/ (mode 0700), which is
// inside the protected server or agent tree and outside every path a pod can
// open. It holds three things in one file:
//
//   - per-band monotonic totals (evictions, OOM kills, kernel kills, restarts,
//     memory.high events, refused tier-1 deliveries), never reset;
//   - a bounded ring of recent events (time, band, reason) from which the 1 h
//     and 24 h windowed counts are derived. The ring carries no pod name,
//     namespace or UID;
//   - the intent ledger: a record, written BEFORE every k3sm-initiated stop, of
//     which pod (or which container) k3sm is about to stop, so a later exit 137
//     can be told apart from a kernel kill. A kernel pcontrol kill leaves only
//     exit 137 with reason Error and no Event, so an exit 137 with no matching
//     intent counts as a kernel kill. Beside it, the identities of the
//     terminations already classified, so a re-delivered exit (the status stream
//     and the backstop, or the first status after a restart) is counted once.
//     Both hold pod UIDs; neither is ever published.
//
// It also holds the tier-1 arming episode count with the fingerprint it was
// earned under; opening the history under a different fingerprint (a new
// binary, or a policy change once a policy exists) resets the count to 0.
//
// Counter sources on Darwin: evictionsTotal is k3sm's own evictions;
// oomKillsTotal is a container exit runtimed reports as OOMKilled (a vm guest's
// out-of-memory kill); kernelKillsTotal is an exit 137 with no intent. Nothing
// on Darwin produces memHighEventsTotal yet, and tier1RefusedTotal stays 0
// because k3sm delivers tier 1 through its node-side eviction path, which, like
// the kubelet's own eviction, does not consult PodDisruptionBudgets.
//
// Every write replaces the file atomically. A write failure is returned to the
// caller and logged there; the in-memory state stays authoritative for this
// run. An unreadable or unrecognised file is moved aside and the history starts
// empty: the totals then restart at 0, as a counter does after a reset.

// The history file and its bounds.
const (
	budgetHistoryFile    = "history.json"
	budgetHistoryVersion = 1
	// budgetHistoryMaxBytes bounds the file read at open. The bounds below keep
	// a full file far under it.
	budgetHistoryMaxBytes = 2 << 20
	// budgetHistoryRingMax is the most events the ring keeps. A node that
	// records more than this in 24 h under-reports its 24 h windows; the
	// totals are unaffected.
	budgetHistoryRingMax = 2048
	// budgetIntentMax and budgetSeenMax bound the intent ledger and the
	// classified-termination list; the oldest entry goes first.
	budgetIntentMax = 512
	budgetSeenMax   = 1024
	// budgetIntentSlack is how long past a stop's grace its intent stays valid:
	// the exit can be observed some time after the kill.
	budgetIntentSlack = 5 * time.Minute
	// budgetSeenTTL is how long a classified termination is remembered.
	budgetSeenTTL = 24 * time.Hour
)

// oomKilledReason is the container termination reason of an out-of-memory kill.
const oomKilledReason = "OOMKilled"

// errBudgetHistoryFormat marks a history file this build does not read.
var errBudgetHistoryFormat = errors.New("unrecognised budget history format")

// historyTotals are one band's monotonic totals.
type historyTotals struct {
	Evictions    int64 `json:"evictions"`
	OOMKills     int64 `json:"oomKills"`
	KernelKills  int64 `json:"kernelKills"`
	Restarts     int64 `json:"restarts"`
	MemHigh      int64 `json:"memHigh"`
	Tier1Refused int64 `json:"tier1Refused"`
}

// historyEvent is one ring entry: when, which band, what. No pod identity.
type historyEvent struct {
	At     int64                        `json:"at"` // unix seconds
	Band   budgetv1alpha1.Band          `json:"band"`
	Reason budgetv1alpha1.CounterReason `json:"reason"`
}

// killIntent records that k3sm is about to stop a pod (Container empty) or one
// of its containers, valid until Until (unix seconds).
type killIntent struct {
	Pod       types.UID `json:"pod"`
	Container string    `json:"container,omitempty"`
	Until     int64     `json:"until"`
}

// seenExit is one classified termination: the container and runtimed's
// termination identity.
type seenExit struct {
	Pod          types.UID `json:"pod"`
	Container    string    `json:"container"`
	RestartCount int32     `json:"restartCount"`
	FinishedAt   int64     `json:"finishedAt"` // unix nanoseconds
	At           int64     `json:"at"`         // unix seconds, when classified
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
type BudgetHistory struct {
	path string
	log  *slog.Logger

	mu sync.Mutex // guards st
	st historyState
}

// OpenBudgetHistory opens (creating it if needed) the history in dir, which it
// creates mode 0700. fingerprint names the binary and policy the arming count
// is valid for; a stored count earned under another fingerprint is reset.
func OpenBudgetHistory(dir, fingerprint string, log *slog.Logger) (*BudgetHistory, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create budget history dir %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat budget history dir %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("budget history dir %s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict budget history dir %s: %w", dir, err)
	}
	if err := atomicfile.CheckTrustedDir(dir); err != nil {
		return nil, fmt.Errorf("budget history dir: %w", err)
	}
	h := &BudgetHistory{path: filepath.Join(dir, budgetHistoryFile), log: log}
	st, err := readHistory(h.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		st = newHistoryState()
	case err != nil:
		aside := fmt.Sprintf("%s.unreadable-%d", h.path, time.Now().Unix())
		log.Warn("budget history: the stored history is unreadable; starting an empty one",
			"path", h.path, "moved_to", aside, "err", err)
		if rerr := os.Rename(h.path, aside); rerr != nil {
			return nil, fmt.Errorf("move the unreadable budget history aside: %w", rerr)
		}
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
	if err := h.persistLocked(); err != nil {
		return nil, err
	}
	return h, nil
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

// persistLocked writes the state. Caller holds h.mu (or owns h exclusively).
func (h *BudgetHistory) persistLocked() error {
	data, err := json.Marshal(&h.st)
	if err != nil {
		return fmt.Errorf("encode budget history: %w", err)
	}
	if err := atomicfile.Replace(h.path, data, 0o600); err != nil {
		return fmt.Errorf("write budget history: %w", err)
	}
	return nil
}

// recordLocked counts one event of reason for band: the total and the ring.
func (h *BudgetHistory) recordLocked(band budgetv1alpha1.Band, reason budgetv1alpha1.CounterReason, now time.Time) {
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
	h.st.Ring = keepLast(append(h.st.Ring, historyEvent{At: now.Unix(), Band: band, Reason: reason}), budgetHistoryRingMax)
}

// record counts one event and persists it.
func (h *BudgetHistory) record(band budgetv1alpha1.Band, reason budgetv1alpha1.CounterReason, now time.Time) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recordLocked(band, reason, now)
	return h.persistLocked()
}

// recordIntent persists that k3sm is about to stop pod (container empty: every
// container of it) with grace, before the stop is issued.
func (h *BudgetHistory) recordIntent(pod types.UID, container string, grace time.Duration, now time.Time) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)
	until := now.Add(max(grace, 0) + budgetIntentSlack).Unix()
	h.st.Intents = keepLast(append(h.st.Intents, killIntent{Pod: pod, Container: container, Until: until}), budgetIntentMax)
	return h.persistLocked()
}

// pruneLocked drops expired intents and forgotten terminations.
func (h *BudgetHistory) pruneLocked(now time.Time) {
	sec := now.Unix()
	h.st.Intents = filterInPlace(h.st.Intents, func(i killIntent) bool { return i.Until >= sec })
	cut := now.Add(-budgetSeenTTL).Unix()
	h.st.Seen = filterInPlace(h.st.Seen, func(s seenExit) bool { return s.At >= cut })
}

func filterInPlace[T any](s []T, keep func(T) bool) []T {
	out := s[:0]
	for _, v := range s {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}

// observeExit classifies one container termination of pod, once per
// termination identity: an OOMKilled exit is an OOM kill; an exit 137 with no
// intent covering the container is a kernel kill; anything else, and an exit
// 137 k3sm initiated, counts nothing. A container intent is consumed by the
// exit it covers; a pod intent covers every container until it expires.
func (h *BudgetHistory) observeExit(band budgetv1alpha1.Band, pod types.UID, container string, key terminationKey, term *corev1.ContainerStateTerminated, now time.Time) error {
	if h == nil || term == nil {
		return nil
	}
	if term.Reason != oomKilledReason && term.ExitCode != evictedExitCode {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.st.Seen {
		if s.Pod == pod && s.Container == container && s.RestartCount == key.restartCount && s.FinishedAt == key.finishedAt {
			return nil
		}
	}
	h.pruneLocked(now)
	h.st.Seen = keepLast(append(h.st.Seen, seenExit{
		Pod: pod, Container: container, RestartCount: key.restartCount, FinishedAt: key.finishedAt, At: now.Unix(),
	}), budgetSeenMax)
	switch {
	case term.Reason == oomKilledReason:
		h.recordLocked(band, budgetv1alpha1.CounterOOMKill, now)
	case !h.consumeIntentLocked(pod, container):
		h.recordLocked(band, budgetv1alpha1.CounterKernelKill, now)
	}
	return h.persistLocked()
}

// consumeIntentLocked reports whether an intent covers pod's container,
// removing a container intent it matched.
func (h *BudgetHistory) consumeIntentLocked(pod types.UID, container string) bool {
	for i, in := range h.st.Intents {
		if in.Pod != pod {
			continue
		}
		if in.Container == "" {
			return true
		}
		if in.Container == container {
			h.st.Intents = append(h.st.Intents[:i], h.st.Intents[i+1:]...)
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

// recordStopIntent persists, before k3sm stops pod (container empty: the whole
// pod) with grace, that the stop is k3sm's. A failed write is logged and the
// stop goes ahead: the cost is a later exit 137 miscounted as a kernel kill.
func (r *runtimedRuntime) recordStopIntent(pod *corev1.Pod, container string, grace time.Duration) {
	if r.history == nil || pod == nil {
		return
	}
	if err := r.history.recordIntent(pod.UID, container, grace, r.clk.Now()); err != nil {
		r.log.Warn("budget history: could not persist a stop intent", "pod", podKey(pod.Namespace, pod.Name), "container", container, "err", err)
	}
}

// recordBudgetEvent counts one event of reason in pod's band.
func (r *runtimedRuntime) recordBudgetEvent(pod *corev1.Pod, reason budgetv1alpha1.CounterReason) {
	if r.history == nil || pod == nil {
		return
	}
	if err := r.history.record(bandOf(pod), reason, r.clk.Now()); err != nil {
		r.log.Warn("budget history: could not persist an event", "reason", string(reason), "err", err)
	}
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
			if err := r.history.observeExit(band, pod.UID, cs.GetName(), key, term, now); err != nil {
				r.log.Warn("budget history: could not persist a classified exit",
					"pod", podKey(pod.Namespace, pod.Name), "container", cs.GetName(), "err", err)
			}
		}
	}
}
