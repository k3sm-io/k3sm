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
	"slices"
	"sort"
	"strconv"
	"strings"
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
//     and 24 h windowed counts are derived. The ring carries no pod name,
//     namespace or UID;
//   - the intent ledger: a record, written BEFORE every k3sm-initiated stop, of
//     which pod (or which container) k3sm is about to stop, so a later exit 137
//     can be told apart from a SIGKILL k3sm did not send. Beside it, the
//     identities of the terminations already classified, so a re-delivered exit
//     (the status stream and the backstop, or the first status after a restart)
//     is counted once. Both hold pod UIDs; neither is ever published.
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
// Every write replaces the file atomically. A write failure is returned to the
// caller and logged there; the in-memory state stays authoritative for this
// run. An unreadable or unrecognised file is moved aside (the last
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

// historyEvent is one ring entry: when, which band, what. No pod identity.
type historyEvent struct {
	At     int64                        `json:"at"` // unix seconds
	Band   budgetv1alpha1.Band          `json:"band"`
	Reason budgetv1alpha1.CounterReason `json:"reason"`
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

// seenExit is one classified termination: the container and runtimed's
// termination identity. seq is as killIntent's.
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
// Locking: mu guards st and seq and is held only for in-memory work, never
// across a file write. writeMu serialises the writes; it is taken before mu and
// each write marshals the state current when it holds writeMu, so a later write
// never lands an older state.
type BudgetHistory struct {
	path  string // "" keeps the history in memory only
	log   *slog.Logger
	write func(path string, data []byte, mode os.FileMode) error

	writeMu sync.Mutex
	mu      sync.Mutex
	st      historyState
	seq     uint64
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
	h := &BudgetHistory{log: log, write: atomicfile.Replace}
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
	if err := h.persist(); err != nil {
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

// persist writes the current state. It must not be called with h.mu held.
func (h *BudgetHistory) persist() error {
	if h.path == "" {
		return nil
	}
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	h.mu.Lock()
	data, err := json.Marshal(&h.st)
	h.mu.Unlock()
	if err != nil {
		return fmt.Errorf("encode budget history: %w", err)
	}
	if err := h.write(h.path, data, 0o600); err != nil {
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
	h.recordLocked(band, reason, now)
	h.mu.Unlock()
	return h.persist()
}

// noteIntent records in memory that k3sm is about to stop pod (container
// empty: every container of it). The caller persists it (persist) before the
// stop is issued.
func (h *BudgetHistory) noteIntent(pod types.UID, container string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	h.st.Intents = keepLast(append(h.st.Intents, killIntent{Pod: pod, Container: container, seq: h.seq}), budgetIntentMax)
}

// recordIntent records and persists a stop intent (noteIntent, then persist).
func (h *BudgetHistory) recordIntent(pod types.UID, container string) error {
	if h == nil {
		return nil
	}
	h.noteIntent(pod, container)
	return h.persist()
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
// before mark whose pod live does not hold, and persists when anything went.
// live is the provider's pod set read after mark was taken; an entry recorded
// after mark is kept, so a pod tracked between the read and this call keeps
// its intent.
func (h *BudgetHistory) retainPods(live map[types.UID]bool, mark uint64) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	ni, ns := len(h.st.Intents), len(h.st.Seen)
	h.st.Intents = filterInPlace(h.st.Intents, func(i killIntent) bool { return i.seq > mark || live[i.Pod] })
	h.st.Seen = filterInPlace(h.st.Seen, func(s seenExit) bool { return s.seq > mark || live[s.Pod] })
	changed := ni != len(h.st.Intents) || ns != len(h.st.Seen)
	h.mu.Unlock()
	if !changed {
		return nil
	}
	return h.persist()
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
func (h *BudgetHistory) observeExit(band budgetv1alpha1.Band, pod types.UID, container string, key terminationKey, term *corev1.ContainerStateTerminated, now time.Time) error {
	if h == nil || term == nil {
		return nil
	}
	kill := term.Reason == oomKilledReason || term.ExitCode == evictedExitCode
	h.mu.Lock()
	if !kill && !h.coversLocked(pod, container) {
		h.mu.Unlock()
		return nil
	}
	for _, s := range h.st.Seen {
		if s.Pod == pod && s.Container == container && s.RestartCount == key.restartCount && s.FinishedAt == key.finishedAt {
			h.mu.Unlock()
			return nil
		}
	}
	h.seq++
	h.st.Seen = keepLast(append(h.st.Seen, seenExit{
		Pod: pod, Container: container, RestartCount: key.restartCount, FinishedAt: key.finishedAt, At: now.Unix(), seq: h.seq,
	}), budgetSeenMax)
	covered := h.consumeIntentLocked(pod, container)
	switch {
	case term.Reason == oomKilledReason:
		h.recordLocked(band, budgetv1alpha1.CounterOOMKill, now)
	case term.ExitCode == evictedExitCode && !covered:
		h.recordLocked(band, budgetv1alpha1.CounterKernelKill, now)
	}
	h.mu.Unlock()
	return h.persist()
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

// recordStopIntent persists, before k3sm stops pod (container empty: the whole
// pod), that the stop is k3sm's. A failed write is logged and the stop goes
// ahead: the in-memory intent still covers the exit in this run, and the cost
// after a restart is a later exit 137 counted as a SIGKILL k3sm did not send.
func (r *runtimedRuntime) recordStopIntent(pod *corev1.Pod, container string) {
	if r.history == nil || pod == nil {
		return
	}
	if err := r.history.recordIntent(pod.UID, container); err != nil {
		r.log.Warn("budget history: could not persist a stop intent", "pod", podKey(pod.Namespace, pod.Name), "container", container, "err", err)
	}
}

// recordStopIntentWithin is recordStopIntent for a stop that must not wait on
// the disk (the emergency eviction): the intent is recorded in memory at once,
// and the write is waited for at most bound. A write that completes in time
// keeps intent-before-kill ordering on disk; one that does not is left to
// finish on its own (its goroutine ends with the write) and the stop proceeds.
func (r *runtimedRuntime) recordStopIntentWithin(pod *corev1.Pod, container string, bound time.Duration) {
	if r.history == nil || pod == nil {
		return
	}
	r.history.noteIntent(pod.UID, container)
	done := make(chan error, 1)
	go func() { done <- r.history.persist() }()
	t := time.NewTimer(bound)
	defer t.Stop()
	select {
	case err := <-done:
		if err != nil {
			r.log.Warn("budget history: could not persist a stop intent", "pod", podKey(pod.Namespace, pod.Name), "container", container, "err", err)
		}
	case <-t.C:
		r.log.Warn("budget history: the stop intent write is slow; stopping without waiting for it",
			"pod", podKey(pod.Namespace, pod.Name), "container", container, "bound", bound)
	}
}

// pruneBudgetHistory drops the history entries of pods that are gone: in
// neither listed (a successful apiserver list of this node's pods) nor the
// provider's tracked pods. mark is the history's mark taken before the list
// was read.
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
	if err := r.history.retainPods(live, mark); err != nil {
		r.log.Warn("budget history: could not persist the pruned history", "err", err)
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
