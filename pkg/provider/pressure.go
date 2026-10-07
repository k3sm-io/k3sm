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
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// The memory-pressure predicate and the monitor that owns the host sample.
//
// ONE SAMPLE, ONE VERDICT. The node's MemoryPressure condition and the eviction
// manager's trigger are the same function (memoryPressured) applied to the same
// stored snapshot. The monitor is the only thing that samples the host; the
// node-status loop and the eviction manager both read its latest snapshot, so the
// condition a client sees and the decision that evicts a pod can never disagree.
//
// Three signals feed the predicate, all hard thresholds:
//
//   - memory.available, the upstream kubelet signal with the upstream 100Mi floor,
//     computed by the existing formula (hostStats.MemAvailableBytes). It is the
//     LAGGING signal on Darwin: pressure compresses and then swaps anonymous pages,
//     which takes them out of the in-RAM working set, so available memory can stay
//     above the floor while swap grows.
//   - compressor headroom (k3sm-specific): compressed pages at 80% of
//     vm.compressor.pages_compressed_limit, or compressor segments at 80% of
//     vm.compressor.segment.limit. macOS's no-paging-space kill fires at 98% of
//     either limit, so this trips well before the kernel acts.
//   - swap headroom (k3sm-specific, deliberately conjunctive): at least 1 GiB of
//     swap in use AND swap use rising across the last two samples AND under 8 GiB
//     free on the swap volume. Free disk alone is a DiskPressure fact; a full disk
//     with no swap in use must not evict anything, because eviction cannot free it.
//
// HYSTERESIS. Each signal trips at its trip value and clears only at its release
// value (available >= 200Mi; both compressor ratios <= 70%; the swap arm false for
// two consecutive samples). Between the two the verdict holds. The hold is state,
// so the monitor carries it forward and stamps it into each snapshot it stores
// (hostStats.history); memoryPressured then stays a pure function of one snapshot,
// which is what lets the status loop and the eviction manager re-derive the same
// answer from the same stored value. This is the DiskPressure Schmitt trigger of
// reconcileTransitions, moved to where a multi-signal hold can be expressed.

// pressureSignal names the memory-pressure arm that fired. The empty value means
// no arm fired.
type pressureSignal string

const (
	signalNone            pressureSignal = ""
	signalMemoryAvailable pressureSignal = "memory.available"
	signalCompressor      pressureSignal = "compressor"
	signalSwap            pressureSignal = "swap"
)

// memAvailableReleaseBytes is the available-memory level at or above which a
// raised memory.available arm clears: twice the upstream 100Mi trip floor. The
// gap keeps a node hovering at the floor from flapping the condition (and the
// node-lifecycle taint it drives) every sample.
const memAvailableReleaseBytes int64 = 200 * 1024 * 1024

// The compressor-headroom arm's trip and release levels, in percent of each
// kernel limit. The kernel's own compressor-low test is 98% of either limit
// (vm_compressor.c), so 80% leaves an 18-point band for the eviction manager to
// act in before macOS picks a victim itself.
const (
	compressorTripPercent    int64 = 80
	compressorReleasePercent int64 = 70
)

// The swap-headroom arm's thresholds: swap in use at all (1 GiB, so a Mac with a
// little idle swap is not "swapping"), and the free space left on the volume the
// swapfiles live on. The kernel's swap-low test needs a failed swapfile creation
// (the volume full) or the swapfile cap, so 8 GiB free is a margin ahead of it.
// The arm releases after swapReleaseCalmSamples consecutive false samples.
const (
	swapTripUsedBytes       int64 = 1 << 30
	swapVolumeTripFreeBytes int64 = 8 << 30
	swapReleaseCalmSamples        = 2
)

// swapVolumePath is the APFS volume macOS keeps its swapfiles on. It shares its
// container (and so its free space) with the data volume.
const swapVolumePath = "/System/Volumes/VM"

// The monitor's cadence: calm, fast once any signal passes its half-way mark
// (pressureElevated), and the number of calm samples that switch it back.
const (
	pressureCalmInterval          = 10 * time.Second
	pressureFastInterval          = time.Second
	pressureCalmSamplesToSlowDown = 3
)

// The half-way marks pressureElevated tests against.
const (
	memAvailableElevatedBytes   = memAvailableReleaseBytes
	compressorElevatedPercent   = compressorTripPercent / 2
	swapElevatedUsedBytes       = swapTripUsedBytes / 2
	swapVolumeElevatedFreeBytes = 2 * swapVolumeTripFreeBytes
)

// The MemoryPressure Reason/Message vocabulary, the kubelet's literals. A raised
// condition's Message appends the firing arm's reading after a colon.
const (
	insufficientMemoryReason  = "KubeletHasInsufficientMemory"
	insufficientMemoryMessage = "kubelet has insufficient memory available"
	sufficientMemoryReason    = "KubeletHasSufficientMemory"
	sufficientMemoryMessage   = "kubelet has sufficient memory available"
)

// memoryHold is the per-arm latch the hysteresis needs: which arms are currently
// raised, and how many consecutive samples the swap arm has read false while
// raised. The zero value is "nothing raised", so an unstamped snapshot evaluates
// to the raw trip verdict.
type memoryHold struct {
	available  bool
	compressor bool
	swap       bool
	swapCalm   int
}

// pressureHistory is what the monitor stamps into a snapshot from the samples
// before it: the hold in force when the sample was taken, and the previous
// sample's swap use (the swap arm's "rising" test). A snapshot that never passed
// through the monitor carries the zero value: no hold, no previous swap reading,
// so the swap arm cannot fire on it.
type pressureHistory struct {
	hold       memoryHold
	swapPrev   int64
	swapPrevOK bool
}

// memoryVerdict is the full evaluation of one snapshot: whether the node is under
// memory pressure, which arm the condition and the eviction report, a human
// reading of that arm, a scalar level for "has it moved toward release", and the
// hold the next snapshot must carry.
type memoryVerdict struct {
	pressured bool
	signal    pressureSignal
	// reading is the firing arm's value in prose, e.g. "compressor 83% of limit".
	reading string
	// threshold is the firing arm's trip value in prose, for the eviction message.
	threshold string
	// level is a scalar that grows with pressure on the firing arm. Two levels
	// are comparable only when their signals are equal.
	level float64
	next  memoryHold
}

// memoryPressured reports whether snapshot s is under memory pressure, and which
// arm fired. It is PURE over s: the hysteresis hold it honours rides inside s
// (stamped by the monitor). Both computeNodeConditions and the eviction manager
// call it, so the condition and the eviction trigger are one verdict.
func memoryPressured(s hostStats) (bool, pressureSignal) {
	v := evaluateMemory(s)
	return v.pressured, v.signal
}

// evaluateMemory is memoryPressured with its working shown. Arms are reported in
// a fixed order (memory.available, compressor, swap): the first one raised names
// the condition's Message and the eviction message.
func evaluateMemory(s hostStats) memoryVerdict {
	prev := s.history.hold
	var next memoryHold

	// memory.available: the existing formula and the upstream 100Mi floor, unchanged.
	availTrip := s.MemAvailableBytes < memAvailableHardEvictionBytes
	next.available = availTrip || (prev.available && s.MemAvailableBytes < memAvailableReleaseBytes)

	// compressor: either ratio at its trip, or held while either is above release.
	pagesPct, pagesOK := percentOf(s.CompressorPages, s.CompressorPagesLimit)
	segsPct, segsOK := percentOf(s.CompressorSegments, s.CompressorSegmentsLimit)
	compTrip := (pagesOK && pagesPct >= compressorTripPercent) || (segsOK && segsPct >= compressorTripPercent)
	compBand := (pagesOK && pagesPct > compressorReleasePercent) || (segsOK && segsPct > compressorReleasePercent)
	next.compressor = compTrip || (prev.compressor && compBand)

	// swap: the conjunctive raw arm; released after two consecutive false samples.
	swapRaw := swapArm(s)
	switch {
	case swapRaw:
		next.swap = true
	case prev.swap:
		next.swapCalm = prev.swapCalm + 1
		next.swap = next.swapCalm < swapReleaseCalmSamples
		if !next.swap {
			next.swapCalm = 0
		}
	}

	v := memoryVerdict{next: next}
	switch {
	case next.available:
		v.pressured, v.signal = true, signalMemoryAvailable
		v.reading = "memory.available " + formatBytes(s.MemAvailableBytes)
		v.threshold = formatBytes(memAvailableHardEvictionBytes)
		v.level = -float64(s.MemAvailableBytes)
	case next.compressor:
		pct := max(pctOrZero(pagesPct, pagesOK), pctOrZero(segsPct, segsOK))
		v.pressured, v.signal = true, signalCompressor
		v.reading = fmt.Sprintf("compressor %d%% of limit", pct)
		v.threshold = fmt.Sprintf("compressor %d%% of limit", compressorTripPercent)
		v.level = max(ratioOf(s.CompressorPages, s.CompressorPagesLimit), ratioOf(s.CompressorSegments, s.CompressorSegmentsLimit))
	case next.swap:
		v.pressured, v.signal = true, signalSwap
		v.reading = fmt.Sprintf("swap growing, %s free on the swap volume", formatBytes(s.SwapVolumeAvailableBytes))
		v.threshold = fmt.Sprintf("%s free on the swap volume", formatBytes(swapVolumeTripFreeBytes))
		v.level = float64(s.SwapUsedBytes)
	}
	return v
}

// swapArm is the raw (un-held) swap arm. Every leg must be sampled: an unsampled
// swap volume (zero capacity) or a snapshot with no previous swap reading cannot
// fire it.
func swapArm(s hostStats) bool {
	if s.SwapVolumeCapacityBytes <= 0 || !s.history.swapPrevOK {
		return false
	}
	return s.SwapUsedBytes >= swapTripUsedBytes &&
		s.SwapUsedBytes > s.history.swapPrev &&
		s.SwapVolumeAvailableBytes < swapVolumeTripFreeBytes
}

// pressureElevated reports whether any signal has passed the half-way mark to its
// trip value, which switches the monitor to its fast cadence. "Half-way" is half
// the trip ratio for the compressor arms, and twice the floor for the two
// below-a-floor quantities (available memory and free swap-volume space), plus
// half the swap-in-use floor.
func pressureElevated(s hostStats) bool {
	if s.MemAvailableBytes < memAvailableElevatedBytes {
		return true
	}
	if p, ok := percentOf(s.CompressorPages, s.CompressorPagesLimit); ok && p >= compressorElevatedPercent {
		return true
	}
	if p, ok := percentOf(s.CompressorSegments, s.CompressorSegmentsLimit); ok && p >= compressorElevatedPercent {
		return true
	}
	return s.SwapVolumeCapacityBytes > 0 &&
		s.SwapUsedBytes >= swapElevatedUsedBytes &&
		s.SwapVolumeAvailableBytes < swapVolumeElevatedFreeBytes
}

// percentOf returns n as a whole percentage of limit, rounded down, and false
// when limit is zero or negative (an unsampled limit is no pressure, the
// DiskCapacityBytes precedent). The compressor counters are compared as ratios
// of like units only (pages to pages, segments to segments).
func percentOf(n, limit int64) (int64, bool) {
	if limit <= 0 {
		return 0, false
	}
	return n * 100 / limit, true
}

// ratioOf is n/limit as a float, zero for an unsampled limit.
func ratioOf(n, limit int64) float64 {
	if limit <= 0 {
		return 0
	}
	return float64(n) / float64(limit)
}

// pctOrZero is percentOf's value with an unsampled limit read as zero.
func pctOrZero(p int64, ok bool) int64 {
	if !ok {
		return 0
	}
	return p
}

// formatBytes renders a byte count for a condition message: whole MiB below a
// GiB, one decimal of GiB above.
func formatBytes(b int64) string {
	if b >= 1<<30 {
		return fmt.Sprintf("%.1fGi", float64(b)/float64(1<<30))
	}
	return fmt.Sprintf("%dMi", b>>20)
}

// pressureMonitor owns the host sample. It samples on an adaptive cadence (10 s
// while every signal is calm, 1 s once any signal passes half its trip value,
// back to 10 s after three calm samples), keeps the latest good snapshot with the
// hysteresis history stamped in, and tells two consumers about it: the
// node-status loop (pushed on a False->True memory-pressure edge, so the
// condition publishes without waiting for the 60 s status tick) and the eviction
// manager (woken on every sample attempt).
//
// A failed sample is never "no pressure": the previous snapshot is kept, a Warn
// names the failure, and the age of the last good sample keeps growing.
type pressureMonitor struct {
	// sample takes one host snapshot. Read on every attempt, never cached, so a
	// test can swap it after construction.
	sample func() (hostStats, error)
	// after is the cadence seam: it returns a channel that fires once after d. A
	// fixed ticker cannot express the cadence change, so the period is chosen
	// again before every wait.
	after func(d time.Duration) <-chan time.Time
	now   func() time.Time
	log   *slog.Logger

	// mu guards every field below. It is never held across sample(), a log
	// call, or a channel send.
	mu       sync.Mutex
	snap     hostStats
	seq      uint64 // successful samples so far; 0 means no snapshot exists
	attempts uint64 // sample attempts, successful or not
	lastOK   time.Time
	hold     memoryHold // the hold the NEXT snapshot carries
	fast     bool
	calm     int
	// tick is closed and replaced after every sample attempt: the eviction
	// manager's wake-up.
	tick chan struct{}
	// edge carries one pending False->True notification for the status loop.
	// Buffered by one and sent without blocking: a second edge before the loop
	// drains the first is the same news.
	edge chan struct{}
}

// newPressureMonitor returns a monitor over sample with the production clock and
// cadence seams.
func newPressureMonitor(sample func() (hostStats, error), log *slog.Logger) *pressureMonitor {
	if log == nil {
		log = slog.Default()
	}
	return &pressureMonitor{
		sample: sample,
		after:  time.After,
		now:    time.Now,
		log:    log,
		tick:   make(chan struct{}),
		edge:   make(chan struct{}, 1),
	}
}

// run samples on the adaptive cadence until ctx ends. The caller takes the first
// sample itself (NodeStatusProvider.Run does, before its first publish), so run
// begins with a wait.
func (m *pressureMonitor) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.after(m.interval()):
			m.sampleOnce()
		}
	}
}

// interval is the wait before the next sample.
func (m *pressureMonitor) interval() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fast {
		return pressureFastInterval
	}
	return pressureCalmInterval
}

// sampleOnce takes one host sample and folds it in. On success the snapshot is
// stamped with the hysteresis history, stored, and the cadence and edge are
// updated. On failure the previous snapshot is kept.
func (m *pressureMonitor) sampleOnce() {
	s, err := m.sample()
	now := m.now()

	m.mu.Lock()
	m.attempts++
	if err != nil {
		var age time.Duration
		hadOne := m.seq > 0
		if hadOne {
			age = now.Sub(m.lastOK)
		}
		m.broadcastLocked()
		m.mu.Unlock()
		m.log.Warn("host pressure sample failed; keeping the previous snapshot",
			"error", err, "have_previous", hadOne,
			"last_successful_sample_age_seconds", int64(age/time.Second))
		return
	}
	s.history = pressureHistory{hold: m.hold, swapPrev: m.snap.SwapUsedBytes, swapPrevOK: m.seq > 0}
	wasPressured := false
	if m.seq > 0 {
		wasPressured = evaluateMemory(m.snap).pressured
	}
	v := evaluateMemory(s)
	m.hold = v.next
	m.snap = s
	m.seq++
	m.lastOK = now
	switch {
	case v.pressured || pressureElevated(s):
		m.fast, m.calm = true, 0
	case m.fast:
		m.calm++
		if m.calm >= pressureCalmSamplesToSlowDown {
			m.fast, m.calm = false, 0
		}
	}
	m.broadcastLocked()
	m.mu.Unlock()

	if v.pressured && !wasPressured {
		m.log.Warn("node memory pressure raised", "signal", string(v.signal), "reading", v.reading)
		select {
		case m.edge <- struct{}{}:
		default:
		}
	} else if !v.pressured && wasPressured {
		m.log.Info("node memory pressure released")
	}
}

// broadcastLocked wakes every waiter on the current tick. Caller holds m.mu.
func (m *pressureMonitor) broadcastLocked() {
	close(m.tick)
	m.tick = make(chan struct{})
}

// latest returns the latest good snapshot and its sequence number. ok is false
// until the first successful sample.
func (m *pressureMonitor) latest() (s hostStats, seq uint64, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snap, m.seq, m.seq > 0
}

// next returns a channel closed by the next sample attempt.
func (m *pressureMonitor) next() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tick
}

// edges returns the False->True notification channel the status loop selects on.
func (m *pressureMonitor) edges() <-chan struct{} { return m.edge }

// sampleAge is how long ago the last successful sample was taken, measured on
// the monitor's clock; zero before the first one.
func (m *pressureMonitor) sampleAge() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seq == 0 {
		return 0
	}
	return m.now().Sub(m.lastOK)
}
