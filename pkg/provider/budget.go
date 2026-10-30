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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

// The node budget: a graded reading of the same host sample the memory-pressure
// predicate uses, published for applications that want to back off before the
// node evicts anything.
//
// Each signal has a five-rung ladder, warn < admit-stop < critical < evict-soft
// < evict-hard, every rung with a release value. budgetOf reduces one snapshot
// and a ladder to a NodeBudgetObservation. It is PURE over the snapshot, the
// same way memoryPressured is: the hold it honours (which rungs are held since
// when, and the level dwell) rides inside the snapshot (hostStats.history),
// stamped by the pressure monitor, so the status loop and any later reader
// derive the same budget from the same stored sample.
//
// The ladder is ADVISORY. Nothing here evicts, refuses a pod or taints a node.
// The evict-hard rung of every signal is today's compiled tier-2 trip, derived
// from the same constants the eviction manager uses, so the published hard
// value cannot drift from the trip that actually acts. The node level reads
// `evicting` whenever memoryPressured is true, because then tier 2 is acting.
//
// HOLDS ARE WALL-CLOCK. A rung is held from the first sample at or past its
// threshold until a sample is back on the calm side of its release. A level
// rises at once and falls only after the higher level has been unobserved for
// the level dwell (budgetLevelDwell), measured on the sample timestamps, never as
// a count of samples, because the monitor's cadence varies between 1 s and 10 s.
//
// Every hold, dwell timer and the memory.swap growth window live in memory.
// After a provider restart the first sample computes the raw rungs with no
// hold, memory.swap reads unset until a second sample exists, and the dwell
// restarts.

// budgetRung indexes the five rungs of a signal's ladder, calmest first.
type budgetRung int

const (
	rungWarn budgetRung = iota
	rungAdmitStop
	rungCritical
	rungEvictSoft
	rungEvictHard
	numBudgetRungs
)

// budgetRungNames are the rung names a SoftPressure message quotes.
var budgetRungNames = [numBudgetRungs]string{"warn", "admit-stop", "critical", "evict-soft", "evict-hard"}

// budgetLevelDwell is how long a raised level stays published after the last
// sample that observed it: the kubelet's evictionPressureTransitionPeriod
// default (5m). A rise publishes at once. A policy's dwell overrides it.
const budgetLevelDwell = 5 * time.Minute

// memorySwapWindow is the memory.swap growth window: the signal's value is the
// rise in swap use over the last 60 s.
const memorySwapWindow = 60 * time.Second

// memEvictionReserveBytes is the memory the eviction manager keeps in reserve:
// the upstream memory.available hard-eviction floor, published in the capacity
// block.
const memEvictionReserveBytes = memAvailableHardEvictionBytes

// The memory.available evict-soft grace and the compressor evict-soft grace, in
// seconds (R4).
const (
	memAvailableEvictSoftGraceSeconds int64 = 90
	compressorEvictSoftGraceSeconds   int64 = 60
)

// minPIDLadderMax is the smallest process ceiling the pid.available ladder is
// published for. Below it the percentage rungs collapse onto each other, so the
// ladder is left unset rather than published out of order.
const minPIDLadderMax int64 = 100

// numBudgetSlots sizes the per-signal hold arrays: one slot per page code.
const numBudgetSlots = budgetv1alpha1.MaxBudgetSignals

// signalLadder is one signal's generic record: its rungs and releases (nil for
// a rung the signal does not have), the evict-soft grace, the growth window,
// the reclaim target and the resource that limits it. Nothing in it is
// platform-specific; Darwin detail lives in budgetLadder.darwin.
type signalLadder struct {
	id              budgetv1alpha1.SignalID
	rungs           [numBudgetRungs]*int64
	releases        [numBudgetRungs]*int64
	graceSeconds    *int64
	windowSeconds   *int64
	minReclaimBytes *int64
	limiting        budgetv1alpha1.LimitingResource
	sharedWith      budgetv1alpha1.SignalID
}

// darwinLadder is the Darwin-only part of the ladder.
type darwinLadder struct {
	// swapGateBytes is the memory.swap producer-side gate: the signal's rungs
	// count only while swap in use is at least this, max(1Gi, memsize/4).
	swapGateBytes int64
}

// budgetLadder is the full ladder for one host: every signal at its page-code
// slot (index PageCode-1; an empty slot has no id), the level dwell, and the
// platform detail. It is a fixed-size value, so a snapshot carrying it stays
// comparable.
type budgetLadder struct {
	signals [numBudgetSlots]signalLadder
	dwell   time.Duration
	darwin  darwinLadder
}

// i64 returns a pointer to v.
func i64(v int64) *int64 { return &v }

// halfGapReleases fills each advisory rung's release (warn to evict-soft) at
// half the gap toward the next calmer rung past its threshold; warn uses the
// gap to admit-stop. A rung without a calmer neighbour on either side keeps a
// nil release. The evict-hard release is left as the caller set it: it is the
// tier-2 release, unchanged.
func halfGapReleases(l *signalLadder) {
	desc := budgetv1alpha1.IsDescending(l.id)
	for r := rungWarn; r <= rungEvictSoft; r++ {
		if l.rungs[r] == nil {
			continue
		}
		var calmer *int64
		if r == rungWarn {
			// Warn has no calmer rung; it uses the gap to the next rung up.
			for n := rungAdmitStop; n <= rungEvictSoft && calmer == nil; n++ {
				calmer = l.rungs[n]
			}
		} else {
			for n := r - 1; n >= rungWarn && calmer == nil; n-- {
				calmer = l.rungs[n]
			}
		}
		if calmer == nil {
			continue
		}
		gap := *calmer - *l.rungs[r]
		if gap < 0 {
			gap = -gap
		}
		if desc {
			l.releases[r] = i64(*l.rungs[r] + gap/2)
		} else {
			l.releases[r] = i64(*l.rungs[r] - gap/2)
		}
	}
}

// defaultLadder is the host-scaled default ladder (R4 as amended by the P0
// results) for a host with memCapacity bytes of memory and a process ceiling
// of pidMax. Every evict-hard value comes from the compiled tier-2 constants.
func defaultLadder(memCapacity, pidMax int64) budgetLadder {
	const mi = int64(1) << 20
	const gi = int64(1) << 30

	mem := signalLadder{id: budgetv1alpha1.SignalMemoryAvailable, limiting: budgetv1alpha1.ResourceMemory}
	mem.rungs = [numBudgetRungs]*int64{
		i64(max(gi, memCapacity*12/100)),
		i64(max(768*mi, memCapacity*8/100)),
		i64(max(512*mi, memCapacity*5/100)),
		i64(max(256*mi, memCapacity*25/1000)),
		i64(memAvailableHardEvictionBytes),
	}
	mem.releases[rungEvictHard] = i64(memAvailableReleaseBytes)
	halfGapReleases(&mem)
	mem.graceSeconds = i64(memAvailableEvictSoftGraceSeconds)
	mem.minReclaimBytes = i64(*mem.releases[rungEvictSoft] - *mem.rungs[rungEvictSoft])

	comp := signalLadder{id: budgetv1alpha1.SignalMemoryCompressor, limiting: budgetv1alpha1.ResourceMemory}
	comp.rungs = [numBudgetRungs]*int64{i64(500), i64(600), i64(700), i64(750), i64(compressorTripPercent * 10)}
	comp.releases[rungEvictHard] = i64(compressorReleasePercent * 10)
	halfGapReleases(&comp)
	comp.graceSeconds = i64(compressorEvictSoftGraceSeconds)

	swap := signalLadder{id: budgetv1alpha1.SignalMemorySwap, limiting: budgetv1alpha1.ResourceMemory}
	swap.rungs = [numBudgetRungs]*int64{i64(256 * mi), i64(512 * mi), i64(gi), nil, nil}
	halfGapReleases(&swap)
	swap.windowSeconds = i64(int64(memorySwapWindow / time.Second))

	floor := swapfsFloor(memCapacity)
	swapfs := signalLadder{id: budgetv1alpha1.SignalSwapfsAvailable, limiting: budgetv1alpha1.ResourceSwapfs}
	swapfs.rungs = [numBudgetRungs]*int64{i64(3 * floor), i64(2 * floor), i64(floor * 3 / 2), nil, i64(floor)}
	swapfs.releases[rungEvictHard] = i64(floor * swapfsDiskPressureClearNum / swapfsDiskPressureClearDen)
	halfGapReleases(&swapfs)

	nodefs := signalLadder{id: budgetv1alpha1.SignalNodefsAvailable, limiting: budgetv1alpha1.ResourceNodefs}
	nodefs.rungs = [numBudgetRungs]*int64{i64(20 * gi), i64(15 * gi), i64(10 * gi), nil, i64(diskPressureTripFreeBytes)}
	nodefs.releases[rungEvictHard] = i64(diskPressureClearFreeBytes)
	halfGapReleases(&nodefs)

	// The image store lives on the data volume, so imagefs is nodefs under
	// another name and says so.
	imagefs := nodefs
	imagefs.id = budgetv1alpha1.SignalImagefsAvailable
	imagefs.limiting = budgetv1alpha1.ResourceImagefs
	imagefs.sharedWith = budgetv1alpha1.SignalNodefsAvailable

	pid := signalLadder{id: budgetv1alpha1.SignalPIDAvailable, limiting: budgetv1alpha1.ResourcePID}
	if pidMax >= minPIDLadderMax {
		// Today's PIDPressure trips above pidPressureUsedPercent used, so the
		// hard rung is the remaining share. It has no hysteresis, so no release.
		pid.rungs = [numBudgetRungs]*int64{
			i64(pidMax * 30 / 100),
			i64(pidMax * 25 / 100),
			i64(pidMax * 15 / 100),
			nil,
			i64(pidMax * (100 - pidPressureUsedPercent) / 100),
		}
		halfGapReleases(&pid)
	}

	l := budgetLadder{
		dwell:  budgetLevelDwell,
		darwin: darwinLadder{swapGateBytes: max(swapTripUsedBytes, memCapacity/4)},
	}
	for _, sl := range []signalLadder{mem, comp, swap, swapfs, nodefs, imagefs, pid} {
		l.signals[sl.id.PageCode()-1] = sl
	}
	return l
}

// ladderOf returns the ladder stamped into s by the monitor, or the default
// ladder for s's host when s never passed through one.
func ladderOf(s hostStats) budgetLadder {
	if s.history.ladderSet {
		return s.history.ladder
	}
	return defaultLadder(s.MemCapacityBytes, s.PIDMax)
}

// swapReading is one sample of swap in use, for the memory.swap window.
type swapReading struct {
	at   time.Time
	used int64
}

// swapWindowCap bounds the memory.swap window: the fastest cadence is one
// sample a second, so 60 s holds at most 61 readings.
const swapWindowCap = 64

// swapWindow is the memory.swap readings of the last memorySwapWindow, oldest
// first. It is a fixed-size value, so a snapshot carrying it stays comparable
// and a stamped window is never shared.
type swapWindow struct {
	r [swapWindowCap]swapReading
	n int
}

// next returns w with the reading (at, used) appended and every reading older
// than memorySwapWindow before at dropped. Past the cap the oldest reading
// goes first.
func (w swapWindow) next(at time.Time, used int64) swapWindow {
	var out swapWindow
	for _, r := range w.r[:w.n] {
		if at.Sub(r.at) <= memorySwapWindow {
			if out.n == swapWindowCap {
				copy(out.r[:], out.r[1:])
				out.n--
			}
			out.r[out.n] = r
			out.n++
		}
	}
	if out.n == swapWindowCap {
		copy(out.r[:], out.r[1:])
		out.n--
	}
	out.r[out.n] = swapReading{at: at, used: used}
	out.n++
	return out
}

// budgetHold is the budget's state carried from one sample to the next: which
// rungs are held and since when, when each level was last observed (the
// dwell), and what last blocked admission. The zero value holds nothing.
type budgetHold struct {
	held  [numBudgetSlots][numBudgetRungs]bool
	since [numBudgetSlots][numBudgetRungs]time.Time
	// lastSeen is when the raw level was last at or above warn, critical and
	// evicting (indexes 1..3 of levelRank); index 0 is unused.
	lastSeen [4]time.Time
	// blockedAt and blockedBy are the last sample that held an admit-stop rung
	// and the signal that held it.
	blockedAt time.Time
	blockedBy budgetv1alpha1.SignalID
	// worst is the last signal seen at warn or above with the highest rung,
	// which names a SoftPressure condition held by the dwell.
	worst budgetv1alpha1.SignalID
	// anyHeld is true when any rung is held at this sample, which keeps the
	// monitor on its fast cadence.
	anyHeld bool
}

// levelRank orders the published levels.
var levelRank = [4]budgetv1alpha1.Level{
	budgetv1alpha1.LevelOK, budgetv1alpha1.LevelWarn, budgetv1alpha1.LevelCritical, budgetv1alpha1.LevelEvicting,
}

// rungLevel is the level a held rung puts its signal at. A hard trip on its
// own is critical: of the hard rungs only the memory arms evict, and when they
// do memoryPressured raises the node to evicting.
func rungLevel(r budgetRung) int {
	switch r {
	case rungWarn, rungAdmitStop:
		return 1
	case rungEvictSoft:
		return 3
	default:
		return 2
	}
}

// budgetSignalValue returns the signal's current value, or nil when the
// snapshot did not sample it.
func budgetSignalValue(s hostStats, id budgetv1alpha1.SignalID) *int64 {
	switch id {
	case budgetv1alpha1.SignalMemoryAvailable:
		if s.MemCapacityBytes <= 0 {
			return nil
		}
		return i64(max(0, s.MemAvailableBytes))
	case budgetv1alpha1.SignalMemoryCompressor:
		var v int64
		ok := false
		if s.CompressorPagesLimit > 0 {
			v, ok = s.CompressorPages*1000/s.CompressorPagesLimit, true
		}
		if s.CompressorSegmentsLimit > 0 {
			v, ok = max(v, s.CompressorSegments*1000/s.CompressorSegmentsLimit), true
		}
		if !ok {
			return nil
		}
		return i64(max(0, v))
	case budgetv1alpha1.SignalMemorySwap:
		now := s.history.sampledAt
		low, ok := s.SwapUsedBytes, false
		w := s.history.swapWindow
		for _, r := range w.r[:w.n] {
			if now.Sub(r.at) <= memorySwapWindow {
				low, ok = min(low, r.used), true
			}
		}
		if !ok {
			return nil
		}
		return i64(max(0, s.SwapUsedBytes-low))
	case budgetv1alpha1.SignalSwapfsAvailable:
		if s.SwapVolumeCapacityBytes <= 0 {
			return nil
		}
		return i64(max(0, s.SwapVolumeAvailableBytes))
	case budgetv1alpha1.SignalNodefsAvailable, budgetv1alpha1.SignalImagefsAvailable:
		if s.DiskCapacityBytes <= 0 {
			return nil
		}
		return i64(max(0, s.DiskAvailableBytes))
	case budgetv1alpha1.SignalPIDAvailable:
		if s.PIDMax <= 0 {
			return nil
		}
		return i64(max(0, s.PIDMax-s.PIDCount))
	}
	return nil
}

// pastRung reports whether v is at or past threshold t on a signal falling
// (desc) or rising under pressure.
func pastRung(desc bool, v, t int64) bool {
	if desc {
		return v <= t
	}
	return v >= t
}

// calmOfRelease reports whether v is on the calm side of release rel: above it
// on a falling signal, below it on a rising one. A rung with no release is
// calm as soon as v is no longer past the rung itself.
func calmOfRelease(desc bool, v int64, rel, t *int64) bool {
	if rel == nil {
		return !pastRung(desc, v, *t)
	}
	if desc {
		return v >= *rel
	}
	return v <= *rel
}

// budgetOf reduces snapshot s and ladder l to the node budget observation, and
// returns the hold the next snapshot must carry. It is PURE over (s, l): the
// previous hold and the sample time ride in s.history. Capacity beyond the
// host sample (CPU, allocatable) is the caller's to add.
func budgetOf(s hostStats, l budgetLadder) (budgetv1alpha1.NodeBudgetObservation, budgetHold) {
	prev := s.history.budget
	now := s.history.sampledAt
	var next budgetHold
	next.worst = prev.worst

	obs := budgetv1alpha1.NodeBudgetObservation{
		ObservedAt: metav1.NewTime(now),
		Platform:   budgetv1alpha1.PlatformDarwin,
		Admit:      true,
		Darwin:     &budgetv1alpha1.DarwinSignals{VMPressureLevel: s.VMPressureLevel},
	}
	if s.MemorystatusLevel != nil {
		obs.Darwin.MemorystatusLevelPermille = i64(min(1000, max(0, *s.MemorystatusLevel*10)))
	}
	if s.MemCapacityBytes > 0 {
		obs.Capacity.MemCapacityBytes = i64(s.MemCapacityBytes)
	}
	obs.Capacity.MemEvictionReserveBytes = i64(memEvictionReserveBytes)
	obs.Capacity.SwapUsedBytes = i64(max(0, s.SwapUsedBytes))

	raw := 0
	worstRung := budgetRung(-1)
	var blockedBy budgetv1alpha1.SignalID
	var deadline *time.Time
	var memAdmitStop *int64

	for _, sl := range l.signals {
		slot := int(sl.id.PageCode()) - 1
		if slot < 0 || slot >= numBudgetSlots {
			continue
		}
		desc := budgetv1alpha1.IsDescending(sl.id)
		v := budgetSignalValue(s, sl.id)
		gated := sl.id == budgetv1alpha1.SignalMemorySwap && s.SwapUsedBytes < l.darwin.swapGateBytes

		top := budgetRung(-1)
		for r := rungWarn; r < numBudgetRungs; r++ {
			t := sl.rungs[r]
			if t == nil || v == nil || gated {
				continue
			}
			held := pastRung(desc, *v, *t) ||
				(prev.held[slot][r] && !calmOfRelease(desc, *v, sl.releases[r], t))
			if !held {
				continue
			}
			next.held[slot][r] = true
			next.since[slot][r] = now
			if prev.held[slot][r] {
				next.since[slot][r] = prev.since[slot][r]
			}
			next.anyHeld = true
			top = r
		}

		if top >= 0 {
			if lv := rungLevel(top); lv > raw {
				raw = lv
			}
			if top > worstRung {
				worstRung, next.worst = top, sl.id
			}
			if top >= rungAdmitStop && blockedBy == "" {
				blockedBy = sl.id
			}
		}
		if next.held[slot][rungEvictSoft] && sl.graceSeconds != nil {
			d := next.since[slot][rungEvictSoft].Add(time.Duration(*sl.graceSeconds) * time.Second)
			if deadline == nil || d.Before(*deadline) {
				deadline = &d
			}
		}
		if sl.id == budgetv1alpha1.SignalMemoryAvailable {
			memAdmitStop = sl.rungs[rungAdmitStop]
		}

		obs.Signals = append(obs.Signals, budgetv1alpha1.BudgetSignal{
			ID:                 sl.id,
			Unit:               sl.id.Unit(),
			Value:              v,
			WarnThreshold:      sl.rungs[rungWarn],
			AdmitStopThreshold: sl.rungs[rungAdmitStop],
			CriticalThreshold:  sl.rungs[rungCritical],
			EvictSoftThreshold: sl.rungs[rungEvictSoft],
			EvictHardThreshold: sl.rungs[rungEvictHard],
			WarnRelease:        sl.releases[rungWarn],
			AdmitStopRelease:   sl.releases[rungAdmitStop],
			CriticalRelease:    sl.releases[rungCritical],
			EvictSoftRelease:   sl.releases[rungEvictSoft],
			EvictHardRelease:   sl.releases[rungEvictHard],
			GraceSeconds:       sl.graceSeconds,
			MinReclaimBytes:    sl.minReclaimBytes,
			WindowSeconds:      sl.windowSeconds,
			LimitingResource:   sl.limiting,
			SharedWith:         sl.sharedWith,
		})
	}

	// Tier 2 is acting: the node is evicting whatever the advisory rungs say.
	if pressured, _ := memoryPressured(s); pressured {
		raw = 3
	}

	// The level dwell: a level stays published until it has gone unobserved
	// for the dwell, on the sample clock.
	level := raw
	for lv := 1; lv <= 3; lv++ {
		switch {
		case raw >= lv:
			next.lastSeen[lv] = now
		case !prev.lastSeen[lv].IsZero() && now.Sub(prev.lastSeen[lv]) < l.dwell:
			next.lastSeen[lv] = prev.lastSeen[lv]
			level = max(level, lv)
		}
	}
	obs.Level = levelRank[level]
	if level == 0 {
		next.worst = ""
	}

	// Admission follows the admit-stop rungs with the same dwell.
	switch {
	case blockedBy != "":
		next.blockedAt, next.blockedBy = now, blockedBy
	case prev.blockedBy != "" && now.Sub(prev.blockedAt) < l.dwell:
		next.blockedAt, next.blockedBy = prev.blockedAt, prev.blockedBy
	}
	if next.blockedBy != "" {
		obs.Admit = false
		obs.AdmitReasonSignal = next.blockedBy
	}

	if deadline != nil {
		obs.EvictDeadline = &metav1.Time{Time: *deadline}
	}

	if memAdmitStop != nil && s.MemCapacityBytes > 0 {
		safe := int64(0)
		if obs.Admit {
			safe = max(0, s.MemAvailableBytes-*memAdmitStop) * (1000 - budgetv1alpha1.DefaultMarginPermille) / 1000
		}
		obs.Recommendation = budgetv1alpha1.BudgetRecommendation{
			SafeAdditionalBytes: i64(safe),
			Basis:               budgetv1alpha1.SignalMemoryAvailable,
		}
	}
	return obs, next
}
