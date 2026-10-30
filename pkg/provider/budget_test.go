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
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

const (
	tMi = int64(1) << 20
	tGi = int64(1) << 30
)

// budgetRig drives a real pressure monitor over a settable snapshot and a fake
// wall clock, and reads the budget the way the status loop does: budgetOf over
// the stored snapshot.
type budgetRig struct {
	t     *testing.T
	m     *pressureMonitor
	s     hostStats
	clock time.Time
}

func newBudgetRig(t *testing.T, s hostStats) *budgetRig {
	t.Helper()
	r := &budgetRig{t: t, s: s, clock: time.Unix(1_800_000_000, 0)}
	r.m = newPressureMonitor(func() (hostStats, error) { return r.s, nil }, discardLog())
	r.m.now = func() time.Time { return r.clock }
	return r
}

// step advances the clock by d, samples s and returns the observation and the
// hold of the stored snapshot. Every observation must validate.
func (r *budgetRig) step(d time.Duration, s hostStats) (budgetv1alpha1.NodeBudgetObservation, budgetHold) {
	r.t.Helper()
	r.clock = r.clock.Add(d)
	r.s = s
	r.m.sampleOnce()
	snap, _, ok := r.m.latest()
	if !ok {
		r.t.Fatal("no snapshot after a sample")
	}
	obs, h := budgetOf(snap, ladderOf(snap))
	if err := obs.Validate(); err != nil {
		r.t.Fatalf("observation does not validate: %v", err)
	}
	return obs, h
}

// budgetHost is a calm snapshot of a host with memGi GiB of memory and a
// process ceiling of pidMax: every signal sampled, none near a rung.
func budgetHost(memGi, pidMax int64) hostStats {
	return hostStats{
		MemCapacityBytes:         memGi * tGi,
		MemAvailableBytes:        memGi * tGi / 2,
		DiskCapacityBytes:        2048 * tGi,
		DiskAvailableBytes:       1024 * tGi,
		PIDMax:                   pidMax,
		PIDCount:                 0,
		CompressorPagesLimit:     1000,
		CompressorSegmentsLimit:  1000,
		SwapVolumeCapacityBytes:  2048 * tGi,
		SwapVolumeAvailableBytes: 1024 * tGi,
	}
}

// withSignal sets the value of signal id in s.
func withSignal(s hostStats, id budgetv1alpha1.SignalID, v int64) hostStats {
	switch id {
	case budgetv1alpha1.SignalMemoryAvailable:
		s.MemAvailableBytes = v
	case budgetv1alpha1.SignalMemoryCompressor:
		s.CompressorPages = v
	case budgetv1alpha1.SignalSwapfsAvailable:
		s.SwapVolumeAvailableBytes = v
	case budgetv1alpha1.SignalNodefsAvailable, budgetv1alpha1.SignalImagefsAvailable:
		s.DiskAvailableBytes = v
	case budgetv1alpha1.SignalPIDAvailable:
		s.PIDCount = s.PIDMax - v
	}
	return s
}

func ladderSignal(l budgetLadder, id budgetv1alpha1.SignalID) signalLadder {
	return l.signals[id.PageCode()-1]
}

func ptrs(vs ...int64) [numBudgetRungs]*int64 {
	var out [numBudgetRungs]*int64
	for i, v := range vs {
		if v >= 0 {
			out[i] = i64(v)
		}
	}
	return out
}

func fmtRungs(a [numBudgetRungs]*int64) string {
	parts := make([]string, numBudgetRungs)
	for i, p := range a {
		parts[i] = "-"
		if p != nil {
			parts[i] = fmt.Sprint(*p)
		}
	}
	return strings.Join(parts, "/")
}

// TestBudgetOfLadderPerHostSize is the node-budget ladder gate: the default ladder
// pins every rung and release in exact values for 8, 16, 32, 64 and 128 GiB
// hosts (and the pid ladder for two process ceilings), and on each host every
// rung of every signal is crossed down and back: met at its threshold with the
// right level, admit and admitReasonSignal; still held between the threshold
// and its release; released at the release; met again.
func TestBudgetOfLadderPerHostSize(t *testing.T) {
	const none = -1
	hosts := []struct {
		memGi, pidMax int64
		mem, memRel   [5]int64
		floor         int64
	}{
		{8, 2000,
			[5]int64{1073741824, 805306368, 536870912, 268435456, 104857600},
			[5]int64{1207959552, 939524096, 671088640, 402653184, 209715200}, 8 * tGi},
		{16, 4000,
			[5]int64{2061584302, 1374389534, 858993459, 429496729, 104857600},
			[5]int64{2405181686, 1717986918, 1116691496, 644245094, 209715200}, 8 * tGi},
		{32, 8000,
			[5]int64{4123168604, 2748779069, 1717986918, 858993459, 104857600},
			[5]int64{4810363371, 3435973836, 2233382993, 1288490188, 209715200}, 8 * tGi},
		{64, 16000,
			[5]int64{8246337208, 5497558138, 3435973836, 1717986918, 104857600},
			[5]int64{9620726743, 6871947673, 4466765987, 2576980377, 209715200}, 16 * tGi},
		{128, 16000,
			[5]int64{16492674416, 10995116277, 6871947673, 3435973836, 104857600},
			[5]int64{19241453485, 13743895346, 8933531975, 5153960754, 209715200}, 32 * tGi},
	}
	for _, h := range hosts {
		t.Run(fmt.Sprintf("%dGiB/maxproc %d", h.memGi, h.pidMax), func(t *testing.T) {
			l := defaultLadder(h.memGi*tGi, h.pidMax)
			F := h.floor
			p := h.pidMax
			want := map[budgetv1alpha1.SignalID][2][numBudgetRungs]*int64{
				budgetv1alpha1.SignalMemoryAvailable: {ptrs(h.mem[:]...), ptrs(h.memRel[:]...)},
				budgetv1alpha1.SignalMemoryCompressor: {ptrs(500, 600, 700, 750, 800),
					ptrs(450, 550, 650, 725, 700)},
				budgetv1alpha1.SignalMemorySwap: {ptrs(256*tMi, 512*tMi, tGi, none, none),
					ptrs(128*tMi, 384*tMi, 768*tMi, none, none)},
				budgetv1alpha1.SignalSwapfsAvailable: {ptrs(3*F, 2*F, F*3/2, none, F),
					ptrs(F*7/2, F*5/2, F*7/4, none, F*3/2)},
				budgetv1alpha1.SignalNodefsAvailable: {ptrs(20*tGi, 15*tGi, 10*tGi, none, 2*tGi),
					ptrs(20*tGi+tGi*5/2, 15*tGi+tGi*5/2, 10*tGi+tGi*5/2, none, 10*tGi)},
				budgetv1alpha1.SignalImagefsAvailable: {ptrs(20*tGi, 15*tGi, 10*tGi, none, 2*tGi),
					ptrs(20*tGi+tGi*5/2, 15*tGi+tGi*5/2, 10*tGi+tGi*5/2, none, 10*tGi)},
				budgetv1alpha1.SignalPIDAvailable: {ptrs(p*30/100, p*25/100, p*15/100, none, p*10/100),
					ptrs(p*325/1000, p*275/1000, p*20/100, none, none)},
			}
			for id, w := range want {
				sl := ladderSignal(l, id)
				if fmtRungs(sl.rungs) != fmtRungs(w[0]) {
					t.Errorf("%s rungs = %s, want %s", id, fmtRungs(sl.rungs), fmtRungs(w[0]))
				}
				if fmtRungs(sl.releases) != fmtRungs(w[1]) {
					t.Errorf("%s releases = %s, want %s", id, fmtRungs(sl.releases), fmtRungs(w[1]))
				}
			}
			if h.memGi == 64 && h.pidMax == 16000 {
				// The plan's worked example for this host size.
				pid := ladderSignal(l, budgetv1alpha1.SignalPIDAvailable)
				if fmtRungs(pid.rungs) != "4800/4000/2400/-/1600" || fmtRungs(pid.releases) != "5200/4400/3200/-/-" {
					t.Errorf("pid ladder at maxproc 16000 = %s release %s", fmtRungs(pid.rungs), fmtRungs(pid.releases))
				}
			}
			mem := ladderSignal(l, budgetv1alpha1.SignalMemoryAvailable)
			if got, wantR := *mem.minReclaimBytes, h.memRel[3]-h.mem[3]; got != wantR {
				t.Errorf("memory.available minReclaimBytes = %d, want %d", got, wantR)
			}
			if got := l.darwin.swapGateBytes; got != max(tGi, h.memGi*tGi/4) {
				t.Errorf("memory.swap gate = %d, want max(1Gi, mem/4)", got)
			}

			for _, id := range []budgetv1alpha1.SignalID{
				budgetv1alpha1.SignalMemoryAvailable, budgetv1alpha1.SignalMemoryCompressor,
				budgetv1alpha1.SignalSwapfsAvailable, budgetv1alpha1.SignalNodefsAvailable,
				budgetv1alpha1.SignalPIDAvailable,
			} {
				sl := ladderSignal(l, id)
				desc := budgetv1alpha1.IsDescending(id)
				for r := rungWarn; r < numBudgetRungs; r++ {
					if sl.rungs[r] == nil {
						continue
					}
					name := fmt.Sprintf("%s %s", id, budgetRungNames[r])
					crossRung(t, name, budgetHost(h.memGi, h.pidMax), id, r, desc, *sl.rungs[r], sl.releases[r])
				}
			}
		})
	}
}

// crossRung meets rung r of signal id at threshold t, holds it inside the band,
// releases it at rel, and meets it again.
func crossRung(t *testing.T, name string, base hostStats, id budgetv1alpha1.SignalID, r budgetRung, desc bool, th int64, rel *int64) {
	t.Helper()
	rig := newBudgetRig(t, base)
	rig.step(0, base)

	wantLevel := map[budgetRung]budgetv1alpha1.Level{
		rungWarn: budgetv1alpha1.LevelWarn, rungAdmitStop: budgetv1alpha1.LevelWarn,
		rungCritical: budgetv1alpha1.LevelCritical, rungEvictSoft: budgetv1alpha1.LevelEvicting,
		rungEvictHard: budgetv1alpha1.LevelCritical,
	}[r]
	tier2 := r == rungEvictHard && (id == budgetv1alpha1.SignalMemoryAvailable || id == budgetv1alpha1.SignalMemoryCompressor)
	if tier2 {
		wantLevel = budgetv1alpha1.LevelEvicting
	}

	// Tier 2 trips memory.available strictly under 100Mi, so the hard rung is
	// met one byte past its published threshold.
	at := th
	if tier2 && id == budgetv1alpha1.SignalMemoryAvailable {
		at = th - 1
	}
	meet := func(phase string) {
		t.Helper()
		obs, h := rig.step(time.Second, withSignal(base, id, at))
		if got := heldRung(h, id); got != r {
			t.Errorf("%s %s: held rung %d, want %d", name, phase, got, r)
		}
		if obs.Level != wantLevel {
			t.Errorf("%s %s: level %q, want %q", name, phase, obs.Level, wantLevel)
		}
		wantAdmit := r < rungAdmitStop
		if obs.Admit != wantAdmit {
			t.Errorf("%s %s: admit %v, want %v", name, phase, obs.Admit, wantAdmit)
		}
		if !wantAdmit && obs.AdmitReasonSignal != id {
			t.Errorf("%s %s: admitReasonSignal %q, want %q", name, phase, obs.AdmitReasonSignal, id)
		}
		if r == rungEvictSoft && obs.EvictDeadline == nil {
			t.Errorf("%s %s: evictDeadline unset at the evict-soft rung", name, phase)
		}
	}
	meet("met")

	if rel != nil {
		// Inside the band: on the calm side of the threshold, short of the release.
		mid := th + (*rel-th)/2
		if desc && mid <= th || !desc && mid >= th {
			t.Fatalf("%s: release %d is not on the calm side of %d", name, *rel, th)
		}
		_, h := rig.step(time.Second, withSignal(base, id, mid))
		if got := heldRung(h, id); got != r {
			t.Errorf("%s in band (%d): held rung %d, want %d (the release holds it)", name, mid, got, r)
		}
		_, h = rig.step(time.Second, withSignal(base, id, *rel))
		if got := heldRung(h, id); got >= r {
			t.Errorf("%s at release %d: held rung %d, want below %d", name, *rel, got, r)
		}
	} else {
		calm := th + 1
		if !desc {
			calm = th - 1
		}
		_, h := rig.step(time.Second, withSignal(base, id, calm))
		if got := heldRung(h, id); got >= r {
			t.Errorf("%s off the rung (no release): held rung %d, want below %d", name, got, r)
		}
	}
	meet("met again")

	// Back to calm: the level and the admit block hold for the dwell, then clear.
	obs, _ := rig.step(time.Second, base)
	if obs.Level != wantLevel {
		t.Errorf("%s calm inside the dwell: level %q, want %q held", name, obs.Level, wantLevel)
	}
	obs, _ = rig.step(budgetLevelDwell, base)
	if obs.Level != budgetv1alpha1.LevelOK || !obs.Admit || obs.AdmitReasonSignal != "" {
		t.Errorf("%s calm past the dwell: level %q admit %v reason %q, want ok/true/none",
			name, obs.Level, obs.Admit, obs.AdmitReasonSignal)
	}
}

// TestBudgetMemorySwapGrowthWindow pins memory.swap: the rise over the last
// 60 s, unset before a second sample, clamped at 0, gated on swap in use, and
// windowed on the wall clock.
func TestBudgetMemorySwapGrowthWindow(t *testing.T) {
	swapValue := func(obs budgetv1alpha1.NodeBudgetObservation) *int64 {
		for _, s := range obs.Signals {
			if s.ID == budgetv1alpha1.SignalMemorySwap {
				return s.Value
			}
		}
		return nil
	}
	swapUsed := func(used int64) hostStats { s := budgetHost(8, 2000); s.SwapUsedBytes = used; return s }

	rig := newBudgetRig(t, swapUsed(5*tGi))
	obs, _ := rig.step(0, swapUsed(5*tGi))
	if v := swapValue(obs); v != nil {
		t.Fatalf("first sample: memory.swap = %d, want unset", *v)
	}
	obs, h := rig.step(10*time.Second, swapUsed(5*tGi+256*tMi))
	if v := swapValue(obs); v == nil || *v != 256*tMi {
		t.Fatalf("a 256Mi rise in 10s: memory.swap = %v, want 256Mi", v)
	}
	if heldRung(h, budgetv1alpha1.SignalMemorySwap) != rungWarn || obs.Level != budgetv1alpha1.LevelWarn {
		t.Errorf("a 256Mi rise holds warn: rung %d level %q", heldRung(h, budgetv1alpha1.SignalMemorySwap), obs.Level)
	}
	// Falling swap clamps at 0, never negative.
	obs, _ = rig.step(10*time.Second, swapUsed(4*tGi))
	if v := swapValue(obs); v == nil || *v != 0 {
		t.Errorf("falling swap: memory.swap = %v, want 0", v)
	}
	// The window is 60 s of wall clock: a reading 61 s old no longer counts.
	rig2 := newBudgetRig(t, swapUsed(5*tGi))
	rig2.step(0, swapUsed(5*tGi))
	obs, _ = rig2.step(61*time.Second, swapUsed(5*tGi+600*tMi))
	if v := swapValue(obs); v != nil {
		t.Errorf("only a reading 61s old: memory.swap = %d, want unset", *v)
	}
	obs, _ = rig2.step(30*time.Second, swapUsed(5*tGi+700*tMi))
	if v := swapValue(obs); v == nil || *v != 100*tMi {
		t.Errorf("rise over the last 60s: memory.swap = %v, want 100Mi", v)
	}
	// Below the gate (max(1Gi, mem/4) = 2Gi on 8 GiB) growth holds no rung.
	rig3 := newBudgetRig(t, swapUsed(512*tMi))
	rig3.step(0, swapUsed(512*tMi))
	obs, h = rig3.step(time.Second, swapUsed(1536*tMi))
	if heldRung(h, budgetv1alpha1.SignalMemorySwap) != -1 || obs.Level != budgetv1alpha1.LevelOK {
		t.Errorf("1Gi rise under the 2Gi gate: rung %d level %q, want none/ok", heldRung(h, budgetv1alpha1.SignalMemorySwap), obs.Level)
	}
}

// TestBudgetLevelDwellWallClock pins the dwell to the sample clock: rises
// publish at once; a fall publishes only after the higher level has been
// unobserved for budgetLevelDwell, however many samples arrive meanwhile.
func TestBudgetLevelDwellWallClock(t *testing.T) {
	base := budgetHost(8, 2000)
	crit := withSignal(base, budgetv1alpha1.SignalNodefsAvailable, 9*tGi)
	rig := newBudgetRig(t, base)
	rig.step(0, base)
	if obs, _ := rig.step(time.Second, crit); obs.Level != budgetv1alpha1.LevelCritical {
		t.Fatalf("rise: level %q, want critical at once", obs.Level)
	}
	// Calm at a varying cadence: 1 s, 10 s and 3 s gaps, all inside 5 min.
	elapsed := time.Duration(0)
	for _, gap := range []time.Duration{time.Second, 10 * time.Second, 3 * time.Second, 10 * time.Second, 4 * time.Minute} {
		elapsed += gap
		if obs, _ := rig.step(gap, base); obs.Level != budgetv1alpha1.LevelCritical {
			t.Fatalf("%v after the release: level %q, want critical held", elapsed, obs.Level)
		}
	}
	if obs, _ := rig.step(budgetLevelDwell-elapsed, base); obs.Level != budgetv1alpha1.LevelOK {
		t.Errorf("5m after the release: level %q, want ok", obs.Level)
	}
	// A dwell honours the ladder's own value (a policy override).
	rig2 := newBudgetRig(t, base)
	rig2.m.ladder = func(s hostStats) budgetLadder {
		l := defaultLadder(s.MemCapacityBytes, s.PIDMax)
		l.dwell = 30 * time.Second
		return l
	}
	rig2.step(0, base)
	rig2.step(time.Second, crit)
	if obs, _ := rig2.step(31*time.Second, base); obs.Level != budgetv1alpha1.LevelOK {
		t.Errorf("30s dwell, 31s calm: level %q, want ok", obs.Level)
	}
}

// TestBudgetEvictingFollowsTier2Verdict: the node level is evicting exactly
// while memoryPressured is true, and a tier-2 verdict alone sets no deadline.
func TestBudgetEvictingFollowsTier2Verdict(t *testing.T) {
	base := budgetHost(8, 2000)
	rig := newBudgetRig(t, base)
	rig.step(0, base)
	// The swap arm: growing swap and swapfs under the floor. No advisory
	// evict-soft rung is held (swapfs has none), so no deadline.
	s := base
	s.SwapUsedBytes = 3 * tGi
	s.SwapVolumeAvailableBytes = 7 * tGi
	rig.step(time.Second, s)
	s.SwapUsedBytes = 3*tGi + tMi
	obs, _ := rig.step(time.Second, s)
	snap, _, _ := rig.m.latest()
	if p, _ := memoryPressured(snap); !p {
		t.Fatal("the swap arm did not fire")
	}
	if obs.Level != budgetv1alpha1.LevelEvicting {
		t.Errorf("tier 2 acting: level %q, want evicting", obs.Level)
	}
	if obs.EvictDeadline != nil {
		t.Errorf("tier 2 alone: evictDeadline %v, want unset", obs.EvictDeadline)
	}
	// The memory.available evict-soft rung sets a deadline at first-met + 90s.
	rig2 := newBudgetRig(t, base)
	rig2.step(0, base)
	met := rig2.clock.Add(time.Second)
	obs, _ = rig2.step(time.Second, withSignal(base, budgetv1alpha1.SignalMemoryAvailable, 200*tMi))
	obs, _ = rig2.step(time.Second, withSignal(base, budgetv1alpha1.SignalMemoryAvailable, 200*tMi))
	if obs.EvictDeadline == nil || !obs.EvictDeadline.Time.Equal(met.Add(90*time.Second)) {
		t.Errorf("evict-soft deadline = %v, want first-met + 90s (%v)", obs.EvictDeadline, met.Add(90*time.Second))
	}
}

// TestSoftPressureAdvisory: the fifth condition is SoftPressure, False and
// NodeBudgetOK when calm, True with the worst signal's Reason and every held
// signal in the Message, its transition time preserved across heartbeats, and
// no taint anywhere.
func TestSoftPressureAdvisory(t *testing.T) {
	base := budgetHost(8, 2000)
	rig := newBudgetRig(t, base)
	rig.step(0, base)
	snap, _, _ := rig.m.latest()
	t0 := metav1.NewTime(rig.clock)
	prev := reconcileTransitions(nil, computeNodeConditions(snap, t0), snap)
	if len(prev) != 5 {
		t.Fatalf("got %d conditions, want 5", len(prev))
	}
	c := findNodeCondition(prev, nodeSoftPressure)
	if c == nil || c.Status != corev1.ConditionFalse || c.Reason != "NodeBudgetOK" {
		t.Fatalf("calm SoftPressure = %+v, want False NodeBudgetOK", c)
	}

	s := withSignal(base, budgetv1alpha1.SignalSwapfsAvailable, 20*tGi)
	s = withSignal(s, budgetv1alpha1.SignalNodefsAvailable, 12*tGi)
	rig.step(time.Second, s)
	snap, _, _ = rig.m.latest()
	t1 := metav1.NewTime(rig.clock)
	next := reconcileTransitions(prev, computeNodeConditions(snap, t1), snap)
	c = findNodeCondition(next, nodeSoftPressure)
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("SoftPressure under pressure = %+v, want True", c)
	}
	if c.Reason != "NodefsAvailableLow" {
		t.Errorf("Reason = %q, want the worst signal (nodefs at admit-stop)", c.Reason)
	}
	for _, want := range []string{"swapfs.available 20.0Gi (warn 24.0Gi)", "nodefs.available 12.0Gi (admit-stop 15.0Gi)"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("Message %q lacks %q", c.Message, want)
		}
	}
	if !c.LastTransitionTime.Equal(&t1) {
		t.Errorf("transition time = %v, want %v", c.LastTransitionTime, t1)
	}
	rig.step(time.Second, s)
	snap, _, _ = rig.m.latest()
	again := reconcileTransitions(next, computeNodeConditions(snap, metav1.NewTime(rig.clock)), snap)
	if c := findNodeCondition(again, nodeSoftPressure); !c.LastTransitionTime.Equal(&t1) {
		t.Errorf("unchanged SoftPressure moved its transition time to %v", c.LastTransitionTime)
	}

	// No taint: the published node carries only the bootstrap taints.
	h := newNodeStatusHarness(t, bootstrapNode())
	h.setStats(s)
	node := h.step()
	if c := findNodeCondition(node.Status.Conditions, nodeSoftPressure); c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("published SoftPressure = %+v, want True", c)
	}
	if got, want := len(node.Spec.Taints), len(bootstrapNode().Spec.Taints); got != want {
		t.Errorf("published node has %d taints, want the bootstrap's %d", got, want)
	}
	if obs, ok := h.p.Budget(); !ok || obs.Level != budgetv1alpha1.LevelWarn || obs.Capacity.MemAllocatableBytes == nil {
		t.Errorf("Budget() = level %q ok %v allocatable %v", obs.Level, ok, obs.Capacity.MemAllocatableBytes)
	}
}

// TestBudgetObservationValidates: every observation over a spread of hosts and
// readings, including unsampled ones, passes NodeBudgetObservation.Validate.
func TestBudgetObservationValidates(t *testing.T) {
	for _, memGi := range []int64{0, 8, 16, 32, 64, 128} {
		for _, pidMax := range []int64{0, 50, 2000, 16000} {
			base := budgetHost(memGi, pidMax)
			rig := newBudgetRig(t, base)
			rig.step(0, base) // step validates
			for _, id := range []budgetv1alpha1.SignalID{
				budgetv1alpha1.SignalMemoryAvailable, budgetv1alpha1.SignalSwapfsAvailable,
				budgetv1alpha1.SignalNodefsAvailable, budgetv1alpha1.SignalPIDAvailable,
			} {
				rig.step(time.Second, withSignal(base, id, 0))
			}
			rig.step(time.Second, withSignal(base, budgetv1alpha1.SignalMemoryCompressor, 1000))
			rig.step(time.Second, hostStats{})
		}
	}
}

// TestPressureCadenceFastFromWarn: a held warn rung puts the monitor at 1 s,
// even short of every half-way mark, and it slows down after three calm samples.
func TestPressureCadenceFastFromWarn(t *testing.T) {
	base := budgetHost(8, 2000)
	warn := withSignal(base, budgetv1alpha1.SignalNodefsAvailable, 19*tGi)
	if pressureElevated(warn) {
		t.Fatal("fixture is past a half-way mark; it must test the warn rung alone")
	}
	rig := newBudgetRig(t, base)
	rig.step(0, base)
	if d := rig.m.interval(); d != pressureCalmInterval {
		t.Fatalf("calm interval = %v", d)
	}
	rig.step(time.Second, warn)
	if d := rig.m.interval(); d != pressureFastInterval {
		t.Errorf("at warn: interval %v, want %v", d, pressureFastInterval)
	}
	for range pressureCalmSamplesToSlowDown {
		rig.step(time.Second, base)
	}
	if d := rig.m.interval(); d != pressureCalmInterval {
		t.Errorf("after three calm samples: interval %v, want %v", d, pressureCalmInterval)
	}
}
