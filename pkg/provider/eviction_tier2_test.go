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
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

// TestTier2EvictionCharacterization pins today's hard (grace 0) node-pressure
// eviction as it behaves now: the trips, the episode, the timing bounds, the
// candidate order, the critical-pod skip, the grace, and the evicted status. It
// is a characterization test: it is green on today's code by design, and its
// job is to make every later change to this path land as a visible red, then
// green, against a written record of what came before.
//
// Thresholds and timings are written as literals, never as the production
// constants, so a changed constant reds a row instead of moving with it.
//
// ROWS THE PLANNED TIER-2 CHANGES WILL FLIP ON PURPOSE. The node-budget work
// plans to rank tier-2 candidates by band (batch, then standard, never
// critical), to move the tier-2 trips strictly beyond the soft eviction tier, and
// to add a short wall-clock hold with an instantaneous override. When that
// lands, these rows change their expectation in the same change, red to green:
//
//	A1, A2, A3, A4, A5   the trip and release values of each arm
//	A9                   which arm names the eviction
//	A10                  a pressured first sample evicts in the same cycle
//	A11                  the eviction message per arm
//	B1, B2               the candidate order (band ranking goes in front)
//	D3                   the band annotation has no effect today
//	H1                   the fast stale boundary (the cadence changes)
//	G1                   the step schedule of the cascade-cap subtest
//
// Every other row is meant to survive that work unchanged.
//
// ROWS COVERED ELSEWHERE (cited, not duplicated):
//
//	A5  compressor trip at 80%, hold above 70%, release at 70%; segments the same:
//	    TestComputeNodeConditionsCompressorHeadroom (the first two table cases)
//	A8  the swap arm needs under 8 GiB free on the swap volume, strictly:
//	    TestComputeNodeConditionsCompressorHeadroom ("exactly 8Gi free ...")
//	A12 the monitor cadence, 10 s calm, 1 s past half-way, back after three calm:
//	    TestPressureMonitorSharesMemoryPressurePredicate ("cadence: ...")
//	B1  the kubelet's rankMemoryPressure order and the QoS mix:
//	    TestEvictionRanksBestEffortFirst ("upstream helpers_test.go cases,
//	    transcribed", "QoS classes at mixed priorities, full order")
//	B2  a pod without stats ranks first:
//	    TestEvictionRanksBestEffortFirst ("missing stats rank before any pod ...")
//	C1  no victim and no stats fetch without pressure:
//	    TestEvictionRanksBestEffortFirst ("no victim, and no stats fetch, ...")
//	C2  no second eviction while the signal moves toward release:
//	    TestEvictionKillsVictimAndSetsEvictedReason ("hysteresis: ...")
//	D1  one victim per cycle, the top-ranked one, by pod id, no preStop:
//	    TestEvictionKillsVictimAndSetsEvictedReason ("evicts the top-ranked pod: ...")
//	E1  the IsCriticalPod predicate and its fall-through in pickVictim:
//	    TestEvictionRanksBestEffortFirst ("IsCriticalPod boundary, ...")
//	G1  three evictions in five minutes halt the episode; a new episode resumes:
//	    TestEvictionKillsVictimAndSetsEvictedReason ("cascade cap: ...")
//	G3  a failed teardown is rolled back and not counted:
//	    TestEvictionKillsVictimAndSetsEvictedReason ("a failed runtime teardown ...")
//	H0  a stale snapshot never starts an eviction:
//	    TestEvictionKillsVictimAndSetsEvictedReason ("a stale sample never ...")
//	I1  the Evicted tuple on every status path, the apiserver and the Events:
//	    TestEvictionKillsVictimAndSetsEvictedReason ("every status path, ...")
//	I3  the evicted status write retried past a transient apiserver error:
//	    TestEvictionKillsVictimAndSetsEvictedReason ("the evicted status write ...")
//
// NO ROW FOR THE CALM STALE BOUND. The stale bound is staleSampleFactor times
// the monitor's interval, so on paper it is 3 s fast and 30 s calm. The calm
// bound cannot be reached: the manager only reaches the stale check with a
// pressured snapshot, the sample that stored a pressured snapshot set the
// monitor fast, and only a successful calm sample sets it calm again, which
// replaces the snapshot. A failed sample changes neither. So every stale check
// runs against the 1 s interval, and H1 pins the only bound that is live.
func TestTier2EvictionCharacterization(t *testing.T) {
	const (
		gi = int64(1) << 30
		mi = int64(1) << 20
	)
	ctx := context.Background()
	nodeLow := "The node was low on resource: memory. "
	hog := func() evictionCandidate { return cand(evPod("hog", nil, "", ""), "1Gi") }
	hogSentence := "Container c0 was using 1Gi, request is 0, has larger consumption of memory. "

	rows := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"A1 memory.available trips strictly below 100Mi, named in the notice", func(t *testing.T) {
			r := newTier2Rig(hog())
			r.step(availableAt(100 * mi))
			if n := r.notices(); len(n) != 0 {
				t.Fatalf("exactly 100Mi available evicted %v; the trip is strict (<)", n)
			}
			r.step(availableAt(100*mi - 1))
			n := r.notices()
			if len(n) != 1 || n[0].signal != signalMemoryAvailable {
				t.Fatalf("notices below 100Mi = %+v, want one memory.available eviction", n)
			}
			want := nodeLow + "Threshold quantity: 100Mi, available: 99Mi. " + hogSentence
			if n[0].message != want {
				t.Errorf("message = %q\nwant      %q", n[0].message, want)
			}
		}},

		{"A2 memory.available holds below 200Mi, releases at 200Mi, and the episode resets", func(t *testing.T) {
			r := newTier2Rig(hog())
			seq := []int64{99 * mi, 150 * mi, 200*mi - 1, 200 * mi, 150 * mi, 99 * mi}
			wantPressured := []bool{true, true, true, false, false, true}
			wantEvictions := []int{1, 1, 1, 1, 1, 2}
			for i, avail := range seq {
				r.step(availableAt(avail))
				if got := r.pressured(); got != wantPressured[i] {
					t.Errorf("sample %d (%dMi): pressured = %v, want %v", i, avail>>20, got, wantPressured[i])
				}
				if got := len(r.notices()); got != wantEvictions[i] {
					t.Errorf("sample %d (%dMi): evictions = %d, want %d", i, avail>>20, got, wantEvictions[i])
				}
			}
			if n := countPrefix(tier2Events(r.rec), "Warning EvictionThresholdMet Attempting to reclaim memory"); n != 2 {
				t.Errorf("EvictionThresholdMet Events across two episodes = %d, want 2 (one per episode)", n)
			}
		}},

		{"A3 compressor segments trip the manager at 80%", func(t *testing.T) {
			r := newTier2Rig(hog())
			r.step(segmentsAt(79))
			if n := r.notices(); len(n) != 0 {
				t.Fatalf("segments at 79%% evicted %v", n)
			}
			r.step(segmentsAt(80))
			n := r.notices()
			if len(n) != 1 || n[0].signal != signalCompressor {
				t.Fatalf("notices at 80%% segments = %+v, want one compressor eviction", n)
			}
			want := nodeLow + "Threshold quantity: compressor 80% of limit, available: compressor 80% of limit. " + hogSentence
			if n[0].message != want {
				t.Errorf("message = %q\nwant      %q", n[0].message, want)
			}
		}},

		{"A4 the compressor percentage rounds down before the 80% trip", func(t *testing.T) {
			for _, tc := range []struct {
				pages, limit int64
				want         bool
			}{
				{799, 1000, false}, // 79.9% reads as 79
				{800, 1000, true},
				{800, 1001, false}, // 79.92% reads as 79
				{801, 1001, true},  // 80.02% reads as 80
			} {
				s := compressorAt(0)
				s.CompressorPages, s.CompressorPagesLimit = tc.pages, tc.limit
				r := newTier2Rig(hog())
				r.step(s)
				if got := len(r.notices()) == 1; got != tc.want {
					t.Errorf("pages %d of %d: evicted = %v, want %v", tc.pages, tc.limit, got, tc.want)
				}
			}
		}},

		{"A6 the swap arm cannot fire on the first sample", func(t *testing.T) {
			r := newTier2Rig(hog())
			r.step(swapAt(3*gi, 1*gi))
			if r.pressured() || len(r.notices()) != 0 {
				t.Fatalf("first sample: pressured=%v notices=%v; with no previous reading swap cannot be rising", r.pressured(), r.notices())
			}
			r.step(swapAt(4*gi, 1*gi))
			if n := r.notices(); len(n) != 1 || n[0].signal != signalSwap {
				t.Errorf("second, rising sample: notices = %+v, want one swap eviction", n)
			}
		}},

		{"A7 swap trips at exactly 1Gi used, and rising is strict", func(t *testing.T) {
			for _, tc := range []struct {
				name         string
				first, then  int64
				wantEviction bool
			}{
				{"exactly 1Gi used and rising", 0, 1 * gi, true},
				{"1Gi minus one byte used and rising", 0, 1*gi - 1, false},
				{"2Gi used, flat", 2 * gi, 2 * gi, false},
				{"2Gi used, up one byte", 2 * gi, 2*gi + 1, true},
			} {
				r := newTier2Rig(hog())
				r.step(swapAt(tc.first, 7*gi))
				r.step(swapAt(tc.then, 7*gi))
				n := r.notices()
				if got := len(n) == 1 && n[0].signal == signalSwap; got != tc.wantEviction {
					t.Errorf("%s: swap eviction = %v (notices %+v), want %v", tc.name, got, n, tc.wantEviction)
				}
			}
		}},

		{"A9 arm priority: memory.available, then compressor, then swap", func(t *testing.T) {
			at := func(avail, compPct, swapUsed int64) hostStats {
				s := compressorAt(compPct)
				s.MemAvailableBytes = avail
				s.SwapUsedBytes = swapUsed
				s.SwapVolumeAvailableBytes = 1 * gi
				return s
			}
			for _, tc := range []struct {
				name string
				trip hostStats
				want pressureSignal
			}{
				{"all three arms raised", at(50*mi, 90, 3*gi), signalMemoryAvailable},
				{"compressor and swap raised", at(8*gi, 90, 3*gi), signalCompressor},
				{"swap alone raised", at(8*gi, 0, 3*gi), signalSwap},
			} {
				r := newTier2Rig(hog())
				r.step(at(8*gi, 0, 2*gi)) // calm prime: gives the swap arm its previous reading
				r.step(tc.trip)
				if n := r.notices(); len(n) != 1 || n[0].signal != tc.want {
					t.Errorf("%s: notices = %+v, want one eviction named %q", tc.name, n, tc.want)
				}
			}
		}},

		{"A10 a pressured first sample evicts in the same cycle, with no hold", func(t *testing.T) {
			r := newTier2Rig(hog())
			r.step(compressorAt(85))
			_, seq, _ := r.mon.latest()
			if n := r.notices(); seq != 1 || len(n) != 1 {
				t.Errorf("after the first sample (seq %d): evictions = %d, want 1", seq, len(n))
			}
		}},

		{"A11 the eviction message names the firing arm's threshold and reading", func(t *testing.T) {
			noStats := cand(evPod("nostats", nil, "", ""), "")
			for _, tc := range []struct {
				name string
				seq  []hostStats
				want string
			}{
				{"memory.available", []hostStats{availableAt(50 * mi)},
					nodeLow + "Threshold quantity: 100Mi, available: 50Mi. "},
				{"compressor", []hostStats{compressorAt(85)},
					nodeLow + "Threshold quantity: compressor 80% of limit, available: compressor 85% of limit. "},
				{"swap", []hostStats{swapAt(2*gi, 6*gi), swapAt(3*gi, 6*gi)},
					nodeLow + "Threshold quantity: 8.0Gi free on the swap volume, available: swap growing, 6.0Gi free on the swap volume. "},
			} {
				r := newTier2Rig(noStats)
				for _, s := range tc.seq {
					r.step(s)
				}
				n := r.notices()
				if len(n) != 1 || n[0].message != tc.want {
					t.Errorf("%s: notices = %+v\nwant message %q", tc.name, n, tc.want)
				}
			}
		}},

		{"C3 the post-eviction wait for a fresh sample ends at 30s", func(t *testing.T) {
			r := newTier2Rig(hog())
			r.step(compressorAt(85))
			if len(r.notices()) != 1 || !r.m.awaiting {
				t.Fatalf("fixture: evictions=%d awaiting=%v, want 1/true", len(r.notices()), r.m.awaiting)
			}
			// No fresh sample lands. Just under the bound the manager still waits.
			r.clk.advance(30*time.Second - time.Nanosecond)
			r.m.cycle(ctx)
			if !r.m.awaiting || r.m.hasBaseline {
				t.Errorf("at 30s-1ns: awaiting=%v hasBaseline=%v, want still waiting", r.m.awaiting, r.m.hasBaseline)
			}
			// At the bound it proceeds: the look it takes becomes the baseline.
			r.clk.advance(time.Nanosecond)
			r.m.cycle(ctx)
			if r.m.awaiting || !r.m.hasBaseline {
				t.Errorf("at 30s: awaiting=%v hasBaseline=%v, want the wait over and a baseline taken", r.m.awaiting, r.m.hasBaseline)
			}
			if n := len(r.notices()); n != 1 {
				t.Errorf("evictions = %d, want 1 (the wait itself evicts nothing)", n)
			}
		}},

		{"C4 a changed firing signal counts as not improved", func(t *testing.T) {
			run := func(after hostStats) int {
				r := newTier2Rig(hog())
				r.step(compressorAt(85)) // eviction 1
				r.step(compressorAt(85)) // the fresh sample: baseline compressor 85%
				r.step(after)
				return len(r.notices())
			}
			// Control: the compressor falls (still held above 70%): improved, no eviction.
			if n := run(compressorAt(72)); n != 1 {
				t.Fatalf("control: compressor falling to 72%% gave %d evictions, want 1", n)
			}
			// The compressor falls just as far, but memory.available now fires.
			s := compressorAt(72)
			s.MemAvailableBytes = 99 * mi
			if n := run(s); n != 2 {
				t.Errorf("firing signal changed to memory.available: %d evictions, want 2 (not comparable, so not improved)", n)
			}
		}},

		{"D2 a real cycle evicts in rankMemoryPressure order, one pod per eviction", func(t *testing.T) {
			h, _ := newTier2Harness(t)
			// over-low and over-high exceed their zero request; under sits inside
			// its own. Exceed, then ascending priority, then usage over request.
			h.add(evPod("under", prio(0), "4Gi", "4Gi"), "1Gi")
			h.add(evPod("over-high", prio(100), "", ""), "2Gi")
			h.add(evPod("over-low", prio(10), "", ""), "1Gi")
			for range 5 { // evict, baseline, evict, baseline, evict
				h.step(compressorAt(90))
			}
			want := []string{"uid-over-low", "uid-over-high", "uid-under"}
			if got := h.deleteIDs(); !slices.Equal(got, want) {
				t.Errorf("DeletePod order = %v, want %v", got, want)
			}
		}},

		{"D3 the band annotation has no effect on the victim", func(t *testing.T) {
			batch := func(c evictionCandidate) evictionCandidate {
				c.pod.Annotations = map[string]string{"budget.k3sm.io/band": "batch"}
				return c
			}
			for _, tc := range []struct {
				name  string
				cands []evictionCandidate
			}{
				{"a batch pod ranked second is not promoted",
					[]evictionCandidate{batch(cand(evPod("batch", prio(0), "", ""), "1Gi")), cand(evPod("top", prio(0), "", ""), "2Gi")}},
				{"a batch-annotated top pod is not protected either",
					[]evictionCandidate{cand(evPod("second", prio(0), "", ""), "1Gi"), batch(cand(evPod("top", prio(0), "", ""), "2Gi"))}},
			} {
				r := newTier2Rig(tc.cands...)
				r.step(compressorAt(85))
				if got := r.target.evicted; !slices.Equal(got, []string{"top"}) {
					t.Errorf("%s: evicted = %v, want [top]", tc.name, got)
				}
			}
		}},

		{"E2 a critical pod is skipped in a real cycle, logged once per episode", func(t *testing.T) {
			h, _ := newTier2Harness(t)
			logs := &tier2Logs{}
			h.m.log = slog.New(logs)
			// Literal priorities: 2000000000 is system-critical; 1000000000 is not.
			h.add(evPod("critical", prio(2000000000), "", ""), "8Gi")
			h.add(evPod("high", prio(1000000000), "", ""), "1Gi")
			for range 8 {
				h.step(compressorAt(90))
			}
			if got := h.deleteIDs(); !slices.Equal(got, []string{"uid-high"}) {
				t.Fatalf("DeletePod ids = %v, want only the 1000000000 pod; the critical pod is never evicted", got)
			}
			const skipMsg = "eviction manager: cannot evict a critical pod; skipping it"
			const noneMsg = "eviction manager: memory threshold met but no pod is eligible for eviction"
			if n, m := logs.count(skipMsg), logs.count(noneMsg); n != 1 || m != 1 {
				t.Errorf("in one episode: skip warnings = %d, no-eligible warnings = %d, want 1/1", n, m)
			}
			// A new episode warns again; still nothing is evicted.
			h.step(compressorAt(10))
			for range 3 {
				h.step(compressorAt(90))
			}
			if n := logs.count(skipMsg); n != 2 {
				t.Errorf("skip warnings after a second episode = %d, want 2 (once per episode)", n)
			}
			if got := h.deleteIDs(); len(got) != 1 {
				t.Errorf("a node holding only a critical pod evicted %v", got)
			}
		}},

		{"F1 every eviction asks runtimed for grace 0", func(t *testing.T) {
			h, _ := newTier2Harness(t)
			for _, n := range []string{"p1", "p2", "p3"} {
				h.add(evPod(n, nil, "", ""), "1Gi")
			}
			for range 5 {
				h.step(compressorAt(90))
			}
			h.f.mu.Lock()
			graces := slices.Clone(h.f.graces)
			h.f.mu.Unlock()
			if !slices.Equal(graces, []int64{0, 0, 0}) {
				t.Errorf("DeletePod graces = %v, want [0 0 0]", graces)
			}
		}},

		{"G2 an eviction ages out of the five-minute cascade window", func(t *testing.T) {
			// Evictions at t0, t0+1m and t0+2m (each followed by its baseline
			// sample), then one more look at t0+5m minus delta.
			run := func(last time.Duration) *tier2Rig {
				r := newTier2Rig(hog())
				for _, at := range []time.Duration{0, time.Minute, 2 * time.Minute} {
					r.clk.setOffset(at)
					r.step(compressorAt(90)) // eviction
					r.step(compressorAt(90)) // baseline
				}
				r.clk.setOffset(last)
				r.step(compressorAt(90))
				return r
			}
			// Control: just inside the window three evictions count; the episode halts.
			r := run(5*time.Minute - time.Nanosecond)
			if n := len(r.notices()); n != 3 || !r.m.halted {
				t.Fatalf("at t0+5m-1ns: evictions = %d halted = %v, want 3/true", n, r.m.halted)
			}
			if n := countPrefix(tier2Events(r.rec), "Warning EvictionCascadeHalted"); n != 1 {
				t.Errorf("control: EvictionCascadeHalted Events = %d, want 1", n)
			}
			// At t0+5m the first eviction has left the window: a fourth is allowed.
			r = run(5 * time.Minute)
			if n := len(r.notices()); n != 4 || r.m.halted {
				t.Errorf("at t0+5m: evictions = %d halted = %v, want 4/false", n, r.m.halted)
			}
			if n := countPrefix(tier2Events(r.rec), "Warning EvictionCascadeHalted"); n != 0 {
				t.Errorf("EvictionCascadeHalted Events = %d, want 0", n)
			}
		}},

		{"H1 the fast stale bound is exactly 3s", func(t *testing.T) {
			run := func(age time.Duration) int {
				r := newTier2Rig(hog())
				r.sm.set(compressorAt(85))
				r.mon.sampleOnce() // a pressured sample: the monitor runs fast (1s)
				r.clk.advance(age)
				r.m.cycle(ctx)
				return len(r.notices())
			}
			if n := run(3 * time.Second); n != 1 {
				t.Errorf("a 3s-old sample: evictions = %d, want 1 (the bound is inclusive)", n)
			}
			if n := run(3*time.Second + time.Nanosecond); n != 0 {
				t.Errorf("a 3s+1ns-old sample: evictions = %d, want 0 (stale)", n)
			}
		}},

		{"I2 evictedPodStatus terminates init containers and clears PodReadyToStartContainers", func(t *testing.T) {
			started := metav1.NewTime(time.Unix(1000, 0))
			now := metav1.NewTime(time.Unix(2000, 0))
			prior := corev1.PodStatus{
				Phase: corev1.PodRunning,
				InitContainerStatuses: []corev1.ContainerStatus{
					{Name: "done-init", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"}}},
					{Name: "sidecar", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: started}}},
				},
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "main", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: started}}},
				},
				Conditions: []corev1.PodCondition{
					{Type: corev1.PodReadyToStartContainers, Status: corev1.ConditionTrue, LastTransitionTime: started},
				},
			}
			st := evictedPodStatus(prior, "evicted", now)
			for _, cs := range append(slices.Clone(st.ContainerStatuses), st.InitContainerStatuses[1]) {
				term := cs.State.Terminated
				if term == nil || term.ExitCode != 137 || term.Reason != "Error" || !term.StartedAt.Equal(&started) || !term.FinishedAt.Equal(&now) {
					t.Errorf("%s: state = %+v, want terminated 137/Error from %v to %v", cs.Name, cs.State, started, now)
				}
				if cs.Ready || cs.Started == nil || *cs.Started {
					t.Errorf("%s: ready=%v started=%v, want false/false", cs.Name, cs.Ready, cs.Started)
				}
			}
			if term := st.InitContainerStatuses[0].State.Terminated; term == nil || term.ExitCode != 0 || term.Reason != "Completed" {
				t.Errorf("an init container that had already completed was rewritten: %+v", st.InitContainerStatuses[0].State)
			}
			c := findPodCondition(st.Conditions, corev1.PodReadyToStartContainers)
			if c == nil || c.Status != corev1.ConditionFalse || !c.LastTransitionTime.Equal(&now) {
				t.Errorf("PodReadyToStartContainers = %+v, want False at %v", c, now)
			}
			// A condition already False keeps its transition time.
			prior.Conditions[0].Status = corev1.ConditionFalse
			st = evictedPodStatus(prior, "evicted", now)
			if c := findPodCondition(st.Conditions, corev1.PodReadyToStartContainers); c == nil || !c.LastTransitionTime.Equal(&started) {
				t.Errorf("an already-False PodReadyToStartContainers = %+v, want its transition time %v kept", c, started)
			}
		}},

		{"I4 the evicted status is not written over a pod replaced under the same name", func(t *testing.T) {
			h, _ := newTier2Harness(t)
			pod := evPod("hog", nil, "", "")
			h.add(pod, "2Gi")
			// The apiserver object is replaced: same name, new UID.
			if err := h.cs.CoreV1().Pods("default").Delete(ctx, "hog", metav1.DeleteOptions{}); err != nil {
				t.Fatalf("delete: %v", err)
			}
			repl := evPod("hog", nil, "", "")
			repl.UID = types.UID("uid-replacement")
			if _, err := h.cs.CoreV1().Pods("default").Create(ctx, repl, metav1.CreateOptions{}); err != nil {
				t.Fatalf("create replacement: %v", err)
			}
			h.step(compressorAt(85))
			if got := h.deleteIDs(); !slices.Equal(got, []string{"uid-hog"}) {
				t.Fatalf("DeletePod ids = %v, want the tracked pod's", got)
			}
			live, err := h.cs.CoreV1().Pods("default").Get(ctx, "hog", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if live.UID != "uid-replacement" || live.Status.Phase == corev1.PodFailed || live.Status.Reason == reasonEvicted {
				t.Errorf("the replacement pod (uid %s) got %s/%q, want its own status untouched", live.UID, live.Status.Phase, live.Status.Reason)
			}
			// Control: the provider still reports the eviction for the pod it tracked.
			st, err := h.r.GetPodStatus(ctx, "default", "hog")
			if err != nil || st.Reason != reasonEvicted {
				t.Errorf("provider status = %+v, %v; want the evicted pod reported Evicted", st, err)
			}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, row.run)
	}
}

// tier2Clock is the one fake clock the rows wire to BOTH the eviction manager
// and the pressure monitor, so the sample age, the cleanup wait and the cascade
// window all read the same time.
type tier2Clock struct {
	mu   sync.Mutex
	base time.Time
	t    time.Time
}

func newTier2Clock() *tier2Clock {
	t0 := time.Unix(300000, 0)
	return &tier2Clock{base: t0, t: t0}
}

func (c *tier2Clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *tier2Clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// setOffset sets the clock to t0 + d.
func (c *tier2Clock) setOffset(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.base.Add(d)
}

// tier2Rig is the manager over a settable host snapshot and a recording fake
// target, on the shared clock.
type tier2Rig struct {
	sm     *staticMonitor
	mon    *pressureMonitor
	target *fakeEvictionTarget
	rec    *record.FakeRecorder
	m      *evictionManager
	clk    *tier2Clock
}

func newTier2Rig(cands ...evictionCandidate) *tier2Rig {
	clk := newTier2Clock()
	sm := &staticMonitor{s: compressorAt(10)}
	mon := sm.monitor()
	mon.now = clk.now
	target := &fakeEvictionTarget{cands: cands}
	rec := record.NewFakeRecorder(100)
	m := newEvictionManager(mon, target, rec, "mac-0", discardLog())
	m.now = clk.now
	return &tier2Rig{sm: sm, mon: mon, target: target, rec: rec, m: m, clk: clk}
}

// step installs s, takes one monitor sample, and runs one manager cycle.
func (r *tier2Rig) step(s hostStats) {
	r.sm.set(s)
	r.mon.sampleOnce()
	r.m.cycle(context.Background())
}

func (r *tier2Rig) notices() []evictionNotice {
	r.target.mu.Lock()
	defer r.target.mu.Unlock()
	return slices.Clone(r.target.notices)
}

// pressured is the verdict over the monitor's latest snapshot.
func (r *tier2Rig) pressured() bool {
	s, _, ok := r.mon.latest()
	if !ok {
		return false
	}
	p, _ := memoryPressured(s)
	return p
}

// newTier2Harness is the runtimed eviction harness with the shared clock wired
// to the manager and the monitor.
func newTier2Harness(t *testing.T) (*evictionHarness, *tier2Clock) {
	t.Helper()
	h := newEvictionHarness(t)
	clk := newTier2Clock()
	h.m.now = clk.now
	h.mon.now = clk.now
	return h, clk
}

// tier2Events empties a fake recorder.
func tier2Events(rec *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// tier2Logs is a slog handler that records each message, so a row can count
// the manager's once-per-episode warnings.
type tier2Logs struct {
	mu   sync.Mutex
	msgs []string
}

func (l *tier2Logs) Enabled(context.Context, slog.Level) bool { return true }

func (l *tier2Logs) Handle(_ context.Context, rec slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, rec.Message)
	return nil
}

func (l *tier2Logs) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *tier2Logs) WithGroup(string) slog.Handler      { return l }

func (l *tier2Logs) count(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, m := range l.msgs {
		if m == msg {
			n++
		}
	}
	return n
}
