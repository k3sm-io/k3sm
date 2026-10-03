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
	"bufio"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// evPod builds a pod for the ranking tables: priority (nil when prio is nil),
// one container "c0" with the given memory request and limit ("" for none).
func evPod(name string, prio *int32, request, limit string) *corev1.Pod {
	c := corev1.Container{Name: "c0", Image: "registry/" + name + ":latest", Command: []string{"/" + name}}
	if request != "" {
		c.Resources.Requests = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(request)}
	}
	if limit != "" {
		c.Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(limit)}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec:       corev1.PodSpec{Priority: prio, Containers: []corev1.Container{c}},
	}
}

func prio(p int32) *int32 { return &p }

func mib(n int64) int64 { return n << 20 }

// evictionsTotal reads the manager's evictions_total counter for sig.
func evictionsTotal(m *evictionManager, sig pressureSignal) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evictions[sig]
}

// discardLog keeps the gates' expected Warn/Error lines out of the test output.
func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

func quantityBytes(s string) int64 {
	q := resource.MustParse(s)
	return q.Value()
}

// cand is an evictionCandidate with usage parsed from a quantity ("" = no stats).
func cand(pod *corev1.Pod, usage string) evictionCandidate {
	if usage == "" {
		return evictionCandidate{pod: pod}
	}
	q := resource.MustParse(usage)
	return evictionCandidate{pod: pod, usage: q.Value(), hasStats: true, containerUsage: map[string]int64{"c0": q.Value()}}
}

func names(cs []evictionCandidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.pod.Name)
	}
	return out
}

// upstreamRankCase is one transcribed helpers_test.go case.
type upstreamRankCase struct {
	name  string
	cmps  []string
	pods  map[string]evictionCandidate
	input []string
	want  []string
}

// loadUpstreamRankCases parses testdata/eviction/rank-memory-upstream.txt.
func loadUpstreamRankCases(t *testing.T) []upstreamRankCase {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "eviction", "rank-memory-upstream.txt"))
	if err != nil {
		t.Fatalf("open upstream ranking fixture: %v", err)
	}
	defer f.Close()
	var (
		out []upstreamRankCase
		cur *upstreamRankCase
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "case":
			cur = &upstreamRankCase{name: fields[1], cmps: strings.Split(fields[2], ","), pods: map[string]evictionCandidate{}}
		case "pod":
			p, err := strconv.ParseInt(fields[2], 10, 32)
			if err != nil {
				t.Fatalf("fixture priority %q: %v", fields[2], err)
			}
			req := fields[3]
			if req == "-" {
				req = ""
			}
			usage := fields[4]
			if usage == "nostats" {
				usage = ""
			}
			pod := evPod(fields[1], prio(int32(p)), req, "")
			cur.pods[fields[1]] = cand(pod, usage)
		case "input":
			cur.input = fields[1:]
		case "want":
			cur.want = fields[1:]
		case "end":
			out = append(out, *cur)
			cur = nil
		default:
			t.Fatalf("fixture line %q: unknown directive", line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read upstream ranking fixture: %v", err)
	}
	return out
}

// sortBy applies the named upstream comparators, in order, the way upstream's
// orderedBy(...).Sort does, so a single-comparator upstream case is checked
// against that comparator alone.
func sortBy(cands []evictionCandidate, cmpNames []string) {
	byName := map[string]func(a, b *evictionCandidate) int{
		"exceed":   cmpExceedMemoryRequests,
		"priority": cmpPriority,
		"memory":   cmpMemory,
	}
	if slices.Equal(cmpNames, []string{"exceed", "priority", "memory"}) {
		rankMemoryPressure(cands) // the production entry point, not a re-implementation
		return
	}
	cmps := make([]func(a, b *evictionCandidate) int, 0, len(cmpNames))
	for _, n := range cmpNames {
		cmps = append(cmps, byName[n])
	}
	slices.SortStableFunc(cands, func(a, b evictionCandidate) int {
		for _, c := range cmps {
			if r := c(&a, &b); r != 0 {
				return r
			}
		}
		return 0
	})
}

// fakeEvictionTarget records what the manager asks of the runtime.
type fakeEvictionTarget struct {
	mu         sync.Mutex
	cands      []evictionCandidate
	candCalls  int
	evicted    []string
	candidates func() []evictionCandidate
}

func (f *fakeEvictionTarget) evictionCandidates(context.Context) []evictionCandidate {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.candCalls++
	if f.candidates != nil {
		return f.candidates()
	}
	return slices.Clone(f.cands)
}

func (f *fakeEvictionTarget) evictPod(_ context.Context, pod *corev1.Pod, _ evictionNotice) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evicted = append(f.evicted, pod.Name)
	return nil
}

// staticMonitor is a pressure monitor over a settable snapshot.
type staticMonitor struct {
	mu sync.Mutex
	s  hostStats
}

func (sm *staticMonitor) set(s hostStats) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.s = s
}

func (sm *staticMonitor) monitor() *pressureMonitor {
	return newPressureMonitor(func() (hostStats, error) {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		return sm.s, nil
	}, discardLog())
}

// compressorAt returns healthy stats with the compressor pages at pct% of limit.
func compressorAt(pct int64) hostStats {
	s := healthyStats()
	s.CompressorPagesLimit = 1000
	s.CompressorPages = pct * 10
	s.CompressorSegmentsLimit = 1000
	s.CompressorSegments = 10
	s.SwapVolumeCapacityBytes = 500 << 30
	s.SwapVolumeAvailableBytes = 100 << 30
	return s
}

// TestEvictionRanksBestEffortFirst is the ranking gate: the kubelet's
// rankMemoryPressure order (exceeds-requests, then ascending priority, then
// descending usage over requests), BestEffort first as the consequence of zero
// requests, upstream's missing-stats branches, IsCriticalPod at its boundary
// with fall-through to the next candidate, and no victim without pressure.
func TestEvictionRanksBestEffortFirst(t *testing.T) {
	t.Run("upstream helpers_test.go cases, transcribed", func(t *testing.T) {
		cases := loadUpstreamRankCases(t)
		// The fixture is the evidence that the port is the kubelet's order. A
		// fixture that lost cases would make this subtest pass vacuously.
		if len(cases) < 4 {
			t.Fatalf("fixture holds %d upstream cases, want at least 4", len(cases))
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				in := make([]evictionCandidate, 0, len(tc.input))
				for _, n := range tc.input {
					c, ok := tc.pods[n]
					if !ok {
						t.Fatalf("input names unknown pod %q", n)
					}
					in = append(in, c)
				}
				sortBy(in, tc.cmps)
				if got := names(in); !slices.Equal(got, tc.want) {
					t.Errorf("order = %v\nwant    %v", got, tc.want)
				}
			})
		}
	})

	t.Run("QoS classes at mixed priorities, full order", func(t *testing.T) {
		be := cand(evPod("besteffort", nil, "", ""), "300Mi")                     // 300Mi over a zero request
		beHigh := cand(evPod("besteffort-high", prio(1000), "", ""), "800Mi")     // exceeds, but higher priority
		burstOver := cand(evPod("burstable-over", prio(0), "100Mi", ""), "450Mi") // 350Mi over
		burstUnder := cand(evPod("burstable-under", nil, "1Gi", "2Gi"), "500Mi")  // 524Mi under
		guaranteed := cand(evPod("guaranteed", prio(0), "1Gi", "1Gi"), "900Mi")   // 124Mi under
		in := []evictionCandidate{guaranteed, burstUnder, beHigh, be, burstOver}
		rankMemoryPressure(in)
		want := []string{"burstable-over", "besteffort", "besteffort-high", "guaranteed", "burstable-under"}
		if got := names(in); !slices.Equal(got, want) {
			t.Errorf("order = %v\nwant    %v", got, want)
		}
	})

	t.Run("BestEffort ranks first through its zero request, not a rule of its own", func(t *testing.T) {
		// A tiny BestEffort pod exceeds its zero request; a huge Guaranteed pod
		// within its request does not. The comparator, not QoS, puts BE first.
		be := cand(evPod("tiny-besteffort", nil, "", ""), "1Mi")
		g := cand(evPod("huge-guaranteed", nil, "8Gi", "8Gi"), "7Gi")
		in := []evictionCandidate{g, be}
		rankMemoryPressure(in)
		if in[0].pod.Name != "tiny-besteffort" {
			t.Errorf("order = %v, want the BestEffort pod first", names(in))
		}
		if podMemoryRequestBytes(be.pod) != 0 {
			t.Errorf("BestEffort effective request = %d, want 0", podMemoryRequestBytes(be.pod))
		}
	})

	t.Run("missing stats rank before any pod with stats, in both stats comparators", func(t *testing.T) {
		// Upstream's exceedMemoryRequests and memory both return
		// cmpBool(!p1Found, !p2Found): a pod with no stats sorts first, even
		// ahead of a higher-usage BestEffort pod and regardless of priority.
		noStatsHigh := cand(evPod("nostats-high-priority", prio(1000), "1Gi", "1Gi"), "")
		be := cand(evPod("besteffort", prio(-5), "", ""), "4Gi")
		in := []evictionCandidate{be, noStatsHigh}
		rankMemoryPressure(in)
		if got, want := names(in), []string{"nostats-high-priority", "besteffort"}; !slices.Equal(got, want) {
			t.Errorf("order = %v, want %v", got, want)
		}
		a, b := noStatsHigh, be
		if cmpExceedMemoryRequests(&a, &b) != -1 || cmpMemory(&a, &b) != -1 {
			t.Error("a pod with no stats must compare first in exceedMemoryRequests and memory")
		}
		c := cand(evPod("nostats-2", nil, "", ""), "")
		if cmpExceedMemoryRequests(&a, &c) != 0 || cmpMemory(&a, &c) != 0 {
			t.Error("two pods with no stats compare equal in both stats comparators")
		}
	})

	t.Run("effective request: init max, sidecars, overhead", func(t *testing.T) {
		always := corev1.ContainerRestartPolicyAlways
		mem := func(q string) corev1.ResourceRequirements {
			return corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(q)}}
		}
		pod := evPod("init", nil, "100Mi", "")
		pod.Spec.InitContainers = []corev1.Container{
			{Name: "sidecar", Resources: mem("50Mi"), RestartPolicy: &always},
			{Name: "big-init", Resources: mem("500Mi")},
		}
		// max(100 + 50 sidecar, 500 + 50 sidecar before it) = 550Mi.
		if got, want := podMemoryRequestBytes(pod), mib(550); got != want {
			t.Errorf("init-max request = %d, want %d", got, want)
		}
		pod.Spec.Overhead = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("10Mi")}
		if got, want := podMemoryRequestBytes(pod), mib(560); got != want {
			t.Errorf("request with overhead = %d, want %d", got, want)
		}
		be := evPod("be-overhead", nil, "", "")
		be.Spec.Overhead = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("10Mi")}
		if got := podMemoryRequestBytes(be); got != 0 {
			t.Errorf("overhead on a zero request = %d, want 0 (upstream adds overhead only to a non-zero total)", got)
		}
	})

	t.Run("IsCriticalPod boundary, and a skip falls through to the next candidate", func(t *testing.T) {
		critical := cand(evPod("system-critical", prio(systemCriticalPriority), "", ""), "8Gi")
		justBelow := cand(evPod("just-below-critical", prio(systemCriticalPriority-1), "", ""), "8Gi")
		if !isCriticalPod(critical.pod) || isCriticalPod(justBelow.pod) {
			t.Fatalf("isCriticalPod(2000000000)=%v isCriticalPod(1999999999)=%v, want true/false",
				isCriticalPod(critical.pod), isCriticalPod(justBelow.pod))
		}
		mirror := evPod("mirror", nil, "", "")
		mirror.Annotations = map[string]string{configMirrorAnnotationKey: "x"}
		static := evPod("static", nil, "", "")
		static.Annotations = map[string]string{configSourceAnnotationKey: "file"}
		api := evPod("api-sourced", nil, "", "")
		api.Annotations = map[string]string{configSourceAnnotationKey: apiserverSource}
		if !isCriticalPod(mirror) || !isCriticalPod(static) || isCriticalPod(api) {
			t.Error("mirror and static pods are critical; an api-sourced pod is not")
		}

		// The critical pod ranks FIRST (no stats), and is skipped; the cycle's
		// victim is the next candidate, not "nobody".
		criticalNoStats := cand(evPod("critical-nostats", prio(systemCriticalPriority), "", ""), "")
		next := cand(evPod("ordinary", nil, "", ""), "1Gi")
		m := newEvictionManager(newPressureMonitor(nil, discardLog()), &fakeEvictionTarget{}, nil, "mac-0", discardLog())
		v, ok := m.pickVictim([]evictionCandidate{next, criticalNoStats})
		if !ok || v.pod.Name != "ordinary" {
			t.Errorf("victim = %v (ok=%v), want the next candidate after the skipped critical pod", v.pod, ok)
		}
		v, ok = m.pickVictim([]evictionCandidate{justBelow, critical})
		if !ok || v.pod.Name != "just-below-critical" {
			t.Errorf("victim = %v (ok=%v), want the 1999999999 pod (evictable)", v.pod, ok)
		}
		if _, ok := m.pickVictim([]evictionCandidate{critical}); ok {
			t.Error("a node holding only critical pods has no victim")
		}
	})

	t.Run("no victim, and no stats fetch, when memoryPressured is false", func(t *testing.T) {
		sm := &staticMonitor{s: compressorAt(79)} // one point below the trip
		mon := sm.monitor()
		target := &fakeEvictionTarget{cands: []evictionCandidate{cand(evPod("besteffort", nil, "", ""), "8Gi")}}
		m := newEvictionManager(mon, target, nil, "mac-0", discardLog())
		mon.sampleOnce()
		if p, _ := memoryPressured(mustLatest(t, mon)); p {
			t.Fatal("fixture: 79% must not be pressure")
		}
		m.cycle(context.Background())
		if target.candCalls != 0 || len(target.evicted) != 0 {
			t.Errorf("without pressure: candidate fetches=%d evictions=%v, want none", target.candCalls, target.evicted)
		}
		// Control: the same manager at the trip value does evict.
		sm.set(compressorAt(80))
		mon.sampleOnce()
		m.cycle(context.Background())
		if !slices.Equal(target.evicted, []string{"besteffort"}) {
			t.Errorf("at the trip value: evictions=%v, want [besteffort]", target.evicted)
		}
	})
}

func mustLatest(t *testing.T, m *pressureMonitor) hostStats {
	t.Helper()
	s, _, ok := m.latest()
	if !ok {
		t.Fatal("monitor holds no snapshot")
	}
	return s
}

// evictionHarness is a real runtimed provider over the strict fake runtime, a
// fake apiserver, a fake event recorder, a settable host snapshot, and the
// eviction manager wired to all of them.
type evictionHarness struct {
	t   *testing.T
	r   *runtimedRuntime
	f   *fakeRuntimeServer
	cs  *fake.Clientset
	rec *record.FakeRecorder
	sm  *staticMonitor
	mon *pressureMonitor
	m   *evictionManager
	now time.Time

	cbMu   sync.Mutex
	cbPods []*corev1.Pod
}

func newEvictionHarness(t *testing.T) *evictionHarness {
	t.Helper()
	r, f, _ := newRestartFake(t)
	f.strict = t
	h := &evictionHarness{t: t, r: r, f: f, cs: fake.NewClientset(), rec: record.NewFakeRecorder(200), sm: &staticMonitor{s: compressorAt(10)}}
	h.now = time.Unix(100000, 0)
	r.client = h.cs
	r.recorder = h.rec
	r.mu.Lock()
	r.notify = func(p *corev1.Pod) {
		h.cbMu.Lock()
		defer h.cbMu.Unlock()
		h.cbPods = append(h.cbPods, p)
	}
	r.mu.Unlock()
	h.mon = h.sm.monitor()
	h.m = newEvictionManager(h.mon, r, h.rec, "mac-0", discardLog())
	h.m.now = func() time.Time { return h.now }
	return h
}

// add creates pod in the fake apiserver and on the provider, with usage as its
// runtime footprint.
func (h *evictionHarness) add(pod *corev1.Pod, usage string) {
	h.t.Helper()
	if _, err := h.cs.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		h.t.Fatalf("apiserver create %s: %v", pod.Name, err)
	}
	if err := h.r.CreatePod(context.Background(), pod); err != nil {
		h.t.Fatalf("CreatePod %s: %v", pod.Name, err)
	}
	h.f.mu.Lock()
	h.f.footprint[string(pod.UID)] = uint64(quantityBytes(usage))
	h.f.mu.Unlock()
}

// step installs s, takes one monitor sample, and runs one manager cycle.
func (h *evictionHarness) step(s hostStats) {
	h.sm.set(s)
	h.mon.sampleOnce()
	h.m.cycle(context.Background())
}

func (h *evictionHarness) deleteIDs() []string {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	return slices.Clone(h.f.deleteIDs)
}

// events drains the fake recorder.
func (h *evictionHarness) events() []string {
	var out []string
	for {
		select {
		case e := <-h.rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func countPrefix(evs []string, prefix string) int {
	n := 0
	for _, e := range evs {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// assertEvictedTuple checks the full evicted status the kubelet's eviction
// manager produces.
func assertEvictedTuple(t *testing.T, where string, st corev1.PodStatus, wantMsgPrefix string) {
	t.Helper()
	if st.Phase != corev1.PodFailed || st.Reason != reasonEvicted {
		t.Errorf("%s: phase/reason = %s/%q, want Failed/Evicted", where, st.Phase, st.Reason)
	}
	if !strings.HasPrefix(st.Message, wantMsgPrefix) {
		t.Errorf("%s: message = %q\nwant prefix %q", where, st.Message, wantMsgPrefix)
	}
	if len(st.ContainerStatuses) == 0 {
		t.Fatalf("%s: no container statuses", where)
	}
	for _, cs := range st.ContainerStatuses {
		term := cs.State.Terminated
		if term == nil || term.ExitCode != 137 || term.Reason != "Error" {
			t.Errorf("%s: container %s state = %+v, want terminated 137/Error (never OOMKilled)", where, cs.Name, cs.State)
		}
		if cs.Ready {
			t.Errorf("%s: container %s Ready = true", where, cs.Name)
		}
	}
	for _, typ := range []corev1.PodConditionType{corev1.PodReady, corev1.ContainersReady} {
		c := findPodCondition(st.Conditions, typ)
		if c == nil || c.Status != corev1.ConditionFalse {
			t.Errorf("%s: %s = %+v, want False", where, typ, c)
		}
	}
	dt := findPodCondition(st.Conditions, corev1.DisruptionTarget)
	if dt == nil || dt.Status != corev1.ConditionTrue || dt.Reason != corev1.PodReasonTerminationByKubelet || dt.Message != st.Message {
		t.Errorf("%s: DisruptionTarget = %+v, want True/TerminationByKubelet carrying the eviction message", where, dt)
	}
}

// TestEvictionKillsVictimAndSetsEvictedReason is the termination gate: the
// manager evicts exactly the top-ranked pod through the runtime by pod id with
// grace 0 and no preStop, the restart engine stays still, every status path and
// the apiserver report the kubelet's Evicted tuple, the Events fire with their
// cadence, the hysteresis and cascade bounds hold, an evicted pod is never
// re-created, and the runtime never hears of a pod k3sm did not start.
//
// RECYCLED PGID. The provider never signals a pid: its only kill is runtimed's
// DeletePod keyed by pod id, which this test pins (deleteIDs is exactly the
// victim's id; the strict fake fails on any other id). runtimed's own teardown
// signals only containers it has not observed terminate (liveContainersLocked,
// runtimed pkg/runtime/pod.go), so a container the kernel already killed, whose
// pgid number could be recycled, is not signalled; that guard is runtimed's and
// is covered there, not re-implemented here.
func TestEvictionKillsVictimAndSetsEvictedReason(t *testing.T) {
	ctx := context.Background()
	compressorMsg := "The node was low on resource: memory. Threshold quantity: compressor 80% of limit, available: compressor 85% of limit. "

	t.Run("evicts the top-ranked pod: DeletePod once, grace 0, no preStop, restart engine still", func(t *testing.T) {
		h := newEvictionHarness(t)
		rt := &fakeRoundTripper{status: 200}
		h.r.probeTransport = rt
		hog := evPod("hog", nil, "", "")
		hog.Spec.RestartPolicy = corev1.RestartPolicyAlways
		hog.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}
		hog.Spec.Containers[0].Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/quit", Port: intstr.FromString("http")},
		}}
		hog.Status.PodIP = "10.0.0.5"
		quiet := evPod("quiet", nil, "1Gi", "1Gi")
		quiet.Spec.RestartPolicy = corev1.RestartPolicyAlways
		h.add(hog, "2Gi")
		h.add(quiet, "200Mi")

		h.step(compressorAt(10)) // calm: nothing happens
		if ids := h.deleteIDs(); len(ids) != 0 {
			t.Fatalf("calm sample evicted %v", ids)
		}
		h.step(compressorAt(85))
		if got, want := h.deleteIDs(), []string{"uid-hog"}; !slices.Equal(got, want) {
			t.Fatalf("DeletePod ids = %v, want %v", got, want)
		}
		h.f.mu.Lock()
		grace := h.f.lastGrace
		h.f.mu.Unlock()
		if grace != 0 {
			t.Errorf("eviction DeletePod grace = %d, want 0 (hard eviction)", grace)
		}
		if rt.gotURL != "" {
			t.Errorf("the preStop hook ran during a hard eviction (hit %q)", rt.gotURL)
		}
		if n := evictionsTotal(h.m, signalCompressor); n != 1 {
			t.Errorf("evictions_total{compressor} = %d, want 1", n)
		}

		// The restart engine does not move: the evicted pod's exit, delivered on
		// the status convergence, schedules nothing. Positive control on the
		// SAME harness: the same exit for the non-evicted pod arms a re-exec
		// (the path TestRestartTriggerIdempotent drives to a RestartContainer).
		clk := h.r.clk.(*testclock.FakeClock)
		exit := func(id string) *runtimev1.PodStatus {
			return &runtimev1.PodStatus{
				PodId: id, Phase: runtimev1.PodPhase_POD_PHASE_FAILED,
				ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 137, 0, time.Unix(6000, 0))},
			}
		}
		hogTrack := h.r.trackByID("uid-hog")
		h.r.buildStatus(hog.DeepCopy(), hogTrack, exit("uid-hog"), nil)
		// The re-exec timer is armed asynchronously, so "not armed" is held over
		// a settle window rather than read once.
		for deadline := time.Now().Add(100 * time.Millisecond); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if clk.HasWaiters() {
				t.Fatal("an evicted pod's exit armed a re-exec")
			}
		}
		h.f.mu.Lock()
		restarts, starts := h.f.restartCalls, h.f.startCalls
		h.f.mu.Unlock()
		if restarts != 0 || starts != 0 {
			t.Errorf("RestartContainer=%d StartContainer=%d after eviction, want 0/0", restarts, starts)
		}
		h.r.buildStatus(quiet.DeepCopy(), h.r.trackByID("uid-quiet"), exit("uid-quiet"), nil)
		// Positive control: the same delivery to a pod that was not evicted arms
		// the re-exec (fails the test if it never does).
		waitWaiters(t, clk, 1)

		// Positive control for the preStop observable: the same transport IS hit
		// by an ordinary preStop.
		probe := hog.DeepCopy()
		grace30 := int64(30)
		probe.Spec.TerminationGracePeriodSeconds = &grace30
		h.r.runPreStop(ctx, probe)
		if rt.gotURL == "" {
			t.Error("positive control: an ordinary preStop did not hit the transport; the no-preStop check is vacuous")
		}
	})

	t.Run("every status path, the apiserver, the watch and the Events report the eviction", func(t *testing.T) {
		h := newEvictionHarness(t)
		h.add(evPod("hog", nil, "", ""), "2Gi")
		h.step(compressorAt(85))

		wantMsg := compressorMsg + "Container c0 was using 2Gi, request is 0, has larger consumption of memory. "
		st, err := h.r.GetPodStatus(ctx, "default", "hog")
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		assertEvictedTuple(t, "GetPodStatus", *st, wantMsg)
		if st.Message != wantMsg {
			t.Errorf("message = %q\nwant      %q", st.Message, wantMsg)
		}
		pods, err := h.r.GetPods(ctx)
		if err != nil || len(pods) != 1 {
			t.Fatalf("GetPods = %d pods, %v; the evicted pod stays tracked until it is deleted", len(pods), err)
		}
		assertEvictedTuple(t, "GetPods", pods[0].Status, wantMsg)

		live, err := h.cs.CoreV1().Pods("default").Get(ctx, "hog", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("the apiserver pod must survive an eviction: %v", err)
		}
		assertEvictedTuple(t, "apiserver", live.Status, wantMsg)

		h.cbMu.Lock()
		var cb *corev1.Pod
		for _, p := range h.cbPods {
			if p.Name == "hog" && p.Status.Phase == corev1.PodFailed {
				cb = p
			}
		}
		h.cbMu.Unlock()
		if cb == nil {
			t.Fatal("the watch callback never carried the evicted status")
		}
		assertEvictedTuple(t, "watch", cb.Status, wantMsg)

		evs := h.events()
		if n := countPrefix(evs, "Warning Evicted "+wantMsg); n != 1 {
			t.Errorf("pod Evicted Events = %d, want 1: %q", n, evs)
		}
		if n := countPrefix(evs, "Warning EvictionThresholdMet Attempting to reclaim memory"); n != 1 {
			t.Errorf("EvictionThresholdMet Events = %d, want 1: %q", n, evs)
		}
	})

	t.Run("hysteresis: no second eviction while the signal moves toward release", func(t *testing.T) {
		h := newEvictionHarness(t)
		h.add(evPod("first", nil, "", ""), "3Gi")
		h.add(evPod("second", nil, "", ""), "2Gi")
		h.step(compressorAt(85))
		if got := h.deleteIDs(); !slices.Equal(got, []string{"uid-first"}) {
			t.Fatalf("first eviction = %v", got)
		}
		// No fresh sample yet: nothing.
		h.m.cycle(ctx)
		// The first fresh sample after the teardown is the baseline: nothing.
		h.step(compressorAt(85))
		// Moving toward release: nothing.
		h.step(compressorAt(84))
		h.step(compressorAt(83))
		if got := h.deleteIDs(); len(got) != 1 {
			t.Fatalf("evicted again while the signal was falling: %v", got)
		}
		// Flat: not moving toward release, so the next victim goes.
		h.step(compressorAt(83))
		if got := h.deleteIDs(); !slices.Equal(got, []string{"uid-first", "uid-second"}) {
			t.Fatalf("after a flat sample: %v, want the second pod evicted", got)
		}
		if n := countPrefix(h.events(), "Warning EvictionThresholdMet"); n != 1 {
			t.Errorf("EvictionThresholdMet Events across one episode = %d, want 1", n)
		}
		if n := evictionsTotal(h.m, signalCompressor); n != 2 {
			t.Errorf("evictions_total{compressor} = %d, want 2", n)
		}
	})

	t.Run("cascade cap: three evictions in five minutes halt the episode", func(t *testing.T) {
		h := newEvictionHarness(t)
		for _, n := range []string{"p1", "p2", "p3", "p4", "p5"} {
			h.add(evPod(n, nil, "", ""), "1Gi")
		}
		// Flat pressure: evict, baseline, evict, baseline, evict, baseline, halt.
		for range 12 {
			h.step(compressorAt(90))
			h.now = h.now.Add(10 * time.Second)
		}
		if got := len(h.deleteIDs()); got != 3 {
			t.Fatalf("evictions under flat pressure = %d (%v), want the cap of 3", got, h.deleteIDs())
		}
		evs := h.events()
		if n := countPrefix(evs, "Warning EvictionCascadeHalted"); n != 1 {
			t.Errorf("EvictionCascadeHalted Events = %d, want exactly 1: %q", n, evs)
		}
		// The episode ends; a new one starts the count again.
		h.step(compressorAt(10))
		h.step(compressorAt(90))
		if got := len(h.deleteIDs()); got != 4 {
			t.Errorf("a new episode did not resume eviction: %d evictions", got)
		}
		if n := countPrefix(h.events(), "Warning EvictionThresholdMet"); n != 1 {
			t.Errorf("the new episode's EvictionThresholdMet = %d, want 1", n)
		}
	})

	t.Run("a terminal pod is not a candidate", func(t *testing.T) {
		h := newEvictionHarness(t)
		done := evPod("done", nil, "", "")
		h.add(done, "4Gi")
		// The kernel (or the pod itself) already ended its only container.
		h.f.mu.Lock()
		h.f.stopped = map[string]map[string]bool{"uid-done": {"c0": true}}
		h.f.mu.Unlock()
		h.step(compressorAt(90))
		if got := h.deleteIDs(); len(got) != 0 {
			t.Errorf("a terminated pod was evicted: %v", got)
		}
	})

	t.Run("an evicted pod is never created again", func(t *testing.T) {
		h := newEvictionHarness(t)
		pod := evPod("evicted", nil, "", "")
		pod.Spec.RestartPolicy = corev1.RestartPolicyAlways
		pod.Status = corev1.PodStatus{Phase: corev1.PodFailed, Reason: reasonEvicted}
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod on an evicted pod = %v, want nil (a no-op)", err)
		}
		h.f.mu.Lock()
		creates := h.f.createCalls
		h.f.mu.Unlock()
		if creates != 0 || h.r.trackByID("uid-evicted") != nil {
			t.Errorf("CreatePod on an evicted pod: runtime creates=%d tracked=%v, want 0/false", creates, h.r.trackByID("uid-evicted") != nil)
		}
	})

	t.Run("a later DeletePod finishes the teardown without a preStop", func(t *testing.T) {
		h := newEvictionHarness(t)
		pod := evPod("hog", nil, "", "")
		h.add(pod, "2Gi")
		h.step(compressorAt(85))
		if err := h.r.DeletePod(ctx, pod); err != nil {
			t.Fatalf("DeletePod after eviction: %v", err)
		}
		if h.r.trackByID("uid-hog") != nil {
			t.Error("the evicted pod's track survived its DeletePod")
		}
		if got := h.deleteIDs(); !slices.Equal(got, []string{"uid-hog", "uid-hog"}) {
			t.Errorf("DeletePod ids = %v, want the eviction then the idempotent delete, same id", got)
		}
	})

	t.Run("never touches a pod the node did not start", func(t *testing.T) {
		h := newEvictionHarness(t)
		h.add(evPod("ours", nil, "", ""), "1Gi")
		stranger := evPod("stranger", nil, "", "")
		if err := h.r.evictPod(ctx, stranger, evictionNotice{signal: signalCompressor, message: "x"}); err == nil {
			t.Error("evictPod on an untracked pod returned nil, want an error")
		}
		if got := h.deleteIDs(); len(got) != 0 {
			t.Errorf("evictPod on an untracked pod reached the runtime: %v", got)
		}
		// And the manager's own pass touches only the pod it tracks (the strict
		// fake fails the test on any other id).
		h.step(compressorAt(90))
		if got := h.deleteIDs(); !slices.Equal(got, []string{"uid-ours"}) {
			t.Errorf("DeletePod ids = %v, want only the tracked pod", got)
		}
	})
}
