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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	testclock "k8s.io/utils/clock/testing"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

const (
	budgetTestNode = "budget-node"
	budgetTestGi   = int64(1) << 30
	// budgetTestMem is 32 GiB, so one memory quantum is 1.6 GiB.
	budgetTestMem      = 32 * budgetTestGi
	budgetTestQuantum  = budgetTestMem / budgetQuantumDivisor
	budgetTestCPUMilli = int64(8000)
)

// budgetSampleSource is a BudgetSource the test moves. reads counts the samples
// the publisher took.
type budgetSampleSource struct {
	mu    sync.Mutex
	clk   *testclock.FakeClock
	level budgetv1alpha1.Level
	avail int64
	none  bool
	reads int
}

func (s *budgetSampleSource) set(level budgetv1alpha1.Level, avail int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.level, s.avail = level, avail
}

func (s *budgetSampleSource) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// Budget returns a real budgetOf observation for the current reading, with the
// level the test named, so every write passes the real validators.
func (s *budgetSampleSource) Budget() (budgetv1alpha1.NodeBudgetObservation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.none {
		return budgetv1alpha1.NodeBudgetObservation{}, false
	}
	host := hostStats{MemCapacityBytes: budgetTestMem, MemAvailableBytes: s.avail, PIDMax: 4000, PIDCount: 100}
	host.history.sampledAt = s.clk.Now()
	ladder := defaultLadder(host.MemCapacityBytes, host.PIDMax)
	obs, _ := budgetOf(host, ladder)
	obs.Level = s.level
	obs.Admit = s.level == budgetv1alpha1.LevelOK || s.level == budgetv1alpha1.LevelWarn
	obs.AdmitReasonSignal = ""
	if !obs.Admit {
		obs.AdmitReasonSignal = budgetv1alpha1.SignalMemoryAvailable
	}
	obs.Capacity.CPUCapacityMilli = i64(budgetTestCPUMilli)
	return obs, true
}

// budgetLiveNode is a BudgetOwnNode reading the fake apiserver directly, so a
// write is visible at once and no informer timing enters the test.
type budgetLiveNode struct {
	cs      *fake.Clientset
	changed chan struct{}
}

func (n *budgetLiveNode) Annotation(key string) (string, bool) {
	node, err := n.cs.CoreV1().Nodes().Get(context.Background(), budgetTestNode, metav1.GetOptions{})
	if err != nil {
		return "", false
	}
	return node.Annotations[key], true
}

func (n *budgetLiveNode) Changed() <-chan struct{} { return n.changed }

// publisherRig is one publisher under test on a fake clock.
type publisherRig struct {
	t   *testing.T
	clk *testclock.FakeClock
	cs  *fake.Clientset
	src *budgetSampleSource
	own *budgetLiveNode
	pub *BudgetPublisher
}

// newPublisherRig builds a rig whose Node carries annotations, without starting it.
func newPublisherRig(t *testing.T, stateDir string, annotations map[string]string) *publisherRig {
	t.Helper()
	clk := testclock.NewFakeClock(time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC))
	cs := fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: budgetTestNode, Annotations: annotations}})
	src := &budgetSampleSource{clk: clk, level: budgetv1alpha1.LevelOK, avail: 20 * budgetTestGi}
	own := &budgetLiveNode{cs: cs, changed: make(chan struct{}, 1)}
	return &publisherRig{t: t, clk: clk, cs: cs, src: src, own: own, pub: NewBudgetPublisher(BudgetPublisherConfig{
		Client:   cs,
		NodeName: budgetTestNode,
		Own:      own,
		Source:   src,
		StateDir: stateDir,
		Clock:    clk,
		Log:      slog.New(slog.DiscardHandler),
	})}
}

// start runs the publisher and returns once its first pass is done, shown by
// the timer it arms after a pass. The publisher stops with the test.
func (r *publisherRig) start() {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.pub.Run(ctx) }()
	r.t.Cleanup(func() { cancel(); <-done })
	waitFor(r.t, "the first pass", r.clk.HasWaiters)
}

// poll advances the clock by one poll and returns once that pass has finished.
// The fired timer leaves the waiter list, so HasWaiters goes true again only when
// the loop has finished the pass and armed its next timer; reads proves the pass
// took a sample. That is the positive barrier before any "no write" assertion.
func (r *publisherRig) poll() {
	r.t.Helper()
	waitFor(r.t, "the publisher's timer", r.clk.HasWaiters)
	before := r.src.readCount()
	r.clk.Step(budgetAnnotationPoll)
	waitFor(r.t, "the pass", func() bool { return r.src.readCount() > before && r.clk.HasWaiters() })
}

// pollFor runs polls covering d.
func (r *publisherRig) pollFor(d time.Duration) {
	r.t.Helper()
	for n := d / budgetAnnotationPoll; n > 0; n-- {
		r.poll()
	}
}

// statusWrites are the status annotation writes the publisher made, in order.
func (r *publisherRig) statusWrites() []budgetv1alpha1.NodeBudgetReport {
	r.t.Helper()
	var out []budgetv1alpha1.NodeBudgetReport
	for _, a := range r.cs.Actions() {
		p, ok := a.(k8stesting.PatchAction)
		if !ok || a.GetVerb() != "patch" {
			continue
		}
		var body struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(p.GetPatch(), &body); err != nil {
			r.t.Fatalf("patch body: %v", err)
		}
		rep, err := budgetv1alpha1.ParseNodeBudgetReport(body.Metadata.Annotations[budgetv1alpha1.AnnotationStatus])
		if err != nil {
			r.t.Fatalf("a written annotation does not parse: %v", err)
		}
		out = append(out, rep)
	}
	return out
}

// lastWrite is the newest status write.
func (r *publisherRig) lastWrite() budgetv1alpha1.NodeBudgetReport {
	r.t.Helper()
	w := r.statusWrites()
	if len(w) == 0 {
		r.t.Fatal("no status annotation was written")
	}
	return w[len(w)-1]
}

func (r *publisherRig) wantWrites(n int, when string) {
	r.t.Helper()
	if got := len(r.statusWrites()); got != n {
		r.t.Fatalf("%s: %d status writes, want %d", when, got, n)
	}
}

// setPolicy sets the policy annotation as the relay would, without a patch, so
// patches are the publisher's alone, and returns after signalling the change.
func (r *publisherRig) setPolicy(value string) {
	r.t.Helper()
	n, err := r.cs.CoreV1().Nodes().Get(context.Background(), budgetTestNode, metav1.GetOptions{})
	if err != nil {
		r.t.Fatal(err)
	}
	if n.Annotations == nil {
		n.Annotations = map[string]string{}
	}
	n.Annotations[budgetv1alpha1.AnnotationPolicy] = value
	if value == "" {
		delete(n.Annotations, budgetv1alpha1.AnnotationPolicy)
	}
	if _, err := r.cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		r.t.Fatal(err)
	}
	select {
	case r.own.changed <- struct{}{}:
	default:
	}
}

// waitPolicyOutcome waits for the publisher to record outcome, the positive
// barrier before asserting what stayed in force.
func (r *publisherRig) waitPolicyOutcome(name string, outcome budgetv1alpha1.PolicyOutcome) {
	r.t.Helper()
	waitFor(r.t, "policy outcome "+string(outcome), func() bool {
		r.pub.mu.Lock()
		defer r.pub.mu.Unlock()
		return r.pub.applied != nil && r.pub.applied.Name == name && r.pub.applied.Outcome == outcome
	})
}

func budgetPolicyValue(t *testing.T, name, rv string, spec budgetv1alpha1.NodeBudgetPolicySpec) string {
	t.Helper()
	d := budgetv1alpha1.NodeBudgetDesiredPolicy{Schema: budgetv1alpha1.BudgetAnnotationSchema, Name: name, ResourceVersion: rv, Spec: spec}
	v, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func budgetPolicyInForceName(t *testing.T, p *BudgetPublisher) string {
	t.Helper()
	ref, _, ok := p.InForce()
	if !ok {
		return ""
	}
	return ref.Name
}

func signalValue(t *testing.T, r budgetv1alpha1.NodeBudgetReport, id budgetv1alpha1.SignalID) *int64 {
	t.Helper()
	for i := range r.Signals {
		if r.Signals[i].ID == id {
			return r.Signals[i].Value
		}
	}
	t.Fatalf("no signal %s", id)
	return nil
}

// TestBudgetAnnotationRateLimitedAndQuantized is the node's half of the budget
// channel: it writes its own Node's status annotation on a quantized edge, at most
// once per 60 s at every level, and applies the relayed policy.
func TestBudgetAnnotationRateLimitedAndQuantized(t *testing.T) {
	t.Run("the first sample writes one patch of one key on the node's own Node", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		r.start()
		r.wantWrites(1, "after the first pass")
		for _, a := range r.cs.Actions() {
			if a.GetResource().Resource != "nodes" {
				t.Fatalf("the publisher touched %s (verb %s); it reports only through its Node", a.GetResource().Resource, a.GetVerb())
			}
			switch p := a.(type) {
			case k8stesting.PatchAction:
				if p.GetName() != budgetTestNode || p.GetPatchType() != types.MergePatchType {
					t.Fatalf("patch of %q type %q, want a merge patch of this node", p.GetName(), p.GetPatchType())
				}
				var body map[string]map[string]map[string]any
				if err := json.Unmarshal(p.GetPatch(), &body); err != nil {
					t.Fatal(err)
				}
				if len(body) != 1 || len(body["metadata"]) != 1 || len(body["metadata"]["annotations"]) != 1 {
					t.Fatalf("patch %s touches more than the status annotation", p.GetPatch())
				}
				if _, ok := body["metadata"]["annotations"][budgetv1alpha1.AnnotationStatus]; !ok {
					t.Fatalf("patch %s does not write the status annotation", p.GetPatch())
				}
			default:
				if v := a.GetVerb(); v != "get" {
					t.Fatalf("unexpected %s of nodes", v)
				}
			}
		}
	})

	t.Run("an unchanged quantized value writes nothing, however long it holds", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		r.start()
		// Every poll moves the raw reading, inside one bucket.
		for i := range int64(36) {
			r.src.set(budgetv1alpha1.LevelOK, 20*budgetTestGi+i%4*budgetTestQuantum/8)
			r.poll()
		}
		r.wantWrites(1, "after three minutes in one bucket")
	})

	t.Run("a change after a quiet minute is written at the next poll", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		r.start()
		r.pollFor(budgetAnnotationMinInterval)
		r.wantWrites(1, "before the edge")
		r.src.set(budgetv1alpha1.LevelWarn, 20*budgetTestGi)
		r.poll()
		r.wantWrites(2, "one poll after the edge")
		if got := r.lastWrite().Level; got != budgetv1alpha1.LevelWarn {
			t.Fatalf("written level %s, want warn", got)
		}
	})

	t.Run("at every level a change waits out the 60 s and the newest value is written", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		r.start()
		writes := 1
		last := r.clk.Now()
		for _, level := range []budgetv1alpha1.Level{budgetv1alpha1.LevelWarn, budgetv1alpha1.LevelCritical, budgetv1alpha1.LevelEvicting, budgetv1alpha1.LevelOK} {
			// The edge lands one poll into a fresh interval, and the reading
			// keeps moving through it, always in a new bucket.
			for i := range 11 {
				r.src.set(level, 20*budgetTestGi+int64(i)*2*budgetTestQuantum)
				r.poll()
				r.wantWrites(writes, "inside the interval at level "+string(level))
			}
			r.poll()
			writes++
			r.wantWrites(writes, "at the end of the interval at level "+string(level))
			got := r.lastWrite()
			if got.Level != level {
				t.Fatalf("written level %s, want %s", got.Level, level)
			}
			want := (20*budgetTestGi + 10*2*budgetTestQuantum) / budgetTestQuantum * budgetTestQuantum
			if v := signalValue(t, got, budgetv1alpha1.SignalMemoryAvailable); v == nil || *v != want {
				t.Fatalf("written memory.available %v, want the newest bucket %d", v, want)
			}
			if gap := r.clk.Now().Sub(last); gap < budgetAnnotationMinInterval {
				t.Fatalf("two writes %s apart at level %s, want at least %s", gap, level, budgetAnnotationMinInterval)
			}
			last = r.clk.Now()
		}
	})

	t.Run("a change gone by the end of the interval writes nothing", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		r.start()
		r.src.set(budgetv1alpha1.LevelCritical, 20*budgetTestGi)
		r.pollFor(30 * time.Second)
		r.src.set(budgetv1alpha1.LevelOK, 20*budgetTestGi)
		r.pollFor(2 * budgetAnnotationMinInterval)
		r.wantWrites(1, "after a blip inside the interval")
	})

	t.Run("a reading flapping on a bucket edge writes nothing", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		edge := 13 * budgetTestQuantum
		r.src.set(budgetv1alpha1.LevelOK, edge+1)
		r.start()
		for range 30 {
			r.src.set(budgetv1alpha1.LevelOK, edge-budgetTestQuantum/8)
			r.poll()
			r.src.set(budgetv1alpha1.LevelOK, edge+budgetTestQuantum/8)
			r.poll()
		}
		r.wantWrites(1, "after five minutes on a bucket edge")
	})

	t.Run("a failed write is retried only after the interval", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		var mu sync.Mutex
		fail, attempts := true, 0
		r.cs.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if fail {
				return true, nil, errors.New("apiserver unavailable")
			}
			return false, nil, nil
		})
		r.start()
		r.pollFor(budgetAnnotationMinInterval - budgetAnnotationPoll)
		mu.Lock()
		if attempts != 1 {
			mu.Unlock()
			t.Fatalf("%d attempts inside the interval, want 1", attempts)
		}
		fail = false
		mu.Unlock()
		r.poll()
		mu.Lock()
		defer mu.Unlock()
		if attempts != 2 {
			t.Fatalf("%d attempts after the interval, want 2", attempts)
		}
	})

	t.Run("a restart with the value on the Node writes nothing", func(t *testing.T) {
		first := newPublisherRig(t, "", nil)
		first.start()
		left, ok := first.own.Annotation(budgetv1alpha1.AnnotationStatus)
		if !ok || left == "" {
			t.Fatal("no annotation to restart from")
		}
		r := newPublisherRig(t, "", map[string]string{budgetv1alpha1.AnnotationStatus: left})
		r.start()
		r.pollFor(2 * budgetAnnotationMinInterval)
		r.wantWrites(0, "after a restart with an unchanged value")
	})

	t.Run("a restart inside the interval still waits it out", func(t *testing.T) {
		first := newPublisherRig(t, "", nil)
		first.start()
		left, _ := first.own.Annotation(budgetv1alpha1.AnnotationStatus)
		r := newPublisherRig(t, "", map[string]string{budgetv1alpha1.AnnotationStatus: left})
		r.src.set(budgetv1alpha1.LevelCritical, 20*budgetTestGi)
		// 20 s after the old sample. Its write may have come one calm sample
		// interval after it, so the interval runs to 70 s after the sample.
		r.clk.Step(20 * time.Second)
		r.start()
		r.pollFor(45 * time.Second)
		r.wantWrites(0, "65 s after the old sample")
		r.poll()
		r.wantWrites(1, "70 s after the old sample")
	})

	t.Run("an unreadable annotation on the Node is replaced at once", func(t *testing.T) {
		r := newPublisherRig(t, "", map[string]string{budgetv1alpha1.AnnotationStatus: `{"schema":1,"bogus":true}`})
		r.start()
		r.wantWrites(1, "after the first pass")
	})

	t.Run("no Node yet writes nothing", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		if err := r.cs.CoreV1().Nodes().Delete(context.Background(), budgetTestNode, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		r.start()
		r.pollFor(budgetAnnotationMinInterval)
		r.wantWrites(0, "with no Node")
	})

	t.Run("no sample yet writes nothing, and the first sample writes at once", func(t *testing.T) {
		r := newPublisherRig(t, "", nil)
		r.src.mu.Lock()
		r.src.none = true
		r.src.mu.Unlock()
		r.start()
		r.pollFor(budgetAnnotationMinInterval)
		r.wantWrites(0, "with no sample")
		r.src.mu.Lock()
		r.src.none = false
		r.src.mu.Unlock()
		r.poll()
		r.wantWrites(1, "after the first sample")
	})

	t.Run("a valid policy is in force and reported applied", func(t *testing.T) {
		dir := t.TempDir()
		r := newPublisherRig(t, dir, nil)
		r.start()
		r.pollFor(budgetAnnotationMinInterval)
		r.setPolicy(budgetPolicyValue(t, "good", "7", budgetv1alpha1.NodeBudgetPolicySpec{Mode: budgetv1alpha1.KillModeOff}))
		r.waitPolicyOutcome("good", budgetv1alpha1.PolicyApplied)
		waitFor(t, "the outcome's write", func() bool { return len(r.statusWrites()) == 2 })
		got := r.lastWrite()
		if got.Policy == nil || got.Policy.Name != "good" || got.Policy.ResourceVersion != "7" || got.Policy.Outcome != budgetv1alpha1.PolicyApplied {
			t.Fatalf("written policy %+v", got.Policy)
		}
		if got.InForce == nil || got.InForce.Name != "good" {
			t.Fatalf("written inForce %+v", got.InForce)
		}
		_, spec, ok := r.pub.InForce()
		if !ok || spec.Mode != budgetv1alpha1.KillModeOff {
			t.Fatalf("in force %+v ok=%t", spec, ok)
		}
	})

	t.Run("an invalid policy is rejected and the last valid one kept", func(t *testing.T) {
		valid := budgetPolicyValue(t, "good", "7", budgetv1alpha1.NodeBudgetPolicySpec{Mode: budgetv1alpha1.KillModeOff})
		for _, tc := range []struct {
			name, value, wantName, wantRV string
		}{
			{"a strict decode failure names what it can", `{"schema":1,"name":"bad","resourceVersion":"8","spec":{},"extra":1}`, "bad", "8"},
			{"a newer schema", `{"schema":2,"name":"future","resourceVersion":"9","spec":{}}`, "future", "9"},
			{"a bad name is not repeated", `{"schema":1,"name":"Not A Name","resourceVersion":"8","spec":{}}`, budgetPolicyUnparseableName, ""},
			{"a control character in a resourceVersion is not repeated", `{"schema":1,"name":"bad","resourceVersion":"8\n","spec":{}}`, "bad", ""},
			{"not JSON", `not json`, budgetPolicyUnparseableName, ""},
			{"oversized", `{"schema":1,"name":"big","x":"` + strings.Repeat("a", budgetv1alpha1.MaxBudgetAnnotationBytes) + `"}`, budgetPolicyUnparseableName, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := newPublisherRig(t, t.TempDir(), nil)
				r.start()
				r.setPolicy(valid)
				r.waitPolicyOutcome("good", budgetv1alpha1.PolicyApplied)
				r.setPolicy(tc.value)
				r.waitPolicyOutcome(tc.wantName, budgetv1alpha1.PolicyRejected)
				r.poll()
				if n := budgetPolicyInForceName(t, r.pub); n != "good" {
					t.Fatalf("in force %q, want the last valid policy", n)
				}
				r.pollFor(budgetAnnotationMinInterval + budgetAnnotationPoll)
				got := r.lastWrite()
				if got.Policy == nil || got.Policy.Outcome != budgetv1alpha1.PolicyRejected || got.Policy.Name != tc.wantName || got.Policy.ResourceVersion != tc.wantRV {
					t.Fatalf("written policy %+v, want rejected %s/%s", got.Policy, tc.wantName, tc.wantRV)
				}
				if got.InForce == nil || got.InForce.Name != "good" {
					t.Fatalf("written inForce %+v, want the last valid policy", got.InForce)
				}
			})
		}
	})

	t.Run("an invalid policy with no last valid one leaves the defaults in force", func(t *testing.T) {
		r := newPublisherRig(t, t.TempDir(), nil)
		r.start()
		r.setPolicy(`not json`)
		r.waitPolicyOutcome(budgetPolicyUnparseableName, budgetv1alpha1.PolicyRejected)
		r.poll()
		if _, _, ok := r.pub.InForce(); ok {
			t.Fatal("a policy is in force after the only one was refused")
		}
		r.pollFor(budgetAnnotationMinInterval + budgetAnnotationPoll)
		got := r.lastWrite()
		if got.Policy == nil || got.Policy.Outcome != budgetv1alpha1.PolicyRejected || got.InForce != nil {
			t.Fatalf("written policy %+v inForce %+v", got.Policy, got.InForce)
		}
	})

	t.Run("reserves above the measured value are clamped and reported", func(t *testing.T) {
		r := newPublisherRig(t, t.TempDir(), nil)
		r.start()
		r.pollFor(budgetAnnotationMinInterval)
		r.setPolicy(budgetPolicyValue(t, "greedy", "3", budgetv1alpha1.NodeBudgetPolicySpec{
			Reserves: &budgetv1alpha1.BudgetReserves{
				CPUSystemReserveMilli:   i64(budgetTestCPUMilli + 1),
				MemSystemReserveBytes:   i64(budgetTestMem + 1),
				MemEvictionReserveBytes: i64(budgetTestGi), // below the measured value: stands
			},
			Tier1GraceSeconds: i64(1),
		}))
		r.waitPolicyOutcome("greedy", budgetv1alpha1.PolicyClamped)
		waitFor(t, "the outcome's write", func() bool { return len(r.statusWrites()) == 2 })
		got := r.lastWrite()
		want := []budgetv1alpha1.PolicyField{budgetv1alpha1.FieldTier1GraceSeconds, budgetv1alpha1.FieldReservesCPUSystemReserveMilli, budgetv1alpha1.FieldReservesMemSystemReserveBytes}
		if got.Policy == nil || got.Policy.Outcome != budgetv1alpha1.PolicyClamped || !equalFields(got.Policy.ClampedFields, want) {
			t.Fatalf("written policy %+v, want clamped %v", got.Policy, want)
		}
		_, spec, ok := r.pub.InForce()
		if !ok {
			t.Fatal("no policy in force")
		}
		if *spec.Reserves.CPUSystemReserveMilli != budgetTestCPUMilli || *spec.Reserves.MemSystemReserveBytes != budgetTestMem || *spec.Reserves.MemEvictionReserveBytes != budgetTestGi {
			t.Fatalf("in force reserves cpu=%d sys=%d evict=%d", *spec.Reserves.CPUSystemReserveMilli, *spec.Reserves.MemSystemReserveBytes, *spec.Reserves.MemEvictionReserveBytes)
		}
		if *spec.Tier1GraceSeconds != budgetv1alpha1.MinTier1GraceSeconds {
			t.Fatalf("in force grace %d", *spec.Tier1GraceSeconds)
		}
	})

	t.Run("a cold start keeps the cached policy against an invalid annotation", func(t *testing.T) {
		dir := t.TempDir()
		valid := budgetPolicyValue(t, "cached", "5", budgetv1alpha1.NodeBudgetPolicySpec{Mode: budgetv1alpha1.KillModeOff})
		first := newPublisherRig(t, dir, nil)
		first.start()
		first.setPolicy(valid)
		first.waitPolicyOutcome("cached", budgetv1alpha1.PolicyApplied)
		fi, err := os.Stat(filepath.Join(dir, budgetPolicyFile))
		if err != nil {
			t.Fatalf("the valid policy was not cached: %v", err)
		}
		if m := fi.Mode().Perm(); m != 0o600 {
			t.Fatalf("cache mode %o, want 0600", m)
		}

		r := newPublisherRig(t, dir, map[string]string{budgetv1alpha1.AnnotationPolicy: `not json`})
		if n := budgetPolicyInForceName(t, r.pub); n != "cached" {
			t.Fatalf("before the Node is read, in force %q, want the cached policy", n)
		}
		r.start()
		r.waitPolicyOutcome(budgetPolicyUnparseableName, budgetv1alpha1.PolicyRejected)
		if n := budgetPolicyInForceName(t, r.pub); n != "cached" {
			t.Fatalf("in force %q, want the cached policy", n)
		}
		got := r.lastWrite()
		if got.Policy == nil || got.Policy.Outcome != budgetv1alpha1.PolicyRejected || got.InForce == nil || got.InForce.Name != "cached" {
			t.Fatalf("written policy %+v inForce %+v", got.Policy, got.InForce)
		}
	})

	t.Run("an invalid cache is ignored", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, budgetPolicyFile), []byte(`{"schema":99}`), 0o600); err != nil {
			t.Fatal(err)
		}
		r := newPublisherRig(t, dir, nil)
		if _, _, ok := r.pub.InForce(); ok {
			t.Fatal("an invalid cache put a policy in force")
		}
	})

	t.Run("a removed policy returns to the defaults and drops the cache", func(t *testing.T) {
		dir := t.TempDir()
		r := newPublisherRig(t, dir, nil)
		r.start()
		r.setPolicy(budgetPolicyValue(t, "good", "7", budgetv1alpha1.NodeBudgetPolicySpec{}))
		r.waitPolicyOutcome("good", budgetv1alpha1.PolicyApplied)
		r.setPolicy("")
		waitFor(t, "the policy to leave", func() bool { _, _, ok := r.pub.InForce(); return !ok })
		r.poll()
		if _, err := os.Stat(filepath.Join(dir, budgetPolicyFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cache after removal: %v", err)
		}
		r.pollFor(budgetAnnotationMinInterval + budgetAnnotationPoll)
		if got := r.lastWrite(); got.Policy != nil || got.InForce != nil {
			t.Fatalf("written policy %+v inForce %+v after removal", got.Policy, got.InForce)
		}
	})
}

func equalFields(a, b []budgetv1alpha1.PolicyField) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestQuantizeWithHysteresis(t *testing.T) {
	const q = int64(100)
	for _, tc := range []struct {
		name string
		v    *int64
		q    int64
		prev *int64
		want *int64
	}{
		{"nil stays nil", nil, q, nil, nil},
		{"no quantum publishes no value", i64(5), 0, nil, nil},
		{"rounds down", i64(199), q, nil, i64(100)},
		{"zero stays zero", i64(0), q, nil, i64(0)},
		{"inside the bucket keeps prev", i64(150), q, i64(100), i64(100)},
		{"a quarter quantum below the bucket keeps prev", i64(75), q, i64(100), i64(100)},
		{"below that moves", i64(74), q, i64(100), i64(0)},
		{"just short of a quarter above the bucket keeps prev", i64(224), q, i64(100), i64(100)},
		{"a quarter quantum above the bucket moves", i64(225), q, i64(100), i64(200)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := quantizeWithHysteresis(tc.v, tc.q, tc.prev)
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
