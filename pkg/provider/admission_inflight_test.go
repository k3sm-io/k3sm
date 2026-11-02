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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// switchSource is an admission source the test flips between calm and
// pressured, so each create's verdict is chosen, not raced.
type switchSource struct {
	mu sync.Mutex
	s  hostStats
}

func (w *switchSource) set(s hostStats) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.s = s
}

func (w *switchSource) latest() (hostStats, uint64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.s, 1, true
}

// holdFirstAdmitted parks the first create admission lets through inside
// CreatePod's admission window, after the decision and before the track is
// registered: entered is closed when it gets there, and it stays until release
// is closed. Every later create passes straight through. Set before any create.
func holdFirstAdmitted(r *runtimedRuntime) (entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.admittedHook = func(string) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(entered)
			<-release
		}
	}
	return entered, release
}

// awaitClosed waits for ch to close, failing the test after a generous bound.
func awaitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	tm := time.NewTimer(10 * time.Second)
	defer tm.Stop()
	select {
	case <-ch:
	case <-tm.C:
		t.Fatalf("timed out waiting for %s", what)
	}
}

// awaitErr waits for one create's result, failing the test after a generous
// bound.
func awaitErr(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	tm := time.NewTimer(10 * time.Second)
	defer tm.Stop()
	select {
	case err := <-ch:
		return err
	case <-tm.C:
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

func (h *evictionHarness) createCount() int {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	return h.f.createCalls
}

func (h *evictionHarness) apiPhase(t *testing.T, pod *corev1.Pod) corev1.PodPhase {
	t.Helper()
	live, err := h.cs.CoreV1().Pods(pod.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("apiserver get %s: %v", pod.Name, err)
	}
	return live.Status.Phase
}

// trackState names a track's admission-relevant state for a failure message.
func trackState(tr *podTrack) string {
	if tr == nil {
		return "no track"
	}
	return fmt.Sprintf("rejected %v, terminal %v", tr.rejected, tr.evictedStatus() != nil)
}

func (h *evictionHarness) admittingCount(id string) int {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	return h.r.admitting[id]
}

// raceHarness is an admission harness with a switchable source, a calm start
// and pod created in the fake apiserver.
func raceHarness(t *testing.T, pod *corev1.Pod) (*evictionHarness, *switchSource) {
	t.Helper()
	h := admissionHarness(t, compressorAt(10))
	src := &switchSource{s: compressorAt(10)}
	h.r.setAdmissionSource(src)
	if _, err := h.cs.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("apiserver create %s: %v", pod.Name, err)
	}
	return h, src
}

// TestAdmissionRefusalYieldsToAdmittedCreateInFlight: create 1 of a BestEffort
// pod is admitted on a calm node and held inside the admission window, before
// its track exists. Pressure rises and create 2 of the same pod decides. It
// must yield to the admitted create in flight rather than refuse: the pod runs,
// and the apiserver never reports it Failed.
//
// Fails without the admitting[id] == 0 yield in admitOnCreate: create 2 reads
// the pressure, installs the rejected track and writes Failed, and create 1 then
// stops at the terminal-track fence, so an admitted pod is refused.
func TestAdmissionRefusalYieldsToAdmittedCreateInFlight(t *testing.T) {
	ctx := context.Background()
	pod := evPod("yield", nil, "", "")
	h, src := raceHarness(t, pod)
	entered, release := holdFirstAdmitted(h.r)

	first := make(chan error, 1)
	go func() { first <- h.r.CreatePod(ctx, pod.DeepCopy()) }()
	awaitClosed(t, entered, "create 1 to reach the admission window")

	src.set(compressorAt(85))
	if err := h.r.CreatePod(ctx, pod.DeepCopy()); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if tr := h.r.trackByID(string(pod.UID)); tr == nil || tr.rejected || tr.evictedStatus() != nil {
		t.Fatalf("create 2 refused the pod while an admitted create was in flight (%s)", trackState(tr))
	}
	close(release)
	if err := awaitErr(t, first, "create 1"); err != nil {
		t.Fatalf("create 1: %v", err)
	}

	tr := h.r.trackByID(string(pod.UID))
	if tr == nil || tr.rejected || tr.evictedStatus() != nil {
		t.Fatalf("the pod is not tracked as admitted after both creates (%s)", trackState(tr))
	}
	if n := h.createCount(); n == 0 {
		t.Fatal("the admitted pod never reached the runtime")
	}
	if ph := h.apiPhase(t, pod); ph == corev1.PodFailed {
		t.Fatal("the node runs the pod but the apiserver reports it Failed")
	}
	if n := countPrefix(h.events(), "Warning Evicted"); n != 0 {
		t.Errorf("Warning Evicted Events = %d, want 0", n)
	}
	if n := h.admittingCount(string(pod.UID)); n != 0 {
		t.Errorf("in-flight admitted creates after both returned = %d, want 0", n)
	}
}

// TestAdmissionFenceStopsAdmittedCreateAfterRefusal: create 1 is admitted and
// held inside the admission window; its in-flight count is then released, which
// is the one thing that lets a refusal land there, and create 2 refuses the pod
// under pressure. When create 1 resumes it must stop at the terminal-track
// fence: the refusal stands, the runtime is never asked to create the pod, and
// the apiserver keeps Failed.
//
// Fails without the evictedStatus() fence in CreatePod: create 1 replaces the
// rejected track with a live one and creates the pod the apiserver reports
// Failed.
func TestAdmissionFenceStopsAdmittedCreateAfterRefusal(t *testing.T) {
	ctx := context.Background()
	pod := evPod("fence", nil, "", "")
	id := string(pod.UID)
	h, src := raceHarness(t, pod)
	entered, release := holdFirstAdmitted(h.r)

	first := make(chan error, 1)
	go func() { first <- h.r.CreatePod(ctx, pod.DeepCopy()) }()
	awaitClosed(t, entered, "create 1 to reach the admission window")

	h.r.admitDone(id)
	src.set(compressorAt(85))
	if err := h.r.CreatePod(ctx, pod.DeepCopy()); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if tr := h.r.trackByID(id); tr == nil || !tr.rejected {
		t.Fatalf("create 2 under pressure did not refuse the pod (%s)", trackState(tr))
	}
	close(release)
	if err := awaitErr(t, first, "create 1"); err != nil {
		t.Fatalf("create 1: %v", err)
	}

	tr := h.r.trackByID(id)
	if tr == nil || !tr.rejected || tr.evictedStatus() == nil {
		t.Fatalf("the refusal was overwritten by the admitted create (%s)", trackState(tr))
	}
	if n := h.createCount(); n != 0 {
		t.Fatalf("runtime CreatePod calls = %d, want 0 for a refused pod", n)
	}
	if ph := h.apiPhase(t, pod); ph != corev1.PodFailed {
		t.Fatalf("apiserver phase = %q, want Failed", ph)
	}
}

// TestCreatePodFenceOnEvictedDuringCreate: a repeat create of a running pod is
// held inside the admission window while the eviction manager evicts the pod.
// When it resumes it must stop at the terminal-track fence: the eviction stands,
// the runtime is not asked to create the pod again, and the apiserver keeps
// Failed.
//
// Fails without the evictedStatus() fence in CreatePod: the repeat create
// replaces the evicted track with a live one and re-creates the pod.
func TestCreatePodFenceOnEvictedDuringCreate(t *testing.T) {
	ctx := context.Background()
	h := admissionHarness(t, compressorAt(10))
	pod := evPod("evicted", nil, "", "")
	id := string(pod.UID)
	if n := createOn(t, h, pod); n != 1 {
		t.Fatalf("runtime CreatePod calls = %d, want 1", n)
	}
	entered, release := holdFirstAdmitted(h.r)

	again := make(chan error, 1)
	go func() { again <- h.r.CreatePod(ctx, pod.DeepCopy()) }()
	awaitClosed(t, entered, "the repeat create to reach the admission window")
	if err := h.r.evictPod(ctx, pod, evictionNotice{signal: signalCompressor, message: "evicted for the test"}); err != nil {
		t.Fatalf("evictPod: %v", err)
	}
	before := h.createCount()
	close(release)
	if err := awaitErr(t, again, "the repeat create"); err != nil {
		t.Fatalf("repeat create: %v", err)
	}

	tr := h.r.trackByID(id)
	if tr == nil || tr.evictedStatus() == nil {
		t.Fatalf("the eviction was overwritten by the repeat create (%s)", trackState(tr))
	}
	if n := h.createCount() - before; n != 0 {
		t.Fatalf("runtime CreatePod calls after the eviction = %d, want 0", n)
	}
	if ph := h.apiPhase(t, pod); ph != corev1.PodFailed {
		t.Fatalf("apiserver phase = %q, want Failed", ph)
	}
}

// TestAdmissionInFlightLeakDoesNotBypassRetry pins the in-flight count's
// lifecycle: an admitted create ends its count when it returns, on every path,
// exactly once.
func TestAdmissionInFlightLeakDoesNotBypassRetry(t *testing.T) {
	ctx := context.Background()

	// Fails without CreatePod's deferred admitted(): the failed create leaves
	// its count at 1, so the retry skips the pressure read, is admitted, and
	// fails the same preflight again instead of being refused.
	t.Run("a create that fails before its track is registered, then a retry under pressure is refused", func(t *testing.T) {
		pod := emptyDirPod("leak", "Memory")
		id := string(pod.UID)
		h, src := raceHarness(t, pod)
		if err := h.r.CreatePod(ctx, pod.DeepCopy()); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
			t.Fatalf("create = %v, want ErrEmptyDirMediumUnsupported", err)
		}
		if h.r.trackByID(id) != nil {
			t.Fatal("the failed create left a track")
		}
		src.set(compressorAt(85))
		if err := h.r.CreatePod(ctx, pod.DeepCopy()); err != nil {
			t.Fatalf("retry under pressure = %v, want refused (nil)", err)
		}
		if tr := h.r.trackByID(id); tr == nil || !tr.rejected {
			t.Fatalf("the retry under pressure was not refused (%s)", trackState(tr))
		}
		if n := h.createCount(); n != 0 {
			t.Fatalf("runtime CreatePod calls = %d, want 0", n)
		}
		if n := h.admittingCount(id); n != 0 {
			t.Errorf("in-flight admitted creates after both returned = %d, want 0", n)
		}
	})

	// admit runs admission alone for pod and fails the test if it refused.
	admit := func(t *testing.T, h *evictionHarness, pod *corev1.Pod) func() {
		t.Helper()
		refused, done := h.r.admitOnCreate(ctx, pod.DeepCopy())
		if refused || done == nil {
			t.Fatalf("admission refused %s (refused %v, done nil %v)", pod.Name, refused, done == nil)
		}
		return done
	}

	t.Run("two in flight, one done: a refusal still yields to the other", func(t *testing.T) {
		pod := evPod("two", nil, "", "")
		id := string(pod.UID)
		h, src := raceHarness(t, pod)
		d1 := admit(t, h, pod)
		d2 := admit(t, h, pod)
		if n := h.admittingCount(id); n != 2 {
			t.Fatalf("in flight = %d, want 2", n)
		}
		d1()
		if n := h.admittingCount(id); n != 1 {
			t.Fatalf("in flight after one done = %d, want 1", n)
		}
		src.set(compressorAt(85))
		d3 := admit(t, h, pod) // yields to d2's create
		d2()
		d3()
		if n := h.admittingCount(id); n != 0 {
			t.Fatalf("in flight after all done = %d, want 0", n)
		}
		if refused, _ := h.r.admitOnCreate(ctx, pod.DeepCopy()); !refused {
			t.Fatal("with nothing in flight, a create under pressure was admitted")
		}
	})

	t.Run("a double done ends one create, not two", func(t *testing.T) {
		pod := evPod("double", nil, "", "")
		id := string(pod.UID)
		h, src := raceHarness(t, pod)
		d1 := admit(t, h, pod)
		d2 := admit(t, h, pod)
		d1()
		d1()
		if n := h.admittingCount(id); n != 1 {
			t.Fatalf("in flight after a double done = %d, want 1", n)
		}
		src.set(compressorAt(85))
		d3 := admit(t, h, pod) // still yields to d2's create
		d3()
		d2()
		d2()
		if n := h.admittingCount(id); n != 0 {
			t.Fatalf("in flight after all done = %d, want 0", n)
		}
		if refused, _ := h.r.admitOnCreate(ctx, pod.DeepCopy()); !refused {
			t.Fatal("with nothing in flight, a create under pressure was admitted")
		}
	})
}
