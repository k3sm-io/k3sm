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
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// admissionHarness wires node-side admission the way the node does: through
// VKProvider.RunEvictionManager over the harness's monitor. The context is
// already cancelled, so the manager loop returns at once and every eviction
// decision stays the test's to drive; only the wiring runs.
func admissionHarness(t *testing.T, s hostStats) *evictionHarness {
	t.Helper()
	h := newEvictionHarness(t)
	h.sm.set(s)
	h.mon.sampleOnce()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	NewVKProvider(h.r, "mac-0").RunEvictionManager(ctx, EvictionConfig{
		Status: &NodeStatusProvider{monitor: h.mon}, Recorder: h.rec, NodeName: "mac-0", Log: discardLog(),
	})
	return h
}

// createOn creates pod in the fake apiserver and on the provider, and returns
// the number of runtime CreatePod calls it caused.
func createOn(t *testing.T, h *evictionHarness, pod *corev1.Pod) int {
	t.Helper()
	ctx := context.Background()
	if _, err := h.cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("apiserver create %s: %v", pod.Name, err)
	}
	h.f.mu.Lock()
	before := h.f.createCalls
	h.f.mu.Unlock()
	if err := h.r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod %s: %v", pod.Name, err)
	}
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	return h.f.createCalls - before
}

// TestBestEffortRefusedUnderMemoryPressure is the admission gate: under
// MemoryPressure a BestEffort pod is refused before anything runs, with the
// kubelet's rejection (phase Failed, reason Evicted, message "Pod was rejected:
// The node had condition: [MemoryPressure]. ", the QoS class kept), on every
// status path, in the apiserver and as a Warning Event; upstream's exemptions
// (critical pods, pods tolerating node.kubernetes.io/memory-pressure) and the
// non-BestEffort classes are admitted; a calm node, and a node whose admission
// is not wired yet, refuse nothing; and admission judges a pod once.
//
// Upstream: managerImpl.Admit (pkg/kubelet/eviction/eviction_manager.go) and
// Kubelet.rejectPod (pkg/kubelet/kubelet.go), v1.36.2.
func TestBestEffortRefusedUnderMemoryPressure(t *testing.T) {
	ctx := context.Background()
	const wantMsg = "The node had condition: [MemoryPressure]. "
	pressured := compressorAt(85)

	t.Run("a BestEffort pod is refused: nothing runs, the kubelet's rejection everywhere", func(t *testing.T) {
		h := admissionHarness(t, pressured)
		pod := evPod("be", nil, "", "")
		if n := createOn(t, h, pod); n != 0 {
			t.Fatalf("runtime CreatePod calls = %d, want 0 (a refused pod runs nothing)", n)
		}
		check := func(where string, st corev1.PodStatus) {
			t.Helper()
			if st.Phase != corev1.PodFailed || st.Reason != "Evicted" || st.Message != "Pod was rejected: "+wantMsg {
				t.Errorf("%s: phase/reason/message = %s/%q/%q, want Failed/Evicted/%q", where, st.Phase, st.Reason, st.Message, "Pod was rejected: "+wantMsg)
			}
			if st.QOSClass != corev1.PodQOSBestEffort {
				t.Errorf("%s: qosClass = %q, want BestEffort (kept as is)", where, st.QOSClass)
			}
			if len(st.ContainerStatuses) != 0 || len(st.Conditions) != 0 {
				t.Errorf("%s: status carries containers %v / conditions %v; a rejected pod never started", where, st.ContainerStatuses, st.Conditions)
			}
		}
		st, err := h.r.GetPodStatus(ctx, pod.Namespace, pod.Name)
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		check("GetPodStatus", *st)
		live, err := h.cs.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("apiserver get: %v", err)
		}
		check("apiserver", live.Status)
		h.cbMu.Lock()
		cbs := len(h.cbPods)
		var last *corev1.Pod
		if cbs > 0 {
			last = h.cbPods[cbs-1]
		}
		h.cbMu.Unlock()
		if last == nil {
			t.Fatal("no status pushed through the watch callback")
		}
		check("callback", last.Status)
		evs := h.events()
		if n := countPrefix(evs, "Warning Evicted "+wantMsg); n != 1 {
			t.Errorf("Warning Evicted Events = %d, want 1; events %q", n, evs)
		}

		// It is not an eviction candidate, and a repeat create runs nothing.
		if c := h.r.evictionCandidates(ctx); len(c) != 0 {
			t.Errorf("eviction candidates = %d, want 0", len(c))
		}
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("repeat CreatePod: %v", err)
		}
		h.f.mu.Lock()
		calls := h.f.createCalls
		h.f.mu.Unlock()
		if calls != 0 {
			t.Errorf("a repeat create of a rejected pod reached the runtime (%d calls)", calls)
		}
		// DeletePod finishes it.
		if err := h.r.DeletePod(ctx, pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if h.r.trackByID(string(pod.UID)) != nil {
			t.Error("the rejected pod is still tracked after DeletePod")
		}
	})

	admitted := []struct {
		name string
		pod  func() *corev1.Pod
	}{
		{"a Burstable pod", func() *corev1.Pod { return evPod("burst", nil, "64Mi", "") }},
		{"a Guaranteed pod", func() *corev1.Pod {
			p := evPod("guar", nil, "64Mi", "64Mi")
			p.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("100m")
			p.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = resource.MustParse("100m")
			return p
		}},
		{"a critical BestEffort pod (system-critical priority)", func() *corev1.Pod { return evPod("crit", prio(2000000000), "", "") }},
		{"a BestEffort pod tolerating the memory-pressure taint (Exists)", func() *corev1.Pod {
			p := evPod("tol-exists", nil, "", "")
			p.Spec.Tolerations = []corev1.Toleration{{Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
			return p
		}},
		{"a BestEffort pod tolerating it by Equal with no value and no effect", func() *corev1.Pod {
			p := evPod("tol-equal", nil, "", "")
			p.Spec.Tolerations = []corev1.Toleration{{Key: "node.kubernetes.io/memory-pressure"}}
			return p
		}},
		{"a BestEffort pod tolerating everything", func() *corev1.Pod {
			p := evPod("tol-all", nil, "", "")
			p.Spec.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpExists}}
			return p
		}},
	}
	for _, c := range admitted {
		t.Run(c.name+" is admitted under MemoryPressure", func(t *testing.T) {
			h := admissionHarness(t, pressured)
			pod := c.pod()
			if n := createOn(t, h, pod); n != 1 {
				t.Fatalf("runtime CreatePod calls = %d, want 1 (admitted)", n)
			}
			if t2 := h.r.trackByID(string(pod.UID)); t2 == nil || t2.evictedStatus() != nil {
				t.Errorf("the admitted pod carries a terminal status")
			}
		})
	}

	refused := []struct {
		name string
		tols []corev1.Toleration
	}{
		{"a BestEffort pod tolerating only DiskPressure", []corev1.Toleration{{Key: "node.kubernetes.io/disk-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}},
		{"a BestEffort pod tolerating memory-pressure NoExecute only", []corev1.Toleration{{Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute}}},
		{"a BestEffort pod tolerating memory-pressure with a value", []corev1.Toleration{{Key: "node.kubernetes.io/memory-pressure", Value: "x", Effect: corev1.TaintEffectNoSchedule}}},
		{"a BestEffort pod just under system-critical priority", nil},
	}
	for _, c := range refused {
		t.Run(c.name+" is refused", func(t *testing.T) {
			h := admissionHarness(t, pressured)
			pod := evPod("be", nil, "", "")
			if c.tols == nil {
				pod.Spec.Priority = prio(2000000000 - 1)
			}
			pod.Spec.Tolerations = c.tols
			if n := createOn(t, h, pod); n != 0 {
				t.Fatalf("runtime CreatePod calls = %d, want 0 (refused)", n)
			}
			st, err := h.r.GetPodStatus(ctx, pod.Namespace, pod.Name)
			if err != nil || st.Reason != "Evicted" {
				t.Fatalf("status = %+v, %v; want reason Evicted", st, err)
			}
		})
	}

	t.Run("a BestEffort pod is admitted on a calm node", func(t *testing.T) {
		h := admissionHarness(t, compressorAt(10))
		if n := createOn(t, h, evPod("be", nil, "", "")); n != 1 {
			t.Fatalf("runtime CreatePod calls = %d, want 1", n)
		}
	})

	t.Run("before admission is wired nothing is refused", func(t *testing.T) {
		h := newEvictionHarness(t)
		h.sm.set(pressured)
		h.mon.sampleOnce()
		if n := createOn(t, h, evPod("be", nil, "", "")); n != 1 {
			t.Fatalf("runtime CreatePod calls = %d, want 1", n)
		}
	})

	t.Run("an admitted pod is not judged again on a repeat create under pressure", func(t *testing.T) {
		h := admissionHarness(t, compressorAt(10))
		pod := evPod("be", nil, "", "")
		if n := createOn(t, h, pod); n != 1 {
			t.Fatalf("first create: runtime calls = %d, want 1", n)
		}
		h.sm.set(pressured)
		h.mon.sampleOnce()
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("repeat CreatePod: %v", err)
		}
		if tr := h.r.trackByID(string(pod.UID)); tr == nil || tr.evictedStatus() != nil {
			t.Error("a running pod was rejected by a repeat create")
		}
	})
}

// TestPodBandDerivation pins the bands: critical from priority (isCriticalPod),
// which no annotation lowers past nor raises to; batch only by the exact
// annotation; standard for everything else.
func TestPodBandDerivation(t *testing.T) {
	ann := func(p *corev1.Pod, v string) *corev1.Pod {
		p.Annotations = map[string]string{budgetv1alpha1.AnnotationBand: v}
		return p
	}
	cases := []struct {
		name string
		pod  *corev1.Pod
		want budgetv1alpha1.Band
	}{
		{"unmarked, default priority", evPod("a", nil, "", ""), budgetv1alpha1.BandStandard},
		{"batch annotation", ann(evPod("a", nil, "", ""), "batch"), budgetv1alpha1.BandBatch},
		{"batch annotation, high but not critical priority", ann(evPod("a", prio(1000000000), "", ""), "batch"), budgetv1alpha1.BandBatch},
		{"system-critical priority", evPod("a", prio(2000000000), "", ""), budgetv1alpha1.BandCritical},
		{"system-critical priority ignores batch", ann(evPod("a", prio(2000001000), "", ""), "batch"), budgetv1alpha1.BandCritical},
		{"static pod ignores batch", func() *corev1.Pod {
			p := ann(evPod("a", nil, "", ""), "batch")
			p.Annotations["kubernetes.io/config.source"] = "file"
			return p
		}(), budgetv1alpha1.BandCritical},
		{"critical annotation cannot raise", ann(evPod("a", nil, "", ""), "critical"), budgetv1alpha1.BandStandard},
		{"standard annotation", ann(evPod("a", nil, "", ""), "standard"), budgetv1alpha1.BandStandard},
		{"misspelt Batch", ann(evPod("a", nil, "", ""), "Batch"), budgetv1alpha1.BandStandard},
		{"batch with a space", ann(evPod("a", nil, "", ""), "batch "), budgetv1alpha1.BandStandard},
		{"empty value", ann(evPod("a", nil, "", ""), ""), budgetv1alpha1.BandStandard},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bandOf(c.pod); got != c.want {
				t.Errorf("bandOf = %s, want %s", got, c.want)
			}
		})
	}

	// The classifier cannot derive batch for an unmarked pod, whatever its QoS,
	// priority or other annotations (ruling (f)).
	t.Run("an unmarked pod is never batch", func(t *testing.T) {
		qos := map[string]func() *corev1.Pod{
			"BestEffort": func() *corev1.Pod { return evPod("p", nil, "", "") },
			"Burstable":  func() *corev1.Pod { return evPod("p", nil, "64Mi", "") },
			"Guaranteed": func() *corev1.Pod {
				p := evPod("p", nil, "64Mi", "64Mi")
				p.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("1")
				p.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = resource.MustParse("1")
				return p
			},
		}
		prios := []*int32{nil, prio(-10), prio(0), prio(1000), prio(1000000000), prio(2000000000)}
		others := []map[string]string{nil, {"budget.k3sm.io/page": "true"}, {"k3sm.io/anything": "batch"}}
		for qn, mk := range qos {
			for _, pr := range prios {
				for _, o := range others {
					p := mk()
					p.Spec.Priority = pr
					p.Annotations = o
					if got := bandOf(p); got == budgetv1alpha1.BandBatch {
						t.Errorf("unmarked %s pod (priority %v, annotations %v) derived batch", qn, pr, o)
					}
				}
			}
		}
	})
}

// TestBatchRefusedAtBudgetCritical pins the budget rule: at the critical level
// or above a batch-band pod is refused with k3sm's reason; below it, and for
// every other band, it is admitted; the memory-pressure rule runs first.
func TestBatchRefusedAtBudgetCritical(t *testing.T) {
	batch := func(name string, pr *int32, req string) *corev1.Pod {
		p := evPod(name, pr, req, "")
		p.Annotations = map[string]string{budgetv1alpha1.AnnotationBand: "batch"}
		return p
	}
	cases := []struct {
		name       string
		s          hostStats
		pod        *corev1.Pod
		wantReason string // "" means admitted
		wantMsg    string
	}{
		{"batch at critical", compressorAt(72), batch("b", nil, "64Mi"), "NodeBudgetCritical", "The node budget is at level critical; pods in the batch band are not admitted. "},
		{"batch at evict-soft (evicting)", compressorAt(77), batch("b", nil, "64Mi"), "NodeBudgetCritical", "The node budget is at level evicting; pods in the batch band are not admitted. "},
		{"batch at warn (admit-stop)", compressorAt(62), batch("b", nil, "64Mi"), "", ""},
		{"batch on a calm node", compressorAt(10), batch("b", nil, "64Mi"), "", ""},
		{"standard at critical", compressorAt(72), evPod("s", nil, "64Mi", ""), "", ""},
		{"BestEffort standard at critical, no MemoryPressure", compressorAt(72), evPod("s", nil, "", ""), "", ""},
		{"critical batch-annotated at critical", compressorAt(72), batch("c", prio(2000000000), ""), "", ""},
		{"BestEffort batch under MemoryPressure gets upstream's rejection", compressorAt(85), batch("b", nil, ""), "Evicted", "The node had condition: [MemoryPressure]. "},
		{"Burstable batch under MemoryPressure gets the budget rejection", compressorAt(85), batch("b", nil, "64Mi"), "NodeBudgetCritical", "The node budget is at level evicting; pods in the batch band are not admitted. "},
	}
	for _, c := range cases {
		t.Run(c.name+" (pure)", func(t *testing.T) {
			res := admitPod(c.pod, c.s, true)
			if res.admit != (c.wantReason == "") || res.reason != c.wantReason || res.message != c.wantMsg {
				t.Errorf("admitPod = %+v, want reason %q message %q", res, c.wantReason, c.wantMsg)
			}
		})
	}
	t.Run("no snapshot admits everything", func(t *testing.T) {
		if res := admitPod(batch("b", nil, ""), hostStats{}, false); !res.admit {
			t.Errorf("admitPod with no snapshot = %+v, want admit", res)
		}
	})
	t.Run("a refused batch pod reports the rejection through the provider", func(t *testing.T) {
		h := admissionHarness(t, compressorAt(72))
		pod := batch("b", nil, "64Mi")
		if n := createOn(t, h, pod); n != 0 {
			t.Fatalf("runtime CreatePod calls = %d, want 0", n)
		}
		st, err := h.r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		want := "Pod was rejected: The node budget is at level critical; pods in the batch band are not admitted. "
		if st.Phase != corev1.PodFailed || st.Reason != "NodeBudgetCritical" || st.Message != want || st.QOSClass != corev1.PodQOSBurstable {
			t.Errorf("status = %s/%q/%q/%s, want Failed/NodeBudgetCritical/%q/Burstable", st.Phase, st.Reason, st.Message, st.QOSClass, want)
		}
		// The persisted rejection is a fence: a fresh provider object for the
		// same pod is never created.
		live, err := h.cs.CoreV1().Pods(pod.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("apiserver get: %v", err)
		}
		if !isBudgetRejectedPod(live) {
			t.Errorf("apiserver status %s/%q is not the persisted rejection", live.Status.Phase, live.Status.Reason)
		}
	})
}

// idRecordingRuntime is the strict fake with every pod-id RPC the tests below
// care about recorded, so a test can assert the runtime was never asked about
// a pod.
type idRecordingRuntime struct {
	*fakeRuntimeServer
	mu  sync.Mutex
	ids []string
}

func (r *idRecordingRuntime) note(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
}

func (r *idRecordingRuntime) asked(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.ids, id)
}

func (r *idRecordingRuntime) GetPodStatus(ctx context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	r.note(req.GetPodId())
	return r.fakeRuntimeServer.GetPodStatus(ctx, req)
}

func (r *idRecordingRuntime) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	r.note(req.GetPodId())
	return r.fakeRuntimeServer.DeletePod(ctx, req)
}

func (r *idRecordingRuntime) ReopenContainerLog(ctx context.Context, req *runtimev1.ReopenContainerLogRequest) (*runtimev1.ReopenContainerLogResponse, error) {
	r.note(req.GetPodId())
	return r.fakeRuntimeServer.ReopenContainerLog(ctx, req)
}

// rejectedHarness is an admission harness under MemoryPressure holding one
// BestEffort pod refused at admission, with its runtime calls recorded from
// the refusal on.
func rejectedHarness(t *testing.T) (*evictionHarness, *idRecordingRuntime, *corev1.Pod) {
	t.Helper()
	h := admissionHarness(t, compressorAt(85))
	rec := &idRecordingRuntime{fakeRuntimeServer: h.f}
	h.r.rt = rec
	pod := evPod("be", nil, "", "")
	if n := createOn(t, h, pod); n != 0 {
		t.Fatalf("runtime CreatePod calls = %d, want 0", n)
	}
	if tr := h.r.trackByID(string(pod.UID)); tr == nil || !tr.rejected {
		t.Fatal("the pod is not tracked as rejected")
	}
	return h, rec, pod
}

// TestAdmissionConcurrentCreatesRefuseTogether: two CreatePods racing for one
// pod under MemoryPressure are both refused; neither reaches the runtime, and
// the pod ends with one rejected track.
func TestAdmissionConcurrentCreatesRefuseTogether(t *testing.T) {
	h := admissionHarness(t, compressorAt(85))
	ctx := context.Background()
	for i := range 50 {
		pod := evPod("race-"+strconv.Itoa(i), nil, "", "")
		if _, err := h.cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
			t.Fatalf("apiserver create: %v", err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for g := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[g] = h.r.CreatePod(ctx, pod.DeepCopy())
			}()
		}
		wg.Wait()
		for g, err := range errs {
			if err != nil {
				t.Fatalf("pod %s: CreatePod %d: %v", pod.Name, g, err)
			}
		}
		if tr := h.r.trackByID(string(pod.UID)); tr == nil || !tr.rejected {
			t.Fatalf("pod %s: not tracked as rejected", pod.Name)
		}
	}
	h.f.mu.Lock()
	calls := h.f.createCalls
	h.f.mu.Unlock()
	if calls != 0 {
		t.Errorf("runtime CreatePod calls = %d across the races, want 0", calls)
	}
}

// TestRejectedPodOrphanReap: a rejected pod the apiserver no longer holds is
// forgotten by the orphan reaper after the usual threshold, without a runtime
// call for it.
func TestRejectedPodOrphanReap(t *testing.T) {
	h, rec, pod := rejectedHarness(t)
	h.r.podSource = &fakePodSource{got: map[string]*corev1.Pod{}}
	ctx := context.Background()
	for range orphanReapThreshold {
		if h.r.trackByID(string(pod.UID)) == nil {
			t.Fatal("reaped before the threshold")
		}
		h.r.reapOrphans(ctx)
	}
	if h.r.trackByID(string(pod.UID)) != nil {
		t.Error("the rejected pod is still tracked after the reap threshold")
	}
	h.r.orphanMu.Lock()
	_, gauge := h.r.orphanGauges[string(pod.UID)]
	h.r.orphanMu.Unlock()
	if gauge {
		t.Error("the reaped pod's gauge was kept")
	}
	if rec.asked(string(pod.UID)) {
		t.Errorf("the runtime was asked about the rejected pod: %v", rec.ids)
	}
}

// TestRejectedPodLogs: kubectl logs for a rejected pod answers the kubelet's
// "not available" for a container with no status, and neither the read nor the
// log rotation asks the runtime about the pod.
func TestRejectedPodLogs(t *testing.T) {
	h, rec, pod := rejectedHarness(t)
	ctx := context.Background()
	_, err := h.r.GetContainerLogs(ctx, pod.Namespace, pod.Name, "c0", nil)
	if want := `container "c0" in pod "be" is not available`; err == nil || err.Error() != want {
		t.Errorf("GetContainerLogs error = %v, want %q", err, want)
	}
	follow := &corev1.PodLogOptions{Follow: true}
	rc, err := h.r.GetContainerLogs(ctx, pod.Namespace, pod.Name, "c0", follow)
	if err != nil {
		t.Fatalf("follow GetContainerLogs: %v", err)
	}
	if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "is not available") {
		t.Errorf("follow read error = %v, want the not-available answer", err)
	}
	_ = rc.Close()
	refs, err := h.r.RunningContainerLogs(ctx)
	if err != nil || len(refs) != 0 {
		t.Errorf("RunningContainerLogs = %v, %v; want none", refs, err)
	}
	if _, err := h.r.ContainerLog(ctx, "no-such-container"); err == nil {
		t.Error("ContainerLog found a container for no pod")
	}
	if rec.asked(string(pod.UID)) {
		t.Errorf("the runtime was asked about the rejected pod: %v", rec.ids)
	}
}
