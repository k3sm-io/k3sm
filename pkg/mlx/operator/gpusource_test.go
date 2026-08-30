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

package operator

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeRuntimeInfo is a stand-in for the node's runtime: one GetRuntimeInfo RPC,
// answered from a fixed response or a fixed error, counting its calls so the
// caching contract is observable.
//
// It is driven from the test goroutine only, so the unsynchronized counter is
// race-clean under -race.
type fakeRuntimeInfo struct {
	resp  *runtimev1.GetRuntimeInfoResponse
	err   error
	calls int
}

func (f *fakeRuntimeInfo) GetRuntimeInfo(context.Context, *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// warnLog returns a logger that captures Warn-level records, plus the buffer to
// read them back from.
func warnLog() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})), buf
}

// TestServerPathFitCheckUsesLiveGPUFacts is the B195 gate: the server path's fit
// check runs against the node's LIVE GPU facts, read from the same
// GetRuntimeInfo the node path's capability probe calls.
//
// Before this wiring the server built the operator with a nil GPUSource, so
// ValidateFit was skipped in production — the whole M8.5 refusal path existed,
// was mutant-tested, and could not fire on the only path that ships it. The
// first subtest is therefore the one that matters: an unfittable spec reaching a
// LIVE source must be refused before anything is applied. The remaining subtests
// pin the other half of the contract, which is just as load bearing: a source
// that cannot answer must DEGRADE to the documented skip, never refuse a model
// and never crash the reconcile.
func TestServerPathFitCheckUsesLiveGPUFacts(t *testing.T) {
	// The node's facts: plenty of host memory and working set, but an explicitly
	// configured iogpu wired limit well under the spec's 24Gi. That combination is
	// the realistic one — a large model is bounded by the wired limit long before
	// it is bounded by the machine — and it makes the refusal provably come from
	// the LIVE numbers rather than from a degenerate all-zero fact set.
	live := facts(func(f *runtimev1.GPUFacts) { f.IogpuWiredLimitBytes = uint64(8 * gib) })

	t.Run("live facts refuse an unfittable spec and apply nothing", func(t *testing.T) {
		log, warnings := warnLog()
		src := &fakeRuntimeInfo{resp: &runtimev1.GetRuntimeInfoResponse{Gpu: live}}
		gpu := NewRuntimeGPU(log)
		gpu.Attach(src)

		h := newHarness(t, model(), func(c *Config) { c.GPU = gpu })
		h.reconcile(t)

		if src.calls == 0 {
			t.Fatal("the reconcile never asked the runtime for gpu facts; the fit check is not reading the live source")
		}
		if sts := h.statefulSet(t); sts != nil {
			t.Error("a StatefulSet was applied for a spec the node's live gpu facts cannot fund")
		}
		pods, err := h.kube.CoreV1().Pods(testNamespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatalf("list pods: %v", err)
		}
		if len(pods.Items) != 0 {
			t.Errorf("%d pods exist for a refused spec, want 0", len(pods.Items))
		}
		for _, action := range h.kube.Actions() {
			if action.GetVerb() == "patch" {
				t.Errorf("an object (%s) was applied for a refused spec", action.GetResource().Resource)
			}
		}

		status := h.status(t)
		if status.Phase != mlxv1alpha1.MLXModelPhaseFailed {
			t.Errorf("phase = %q, want Failed", status.Phase)
		}
		ready := meta.FindStatusCondition(status.Conditions, mlxv1alpha1.MLXModelConditionReady)
		if ready == nil || ready.Status != metav1.ConditionFalse {
			t.Fatalf("Ready condition = %+v, want False", ready)
		}
		if ready.Reason != ReasonMemoryExceedsWiredLimit {
			t.Errorf("Ready reason = %q, want %q — the refusal must name the live wired limit, not a coincidence",
				ready.Reason, ReasonMemoryExceedsWiredLimit)
		}
		if !strings.Contains(ready.Message, "8Gi") {
			t.Errorf("message %q does not name the live wired limit the spec was compared against", ready.Message)
		}
		if warnings.Len() != 0 {
			t.Errorf("a degradation was logged for a source that answered: %s", warnings.String())
		}
	})

	t.Run("a fittable spec is applied against the same live facts", func(t *testing.T) {
		log, _ := warnLog()
		src := &fakeRuntimeInfo{resp: &runtimev1.GetRuntimeInfoResponse{Gpu: live}}
		gpu := NewRuntimeGPU(log)
		gpu.Attach(src)

		fits := model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.MustParse("4Gi") })
		h := newHarness(t, fits, func(c *Config) { c.GPU = gpu })
		h.reconcile(t)

		if sts := h.statefulSet(t); sts == nil {
			t.Fatal("no StatefulSet was applied for a spec the live facts DO fund; a live source must not refuse everything")
		}
	})

	t.Run("a probe error skips the check with a warning", func(t *testing.T) {
		log, warnings := warnLog()
		src := &fakeRuntimeInfo{err: errors.New("dial runtimed: connection refused")}
		gpu := NewRuntimeGPU(log)
		gpu.Attach(src)

		// The spec is the one the live facts REFUSE. With the source unable to
		// answer, the fit check must be skipped rather than resolved either way —
		// so this reconciling to applied objects is exactly the documented
		// nil-means-skip posture, and a panic here is the crash this wiring must
		// not introduce.
		h := newHarness(t, model(), func(c *Config) { c.GPU = gpu })
		h.reconcile(t)

		if sts := h.statefulSet(t); sts == nil {
			t.Error("a probe error blocked the reconcile; an unreachable runtime must degrade to skip, not refuse the model")
		}
		if status := h.status(t); status.Phase == mlxv1alpha1.MLXModelPhaseFailed {
			t.Error("a probe error produced a Failed status; unknown facts are not a failed fit")
		}
		assertWarned(t, warnings, "could not be asked")
	})

	t.Run("an unattached source skips the check with a warning", func(t *testing.T) {
		log, warnings := warnLog()
		gpu := NewRuntimeGPU(log) // the bring-up window: the node has not published its runtime yet

		h := newHarness(t, model(), func(c *Config) { c.GPU = gpu })
		h.reconcile(t)

		if sts := h.statefulSet(t); sts == nil {
			t.Error("an unattached source blocked the reconcile; it must behave exactly as the nil source did")
		}
		assertWarned(t, warnings, "no runtime connection is wired yet")
	})

	t.Run("a daemon reporting no gpu facts skips the check with a warning", func(t *testing.T) {
		log, warnings := warnLog()
		src := &fakeRuntimeInfo{resp: &runtimev1.GetRuntimeInfoResponse{}} // an older daemon: no gpu message at all
		gpu := NewRuntimeGPU(log)
		gpu.Attach(src)

		h := newHarness(t, model(), func(c *Config) { c.GPU = gpu })
		h.reconcile(t)

		if sts := h.statefulSet(t); sts == nil {
			t.Error("a daemon that reports no gpu facts blocked the reconcile; absent facts are a skip")
		}
		assertWarned(t, warnings, "no gpu facts at all")
	})
}

// assertWarned fails unless the captured log carries a warning containing want.
// The skip is only safe because it is VISIBLE: a fit check that silently stops
// running is indistinguishable from one that is passing every spec.
func assertWarned(t *testing.T, warnings *bytes.Buffer, want string) {
	t.Helper()
	if got := warnings.String(); !strings.Contains(got, want) {
		t.Errorf("no warning naming %q was logged for a skipped fit check; got: %s", want, got)
	}
}

// TestRuntimeGPUCachesTheNearStaticFacts pins the read cadence: the facts are
// read ONCE and reused.
//
// The daemon derives them a single time in its own constructor, so a per-reconcile
// read would spend an RPC per model per pass to receive the same answer. A FAILED
// read is deliberately not cached — the failure describes reachability, not the
// host — so a runtime that becomes reachable is picked up without a restart.
func TestRuntimeGPUCachesTheNearStaticFacts(t *testing.T) {
	t.Run("a successful read is cached", func(t *testing.T) {
		src := &fakeRuntimeInfo{resp: &runtimev1.GetRuntimeInfoResponse{Gpu: facts()}}
		log, _ := warnLog()
		gpu := NewRuntimeGPU(log)
		gpu.Attach(src)

		for range 3 {
			if got := gpu.GPUFacts(t.Context()); got == nil {
				t.Fatal("GPUFacts returned nil for a source that answered")
			}
		}
		if src.calls != 1 {
			t.Errorf("the runtime was asked %d times, want 1; the facts are near-static and re-reading them costs an RPC per model per pass", src.calls)
		}
	})

	t.Run("a failed read is retried", func(t *testing.T) {
		src := &fakeRuntimeInfo{err: errors.New("connection refused")}
		log, _ := warnLog()
		gpu := NewRuntimeGPU(log)
		gpu.Attach(src)

		if got := gpu.GPUFacts(t.Context()); got != nil {
			t.Fatalf("GPUFacts returned %v after a probe error, want nil (skip)", got)
		}
		src.err = nil
		src.resp = &runtimev1.GetRuntimeInfoResponse{Gpu: facts()}
		if got := gpu.GPUFacts(t.Context()); got == nil {
			t.Error("a runtime that became reachable was never re-asked; an error must not be cached as an answer")
		}
	})

	t.Run("a re-attach re-reads", func(t *testing.T) {
		first := &fakeRuntimeInfo{resp: &runtimev1.GetRuntimeInfoResponse{Gpu: facts()}}
		log, _ := warnLog()
		gpu := NewRuntimeGPU(log)
		gpu.Attach(first)
		_ = gpu.GPUFacts(t.Context())

		second := &fakeRuntimeInfo{resp: &runtimev1.GetRuntimeInfoResponse{Gpu: facts(func(f *runtimev1.GPUFacts) { f.MemBytes = uint64(16 * gib) })}}
		gpu.Attach(second)
		got := gpu.GPUFacts(t.Context())
		if got == nil || got.GetMemBytes() != uint64(16*gib) {
			t.Errorf("after Attach the cached answer from the previous source was still served: %v", got)
		}
	})

	t.Run("a nil attach detaches without panicking", func(t *testing.T) {
		log, warnings := warnLog()
		gpu := NewRuntimeGPU(log)
		gpu.Attach(nil)
		if got := gpu.GPUFacts(t.Context()); got != nil {
			t.Errorf("GPUFacts returned %v with no source, want nil", got)
		}
		assertWarned(t, warnings, "no runtime connection is wired yet")
	})
}
