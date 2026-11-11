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
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// recordedEvent is one Eventf call the fake recorder saw.
type recordedEvent struct {
	object    runtime.Object
	eventType string
	reason    string
	format    string
	message   string
}

// fakeRecorder is an EventRecorder that keeps every Event in memory.
type fakeRecorder struct{ events []recordedEvent }

func (f *fakeRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...any) {
	f.events = append(f.events, recordedEvent{
		object:    object,
		eventType: eventtype,
		reason:    reason,
		format:    messageFmt,
		message:   fmt.Sprintf(messageFmt, args...),
	})
}

// TestInvalidSpecEmitsOneEventPerGeneration pins the refusal Event: a model the
// operator will not serve gets exactly one Warning Event per generation, with
// the reason and message of its Ready condition. A reconcile retry of the same
// generation (a resync, a status write that re-enqueues it) must not add a
// second one, or `kubectl describe` fills with copies of one decision; a new
// generation is a new decision and gets its own. The contract holds within one
// refusal episode: a model served in between starts a new episode, which
// records again at the same generation (see TestRefusalEventsArePerEpisode).
func TestInvalidSpecEmitsOneEventPerGeneration(t *testing.T) {
	cases := []struct {
		name   string
		model  *mlxv1alpha1.MLXModel
		cfg    func(*Config)
		reason string
	}{
		{
			name:   "invalid spec",
			model:  model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Model = "" }),
			reason: ReasonInvalidSpec,
		},
		{
			name:   "fit block",
			model:  model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.MustParse("512Gi") }),
			cfg:    func(c *Config) { c.GPU = StaticGPU(facts()) },
			reason: ReasonMemoryExceedsHostMemory,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			h := newHarness(t, tc.model, func(c *Config) {
				c.Recorder = rec
				if tc.cfg != nil {
					tc.cfg(c)
				}
			})

			h.reconcile(t)
			if len(rec.events) != 1 {
				t.Fatalf("after the first reconcile: %d events, want 1: %+v", len(rec.events), rec.events)
			}
			got := rec.events[0]
			if got.eventType != corev1.EventTypeWarning || got.reason != tc.reason {
				t.Errorf("event = %s/%s, want %s/%s", got.eventType, got.reason, corev1.EventTypeWarning, tc.reason)
			}
			ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
			if ready == nil || got.message != ready.Message {
				t.Errorf("event message = %q, want the Ready condition's %+v", got.message, ready)
			}
			obj, err := meta.Accessor(got.object)
			if err != nil {
				t.Fatalf("event object: %v", err)
			}
			if obj.GetUID() != tc.model.UID || obj.GetName() != testModelName || obj.GetNamespace() != testNamespace {
				t.Errorf("event is on %s/%s (uid %s), want the model", obj.GetNamespace(), obj.GetName(), obj.GetUID())
			}

			h.reconcile(t)
			if len(rec.events) != 1 {
				t.Fatalf("after a second reconcile of the same generation: %d events, want still 1", len(rec.events))
			}

			h.bumpGeneration(t)
			h.reconcile(t)
			if len(rec.events) != 2 {
				t.Fatalf("after the generation changed: %d events, want 2", len(rec.events))
			}
			if rec.events[1].reason != tc.reason {
				t.Errorf("second event reason = %q, want %q", rec.events[1].reason, tc.reason)
			}
		})
	}
}

// TestRefusalEventMessageIsBoundedAndVerbatim pins the Event message: the API
// server rejects an Event message over 1024 characters, so a long refusal
// message is cut to at most maxEventMessageBytes on a rune boundary, and a
// message carrying printf verbs arrives as written, because it is an argument
// and never the format.
func TestRefusalEventMessageIsBoundedAndVerbatim(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    string
	}{
		{name: "short", message: "spec.model is empty", want: "spec.model is empty"},
		{name: "percent verbs", message: "100% of %d %s %!x(BADPREC)", want: "100% of %d %s %!x(BADPREC)"},
		{name: "long ascii", message: strings.Repeat("a", 2000), want: strings.Repeat("a", maxEventMessageBytes)},
		{
			// 999 one-byte runes then two-byte ones: byte 1000 is the middle of
			// the first two-byte rune, so the cut must back off to 999.
			name:    "long multibyte split at the bound",
			message: strings.Repeat("a", 999) + strings.Repeat("\u00e9", 100),
			want:    strings.Repeat("a", 999),
		},
		{name: "exactly at the bound", message: strings.Repeat("a", 1000), want: strings.Repeat("a", 1000)},
		{name: "one byte over the bound", message: strings.Repeat("a", 1001), want: strings.Repeat("a", 1000)},
		{
			// U+20AC is three bytes at 998..1000: the cut backs off to 998.
			name:    "three-byte rune straddling the bound",
			message: strings.Repeat("a", 998) + "€",
			want:    strings.Repeat("a", 998),
		},
		{
			// U+1F600 is four bytes at 997..1000: the cut backs off to 997.
			name:    "four-byte rune straddling the bound",
			message: strings.Repeat("a", 997) + "\U0001F600",
			want:    strings.Repeat("a", 997),
		},
		{
			// U+1F600 at 999..1002: byte 1000 is its second byte.
			name:    "four-byte rune starting just under the bound",
			message: strings.Repeat("a", 999) + "\U0001F600",
			want:    strings.Repeat("a", 999),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			h := newHarness(t, nil, nil)
			m := model()
			raw, err := toUnstructured(m)
			if err != nil {
				t.Fatalf("encode model: %v", err)
			}
			h.ctrl.recordRefusal(rec, raw, m, ReasonInvalidSpec, tc.message)
			if len(rec.events) != 1 {
				t.Fatalf("%d events, want 1", len(rec.events))
			}
			got := rec.events[0]
			if got.format != "%s" {
				t.Errorf("format = %q, want %q: the message must be an argument", got.format, "%s")
			}
			if got.message != tc.want {
				t.Errorf("message = %q (%d bytes), want %q (%d bytes)", got.message, len(got.message), tc.want, len(tc.want))
			}
			if len(got.message) > maxEventMessageBytes || !utf8.ValidString(got.message) {
				t.Errorf("message is %d bytes, valid UTF-8 %v; want at most %d and valid", len(got.message), utf8.ValidString(got.message), maxEventMessageBytes)
			}
		})
	}
}

// TestReconcileWithoutARecorderRecordsNothing pins the nil recorder: a
// Controller called outside Run with no Config.Recorder still refuses (the
// status is written) and does not panic.
func TestReconcileWithoutARecorderRecordsNothing(t *testing.T) {
	h := newHarness(t, model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Model = "" }), nil)
	h.reconcile(t)
	h.reconcile(t)
	ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
	if ready == nil || ready.Reason != ReasonInvalidSpec {
		t.Fatalf("Ready = %+v, want reason %s", ready, ReasonInvalidSpec)
	}
	if n := len(h.ctrl.refusals); n != 0 {
		t.Errorf("refusals holds %d entries with no recorder, want 0", n)
	}
}

// TestRunRecorderIsScopedToRun pins the recorder's lifetime: Run with no
// Config.Recorder records refusal Events through a broadcaster of its own and
// shuts it down on return, so it must not leave that recorder on the
// Controller for a later Run or Reconcile to write through.
func TestRunRecorderIsScopedToRun(t *testing.T) {
	h := newHarness(t, model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Model = "" }), nil)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- h.ctrl.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		list, err := h.kube.CoreV1().Events(testNamespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false
		}
		for _, e := range list.Items {
			if e.Reason == ReasonInvalidSpec && e.InvolvedObject.Name == testModelName {
				return true
			}
		}
		return false
	}, "Run never recorded the refusal Event")

	cancel()
	if err := <-runDone; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if h.ctrl.recorder != nil {
		t.Errorf("Run left its recorder on the Controller: %T", h.ctrl.recorder)
	}
}

// TestArtifactResolutionFailureEventReason pins the Event reason of the
// artifact branch: the status stays InvalidSpec, but the Event says
// ArtifactUnresolved, because a registry outage is retried and is not a bad
// spec. A render failure keeps InvalidSpec for both.
func TestArtifactResolutionFailureEventReason(t *testing.T) {
	t.Run("registry error", func(t *testing.T) {
		rec := &fakeRecorder{}
		outage := ArtifactResolverFunc(func(context.Context, string, string, string) (string, error) {
			return "", errors.New("registry-k3sm:6450: connection refused")
		})
		h := artifactHarness(t, testRegistryHost+"/models/qwen3:v1", outage)
		h.ctrl.recorder = rec
		if err := h.ctrl.Reconcile(context.Background(), key()); err == nil {
			t.Fatal("Reconcile returned nil for a registry outage, want the transient error")
		}
		assertArtifactUnresolved(t, h, rec)
	})
	t.Run("registry error retried at one generation", func(t *testing.T) {
		rec := &fakeRecorder{}
		outage := ArtifactResolverFunc(func(context.Context, string, string, string) (string, error) {
			return "", errors.New("registry-k3sm:6450: connection refused")
		})
		h := artifactHarness(t, testRegistryHost+"/models/qwen3:v1", outage)
		h.ctrl.recorder = rec
		for i := range 2 {
			if err := h.ctrl.Reconcile(context.Background(), key()); err == nil {
				t.Fatalf("reconcile %d returned nil for a registry outage, want the transient error", i+1)
			}
		}
		assertArtifactUnresolved(t, h, rec)
	})
	t.Run("no resolver", func(t *testing.T) {
		rec := &fakeRecorder{}
		h := artifactHarness(t, testRegistryHost+"/models/qwen3:v1", nil)
		h.ctrl.recorder = rec
		h.reconcile(t)
		assertArtifactUnresolved(t, h, rec)
	})
	t.Run("render failure", func(t *testing.T) {
		rec := &fakeRecorder{}
		h := newHarness(t, model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Model = "" }), func(c *Config) { c.Recorder = rec })
		h.reconcile(t)
		if len(rec.events) != 1 || rec.events[0].reason != ReasonInvalidSpec {
			t.Fatalf("events = %+v, want one %s", rec.events, ReasonInvalidSpec)
		}
	})
}

func assertArtifactUnresolved(t *testing.T, h *harness, rec *fakeRecorder) {
	t.Helper()
	ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
	if ready == nil || ready.Reason != ReasonInvalidSpec {
		t.Errorf("Ready = %+v, want the status reason to stay %s", ready, ReasonInvalidSpec)
	}
	if len(rec.events) != 1 {
		t.Fatalf("%d events, want 1: %+v", len(rec.events), rec.events)
	}
	if got := rec.events[0]; got.reason != eventReasonArtifactUnresolved || got.eventType != corev1.EventTypeWarning {
		t.Errorf("event = %s/%s, want %s/%s", got.eventType, got.reason, corev1.EventTypeWarning, eventReasonArtifactUnresolved)
	}
	if ready != nil && rec.events[0].message != ready.Message {
		t.Errorf("event message = %q, want the Ready condition's %q", rec.events[0].message, ready.Message)
	}
}

// switchGPU is a GPUSource a test flips between facts, standing in for a node
// whose GPU facts change while a model's generation does not.
type switchGPU struct{ facts *runtimev1.GPUFacts }

func (g *switchGPU) GPUFacts(context.Context) *runtimev1.GPUFacts { return g.facts }

// TestRefusalEventsArePerEpisode pins the episode rule: Events are one per
// refusal episode per generation. Serving the model ends the episode, so a
// later refusal at the same generation and reason records again; within one
// episode each distinct reason records once; a model recreated under the same
// name is a new UID and records again; the memory is dropped once the model
// is gone.
func TestRefusalEventsArePerEpisode(t *testing.T) {
	tooBig := func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.MustParse("512Gi") }
	noMetal := facts(func(f *runtimev1.GPUFacts) { f.MetalAvailable = false })

	t.Run("refused served refused", func(t *testing.T) {
		rec := &fakeRecorder{}
		gpu := &switchGPU{facts: facts()}
		h := newHarness(t, model(tooBig), func(c *Config) { c.Recorder = rec; c.GPU = gpu })
		h.reconcile(t)
		gpu.facts = nil // the fit check is skipped: the model is served
		h.reconcile(t)
		if h.statefulSet(t) == nil {
			t.Fatal("the model was not served while the fit check was skipped")
		}
		gpu.facts = facts()
		h.reconcile(t)
		h.reconcile(t)
		if len(rec.events) != 2 {
			t.Fatalf("%d events, want 2 (one per refusal episode): %+v", len(rec.events), rec.events)
		}
		for i, e := range rec.events {
			if e.reason != ReasonMemoryExceedsHostMemory {
				t.Errorf("event %d reason = %s, want %s", i, e.reason, ReasonMemoryExceedsHostMemory)
			}
		}
	})

	t.Run("reason change", func(t *testing.T) {
		rec := &fakeRecorder{}
		gpu := &switchGPU{facts: facts()}
		h := newHarness(t, model(tooBig), func(c *Config) { c.Recorder = rec; c.GPU = gpu })
		for _, f := range []*runtimev1.GPUFacts{facts(), noMetal, facts(), noMetal} {
			gpu.facts = f
			h.reconcile(t)
		}
		if len(rec.events) != 2 {
			t.Fatalf("%d events, want 2 (one per reason): %+v", len(rec.events), rec.events)
		}
		if rec.events[0].reason == rec.events[1].reason {
			t.Errorf("both events have reason %s, want two distinct reasons", rec.events[0].reason)
		}
	})

	t.Run("recreated with a new uid", func(t *testing.T) {
		rec := &fakeRecorder{}
		h := newHarness(t, model(tooBig), func(c *Config) { c.Recorder = rec; c.GPU = StaticGPU(facts()) })
		h.reconcile(t)
		// Delete and recreate between two reconciles, so no reconcile sees the
		// model gone: only the UID tells the two apart.
		h.replaceModel(t, model(tooBig, func(m *mlxv1alpha1.MLXModel) { m.UID = "99999999-2222-3333-4444-555555555555" }))
		h.reconcile(t)
		if len(rec.events) != 2 {
			t.Fatalf("%d events, want 2 (one per UID): %+v", len(rec.events), rec.events)
		}
		obj, err := meta.Accessor(rec.events[1].object)
		if err != nil {
			t.Fatalf("event object: %v", err)
		}
		if obj.GetUID() != types.UID("99999999-2222-3333-4444-555555555555") {
			t.Errorf("second event is on uid %s, want the recreated model", obj.GetUID())
		}
	})

	t.Run("entry removed on deletion", func(t *testing.T) {
		rec := &fakeRecorder{}
		h := newHarness(t, model(tooBig), func(c *Config) { c.Recorder = rec; c.GPU = StaticGPU(facts()) })
		h.reconcile(t)
		if _, ok := h.ctrl.refusals[key()]; !ok {
			t.Fatal("no refusal entry after a refusal")
		}
		if err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).
			Delete(context.Background(), testModelName, metav1.DeleteOptions{}); err != nil {
			t.Fatalf("delete model: %v", err)
		}
		h.reconcile(t)
		if _, ok := h.ctrl.refusals[key()]; ok {
			t.Error("the refusal entry outlived its model")
		}
	})

	t.Run("entry removed when terminating", func(t *testing.T) {
		rec := &fakeRecorder{}
		h := newHarness(t, model(tooBig), func(c *Config) { c.Recorder = rec; c.GPU = StaticGPU(facts()) })
		h.reconcile(t)
		if _, ok := h.ctrl.refusals[key()]; !ok {
			t.Fatal("no refusal entry after a refusal")
		}
		// The API server bumps the generation when it sets the deletion
		// timestamp, so a reconcile that refused the terminating object would
		// be a new decision and record a second Event.
		res := h.dyn.Resource(mlxModelResource).Namespace(testNamespace)
		raw, err := res.Get(context.Background(), testModelName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("read mlxmodel: %v", err)
		}
		now := metav1.NewTime(time.Unix(1700000000, 0))
		raw.SetDeletionTimestamp(&now)
		raw.SetGeneration(raw.GetGeneration() + 1)
		if _, err := res.Update(context.Background(), raw, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("mark mlxmodel terminating: %v", err)
		}
		h.reconcile(t)
		if len(rec.events) != 1 {
			t.Errorf("%d events after reconciling a terminating model, want still 1: %+v", len(rec.events), rec.events)
		}
		if _, ok := h.ctrl.refusals[key()]; ok {
			t.Error("the refusal entry outlived its model's termination")
		}
	})
}

// replaceModel deletes the seeded model and creates m in its place.
func (h *harness) replaceModel(t *testing.T, m *mlxv1alpha1.MLXModel) {
	t.Helper()
	res := h.dyn.Resource(mlxModelResource).Namespace(testNamespace)
	if err := res.Delete(context.Background(), testModelName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete model: %v", err)
	}
	u, err := toUnstructured(m)
	if err != nil {
		t.Fatalf("encode model: %v", err)
	}
	if _, err := res.Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
		t.Fatalf("recreate model: %v", err)
	}
}

// TestShardedRefusalEmitsAnEvent pins that the sharded path's refusals take
// the same Event path as the single-node ones.
func TestShardedRefusalEmitsAnEvent(t *testing.T) {
	m := shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing)
	m.Spec.Replicas = ptr.To(int32(2))
	h := shardedHarness(t, m, twoMacs(), nil)
	rec := &fakeRecorder{}
	h.ctrl.recorder = rec
	h.reconcile(t)
	h.reconcile(t)
	if len(rec.events) != 1 {
		t.Fatalf("%d events, want 1: %+v", len(rec.events), rec.events)
	}
	if got := rec.events[0]; got.eventType != corev1.EventTypeWarning || got.reason != ReasonInvalidSpec {
		t.Errorf("event = %s/%s, want %s/%s", got.eventType, got.reason, corev1.EventTypeWarning, ReasonInvalidSpec)
	}
}

// TestShardedRefusalEventsArePerEpisode pins the episode rule on the sharded
// path: serving the gang ends the episode both where it is placed and where a
// whole gang is kept, so a refusal after either, at the same generation and
// reason, records again.
func TestShardedRefusalEventsArePerEpisode(t *testing.T) {
	noMetal := facts(func(f *runtimev1.GPUFacts) { f.MetalAvailable = false })
	h := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs(), nil)
	rec := &fakeRecorder{}
	gpu := &switchGPU{facts: noMetal}
	h.ctrl.recorder = rec
	h.ctrl.gpu = gpu

	h.reconcile(t) // refused: one Event
	gpu.facts = nil
	h.reconcile(t) // the gang is placed
	if len(h.rankPods(t)) == 0 {
		t.Fatal("the gang was not placed while the fit check was skipped")
	}
	gpu.facts = noMetal
	h.reconcile(t) // refused again: a new episode
	if len(rec.events) != 2 {
		t.Fatalf("after refused, placed, refused: %d events, want 2: %+v", len(rec.events), rec.events)
	}

	h.markRanks(t, true)
	gpu.facts = nil
	h.reconcile(t) // the whole gang is kept
	gpu.facts = noMetal
	h.reconcile(t) // refused again: a new episode
	if len(rec.events) != 3 {
		t.Fatalf("after a kept gang then a refusal: %d events, want 3: %+v", len(rec.events), rec.events)
	}
	for i, e := range rec.events {
		if e.reason != rec.events[0].reason {
			t.Errorf("event %d reason = %s, want %s", i, e.reason, rec.events[0].reason)
		}
	}
}

// TestFailedStatusWriteRecordsNoEvent pins the ordering: the Event follows a
// successful status write, so a write that fails records nothing and the retry
// of the same generation records exactly one.
func TestFailedStatusWriteRecordsNoEvent(t *testing.T) {
	rec := &fakeRecorder{}
	h := newHarness(t, model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Model = "" }), func(c *Config) { c.Recorder = rec })
	failures := 1
	h.dyn.PrependReactor("update", "mlxmodels", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "status" || failures == 0 {
			return false, nil, nil
		}
		failures--
		return true, nil, errors.New("apiserver unavailable")
	})
	if err := h.ctrl.Reconcile(context.Background(), key()); err == nil {
		t.Fatal("Reconcile returned nil for a failed status write")
	}
	if len(rec.events) != 0 {
		t.Fatalf("%d events after a failed status write, want 0: %+v", len(rec.events), rec.events)
	}
	h.reconcile(t)
	h.reconcile(t)
	if len(rec.events) != 1 {
		t.Fatalf("%d events after the retry, want 1: %+v", len(rec.events), rec.events)
	}
}
