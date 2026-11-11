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
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// recordedEvent is one Eventf call the fake recorder saw.
type recordedEvent struct {
	object    runtime.Object
	eventType string
	reason    string
	message   string
}

// fakeRecorder is an EventRecorder that keeps every Event in memory.
type fakeRecorder struct{ events []recordedEvent }

func (f *fakeRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...any) {
	f.events = append(f.events, recordedEvent{
		object:    object,
		eventType: eventtype,
		reason:    reason,
		message:   fmt.Sprintf(messageFmt, args...),
	})
}

// TestInvalidSpecEmitsOneEventPerGeneration pins the refusal Event: a model the
// operator will not serve gets exactly one Warning Event per generation, with
// the reason and message of its Ready condition. A reconcile retry of the same
// generation (a resync, a status write that re-enqueues it) must not add a
// second one, or `kubectl describe` fills with copies of one decision; a new
// generation is a new decision and gets its own.
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
