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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// TestReconcileRefusesClusterStoreHubArgs pins the operator end of the
// cluster-store Hub-argument refusal: a cluster-store model whose runtime args
// name a Hub repository through --adapter-path reconciles to Ready=False with
// reason InvalidSpec and a message naming the flag, returns no error (a bad
// spec is not requeued), records one Warning Event, and applies no serving
// object. The same model with an absolute path reconciles past the refusal.
func TestReconcileRefusesClusterStoreHubArgs(t *testing.T) {
	// storeModel is a cluster-store (artifact by digest) model with args,
	// wired to rec.
	storeModel := func(rec *fakeRecorder, args ...string) *harness {
		m := model(func(m *mlxv1alpha1.MLXModel) {
			m.Spec.Model = ""
			m.Spec.Artifact = &mlxv1alpha1.ArtifactRef{Reference: testRegistryHost + "/models/qwen3@" + testDigestA}
			m.Spec.Runtime.Args = args
		})
		return newHarness(t, m, func(c *Config) {
			c.Options.RegistryHost = testRegistryHost
			c.Artifacts = &countingResolver{digest: testDigestA}
			c.Recorder = rec
		})
	}

	t.Run("hub repo id is refused", func(t *testing.T) {
		rec := &fakeRecorder{}
		h := storeModel(rec, "--adapter-path", "org/adapter")

		if err := h.ctrl.Reconcile(context.Background(), key()); err != nil {
			t.Fatalf("Reconcile returned a transient error for a permanently bad spec: %v", err)
		}
		ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
		if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != ReasonInvalidSpec {
			t.Fatalf("Ready = %+v, want False/%s", ready, ReasonInvalidSpec)
		}
		if !hasReason(h.status(t), ReasonInvalidSpec, "--adapter-path") {
			t.Errorf("Ready message %q does not name --adapter-path", ready.Message)
		}
		if len(rec.events) != 1 {
			t.Fatalf("%d events, want 1: %+v", len(rec.events), rec.events)
		}
		if got := rec.events[0]; got.eventType != corev1.EventTypeWarning || got.reason != ReasonInvalidSpec {
			t.Errorf("event = %s/%s, want %s/%s", got.eventType, got.reason, corev1.EventTypeWarning, ReasonInvalidSpec)
		}
		if sts := h.statefulSet(t); sts != nil {
			t.Error("a StatefulSet was applied for a refused cluster-store model")
		}
		for _, action := range h.kube.Actions() {
			switch action.GetVerb() {
			case "create", "update", "patch":
				t.Errorf("%s %s for a refused cluster-store model", action.GetVerb(), action.GetResource().Resource)
			}
		}
	})

	t.Run("absolute path passes the refusal", func(t *testing.T) {
		h := storeModel(&fakeRecorder{}, "--adapter-path", "/models/adapter")
		h.reconcile(t)
		if hasReason(h.status(t), ReasonInvalidSpec, "") {
			t.Fatalf("status = %+v, want past the InvalidSpec refusal", h.status(t))
		}
		if h.statefulSet(t) == nil {
			t.Error("no StatefulSet applied for a cluster-store model with an absolute adapter path")
		}
	})
}
