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

package mlx

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

const (
	testRevision = "0f1e2d3c4b5a69788796a5b4c3d2e1f001234567"
	testEndpoint = "qwen3.models.svc.cluster.local:9123"
)

// statusBase is the derivation clock's origin. Every step below stamps its own
// time so a preserved LastTransitionTime is distinguishable from a re-stamped
// one; a derivation using its own clock could not be asserted at all.
var statusBase = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func statusOptions() StatusOptions { return StatusOptions{Options: testOptions()} }

// singleReplicaModel is the lifecycle subject: one replica, so "ready" and "all
// replicas ready" cannot be confused, and an explicit port so the endpoint
// assertion pins the render's port and not the operator default.
func singleReplicaModel() *mlxv1alpha1.MLXModel {
	m := newModel()
	m.Spec.Replicas = ptr.To(int32(1))
	m.Generation = 1
	return m
}

// step is one observation fed to DeriveStatus, with everything the resulting
// status must say. The table's cases ARE the state transitions: each step is
// applied to the status the previous step produced, exactly as a reconcile
// would.
type step struct {
	name string
	// gen is metadata.generation at this step; status.observedGeneration and the
	// condition's observedGeneration must both follow it.
	gen int64
	// at is the time this derivation runs.
	at time.Time
	// obs is the injected pod/probe state.
	obs Observation

	wantReady    metav1.ConditionStatus
	wantReason   string
	wantPhase    mlxv1alpha1.MLXModelPhase
	wantEndpoint string
	wantRevision string
	// wantTransitionAt is the LastTransitionTime the Ready condition must carry.
	// A value equal to an EARLIER step's time is the preservation assertion: the
	// timestamp must not be re-stamped while the condition's Status is unchanged.
	wantTransitionAt time.Time
}

func running(name string, v ProbeVerdict) PodState {
	return PodState{Name: name, Phase: corev1.PodRunning, Probe: v}
}

func serving(name string) PodState {
	return PodState{Name: name, Phase: corev1.PodRunning, Ready: true, Probe: ProbeServing}
}

// runSteps applies each step in order to the running status, asserting the whole
// status at every step.
func runSteps(t *testing.T, m *mlxv1alpha1.MLXModel, steps []step) {
	t.Helper()
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			m.Generation = s.gen
			got := DeriveStatus(m, s.obs, statusOptions(), s.at)

			c := meta.FindStatusCondition(got.Conditions, mlxv1alpha1.MLXModelConditionReady)
			if c == nil {
				t.Fatalf("DeriveStatus() published no %q condition; got %+v",
					mlxv1alpha1.MLXModelConditionReady, got.Conditions)
			}
			if c.Status != s.wantReady {
				t.Errorf("Ready condition status = %q, want %q", c.Status, s.wantReady)
			}
			if c.Reason != s.wantReason {
				t.Errorf("Ready condition reason = %q, want %q", c.Reason, s.wantReason)
			}
			if c.Message == "" {
				t.Error("Ready condition has an empty message; a not-ready model must say which replica holds it back")
			}
			if !c.LastTransitionTime.Time.Equal(s.wantTransitionAt) {
				t.Errorf("Ready condition lastTransitionTime = %v, want %v (a timestamp re-stamped while status is unchanged loses when the model actually changed state)",
					c.LastTransitionTime.Time.UTC(), s.wantTransitionAt.UTC())
			}
			if c.ObservedGeneration != s.gen {
				t.Errorf("Ready condition observedGeneration = %d, want %d", c.ObservedGeneration, s.gen)
			}
			if got.ObservedGeneration != s.gen {
				t.Errorf("status.observedGeneration = %d, want %d", got.ObservedGeneration, s.gen)
			}
			if got.Phase != s.wantPhase {
				t.Errorf("status.phase = %q, want %q", got.Phase, s.wantPhase)
			}
			if got.Endpoint != s.wantEndpoint {
				t.Errorf("status.endpoint = %q, want %q", got.Endpoint, s.wantEndpoint)
			}
			if got.ResolvedRevision != s.wantRevision {
				t.Errorf("status.resolvedRevision = %q, want %q", got.ResolvedRevision, s.wantRevision)
			}
			if len(got.Conditions) != 1 {
				t.Errorf("status carries %d conditions, want exactly 1 (Ready); got %+v", len(got.Conditions), got.Conditions)
			}
			m.Status = got
		})
	}
}

// TestStatusConditionsDerivedFromPodProbeState is the status contract: observed
// pod and probe state becomes a Ready condition, and everything else in the
// status — the phase printer column, the endpoint, the resolved revision — is
// derived from that condition or from the observation, never invented.
//
// The derivation is HONEST about what a readiness-only probe can tell it (see
// the readiness-only probe model): "Loading" is a running replica whose serving surface answers
// but whose readiness has not passed, "Ready" is readiness passing, and no state
// claims knowledge of a liveness signal that the rendered pod deliberately does
// not have.
func TestStatusConditionsDerivedFromPodProbeState(t *testing.T) {
	t.Run("pending_downloading_loading_ready_lifecycle", func(t *testing.T) {
		m := singleReplicaModel()
		runSteps(t, m, []step{
			{
				name: "pending_no_pods_yet",
				gen:  1, at: statusBase,
				obs:              Observation{},
				wantReady:        metav1.ConditionFalse,
				wantReason:       ReasonPending,
				wantPhase:        mlxv1alpha1.MLXModelPhasePending,
				wantTransitionAt: statusBase,
			},
			{
				name: "pending_pod_scheduled_not_started",
				gen:  1, at: statusBase.Add(1 * time.Minute),
				obs:              Observation{Pods: []PodState{{Name: "qwen3-0", Phase: corev1.PodPending}}},
				wantReady:        metav1.ConditionFalse,
				wantReason:       ReasonPending,
				wantPhase:        mlxv1alpha1.MLXModelPhasePending,
				wantTransitionAt: statusBase,
			},
			{
				name: "downloading_running_but_surface_silent",
				gen:  1, at: statusBase.Add(2 * time.Minute),
				obs: Observation{
					Pods:             []PodState{running("qwen3-0", ProbeUnreachable)},
					ResolvedRevision: testRevision,
				},
				wantReady:        metav1.ConditionFalse,
				wantReason:       ReasonDownloading,
				wantPhase:        mlxv1alpha1.MLXModelPhaseDownloading,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase,
			},
			{
				name: "loading_surface_answers_readiness_has_not_passed",
				gen:  1, at: statusBase.Add(3 * time.Minute),
				obs:              Observation{Pods: []PodState{running("qwen3-0", ProbeLoading)}},
				wantReady:        metav1.ConditionFalse,
				wantReason:       ReasonLoading,
				wantPhase:        mlxv1alpha1.MLXModelPhaseLoading,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase,
			},
			{
				name: "ready_readiness_passing",
				gen:  1, at: statusBase.Add(4 * time.Minute),
				obs:              Observation{Pods: []PodState{serving("qwen3-0")}},
				wantReady:        metav1.ConditionTrue,
				wantReason:       ReasonServing,
				wantPhase:        mlxv1alpha1.MLXModelPhaseReady,
				wantEndpoint:     testEndpoint,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase.Add(4 * time.Minute),
			},
			{
				name: "ready_again_generation_bumped_transition_time_preserved",
				gen:  2, at: statusBase.Add(5 * time.Minute),
				obs:              Observation{Pods: []PodState{serving("qwen3-0")}},
				wantReady:        metav1.ConditionTrue,
				wantReason:       ReasonServing,
				wantPhase:        mlxv1alpha1.MLXModelPhaseReady,
				wantEndpoint:     testEndpoint,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase.Add(4 * time.Minute),
			},
			{
				name: "ready_to_loading_regression_on_readiness_loss",
				gen:  2, at: statusBase.Add(6 * time.Minute),
				obs:              Observation{Pods: []PodState{running("qwen3-0", ProbeLoading)}},
				wantReady:        metav1.ConditionFalse,
				wantReason:       ReasonLoading,
				wantPhase:        mlxv1alpha1.MLXModelPhaseLoading,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase.Add(6 * time.Minute),
			},
			{
				name: "regression_to_downloading_when_the_surface_goes_silent",
				gen:  2, at: statusBase.Add(7 * time.Minute),
				obs:              Observation{Pods: []PodState{running("qwen3-0", ProbeUnreachable)}},
				wantReady:        metav1.ConditionFalse,
				wantReason:       ReasonDownloading,
				wantPhase:        mlxv1alpha1.MLXModelPhaseDownloading,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase.Add(6 * time.Minute),
			},
			{
				name: "failed_from_pod_failure",
				gen:  2, at: statusBase.Add(8 * time.Minute),
				obs:              Observation{Pods: []PodState{{Name: "qwen3-0", Phase: corev1.PodFailed}}},
				wantReady:        metav1.ConditionFalse,
				wantReason:       ReasonPodFailed,
				wantPhase:        mlxv1alpha1.MLXModelPhaseFailed,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase.Add(6 * time.Minute),
			},
			{
				name: "recovers_to_ready_and_republishes_the_endpoint",
				gen:  3, at: statusBase.Add(9 * time.Minute),
				obs:              Observation{Pods: []PodState{serving("qwen3-0")}},
				wantReady:        metav1.ConditionTrue,
				wantReason:       ReasonServing,
				wantPhase:        mlxv1alpha1.MLXModelPhaseReady,
				wantEndpoint:     testEndpoint,
				wantRevision:     testRevision,
				wantTransitionAt: statusBase.Add(9 * time.Minute),
			},
		})
	})

	t.Run("probe_verdict_never_overrides_readiness", func(t *testing.T) {
		// A replica whose serving surface reports the model loaded but whose
		// readiness has not passed is NOT ready: readiness is what puts the
		// address into the Service's endpoints, so anything else would publish an
		// endpoint that routes nowhere.
		m := singleReplicaModel()
		got := DeriveStatus(m, Observation{Pods: []PodState{running("qwen3-0", ProbeServing)}}, statusOptions(), statusBase)
		if got.Phase != mlxv1alpha1.MLXModelPhaseLoading {
			t.Errorf("status.phase = %q, want %q for a running replica whose readiness has not passed", got.Phase, mlxv1alpha1.MLXModelPhaseLoading)
		}
		if got.Endpoint != "" {
			t.Errorf("status.endpoint = %q, want empty: a probe verdict must not publish an endpoint readiness has not opened", got.Endpoint)
		}
	})

	t.Run("partial_readiness_is_not_ready", func(t *testing.T) {
		// newModel asks for 2 replicas; one serving replica is not the model.
		m := newModel()
		m.Generation = 4
		got := DeriveStatus(m, Observation{
			Pods: []PodState{serving("qwen3-0"), running("qwen3-1", ProbeLoading)},
		}, statusOptions(), statusBase)
		if got.Phase != mlxv1alpha1.MLXModelPhaseLoading {
			t.Errorf("status.phase = %q, want %q with 1 of 2 replicas ready", got.Phase, mlxv1alpha1.MLXModelPhaseLoading)
		}
		if got.Endpoint != "" {
			t.Errorf("status.endpoint = %q, want empty below the desired replica count", got.Endpoint)
		}
	})

	t.Run("the_least_advanced_replica_governs_the_phase", func(t *testing.T) {
		// newModel asks for 2 replicas. One is loading the weights it already
		// fetched; the other has not answered its serving surface at all. The
		// model serves when the LAGGARD is ready, so a phase of Loading would
		// claim progress the model has not made — and the verdict must not depend
		// on the order the lister happened to return the pods in.
		for _, order := range []struct {
			name string
			pods []PodState
		}{
			{name: "loading_first", pods: []PodState{running("qwen3-0", ProbeLoading), running("qwen3-1", ProbeUnreachable)}},
			{name: "downloading_first", pods: []PodState{running("qwen3-1", ProbeUnreachable), running("qwen3-0", ProbeLoading)}},
		} {
			t.Run(order.name, func(t *testing.T) {
				m := newModel()
				m.Generation = 7
				got := DeriveStatus(m, Observation{Pods: order.pods}, statusOptions(), statusBase)
				if got.Phase != mlxv1alpha1.MLXModelPhaseDownloading {
					t.Errorf("status.phase = %q, want %q: the replica still fetching weights decides when the model serves",
						got.Phase, mlxv1alpha1.MLXModelPhaseDownloading)
				}
				c := meta.FindStatusCondition(got.Conditions, mlxv1alpha1.MLXModelConditionReady)
				if c == nil || c.Reason != ReasonDownloading {
					t.Fatalf("Ready condition reason = %v, want %q", c, ReasonDownloading)
				}
				if !strings.Contains(c.Message, "qwen3-1") {
					t.Errorf("Ready condition message = %q, want it to name the replica holding the model back (qwen3-1)", c.Message)
				}
			})
		}
	})

	t.Run("an_uncreated_replica_is_the_ultimate_laggard", func(t *testing.T) {
		// newModel asks for 2 and the StatefulSet has created 1. The absent
		// replica outranks the serving one: reporting Ready here would publish an
		// endpoint for half the requested capacity.
		m := newModel()
		got := DeriveStatus(m, Observation{Pods: []PodState{serving("qwen3-0")}}, statusOptions(), statusBase)
		if got.Phase != mlxv1alpha1.MLXModelPhasePending {
			t.Errorf("status.phase = %q, want %q with 1 of 2 replicas created", got.Phase, mlxv1alpha1.MLXModelPhasePending)
		}
		if got.Endpoint != "" {
			t.Errorf("status.endpoint = %q, want empty while a replica is uncreated", got.Endpoint)
		}

		// And it outranks a replica that IS making progress: the absent replica
		// has not begun, so the model is further from serving than the observed
		// one suggests. Pod management is Parallel, so this is an informer-lag
		// window rather than a steady state.
		got = DeriveStatus(m, Observation{Pods: []PodState{running("qwen3-0", ProbeLoading)}}, statusOptions(), statusBase)
		if got.Phase != mlxv1alpha1.MLXModelPhasePending {
			t.Errorf("status.phase = %q, want %q: an uncreated replica outranks a loading one",
				got.Phase, mlxv1alpha1.MLXModelPhasePending)
		}
	})

	t.Run("a_failed_replica_alongside_a_full_complement_stays_ready", func(t *testing.T) {
		// Precedence: a model answering requests is Ready. A Failed phase would
		// say "this will not recover" about a model currently serving traffic.
		m := singleReplicaModel()
		got := DeriveStatus(m, Observation{
			Pods: []PodState{serving("qwen3-0"), {Name: "qwen3-1", Phase: corev1.PodFailed}},
		}, statusOptions(), statusBase)
		if got.Phase != mlxv1alpha1.MLXModelPhaseReady {
			t.Errorf("status.phase = %q, want %q", got.Phase, mlxv1alpha1.MLXModelPhaseReady)
		}
		if got.Endpoint != testEndpoint {
			t.Errorf("status.endpoint = %q, want %q", got.Endpoint, testEndpoint)
		}
	})

	t.Run("scale_to_zero_is_pending_not_ready", func(t *testing.T) {
		// 0 of 0 replicas ready must not satisfy the serving test: that publishes
		// an endpoint for a model deliberately not running.
		m := newModel()
		m.Spec.Replicas = ptr.To(int32(0))
		got := DeriveStatus(m, Observation{}, statusOptions(), statusBase)
		if got.Phase != mlxv1alpha1.MLXModelPhasePending {
			t.Errorf("status.phase = %q, want %q", got.Phase, mlxv1alpha1.MLXModelPhasePending)
		}
		c := meta.FindStatusCondition(got.Conditions, mlxv1alpha1.MLXModelConditionReady)
		if c == nil || c.Reason != ReasonScaledToZero {
			t.Errorf("Ready condition reason = %v, want %q", c, ReasonScaledToZero)
		}
		if got.Endpoint != "" {
			t.Errorf("status.endpoint = %q, want empty at scale-to-zero", got.Endpoint)
		}
	})

	t.Run("resolved_revision_is_sticky_and_re_resolvable", func(t *testing.T) {
		m := singleReplicaModel()
		m.Status.ResolvedRevision = testRevision

		got := DeriveStatus(m, Observation{Pods: []PodState{running("qwen3-0", ProbeUnreachable)}}, statusOptions(), statusBase)
		if got.ResolvedRevision != testRevision {
			t.Errorf("status.resolvedRevision = %q, want %q preserved when the observation no longer knows it",
				got.ResolvedRevision, testRevision)
		}

		const next = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		m.Status = got
		got = DeriveStatus(m, Observation{
			Pods:             []PodState{running("qwen3-0", ProbeLoading)},
			ResolvedRevision: next,
		}, statusOptions(), statusBase)
		if got.ResolvedRevision != next {
			t.Errorf("status.resolvedRevision = %q, want %q: a newly resolved revision replaces the recorded one",
				got.ResolvedRevision, next)
		}
	})

	t.Run("endpoint_uses_the_renders_service_name_port_and_cluster_domain", func(t *testing.T) {
		m := singleReplicaModel()
		m.Spec.Port = 0 // fall back to the operator default, exactly as Render does
		opts := statusOptions()
		opts.ClusterDomain = "k3sm.internal"
		got := DeriveStatus(m, Observation{Pods: []PodState{serving("qwen3-0")}}, opts, statusBase)
		want := ServiceName(m.Name) + ".models.svc.k3sm.internal:8080"
		if got.Endpoint != want {
			t.Errorf("status.endpoint = %q, want %q", got.Endpoint, want)
		}
	})

	t.Run("no_endpoint_when_the_port_cannot_be_resolved", func(t *testing.T) {
		m := singleReplicaModel()
		m.Spec.Port = 0
		got := DeriveStatus(m, Observation{Pods: []PodState{serving("qwen3-0")}}, StatusOptions{}, statusBase)
		if got.Endpoint != "" {
			t.Errorf("status.endpoint = %q, want empty: an unresolvable port must not become :0", got.Endpoint)
		}
	})

	t.Run("derivation_does_not_mutate_the_model", func(t *testing.T) {
		m := singleReplicaModel()
		m.Status = DeriveStatus(m, Observation{Pods: []PodState{serving("qwen3-0")}}, statusOptions(), statusBase)
		before := m.DeepCopy()

		_ = DeriveStatus(m, Observation{Pods: []PodState{running("qwen3-0", ProbeLoading)}}, statusOptions(), statusBase.Add(time.Minute))

		if !equalStatus(m.Status, before.Status) {
			t.Errorf("DeriveStatus() mutated the input model status: got %+v, want %+v", m.Status, before.Status)
		}
	})

	t.Run("nil_model_yields_the_zero_status", func(t *testing.T) {
		if got := DeriveStatus(nil, Observation{}, statusOptions(), statusBase); !equalStatus(got, mlxv1alpha1.MLXModelStatus{}) {
			t.Errorf("DeriveStatus(nil) = %+v, want the zero status", got)
		}
	})
}

// TestPhaseFromConditionsIsAProjectionOfTheReadyCondition pins the direction of
// the derivation: the phase is read OUT of the conditions, so a status whose
// conditions were written by an older or newer operator still summarizes
// consistently — and an unrecognized reason summarizes to nothing rather than to
// a guess.
func TestPhaseFromConditionsIsAProjectionOfTheReadyCondition(t *testing.T) {
	tests := []struct {
		name  string
		conds []metav1.Condition
		want  mlxv1alpha1.MLXModelPhase
	}{
		{name: "no_conditions", want: ""},
		{
			name:  "unrelated_condition_only",
			conds: []metav1.Condition{{Type: "Degraded", Status: metav1.ConditionTrue, Reason: ReasonPodFailed}},
			want:  "",
		},
		{
			name:  "ready_true",
			conds: []metav1.Condition{{Type: mlxv1alpha1.MLXModelConditionReady, Status: metav1.ConditionTrue, Reason: ReasonServing}},
			want:  mlxv1alpha1.MLXModelPhaseReady,
		},
		{
			name:  "downloading",
			conds: []metav1.Condition{{Type: mlxv1alpha1.MLXModelConditionReady, Status: metav1.ConditionFalse, Reason: ReasonDownloading}},
			want:  mlxv1alpha1.MLXModelPhaseDownloading,
		},
		{
			name:  "loading",
			conds: []metav1.Condition{{Type: mlxv1alpha1.MLXModelConditionReady, Status: metav1.ConditionFalse, Reason: ReasonLoading}},
			want:  mlxv1alpha1.MLXModelPhaseLoading,
		},
		{
			name:  "pod_failed",
			conds: []metav1.Condition{{Type: mlxv1alpha1.MLXModelConditionReady, Status: metav1.ConditionFalse, Reason: ReasonPodFailed}},
			want:  mlxv1alpha1.MLXModelPhaseFailed,
		},
		{
			name:  "scaled_to_zero",
			conds: []metav1.Condition{{Type: mlxv1alpha1.MLXModelConditionReady, Status: metav1.ConditionFalse, Reason: ReasonScaledToZero}},
			want:  mlxv1alpha1.MLXModelPhasePending,
		},
		{
			name:  "unrecognized_reason",
			conds: []metav1.Condition{{Type: mlxv1alpha1.MLXModelConditionReady, Status: metav1.ConditionFalse, Reason: "Whatever"}},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PhaseFromConditions(tt.conds); got != tt.want {
				t.Errorf("PhaseFromConditions() = %q, want %q", got, tt.want)
			}
		})
	}
}

// equalStatus compares two statuses field by field, including every condition.
// reflect.DeepEqual would work but reports a wall of struct text on failure and
// is sensitive to metav1.Time's monotonic clock reading.
func equalStatus(a, b mlxv1alpha1.MLXModelStatus) bool {
	if a.Phase != b.Phase || a.Endpoint != b.Endpoint ||
		a.ResolvedRevision != b.ResolvedRevision || a.ObservedGeneration != b.ObservedGeneration ||
		len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason ||
			x.Message != y.Message || x.ObservedGeneration != y.ObservedGeneration ||
			!x.LastTransitionTime.Time.Equal(y.LastTransitionTime.Time) {
			return false
		}
	}
	return true
}
