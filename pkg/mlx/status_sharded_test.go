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

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// TestDeriveShardedStatus pins the sharded condition set and its projection
// to the phase: placement refusals read Pending, a gang restart never serves,
// Ready needs every rank, and LinkDegraded says what the backend can do.
func TestDeriveShardedStatus(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	ready := func(name string) PodState {
		return PodState{Name: name, Phase: corev1.PodRunning, Ready: true, Revision: "h"}
	}
	cases := []struct {
		name      string
		obs       ShardObservation
		wantReady metav1.ConditionStatus
		wantRsn   string
		wantPhase mlxv1alpha1.MLXModelPhase
		wantLinks string // "" = condition absent
		wantMsg   string // substring of the LinksHealthy or Ready message
	}{
		{name: "no_topology", obs: ShardObservation{Desired: 3, PlacementReason: ReasonNoDirectLinkTopology, PlacementMessage: "no rdma clique of 3"},
			wantReady: metav1.ConditionFalse, wantRsn: ReasonNoDirectLinkTopology, wantPhase: mlxv1alpha1.MLXModelPhasePending, wantMsg: "no rdma clique of 3"},
		{name: "insufficient_memory", obs: ShardObservation{Desired: 2, PlacementReason: ReasonInsufficientMemory, PlacementMessage: "x"},
			wantReady: metav1.ConditionFalse, wantRsn: ReasonInsufficientMemory, wantPhase: mlxv1alpha1.MLXModelPhasePending},
		{name: "scaled_to_zero", obs: ShardObservation{Desired: 0},
			wantReady: metav1.ConditionFalse, wantRsn: ReasonScaledToZero, wantPhase: mlxv1alpha1.MLXModelPhasePending},
		{name: "gang_restart", obs: ShardObservation{Desired: 2, GangRestart: "rank pod m-rank-1 is missing"},
			wantReady: metav1.ConditionFalse, wantRsn: ReasonPending, wantPhase: mlxv1alpha1.MLXModelPhasePending, wantMsg: "gang restart"},
		{name: "one_rank_ready_of_two", obs: ShardObservation{Desired: 2, Placed: true, SpecHash: "h",
			Pods: []PodState{ready("m-rank-0"), {Name: "m-rank-1", Phase: corev1.PodPending, Revision: "h"}}},
			wantReady: metav1.ConditionFalse, wantRsn: ReasonPending, wantPhase: mlxv1alpha1.MLXModelPhasePending, wantLinks: ReasonLinksUp},
		{name: "all_ranks_ready", obs: ShardObservation{Desired: 2, Placed: true, SpecHash: "h", PlacedLinks: 1,
			Pods: []PodState{ready("m-rank-0"), ready("m-rank-1")}},
			wantReady: metav1.ConditionTrue, wantRsn: ReasonServing, wantPhase: mlxv1alpha1.MLXModelPhaseReady, wantLinks: ReasonLinksUp, wantMsg: "all 1 placed"},
		{name: "jaccl_link_degraded", obs: ShardObservation{Desired: 2, Placed: true, SpecHash: "h", Backend: mlxv1alpha1.MLXDistributedBackendJACCL,
			PlacedLinks: 1, DownLinks: []string{"a/b"}, Pods: []PodState{ready("m-rank-0"), ready("m-rank-1")}},
			wantReady: metav1.ConditionTrue, wantRsn: ReasonServing, wantPhase: mlxv1alpha1.MLXModelPhaseReady, wantLinks: ReasonLinkDegraded, wantMsg: "jaccl has no fallback"},
		{name: "stale_rank_is_not_ready", obs: ShardObservation{Desired: 2, Placed: true, SpecHash: "new",
			Pods: []PodState{ready("m-rank-0"), ready("m-rank-1")}},
			wantReady: metav1.ConditionFalse, wantRsn: ReasonPending, wantPhase: mlxv1alpha1.MLXModelPhasePending, wantLinks: ReasonLinksUp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newModel()
			m.Spec.Replicas = nil
			s := DeriveShardedStatus(m, tc.obs, StatusOptions{Options: testOptions()}, now)
			r := meta.FindStatusCondition(s.Conditions, mlxv1alpha1.MLXModelConditionReady)
			if r == nil || r.Status != tc.wantReady || r.Reason != tc.wantRsn {
				t.Fatalf("Ready = %+v, want %s/%s", r, tc.wantReady, tc.wantRsn)
			}
			if s.Phase != tc.wantPhase {
				t.Errorf("phase = %s, want %s", s.Phase, tc.wantPhase)
			}
			if (s.Endpoint != "") != (tc.wantPhase == mlxv1alpha1.MLXModelPhaseReady) {
				t.Errorf("endpoint = %q in phase %s", s.Endpoint, s.Phase)
			}
			l := meta.FindStatusCondition(s.Conditions, ConditionLinksHealthy)
			switch {
			case tc.wantLinks == "" && l != nil && tc.obs.GangRestart == "":
				t.Errorf("LinksHealthy present (%+v), want absent", l)
			case tc.wantLinks != "" && (l == nil || l.Reason != tc.wantLinks):
				t.Errorf("LinksHealthy = %+v, want reason %s", l, tc.wantLinks)
			}
			if tc.wantMsg != "" {
				msg := r.Message
				if l != nil {
					msg += " | " + l.Message
				}
				if !strings.Contains(msg, tc.wantMsg) {
					t.Errorf("messages %q do not contain %q", msg, tc.wantMsg)
				}
			}
		})
	}
}
