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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
)

// schedulerMessage is what the scheduler says about a rank it cannot bind.
const schedulerMessage = "0/2 nodes are available: 1 Insufficient mlx.k3sm.io/gpu"

// setUnschedulable marks a rank Pod Pending with PodScheduled=False
// (Unschedulable) since fixedNow minus age, and no spec.nodeName.
func (h *harness) setUnschedulable(t *testing.T, rank int, age time.Duration) {
	t.Helper()
	pod := h.rankPod(t, rank)
	pod.Status.Phase = corev1.PodPending
	pod.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable,
		Message: schedulerMessage, LastTransitionTime: metav1.NewTime(fixedNow.Add(-age)),
	}}
	if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// setScheduled binds a rank Pod to node and leaves it Pending with
// PodScheduled=True, as the scheduler does before the kubelet starts it.
func (h *harness) setScheduled(t *testing.T, rank int, node string) {
	t.Helper()
	pod := h.rankPod(t, rank)
	pod.Spec.NodeName = node
	updated, err := h.kube.CoreV1().Pods(testNamespace).Update(context.Background(), &pod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	updated.Status.Phase = corev1.PodPending
	updated.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodScheduled, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(fixedNow),
	}}
	if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// setRankReady marks a rank Pod Running and Ready on node.
func (h *harness) setRankReady(t *testing.T, rank int, node string) {
	t.Helper()
	pod := h.rankPod(t, rank)
	pod.Spec.NodeName = node
	updated, err := h.kube.CoreV1().Pods(testNamespace).Update(context.Background(), &pod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	updated.Status.Phase = corev1.PodRunning
	updated.Status.PodIP = "10.42.0.9"
	updated.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
		{Type: corev1.PodReady, Status: corev1.ConditionTrue},
	}
	if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// rankPod reads back one rank Pod.
func (h *harness) rankPod(t *testing.T, rank int) corev1.Pod {
	t.Helper()
	pod, err := h.kube.CoreV1().Pods(testNamespace).Get(context.Background(), mlx.RankPodName(testModelName, rank), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return *pod
}

// dropPodScheduled removes every rank Pod's PodScheduled condition, keeping
// everything else: the baseline an unchanged status is compared against.
func (h *harness) dropPodScheduled(t *testing.T) {
	t.Helper()
	for _, pod := range h.rankPods(t) {
		var kept []corev1.PodCondition
		for _, c := range pod.Status.Conditions {
			if c.Type != corev1.PodScheduled {
				kept = append(kept, c)
			}
		}
		pod.Status.Conditions = kept
		if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestShardedUnschedulableRankIsReported: a rank Pod the scheduler refuses for
// longer than rankUnschedulableGrace makes Ready read RankUnschedulable, naming
// the rank and the scheduler's message, while ShardsPlaced stays True and no
// rank Pod is deleted. Inside the grace, or once scheduled, the status is what
// it would be without the PodScheduled condition at all.
func TestShardedUnschedulableRankIsReported(t *testing.T) {
	cases := []struct {
		name string
		// set puts the rank Pods in the state under test.
		set func(t *testing.T, h *harness)
		// wantRank is the rank Pod Ready must name as unschedulable; "" means
		// the status is unchanged by the PodScheduled condition.
		wantRank string
	}{
		{"inside_grace", func(t *testing.T, h *harness) {
			h.setUnschedulable(t, 1, rankUnschedulableGrace-time.Second)
		}, ""},
		{"past_grace", func(t *testing.T, h *harness) {
			h.setUnschedulable(t, 0, rankUnschedulableGrace+time.Second)
		}, mlx.RankPodName(testModelName, 0)},
		{"scheduled_but_pending", func(t *testing.T, h *harness) {
			h.setScheduled(t, 1, "mac-b")
		}, ""},
		{"rank1_unschedulable_rank0_ready", func(t *testing.T, h *harness) {
			h.setRankReady(t, 0, "mac-a")
			h.setUnschedulable(t, 1, rankUnschedulableGrace+time.Minute)
		}, mlx.RankPodName(testModelName, 1)},
		{"unschedulable_then_scheduled", func(t *testing.T, h *harness) {
			h.setUnschedulable(t, 1, rankUnschedulableGrace+time.Minute)
			h.reconcile(t)
			if c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); c.Reason != mlx.ReasonRankUnschedulable {
				t.Fatalf("precondition: Ready reason = %s %q, want %s", c.Reason, c.Message, mlx.ReasonRankUnschedulable)
			}
			h.setScheduled(t, 1, "mac-b")
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs(), nil)
			h.reconcile(t)
			first := map[string]string{}
			for _, p := range h.rankPods(t) {
				first[p.Name] = string(p.UID)
			}

			tc.set(t, h)
			h.reconcile(t)
			s := h.status(t)
			ready := condition(t, s, mlxv1alpha1.MLXModelConditionReady)

			if c := condition(t, s, mlx.ConditionShardsPlaced); c.Status != metav1.ConditionTrue || c.Reason != mlx.ReasonPlaced {
				t.Errorf("ShardsPlaced = %s/%s, want True/Placed", c.Status, c.Reason)
			}
			if s.Phase != mlxv1alpha1.MLXModelPhasePending {
				t.Errorf("phase = %s, want Pending", s.Phase)
			}
			pods := h.rankPods(t)
			if len(pods) != len(first) {
				t.Errorf("%d rank pods, want %d: none may be deleted", len(pods), len(first))
			}
			for _, p := range pods {
				if first[p.Name] != string(p.UID) {
					t.Errorf("rank pod %s was replaced", p.Name)
				}
			}

			if tc.wantRank != "" {
				if ready.Status != metav1.ConditionFalse || ready.Reason != mlx.ReasonRankUnschedulable {
					t.Errorf("Ready = %s/%s, want False/%s", ready.Status, ready.Reason, mlx.ReasonRankUnschedulable)
				}
				if !strings.Contains(ready.Message, tc.wantRank) || !strings.Contains(ready.Message, schedulerMessage) {
					t.Errorf("Ready message %q does not name rank %s and the scheduler's message", ready.Message, tc.wantRank)
				}
				return
			}
			if ready.Reason == mlx.ReasonRankUnschedulable {
				t.Errorf("Ready reason = %s %q, want the status unchanged", ready.Reason, ready.Message)
			}
			h.dropPodScheduled(t)
			h.reconcile(t)
			base := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady)
			if ready.Status != base.Status || ready.Reason != base.Reason || ready.Message != base.Message {
				t.Errorf("Ready = %s/%s %q, want the status without PodScheduled: %s/%s %q",
					ready.Status, ready.Reason, ready.Message, base.Status, base.Reason, base.Message)
			}
		})
	}
}

// TestShardedUnschedulableInsideGraceRequeues: a reconcile that sees a refusal
// still inside the grace schedules the model again for the moment it leaves
// it, and one that sees only a refusal past the grace does not.
func TestShardedUnschedulableInsideGraceRequeues(t *testing.T) {
	h := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs(), nil)
	h.reconcile(t)
	q := h.recordRequeues()

	h.setUnschedulable(t, 1, rankUnschedulableGrace-7*time.Second)
	h.reconcile(t)
	if !hasRequeue(q.take(), key(), 7*time.Second) {
		t.Errorf("no requeue of %s after 7s for a refusal 7s short of the grace", key())
	}

	h.setUnschedulable(t, 1, rankUnschedulableGrace+time.Second)
	h.reconcile(t)
	if got := q.take(); hasRequeue(got, key(), time.Second) || hasRequeue(got, key(), 0) {
		t.Errorf("requeues %v for a refusal already past the grace", got)
	}
}

// hasRequeue reports whether rs holds an AddAfter of k after d.
func hasRequeue(rs []requeue, k string, d time.Duration) bool {
	for _, r := range rs {
		if r.key == k && r.after == d {
			return true
		}
	}
	return false
}

// TestUnschedulableRecheck: the requeue fires when the earliest refusal still
// inside the grace leaves it, and not at all once every refusal is past it.
func TestUnschedulableRecheck(t *testing.T) {
	refused := func(age time.Duration) corev1.Pod {
		return corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{
			Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable,
			LastTransitionTime: metav1.NewTime(fixedNow.Add(-age)),
		}}}}
	}
	created := corev1.Pod{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(fixedNow.Add(-25 * time.Second))},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{
			Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable,
		}}}}
	cases := []struct {
		name   string
		pods   []corev1.Pod
		want   time.Duration
		wantOK bool
	}{
		{"none", []corev1.Pod{{}}, 0, false},
		{"earliest_expiry", []corev1.Pod{refused(10 * time.Second), refused(20 * time.Second)}, 10 * time.Second, true},
		{"past_grace", []corev1.Pod{refused(rankUnschedulableGrace)}, 0, false},
		{"creation_time_fallback", []corev1.Pod{created}, 5 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := unschedulableRecheck(tc.pods, fixedNow)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("unschedulableRecheck = %s, %t; want %s, %t", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
