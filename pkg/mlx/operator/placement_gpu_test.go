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
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/mlx/topology"
)

// gpuPod builds a pod bound to node that holds gpu units of the MLX GPU
// resource (as a limit, the way every MLX pod asks for it).
func gpuPod(namespace, name, node string, gpu int64, mutate ...func(*corev1.Pod)) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.PodSpec{
			NodeName: node,
			Containers: []corev1.Container{{Name: "worker", Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{corev1.ResourceName(mlxv1alpha1.ResourceGPU): *resource.NewQuantity(gpu, resource.DecimalSI)},
			}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, m := range mutate {
		m(&p)
	}
	return p
}

// ownRank marks p as one of the model's own rank Pods: the labels the render
// stamps and the model's namespace.
func ownRank(m *mlxv1alpha1.MLXModel, rank int) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Namespace = m.Namespace
		p.Name = mlx.RankPodName(m.Name, rank)
		p.Labels = map[string]string{
			"app.kubernetes.io/name":     "mlx-model",
			"app.kubernetes.io/instance": m.Name,
			mlx.LabelRank:                "0",
		}
	}
}

// TestPlaceRefusesHeldGPU: a node whose mlx.k3sm.io/gpu slots are all held by
// other pods is not a rank candidate, and a model that cannot be placed for
// that reason is refused InsufficientGPU naming the node. The model's own rank
// Pods (a gang restart re-placing onto its own nodes) and ended pods do not
// hold a slot.
func TestPlaceRefusesHeldGPU(t *testing.T) {
	ring := mlxv1alpha1.MLXDistributedBackendRing
	m := shardSpec(2, ring, "48Gi")
	two := []corev1.Node{gpuNode("a", "64Gi", false), gpuNode("b", "64Gi", false)}
	three := []corev1.Node{gpuNode("a", "64Gi", false), gpuNode("b", "64Gi", false), gpuNode("c", "64Gi", false)}

	cases := []struct {
		name       string
		nodes      []corev1.Node
		pods       []corev1.Pod
		wantNodes  []string
		wantReason string
		wantMsg    string
	}{
		{name: "held_node_refused", nodes: two,
			pods:       []corev1.Pod{gpuPod("other", "serve-0", "a", 1)},
			wantReason: mlx.ReasonInsufficientGPU, wantMsg: "(a)"},
		{name: "held_node_skipped_for_a_free_one", nodes: three,
			pods:      []corev1.Pod{gpuPod("other", "serve-0", "a", 1)},
			wantNodes: []string{"b", "c"}},
		{name: "own_rank_pods_are_not_held", nodes: two,
			pods:      []corev1.Pod{gpuPod("", "", "a", 1, ownRank(m, 0)), gpuPod("", "", "b", 1, ownRank(m, 1))},
			wantNodes: []string{"a", "b"}},
		{name: "same_name_other_namespace_is_held", nodes: two,
			pods:       []corev1.Pod{gpuPod("", "", "a", 1, ownRank(m, 0), func(p *corev1.Pod) { p.Namespace = "elsewhere" })},
			wantReason: mlx.ReasonInsufficientGPU, wantMsg: "(a)"},
		{name: "terminal_pods_are_not_held", nodes: two,
			pods: []corev1.Pod{
				gpuPod("other", "done", "a", 1, func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }),
				gpuPod("other", "dead", "b", 1, func(p *corev1.Pod) { p.Status.Phase = corev1.PodFailed }),
			},
			wantNodes: []string{"a", "b"}},
		{name: "non_gpu_and_unbound_pods_are_not_held", nodes: two,
			pods:      []corev1.Pod{gpuPod("other", "cpu", "a", 0), gpuPod("other", "pending", "", 1)},
			wantNodes: []string{"a", "b"}},
		{name: "second_slot_still_free", nodes: func() []corev1.Node {
			ns := []corev1.Node{gpuNode("a", "64Gi", false), gpuNode("b", "64Gi", false)}
			ns[0].Status.Allocatable[corev1.ResourceName(mlxv1alpha1.ResourceGPU)] = resource.MustParse("2")
			return ns
		}(),
			pods:      []corev1.Pod{gpuPod("other", "serve-0", "a", 1)},
			wantNodes: []string{"a", "b"}},
		{name: "every_slot_held_on_both", nodes: two,
			pods:       []corev1.Pod{gpuPod("other", "x", "a", 1), gpuPod("other", "y", "b", 1)},
			wantReason: mlx.ReasonInsufficientGPU, wantMsg: "(a, b)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Place(m, topology.Graph{}, tc.nodes, HeldGPUSlots(m, tc.pods))
			if tc.wantReason != "" {
				var pe *PlacementError
				if !errors.As(err, &pe) {
					t.Fatalf("Place() = %+v, %v; want a PlacementError %s", p, err, tc.wantReason)
				}
				if pe.Reason != tc.wantReason || !strings.Contains(pe.Message, tc.wantMsg) {
					t.Errorf("Place() refusal = %s %q, want %s containing %q", pe.Reason, pe.Message, tc.wantReason, tc.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("Place() error = %v", err)
			}
			if got := placedNodes(p); !reflect.DeepEqual(got, tc.wantNodes) {
				t.Errorf("nodes = %v, want %v", got, tc.wantNodes)
			}
		})
	}
}
