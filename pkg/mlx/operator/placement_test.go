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
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/mlx/topology"
)

// gpuNode builds a Ready GPU node with the guardrail labels, mem of
// allocatable memory, and the k3sm.io/rdma label when rdma is set.
func gpuNode(name, mem string, rdma bool) corev1.Node {
	n := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
			corev1.LabelOSStable:        "darwin",
			mlxv1alpha1.LabelGPUPresent: "true",
		}},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceMemory:                        resource.MustParse(mem),
				corev1.ResourceName(mlxv1alpha1.ResourceGPU): resource.MustParse("1"),
			},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
	if rdma {
		n.Labels[netv1alpha1.LabelRDMA] = "true"
	}
	return n
}

// cable adds a symmetric up link a<->b to g; rdma puts a device at both ends.
func cable(g topology.Graph, a, b string, rdma bool) topology.Graph {
	if g.Edges == nil {
		g.Edges = map[string]map[string]topology.Edge{}
	}
	dev := func(x, y string) string {
		if !rdma {
			return ""
		}
		return "rdma_" + x + "-" + y
	}
	for _, d := range [][2]string{{a, b}, {b, a}} {
		if g.Edges[d[0]] == nil {
			g.Edges[d[0]] = map[string]topology.Edge{}
		}
		g.Edges[d[0]][d[1]] = topology.Edge{LocalIface: "en1", LocalRDMA: dev(d[0], d[1]), PeerRDMA: dev(d[1], d[0])}
	}
	return g
}

func shardSpec(ranks int32, backend mlxv1alpha1.MLXDistributedBackend, mem string) *mlxv1alpha1.MLXModel {
	return model(func(m *mlxv1alpha1.MLXModel) {
		m.Spec.Memory = resource.MustParse(mem)
		m.Spec.Distributed = &mlxv1alpha1.MLXDistributed{Ranks: ranks, Backend: backend}
	})
}

// TestPlace is the placement table over fake graphs: clique, cycle, any-nodes,
// memory fit, the node selector, and every named ShardsPlaced reason.
func TestPlace(t *testing.T) {
	ring, jaccl, auto := mlxv1alpha1.MLXDistributedBackendRing, mlxv1alpha1.MLXDistributedBackendJACCL, mlxv1alpha1.MLXDistributedBackendAuto
	threeRDMA := cable(cable(cable(topology.Graph{}, "a", "b", true), "b", "c", true), "a", "c", true)
	threeOneTCP := cable(cable(cable(topology.Graph{}, "a", "b", true), "b", "c", true), "a", "c", false)
	// a 4-cycle a-b-d-c-a with no chords: a cycle exists, no clique of 3.
	fourRing := cable(cable(cable(cable(topology.Graph{}, "a", "b", false), "b", "d", false), "d", "c", false), "c", "a", false)
	nodes3 := []corev1.Node{gpuNode("c", "64Gi", true), gpuNode("a", "64Gi", true), gpuNode("b", "64Gi", true)}
	nodes4 := append(nodes3[:3:3], gpuNode("d", "64Gi", false))

	cases := []struct {
		name        string
		model       *mlxv1alpha1.MLXModel
		graph       topology.Graph
		nodes       []corev1.Node
		wantBackend mlxv1alpha1.MLXDistributedBackend
		wantNodes   []string
		wantLinks   [][2]string
		wantReason  string
		wantMsg     string
	}{
		{name: "jaccl_rdma_clique_of_3", model: shardSpec(3, jaccl, "48Gi"), graph: threeRDMA, nodes: nodes3,
			wantBackend: jaccl, wantNodes: []string{"a", "b", "c"}, wantLinks: [][2]string{{"a", "b"}, {"a", "c"}, {"b", "c"}}},
		{name: "jaccl_one_tcp_edge_refused", model: shardSpec(3, jaccl, "48Gi"), graph: threeOneTCP, nodes: nodes3,
			wantReason: mlx.ReasonNoDirectLinkTopology, wantMsg: "no rdma clique of 3"},
		{name: "jaccl_needs_the_rdma_label", model: shardSpec(3, jaccl, "48Gi"), graph: threeRDMA,
			nodes:      []corev1.Node{gpuNode("a", "64Gi", true), gpuNode("b", "64Gi", false), gpuNode("c", "64Gi", true)},
			wantReason: mlx.ReasonNoDirectLinkTopology, wantMsg: "2 fitting nodes carry the label"},
		{name: "auto_picks_jaccl_on_a_clique", model: shardSpec(3, auto, "48Gi"), graph: threeRDMA, nodes: nodes3,
			wantBackend: jaccl, wantNodes: []string{"a", "b", "c"}, wantLinks: [][2]string{{"a", "b"}, {"a", "c"}, {"b", "c"}}},
		{name: "auto_falls_to_ring_without_clique", model: shardSpec(3, auto, "48Gi"), graph: threeOneTCP, nodes: nodes3,
			wantBackend: ring, wantNodes: []string{"a", "b", "c"}, wantLinks: [][2]string{{"a", "b"}, {"b", "c"}, {"a", "c"}}},
		{name: "ring_prefers_the_cycle", model: shardSpec(4, ring, "48Gi"), graph: fourRing, nodes: nodes4,
			wantBackend: ring, wantNodes: []string{"a", "b", "d", "c"}, wantLinks: [][2]string{{"a", "b"}, {"b", "d"}, {"c", "d"}, {"a", "c"}}},
		{name: "ring_any_nodes_without_cables", model: shardSpec(2, ring, "48Gi"), graph: topology.Graph{}, nodes: nodes3,
			wantBackend: ring, wantNodes: []string{"a", "b"}},
		{name: "ring_two_ranks_one_cable", model: shardSpec(2, ring, "48Gi"), graph: cable(topology.Graph{}, "b", "c", false), nodes: nodes3,
			wantBackend: ring, wantNodes: []string{"b", "c"}, wantLinks: [][2]string{{"b", "c"}}},
		{name: "too_few_gpu_nodes", model: shardSpec(4, ring, "48Gi"), graph: fourRing, nodes: nodes3,
			wantReason: mlx.ReasonNoDirectLinkTopology, wantMsg: "found 3 (a, b, c)"},
		{name: "not_ready_node_is_not_a_candidate", model: shardSpec(3, ring, "48Gi"), graph: threeRDMA,
			nodes: func() []corev1.Node {
				ns := []corev1.Node{gpuNode("a", "64Gi", true), gpuNode("b", "64Gi", true), gpuNode("c", "64Gi", true)}
				ns[1].Status.Conditions[0].Status = corev1.ConditionFalse
				return ns
			}(),
			wantReason: mlx.ReasonNoDirectLinkTopology, wantMsg: "found 2"},
		{name: "node_selector_filters", model: func() *mlxv1alpha1.MLXModel {
			m := shardSpec(2, ring, "48Gi")
			m.Spec.NodeSelector = map[string]string{mlxv1alpha1.LabelChipFamily: "m4"}
			return m
		}(), graph: threeRDMA, nodes: nodes3, wantReason: mlx.ReasonNoDirectLinkTopology, wantMsg: "found 0"},
		{name: "per_rank_share_does_not_fit", model: shardSpec(2, ring, "48Gi"), graph: threeRDMA,
			nodes:      []corev1.Node{gpuNode("a", "16Gi", true), gpuNode("b", "64Gi", true), gpuNode("c", "16Gi", true)},
			wantReason: mlx.ReasonInsufficientMemory, wantMsg: "1 of 3 candidate nodes have it (b)"},
		{name: "memory_share_cannot_fund_a_context", model: shardSpec(4, ring, "1Gi"), graph: fourRing, nodes: nodes4,
			wantReason: mlx.ReasonInsufficientMemory, wantMsg: "per-rank share"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Place(tc.model, tc.graph, tc.nodes, nil)
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
			if p.Backend != tc.wantBackend {
				t.Errorf("backend = %q, want %q", p.Backend, tc.wantBackend)
			}
			var got []string
			for i, r := range p.Ranks {
				if r.Rank != i {
					t.Errorf("entry %d is rank %d", i, r.Rank)
				}
				got = append(got, r.Node)
			}
			if !reflect.DeepEqual(got, tc.wantNodes) {
				t.Errorf("rank nodes = %v, want %v", got, tc.wantNodes)
			}
			if !reflect.DeepEqual(p.Links, tc.wantLinks) {
				t.Errorf("links = %v, want %v", p.Links, tc.wantLinks)
			}
			if _, err := mlx.RenderSharded(withRuntime(tc.model), mlx.Options{DefaultImage: testImage, DefaultPort: testPort}, p); err != nil {
				t.Errorf("RenderSharded(placement) error = %v; a placement must always render", err)
			}
		})
	}
}

// withRuntime gives a model a name-safe UID for RenderSharded.
func withRuntime(m *mlxv1alpha1.MLXModel) *mlxv1alpha1.MLXModel {
	c := m.DeepCopy()
	if c.UID == "" {
		c.UID = "u"
	}
	return c
}

// TestPlaceJACCLDevicesIndexedByPeerRank pins the device matrix: entry j of
// rank i's list is rank i's local device on the link to rank j, empty for self.
func TestPlaceJACCLDevicesIndexedByPeerRank(t *testing.T) {
	g := cable(cable(cable(topology.Graph{}, "a", "b", true), "b", "c", true), "a", "c", true)
	nodes := []corev1.Node{gpuNode("a", "64Gi", true), gpuNode("b", "64Gi", true), gpuNode("c", "64Gi", true)}
	p, err := Place(shardSpec(3, mlxv1alpha1.MLXDistributedBackendJACCL, "48Gi"), g, nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"", "rdma_a-b", "rdma_a-c"},
		{"rdma_b-a", "", "rdma_b-c"},
		{"rdma_c-a", "rdma_c-b", ""},
	}
	for i, r := range p.Ranks {
		if !reflect.DeepEqual(r.RDMADevices, want[i]) {
			t.Errorf("rank %d devices = %v, want %v", i, r.RDMADevices, want[i])
		}
	}
	// Determinism: node input order never changes the answer.
	rev := []corev1.Node{nodes[2], nodes[0], nodes[1]}
	q, err := Place(shardSpec(3, mlxv1alpha1.MLXDistributedBackendJACCL, "48Gi"), g, rev, nil)
	if err != nil || !reflect.DeepEqual(p, q) {
		t.Errorf("Place over reordered nodes = %+v, %v; want %+v", q, err, p)
	}
}

// TestValidateDistributed pins what the operator honours in spec.distributed.
func TestValidateDistributed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*mlxv1alpha1.MLXModelSpec)
		ok     bool
	}{
		{"nil_is_single_node", func(s *mlxv1alpha1.MLXModelSpec) { s.Distributed = nil }, true},
		{"two_ranks_defaults", func(*mlxv1alpha1.MLXModelSpec) {}, true},
		{"jaccl_pipeline", func(s *mlxv1alpha1.MLXModelSpec) {
			s.Distributed.Backend, s.Distributed.Parallelism = mlxv1alpha1.MLXDistributedBackendJACCL, mlxv1alpha1.MLXParallelismPipeline
		}, true},
		{"one_rank", func(s *mlxv1alpha1.MLXModelSpec) { s.Distributed.Ranks = 1 }, false},
		{"unknown_backend", func(s *mlxv1alpha1.MLXModelSpec) { s.Distributed.Backend = "mpi" }, false},
		{"unknown_parallelism", func(s *mlxv1alpha1.MLXModelSpec) { s.Distributed.Parallelism = "expert" }, false},
		{"two_replicas", func(s *mlxv1alpha1.MLXModelSpec) { two := int32(2); s.Replicas = &two }, false},
		{"zero_replicas_is_scale_to_zero", func(s *mlxv1alpha1.MLXModelSpec) { zero := int32(0); s.Replicas = &zero }, true},
		{"adapter_refused", func(s *mlxv1alpha1.MLXModelSpec) { s.Runtime.Args = []string{"--adapter-path", "/x"} }, false},
		{"draft_model_equals_form_refused", func(s *mlxv1alpha1.MLXModelSpec) { s.Runtime.Args = []string{"--draft-model=x"} }, false},
		{"draft_abbreviation_refused", func(s *mlxv1alpha1.MLXModelSpec) { s.Runtime.Args = []string{"--draft", "x"} }, false},
		{"other_args_pass", func(s *mlxv1alpha1.MLXModelSpec) { s.Runtime.Args = []string{"--max-tokens", "64", "-v"} }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := shardSpec(2, "", "48Gi").Spec
			tc.mutate(&spec)
			err := ValidateDistributed(spec)
			if tc.ok && err != nil {
				t.Errorf("ValidateDistributed() = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidDistributed) {
				t.Errorf("ValidateDistributed() = %v, want ErrInvalidDistributed", err)
			}
		})
	}
}
