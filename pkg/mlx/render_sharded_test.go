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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/policy"
)

// shardedModel is newModel made sharded: ranks, backend, parallelism, and the
// one-logical-replica rule (spec.replicas unset).
func shardedModel(ranks int32, backend mlxv1alpha1.MLXDistributedBackend, par mlxv1alpha1.MLXParallelism) *mlxv1alpha1.MLXModel {
	m := newModel()
	m.Spec.Replicas = nil
	m.Spec.Distributed = &mlxv1alpha1.MLXDistributed{Ranks: ranks, Backend: backend, Parallelism: par}
	return m
}

// ringPlacement is a two-rank ring over one cable.
func ringPlacement() Placement {
	return Placement{
		Backend: mlxv1alpha1.MLXDistributedBackendRing,
		Ranks:   []RankPlacement{{Rank: 0, Node: "mac-a"}, {Rank: 1, Node: "mac-b"}},
		Links:   [][2]string{{"mac-a", "mac-b"}},
	}
}

// jacclPlacement is a three-rank RDMA clique.
func jacclPlacement() Placement {
	return Placement{
		Backend: mlxv1alpha1.MLXDistributedBackendJACCL,
		Ranks: []RankPlacement{
			{Rank: 0, Node: "mac-a", RDMADevices: []string{"", "rdma_en2", "rdma_en3"}},
			{Rank: 1, Node: "mac-b", RDMADevices: []string{"rdma_en2", "", "rdma_en4"}},
			{Rank: 2, Node: "mac-c", RDMADevices: []string{"rdma_en3", "rdma_en4", ""}},
		},
		Links: [][2]string{{"mac-a", "mac-b"}, {"mac-a", "mac-c"}, {"mac-b", "mac-c"}},
	}
}

// TestRenderShardedGolden pins the whole rendered object set for a 2-rank
// ring and a 3-rank jaccl model against reviewed goldens. Regenerate with
// go test ./pkg/mlx/ -run TestRenderShardedGolden -update and REVIEW THE DIFF.
func TestRenderShardedGolden(t *testing.T) {
	cases := []struct {
		name      string
		model     *mlxv1alpha1.MLXModel
		placement Placement
	}{
		{"sharded-ring-2", shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing, mlxv1alpha1.MLXParallelismPipeline), ringPlacement()},
		{"sharded-jaccl-3", shardedModel(3, mlxv1alpha1.MLXDistributedBackendAuto, ""), jacclPlacement()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs, err := RenderSharded(tc.model, testOptions(), tc.placement)
			if err != nil {
				t.Fatalf("RenderSharded() error = %v", err)
			}
			var docs []string
			add := func(o any) {
				raw, err := yaml.Marshal(o)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				docs = append(docs, string(raw))
			}
			add(objs.HeadlessService)
			add(objs.ClusterIPService)
			for _, c := range objs.Claims {
				add(c)
			}
			for _, p := range objs.Pods {
				add(p)
			}
			got := "# Regenerate: go test ./pkg/mlx/ -run TestRenderShardedGolden -update (then review the diff)\n---\n" +
				strings.Join(docs, "---\n")
			golden := filepath.Join("testdata", tc.name+".golden.yaml")
			if *updateSizingGolden {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden %s: %v (regenerate with -update)", golden, err)
			}
			if string(want) != got {
				t.Errorf("render differs from %s (regenerate with -update if deliberate)\n--- got ---\n%s", golden, got)
			}
		})
	}
}

// TestRenderShardedContract asserts the properties the goldens only show: the
// owner, the per-pod identity, the shared guardrail builder, the rank-0-only
// client Service, the per-rank env, and the jaccl device matrix.
func TestRenderShardedContract(t *testing.T) {
	m := shardedModel(3, mlxv1alpha1.MLXDistributedBackendJACCL, mlxv1alpha1.MLXParallelismTensor)
	objs, err := RenderSharded(m, testOptions(), jacclPlacement())
	if err != nil {
		t.Fatalf("RenderSharded() error = %v", err)
	}
	single := newModel()
	single.Spec.Replicas = nil
	sts, err := Render(single, testOptions())
	if err != nil {
		t.Fatalf("Render(single) error = %v", err)
	}
	tmpl := sts.StatefulSet.Spec.Template.Spec

	if len(objs.Pods) != 3 {
		t.Fatalf("rendered %d pods, want 3", len(objs.Pods))
	}
	for i, pod := range objs.Pods {
		if want := RankPodName(m.Name, i); pod.Name != want || pod.Spec.Hostname != want {
			t.Errorf("rank %d name/hostname = %q/%q, want %q", i, pod.Name, pod.Spec.Hostname, want)
		}
		if pod.Spec.Subdomain != HeadlessServiceName(m.Name) {
			t.Errorf("rank %d subdomain = %q, want the headless Service %q", i, pod.Spec.Subdomain, HeadlessServiceName(m.Name))
		}
		if pod.Spec.NodeName != jacclPlacement().Ranks[i].Node {
			t.Errorf("rank %d nodeName = %q, want %q", i, pod.Spec.NodeName, jacclPlacement().Ranks[i].Node)
		}
		if len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].UID != m.UID || !ptr.Deref(pod.OwnerReferences[0].Controller, false) {
			t.Errorf("rank %d ownerReferences = %v, want one controller reference to the model", i, pod.OwnerReferences)
		}
		if !reflect.DeepEqual(pod.Spec.NodeSelector, tmpl.NodeSelector) {
			t.Errorf("rank %d nodeSelector = %v, want the StatefulSet's %v (one builder)", i, pod.Spec.NodeSelector, tmpl.NodeSelector)
		}
		if !reflect.DeepEqual(pod.Spec.Tolerations, tmpl.Tolerations) || len(pod.Spec.Tolerations) != 1 || pod.Spec.Tolerations[0].Key != policy.ProviderTaintKey {
			t.Errorf("rank %d tolerations = %v, want the StatefulSet's %v", i, pod.Spec.Tolerations, tmpl.Tolerations)
		}
		if pod.Labels[LabelRank] != string(rune('0'+i)) {
			t.Errorf("rank %d label %s = %q", i, LabelRank, pod.Labels[LabelRank])
		}
		if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
			t.Errorf("rank %d restartPolicy = %q, want Never (a lone restart cannot rejoin the collective)", i, pod.Spec.RestartPolicy)
		}
		c := pod.Spec.Containers[0]
		gpu := c.Resources.Limits[corev1.ResourceName(mlxv1alpha1.ResourceGPU)]
		if gpu.Value() != 1 {
			t.Errorf("rank %d gpu limit = %v, want 1", i, gpu.String())
		}
		env := map[string]string{}
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		want := map[string]string{
			"MLX_RANK": string(rune('0' + i)), "MLX_WORLD_SIZE": "3", "MLX_METAL_FAST_SYNCH": "1",
			"K3SM_MLX_BACKEND": "jaccl", "K3SM_MLX_PARALLELISM": "tensor", "K3SM_MLX_PORT": "29500",
			"K3SM_MLX_RANKS": "qwen3-rank-0.qwen3-headless.models.svc,qwen3-rank-1.qwen3-headless.models.svc,qwen3-rank-2.qwen3-headless.models.svc",
		}
		for k, v := range want {
			if env[k] != v {
				t.Errorf("rank %d env %s = %q, want %q", i, k, env[k], v)
			}
		}
		var matrix [][]*string
		if err := json.Unmarshal([]byte(env["K3SM_MLX_IBV_DEVICES_JSON"]), &matrix); err != nil {
			t.Fatalf("rank %d K3SM_MLX_IBV_DEVICES_JSON: %v", i, err)
		}
		if matrix[i][i] != nil {
			t.Errorf("rank %d device matrix self entry = %v, want null", i, *matrix[i][i])
		}
		if (c.LivenessProbe != nil) != (i == 0) || (c.ReadinessProbe != nil) != (i == 0) {
			t.Errorf("rank %d probes: liveness=%v readiness=%v, want both on rank 0 only", i, c.LivenessProbe != nil, c.ReadinessProbe != nil)
		}
	}
	if got := objs.ClusterIPService.Spec.Selector[LabelRank]; got != "0" {
		t.Errorf("ClusterIP selector %s = %q, want 0 (rank 0 alone serves HTTP)", LabelRank, got)
	}
	if _, ok := objs.HeadlessService.Spec.Selector[LabelRank]; ok || !objs.HeadlessService.Spec.PublishNotReadyAddresses {
		t.Errorf("headless Service = selector %v publishNotReady %v, want every rank and not-ready addresses", objs.HeadlessService.Spec.Selector, objs.HeadlessService.Spec.PublishNotReadyAddresses)
	}
	probe := objs.Pods[0].Spec.Containers[0].LivenessProbe
	if probe.PeriodSeconds != 60 || probe.Exec == nil || probe.Exec.Command[len(probe.Exec.Command)-1] != "--probe" {
		t.Errorf("rank-0 liveness = %+v, want an exec k3sm-shard --probe every 60 s", probe)
	}
	// Each rank requests its SHARE plus the per-process floor, not the whole.
	per, _ := PerRankMemory(m.Spec.Memory, 3)
	got := objs.Pods[1].Spec.Containers[0].Resources.Requests[corev1.ResourceMemory]
	if got.Cmp(per) != 0 || got.Cmp(m.Spec.Memory) >= 0 {
		t.Errorf("rank memory request = %s, want the per-rank %s (below the whole %s)", got.String(), per.String(), m.Spec.Memory.String())
	}
	if len(objs.Claims) != 3 || objs.Claims[2].Name != "cache-qwen3-mac-c" {
		t.Errorf("claims = %d, last %q, want one per rank named for its node", len(objs.Claims), objs.Claims[len(objs.Claims)-1].Name)
	}
}

// TestRenderShardedRefusals pins the sentinel per refused input.
func TestRenderShardedRefusals(t *testing.T) {
	ring := ringPlacement()
	cases := []struct {
		name      string
		mutate    func(*mlxv1alpha1.MLXModel)
		placement Placement
		want      error
	}{
		{"not_distributed", func(m *mlxv1alpha1.MLXModel) { m.Spec.Distributed = nil }, ring, ErrNotDistributed},
		{"one_rank", func(m *mlxv1alpha1.MLXModel) { m.Spec.Distributed.Ranks = 1 }, ring, ErrInvalidRanks},
		{"two_replicas", func(m *mlxv1alpha1.MLXModel) { m.Spec.Replicas = ptr.To(int32(2)) }, ring, ErrShardedReplicas},
		{"collective_port", func(m *mlxv1alpha1.MLXModel) { m.Spec.Port = CollectivePort }, ring, ErrCollectivePortConflict},
		{"placement_short", nil, Placement{Backend: mlxv1alpha1.MLXDistributedBackendRing, Ranks: ring.Ranks[:1]}, ErrPlacementMismatch},
		{"placement_auto_unresolved", nil, Placement{Backend: mlxv1alpha1.MLXDistributedBackendAuto, Ranks: ring.Ranks}, ErrPlacementMismatch},
		{"placement_same_node", nil, Placement{Backend: mlxv1alpha1.MLXDistributedBackendRing, Ranks: []RankPlacement{{Rank: 0, Node: "a"}, {Rank: 1, Node: "a"}}}, ErrPlacementMismatch},
		{"memory_share_too_small", func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.MustParse("1Gi") }, ring, ErrMemoryTooSmall},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing, "")
			if tc.mutate != nil {
				tc.mutate(m)
			}
			if _, err := RenderSharded(m, testOptions(), tc.placement); !errors.Is(err, tc.want) {
				t.Errorf("RenderSharded() error = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("single_node_render_refuses_a_sharded_spec", func(t *testing.T) {
		if _, err := Render(shardedModel(2, "", ""), testOptions()); !errors.Is(err, ErrDistributedSpec) {
			t.Errorf("Render(sharded) error = %v, want ErrDistributedSpec", err)
		}
	})
}

// TestSpecHashIgnoresPlacement pins what restarts a gang: a spec change does,
// a placement change does not.
func TestSpecHashIgnoresPlacement(t *testing.T) {
	m := shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing, "")
	a, err := RenderSharded(m, testOptions(), ringPlacement())
	if err != nil {
		t.Fatal(err)
	}
	moved := ringPlacement()
	moved.Ranks[1].Node = "mac-z"
	b, err := RenderSharded(m, testOptions(), moved)
	if err != nil {
		t.Fatal(err)
	}
	if a.SpecHash != b.SpecHash {
		t.Errorf("spec hash moved with the placement: %s vs %s", a.SpecHash, b.SpecHash)
	}
	m.Spec.Runtime.Args = append(m.Spec.Runtime.Args, "--temp", "0")
	c, err := RenderSharded(m, testOptions(), ringPlacement())
	if err != nil {
		t.Fatal(err)
	}
	if c.SpecHash == a.SpecHash {
		t.Error("spec hash did not move with the spec")
	}
	if got := ParsePlacedLinks(FormatPlacedLinks(jacclPlacement().Links)); !reflect.DeepEqual(got, jacclPlacement().Links) {
		t.Errorf("placed-links round trip = %v", got)
	}
}
