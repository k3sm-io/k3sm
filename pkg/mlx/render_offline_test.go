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
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// envValues returns every value of the env var name in env, in order.
func envValues(env []corev1.EnvVar, name string) []string {
	var vals []string
	for _, e := range env {
		if e.Name == name {
			vals = append(vals, e.Value)
		}
	}
	return vals
}

// servingPodSpecs renders m on the single-node path, or the sharded path when
// it sets spec.distributed, and returns every serving pod spec. Unlike
// renderedPods it asserts nothing about the cache, so it serves Hub models too.
func servingPodSpecs(t *testing.T, m *mlxv1alpha1.MLXModel) []corev1.PodSpec {
	t.Helper()
	if m.Spec.Distributed == nil {
		objs, err := Render(m, artifactOptions())
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		return []corev1.PodSpec{objs.StatefulSet.Spec.Template.Spec}
	}
	objs, err := RenderSharded(m, artifactOptions(), ringPlacement())
	if err != nil {
		t.Fatalf("RenderSharded: %v", err)
	}
	specs := make([]corev1.PodSpec, 0, len(objs.Pods))
	for _, p := range objs.Pods {
		specs = append(specs, p.Spec)
	}
	return specs
}

// TestRenderSetsHubOfflineForClusterStoreModels pins that a model served from
// the cluster store runs with the Hub switched off, on both render paths, and
// that a Hub model, which downloads its weights at start, keeps the Hub. The
// cache's HF_HOME is untouched either way.
func TestRenderSetsHubOfflineForClusterStoreModels(t *testing.T) {
	tests := []struct {
		name        string
		model       func() *mlxv1alpha1.MLXModel
		wantOffline []string
		wantHFHome  []string
	}{
		{"cluster_store_single_node", artifactModel, []string{"1"}, nil},
		{"cluster_store_sharded", shardedArtifactModel, []string{"1"}, nil},
		{"hub_single_node", newModel, nil, []string{hfHomePath}},
		{"hub_sharded", func() *mlxv1alpha1.MLXModel {
			return shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing, "")
		}, nil, []string{hfHomePath}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			specs := servingPodSpecs(t, tc.model())
			if len(specs) == 0 {
				t.Fatal("render produced no pods")
			}
			for i, spec := range specs {
				if len(spec.Containers) != 1 {
					t.Fatalf("pod %d: %d containers, want 1", i, len(spec.Containers))
				}
				env := spec.Containers[0].Env
				if got := envValues(env, "HF_HUB_OFFLINE"); !slices.Equal(got, tc.wantOffline) {
					t.Errorf("pod %d: %s values = %q, want %q", i, "HF_HUB_OFFLINE", got, tc.wantOffline)
				}
				if got := envValues(env, hfHomeEnv); !slices.Equal(got, tc.wantHFHome) {
					t.Errorf("pod %d: %s values = %q, want %q", i, hfHomeEnv, got, tc.wantHFHome)
				}
			}
		})
	}
}
