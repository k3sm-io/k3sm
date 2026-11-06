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
	"errors"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	testRegistryHost = "registry-k3sm:6450"
	testDigest       = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testOtherDigest  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// artifactOptions are testOptions plus the cluster registry host.
func artifactOptions() Options {
	o := testOptions()
	o.RegistryHost = testRegistryHost
	return o
}

// artifactModel is newModel turned into an artifact model: no spec.model, no
// revision and no cache (each exclusive with spec.artifact), a tag reference
// into the cluster registry, and the digest the operator resolved it to.
func artifactModel() *mlxv1alpha1.MLXModel {
	m := newModel()
	m.Spec.Model, m.Spec.Revision, m.Spec.Cache = "", "", nil
	m.Spec.Artifact = &mlxv1alpha1.ArtifactRef{Reference: testRegistryHost + "/models/qwen3:v1"}
	m.Status.ResolvedArtifact = testDigest
	return m
}

// shardedArtifactModel is artifactModel as a two-rank ring.
func shardedArtifactModel() *mlxv1alpha1.MLXModel {
	m := artifactModel()
	m.Spec.Replicas = nil
	m.Spec.Distributed = &mlxv1alpha1.MLXDistributed{Ranks: 2, Backend: mlxv1alpha1.MLXDistributedBackendRing}
	return m
}

// renderedPods renders m on the single-node path, or the sharded path
// when it sets spec.distributed, and returns every pod spec and annotation
// set the render produced.
func renderedPods(t *testing.T, m *mlxv1alpha1.MLXModel) (specs []corev1.PodSpec, annotations []map[string]string) {
	t.Helper()
	if m.Spec.Distributed == nil {
		objs, err := Render(m, artifactOptions())
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		tmpl := objs.StatefulSet.Spec.Template
		if n := len(objs.StatefulSet.Spec.VolumeClaimTemplates); n != 0 {
			t.Errorf("artifact model rendered %d volumeClaimTemplates, want none", n)
		}
		return []corev1.PodSpec{tmpl.Spec}, []map[string]string{tmpl.Annotations}
	}
	objs, err := RenderSharded(m, artifactOptions(), ringPlacement())
	if err != nil {
		t.Fatalf("RenderSharded: %v", err)
	}
	if len(objs.Claims) != 0 {
		t.Errorf("artifact model rendered %d cache claims, want none", len(objs.Claims))
	}
	for _, p := range objs.Pods {
		specs = append(specs, p.Spec)
		annotations = append(annotations, p.Annotations)
	}
	return specs, annotations
}

// flagValue returns the argument after flag in args, or "" when absent.
func flagValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

// TestRenderArtifactModelAsImageVolume pins the artifact render on both
// paths: one image volume pinned to the resolved digest (never the tag) with
// pullPolicy IfNotPresent, mounted read-only, its mount path the engine's
// model path, and the model served under metadata.name. A digest reference
// renders that digest.
func TestRenderArtifactModelAsImageVolume(t *testing.T) {
	byDigest := artifactModel()
	byDigest.Spec.Artifact.Reference = testRegistryHost + "/models/qwen3@" + testDigest
	cases := []struct {
		name  string
		model *mlxv1alpha1.MLXModel
	}{
		{"single-node by tag", artifactModel()},
		{"single-node by digest", byDigest},
		{"sharded by tag", shardedArtifactModel()},
	}
	wantRef := testRegistryHost + "/models/qwen3@" + testDigest
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specs, _ := renderedPods(t, tc.model)
			for i, spec := range specs {
				if len(spec.Volumes) != 1 {
					t.Fatalf("pod %d: %d volumes, want exactly the artifact volume: %+v", i, len(spec.Volumes), spec.Volumes)
				}
				vol := spec.Volumes[0]
				if vol.Image == nil {
					t.Fatalf("pod %d: volume %q is not an image volume: %+v", i, vol.Name, vol.VolumeSource)
				}
				if vol.Image.Reference != wantRef {
					t.Errorf("pod %d: image volume reference = %q, want %q", i, vol.Image.Reference, wantRef)
				}
				if vol.Image.PullPolicy != corev1.PullIfNotPresent {
					t.Errorf("pod %d: pullPolicy = %q, want %q", i, vol.Image.PullPolicy, corev1.PullIfNotPresent)
				}
				c := spec.Containers[0]
				if len(c.VolumeMounts) != 1 {
					t.Fatalf("pod %d: %d mounts, want one: %+v", i, len(c.VolumeMounts), c.VolumeMounts)
				}
				mnt := c.VolumeMounts[0]
				if mnt.Name != vol.Name || mnt.MountPath != ArtifactMountPath || !mnt.ReadOnly {
					t.Errorf("pod %d: mount = %+v, want %q read-only at %s", i, mnt, vol.Name, ArtifactMountPath)
				}
				var model string
				if tc.model.Spec.Distributed == nil {
					model = c.Args[0]
				} else {
					model = flagValue(c.Args, shardModelFlag)
				}
				if model != ArtifactMountPath {
					t.Errorf("pod %d: engine model path = %q, want the mount path %s (args %q)", i, model, ArtifactMountPath, c.Args)
				}
				if got := flagValue(c.Args, argServedModelName); got != tc.model.Name {
					t.Errorf("pod %d: served model name = %q, want metadata.name %q", i, got, tc.model.Name)
				}
			}
		})
	}
}

// TestRenderArtifactModelHasNoCachePVCOrEgress pins what an artifact model
// does NOT get: no cache claim or claim volume, no HF_HOME, no egress
// annotation, and nothing in the argv naming the Hub. A spec.cache set beside
// spec.artifact is refused rather than silently dropped.
func TestRenderArtifactModelHasNoCachePVCOrEgress(t *testing.T) {
	for _, m := range []*mlxv1alpha1.MLXModel{artifactModel(), shardedArtifactModel()} {
		specs, annotations := renderedPods(t, m)
		for i, spec := range specs {
			for _, v := range spec.Volumes {
				if v.PersistentVolumeClaim != nil {
					t.Errorf("pod %d: claim volume %q on an artifact model", i, v.Name)
				}
			}
			c := spec.Containers[0]
			for _, e := range c.Env {
				if e.Name == hfHomeEnv {
					t.Errorf("pod %d: %s=%q on an artifact model", i, e.Name, e.Value)
				}
			}
			for _, a := range c.Args {
				if strings.Contains(a, "huggingface") || strings.Contains(a, CacheMountPath) {
					t.Errorf("pod %d: argv names the Hub cache: %q", i, c.Args)
				}
			}
			if _, ok := annotations[i][runtimev1.AnnotationInternetEgress]; ok {
				t.Errorf("pod %d: carries %s", i, runtimev1.AnnotationInternetEgress)
			}
		}
	}

	for _, m := range []*mlxv1alpha1.MLXModel{artifactModel(), shardedArtifactModel()} {
		m.Spec.Cache = &mlxv1alpha1.MLXCache{Size: resource.MustParse("64Gi")}
		if err := renderEither(m); !errors.Is(err, ErrArtifactConflict) {
			t.Errorf("spec.cache beside spec.artifact (distributed=%v): err = %v, want ErrArtifactConflict", m.Spec.Distributed != nil, err)
		}
	}
}

// renderEither renders m on its path and returns the render error.
func renderEither(m *mlxv1alpha1.MLXModel) error {
	if m.Spec.Distributed == nil {
		_, err := Render(m, artifactOptions())
		return err
	}
	_, err := RenderSharded(m, artifactOptions(), ringPlacement())
	return err
}

// TestRenderRefusesUnresolvedOrForeignArtifact pins the refusals: a reference
// off the cluster registry host (or with no host configured to compare with),
// a digest not yet resolved or stale for a digest reference, a malformed
// reference, and the Hub-only fields beside spec.artifact. Each refuses on
// both paths with its sentinel and renders nothing, so no Hub fetch is ever
// rendered for an artifact model.
func TestRenderRefusesUnresolvedOrForeignArtifact(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*mlxv1alpha1.MLXModel, *Options)
		want   error
	}{
		{"foreign host", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Artifact.Reference = "ghcr.io/models/qwen3:v1"
		}, ErrForeignArtifact},
		{"host-less reference", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Artifact.Reference = "models/qwen3:v1"
		}, ErrForeignArtifact},
		{"cluster host on another port", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Artifact.Reference = "registry-k3sm:6451/models/qwen3:v1"
		}, ErrForeignArtifact},
		{"no registry host configured", func(_ *mlxv1alpha1.MLXModel, o *Options) {
			o.RegistryHost = ""
		}, ErrForeignArtifact},
		{"unresolved", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Status.ResolvedArtifact = ""
		}, ErrArtifactUnresolved},
		{"resolved to a non-digest", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Status.ResolvedArtifact = "v1"
		}, ErrArtifactUnresolved},
		{"stale digest for a digest reference", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Artifact.Reference = testRegistryHost + "/models/qwen3@" + testOtherDigest
		}, ErrArtifactUnresolved},
		{"no tag or digest", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Artifact.Reference = testRegistryHost + "/models/qwen3"
		}, ErrInvalidArtifact},
		{"short digest", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Artifact.Reference = testRegistryHost + "/models/qwen3@sha256:22"
		}, ErrInvalidArtifact},
		{"spec.model beside spec.artifact", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Model = "mlx-community/Qwen3-0.6B-4bit"
		}, ErrArtifactConflict},
		{"spec.revision beside spec.artifact", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Revision = "0f1e2d3c4b5a69788796a5b4c3d2e1f001234567"
		}, ErrArtifactConflict},
		{"variant", func(m *mlxv1alpha1.MLXModel, _ *Options) {
			m.Spec.Artifact.Variant = "4bit"
		}, ErrArtifactVariantUnsupported},
	}
	for _, tc := range cases {
		for _, base := range []func() *mlxv1alpha1.MLXModel{artifactModel, shardedArtifactModel} {
			m := base()
			opts := artifactOptions()
			tc.mutate(m, &opts)
			name := tc.name + map[bool]string{false: "/single-node", true: "/sharded"}[m.Spec.Distributed != nil]
			t.Run(name, func(t *testing.T) {
				var got bool
				var err error
				if m.Spec.Distributed == nil {
					objs, rerr := Render(m, opts)
					got, err = objs != nil, rerr
				} else {
					objs, rerr := RenderSharded(m, opts, ringPlacement())
					got, err = objs != nil, rerr
					if _, _, serr := RenderShardedServices(m, opts); !errors.Is(serr, tc.want) {
						t.Errorf("RenderShardedServices: err = %v, want %v", serr, tc.want)
					}
				}
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				if got {
					t.Error("a refused artifact model rendered objects")
				}
			})
		}
	}
}
