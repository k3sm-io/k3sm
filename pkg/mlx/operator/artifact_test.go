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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
)

const (
	testRegistryHost = "registry-k3sm:6450"
	testDigestA      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB      = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// countingResolver is a registry whose tag points at digest, counting the
// resolutions asked of it.
type countingResolver struct {
	calls  int
	digest string
	asked  []string
}

func (r *countingResolver) ResolveArtifact(_ context.Context, repository, tag, _ string) (string, error) {
	r.calls++
	r.asked = append(r.asked, repository+":"+tag)
	return r.digest, nil
}

// artifactHarness wires the controller over an artifact model with resolver
// and the cluster registry host configured.
func artifactHarness(t *testing.T, reference string, resolver ArtifactResolver) *harness {
	t.Helper()
	m := model(func(m *mlxv1alpha1.MLXModel) {
		m.Spec.Model = ""
		m.Spec.Artifact = &mlxv1alpha1.ArtifactRef{Reference: reference}
	})
	return newHarness(t, m, func(c *Config) {
		c.Options.RegistryHost = testRegistryHost
		c.Artifacts = resolver
	})
}

// renderedArtifactReference is the image volume reference of the applied
// StatefulSet.
func (h *harness) renderedArtifactReference(t *testing.T) string {
	t.Helper()
	sts := h.statefulSet(t)
	if sts == nil {
		t.Fatalf("no StatefulSet applied; status %+v", h.status(t).Conditions)
	}
	for _, v := range sts.Spec.Template.Spec.Volumes {
		if v.Image != nil {
			return v.Image.Reference
		}
	}
	t.Fatal("the applied StatefulSet has no image volume")
	return ""
}

// bumpGeneration stands in for the API server incrementing
// metadata.generation on a spec edit.
func (h *harness) bumpGeneration(t *testing.T) {
	t.Helper()
	res := h.dyn.Resource(mlxModelResource).Namespace(testNamespace)
	raw, err := res.Get(context.Background(), testModelName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read mlxmodel: %v", err)
	}
	raw.SetGeneration(raw.GetGeneration() + 1)
	if _, err := res.Update(context.Background(), raw, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("bump generation: %v", err)
	}
}

// TestResolvesArtifactDigestOncePerGeneration pins the resolution contract: a
// tag is resolved once per metadata.generation, recorded in
// status.resolvedArtifact and rendered by digest. A second reconcile at the
// same generation asks the registry nothing and keeps the digest even after the
// tag moved; a generation bump resolves again and re-renders against the new
// digest. A reference by digest is used as is and never asks the registry.
func TestResolvesArtifactDigestOncePerGeneration(t *testing.T) {
	reg := &countingResolver{digest: testDigestA}
	h := artifactHarness(t, testRegistryHost+"/models/qwen3:v1", reg)

	h.reconcile(t)
	h.reconcile(t)
	if reg.calls != 1 {
		t.Fatalf("resolver called %d times over two reconciles at one generation, want 1", reg.calls)
	}
	if want := "models/qwen3:v1"; reg.asked[0] != want {
		t.Errorf("resolver asked for %q, want %q", reg.asked[0], want)
	}
	if got := h.status(t).ResolvedArtifact; got != testDigestA {
		t.Fatalf("status.resolvedArtifact = %q, want %q", got, testDigestA)
	}
	if got, want := h.renderedArtifactReference(t), testRegistryHost+"/models/qwen3@"+testDigestA; got != want {
		t.Fatalf("rendered reference = %q, want %q", got, want)
	}

	// The tag moves in the registry; the generation does not.
	reg.digest = testDigestB
	h.reconcile(t)
	if reg.calls != 1 {
		t.Fatalf("resolver called %d times at an unchanged generation, want 1", reg.calls)
	}
	if got := h.status(t).ResolvedArtifact; got != testDigestA {
		t.Fatalf("status.resolvedArtifact moved to %q without a generation bump", got)
	}

	h.bumpGeneration(t)
	h.reconcile(t)
	if reg.calls != 2 {
		t.Fatalf("resolver called %d times after a generation bump, want 2", reg.calls)
	}
	if got := h.status(t).ResolvedArtifact; got != testDigestB {
		t.Fatalf("status.resolvedArtifact = %q after the bump, want %q", got, testDigestB)
	}
	if got := h.renderedArtifactReference(t); !strings.HasSuffix(got, "@"+testDigestB) {
		t.Fatalf("rendered reference = %q after the bump, want digest %s", got, testDigestB)
	}

	t.Run("by digest", func(t *testing.T) {
		reg := &countingResolver{digest: testDigestB}
		h := artifactHarness(t, testRegistryHost+"/models/qwen3@"+testDigestA, reg)
		h.reconcile(t)
		if reg.calls != 0 {
			t.Errorf("resolver called %d times for a digest reference, want 0", reg.calls)
		}
		if got := h.status(t).ResolvedArtifact; got != testDigestA {
			t.Errorf("status.resolvedArtifact = %q, want %q", got, testDigestA)
		}
	})

	t.Run("foreign host is never resolved", func(t *testing.T) {
		reg := &countingResolver{digest: testDigestA}
		h := artifactHarness(t, "ghcr.io/models/qwen3:v1", reg)
		h.reconcile(t)
		if reg.calls != 0 {
			t.Errorf("resolver called %d times for a foreign reference, want 0", reg.calls)
		}
		if h.statefulSet(t) != nil {
			t.Error("a StatefulSet was applied for a foreign artifact")
		}
		st := h.status(t)
		if st.ResolvedArtifact != "" || !hasReason(st, ReasonInvalidSpec, mlx.ErrForeignArtifact.Error()) {
			t.Errorf("status = %+v, want InvalidSpec naming the foreign host and no digest", st)
		}
	})
}

// hasReason reports whether the Ready condition carries reason and a message
// containing text.
func hasReason(st mlxv1alpha1.MLXModelStatus, reason, text string) bool {
	for _, c := range st.Conditions {
		if c.Type == mlxv1alpha1.MLXModelConditionReady {
			return c.Reason == reason && strings.Contains(c.Message, text)
		}
	}
	return false
}
