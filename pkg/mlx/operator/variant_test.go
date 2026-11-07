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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
	"k3sm.io/runtimed/pkg/artifact"
)

// variantEntry is one index entry: a manifest descriptor and the variant
// annotation it carries ("" for none).
type variantEntry struct {
	desc    registryclient.Descriptor
	variant string
}

// putIndex stores an OCI image index over entries at repository:tag and
// returns its digest.
func putIndex(t *testing.T, reg *registrytest.Registry, repository, tag string, entries ...variantEntry) string {
	t.Helper()
	ms := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		m := map[string]any{"mediaType": registryclient.MediaTypeOCIManifest, "digest": e.desc.Digest, "size": e.desc.Size}
		if e.variant != "" {
			m["annotations"] = map[string]string{artifact.AnnotationVariant: e.variant}
		}
		ms = append(ms, m)
	}
	body, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": registryclient.MediaTypeOCIIndex, "manifests": ms})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/v2/"+repository+"/manifests/"+tag, bytes.NewReader(body))
	req.Header.Set("Content-Type", registryclient.MediaTypeOCIIndex)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT index %s:%s: HTTP %d %s", repository, tag, rec.Code, rec.Body)
	}
	return rec.Header().Get("Docker-Content-Digest")
}

// handlerTransport serves every request with h in process, through a
// response recorder: no socket is opened.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	in := req.Clone(req.Context())
	in.RequestURI = req.URL.RequestURI()
	if in.Body == nil {
		in.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, in)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// putManifestAt stores body at repository:reference served as mediaType
// and returns its digest.
func putManifestAt(t *testing.T, reg *registrytest.Registry, repository, reference, mediaType string, body []byte) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v2/"+repository+"/manifests/"+reference, bytes.NewReader(body))
	req.Header.Set("Content-Type", mediaType)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT %s:%s: HTTP %d %s", repository, reference, rec.Code, rec.Body)
	}
	return rec.Header().Get("Docker-Content-Digest")
}

// putManifest stores body by its digest in repository, untagged.
func putManifest(t *testing.T, reg *registrytest.Registry, repository, mediaType string, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	return putManifestAt(t, reg, repository, "sha256:"+hex.EncodeToString(sum[:]), mediaType, body)
}

// q4config is a config descriptor for a blob stored in repository.
func q4config(t *testing.T, reg *registrytest.Registry, repository string) registryclient.Descriptor {
	t.Helper()
	body := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers"}}`)
	sum := sha256.Sum256(body)
	d := "sha256:" + hex.EncodeToString(sum[:])
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v2/"+repository+"/blobs/uploads/?digest="+d, bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload config: HTTP %d", rec.Code)
	}
	return registryclient.Descriptor{MediaType: "application/vnd.docker.container.image.v1+json", Digest: d, Size: int64(len(body))}
}

// TestResolveArtifactVariant: spec.quantization selects the index entry whose
// variant annotation equals it, by tag or by the index's digest, and the
// selected manifest's digest is recorded and rendered. No matching entry,
// two matching entries, a single manifest with quantization set and an index
// without quantization are each refused as InvalidSpec naming the reason,
// with no digest recorded and nothing applied.
// It also refuses an entry whose digest holds a Docker manifest.
func TestResolveArtifactVariant(t *testing.T) {
	const repo = "models/qwen3"
	reg := registrytest.New()
	reg.AcceptWrites = true
	client, err := registryclient.New("https://"+testRegistryHost, registryclient.Options{Transport: handlerTransport{reg.Handler()}})
	if err != nil {
		t.Fatal(err)
	}
	plat := registryclient.Platform{OS: "linux", Architecture: "arm64"}
	q4 := reg.Image(repo, "", plat, []byte("four"))
	q8 := reg.Image(repo, "", plat, []byte("eight"))
	reg.Image(repo, "plain", plat, []byte("plain"))
	indexDigest := putIndex(t, reg, repo, "v1", variantEntry{q4, "4bit"}, variantEntry{q8, "8bit"})
	putIndex(t, reg, repo, "dup", variantEntry{q4, "4bit"}, variantEntry{q8, "4bit"})
	// An entry that claims an OCI image manifest whose digest holds a
	// Docker schema 2 manifest.
	dockerBody, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": registryclient.MediaTypeDockerManifest,
		"config": q4config(t, reg, repo), "layers": []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	docker := registryclient.Descriptor{MediaType: registryclient.MediaTypeOCIManifest, Digest: putManifest(t, reg, repo, registryclient.MediaTypeDockerManifest, dockerBody), Size: int64(len(dockerBody))}
	putIndex(t, reg, repo, "docker", variantEntry{docker, "4bit"})

	harnessFor := func(t *testing.T, reference, quantization string) *harness {
		t.Helper()
		m := model(func(m *mlxv1alpha1.MLXModel) {
			m.Spec.Model = ""
			m.Spec.Quantization = quantization
			m.Spec.Artifact = &mlxv1alpha1.ArtifactRef{Reference: testRegistryHost + "/" + repo + reference}
		})
		return newHarness(t, m, func(c *Config) {
			c.Options.RegistryHost = testRegistryHost
			c.Artifacts = RegistryResolver(client)
		})
	}

	for _, tc := range []struct {
		name, reference, quantization string
		want                          string
	}{
		{"by tag", ":v1", "8bit", q8.Digest},
		{"by tag, the other variant", ":v1", "4bit", q4.Digest},
		{"by index digest", "@" + indexDigest, "8bit", q8.Digest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := harnessFor(t, tc.reference, tc.quantization)
			h.reconcile(t)
			if got := h.status(t).ResolvedArtifact; got != tc.want {
				t.Fatalf("status.resolvedArtifact = %q, want the %s manifest %s", got, tc.quantization, tc.want)
			}
			if got, want := h.renderedArtifactReference(t), testRegistryHost+"/"+repo+"@"+tc.want; got != want {
				t.Errorf("rendered reference = %q, want %q", got, want)
			}
		})
	}

	for _, tc := range []struct {
		name, reference, quantization string
		want                          error
	}{
		{"no entry carries the variant", ":v1", "bf16", artifact.ErrVariantNotFound},
		{"two entries carry the variant", ":dup", "4bit", artifact.ErrVariantAmbiguous},
		{"a single manifest with quantization", ":plain", "4bit", artifact.ErrVariantOnManifest},
		{"an index without quantization", ":v1", "", artifact.ErrVariantRequired},
		{"a docker manifest at the selected digest", ":docker", "4bit", artifact.ErrManifestInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := harnessFor(t, tc.reference, tc.quantization)
			err := h.ctrl.Reconcile(context.Background(), key())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Reconcile = %v, want %v", err, tc.want)
			}
			st := h.status(t)
			if st.ResolvedArtifact != "" {
				t.Errorf("status.resolvedArtifact = %q after a refusal, want empty", st.ResolvedArtifact)
			}
			if !hasReason(st, ReasonInvalidSpec, tc.want.Error()) {
				t.Errorf("status = %+v, want InvalidSpec naming %q", st.Conditions, tc.want)
			}
			if tc.quantization != "" && !hasReason(st, ReasonInvalidSpec, `"`+tc.quantization+`"`) {
				t.Errorf("status = %+v, want the message to name the variant %q", st.Conditions, tc.quantization)
			}
			if h.statefulSet(t) != nil {
				t.Error("a StatefulSet was applied for a refused variant")
			}
		})
	}
}
