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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	artifactv1 "k3sm.io/apis/artifact/v1"

	"k3sm.io/k3sm/pkg/modelpack"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// storeModel builds the model whose files are files and writes it into reg as
// repository:tag through the registry's push endpoints, returning it.
func storeModel(t *testing.T, reg *registrytest.Registry, repository, tag string, files map[string]string) *modelpack.Artifact {
	t.Helper()
	dir := t.TempDir()
	for p, body := range files {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, err := modelpack.Build(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	put := func(digest string, body []byte) {
		t.Helper()
		rec := httptest.NewRecorder()
		reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v2/"+repository+"/blobs/uploads/?digest="+digest, bytes.NewReader(body)))
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload %s: HTTP %d", digest, rec.Code)
		}
	}
	put(a.ConfigDescriptor.Digest.String(), a.Config)
	for _, l := range a.Layers {
		rc, err := a.Open(l)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		put(l.Descriptor.Digest.String(), b)
	}
	storeManifest(t, reg, repository, tag, a.Manifest)
	return a
}

func storeManifest(t *testing.T, reg *registrytest.Registry, repository, tag string, body []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v2/"+repository+"/manifests/"+tag, bytes.NewReader(body))
	req.Header.Set("Content-Type", registryclient.MediaTypeOCIManifest)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("put manifest %s:%s: HTTP %d", repository, tag, rec.Code)
	}
}

// modelLsFixture is a registry holding two models, a model whose config blob
// is not JSON, an image filed under models/, and an image outside models/.
type modelLsFixture struct {
	env          imageRegistryEnv
	reg          *registrytest.Registry
	llama, qwen  *modelpack.Artifact
	brokenDigest string
}

func newModelLsFixture(t *testing.T, reachable bool) modelLsFixture {
	t.Helper()
	reg := registrytest.New()
	reg.AcceptWrites = true
	f := modelLsFixture{reg: reg}
	f.llama = storeModel(t, reg, "models/llama", "v1", map[string]string{
		"config.json":                      `{"model_type":"llama","quantization":{"group_size":64,"bits":4}}`,
		"model.safetensors.index.json":     `{"weight_map":{}}`,
		"model-00001-of-00002.safetensors": "first half",
		"model-00002-of-00002.safetensors": "second half",
		"tokenizer.json":                   "{}",
	})
	f.qwen = storeModel(t, reg, "models/qwen", "q4", map[string]string{
		"config.json": `{"quantization":"Q4_K_M","paramSize":"7B"}`,
		"qwen.gguf":   "gguf weights",
	})
	// A ModelPack manifest whose config blob is not JSON: listed, without
	// metadata, never a failed listing.
	bad := []byte("not json")
	rec := httptest.NewRecorder()
	badDigest := "sha256:" + sha256Hex(bad)
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v2/models/broken/blobs/uploads/?digest="+badDigest, bytes.NewReader(bad)))
	broken, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": registryclient.MediaTypeOCIManifest, "artifactType": artifactv1.ArtifactTypeModel,
		"config": map[string]any{"mediaType": artifactv1.MediaTypeModelConfig, "digest": badDigest, "size": len(bad)},
		"layers": []any{},
	})
	storeManifest(t, reg, "models/broken", "v1", broken)
	f.brokenDigest = "sha256:" + sha256Hex(broken)
	reg.Image("models/notamodel", "v1", registryclient.Platform{OS: "linux", Architecture: "arm64"}, []byte("layer"))
	reg.Image("app", "v1", registryclient.Platform{OS: "linux", Architecture: "arm64"}, []byte("layer"))

	var transport http.RoundTripper = handlerTransport{reg.Handler()}
	if !reachable {
		transport = refusedTransport{}
	}
	doc, err := registrysvc.HostingDocument(6450, "")
	if err != nil {
		t.Fatal(err)
	}
	hosting := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: registrysvc.HostingNamespace, Name: registrysvc.HostingConfigMapName},
		Data:       map[string]string{registrysvc.HostingDataKey: string(doc)},
	}
	f.env = imageRegistryEnv{kube: fake.NewSimpleClientset(hosting), apiHost: "127.0.0.1", transport: transport}
	return f
}

func runModelLs(t *testing.T, env imageRegistryEnv, args ...string) string {
	t.Helper()
	o, err := parseModelArgs(append([]string{"ls"}, args...), io.Discard)
	if err != nil {
		t.Fatalf("parseModelArgs(ls %v): %v", args, err)
	}
	var out bytes.Buffer
	if err := modelLs(context.Background(), o, &out, env); err != nil {
		t.Fatalf("model ls %v: %v", args, err)
	}
	return out.String()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func layersSize(a *modelpack.Artifact) int64 {
	var n int64
	for _, l := range a.Layers {
		n += l.Descriptor.Size
	}
	return n
}

// TestModelLsReadsManifestAndConfig is the gate for `k3sm model ls`: every
// tag under models/ whose manifest carries the ModelPack artifactType is
// listed with its format, total size, file count, shard count, quantization
// and parameter size, read from the manifest and the ModelPack config alone.
// No file of the model is fetched; an image filed under models/ and a
// repository outside it are not listed; a model whose config cannot be
// decoded is listed without metadata rather than failing the listing.
func TestModelLsReadsManifestAndConfig(t *testing.T) {
	f := newModelLsFixture(t, true)
	f.reg.ResetRequests()

	var rep modelListReport
	if err := json.Unmarshal([]byte(runModelLs(t, f.env, "-o", "json")), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Registry.Reachable || rep.SchemaVersion != 1 {
		t.Fatalf("registry/schemaVersion = %+v/%d, want reachable, 1", rep.Registry, rep.SchemaVersion)
	}
	want := []modelRow{
		{
			Name: "broken", Repository: "models/broken", Tag: "v1",
			Reference: "registry-k3sm:6450/models/broken:v1", Digest: f.brokenDigest,
			Error: rep.Models[0].Error,
		},
		{
			Name: "llama", Repository: "models/llama", Tag: "v1",
			Reference: "registry-k3sm:6450/models/llama:v1", Digest: f.llama.Digest.String(),
			Format: "safetensors", SizeBytes: layersSize(f.llama), Files: 5, Shards: 2, Quantization: "4bit",
		},
		{
			Name: "qwen", Repository: "models/qwen", Tag: "q4",
			Reference: "registry-k3sm:6450/models/qwen:q4", Digest: f.qwen.Digest.String(),
			Format: "gguf", SizeBytes: layersSize(f.qwen), Files: 2, Shards: 1, Quantization: "Q4_K_M", ParamSize: "7B",
		},
	}
	if !slices.Equal(rep.Models, want) {
		t.Errorf("models =\n%+v\nwant\n%+v", rep.Models, want)
	}
	if rep.Models[0].Error == "" {
		t.Error("the model with an undecodable config carries no error")
	}
	// Two models, one broken: one config blob each, and no other blob.
	if got := f.reg.Requests(http.MethodGet, registrytest.ClassBlob); got != 3 {
		t.Errorf("fetched %d blobs, want 3 (one config per model, no file)", got)
	}
	if got := f.reg.Requests(http.MethodGet, registrytest.ClassTags); got != 4 {
		t.Errorf("read %d tag lists, want 4 (models/ only)", got)
	}

	t.Run("table", func(t *testing.T) {
		out := runModelLs(t, f.env)
		for _, s := range []string{"NAME", "FORMAT", "QUANT", "llama:v1", "safetensors", "4bit", "qwen:q4", "gguf", "Q4_K_M", "7B", "broken:v1"} {
			if !strings.Contains(out, s) {
				t.Errorf("table lacks %q:\n%s", s, out)
			}
		}
		for _, s := range []string{"notamodel", "app"} {
			if strings.Contains(out, s) {
				t.Errorf("table lists %q:\n%s", s, out)
			}
		}
	})
	t.Run("an unreachable registry is reported, not an error", func(t *testing.T) {
		u := newModelLsFixture(t, false)
		var rep modelListReport
		if err := json.Unmarshal([]byte(runModelLs(t, u.env, "-o", "json")), &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Registry.Reachable || rep.Registry.Error == "" || rep.Models == nil || len(rep.Models) != 0 {
			t.Errorf("report = %+v, want unreachable with an error and an empty models list", rep)
		}
		if out := runModelLs(t, u.env); !strings.Contains(out, "unreachable") {
			t.Errorf("table = %q, want the registry named unreachable", out)
		}
	})
}

// TestModelLsJSONShape pins `k3sm model ls -o json` key for key, so the app
// can read it: a versioned document whose shape only ever grows. Every model
// key is present on every row, empty when the model does not record it; only
// error is omitted when there is none.
func TestModelLsJSONShape(t *testing.T) {
	f := newModelLsFixture(t, true)
	var doc map[string]any
	if err := json.Unmarshal([]byte(runModelLs(t, f.env, "-o", "json")), &doc); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	if got, want := keys(doc), []string{"models", "registry", "schemaVersion"}; !slices.Equal(got, want) {
		t.Errorf("top-level keys = %v, want %v", got, want)
	}
	if v, ok := doc["schemaVersion"].(float64); !ok || v != 1 {
		t.Errorf("schemaVersion = %v, want 1", doc["schemaVersion"])
	}
	if got, want := keys(doc["registry"].(map[string]any)), []string{"name", "reachable"}; !slices.Equal(got, want) {
		t.Errorf("registry keys = %v, want %v", got, want)
	}
	models, ok := doc["models"].([]any)
	if !ok || len(models) != 3 {
		t.Fatalf("models = %v, want three rows", doc["models"])
	}
	rowKeys := []string{"digest", "files", "format", "name", "paramSize", "quantization", "reference", "repository", "shards", "sizeBytes", "tag"}
	for _, m := range models {
		row := m.(map[string]any)
		got := keys(row)
		want := rowKeys
		if row["name"] == "broken" {
			want = slices.Sorted(slices.Values(append(slices.Clone(rowKeys), "error")))
		}
		if !slices.Equal(got, want) {
			t.Errorf("row %v keys = %v, want %v", row["name"], got, want)
		}
		for _, k := range []string{"files", "shards", "sizeBytes"} {
			if _, ok := row[k].(float64); !ok {
				t.Errorf("row %v %s = %T, want a number", row["name"], k, row[k])
			}
		}
		for _, k := range []string{"digest", "format", "name", "paramSize", "quantization", "reference", "repository", "tag"} {
			if _, ok := row[k].(string); !ok {
				t.Errorf("row %v %s = %T, want a string", row["name"], k, row[k])
			}
		}
	}
	if _, err := parseModelArgs([]string{"ls", "-o", "yaml"}, io.Discard); err == nil {
		t.Error("ls -o yaml accepted")
	}
	if _, err := parseModelArgs([]string{"ls", "extra"}, io.Discard); err == nil {
		t.Error("ls with an argument accepted")
	}
}
