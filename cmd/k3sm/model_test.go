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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"

	"k3sm.io/k3sm/pkg/modelpack"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

func runModelCmd(t *testing.T, args []string) (string, error) {
	t.Helper()
	opts, err := parseModelArgs(args, io.Discard)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	err = modelCommand(ctx, opts, &out)
	return out.String(), err
}

// getBlob reads repository's blob digest from reg as a client would.
func getBlob(t *testing.T, reg *registrytest.Registry, repository, digest string) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/blobs/"+digest, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET blob %s/%s: HTTP %d", repository, digest, rec.Code)
	}
	return rec.Body.Bytes()
}

// TestModelPushRoundTripsThroughTheRegistry is the gate for `k3sm model push`:
// the artifact modelpack builds from a directory lands in the cluster registry
// under models/<name>, through the push gate with a builder token as every
// other write does, every file reads back byte for byte, and the printed
// digest is the manifest's. A second push of the same files uploads no blob
// and names the same digest.
func TestModelPushRoundTripsThroughTheRegistry(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")

	reg := registrytest.New()
	reg.AcceptWrites = true
	g := startGateRegistryWith(t, reg.Handler())
	// Every request but the ping must carry the builder token the push gate takes.
	g.probe.require = "Basic " + base64.StdEncoding.EncodeToString([]byte(builderTokenUser+":"+fakeBuilderTokenToken))
	clusterAPIFor(t, g)
	workDir := asServer(t, g.port)

	files := map[string]string{
		"config.json":                      `{"quantization_config":{"quant_method":"awq"}}`,
		"model.safetensors.index.json":     `{"weight_map":{}}`,
		"model-00001-of-00002.safetensors": "first half",
		"model-00002-of-00002.safetensors": "second half",
		"tokenizer.json":                   "{}",
		"README.md":                        "# llama",
	}
	dir := t.TempDir()
	for p, body := range files {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	built, err := modelpack.Build(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := built.Digest.String()

	out, err := runModelCmd(t, []string{"push", "--work-dir", workDir, dir, "llama:v1"})
	if err != nil {
		t.Fatalf("model push: %v", err)
	}
	if !strings.Contains(out, "registry-k3sm:6450/models/llama:v1") || !strings.Contains(out, want) {
		t.Errorf("push output = %q, want the flat name and the digest %s", out, want)
	}
	if got, ok := reg.Manifest("models/llama", "v1"); !ok || got != want {
		t.Fatalf("models/llama:v1 = %q (held %v), want %s", got, ok, want)
	}
	if len(g.probe.headers()) == 0 {
		t.Error("the push did not reach the gate")
	}

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/models/llama/manifests/v1", nil))
	if ct := rec.Header().Get("Content-Type"); ct != ispec.MediaTypeImageManifest {
		t.Errorf("manifest Content-Type = %q, want %q", ct, ispec.MediaTypeImageManifest)
	}
	var m ispec.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode the pushed manifest: %v", err)
	}
	if m.ArtifactType != artifactv1.ArtifactTypeModel || m.Config.MediaType != artifactv1.MediaTypeModelConfig {
		t.Errorf("pushed artifactType/config = %q/%q, want the ModelPack types", m.ArtifactType, m.Config.MediaType)
	}
	if got := getBlob(t, reg, "models/llama", m.Config.Digest.String()); !bytes.Equal(got, built.Config) {
		t.Errorf("config blob = %s, want %s", got, built.Config)
	}
	if len(m.Layers) != len(files) {
		t.Fatalf("%d layers, want %d", len(m.Layers), len(files))
	}
	for _, l := range m.Layers {
		p := l.Annotations[artifactv1.AnnotationFilepath]
		if got := getBlob(t, reg, "models/llama", l.Digest.String()); string(got) != files[p] {
			t.Errorf("layer %s read back %q, want %q", p, got, files[p])
		}
	}
	uploads := 0
	for _, w := range reg.Writes() {
		if w.Op == "upload" {
			uploads++
		}
	}
	if uploads != len(files)+1 {
		t.Errorf("first push uploaded %d blobs, want %d (every file and the config)", uploads, len(files)+1)
	}

	t.Run("a second push uploads no blob", func(t *testing.T) {
		before := len(reg.Writes())
		out, err := runModelCmd(t, []string{"push", "--work-dir", workDir, dir, "llama:v1"})
		if err != nil {
			t.Fatalf("second push: %v", err)
		}
		if !strings.Contains(out, want) {
			t.Errorf("second push output = %q, want the same digest %s", out, want)
		}
		for _, w := range reg.Writes()[before:] {
			if w.Op != "manifest" {
				t.Errorf("second push wrote %+v; want the manifest alone", w)
			}
		}
	})

	t.Run("a refused directory sends nothing", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "modeling_llama.py"), []byte("import os"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(filepath.Join(dir, "modeling_llama.py")) })
		before := len(g.probe.headers())
		if _, err := runModelCmd(t, []string{"push", "--work-dir", workDir, dir, "llama:v2"}); !errors.Is(err, artifactv1.ErrCodeFile) {
			t.Errorf("push of a directory holding code = %v, want ErrCodeFile", err)
		}
		if len(g.probe.headers()) != before {
			t.Error("a refused push still contacted the registry")
		}
	})
}

// TestModelNameIsUnderModels pins how a model name becomes a cluster-registry
// reference: under models/, tag latest by default, and never another registry
// or a digest.
func TestModelNameIsUnderModels(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"llama", "registry-k3sm:6450/models/llama:latest"},
		{"llama:v1", "registry-k3sm:6450/models/llama:v1"},
		{"meta/llama-3.1-8b:q4", "registry-k3sm:6450/models/meta/llama-3.1-8b:q4"},
		{"models/llama:v1", "registry-k3sm:6450/models/llama:v1"},
	} {
		c, err := modelReference(tc.in)
		if err != nil {
			t.Errorf("modelReference(%q): %v", tc.in, err)
			continue
		}
		if got := c.flat.String(); got != tc.want {
			t.Errorf("modelReference(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "Llama", "registry-k3sm:6450/llama", "ghcr.io/x/llama", "llama@sha256:" + strings.Repeat("a", 64), "llama:", "../llama", "models/"} {
		if c, err := modelReference(bad); err == nil {
			t.Errorf("modelReference(%q) = %s, want a refusal", bad, c.flat)
		}
	}
}

func TestModelArgs(t *testing.T) {
	for _, args := range [][]string{
		{}, {"push"}, {"push", "dir"}, {"push", "dir", "name", "extra"}, {"rm"}, {"rm", "a", "b"}, {"pull", "x"},
	} {
		if _, err := parseModelArgs(args, io.Discard); err == nil {
			t.Errorf("parseModelArgs(%q) accepted", args)
		}
	}
}

// TestModelImportArgs: `model import` takes an hf:// reference and an
// optional model name, defaulting to the repository id lowercased, and
// repeatable --sha256 path=hex; anything else is refused at parse time,
// before the Hub or the registry is contacted.
func TestModelImportArgs(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	o, err := parseModelArgs([]string{"import", "--sha256", "config.json=" + strings.ToUpper(sum), "hf://Acme/Tiny-Model@main"}, io.Discard)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.source.Repo != "Acme/Tiny-Model" || o.source.Revision != "main" || o.name != "acme/tiny-model" || o.sha256["config.json"] != sum {
		t.Errorf("parsed %+v; want the reference, the lowercased default name and the lowercased sha256", o)
	}
	o, err = parseModelArgs([]string{"import", "hf://acme/m", "llama:v1"}, io.Discard)
	if err != nil || o.name != "llama:v1" || o.source.Revision != "main" {
		t.Errorf("parse with a name = %+v, %v", o, err)
	}
	for _, args := range [][]string{
		{"import"},
		{"import", "acme/m"},
		{"import", "hf://acme/m", "a", "b"},
		{"import", "--sha256", "config.json", "hf://acme/m"},
		{"import", "--sha256", "a=" + sum, "--sha256", "a=" + sum, "hf://acme/m"},
	} {
		if _, err := parseModelArgs(args, io.Discard); err == nil {
			t.Errorf("parseModelArgs(%q) accepted", args)
		}
	}
	if _, err := runModelCmd(t, []string{"import", "hf://acme/m", "registry.example.com/m"}); err == nil || !strings.Contains(err.Error(), "name the model") {
		t.Errorf("import to a foreign registry = %v, want a refusal that asks for a model name", err)
	}
}

// TestModelPushVariant: `model push --variant` records the manifest in an OCI
// image index at the tag through the push gate, a variant push over a tag that
// names a plain manifest is refused naming the reason, and a bad variant is
// refused at parse time.
func TestModelPushVariant(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")

	reg := registrytest.New()
	reg.AcceptWrites = true
	g := startGateRegistryWith(t, reg.Handler())
	g.probe.require = "Basic " + base64.StdEncoding.EncodeToString([]byte(builderTokenUser+":"+fakeBuilderTokenToken))
	clusterAPIFor(t, g)
	workDir := asServer(t, g.port)

	dir := t.TempDir()
	for p, body := range map[string]string{"config.json": "{}", "model.safetensors": "weights"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	built, err := modelpack.Build(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runModelCmd(t, []string{"push", "--work-dir", workDir, "--variant", "4bit", dir, "llama:v1"})
	if err != nil {
		t.Fatalf("model push --variant: %v", err)
	}
	if !strings.Contains(out, "variant 4bit") || !strings.Contains(out, built.Digest.String()) {
		t.Errorf("push output = %q, want the variant and the digest %s", out, built.Digest)
	}
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/models/llama/manifests/v1", nil))
	if ct := rec.Header().Get("Content-Type"); ct != ispec.MediaTypeImageIndex {
		t.Fatalf("tag Content-Type = %q, want %q", ct, ispec.MediaTypeImageIndex)
	}
	var idx ispec.Index
	if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 1 || idx.Manifests[0].Digest != built.Digest || idx.Manifests[0].Annotations[modelpack.AnnotationVariant] != "4bit" {
		t.Errorf("index = %+v, want one 4bit entry naming %s", idx.Manifests, built.Digest)
	}

	if _, err := runModelCmd(t, []string{"push", "--work-dir", workDir, dir, "llama:plain"}); err != nil {
		t.Fatal(err)
	}
	if _, err := runModelCmd(t, []string{"push", "--work-dir", workDir, "--variant", "8bit", dir, "llama:plain"}); !errors.Is(err, modelpack.ErrTagIsManifest) {
		t.Errorf("variant over a plain manifest: err = %v, want ErrTagIsManifest", err)
	}
	for _, bad := range []string{"4 bit", "a/b", strings.Repeat("x", 129)} {
		if _, err := parseModelArgs([]string{"push", "--variant", bad, dir, "llama:v1"}, io.Discard); !errors.Is(err, modelpack.ErrInvalidVariant) {
			t.Errorf("--variant %q: err = %v, want ErrInvalidVariant", bad, err)
		}
	}
}
