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

package modelpack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// writeTree writes files (relative slash path -> content) under a fresh
// directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, body := range files {
		abs := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func build(t *testing.T, dir string) *Artifact {
	t.Helper()
	a, err := Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("Build(%s): %v", dir, err)
	}
	return a
}

func decodeManifest(t *testing.T, a *Artifact) ispec.Manifest {
	t.Helper()
	var m ispec.Manifest
	if err := json.Unmarshal(a.Manifest, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return m
}

func decodeConfig(t *testing.T, a *Artifact) Config {
	t.Helper()
	var c Config
	if err := json.Unmarshal(a.Config, &c); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return c
}

// layerTypes is the media type of each layer, keyed by its file path.
func layerTypes(t *testing.T, m ispec.Manifest) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range m.Layers {
		out[l.Annotations[artifactv1.AnnotationFilepath]] = l.MediaType
	}
	return out
}

// TestManifestOneRawLayerPerFile pins the k3sm profile of ModelPack: one raw
// layer per file, typed by what the file is, carrying its validated path in
// both the ModelPack and the OCI title annotation; the ModelPack artifactType
// and config media type; and a config that records the format and lists every
// layer's digest.
func TestManifestOneRawLayerPerFile(t *testing.T) {
	files := map[string]string{
		"config.json":             `{"model_type":"llama","quantization_config":{"quant_method":"awq"},"paramSize":"8b"}`,
		"tokenizer.json":          `{"version":"1.0"}`,
		"tokenizer_config.json":   `{}`,
		"model.safetensors":       "weights",
		"README.md":               "# a model",
		"LICENSE":                 "apache",
		"chat/template.jinja":     "{{ messages }}",
		"generation_config.json":  `{"temperature":0.7}`,
		"special_tokens_map.json": `{}`,
	}
	a := build(t, writeTree(t, files))
	m := decodeManifest(t, a)

	if m.SchemaVersion != 2 || m.MediaType != ispec.MediaTypeImageManifest {
		t.Errorf("manifest schemaVersion/mediaType = %d/%q, want 2/%q", m.SchemaVersion, m.MediaType, ispec.MediaTypeImageManifest)
	}
	if m.ArtifactType != artifactv1.ArtifactTypeModel {
		t.Errorf("artifactType = %q, want %q", m.ArtifactType, artifactv1.ArtifactTypeModel)
	}
	if m.Config.MediaType != artifactv1.MediaTypeModelConfig {
		t.Errorf("config mediaType = %q, want %q", m.Config.MediaType, artifactv1.MediaTypeModelConfig)
	}
	if got := sha(string(a.Config)); m.Config.Digest.String() != got || m.Config.Size != int64(len(a.Config)) {
		t.Errorf("config descriptor = %s/%d, want %s/%d", m.Config.Digest, m.Config.Size, got, len(a.Config))
	}
	if got := sha(string(a.Manifest)); a.Digest.String() != got {
		t.Errorf("artifact digest = %s, want the manifest bytes' %s", a.Digest, got)
	}
	if len(m.Layers) != len(files) {
		t.Fatalf("%d layers, want one per file (%d)", len(m.Layers), len(files))
	}
	want := map[string]string{
		"config.json":             artifactv1.MediaTypeModelWeightConfig,
		"tokenizer.json":          artifactv1.MediaTypeModelWeightConfig,
		"tokenizer_config.json":   artifactv1.MediaTypeModelWeightConfig,
		"generation_config.json":  artifactv1.MediaTypeModelWeightConfig,
		"special_tokens_map.json": artifactv1.MediaTypeModelWeightConfig,
		"chat/template.jinja":     artifactv1.MediaTypeModelWeightConfig,
		"model.safetensors":       artifactv1.MediaTypeModelWeight,
		"README.md":               artifactv1.MediaTypeModelDoc,
		"LICENSE":                 artifactv1.MediaTypeModelDoc,
	}
	allow := artifactv1.ImageVolumeAllowSet()
	var paths []string
	for i, l := range m.Layers {
		p := l.Annotations[artifactv1.AnnotationFilepath]
		paths = append(paths, p)
		if l.Annotations[ispec.AnnotationTitle] != p {
			t.Errorf("layer %d: title %q, filepath %q; want them equal", i, l.Annotations[ispec.AnnotationTitle], p)
		}
		if len(l.Annotations) != 2 {
			t.Errorf("layer %s: annotations %v, want only filepath and title", p, l.Annotations)
		}
		if l.MediaType != want[p] {
			t.Errorf("layer %s: mediaType %q, want %q", p, l.MediaType, want[p])
		}
		if !strings.HasSuffix(l.MediaType, ".raw") || !allow.AllowsLayer(artifactv1.ArtifactTypeModel, l.MediaType) {
			t.Errorf("layer %s: mediaType %q is not a raw model layer the image-volume allow-set takes", p, l.MediaType)
		}
		if l.Digest.String() != sha(files[p]) || l.Size != int64(len(files[p])) {
			t.Errorf("layer %s: %s/%d, want %s/%d", p, l.Digest, l.Size, sha(files[p]), len(files[p]))
		}
	}
	if !slices.IsSorted(paths) {
		t.Errorf("layers are not sorted by path: %v", paths)
	}

	c := decodeConfig(t, a)
	if c.Config.Format != FormatSafetensors {
		t.Errorf("config format = %q, want %q", c.Config.Format, FormatSafetensors)
	}
	if c.Config.Quantization != "awq" || c.Config.ParamSize != "8b" {
		t.Errorf("config quantization/paramSize = %q/%q, want awq/8b copied from config.json", c.Config.Quantization, c.Config.ParamSize)
	}
	if c.ModelFS.Type != "layers" || len(c.ModelFS.DiffIDs) != len(m.Layers) {
		t.Fatalf("modelfs = %+v, want type layers and one diffId per layer", c.ModelFS)
	}
	for i, l := range m.Layers {
		if c.ModelFS.DiffIDs[i] != l.Digest {
			t.Errorf("diffIds[%d] = %s, want the raw layer's digest %s", i, c.ModelFS.DiffIDs[i], l.Digest)
		}
	}

	// Every layer reads back as the bytes it was hashed from.
	for _, l := range a.Layers {
		rc, err := a.Open(l)
		if err != nil {
			t.Fatalf("open %s: %v", l.Path, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || string(b) != files[l.Path] {
			t.Errorf("read %s = %q, %v; want %q", l.Path, b, err, files[l.Path])
		}
	}
}

// TestOpenRefusesAFileThatChanged pins that the bytes uploaded are the bytes
// the manifest names: a file rewritten after Build fails its read at the end.
func TestOpenRefusesAFileThatChanged(t *testing.T) {
	dir := writeTree(t, map[string]string{"model.safetensors": "weights", "config.json": "{}"})
	a := build(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("WEIGHTS"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, l := range a.Layers {
		if l.Path != "model.safetensors" {
			continue
		}
		rc, err := a.Open(l)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(rc)
		rc.Close()
		if !errors.Is(err, ErrContentChanged) {
			t.Errorf("read of a rewritten file: %v, want ErrContentChanged", err)
		}
	}
}

func TestSplitSafetensorsIsNLayers(t *testing.T) {
	split := map[string]string{
		"config.json":                      "{}",
		"model.safetensors.index.json":     `{"weight_map":{}}`,
		"model-00001-of-00003.safetensors": "one",
		"model-00002-of-00003.safetensors": "two",
		"model-00003-of-00003.safetensors": "three",
		"tokenizer.json":                   "{}",
	}
	a := build(t, writeTree(t, split))
	got := layerTypes(t, decodeManifest(t, a))
	var weights []string
	for p, mt := range got {
		if mt == artifactv1.MediaTypeModelWeight {
			weights = append(weights, p)
		}
	}
	slices.Sort(weights)
	if want := []string{"model-00001-of-00003.safetensors", "model-00002-of-00003.safetensors", "model-00003-of-00003.safetensors"}; !slices.Equal(weights, want) {
		t.Errorf("weight layers = %v, want the three splits by name %v", weights, want)
	}
	if got["model.safetensors.index.json"] != artifactv1.MediaTypeModelWeightConfig {
		t.Errorf("the index is %q, want a weight-config layer", got["model.safetensors.index.json"])
	}
	if f := decodeConfig(t, a).Config.Format; f != FormatSafetensors {
		t.Errorf("format = %q, want safetensors", f)
	}

	t.Run("a missing split is refused", func(t *testing.T) {
		m := maps.Clone(split)
		delete(m, "model-00002-of-00003.safetensors")
		if _, err := Build(context.Background(), writeTree(t, m)); !errors.Is(err, ErrIncompleteSplit) {
			t.Errorf("Build = %v, want ErrIncompleteSplit", err)
		}
	})
	t.Run("a split set without its index is refused", func(t *testing.T) {
		m := maps.Clone(split)
		delete(m, "model.safetensors.index.json")
		if _, err := Build(context.Background(), writeTree(t, m)); !errors.Is(err, ErrIncompleteSplit) {
			t.Errorf("Build = %v, want ErrIncompleteSplit", err)
		}
	})
}

func TestSplitGGUFIsNLayers(t *testing.T) {
	split := map[string]string{
		"llama-q4_k_m-00001-of-00002.gguf": "one",
		"llama-q4_k_m-00002-of-00002.gguf": "two",
		"README.md":                        "doc",
	}
	a := build(t, writeTree(t, split))
	m := decodeManifest(t, a)
	got := layerTypes(t, m)
	if len(m.Layers) != 3 {
		t.Fatalf("%d layers, want 3", len(m.Layers))
	}
	for _, p := range []string{"llama-q4_k_m-00001-of-00002.gguf", "llama-q4_k_m-00002-of-00002.gguf"} {
		if got[p] != artifactv1.MediaTypeModelWeight {
			t.Errorf("%s is %q, want a weight layer under its own name", p, got[p])
		}
	}
	if f := decodeConfig(t, a).Config.Format; f != FormatGGUF {
		t.Errorf("format = %q, want gguf", f)
	}

	t.Run("a missing split is refused", func(t *testing.T) {
		m := maps.Clone(split)
		delete(m, "llama-q4_k_m-00001-of-00002.gguf")
		if _, err := Build(context.Background(), writeTree(t, m)); !errors.Is(err, ErrIncompleteSplit) {
			t.Errorf("Build = %v, want ErrIncompleteSplit", err)
		}
	})
	t.Run("safetensors and gguf in one artifact are refused", func(t *testing.T) {
		m := maps.Clone(split)
		m["model.safetensors"] = "w"
		if _, err := Build(context.Background(), writeTree(t, m)); !errors.Is(err, ErrMixedFormats) {
			t.Errorf("Build = %v, want ErrMixedFormats", err)
		}
	})
	t.Run("a directory with no weights is refused", func(t *testing.T) {
		if _, err := Build(context.Background(), writeTree(t, map[string]string{"README.md": "x"})); !errors.Is(err, ErrNoWeights) {
			t.Errorf("Build = %v, want ErrNoWeights", err)
		}
	})
}

// TestManifestIsDeterministic pins that the same files give the same digest:
// written in another order, at other times, in another directory.
func TestManifestIsDeterministic(t *testing.T) {
	files := map[string]string{
		"config.json":       `{"quantization":"q4"}`,
		"model.safetensors": "weights",
		"tokenizer.json":    "{}",
		"docs/README.md":    "doc",
	}
	a := build(t, writeTree(t, files))
	b := build(t, writeTree(t, files))
	dir := writeTree(t, files)
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	for p := range files {
		if err := os.Chtimes(filepath.Join(dir, filepath.FromSlash(p)), old, old); err != nil {
			t.Fatal(err)
		}
	}
	c := build(t, dir)
	for _, other := range []*Artifact{b, c} {
		if !bytes.Equal(a.Manifest, other.Manifest) || a.Digest != other.Digest {
			t.Errorf("manifests differ:\n%s\n%s", a.Manifest, other.Manifest)
		}
		if !bytes.Equal(a.Config, other.Config) {
			t.Errorf("configs differ:\n%s\n%s", a.Config, other.Config)
		}
	}
	for _, blob := range [][]byte{a.Manifest, a.Config} {
		for _, key := range []string{"created", "createdAt", ispec.AnnotationCreated} {
			if bytes.Contains(blob, []byte(`"`+key+`"`)) {
				t.Errorf("%s carries a timestamp key %q", blob, key)
			}
		}
	}
}

// countingFS is an fs.FS that records every file opened for reading.
type countingFS struct {
	fs.FS
	mu     sync.Mutex
	opened []string
}

func (c *countingFS) Open(name string) (fs.File, error) {
	f, err := c.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil && !st.IsDir() {
		c.mu.Lock()
		c.opened = append(c.opened, name)
		c.mu.Unlock()
	}
	return f, nil
}

func (c *countingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(c.FS, name)
}

func TestRefusesCaseCollidingPaths(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
	}{
		{"two weight files", []string{"model.safetensors", "Model.safetensors"}},
		{"a config and its case twin", []string{"model.safetensors", "tokenizer.json", "Tokenizer.JSON"}},
		{"a file and a directory of another case", []string{"model.safetensors", "docs", "DOCS/README.md"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := fstest.MapFS{}
			for _, p := range tc.paths {
				m[p] = &fstest.MapFile{Data: []byte("x"), Mode: 0o644}
			}
			cfs := &countingFS{FS: m}
			_, err := BuildFS(context.Background(), cfs)
			if !errors.Is(err, artifactv1.ErrCaseCollision) && !errors.Is(err, artifactv1.ErrFileDirConflict) {
				t.Errorf("BuildFS = %v, want a case collision refused", err)
			}
			if len(cfs.opened) != 0 {
				t.Errorf("read %v before refusing", cfs.opened)
			}
		})
	}
}

// TestRefusesCodeFilesBeforeReading pins BR4: a code or pickle file is
// refused by its name, before any byte of any file is read. The .py here is
// unreadable, so a build that opened it would fail with a permission error
// instead of the refusal.
func TestRefusesCodeFilesBeforeReading(t *testing.T) {
	for _, name := range []string{"modeling_llama.py", "sub/helper.PYC", "pytorch_model.bin", "w.pt", "w.pth", "t.pkl", "t.pickle", "m.ckpt", "lib.so", "lib.dylib"} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"model.safetensors": "w", "config.json": "{}", name: "import os"})
			code := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.Chmod(code, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(code, 0o644) })
			if _, err := Build(context.Background(), dir); !errors.Is(err, artifactv1.ErrCodeFile) {
				t.Errorf("Build = %v, want ErrCodeFile", err)
			}
		})
	}
	t.Run("nothing is opened", func(t *testing.T) {
		cfs := &countingFS{FS: fstest.MapFS{
			"model.safetensors": {Data: []byte("w")},
			"config.json":       {Data: []byte("{}")},
			"modeling_llama.py": {Data: []byte("import os")},
		}}
		if _, err := BuildFS(context.Background(), cfs); !errors.Is(err, artifactv1.ErrCodeFile) {
			t.Errorf("BuildFS = %v, want ErrCodeFile", err)
		}
		if len(cfs.opened) != 0 {
			t.Errorf("read %v before refusing", cfs.opened)
		}
	})
}

// TestRefusesNonRegularFiles pins that a symbolic link is refused rather than
// followed out of the model directory.
func TestRefusesNonRegularFiles(t *testing.T) {
	dir := writeTree(t, map[string]string{"model.safetensors": "w"})
	outside := writeTree(t, map[string]string{"secret.json": "{}"})
	if err := os.Symlink(filepath.Join(outside, "secret.json"), filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), dir); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Build = %v, want ErrNotRegular", err)
	}
}
