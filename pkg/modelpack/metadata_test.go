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
	"errors"
	"math"
	"strings"
	"testing"
	"testing/iotest"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// TestModelConfigJSONMetadata pins what is copied from a model's config.json:
// the quantization (a string, the Hugging Face quant_method, or MLX's bits)
// and the parameter size, each only when it is a short value of the closed
// character set. Every other field is ignored.
func TestModelConfigJSONMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, in      string
		quant, params string
	}{
		{"a string quantization and paramSize", `{"quantization":"q4_k_m","paramSize":"8B"}`, "q4_k_m", "8B"},
		{"the Hugging Face quant_method", `{"quantization_config":{"quant_method":"awq","bits":4}}`, "awq", ""},
		{"MLX bits", `{"quantization":{"group_size":64,"bits":4}}`, "4bit", ""},
		{"a string quantization wins over quant_method", `{"quantization":"fp8","quantization_config":{"quant_method":"awq"}}`, "fp8", ""},
		{"unknown fields are ignored", `{"model_type":"llama","rope_scaling":{"x":[1,2]},"paramSize":"70b"}`, "", "70b"},
		{"a non-string paramSize is dropped", `{"paramSize":8000000000}`, "", ""},
		{"MLX bits out of range are dropped", `{"quantization":{"bits":0}}`, "", ""},
		{"fractional MLX bits are dropped", `{"quantization":{"bits":4.5}}`, "", ""},
		{"a control character is dropped", `{"quantization":"q4\u001b[31m"}`, "", ""},
		{"a tab is dropped", `{"paramSize":"8\tB"}`, "", ""},
		{"an over-long value is dropped", `{"paramSize":"` + strings.Repeat("a", maxMetadataValue+1) + `"}`, "", ""},
		{"an empty object", `{}`, "", ""},
		{"null", `null`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := readModelConfig(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("readModelConfig: %v", err)
			}
			if f.Quantization != tc.quant || f.ParamSize != tc.params {
				t.Errorf("quantization/paramSize = %q/%q, want %q/%q", f.Quantization, f.ParamSize, tc.quant, tc.params)
			}
		})
	}
}

// TestMalformedConfigJSONGivesNoMetadata pins the fail-closed reading: a
// config.json that is not JSON, not an object, or larger than the bound
// yields no metadata and no error, so the model still pushes. Only a read
// failure is an error.
func TestMalformedConfigJSONGivesNoMetadata(t *testing.T) {
	big := `{"quantization":"q4","pad":"` + strings.Repeat("x", MaxModelConfigJSONBytes) + `"}`
	for name, in := range map[string]string{
		"not JSON":       `{"quantization":"q4"`,
		"an array":       `["q4"]`,
		"a string":       `"q4"`,
		"trailing bytes": `{"quantization":"q4"} {"quantization":"q8"}`,
		"over the bound": big,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := readModelConfig(strings.NewReader(in))
			if err != nil {
				t.Fatalf("readModelConfig: %v, want no error", err)
			}
			if f != (ConfigFields{}) {
				t.Errorf("fields = %+v, want none", f)
			}
		})
	}
	t.Run("a read failure is an error", func(t *testing.T) {
		boom := errors.New("boom")
		if _, err := readModelConfig(iotest.ErrReader(boom)); !errors.Is(err, boom) {
			t.Errorf("readModelConfig = %v, want the read error", err)
		}
	})
	t.Run("the push still builds", func(t *testing.T) {
		a := build(t, writeTree(t, map[string]string{"model.safetensors": "w", "config.json": "{not json"}))
		c := decodeConfig(t, a)
		if c.Config.Format != FormatSafetensors || c.Config.Quantization != "" || c.Config.ParamSize != "" {
			t.Errorf("config = %+v, want the format alone", c.Config)
		}
		if len(a.Layers) != 2 {
			t.Errorf("%d layers, want config.json pushed as a file", len(a.Layers))
		}
	})
}

// TestDescribeReadsManifestAndConfig pins the metadata a listing shows, from
// the manifest and the ModelPack config alone: format, total size, file
// count, weight shard count, quantization and parameter size. The config is
// untrusted registry content, read as fail-closed as config.json is.
func TestDescribeReadsManifestAndConfig(t *testing.T) {
	a := build(t, writeTree(t, map[string]string{
		"config.json":                      `{"quantization":{"bits":4}}`,
		"model.safetensors.index.json":     `{}`,
		"model-00001-of-00002.safetensors": "first",
		"model-00002-of-00002.safetensors": "second",
		"README.md":                        "doc",
	}))
	m := decodeManifest(t, a)
	md, err := Describe(m.Layers, a.Config)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	for _, l := range a.Layers {
		size += l.Descriptor.Size
	}
	want := Metadata{Format: FormatSafetensors, SizeBytes: size, Files: 5, Shards: 2, Quantization: "4bit"}
	if md != want {
		t.Errorf("Describe = %+v, want %+v", md, want)
	}

	t.Run("an unknown format or a hostile value is dropped", func(t *testing.T) {
		md, err := Describe(m.Layers, []byte(`{"config":{"format":"pickle","quantization":"q4\n","paramSize":"8B","extra":1},"modelfs":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		if md.Format != "" || md.Quantization != "" || md.ParamSize != "8B" {
			t.Errorf("Describe = %+v, want no format, no quantization, paramSize 8B", md)
		}
	})
	t.Run("a config that is not JSON is an error", func(t *testing.T) {
		if _, err := Describe(m.Layers, []byte(`{`)); !errors.Is(err, ErrBadModelConfig) {
			t.Errorf("Describe = %v, want ErrBadModelConfig", err)
		}
	})
	t.Run("a negative or overflowing size is an error", func(t *testing.T) {
		neg := []ispec.Descriptor{{MediaType: artifactv1.MediaTypeModelWeight, Size: -1}}
		if _, err := Describe(neg, a.Config); !errors.Is(err, ErrBadModelConfig) {
			t.Errorf("Describe(negative size) = %v, want ErrBadModelConfig", err)
		}
		huge := []ispec.Descriptor{{Size: math.MaxInt64}, {Size: 1}}
		if _, err := Describe(huge, a.Config); !errors.Is(err, ErrBadModelConfig) {
			t.Errorf("Describe(overflow) = %v, want ErrBadModelConfig", err)
		}
	})
}

// FuzzReadModelConfig drives the config.json reader with arbitrary bytes. It
// must never panic, never fail on content (only a read can fail), and only
// ever return values of the closed character set within the length bound.
func FuzzReadModelConfig(f *testing.F) {
	for _, s := range []string{
		`{}`, `null`, `[]`, `"x"`, `{`,
		`{"quantization":"q4_k_m","paramSize":"8B"}`,
		`{"quantization_config":{"quant_method":"gptq","bits":4}}`,
		`{"quantization":{"group_size":64,"bits":4}}`,
		`{"quantization":{"bits":1e400}}`,
		`{"quantization":"\u0000"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := readModelConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("readModelConfig failed on content: %v", err)
		}
		if got.Format != "" {
			t.Fatalf("config.json set the format %q", got.Format)
		}
		for _, v := range []string{got.Quantization, got.ParamSize} {
			if len(v) > maxMetadataValue || !validMetadataValue(v) && v != "" {
				t.Fatalf("value %q escapes the closed set", v)
			}
		}
	})
}
