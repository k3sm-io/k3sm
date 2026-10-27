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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

// writeSnapshot stages a snapshot directory holding config (or no config.json
// at all when config is empty) and returns its path.
func writeSnapshot(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, modelConfigFile), []byte(config), 0o644); err != nil {
			t.Fatalf("write config.json: %v", err)
		}
	}
	return dir
}

// TestReadKVGeometry pins the reader against the geometry fields of real model
// configs (the values below are the published config.json fields of each
// repository) and against the fp16 per-token footprint those fields imply:
// 2 tensors (K and V) x 2 bytes x layers x kv_heads x head_dim.
func TestReadKVGeometry(t *testing.T) {
	cases := []struct {
		name        string
		config      string
		want        KVGeometry
		bytesPerTok int64
	}{
		{
			// Qwen3 states head_dim explicitly, and it is NOT hidden_size /
			// num_attention_heads (1024 / 16 = 64): the explicit field must win.
			name:        "qwen3_0.6b_explicit_head_dim",
			config:      `{"model_type":"qwen3","num_hidden_layers":28,"num_attention_heads":16,"num_key_value_heads":8,"hidden_size":1024,"head_dim":128}`,
			want:        KVGeometry{Layers: 28, KVHeads: 8, HeadDim: 128},
			bytesPerTok: 114_688,
		},
		{
			name:        "qwen2.5_7b_derived_head_dim",
			config:      `{"model_type":"qwen2","num_hidden_layers":28,"num_attention_heads":28,"num_key_value_heads":4,"hidden_size":3584}`,
			want:        KVGeometry{Layers: 28, KVHeads: 4, HeadDim: 128},
			bytesPerTok: 57_344,
		},
		{
			name:        "qwen2.5_32b_derived_head_dim",
			config:      `{"model_type":"qwen2","num_hidden_layers":64,"num_attention_heads":40,"num_key_value_heads":8,"hidden_size":5120}`,
			want:        KVGeometry{Layers: 64, KVHeads: 8, HeadDim: 128},
			bytesPerTok: 262_144,
		},
		{
			name:        "llama_3.3_70b",
			config:      `{"model_type":"llama","num_hidden_layers":80,"num_attention_heads":64,"num_key_value_heads":8,"hidden_size":8192,"head_dim":128}`,
			want:        KVGeometry{Layers: 80, KVHeads: 8, HeadDim: 128},
			bytesPerTok: 327_680,
		},
		{
			// The S3 calibration model: the formula must land under the measured
			// growth the fallback constant was rounded up from.
			name:        "llama_3.2_3b_the_s3_calibration_model",
			config:      `{"model_type":"llama","num_hidden_layers":28,"num_attention_heads":24,"num_key_value_heads":8,"hidden_size":3072,"head_dim":128}`,
			want:        KVGeometry{Layers: 28, KVHeads: 8, HeadDim: 128},
			bytesPerTok: 114_688,
		},
		{
			// Pre-GQA configs carry no num_key_value_heads: every attention head
			// has its own K and V.
			name:        "no_kv_heads_falls_back_to_attention_heads",
			config:      `{"num_hidden_layers":32,"num_attention_heads":32,"hidden_size":4096}`,
			want:        KVGeometry{Layers: 32, KVHeads: 32, HeadDim: 128},
			bytesPerTok: 524_288,
		},
		{
			name:        "null_head_dim_falls_back_to_hidden_over_heads",
			config:      `{"num_hidden_layers":28,"num_attention_heads":28,"num_key_value_heads":4,"hidden_size":3584,"head_dim":null}`,
			want:        KVGeometry{Layers: 28, KVHeads: 4, HeadDim: 128},
			bytesPerTok: 57_344,
		},
		{
			// Multimodal configs nest the language model under text_config; the
			// top level describes the wrapper (and here, deliberately, a vision
			// tower that must not be read as the LM).
			name: "multimodal_text_config_wins",
			config: `{"model_type":"gemma3","num_hidden_layers":27,"num_attention_heads":16,"hidden_size":1152,
				"text_config":{"num_hidden_layers":34,"num_attention_heads":8,"num_key_value_heads":4,"hidden_size":2560,"head_dim":256}}`,
			want:        KVGeometry{Layers: 34, KVHeads: 4, HeadDim: 256},
			bytesPerTok: 139_264,
		},
		{
			// A text_config that states only some fields inherits the rest from
			// the top level, the way the config classes resolve them.
			name:        "text_config_inherits_missing_fields",
			config:      `{"num_attention_heads":32,"hidden_size":4096,"text_config":{"num_hidden_layers":32,"num_key_value_heads":8}}`,
			want:        KVGeometry{Layers: 32, KVHeads: 8, HeadDim: 128},
			bytesPerTok: 131_072,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadKVGeometry(writeSnapshot(t, tc.config))
			if err != nil {
				t.Fatalf("ReadKVGeometry() error = %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("ReadKVGeometry() = %+v, want %+v", got, tc.want)
			}
			if b := got.BytesPerToken(); b != tc.bytesPerTok {
				t.Errorf("BytesPerToken() = %d, want %d (4 x layers x kv_heads x head_dim)", b, tc.bytesPerTok)
			}
		})
	}
}

// TestReadKVGeometryUnusable pins the sentinel: a snapshot whose config cannot
// yield a geometry is ErrNoKVGeometry, never a zero or guessed geometry, so the
// caller falls back to the measured constant knowingly.
func TestReadKVGeometryUnusable(t *testing.T) {
	cases := map[string]string{
		"missing_config_json":         "",
		"not_json":                    `{"num_hidden_layers": 28,`,
		"not_an_object":               `[28, 8, 128]`,
		"no_layers":                   `{"num_attention_heads":16,"num_key_value_heads":8,"head_dim":128}`,
		"zero_layers":                 `{"num_hidden_layers":0,"num_attention_heads":16,"num_key_value_heads":8,"head_dim":128}`,
		"negative_kv_heads":           `{"num_hidden_layers":28,"num_attention_heads":16,"num_key_value_heads":-8,"head_dim":128}`,
		"no_heads_at_all":             `{"num_hidden_layers":28,"hidden_size":1024}`,
		"no_head_dim_and_no_hidden":   `{"num_hidden_layers":28,"num_attention_heads":16,"num_key_value_heads":8}`,
		"hidden_not_divisible":        `{"num_hidden_layers":28,"num_attention_heads":7,"num_key_value_heads":1,"hidden_size":1000}`,
		"fractional_layers":           `{"num_hidden_layers":28.5,"num_attention_heads":16,"num_key_value_heads":8,"head_dim":128}`,
		"string_layers":               `{"num_hidden_layers":"28","num_attention_heads":16,"num_key_value_heads":8,"head_dim":128}`,
		"absurd_layers":               `{"num_hidden_layers":1000000000,"num_attention_heads":16,"num_key_value_heads":8,"head_dim":128}`,
		"text_config_not_an_object":   `{"num_hidden_layers":28,"num_attention_heads":16,"num_key_value_heads":8,"head_dim":128,"text_config":"x"}`,
		"oversized_config_is_refused": `{"pad":"` + strings.Repeat("x", maxModelConfigBytes) + `"}`,
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ReadKVGeometry(writeSnapshot(t, config))
			if !errors.Is(err, ErrNoKVGeometry) {
				t.Fatalf("ReadKVGeometry() = %+v, %v; want ErrNoKVGeometry", got, err)
			}
			if got.Known() {
				t.Errorf("ReadKVGeometry() returned a known geometry %+v alongside an error", got)
			}
		})
	}
}

// TestDeriveSizingWithGeometry pins the seam: a known geometry replaces the
// fallback constant, an unknown one keeps it, and the budget the pins bound is
// still inside spec.memory.
func TestDeriveSizingWithGeometry(t *testing.T) {
	mem := resource.MustParse("64Gi")

	fallback, err := DeriveSizing(mem, KVGeometry{})
	if err != nil {
		t.Fatalf("DeriveSizing(64Gi, unknown) error = %v", err)
	}
	if fallback.KVBytesPerToken != kvBytesPerToken {
		t.Errorf("unknown geometry used %d bytes/token, want the fallback constant %d", fallback.KVBytesPerToken, kvBytesPerToken)
	}

	qwen32b := KVGeometry{Layers: 64, KVHeads: 8, HeadDim: 128}
	big, err := DeriveSizing(mem, qwen32b)
	if err != nil {
		t.Fatalf("DeriveSizing(64Gi, 32B) error = %v", err)
	}
	if big.KVBytesPerToken != 262_144 {
		t.Errorf("32B geometry used %d bytes/token, want 262144", big.KVBytesPerToken)
	}
	if big.MaxContextTokens >= fallback.MaxContextTokens {
		t.Errorf("32B context at 64Gi = %d, want it SMALLER than the constant's %d: the constant under-counts a 64-layer model's KV cache",
			big.MaxContextTokens, fallback.MaxContextTokens)
	}

	for _, g := range []KVGeometry{{}, qwen32b, {Layers: 28, KVHeads: 4, HeadDim: 128}, {Layers: 80, KVHeads: 8, HeadDim: 128}} {
		s, err := DeriveSizing(mem, g)
		if err != nil {
			t.Fatalf("DeriveSizing(64Gi, %+v) error = %v", g, err)
		}
		total := mem.Value()
		usable := total - compileScratchBytes - total*headroomPercent/100
		if budget := usable * kvSharePercent / 100; s.KVCacheBytes > budget {
			t.Errorf("geometry %+v: KV pin costs %d bytes, above the %d-byte share", g, s.KVCacheBytes, budget)
		}
		if s.KVCacheBytes != s.MaxContextTokens*s.MaxSequences*s.KVBytesPerToken {
			t.Errorf("geometry %+v: KVCacheBytes = %d, want context x sequences x bytes/token", g, s.KVCacheBytes)
		}
	}

	// The 70B geometry needs more memory per token than a small pod can fund:
	// the floor is reported, not silently pinned below it.
	if _, err := DeriveSizing(resource.MustParse("2Gi"), KVGeometry{Layers: 80, KVHeads: 8, HeadDim: 128}); !errors.Is(err, ErrMemoryTooSmall) {
		t.Errorf("DeriveSizing(2Gi, 70B) error = %v, want ErrMemoryTooSmall", err)
	}
}
