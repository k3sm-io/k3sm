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
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

// ErrNoKVGeometry is returned by ReadKVGeometry when a snapshot has no
// config.json, or one from which the KV geometry cannot be read: a missing or
// non-positive field, a head dimension that cannot be derived, a value too large
// to be a real model. It is a reason to fall back to the measured constant, not
// to guess a geometry.
var ErrNoKVGeometry = errors.New("model config yields no kv-cache geometry")

const (
	// modelConfigFile is the Hugging Face model config inside a snapshot
	// directory: the file the engine itself reads the architecture from.
	modelConfigFile = "config.json"
	// maxModelConfigBytes bounds the read. A config.json is a few kilobytes; the
	// cap keeps a hostile or corrupt snapshot from making the reader allocate
	// without bound.
	maxModelConfigBytes = 1 << 20
	// maxGeometryField bounds each geometry field. The largest published models
	// sit two to three orders of magnitude below it, and the bound keeps
	// BytesPerToken's product inside int64 (4 x 2^16 x 2^16 x 2^16 = 2^50).
	maxGeometryField = 1 << 16
)

// KVGeometry is the shape of a model's KV cache: what one generated token costs
// in every layer. The zero value means "unknown" (no snapshot was read), and
// DeriveSizing then falls back to the measured constant.
type KVGeometry struct {
	// Layers is num_hidden_layers: one K and one V tensor per layer.
	Layers int64
	// KVHeads is num_key_value_heads (grouped-query attention), or
	// num_attention_heads for a config that predates GQA.
	KVHeads int64
	// HeadDim is head_dim, or hidden_size / num_attention_heads when the
	// config does not state it.
	HeadDim int64
}

// Known reports whether every field is positive, the only state in which
// BytesPerToken means anything.
func (g KVGeometry) Known() bool {
	return g.Layers > 0 && g.KVHeads > 0 && g.HeadDim > 0
}

// BytesPerToken is the KV-cache growth per token, per sequence, at fp16/bf16:
//
//	2 (K and V) x 2 bytes x layers x kv_heads x head_dim
//
// mlx-lm's KVCache holds keys and values as [batch, kv_heads, tokens, head_dim]
// arrays in the model's activation dtype, which for the served models is fp16 or
// bf16 (quantized weights do not quantize the cache). It is an UPPER bound: a
// quantized KV cache, or sliding-window layers that stop growing, use less, so
// sizing from it errs toward a smaller context, never a larger one. S3's
// measured growth for its 3B model agrees with it to within the allocator's
// 256-token step. It returns 0 for an unknown geometry.
func (g KVGeometry) BytesPerToken() int64 {
	if !g.Known() {
		return 0
	}
	return 4 * g.Layers * g.KVHeads * g.HeadDim
}

// modelConfig is the subset of a Hugging Face config.json the geometry needs.
// A pointer field distinguishes "absent or null" from a stated value.
type modelConfig struct {
	NumHiddenLayers   *float64 `json:"num_hidden_layers"`
	NumAttentionHeads *float64 `json:"num_attention_heads"`
	NumKeyValueHeads  *float64 `json:"num_key_value_heads"`
	HeadDim           *float64 `json:"head_dim"`
	HiddenSize        *float64 `json:"hidden_size"`
	// TextConfig is the language model's own config in a multimodal
	// checkpoint; the top level then describes the wrapper.
	TextConfig *modelConfig `json:"text_config"`
}

// inherit fills the fields c leaves unset from parent, the way a multimodal
// config resolves a text_config that states only what differs.
func (c modelConfig) inherit(parent modelConfig) modelConfig {
	for _, f := range []struct{ dst, src **float64 }{
		{&c.NumHiddenLayers, &parent.NumHiddenLayers},
		{&c.NumAttentionHeads, &parent.NumAttentionHeads},
		{&c.NumKeyValueHeads, &parent.NumKeyValueHeads},
		{&c.HeadDim, &parent.HeadDim},
		{&c.HiddenSize, &parent.HiddenSize},
	} {
		if *f.dst == nil {
			*f.dst = *f.src
		}
	}
	return c
}

// ReadKVGeometry reads the KV geometry from the config.json of the model
// snapshot directory snapshotDir (the directory holding the weights, for
// example <HF_HOME>/hub/models--<org>--<name>/snapshots/<revision>).
//
// When the config nests a text_config (a multimodal checkpoint), the language
// model's fields are read from it, with any it leaves out taken from the top
// level. num_key_value_heads falls back to num_attention_heads, and head_dim to
// hidden_size / num_attention_heads, the defaults the model classes apply. Any
// config that still leaves a field unknown, non-integer, non-positive or
// implausibly large is ErrNoKVGeometry.
func ReadKVGeometry(snapshotDir string) (KVGeometry, error) {
	path := filepath.Join(snapshotDir, modelConfigFile)
	f, err := os.Open(path)
	if err != nil {
		return KVGeometry{}, fmt.Errorf("%w: %w", ErrNoKVGeometry, err)
	}
	defer func() { _ = f.Close() }() // read-only; a close error loses nothing

	raw, err := io.ReadAll(io.LimitReader(f, maxModelConfigBytes+1))
	if err != nil {
		return KVGeometry{}, fmt.Errorf("%w: read %s: %w", ErrNoKVGeometry, path, err)
	}
	if len(raw) > maxModelConfigBytes {
		return KVGeometry{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrNoKVGeometry, path, maxModelConfigBytes)
	}
	var cfg modelConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return KVGeometry{}, fmt.Errorf("%w: parse %s: %w", ErrNoKVGeometry, path, err)
	}
	if cfg.TextConfig != nil {
		cfg = cfg.TextConfig.inherit(cfg)
	}
	g, err := cfg.geometry()
	if err != nil {
		return KVGeometry{}, fmt.Errorf("%w: %s: %w", ErrNoKVGeometry, path, err)
	}
	return g, nil
}

// geometry resolves the three fields, applying the two fallbacks.
func (c modelConfig) geometry() (KVGeometry, error) {
	layers, err := field("num_hidden_layers", c.NumHiddenLayers)
	if err != nil {
		return KVGeometry{}, err
	}
	kvHeads, err := field("num_key_value_heads", c.NumKeyValueHeads)
	if errors.Is(err, errFieldAbsent) {
		kvHeads, err = field("num_attention_heads", c.NumAttentionHeads)
	}
	if err != nil {
		return KVGeometry{}, err
	}
	headDim, err := field("head_dim", c.HeadDim)
	if errors.Is(err, errFieldAbsent) {
		headDim, err = derivedHeadDim(c)
	}
	if err != nil {
		return KVGeometry{}, err
	}
	return KVGeometry{Layers: layers, KVHeads: kvHeads, HeadDim: headDim}, nil
}

// derivedHeadDim is hidden_size / num_attention_heads, refused when it does not
// divide: a fractional head dimension means the config is not what this
// formula assumes.
func derivedHeadDim(c modelConfig) (int64, error) {
	hidden, err := field("hidden_size", c.HiddenSize)
	if err != nil {
		return 0, err
	}
	heads, err := field("num_attention_heads", c.NumAttentionHeads)
	if err != nil {
		return 0, err
	}
	if hidden%heads != 0 {
		return 0, fmt.Errorf("hidden_size %d is not a multiple of num_attention_heads %d", hidden, heads)
	}
	return hidden / heads, nil
}

// errFieldAbsent marks a field the config does not state (or states as null),
// the one case a fallback applies to. A stated but bad value is not absent.
var errFieldAbsent = errors.New("field is absent")

// field validates one geometry field: present, a whole number, and within
// (0, maxGeometryField].
func field(name string, v *float64) (int64, error) {
	if v == nil {
		return 0, fmt.Errorf("%s: %w", name, errFieldAbsent)
	}
	if *v != math.Trunc(*v) || *v <= 0 || *v > maxGeometryField {
		return 0, fmt.Errorf("%s = %v, want a whole number in [1, %d]", name, *v, maxGeometryField)
	}
	return int64(*v), nil
}
