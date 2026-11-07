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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// MaxModelConfigJSONBytes bounds the model's config.json read at push. A
// model's config.json is a few KiB; a larger one gives no metadata.
const MaxModelConfigJSONBytes = 1 << 20

// MaxConfigBytes bounds a ModelPack config blob a listing reads. k3sm's
// config is the format, two short values and one digest per file, so even
// the most files a manifest may name stay well under it.
const MaxConfigBytes = 1 << 20

// maxMetadataValue bounds a quantization or parameter size value.
const maxMetadataValue = 64

// ErrBadModelConfig is a ModelPack config or manifest a listing cannot read
// metadata from: not a JSON object, or a layer size that is negative or sums
// past what an int64 holds.
var ErrBadModelConfig = errors.New("not a readable ModelPack config")

// Metadata is what a model's manifest and ModelPack config say about it. A
// value the config does not record, or records outside the closed set, is
// empty.
type Metadata struct {
	// Format is safetensors or gguf.
	Format string
	// SizeBytes is the sum of the files' sizes.
	SizeBytes int64
	// Files is the number of files (layers).
	Files int
	// Shards is the number of weight files: 1 for a single file, N for a
	// split set.
	Shards int
	// Quantization and ParamSize are copied from the model's config.json at
	// push.
	Quantization string
	ParamSize    string
}

// readModelConfig reads the quantization and parameter size from a model's
// config.json: a string "quantization", else the Hugging Face
// quantization_config.quant_method, else MLX's integer quantization.bits as
// "<bits>bit"; and a string "paramSize". Every other field is ignored.
//
// It fails closed on content, and content never makes it fail: a file over
// MaxModelConfigJSONBytes or anything but one JSON object gives no metadata,
// and a value outside the closed set is dropped, so a model with an odd
// config.json still pushes, without that metadata. Only a read failure is an
// error.
func readModelConfig(r io.Reader) (ConfigFields, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxModelConfigJSONBytes+1))
	if err != nil {
		return ConfigFields{}, fmt.Errorf("read config.json: %w", err)
	}
	if len(b) > MaxModelConfigJSONBytes {
		return ConfigFields{}, nil
	}
	var raw struct {
		Quantization       json.RawMessage `json:"quantization"`
		QuantizationConfig json.RawMessage `json:"quantization_config"`
		ParamSize          json.RawMessage `json:"paramSize"`
	}
	if decodeObject(b, &raw) != nil {
		return ConfigFields{}, nil
	}
	f := ConfigFields{ParamSize: metadataString(raw.ParamSize)}
	f.Quantization = metadataString(raw.Quantization)
	if f.Quantization == "" {
		var qc struct {
			QuantMethod json.RawMessage `json:"quant_method"`
		}
		if decodeObject(raw.QuantizationConfig, &qc) == nil {
			f.Quantization = metadataString(qc.QuantMethod)
		}
	}
	if f.Quantization == "" {
		var mlx struct {
			Bits json.RawMessage `json:"bits"`
		}
		if decodeObject(raw.Quantization, &mlx) == nil {
			if n, err := strconv.ParseUint(string(mlx.Bits), 10, 8); err == nil && n >= 1 && n <= 16 {
				f.Quantization = strconv.FormatUint(n, 10) + "bit"
			}
		}
	}
	return f, nil
}

// Describe reads a model's metadata from its manifest layers and its
// ModelPack config blob, both untrusted registry content. Unknown config
// fields are ignored and a value outside the closed set is dropped; a config
// that is not one JSON object, or a negative or overflowing layer size, is
// ErrBadModelConfig. The caller bounds the config at MaxConfigBytes and
// checks its digest.
func Describe(layers []ispec.Descriptor, config []byte) (Metadata, error) {
	md := Metadata{Files: len(layers)}
	for _, l := range layers {
		if l.Size < 0 || md.SizeBytes > math.MaxInt64-l.Size {
			return Metadata{}, fmt.Errorf("layer %s has size %d: %w", l.Digest, l.Size, ErrBadModelConfig)
		}
		md.SizeBytes += l.Size
		if l.MediaType == artifactv1.MediaTypeModelWeight {
			md.Shards++
		}
	}
	var c struct {
		Config struct {
			Format       json.RawMessage `json:"format"`
			ParamSize    json.RawMessage `json:"paramSize"`
			Quantization json.RawMessage `json:"quantization"`
		} `json:"config"`
	}
	if err := decodeObject(config, &c); err != nil {
		return Metadata{}, fmt.Errorf("%w: %v", ErrBadModelConfig, err)
	}
	switch f := metadataString(c.Config.Format); f {
	case FormatSafetensors, FormatGGUF:
		md.Format = f
	}
	md.Quantization = metadataString(c.Config.Quantization)
	md.ParamSize = metadataString(c.Config.ParamSize)
	return md, nil
}

// decodeObject decodes b, which must be exactly one JSON object (or null),
// into v.
func decodeObject(b []byte, v any) error {
	if len(b) == 0 {
		return errors.New("empty")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON object")
	}
	return nil
}

// metadataString is raw decoded as a JSON string when it is a valid metadata
// value, else "".
func metadataString(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil || !validMetadataValue(s) {
		return ""
	}
	return s
}

// validMetadataValue reports whether s is a non-empty value of at most
// maxMetadataValue bytes from [A-Za-z0-9._+-]: safe to print in a table
// column and to hand to the app unescaped.
func validMetadataValue(s string) bool {
	if s == "" || len(s) > maxMetadataValue {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}
