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
	"math/rand/v2"
	"testing"
)

// TestChunkersDetectShiftedContent proves the chunkers measure something: a
// 1 KiB-aligned prefix of a buffer defeats fixed-size chunks, content-defined
// chunks resync after it, and the pieces always reassemble the input.
func TestChunkersDetectShiftedContent(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 7))
	data := make([]byte, 4<<20)
	for i := range data {
		data[i] = byte(r.Uint32())
	}
	shifted := append(bytes.Repeat([]byte{0xAB}, 100), data...)

	for name, cut := range map[string]func([]byte) [][]byte{
		"fixed": func(b []byte) [][]byte { return fixed(b, 64<<10) },
		"cdc":   func(b []byte) [][]byte { return cdc(b, 64<<10) },
	} {
		if got := bytes.Join(cut(data), nil); !bytes.Equal(got, data) {
			t.Fatalf("%s: pieces do not reassemble the input", name)
		}
	}
	added := func(cut func([]byte) [][]byte) float64 {
		s := newStore()
		for _, p := range cut(data) {
			s.add(p)
		}
		n := 0
		for _, p := range cut(shifted) {
			n += s.add(p)
		}
		return float64(n) / float64(len(shifted))
	}
	if f := added(func(b []byte) [][]byte { return fixed(b, 64<<10) }); f < 0.99 {
		t.Errorf("fixed chunks after a 100-byte prefix: added %.3f, want ~1 (no resync)", f)
	}
	if f := added(func(b []byte) [][]byte { return cdc(b, 64<<10) }); f > 0.10 {
		t.Errorf("cdc chunks after a 100-byte prefix: added %.3f, want < 0.10 (resync)", f)
	}
	n := len(cdc(data, 64<<10))
	if avg := len(data) / n; avg < 32<<10 || avg > 128<<10 {
		t.Errorf("cdc average chunk %d bytes, want near 64 KiB", avg)
	}
}

// TestTensorMethodSeesUnchangedTensors proves the tensor method is not
// vacuous: a LoRA fine-tune changes only q and v, so the tensor store adds
// about their share of the file, while a quantization adds nearly everything.
func TestTensorMethodSeesUnchangedTensors(t *testing.T) {
	r := measure(smallShape)
	find := func(container, a, b string) pairRow {
		for _, p := range r.Pairs {
			if p.Container == container && p.First == a && p.Second == b {
				return p
			}
		}
		t.Fatalf("no pair %s %s->%s", container, a, b)
		return pairRow{}
	}
	s := smallShape
	qv := float64(2 * s.Layers * s.Hidden * s.Hidden)
	all := float64(s.Vocab*s.Hidden + s.Layers*(4*s.Hidden*s.Hidden+3*s.MLP*s.Hidden))
	for _, c := range []string{"safetensors-like", "gguf-like"} {
		lora := find(c, "base.bf16", "ft-lora.bf16")
		if got, want := lora.Added["tensor"], qv/all; got < want*0.9 || got > want*1.2 {
			t.Errorf("%s lora tensor added %.3f, want about %.3f (the q and v share)", c, got, want)
		}
		if lora.Added["file"] != 1 {
			t.Errorf("%s lora file added %.3f, want 1", c, lora.Added["file"])
		}
		if q := find(c, "base.bf16", "base.q4_0"); q.Added["tensor"] < 0.95 {
			t.Errorf("%s q4 tensor added %.3f, want ~1 across dtypes", c, q.Added["tensor"])
		}
	}
	for _, f := range r.Framing {
		if f.Added["tensor"] > 0.05 {
			t.Errorf("framing %s: tensor added %.3f, want ~0 (same tensors)", f.Second, f.Added["tensor"])
		}
	}
}
