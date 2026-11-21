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

// Command dedupe measures how much of a model family deduplicates below the
// file level. It generates one synthetic transformer family from a fixed seed
// (a bf16 base, its q8_0 and q4_0 quantizations, full fine-tunes at three
// delta sizes, a LoRA-merged fine-tune and its q4_0), serializes every variant
// in a safetensors-like and a GGUF-like container, and reports the bytes a
// store would keep under five methods: whole files, fixed-size chunks,
// content-defined chunks, whole tensors, and tensors stored as a compressed
// XOR delta against the nearest earlier tensor of the same name and size.
//
// It reads nothing and touches no network. The data is synthetic, so the
// numbers bound a real family rather than predict it; the report's Limits
// section says which numbers carry over. Usage: dedupe -out DIR [-small].
package main

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// shape is the transformer the family is generated from.
type shape struct {
	Vocab, Hidden, MLP, Layers, LoRARank int
}

var (
	defaultShape = shape{Vocab: 8192, Hidden: 384, MLP: 1024, Layers: 6, LoRARank: 8}
	smallShape   = shape{Vocab: 512, Hidden: 64, MLP: 128, Layers: 2, LoRARank: 4}
)

// weightStd is the standard deviation of a generated weight, a typical
// initialisation scale for a model of this width.
const weightStd = 0.02

// tensor is one named tensor's float values before encoding.
type tensor struct {
	Name  string
	Shape []int
	Norm  bool // a norm weight: kept f32 in every variant, as llama.cpp does
	Vals  []float32
}

// encoded is a tensor after encoding to a variant's dtype.
type encoded struct {
	Name  string
	DType string
	Shape []int
	Data  []byte
}

// variant is one member of the family.
type variant struct {
	Name    string
	DType   string // bf16, q8_0 or q4_0 for the matrices
	Tensors []encoded
}

// file is one serialized variant, with the byte range of every tensor.
type file struct {
	Variant string
	DType   string
	Bytes   []byte
	Extents map[string][2]int
}

func base(s shape, seed uint64) []tensor {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	gauss := func(n int) []float32 {
		v := make([]float32, n)
		for i := range v {
			v[i] = float32(r.NormFloat64() * weightStd)
		}
		return v
	}
	norm := func(n int) []float32 {
		v := make([]float32, n)
		for i := range v {
			v[i] = float32(1 + r.NormFloat64()*0.05)
		}
		return v
	}
	ts := []tensor{{Name: "embed", Shape: []int{s.Vocab, s.Hidden}, Vals: gauss(s.Vocab * s.Hidden)}}
	for l := 0; l < s.Layers; l++ {
		p := fmt.Sprintf("layers.%d.", l)
		ts = append(ts,
			tensor{Name: p + "attn_norm", Shape: []int{s.Hidden}, Norm: true, Vals: norm(s.Hidden)},
			tensor{Name: p + "q", Shape: []int{s.Hidden, s.Hidden}, Vals: gauss(s.Hidden * s.Hidden)},
			tensor{Name: p + "k", Shape: []int{s.Hidden, s.Hidden}, Vals: gauss(s.Hidden * s.Hidden)},
			tensor{Name: p + "v", Shape: []int{s.Hidden, s.Hidden}, Vals: gauss(s.Hidden * s.Hidden)},
			tensor{Name: p + "o", Shape: []int{s.Hidden, s.Hidden}, Vals: gauss(s.Hidden * s.Hidden)},
			tensor{Name: p + "mlp_norm", Shape: []int{s.Hidden}, Norm: true, Vals: norm(s.Hidden)},
			tensor{Name: p + "gate", Shape: []int{s.MLP, s.Hidden}, Vals: gauss(s.MLP * s.Hidden)},
			tensor{Name: p + "up", Shape: []int{s.MLP, s.Hidden}, Vals: gauss(s.MLP * s.Hidden)},
			tensor{Name: p + "down", Shape: []int{s.Hidden, s.MLP}, Vals: gauss(s.Hidden * s.MLP)},
		)
	}
	return append(ts, tensor{Name: "final_norm", Shape: []int{s.Hidden}, Norm: true, Vals: norm(s.Hidden)})
}

// fullFineTune perturbs every value by Gaussian noise of rel*weightStd.
func fullFineTune(ts []tensor, rel float64, seed uint64) []tensor {
	r := rand.New(rand.NewPCG(seed, 1))
	out := make([]tensor, len(ts))
	for i, t := range ts {
		v := make([]float32, len(t.Vals))
		for j, x := range t.Vals {
			v[j] = x + float32(r.NormFloat64()*rel*weightStd)
		}
		out[i] = tensor{Name: t.Name, Shape: t.Shape, Norm: t.Norm, Vals: v}
	}
	return out
}

// loraFineTune merges a rank-r update into the q and v projections only and
// leaves every other tensor's values untouched, the common LoRA target set.
func loraFineTune(ts []tensor, rank int, seed uint64) []tensor {
	r := rand.New(rand.NewPCG(seed, 2))
	out := make([]tensor, len(ts))
	for i, t := range ts {
		out[i] = t
		if !strings.HasSuffix(t.Name, ".q") && !strings.HasSuffix(t.Name, ".v") {
			continue
		}
		rows, cols := t.Shape[0], t.Shape[1]
		a := make([]float64, rank*cols)
		b := make([]float64, rows*rank)
		for j := range a {
			a[j] = r.NormFloat64() * 0.01
		}
		for j := range b {
			b[j] = r.NormFloat64() * 0.01
		}
		v := make([]float32, len(t.Vals))
		for y := 0; y < rows; y++ {
			for x := 0; x < cols; x++ {
				var d float64
				for k := 0; k < rank; k++ {
					d += b[y*rank+k] * a[k*cols+x]
				}
				v[y*cols+x] = t.Vals[y*cols+x] + float32(d)
			}
		}
		out[i] = tensor{Name: t.Name, Shape: t.Shape, Vals: v}
	}
	return out
}

func bf16(x float32) uint16 {
	b := math.Float32bits(x)
	return uint16((b + 0x7fff + (b>>16)&1) >> 16) // round to nearest even
}

func encodeBF16(v []float32) []byte {
	out := make([]byte, 2*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint16(out[2*i:], bf16(x))
	}
	return out
}

func encodeF32(v []float32) []byte {
	out := make([]byte, 4*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint32(out[4*i:], math.Float32bits(x))
	}
	return out
}

// encodeQ8 is llama.cpp's q8_0 layout: blocks of 32, a 16-bit scale then 32
// signed bytes. The scale is bf16 here, not f16; both differ from the base's
// bytes the same way, which is what the measurement needs.
func encodeQ8(v []float32) []byte {
	var out []byte
	for i := 0; i < len(v); i += 32 {
		blk := v[i:min(i+32, len(v))]
		var amax float32
		for _, x := range blk {
			amax = max(amax, float32(math.Abs(float64(x))))
		}
		d := amax / 127
		out = binary.LittleEndian.AppendUint16(out, bf16(d))
		for j := 0; j < 32; j++ {
			var q int8
			if j < len(blk) && d != 0 {
				q = int8(math.Round(float64(blk[j] / d)))
			}
			out = append(out, byte(q))
		}
	}
	return out
}

// encodeQ4 is llama.cpp's q4_0 layout: blocks of 32, a 16-bit scale then 16
// bytes of packed 4-bit values offset by 8.
func encodeQ4(v []float32) []byte {
	var out []byte
	for i := 0; i < len(v); i += 32 {
		blk := make([]float32, 32)
		copy(blk, v[i:min(i+32, len(v))])
		var amax, mx float32
		for _, x := range blk {
			if a := float32(math.Abs(float64(x))); a > amax {
				amax, mx = a, x
			}
		}
		d := mx / -8
		out = binary.LittleEndian.AppendUint16(out, bf16(d))
		q := func(x float32) byte {
			if d == 0 {
				return 8
			}
			return byte(min(15, max(0, int(math.Round(float64(x/d))+8))))
		}
		for j := 0; j < 16; j++ {
			out = append(out, q(blk[j])|q(blk[j+16])<<4)
		}
	}
	return out
}

func encode(name, dtype string, ts []tensor) variant {
	v := variant{Name: name, DType: dtype}
	for _, t := range ts {
		e := encoded{Name: t.Name, Shape: t.Shape, DType: dtype}
		switch {
		case t.Norm:
			e.DType, e.Data = "f32", encodeF32(t.Vals)
		case dtype == "q8_0":
			e.Data = encodeQ8(t.Vals)
		case dtype == "q4_0":
			e.Data = encodeQ4(t.Vals)
		default:
			e.Data = encodeBF16(t.Vals)
		}
		v.Tensors = append(v.Tensors, e)
	}
	return v
}

// safetensorsLike writes an 8-byte header length, a JSON header naming every
// tensor's offsets and the variant's metadata, then the tensors back to back
// in name order, as safetensors (the MLX format) does.
func safetensorsLike(v variant) file {
	ts := append([]encoded(nil), v.Tensors...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Name < ts[j].Name })
	hdr := map[string]any{"__metadata__": map[string]string{"name": v.Name, "format": "mlx", "quantization": v.DType}}
	off := 0
	ext := map[string][2]int{}
	for _, t := range ts {
		hdr[t.Name] = map[string]any{"dtype": t.DType, "shape": t.Shape, "data_offsets": []int{off, off + len(t.Data)}}
		ext[t.Name] = [2]int{off, off + len(t.Data)}
		off += len(t.Data)
	}
	h, _ := json.Marshal(hdr) // a map of strings and ints cannot fail to marshal
	for len(h)%8 != 0 {
		h = append(h, ' ') // the format pads its header to 8 bytes with spaces
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(h)))
	b.Write(h)
	base := b.Len()
	for _, t := range ts {
		b.Write(t.Data)
	}
	for k, e := range ext {
		ext[k] = [2]int{e[0] + base, e[1] + base}
	}
	return file{Variant: v.Name, DType: v.DType, Bytes: b.Bytes(), Extents: ext}
}

// ggufLike writes a magic, key-value metadata, the tensor table, then the
// tensors in model order, each aligned to 32 bytes, as GGUF does.
func ggufLike(v variant) file {
	var b bytes.Buffer
	str := func(s string) {
		_ = binary.Write(&b, binary.LittleEndian, uint64(len(s)))
		b.WriteString(s)
	}
	b.WriteString("GGUF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(v.Tensors)))
	kv := [][2]string{{"general.name", v.Name}, {"general.file_type", v.DType}, {"general.architecture", "llama"}}
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(kv)))
	for _, p := range kv {
		str(p[0])
		str(p[1])
	}
	off := 0
	rel := map[string]int{}
	for _, t := range v.Tensors {
		str(t.Name)
		str(t.DType)
		_ = binary.Write(&b, binary.LittleEndian, uint64(off))
		rel[t.Name] = off
		off += (len(t.Data) + 31) &^ 31
	}
	for b.Len()%32 != 0 {
		b.WriteByte(0)
	}
	base := b.Len()
	ext := map[string][2]int{}
	for _, t := range v.Tensors {
		for b.Len()-base < rel[t.Name] {
			b.WriteByte(0)
		}
		ext[t.Name] = [2]int{b.Len(), b.Len() + len(t.Data)}
		b.Write(t.Data)
	}
	return file{Variant: v.Name, DType: v.DType, Bytes: b.Bytes(), Extents: ext}
}

// gear is the 256-entry table of the gear rolling hash, from a fixed seed.
var gear = func() (g [256]uint64) {
	r := rand.New(rand.NewPCG(0x6765617268617368, 0))
	for i := range g {
		g[i] = r.Uint64()
	}
	return g
}()

// cdc cuts data into content-defined chunks, FastCDC style: a gear hash, a
// minimum of avg/4, a maximum of avg*4, and normalized chunking (a stricter
// mask before the average size, a looser one after). avg is a power of two.
func cdc(data []byte, avg int) [][]byte {
	bits := uint(math.Log2(float64(avg)))
	strict := uint64(1)<<(bits+1) - 1
	loose := uint64(1)<<(bits-1) - 1
	minSize, maxSize := avg/4, avg*4
	var out [][]byte
	for len(data) > 0 {
		n := len(data)
		if n > minSize {
			n = min(n, maxSize)
			var h uint64
			cut := n
			for i := minSize; i < n; i++ {
				h = h<<1 + gear[data[i]]
				m := strict
				if i >= avg {
					m = loose
				}
				if h&(m<<(64-bits-1)) == 0 {
					cut = i + 1
					break
				}
			}
			n = cut
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

func fixed(data []byte, size int) [][]byte {
	var out [][]byte
	for len(data) > 0 {
		n := min(size, len(data))
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

// store counts the bytes a content-addressed store keeps as pieces arrive.
type store struct {
	seen   map[[32]byte]bool
	kept   int
	pieces int
}

func newStore() *store { return &store{seen: map[[32]byte]bool{}} }

// add stores p and returns the bytes it cost: len(p) when new, else 0.
func (s *store) add(p []byte) int {
	k := sha256.Sum256(p)
	if s.seen[k] {
		return 0
	}
	s.seen[k] = true
	s.kept += len(p)
	s.pieces++
	return len(p)
}

func deflated(p []byte) int {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.BestSpeed) // the level is valid
	_, _ = w.Write(p)
	_ = w.Close()
	return min(b.Len(), len(p))
}

// method is one way of cutting files into stored pieces.
type method struct {
	Name string
	// cost stores f in the method's state and returns the bytes it added.
	cost func(f file) int
	// pieces reports how many distinct pieces the store holds (the index size).
	pieces func() int
}

func methods() []method {
	var ms []method
	whole := newStore()
	ms = append(ms, method{"file", func(f file) int { return whole.add(f.Bytes) }, func() int { return whole.pieces }})
	for _, sz := range []int{16 << 10, 64 << 10, 256 << 10} {
		s, sz := newStore(), sz
		ms = append(ms, method{fmt.Sprintf("fixed-%dK", sz>>10), func(f file) int {
			n := 0
			for _, p := range fixed(f.Bytes, sz) {
				n += s.add(p)
			}
			return n
		}, func() int { return s.pieces }})
	}
	for _, sz := range []int{16 << 10, 64 << 10, 256 << 10} {
		s, sz := newStore(), sz
		ms = append(ms, method{fmt.Sprintf("cdc-%dK", sz>>10), func(f file) int {
			n := 0
			for _, p := range cdc(f.Bytes, sz) {
				n += s.add(p)
			}
			return n
		}, func() int { return s.pieces }})
	}
	ts := newStore()
	ms = append(ms, method{"tensor", func(f file) int { return tensorCost(f, ts, nil, false) }, func() int { return ts.pieces }})
	zs := newStore()
	ms = append(ms, method{"tensor+deflate", func(f file) int { return tensorCost(f, zs, map[string][][]byte{}, false) }, func() int { return zs.pieces }})
	ds := newStore()
	refs := map[string][][]byte{}
	ms = append(ms, method{"tensor+xor-delta", func(f file) int { return tensorCost(f, ds, refs, true) }, func() int { return ds.pieces }})
	return ms
}

// tensorCost stores every tensor of f whole, and the framing (every byte
// outside a tensor) as one piece. With refs, a tensor not already stored costs
// its own bytes deflated; with delta as well, the smallest of that and its XOR
// against an earlier stored tensor of the same name and length, deflated (the
// shape of ZipLLM's BitX). A delta is a new piece; the base it names must stay.
func tensorCost(f file, s *store, refs map[string][][]byte, delta bool) int {
	names := make([]string, 0, len(f.Extents))
	for n := range f.Extents {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return f.Extents[names[i]][0] < f.Extents[names[j]][0] })
	var frame []byte
	at, n := 0, 0
	for _, name := range names {
		e := f.Extents[name]
		frame = append(frame, f.Bytes[at:e[0]]...)
		at = e[1]
		t := f.Bytes[e[0]:e[1]]
		if refs == nil {
			n += s.add(t)
			continue
		}
		k := sha256.Sum256(t)
		if s.seen[k] {
			continue
		}
		s.seen[k] = true
		s.pieces++
		best := deflated(t)
		for _, r := range refs[name] {
			if len(r) != len(t) {
				continue
			}
			x := make([]byte, len(t))
			for i := range t {
				x[i] = t[i] ^ r[i]
			}
			best = min(best, deflated(x))
		}
		if delta {
			refs[name] = append(refs[name], t)
		}
		s.kept += best
		n += best
	}
	frame = append(frame, f.Bytes[at:]...)
	return n + s.add(frame)
}

// result is the report the command writes.
type result struct {
	Shape      shape            `json:"shape"`
	Containers []containerTable `json:"containers"`
	Pairs      []pairRow        `json:"pairs"`
	Framing    []pairRow        `json:"framing"`
	Elements   []elementRow     `json:"elements"`
}

type containerTable struct {
	Container string      `json:"container"`
	Variants  []string    `json:"variants"`
	Total     int         `json:"total_bytes"`
	Methods   []methodRow `json:"methods"`
}

type methodRow struct {
	Method string `json:"method"`
	Kept   int    `json:"kept_bytes"`
	Pieces int    `json:"pieces"`
	// IndexBytes is a 32-byte hash plus an 8-byte length per distinct piece.
	IndexBytes int `json:"index_bytes"`
}

// pairRow is the share of the second file's bytes a store already holding the
// first one would add, per method.
type pairRow struct {
	Container string             `json:"container"`
	First     string             `json:"first"`
	Second    string             `json:"second"`
	SameDType bool               `json:"same_dtype"`
	Size      int                `json:"second_bytes"`
	Added     map[string]float64 `json:"added_fraction"`
}

// elementRow is the share of a fine-tune's bf16 matrix values that are bit
// identical to the base's, the reason a small delta compresses.
type elementRow struct {
	Variant   string  `json:"variant"`
	Identical float64 `json:"identical_fraction"`
}

func measure(s shape) result {
	b := base(s, 1)
	type spec struct {
		name, dtype string
		ts          []tensor
	}
	lora := loraFineTune(b, s.LoRARank, 3)
	ft := map[string][]tensor{}
	specs := []spec{{"base", "bf16", b}, {"base", "q8_0", b}, {"base", "q4_0", b}}
	for _, rel := range []string{"0.001", "0.01", "0.1"} {
		var f float64
		_, _ = fmt.Sscan(rel, &f)
		ft[rel] = fullFineTune(b, f, 2)
		specs = append(specs, spec{"ft-full-" + rel, "bf16", ft[rel]})
	}
	specs = append(specs, spec{"ft-lora", "bf16", lora}, spec{"ft-lora", "q4_0", lora}, spec{"ft-full-0.01", "q4_0", ft["0.01"]})
	var vs []variant
	for _, sp := range specs {
		vs = append(vs, encode(sp.name+"."+sp.dtype, sp.dtype, sp.ts))
	}

	res := result{Shape: s}
	baseBF := encodeBF16(flatten(b, false))
	for _, rel := range []string{"0.001", "0.01", "0.1"} {
		res.Elements = append(res.Elements, elementRow{"ft-full-" + rel + ".bf16", identical(baseBF, encodeBF16(flatten(ft[rel], false)))})
	}
	res.Elements = append(res.Elements, elementRow{"ft-lora.bf16", identical(baseBF, encodeBF16(flatten(lora, false)))})

	containers := []struct {
		name string
		ser  func(variant) file
	}{{"safetensors-like", safetensorsLike}, {"gguf-like", ggufLike}}
	files := map[string]map[string]file{}
	for _, c := range containers {
		files[c.name] = map[string]file{}
		t := containerTable{Container: c.name}
		ms := methods()
		kept := make([]int, len(ms))
		for _, v := range vs {
			f := c.ser(v)
			files[c.name][v.Name] = f
			t.Variants = append(t.Variants, v.Name)
			t.Total += len(f.Bytes)
			for i, m := range ms {
				kept[i] += m.cost(f)
			}
		}
		for i, m := range ms {
			t.Methods = append(t.Methods, methodRow{m.Name, kept[i], m.pieces(), m.pieces() * 40})
		}
		res.Containers = append(res.Containers, t)
	}

	pairs := [][2]string{
		{"base.bf16", "ft-lora.bf16"},
		{"base.bf16", "ft-full-0.001.bf16"},
		{"base.bf16", "ft-full-0.01.bf16"},
		{"base.bf16", "ft-full-0.1.bf16"},
		{"base.q4_0", "ft-lora.q4_0"},
		{"base.q4_0", "ft-full-0.01.q4_0"},
		{"base.bf16", "base.q8_0"},
		{"base.bf16", "base.q4_0"},
		{"base.q8_0", "base.q4_0"},
	}
	for _, c := range containers {
		for _, p := range pairs {
			res.Pairs = append(res.Pairs, pair(c.name, files[c.name][p[0]], files[c.name][p[1]]))
		}
	}
	// The same variant in the other container: only the framing and the
	// tensor order differ, so this isolates what framing does to each method.
	for _, v := range []string{"base.bf16", "base.q4_0"} {
		res.Framing = append(res.Framing, pair("safetensors->gguf", files["safetensors-like"][v], files["gguf-like"][v]))
	}
	return res
}

func pair(container string, a, b file) pairRow {
	row := pairRow{Container: container, First: a.Variant, Second: b.Variant, SameDType: a.DType == b.DType, Size: len(b.Bytes), Added: map[string]float64{}}
	for _, m := range methods() {
		m.cost(a)
		row.Added[m.Name] = float64(m.cost(b)) / float64(len(b.Bytes))
	}
	return row
}

func flatten(ts []tensor, norms bool) []float32 {
	var out []float32
	for _, t := range ts {
		if t.Norm == norms {
			out = append(out, t.Vals...)
		}
	}
	return out
}

func identical(a, b []byte) float64 {
	same := 0
	for i := 0; i+1 < len(a); i += 2 {
		if a[i] == b[i] && a[i+1] == b[i+1] {
			same++
		}
	}
	return float64(same) / float64(len(a)/2)
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", 100*f) }

func markdown(r result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Sub-file dedupe, synthetic family\n\nShape: vocab %d, hidden %d, mlp %d, layers %d, LoRA rank %d. Seeded, so every run prints the same numbers.\n",
		r.Shape.Vocab, r.Shape.Hidden, r.Shape.MLP, r.Shape.Layers, r.Shape.LoRARank)
	for _, c := range r.Containers {
		fmt.Fprintf(&b, "\n## Whole family, %s\n\n%d variants, %d bytes as files.\n\n| method | kept | kept / total | pieces | index |\n|---|---:|---:|---:|---:|\n", c.Container, len(c.Variants), c.Total)
		for _, m := range c.Methods {
			fmt.Fprintf(&b, "| %s | %d | %s | %d | %d |\n", m.Method, m.Kept, pct(float64(m.Kept)/float64(c.Total)), m.Pieces, m.IndexBytes)
		}
	}
	names := []string{"file", "fixed-64K", "cdc-16K", "cdc-64K", "cdc-256K", "tensor", "tensor+deflate", "tensor+xor-delta"}
	table := func(title string, rows []pairRow, same *bool) {
		fmt.Fprintf(&b, "\n## %s\n\nShare of the second file a store holding the first must add.\n\n| container | first | second | %s |\n|---|---|---|%s\n",
			title, strings.Join(names, " | "), strings.Repeat("---:|", len(names)))
		for _, p := range rows {
			if same != nil && p.SameDType != *same {
				continue
			}
			cells := make([]string, len(names))
			for i, n := range names {
				cells[i] = pct(p.Added[n])
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", p.Container, p.First, p.Second, strings.Join(cells, " | "))
		}
	}
	yes, no := true, false
	table("Pairs of one dtype (fine-tunes)", r.Pairs, &yes)
	table("Pairs across dtypes (quantizations; near 100% is expected)", r.Pairs, &no)
	table("The same variant in the other container (framing only)", r.Framing, nil)
	fmt.Fprintf(&b, "\n## bf16 values bit-identical to the base\n\n| variant | identical |\n|---|---:|\n")
	for _, e := range r.Elements {
		fmt.Fprintf(&b, "| %s | %s |\n", e.Variant, pct(e.Identical))
	}
	b.WriteString(limits)
	return b.String()
}

// limits closes every report: what synthetic data can and cannot show.
const limits = `
## Limits

- The weights are seeded Gaussian noise. Exact-match results (quantizations share only norms; a partial
  fine-tune adds only its changed tensors; framing moves fixed chunks) do not depend on the values. The
  delta and compression numbers do, and are illustrative: real weights have structured exponents.
- q8_0 and q4_0 use a bf16 block scale where llama.cpp uses f16; MLX's group-64 scale-and-bias layout is not
  modelled. Neither gives a quantization a byte in common with its base.
- Tensor extents come from the generator, not from parsing headers.
- One family at one size. The exact tensor shares hold at any size; the chunker shares do not, because a
  chunk that straddles a tensor edge is lost, and here a matrix (about 290 KB) is close to the 256 KiB chunk.
  Real tensors of 10 to 100 MB lose proportionally less at their edges.
- Fixed chunks match here only because the variants' headers pad to the same 8-byte length. A real
  header whose padded length differs (offsets, dtypes, metadata) shifts every offset after it, and fixed
  chunks then match nothing, as the framing row shows; CDC and tensors do not care.
`

func main() {
	out := flag.String("out", "", "directory for report.md and report.json (created)")
	small := flag.Bool("small", false, "use the small shape (fast; for tests)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: dedupe -out DIR [-small]")
		os.Exit(2)
	}
	s := defaultShape
	if *small {
		s = smallShape
	}
	r := measure(s)
	j, err := json.MarshalIndent(r, "", "  ")
	if err == nil {
		err = os.MkdirAll(*out, 0o755)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(*out, "report.json"), append(j, '\n'), 0o644)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(*out, "report.md"), []byte(markdown(r)), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dedupe:", err)
		os.Exit(1)
	}
	fmt.Print(markdown(r))
}
