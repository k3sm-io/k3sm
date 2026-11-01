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

package gc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

const grace = time.Hour

// clock is the injected clock: a fixed base plus an offset the test moves.
// Writes the kernel stamps (session chunks, index.json) land near offset 0,
// so the tests keep "now" near 0 and make old content by moving the offset
// back before writing it.
type clock struct {
	mu   sync.Mutex
	base time.Time
	off  time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base.Add(c.off)
}

func (c *clock) set(off time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.off = off
}

type env struct {
	s   *store.Store
	clk *clock
	ctx context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "registry"), filepath.Join(dir, "registry-state"))
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{base: time.Now().Truncate(time.Second)}
	s.SetClock(clk.now)
	return &env{s: s, clk: clk, ctx: context.Background()}
}

// collector returns a collector started at offset at.
func (e *env) collector(t *testing.T, at time.Duration) *Collector {
	t.Helper()
	e.clk.set(at)
	c, err := New(e.s, Options{Grace: grace, Now: e.clk.now, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ran writes the first-sweep marker, so sweeps delete.
func (e *env) ran(t *testing.T) {
	t.Helper()
	if err := WriteMarker(e.s, e.clk.now()); err != nil {
		t.Fatal(err)
	}
}

func name(t *testing.T, s string) ref.Name {
	t.Helper()
	n, err := ref.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) blob(t *testing.T, n ref.Name, body []byte) ispec.Descriptor {
	t.Helper()
	d := digest.FromBytes(body)
	if err := e.s.PutBlob(e.ctx, n, d, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	return ispec.Descriptor{MediaType: ispec.MediaTypeImageLayer, Digest: d, Size: int64(len(body))}
}

func manifestBody(t *testing.T, cfg ispec.Descriptor, layers []ispec.Descriptor, subject *ispec.Descriptor) []byte {
	t.Helper()
	cfg.MediaType = ispec.MediaTypeImageConfig
	m := ispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageManifest, Config: cfg, Layers: layers, Subject: subject}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// image is a pushed image: its manifest and the blobs it names.
type image struct {
	manifest ispec.Descriptor
	body     []byte
	config   ispec.Descriptor
	layers   []ispec.Descriptor
}

func (i image) blobs() []digest.Digest {
	out := []digest.Digest{i.manifest.Digest, i.config.Digest}
	for _, l := range i.layers {
		out = append(out, l.Digest)
	}
	return out
}

// push uploads an image's config and layers and puts its manifest under r
// (a tag, or "" for by digest).
func (e *env) push(t *testing.T, n ref.Name, tag, seed string, layers ...[]byte) image {
	t.Helper()
	var img image
	img.config = e.blob(t, n, []byte(`{"seed":"`+seed+`"}`))
	for _, l := range layers {
		img.layers = append(img.layers, e.blob(t, n, l))
	}
	img.body = manifestBody(t, img.config, img.layers, nil)
	img.manifest = e.putManifest(t, n, tag, ispec.MediaTypeImageManifest, img.body)
	return img
}

func (e *env) putManifest(t *testing.T, n ref.Name, tag, mediaType string, body []byte) ispec.Descriptor {
	t.Helper()
	r := ref.Reference{Tag: tag}
	if tag == "" {
		r = ref.Reference{Digest: digest.FromBytes(body)}
	}
	desc, err := e.s.PutManifest(e.ctx, n, r, mediaType, body)
	if err != nil {
		t.Fatal(err)
	}
	return desc
}

func (e *env) has(n ref.Name, d digest.Digest) bool {
	_, err := e.s.StatBlob(n, d)
	return err == nil
}

func (e *env) dir(t *testing.T, n ref.Name) string {
	t.Helper()
	d, err := n.Dir(e.s.Root())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (e *env) blobFile(t *testing.T, n ref.Name, d digest.Digest) string {
	return filepath.Join(e.dir(t, n), "blobs", d.Algorithm().String(), d.Encoded())
}

func (e *env) sessionFile(t *testing.T, n ref.Name, id string) string {
	return filepath.Join(e.dir(t, n), ".uploads", id)
}

func (e *env) mtime(t *testing.T, p string) time.Time {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

// backdate sets p's mtime to offset at.
func (e *env) backdate(t *testing.T, p string, at time.Duration) {
	t.Helper()
	ts := e.clk.base.Add(at)
	if err := os.Chtimes(p, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func (e *env) session(t *testing.T, n ref.Name, body string) string {
	t.Helper()
	id, err := e.s.NewUpload(e.ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.AppendUpload(e.ctx, n, id, 0, bytes.NewReader([]byte(body))); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) sweep(t *testing.T, c *Collector) Report {
	t.Helper()
	rep, err := c.Sweep(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}
