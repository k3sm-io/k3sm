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

package store_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestSweepStoppedInsideRemoveLayout drives a real layout removal through a
// GC sweep and stops it right after index.json is removed. The next sweeps
// neither fail nor list the half-removed directory, and a push into it makes
// a whole repository that later sweeps keep.
func TestSweepStoppedInsideRemoveLayout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "registry"), filepath.Join(dir, "registry-state"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := ref.ParseName("app")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx, n); err != nil {
		t.Fatal(err)
	}
	repo, err := n.Dir(s.Root())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(repo, "index.json"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.StateDir(), gc.MarkerName), []byte("ran\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-3 * time.Hour)
	clock := func() time.Time { return start }
	c, err := gc.New(s, gc.Options{Grace: time.Hour, Now: func() time.Time { return clock() }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	clock = time.Now

	crash := errors.New("crash")
	store.SetIndexRemoved(s, func() error { return crash })
	if _, err := c.Sweep(ctx); !errors.Is(err, crash) {
		t.Fatalf("sweep: %v, want the stop inside RemoveLayout", err)
	}
	store.SetIndexRemoved(s, nil)
	if _, err := os.Lstat(filepath.Join(repo, "index.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("index.json after the stop: %v", err)
	}
	for range 2 {
		rep, err := c.Sweep(ctx)
		if err != nil || rep.Count(gc.KindRepository) != 0 {
			t.Fatalf("sweep after the stop: %+v, %v", rep, err)
		}
	}
	if repos, err := s.Repositories(); err != nil || slices.Contains(repos, n) {
		t.Fatalf("repositories %v, %v; want no %s", repos, err, n)
	}

	body := []byte("layer")
	d := digest.FromBytes(body)
	if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err != nil {
		t.Fatalf("push into the half-removed layout: %v", err)
	}
	m := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + d.String() + `","size":5},"layers":[]}`)
	if _, err := s.PutManifest(ctx, n, ref.Reference{Tag: "v1"}, ispec.MediaTypeImageManifest, m); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sweep(ctx); err != nil {
		t.Fatalf("sweep after the push: %v", err)
	}
	if repos, err := s.Repositories(); err != nil || !slices.Contains(repos, n) {
		t.Fatalf("repositories %v, %v; want %s", repos, err, n)
	}
	for _, b := range []digest.Digest{d, digest.FromBytes(m)} {
		if _, err := s.StatBlob(n, b); err != nil {
			t.Errorf("%s lost %s: %v", n, b, err)
		}
	}
}
