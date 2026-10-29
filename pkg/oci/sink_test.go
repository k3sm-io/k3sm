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

package oci

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

// TestLayoutSinkWriteIndex pins the multi-platform half of the layout sink: an
// index goes in whole, with every manifest it names, and an existing layout is
// appended to rather than reinitialised.
//
// The layout is the only --output format that can carry more than one platform —
// a docker-save tarball holds one image — so this is the write path a
// multi-platform build depends on.
func TestLayoutSinkWriteIndex(t *testing.T) {
	ref, err := name.NewTag("example.com/app:v1")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("an index goes in whole", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "layout")
		idx := twoPlatformIndex(t)
		if err := (LayoutSink{Path: dir}).WriteIndex(t.Context(), ref, idx); err != nil {
			t.Fatalf("WriteIndex: %v", err)
		}

		p, err := layout.FromPath(dir)
		if err != nil {
			t.Fatalf("read back the layout: %v", err)
		}
		top, err := p.ImageIndex()
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := top.IndexManifest()
		if err != nil {
			t.Fatal(err)
		}
		if len(manifest.Manifests) != 1 || !manifest.Manifests[0].MediaType.IsIndex() {
			t.Fatalf("layout holds %+v, want one index descriptor", manifest.Manifests)
		}
		if got := manifest.Manifests[0].Annotations["org.opencontainers.image.ref.name"]; got != ref.String() {
			t.Errorf("the written index is annotated %q, want the reference", got)
		}
		child, err := top.ImageIndex(manifest.Manifests[0].Digest)
		if err != nil {
			t.Fatal(err)
		}
		children, err := child.IndexManifest()
		if err != nil {
			t.Fatal(err)
		}
		if len(children.Manifests) != 2 {
			t.Errorf("the written index names %d manifests, want 2", len(children.Manifests))
		}
		// Every blob the index names must be readable back out of the layout: an
		// index written without its children is a manifest pointing at nothing.
		for _, desc := range children.Manifests {
			img, err := child.Image(desc.Digest)
			if err != nil {
				t.Fatalf("read %s back: %v", desc.Digest, err)
			}
			if _, err := img.RawConfigFile(); err != nil {
				t.Errorf("config blob of %s is missing: %v", desc.Digest, err)
			}
		}
	})

	t.Run("an existing layout is appended to", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "layout")
		sink := LayoutSink{Path: dir}
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Write(t.Context(), ref, img); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := sink.WriteIndex(t.Context(), ref, twoPlatformIndex(t)); err != nil {
			t.Fatalf("WriteIndex: %v", err)
		}
		p, err := layout.FromPath(dir)
		if err != nil {
			t.Fatal(err)
		}
		top, err := p.ImageIndex()
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := top.IndexManifest()
		if err != nil {
			t.Fatal(err)
		}
		if len(manifest.Manifests) != 2 {
			t.Fatalf("layout holds %d descriptors, want the image AND the index", len(manifest.Manifests))
		}
	})
}

// twoPlatformIndex builds a synthetic index holding one image per platform.
func twoPlatformIndex(t *testing.T) ggcrv1.ImageIndex {
	t.Helper()
	idx := ggcrv1.ImageIndex(empty.Index)
	for _, p := range []ggcrv1.Platform{
		{OS: "linux", Architecture: "arm64"},
		{OS: "linux", Architecture: "amd64"},
	} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: ggcrv1.Descriptor{Platform: &p},
		})
	}
	return idx
}

// TestSinksCarryGzipLayers writes a built image through both sinks and reads
// each back the way a consumer would (`docker load` for the tarball, `k3sm
// image import` for the layout): the image must validate in full (every blob
// re-hashed against its digest, every layer gunzipped against its diff_id) with
// gzip layers. The layout keeps the OCI tar+gzip media type and the built
// manifest digest; a docker-save tarball stores no manifest, so its reader
// synthesizes a Docker one and the gzip layer reads back under Docker's name
// for the same thing.
func TestSinksCarryGzipLayers(t *testing.T) {
	t.Parallel()
	img := buildGzipFixture(t)
	want, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.NewTag("example.com/app:v1")
	if err != nil {
		t.Fatal(err)
	}

	check := func(t *testing.T, got ggcrv1.Image, wantMT types.MediaType) {
		t.Helper()
		if err := validate.Image(got); err != nil {
			t.Fatalf("read-back image does not validate: %v", err)
		}
		m, err := got.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range m.Layers {
			if l.MediaType != wantMT {
				t.Errorf("layer %d media type %q, want %q", i, l.MediaType, wantMT)
			}
		}
	}

	t.Run("tarball", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "img.tar")
		if err := (TarballSink{Path: path}).Write(context.Background(), ref, img); err != nil {
			t.Fatal(err)
		}
		got, err := tarball.ImageFromPath(path, &ref)
		if err != nil {
			t.Fatal(err)
		}
		check(t, got, types.DockerLayer)
	})

	t.Run("layout", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "layout")
		if err := (LayoutSink{Path: dir}).Write(context.Background(), ref, img); err != nil {
			t.Fatal(err)
		}
		p, err := layout.FromPath(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Image(want)
		if err != nil {
			t.Fatalf("layout does not hold the built manifest %s: %v", want, err)
		}
		check(t, got, types.OCILayer)
	})
}
