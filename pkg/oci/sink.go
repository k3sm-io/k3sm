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
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Sink is where an assembled image is written. It is the seam a store-backed or
// registry-backed writer slots into later without touching the build code —
// both of those are cancellable blocking IO, which is why ctx is here from the
// start rather than as a later breaking change to an exported interface.
type Sink interface {
	Write(ctx context.Context, ref name.Reference, img ggcrv1.Image) error
}

// TarballSink writes a docker-save tarball at Path, loadable with `docker load`.
type TarballSink struct{ Path string }

// Write implements Sink.
func (s TarballSink) Write(_ context.Context, ref name.Reference, img ggcrv1.Image) error {
	tag, ok := ref.(name.Tag)
	if !ok {
		return fmt.Errorf("a docker-save tarball needs a tagged reference, got %q", ref)
	}
	if err := tarball.WriteToFile(s.Path, tag, img); err != nil {
		return fmt.Errorf("write tarball %s: %w", s.Path, err)
	}
	return nil
}

// LayoutSink writes an OCI image layout directory at Path — the format
// `k3sm image import` consumes.
type LayoutSink struct{ Path string }

// Write implements Sink.
func (s LayoutSink) Write(_ context.Context, ref name.Reference, img ggcrv1.Image) error {
	if err := os.MkdirAll(s.Path, 0o755); err != nil {
		return fmt.Errorf("create layout dir %s: %w", s.Path, err)
	}
	// An OCI layout is a multi-image container: re-initializing an existing one
	// would drop the manifests already indexed there while orphaning their
	// blobs, silently narrowing an artifact the operator is accumulating into.
	p, err := layout.FromPath(s.Path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("open layout %s: %w", s.Path, err)
		}
		if p, err = layout.Write(s.Path, empty.Index); err != nil {
			return fmt.Errorf("init layout %s: %w", s.Path, err)
		}
	}
	if err := p.AppendImage(img, layout.WithAnnotations(map[string]string{
		"org.opencontainers.image.ref.name": ref.String(),
	})); err != nil {
		return fmt.Errorf("write layout %s: %w", s.Path, err)
	}
	return nil
}
