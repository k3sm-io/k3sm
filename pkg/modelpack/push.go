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
	"context"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// BlobError is an upload of one blob that failed: Digest names the blob and
// Err is the registry's error, unwrapped by errors.As and errors.Is.
type BlobError struct {
	Digest string
	Err    error
}

func (e *BlobError) Error() string { return "upload " + e.Digest + ": " + e.Err.Error() }
func (e *BlobError) Unwrap() error { return e.Err }

// Push uploads a to ref: the config and every layer, then the manifest.
//
// Each blob is uploaded only when the repository lacks it
// (go-containerregistry HEADs it first), and each layer is re-verified as it
// is read (Artifact.Open), so the bytes sent are the bytes the manifest
// names. The manifest goes last, so a tag never names a manifest whose blobs
// are not all there, and is not sent at all when the tag already names this
// digest, so pushing the same files again uploads nothing. A blob upload that fails is a *BlobError; a manifest put
// that fails is the registry's error as is.
func Push(ctx context.Context, ref name.Reference, a *Artifact, opts ...remote.Option) error {
	opts = append(opts[:len(opts):len(opts)], remote.WithContext(ctx))
	repo := ref.Context()
	blobs := []pushBlob{{desc: a.ConfigDescriptor, open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(a.Config)), nil
	}}}
	for _, l := range a.Layers {
		blobs = append(blobs, pushBlob{desc: l.Descriptor, open: func() (io.ReadCloser, error) { return a.Open(l) }})
	}
	for _, b := range blobs {
		if err := remote.WriteLayer(repo, b, opts...); err != nil {
			return &BlobError{Digest: b.desc.Digest.String(), Err: err}
		}
	}
	if d, err := remote.Head(ref, opts...); err == nil && d.Digest.String() == a.Digest.String() {
		return nil // the tag already names this manifest
	}
	if err := remote.Put(ref, rawManifest{body: a.Manifest, mediaType: ispec.MediaTypeImageManifest}, opts...); err != nil {
		return fmt.Errorf("put manifest: %w", err)
	}
	return nil
}

// pushBlob is one blob of a model artifact as go-containerregistry uploads
// it: raw, so its compressed and uncompressed forms are the same bytes.
type pushBlob struct {
	desc ispec.Descriptor
	open func() (io.ReadCloser, error)
}

func (b pushBlob) Digest() (ggcrv1.Hash, error)         { return ggcrv1.NewHash(b.desc.Digest.String()) }
func (b pushBlob) DiffID() (ggcrv1.Hash, error)         { return b.Digest() }
func (b pushBlob) Compressed() (io.ReadCloser, error)   { return b.open() }
func (b pushBlob) Uncompressed() (io.ReadCloser, error) { return b.open() }
func (b pushBlob) Size() (int64, error)                 { return b.desc.Size, nil }
func (b pushBlob) MediaType() (types.MediaType, error) {
	return types.MediaType(b.desc.MediaType), nil
}

// rawManifest is manifest bytes remote.Put sends verbatim under mediaType.
type rawManifest struct {
	body      []byte
	mediaType string
}

func (m rawManifest) RawManifest() ([]byte, error)        { return m.body, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return types.MediaType(m.mediaType), nil }
