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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/runtimed/pkg/artifact"
)

// AnnotationVariant is the index-entry annotation naming a model variant:
// the value spec.quantization selects on an MLXModel that serves the index.
const AnnotationVariant = artifact.AnnotationVariant

// variantPattern is the variant grammar: 1 to MaxVariantLength bytes of
// [A-Za-z0-9._-].
var variantPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Variant push refusals.
var (
	// ErrInvalidVariant is a variant value outside the grammar.
	ErrInvalidVariant = errors.New("a variant is 1 to 128 characters of [A-Za-z0-9._-]")
	// ErrTagIsManifest is a variant push to a tag that names a single
	// manifest: turning it into an index would change what every reader of
	// the tag gets, so it is refused rather than converted.
	ErrTagIsManifest = errors.New("the tag names a single model manifest, not a variant index; push the variant under another tag, or remove the tag first")
	// ErrIndexInvalid is an index at the tag that is not one this push can
	// update: not an OCI image index, malformed, or over its size or entry cap.
	ErrIndexInvalid = errors.New("the index at the tag cannot be updated")
)

// ValidateVariant reports whether v is a variant value a push may record.
func ValidateVariant(v string) error {
	if len(v) == 0 || len(v) > artifact.MaxVariantLength || !variantPattern.MatchString(v) {
		return fmt.Errorf("variant %q: %w", v, ErrInvalidVariant)
	}
	return nil
}

// PushVariant pushes a under variant: the blobs and the manifest by digest,
// then the OCI image index at ref's tag, which ends up holding exactly one
// entry for variant (added, or replacing the entry that carried it) beside
// every other entry it held. Entries are sorted by variant, so the same set
// of variants always makes the same index digest. It returns that digest.
//
// The tag is read before any byte is uploaded, and read again after the
// upload, immediately before the index is written; the variant is merged into
// the index that second read returns. Each read refuses a tag that names a
// single manifest with ErrTagIsManifest, and an index that is not an OCI
// image index within the caps the runtime reads it under with
// ErrIndexInvalid. A registry offers no compare-and-swap on a tag, so two
// pushes of different variants that both re-read before either writes can
// still lose one entry; the window is that one round trip, not the upload,
// and pushing the lost variant again restores it.
func PushVariant(ctx context.Context, ref name.Tag, a *Artifact, variant string, opts ...remote.Option) (string, error) {
	if err := ValidateVariant(variant); err != nil {
		return "", err
	}
	opts = append(opts[:len(opts):len(opts)], remote.WithContext(ctx))
	if _, err := currentIndex(ref, opts); err != nil {
		return "", err
	}
	if err := Push(ctx, ref.Context().Digest(a.Digest.String()), a, opts...); err != nil {
		return "", err
	}
	idx, err := currentIndex(ref, opts)
	if err != nil {
		return "", err
	}
	entry := ispec.Descriptor{
		MediaType:   ispec.MediaTypeImageManifest,
		Digest:      a.Digest,
		Size:        int64(len(a.Manifest)),
		Annotations: map[string]string{AnnotationVariant: variant},
	}
	if art, err := manifestArtifactType(a.Manifest); err == nil {
		entry.ArtifactType = art
	}
	idx.Manifests = slices.DeleteFunc(idx.Manifests, func(d ispec.Descriptor) bool {
		return d.Annotations[AnnotationVariant] == variant
	})
	idx.Manifests = append(idx.Manifests, entry)
	if len(idx.Manifests) > artifact.MaxIndexEntries {
		return "", fmt.Errorf("index would list %d entries, at most %d: %w", len(idx.Manifests), artifact.MaxIndexEntries, ErrIndexInvalid)
	}
	slices.SortStableFunc(idx.Manifests, func(x, y ispec.Descriptor) int {
		return cmp.Compare(x.Annotations[AnnotationVariant], y.Annotations[AnnotationVariant])
	})
	body, err := json.Marshal(idx)
	if err != nil {
		return "", fmt.Errorf("encode index: %w", err)
	}
	if len(body) > artifact.MaxIndexBytes {
		return "", fmt.Errorf("index would be %d bytes, at most %d: %w", len(body), artifact.MaxIndexBytes, ErrIndexInvalid)
	}
	sum := digest.FromBytes(body).String()
	if d, err := remote.Head(ref, opts...); err == nil && d.Digest.String() == sum {
		return sum, nil // the tag already names this index
	}
	if err := remote.Put(ref, rawManifest{body: body, mediaType: ispec.MediaTypeImageIndex}, opts...); err != nil {
		return "", fmt.Errorf("put index: %w", err)
	}
	return sum, nil
}

// currentIndex is the index ref's tag names now, or an empty one when the
// tag does not exist. The body is read under artifact.MaxIndexBytes and must
// list at most artifact.MaxIndexEntries OCI image manifests.
func currentIndex(ref name.Tag, opts []remote.Option) (ispec.Index, error) {
	empty := ispec.Index{MediaType: ispec.MediaTypeImageIndex}
	empty.SchemaVersion = 2
	desc, err := remote.Head(ref, opts...)
	if err != nil {
		if te, ok := errors.AsType[*transport.Error](err); ok && te.StatusCode == http.StatusNotFound {
			return empty, nil
		}
		return ispec.Index{}, fmt.Errorf("read %s: %w", ref, err)
	}
	switch string(desc.MediaType) {
	case ispec.MediaTypeImageIndex:
	case ispec.MediaTypeImageManifest, "application/vnd.docker.distribution.manifest.v2+json":
		return ispec.Index{}, fmt.Errorf("%s: %w", ref, ErrTagIsManifest)
	default:
		return ispec.Index{}, fmt.Errorf("%s is %s, not an OCI image index: %w", ref, desc.MediaType, ErrIndexInvalid)
	}
	if desc.Size > artifact.MaxIndexBytes {
		return ispec.Index{}, fmt.Errorf("%s: index of %d bytes, at most %d: %w", ref, desc.Size, artifact.MaxIndexBytes, ErrIndexInvalid)
	}
	got, err := remote.Get(ref, opts...)
	if err != nil {
		return ispec.Index{}, fmt.Errorf("read %s: %w", ref, err)
	}
	if string(got.MediaType) != ispec.MediaTypeImageIndex {
		return ispec.Index{}, fmt.Errorf("%s is %s, not an OCI image index: %w", ref, got.MediaType, ErrIndexInvalid)
	}
	if len(got.Manifest) > artifact.MaxIndexBytes {
		return ispec.Index{}, fmt.Errorf("%s: index of %d bytes, at most %d: %w", ref, len(got.Manifest), artifact.MaxIndexBytes, ErrIndexInvalid)
	}
	var idx ispec.Index
	if err := json.Unmarshal(got.Manifest, &idx); err != nil {
		return ispec.Index{}, fmt.Errorf("%s: %w: %v", ref, ErrIndexInvalid, err)
	}
	if idx.SchemaVersion != 2 || (idx.MediaType != "" && idx.MediaType != ispec.MediaTypeImageIndex) {
		return ispec.Index{}, fmt.Errorf("%s: schemaVersion %d, mediaType %q: %w", ref, idx.SchemaVersion, idx.MediaType, ErrIndexInvalid)
	}
	if len(idx.Manifests) > artifact.MaxIndexEntries {
		return ispec.Index{}, fmt.Errorf("%s lists %d entries, at most %d: %w", ref, len(idx.Manifests), artifact.MaxIndexEntries, ErrIndexInvalid)
	}
	for i, d := range idx.Manifests {
		if d.MediaType != ispec.MediaTypeImageManifest {
			return ispec.Index{}, fmt.Errorf("%s entry %d is %q, not an OCI image manifest: %w", ref, i, d.MediaType, ErrIndexInvalid)
		}
	}
	idx.MediaType = ispec.MediaTypeImageIndex
	return idx, nil
}

// manifestArtifactType is the artifactType a's manifest declares.
func manifestArtifactType(manifest []byte) (string, error) {
	var m struct {
		ArtifactType string `json:"artifactType"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return "", err
	}
	return m.ArtifactType, nil
}
