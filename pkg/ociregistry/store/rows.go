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

package store

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

func ispecVersioned() specs.Versioned { return specs.Versioned{SchemaVersion: 2} }

// The index.json row rules, as zot applies them (and as the captured store in
// testdata shows):
//
//   - a tagged PUT removes the row the tag was on; when that was the old
//     digest's last row, the row stays in place with its tag dropped, so the
//     old manifest is still addressable by digest until GC;
//   - it then drops every untagged row of the new digest and appends one row
//     carrying the tag; re-putting a tag at the digest it already names
//     changes nothing;
//   - a PUT by digest appends an untagged row unless a row for that digest
//     exists.

// tagRow is a tagged row for desc.
func tagRow(desc ispec.Descriptor, tag string) ispec.Descriptor {
	row := ispec.Descriptor{MediaType: desc.MediaType, Digest: desc.Digest, Size: desc.Size}
	row.Annotations = map[string]string{ispec.AnnotationRefName: tag}
	return row
}

// putTagged applies a tagged PUT of desc to rows.
func putTagged(rows []ispec.Descriptor, desc ispec.Descriptor, tag string) ([]ispec.Descriptor, bool) {
	for _, r := range rows {
		if r.Annotations[ispec.AnnotationRefName] == tag && r.Digest == desc.Digest && r.MediaType == desc.MediaType {
			return rows, false
		}
	}
	if i := slices.IndexFunc(rows, func(r ispec.Descriptor) bool { return r.Annotations[ispec.AnnotationRefName] == tag }); i >= 0 {
		old := rows[i]
		others := slices.ContainsFunc(rows, func(r ispec.Descriptor) bool {
			return r.Digest == old.Digest && r.Annotations[ispec.AnnotationRefName] != tag
		})
		if others {
			rows = slices.Delete(rows, i, i+1)
		} else {
			old.Annotations = maps.Clone(old.Annotations)
			delete(old.Annotations, ispec.AnnotationRefName)
			if len(old.Annotations) == 0 {
				old.Annotations = nil
			}
			rows[i] = old
		}
	}
	rows = slices.DeleteFunc(rows, func(r ispec.Descriptor) bool {
		_, tagged := r.Annotations[ispec.AnnotationRefName]
		return r.Digest == desc.Digest && !tagged
	})
	return append(rows, tagRow(desc, tag)), true
}

// putUntagged applies a PUT by digest of desc to rows.
func putUntagged(rows []ispec.Descriptor, desc ispec.Descriptor) ([]ispec.Descriptor, bool) {
	if slices.ContainsFunc(rows, func(r ispec.Descriptor) bool { return r.Digest == desc.Digest }) {
		return rows, false
	}
	return append(rows, ispec.Descriptor{MediaType: desc.MediaType, Digest: desc.Digest, Size: desc.Size}), true
}

// PutManifest stores body as a manifest of mediaType in n and records it in
// index.json under r: a tag row, or an untagged row when r is a digest (which
// body must hash to). The body is a blob first, durable before the index
// names it. The store checks no manifest content; the server does.
func (s *Store) PutManifest(ctx context.Context, n ref.Name, r ref.Reference, mediaType string, body []byte) (ispec.Descriptor, error) {
	if mediaType == "" {
		return ispec.Descriptor{}, fmt.Errorf("put manifest in %s: no media type", n)
	}
	algo := digest.Canonical
	if r.Digest != "" {
		algo = r.Digest.Algorithm()
	}
	d := algo.FromBytes(body)
	if r.Digest != "" && d != r.Digest {
		return ispec.Descriptor{}, fmt.Errorf("%w: manifest %s hashes to %s", ErrDigestMismatch, r.Digest, d)
	}
	if err := s.writeBlob(ctx, n, d, body); err != nil {
		return ispec.Descriptor{}, fmt.Errorf("put manifest in %s: %w", n, err)
	}
	desc := ispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(body))}
	err := s.updateIndex(ctx, n, func(rows []ispec.Descriptor) ([]ispec.Descriptor, bool, error) {
		if r.Tag != "" {
			rows, changed := putTagged(rows, desc, r.Tag)
			return rows, changed, nil
		}
		rows, changed := putUntagged(rows, desc)
		return rows, changed, nil
	})
	if err != nil {
		return ispec.Descriptor{}, fmt.Errorf("put manifest in %s: %w", n, err)
	}
	return desc, nil
}

// DeleteTag removes the one row carrying tag.
func (s *Store) DeleteTag(ctx context.Context, n ref.Name, tag string) error {
	return s.updateIndex(ctx, n, func(rows []ispec.Descriptor) ([]ispec.Descriptor, bool, error) {
		i := slices.IndexFunc(rows, func(r ispec.Descriptor) bool { return r.Annotations[ispec.AnnotationRefName] == tag })
		if i < 0 {
			return nil, false, fmt.Errorf("%w: %s in %s", ErrManifestUnknown, tag, n)
		}
		return slices.Delete(rows, i, i+1), true, nil
	})
}

// DeleteDigest removes every row with digest d, tagged or not. The blobs stay
// for GC.
func (s *Store) DeleteDigest(ctx context.Context, n ref.Name, d digest.Digest) error {
	return s.updateIndex(ctx, n, func(rows []ispec.Descriptor) ([]ispec.Descriptor, bool, error) {
		kept := slices.DeleteFunc(rows, func(r ispec.Descriptor) bool { return r.Digest == d })
		if len(kept) == len(rows) {
			return nil, false, fmt.Errorf("%w: %s in %s", ErrManifestUnknown, d, n)
		}
		return kept, true, nil
	})
}
