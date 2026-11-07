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
	"encoding/json"
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
//     exists;
//   - a tag delete removes the tag's row; when that was the digest's last row,
//     an untagged row goes at the end of the index, so the manifest is still
//     addressable by digest until a digest delete or GC.

// tagRow is a tagged row for desc.
func tagRow(desc ispec.Descriptor, tag string) ispec.Descriptor {
	row := ispec.Descriptor{MediaType: desc.MediaType, Digest: desc.Digest, Size: desc.Size}
	row.Annotations = map[string]string{ispec.AnnotationRefName: tag}
	return row
}

// untaggedRow is row without its tag, its other annotations kept.
func untaggedRow(row ispec.Descriptor) ispec.Descriptor {
	row.Annotations = maps.Clone(row.Annotations)
	delete(row.Annotations, ispec.AnnotationRefName)
	if len(row.Annotations) == 0 {
		row.Annotations = nil
	}
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
			rows[i] = untaggedRow(old)
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
	return s.PutManifestChecked(ctx, n, r, mediaType, body, nil)
}

// PutManifestChecked is PutManifest that runs check, when it is set, under
// the repository lock immediately before index.json is written, and writes
// nothing to the index when it fails. The server checks there that every blob
// the manifest names is still in the repository: a sweep deletes only under
// the same lock, so a blob present at the check stays until the index names
// it. check holds the lock through its Locked value and must not take it again.
func (s *Store) PutManifestChecked(ctx context.Context, n ref.Name, r ref.Reference, mediaType string, body []byte, check func(*Locked) error) (ispec.Descriptor, error) {
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
	dir, err := s.repoDir(n)
	if err != nil {
		return ispec.Descriptor{}, fmt.Errorf("put manifest in %s: %w", n, err)
	}
	err = s.updateIndex(ctx, n, func(rows []ispec.Descriptor) ([]ispec.Descriptor, bool, error) {
		if check != nil {
			if err := check(&Locked{s: s, n: n, dir: dir}); err != nil {
				return nil, false, err
			}
		}
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

// IndexState is a digest over a repository's index.json rows, in order: it
// changes whenever a row is added, removed, re-tagged or reordered, and only
// then. A reader that computes it from Index and a writer that computes it from
// the rows under the repository lock get the same value for the same rows, so
// it serves as the entity tag of a conditional request: a delete that names
// the state its caller planned against is refused once the repository has
// moved on.
func IndexState(rows []ispec.Descriptor) (string, error) {
	d := digest.Canonical.Digester()
	enc := json.NewEncoder(d.Hash())
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return "", fmt.Errorf("index state: %w", err)
		}
	}
	return d.Digest().String(), nil
}

// deleteTagRow applies a tag delete of the row at i to rows. keep, when it is
// set, decides whether a manifest losing its last row gets the untagged one.
func deleteTagRow(rows []ispec.Descriptor, i int, keep func(ispec.Descriptor) (bool, error)) ([]ispec.Descriptor, error) {
	old := rows[i]
	rows = slices.Delete(rows, i, i+1)
	if slices.ContainsFunc(rows, func(r ispec.Descriptor) bool { return r.Digest == old.Digest }) {
		return rows, nil
	}
	if keep != nil {
		ok, err := keep(old)
		if err != nil {
			return nil, err
		}
		if !ok {
			return rows, nil
		}
	}
	return append(rows, untaggedRow(old)), nil
}

// DeleteTag removes tag and nothing it names: the row carrying it goes, and a
// manifest with no other row keeps an untagged one (see the row rules above).
func (s *Store) DeleteTag(ctx context.Context, n ref.Name, tag string) error {
	return s.DeleteTagChecked(ctx, n, tag, func([]ispec.Descriptor) error { return nil }, nil)
}

// DeleteTagChecked is DeleteTag that first runs check over the rows under the
// repository lock and deletes nothing when it fails. keep, when it is set, runs
// under the lock too, for a manifest losing its last row: it reports whether
// the manifest keeps an untagged row, and an error deletes nothing. Neither may
// take the repository lock.
func (s *Store) DeleteTagChecked(ctx context.Context, n ref.Name, tag string, check func([]ispec.Descriptor) error, keep func(ispec.Descriptor) (bool, error)) error {
	return s.updateIndex(ctx, n, func(rows []ispec.Descriptor) ([]ispec.Descriptor, bool, error) {
		i := slices.IndexFunc(rows, func(r ispec.Descriptor) bool { return r.Annotations[ispec.AnnotationRefName] == tag })
		if i < 0 {
			return nil, false, fmt.Errorf("%w: %s in %s", ErrManifestUnknown, tag, n)
		}
		if err := check(rows); err != nil {
			return nil, false, err
		}
		rows, err := deleteTagRow(rows, i, keep)
		if err != nil {
			return nil, false, err
		}
		return rows, true, nil
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

// DeleteDigestChecked is DeleteDigest that first runs check over the rows
// under the repository lock and deletes nothing when it fails, so a refusal
// based on the index (a manifest an index still names) cannot race a PUT
// that changes it. check must not take the repository lock.
func (s *Store) DeleteDigestChecked(ctx context.Context, n ref.Name, d digest.Digest, check func([]ispec.Descriptor) error) error {
	return s.updateIndex(ctx, n, func(rows []ispec.Descriptor) ([]ispec.Descriptor, bool, error) {
		if !slices.ContainsFunc(rows, func(r ispec.Descriptor) bool { return r.Digest == d }) {
			return nil, false, fmt.Errorf("%w: %s in %s", ErrManifestUnknown, d, n)
		}
		if err := check(rows); err != nil {
			return nil, false, err
		}
		return slices.DeleteFunc(rows, func(r ispec.Descriptor) bool { return r.Digest == d }), true, nil
	})
}
