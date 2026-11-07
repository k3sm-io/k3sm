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
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// msgQuotaExceeded is the fixed message of a manifest PUT the quota refuses.
// The refusal's detail names the artifact type and its quota.
const msgQuotaExceeded = "the push would exceed the registry's storage quota for its artifact type"

// quotaKey is one stored manifest: a repository and a manifest digest. Every
// row of the digest in the repository is the same manifest.
type quotaKey struct {
	repo string
	d    digest.Digest
}

// quotaEntry is what one manifest counts: its artifact type and its layers'
// sizes as the store holds them.
type quotaEntry struct {
	artifactType string
	layers       map[digest.Digest]int64
}

// quotaBlob is one layer a type's manifests name: its size and how many of
// them name it.
type quotaBlob struct {
	size int64
	refs int
}

// quota is the per-artifactType byte quota a manifest PUT is checked against.
//
// Usage is a maintained count, not a scan per PUT. A type's usage is the sum
// of the sizes of the distinct layer blobs its stored manifests name, store
// wide, so a blob two manifests name, in one repository or several, counts
// once. A size is the stored blob's, never what a descriptor claims. Only
// image manifests of a type with a quota count; an index names no layer.
//
// The count is built from the store at the first check, and again at the
// first check after something removed rows (a manifest DELETE, or a sweep the
// caller reports through Server.InvalidateQuota), so a removal never leaves a
// type refused for bytes it no longer holds. A PUT adds its manifest when it
// is admitted, before the row is written, so two concurrent PUTs cannot both
// fit in the same room; one whose write fails takes its manifest out again.
// A rebuild keeps the manifests admitted and not yet written.
//
// mu guards every field below limits, and is held across a rebuild.
type quota struct {
	limits map[string]int64

	mu       sync.Mutex
	built    bool
	entries  map[quotaKey]quotaEntry
	inflight map[quotaKey]quotaEntry
	blobs    map[string]map[digest.Digest]*quotaBlob
	usage    map[string]int64
}

// newQuota returns the quota for limits, or nil when limits is empty. Every
// limit must name a type and be positive.
func newQuota(limits map[string]int64) (*quota, error) {
	if len(limits) == 0 {
		return nil, nil
	}
	l := make(map[string]int64, len(limits))
	for t, n := range limits {
		if t == "" {
			return nil, errors.New("registry api: a quota names no artifact type")
		}
		if n <= 0 {
			return nil, fmt.Errorf("registry api: quota %d for %q must be positive", n, t)
		}
		l[t] = n
	}
	return &quota{limits: l, inflight: map[quotaKey]quotaEntry{}}, nil
}

// invalidate has the next check rebuild the count from the store.
func (q *quota) invalidate() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.built = false
}

// add counts e under k. The caller holds mu.
func (q *quota) add(k quotaKey, e quotaEntry) {
	if _, ok := q.entries[k]; ok {
		return
	}
	q.entries[k] = e
	bs := q.blobs[e.artifactType]
	if bs == nil {
		bs = map[digest.Digest]*quotaBlob{}
		q.blobs[e.artifactType] = bs
	}
	for d, size := range e.layers {
		if b := bs[d]; b != nil {
			b.refs++
			continue
		}
		bs[d] = &quotaBlob{size: size, refs: 1}
		q.usage[e.artifactType] += size
	}
}

// remove stops counting k. The caller holds mu.
func (q *quota) remove(k quotaKey) {
	e, ok := q.entries[k]
	if !ok {
		return
	}
	delete(q.entries, k)
	bs := q.blobs[e.artifactType]
	for d := range e.layers {
		b := bs[d]
		if b == nil {
			continue
		}
		if b.refs--; b.refs == 0 {
			delete(bs, d)
			q.usage[e.artifactType] -= b.size
		}
	}
}

// grows returns the bytes e would add to its type's usage. The caller holds mu.
func (q *quota) grows(k quotaKey, e quotaEntry) int64 {
	if _, ok := q.entries[k]; ok {
		return 0
	}
	var n int64
	bs := q.blobs[e.artifactType]
	for d, size := range e.layers {
		if bs[d] == nil {
			n += size
		}
	}
	return n
}

// admit counts the manifest k of type artifactType naming layers, or refuses it
// when that would take the type past its quota. The returned release takes the
// manifest out again for a PUT whose write failed; done marks the write made.
// A type without a quota, and a manifest already counted, admit at no cost.
func (s *Server) admitQuota(n ref.Name, d digest.Digest, artifactType string, layers []digest.Digest) (release, done func(), err error) {
	noop := func() {}
	q := s.quota
	if q == nil {
		return noop, noop, nil
	}
	limit, ok := q.limits[artifactType]
	if !ok {
		return noop, noop, nil
	}
	e := quotaEntry{artifactType: artifactType, layers: make(map[digest.Digest]int64, len(layers))}
	for _, l := range layers {
		size, err := s.st.StatBlob(n, l)
		if uncountable(err) {
			continue // a non-distributable layer the store does not hold
		}
		if err != nil {
			return nil, nil, err
		}
		e.layers[l] = size
	}
	k := quotaKey{repo: n.String(), d: d}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := s.buildQuota(); err != nil {
		return nil, nil, err
	}
	if _, counted := q.entries[k]; counted {
		return noop, noop, nil
	}
	if q.usage[artifactType]+q.grows(k, e) > limit {
		ae := errorf(http.StatusForbidden, codeDenied, msgQuotaExceeded)
		ae.detail = map[string]string{"artifactType": artifactType, "quota": strconv.FormatInt(limit, 10)}
		return nil, nil, ae
	}
	q.add(k, e)
	q.inflight[k] = e
	release = func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		delete(q.inflight, k)
		q.remove(k)
	}
	done = func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		delete(q.inflight, k)
	}
	return release, done, nil
}

// buildQuota rebuilds the count from the store unless it is built. The caller
// holds s.quota.mu. A manifest whose body is gone, damaged or not a manifest
// counts nothing; any other read error fails the check, and the next one
// tries again.
func (s *Server) buildQuota() error {
	q := s.quota
	if q.built {
		return nil
	}
	q.entries = map[quotaKey]quotaEntry{}
	q.blobs = map[string]map[digest.Digest]*quotaBlob{}
	q.usage = map[string]int64{}
	repos, err := s.st.Repositories()
	if err != nil {
		return fmt.Errorf("count the registry quota: %w", err)
	}
	for _, n := range repos {
		idx, err := s.st.Index(n)
		if errors.Is(err, store.ErrRepositoryUnknown) {
			continue
		}
		if err != nil {
			return fmt.Errorf("count the registry quota: %w", err)
		}
		seen := map[digest.Digest]bool{}
		for _, row := range idx.Manifests {
			if seen[row.Digest] || isIndexType(row.MediaType) {
				continue
			}
			seen[row.Digest] = true
			e, ok, err := s.quotaEntryOf(n, row)
			if err != nil {
				return fmt.Errorf("count the registry quota: %w", err)
			}
			if ok {
				q.add(quotaKey{repo: n.String(), d: row.Digest}, e)
			}
		}
	}
	for k, e := range q.inflight {
		q.add(k, e)
	}
	q.built = true
	return nil
}

// quotaEntryOf reads the manifest row names in n and returns what it counts,
// or false when it counts nothing: a type without a quota, or a body that is
// gone, damaged or not an image manifest.
func (s *Server) quotaEntryOf(n ref.Name, row ispec.Descriptor) (quotaEntry, bool, error) {
	body, err := s.readManifestBlob(n, row)
	if uncountable(err) {
		return quotaEntry{}, false, nil
	}
	if err != nil {
		return quotaEntry{}, false, err
	}
	var m ispec.Manifest
	if json.Unmarshal(body, &m) != nil {
		return quotaEntry{}, false, nil
	}
	t := artifactv1.ArtifactType(m.ArtifactType, m.Config.MediaType)
	if _, ok := s.quota.limits[t]; !ok {
		return quotaEntry{}, false, nil
	}
	e := quotaEntry{artifactType: t, layers: make(map[digest.Digest]int64, len(m.Layers))}
	for _, l := range m.Layers {
		size, err := s.st.StatBlob(n, l.Digest)
		if uncountable(err) {
			continue
		}
		if err != nil {
			return quotaEntry{}, false, err
		}
		e.layers[l.Digest] = size
	}
	return e, true, nil
}

// uncountable reports whether err is a manifest or blob that stays unreadable
// until someone repairs the store, which counts nothing, rather than a read
// that may pass.
func uncountable(err error) bool {
	return errors.Is(err, store.ErrBlobUnknown) || errors.Is(err, store.ErrStoreCorrupt) || errors.Is(err, store.ErrNotRegular) ||
		errors.Is(err, ref.ErrSymlink) || errors.Is(err, ref.ErrInvalidDigest) || errors.Is(err, errManifestSize)
}

// InvalidateQuota tells the server that rows were removed behind its back, by
// a garbage-collection sweep, so the quota's count is rebuilt from the store at
// the next manifest PUT that it limits. It does nothing without a quota.
func (s *Server) InvalidateQuota() { s.quota.invalidate() }
