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
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// Bounds of the referrers view.
const (
	// referrersScanRows and referrersScanBytes are the most manifests, and
	// manifest bytes, one referrers request reads. A repository with more
	// unread manifests than that is read over several requests: each one keeps
	// what it read, and answers 429 with Retry-After until the view is whole.
	referrersScanRows  = 4096
	referrersScanBytes = 64 << 20
	// referrersPage is the default and the largest page of one referrers
	// answer, and referrersPageBytes the encoded descriptor bytes a page
	// stops at (a page always carries at least one descriptor).
	referrersPage      = 1000
	referrersPageBytes = 4 << 20
	// referrerCacheViews, referrerCacheRows and referrerCacheBytes bound the
	// cache over all repositories; past any of them the least recently used
	// views are dropped.
	referrerCacheViews = 1024
	referrerCacheRows  = 1 << 18
	referrerCacheBytes = 64 << 20
)

// errReferrersBusy is a referrers request that used its read budget before the
// repository's view was whole (429; the next request carries on).
var errReferrersBusy = errors.New("referrers view still being built")

// referrerDoc is what the referrers scan reads from each manifest.
type referrerDoc struct {
	MediaType    string             `json:"mediaType"`
	ArtifactType string             `json:"artifactType"`
	Config       *ispec.Descriptor  `json:"config"`
	Subject      *ispec.Descriptor  `json:"subject"`
	Annotations  map[string]string  `json:"annotations"`
	Manifests    []ispec.Descriptor `json:"manifests"`
}

// refEntry is what one manifest contributes to the view: its subject (empty
// when it has none) and the descriptor a referrers answer lists for it, with
// that descriptor's encoded size. A manifest is content addressed, so an entry
// stays right for its digest for as long as a row names it.
type refEntry struct {
	subject digest.Digest
	desc    ispec.Descriptor
	size    int
}

// refView is the referrers view of one repository.
type refView struct {
	// sem is held while the view is checked or rebuilt.
	sem chan struct{}
	// Guarded by sem: the index version the view was built at, whether the
	// build was whole, the entries by manifest digest, and the referrers by
	// subject sorted by digest (each slice is never changed once published).
	version   store.IndexVersion
	ready     bool
	entries   map[digest.Digest]refEntry
	bySubject map[digest.Digest][]refEntry
	// Guarded by referrerCache.mu: the last use, and the cost last accounted.
	used        uint64
	rows, bytes int64
}

// referrerCache holds the views. Lock order: a view's sem, then mu.
type referrerCache struct {
	mu    sync.Mutex
	tick  uint64
	views map[string]*refView
	rows  int64
	bytes int64
}

func newReferrerCache() *referrerCache {
	return &referrerCache{views: map[string]*refView{}}
}

// view returns key's view, creating it, and marks it used.
func (c *referrerCache) view(key string) *refView {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.views[key]
	if v == nil {
		v = &refView{sem: make(chan struct{}, 1)}
		c.views[key] = v
	}
	c.tick++
	v.used = c.tick
	return v
}

// drop forgets key's view when it is still v.
func (c *referrerCache) drop(key string, v *refView) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.views[key] == v {
		delete(c.views, key)
		c.rows -= v.rows
		c.bytes -= v.bytes
	}
}

// account records v's new cost and drops the least recently used other views
// until the cache is within its bounds.
func (c *referrerCache) account(key string, v *refView, rows, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.views[key] != v {
		return // dropped while it was built
	}
	c.rows += rows - v.rows
	c.bytes += bytes - v.bytes
	v.rows, v.bytes = rows, bytes
	for len(c.views) > referrerCacheViews || c.rows > referrerCacheRows || c.bytes > referrerCacheBytes {
		var oldKey string
		var old *refView
		for k, o := range c.views {
			if o != v && (old == nil || o.used < old.used) {
				oldKey, old = k, o
			}
		}
		if old == nil {
			return // v alone; it is bounded by the index and the read budget
		}
		delete(c.views, oldKey)
		c.rows -= old.rows
		c.bytes -= old.bytes
	}
}

// referrersOf returns n's manifests whose subject is d, sorted by digest. It
// answers from the cached view while index.json is unchanged; otherwise it
// rebuilds the view, reading at most the per-request budget of manifests it
// has not read before.
func (s *Server) referrersOf(r *http.Request, n ref.Name, d digest.Digest) ([]refEntry, error) {
	key := n.String()
	v := s.refs.view(key)
	select {
	case v.sem <- struct{}{}:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	defer func() { <-v.sem }()
	ver, err := s.st.IndexVersionOf(n)
	if errors.Is(err, store.ErrRepositoryUnknown) {
		s.refs.drop(key, v)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !v.ready || v.version != ver {
		if err := s.buildReferrers(key, n, v); err != nil {
			if errors.Is(err, store.ErrRepositoryUnknown) {
				s.refs.drop(key, v)
				return nil, nil
			}
			return nil, err
		}
	}
	return v.bySubject[d], nil
}

// buildReferrers rebuilds v from n's current index.json. The caller holds
// v.sem.
func (s *Server) buildReferrers(key string, n ref.Name, v *refView) error {
	idx, ver, err := s.st.IndexAt(n)
	if err != nil {
		return err
	}
	v.ready = false
	entries := make(map[digest.Digest]refEntry, len(idx.Manifests))
	var readRows, readBytes int64
	whole := true
	for _, row := range idx.Manifests {
		if !manifestTypes[row.MediaType] {
			continue
		}
		if _, ok := entries[row.Digest]; ok {
			continue
		}
		if e, ok := v.entries[row.Digest]; ok && e.desc.MediaType == row.MediaType && e.desc.Size == row.Size {
			entries[row.Digest] = e
			continue
		}
		if readRows >= int64(s.refScanRows) || readBytes+max(row.Size, 0) > s.refScanBytes {
			whole = false
			continue
		}
		readRows++
		readBytes += max(row.Size, 0)
		if s.referrerRead != nil {
			s.referrerRead(row.Digest)
		}
		body, err := s.readManifestBlob(n, row)
		if err != nil {
			// Not kept: the next rebuild (the next index change) tries again.
			s.log.Warn("registry referrers scan skipped an unreadable manifest", "repository", key, "digest", row.Digest.String(), "err", err)
			continue
		}
		entries[row.Digest] = entryOf(row, body)
	}
	v.entries = entries
	var rows, bytes int64
	bySubject := map[digest.Digest][]refEntry{}
	for _, e := range entries {
		rows++
		bytes += int64(e.size)
		if e.subject != "" {
			bySubject[e.subject] = append(bySubject[e.subject], e)
		}
	}
	s.refs.account(key, v, rows, bytes)
	if !whole {
		v.bySubject = nil
		return errReferrersBusy
	}
	for _, l := range bySubject {
		slices.SortFunc(l, func(a, b refEntry) int { return strings.Compare(a.desc.Digest.String(), b.desc.Digest.String()) })
	}
	v.bySubject, v.version, v.ready = bySubject, ver, true
	return nil
}

// entryOf decodes what a manifest contributes to the view. A body that does
// not decode, or names no subject, contributes nothing but its row.
func entryOf(row ispec.Descriptor, body []byte) refEntry {
	e := refEntry{desc: ispec.Descriptor{MediaType: row.MediaType, Digest: row.Digest, Size: row.Size}}
	var doc referrerDoc
	if json.Unmarshal(body, &doc) != nil || doc.Subject == nil {
		e.size = 64
		return e
	}
	at := doc.ArtifactType
	if at == "" && doc.Config != nil {
		at = doc.Config.MediaType
	}
	e.subject = doc.Subject.Digest
	e.desc.ArtifactType, e.desc.Annotations = at, doc.Annotations
	b, err := compactJSON(e.desc)
	if err != nil {
		e.size = len(body)
	} else {
		e.size = len(b)
	}
	return e
}
