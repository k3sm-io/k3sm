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
	// referrersScanRows and referrersScanBytes bound what one referrers
	// request reads: at most 4,096 manifests it has not read before, and no
	// further manifest once 64 MiB of manifest bytes have been read (so a
	// request reads at most 64 MiB plus one 4 MiB manifest). A repository of
	// up to 4,096 manifests totalling up to 64 MiB (sixteen at the 4 MiB
	// manifest maximum, or 4,096 of 16 KiB) is read whole by its first
	// request. A larger one is read over several requests the first time:
	// each keeps what it read and answers 429 with Retry-After until the view
	// is whole; after that only manifests new to the index are read.
	referrersScanRows  = 4096
	referrersScanBytes = 64 << 20
	// referrersBuilds is the most views built at once across repositories;
	// a request that needs a build while all are in use answers 429.
	referrersBuilds = 4
	// referrersPage is the default and the largest page of one referrers
	// answer, and referrersPageBytes the encoded descriptor bytes a page
	// stops at (a page always carries at least one descriptor).
	referrersPage      = 1000
	referrersPageBytes = 4 << 20
	// maxArtifactTypes is the most artifactType filter values a request may
	// name.
	maxArtifactTypes = 8
	// referrerCacheViews, referrerCacheRows and referrerCacheBytes bound the
	// cache over all repositories; past any of them the least recently used
	// whole views are dropped. A view being built is never dropped. A partly
	// read view is dropped first only once partly read views hold more than
	// referrerPartialRows entries, so touching many other repositories cannot
	// throw away a large repository's progress; otherwise it is dropped only
	// when no whole view is left to drop, so every bound holds over partly
	// read views too.
	referrerCacheViews  = 1024
	referrerCacheRows   = 1 << 18
	referrerCacheBytes  = 64 << 20
	referrerPartialRows = 1 << 17
)

// errReferrersBusy is a referrers request that used its read budget before the
// repository's view was whole, met a read error worth retrying, or found every
// build slot in use (429; the next request carries on).
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
//
// An unreadable entry is a manifest whose blob is missing, is not a regular
// file, or does not match its row, or whose row has a size no manifest may
// have: it contributes nothing and is not read again while index.json is
// unchanged. fileState marks the first three, which a later write to the
// blob can cure, so they are read again (against the read budget) once
// index.json changes; a row's size cannot change under its digest, so an
// out-of-bounds row is never read again while a row names it.
type refEntry struct {
	subject    digest.Digest
	desc       ispec.Descriptor
	size       int
	unreadable bool
	fileState  bool
}

// refView is the referrers view of one repository.
type refView struct {
	// sem is held while the view is checked or rebuilt.
	sem chan struct{}
	// Guarded by sem: the index version the view was last built at (whole or
	// partly), whether that build was whole, the entries by manifest digest,
	// and the referrers by subject sorted by digest (each slice is never
	// changed once published).
	version   store.IndexVersion
	ready     bool
	entries   map[digest.Digest]refEntry
	bySubject map[digest.Digest][]refEntry
	// Guarded by referrerCache.mu: the last use, the cost last accounted,
	// whether a build is running, and whether the view is only partly read.
	used              uint64
	rows, bytes       int64
	building, partial bool
}

// referrerCache holds the views. Lock order: a view's sem, then mu.
type referrerCache struct {
	mu          sync.Mutex
	tick        uint64
	views       map[string]*refView
	rows        int64
	bytes       int64
	partialRows int64
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
		c.remove(key, v)
	}
}

// remove deletes v and its cost. The caller holds mu.
func (c *referrerCache) remove(key string, v *refView) {
	delete(c.views, key)
	c.rows -= v.rows
	c.bytes -= v.bytes
	if v.partial {
		c.partialRows -= v.rows
	}
}

// building marks v as being built, which pins it against eviction.
func (c *referrerCache) building(v *refView, on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v.building = on
}

// account records v's new cost and whether it is partly read, then drops the
// least recently used evictable views until the cache is within its bounds.
func (c *referrerCache) account(key string, v *refView, rows, bytes int64, partial bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.views[key] != v {
		return // dropped (its repository went away)
	}
	if v.partial {
		c.partialRows -= v.rows
	}
	c.rows += rows - v.rows
	c.bytes += bytes - v.bytes
	v.rows, v.bytes, v.partial = rows, bytes, partial
	if partial {
		c.partialRows += rows
	}
	for len(c.views) > referrerCacheViews || c.rows > referrerCacheRows || c.bytes > referrerCacheBytes || c.partialRows > referrerPartialRows {
		partialOver := c.partialRows > referrerPartialRows
		// The least recently used evictable view, preferring a whole one
		// unless partly read views are over their own bound.
		var oldKey, partKey string
		var old, part *refView
		for k, o := range c.views {
			if o == v || o.building {
				continue
			}
			if o.partial && !partialOver {
				if part == nil || o.used < part.used {
					partKey, part = k, o
				}
				continue
			}
			if old == nil || o.used < old.used {
				oldKey, old = k, o
			}
		}
		if old == nil {
			oldKey, old = partKey, part
		}
		if old == nil {
			return // only v and views being built are left; each is bounded by its index and the read budget
		}
		c.remove(oldKey, old)
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
	if v.ready && v.version == ver {
		return v.bySubject[d], nil
	}
	select {
	case s.refBuilds <- struct{}{}:
	default:
		return nil, errReferrersBusy
	}
	defer func() { <-s.refBuilds }()
	s.refs.building(v, true)
	defer s.refs.building(v, false)
	if err := s.buildReferrers(key, n, v); err != nil {
		if errors.Is(err, store.ErrRepositoryUnknown) {
			s.refs.drop(key, v)
			return nil, nil
		}
		return nil, err
	}
	return v.bySubject[d], nil
}

// permanentReadError reports whether a manifest read failed for a reason that
// will not change while the row names the same digest.
func permanentReadError(err error) bool {
	return errors.Is(err, store.ErrBlobUnknown) || errors.Is(err, store.ErrDigestMismatch) ||
		errors.Is(err, store.ErrNotRegular) || errors.Is(err, ref.ErrSymlink) || errors.Is(err, errManifestSize)
}

// buildReferrers rebuilds v from n's current index.json. The caller holds
// v.sem and a build slot.
func (s *Server) buildReferrers(key string, n ref.Name, v *refView) error {
	idx, ver, err := s.st.IndexAt(n)
	if err != nil {
		return err
	}
	// A changed index re-reads the file-state negatives: their blobs may
	// have been written since.
	reread := v.version != ver
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
		if e, ok := v.entries[row.Digest]; ok && e.desc.MediaType == row.MediaType && e.desc.Size == row.Size && !(reread && e.unreadable && e.fileState) {
			entries[row.Digest] = e
			continue
		}
		if readRows >= int64(s.refScanRows) || readBytes >= s.refScanBytes {
			whole = false
			continue
		}
		readRows++
		if s.referrerRead != nil {
			s.referrerRead(row.Digest)
		}
		body, err := s.readManifestBlob(n, row)
		if err != nil {
			if !permanentReadError(err) {
				// Worth retrying: the view is not whole, and the
				// request answers busy rather than omit the manifest.
				s.log.Warn("registry referrers scan could not read a manifest; will retry", "repository", key, "digest", row.Digest.String(), "err", err)
				whole = false
				continue
			}
			s.log.Warn("registry referrers scan skipped an unreadable manifest", "repository", key, "digest", row.Digest.String(), "err", err)
			entries[row.Digest] = refEntry{desc: ispec.Descriptor{MediaType: row.MediaType, Digest: row.Digest, Size: row.Size}, size: 64, unreadable: true, fileState: !errors.Is(err, errManifestSize)}
			continue
		}
		readBytes += int64(len(body))
		entries[row.Digest] = entryOf(row, body)
	}
	v.entries, v.version = entries, ver
	var rows, bytes int64
	bySubject := map[digest.Digest][]refEntry{}
	for _, e := range entries {
		rows++
		bytes += int64(e.size)
		if e.subject != "" && !e.unreadable {
			bySubject[e.subject] = append(bySubject[e.subject], e)
		}
	}
	s.refs.account(key, v, rows, bytes, !whole)
	if !whole {
		v.bySubject = nil
		return errReferrersBusy
	}
	for _, l := range bySubject {
		slices.SortFunc(l, func(a, b refEntry) int { return strings.Compare(a.desc.Digest.String(), b.desc.Digest.String()) })
	}
	v.bySubject, v.ready = bySubject, true
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
