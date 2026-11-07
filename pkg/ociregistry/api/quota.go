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

// maxQuotaRebuilds is how many times one check reads the store again because
// rows were removed while it read, before it answers 503 and lets the client
// retry. A read that rows left behind would only overcount, but it is not
// installed.
const maxQuotaRebuilds = 3

// errQuotaBusy is a check whose every rebuild was overtaken by a removal.
var errQuotaBusy = errorf(http.StatusServiceUnavailable, codeUnavailable, "the registry quota is being recounted; retry")

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

// quotaCharge is one counted manifest and who holds it: stored when the store
// holds a row of it (as a rebuild read, or a PUT wrote), and holds the PUTs
// admitted under the key that have not yet answered. It is counted while
// either holds it. doneSeq is the quota's seq when a PUT last wrote it.
type quotaCharge struct {
	quotaEntry
	stored  bool
	holds   int
	doneSeq uint64
}

// quotaBlob is one layer a type's manifests name: its size and how many of
// them name it.
type quotaBlob struct {
	size int64
	refs int
}

// quotaShape is what a manifest digest's body says, cached across rebuilds
// since a digest's body never changes: its artifact type ("" for a body that is
// not an image manifest) and its layers. Only a type with a quota keeps its
// layers.
type quotaShape struct {
	artifactType string
	layers       []digest.Digest
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
// type refused for bytes it no longer holds. The rebuild reads the store
// without the lock, one at a time (a check that finds one running waits for
// it), and installs what it read under the lock only when no removal came
// while it read (gen); otherwise it reads again.
//
// A PUT is admitted under the lock before its row is written: it takes a hold
// on its key, charging the key's layers if no one counts it yet, so two PUTs
// cannot both take the same room. Its write either marks the key stored and
// drops the hold, or only drops the hold, and a key nothing holds and the store
// does not hold stops counting. A rebuild keeps every key a PUT holds, and
// every key a PUT wrote while it read (doneSeq), so a manifest the read missed
// is never left out.
//
// mu guards every field below limits; cond waits on mu for a rebuild.
type quota struct {
	limits map[string]int64

	mu       sync.Mutex
	cond     *sync.Cond
	built    bool
	building bool
	gen      uint64 // advanced by each removal
	seq      uint64 // advanced by each write
	charges  map[quotaKey]*quotaCharge
	blobs    map[string]map[digest.Digest]*quotaBlob
	usage    map[string]int64
	shapes   map[digest.Digest]quotaShape
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
	q := &quota{limits: l, charges: map[quotaKey]*quotaCharge{}, blobs: map[string]map[digest.Digest]*quotaBlob{},
		usage: map[string]int64{}, shapes: map[digest.Digest]quotaShape{}}
	q.cond = sync.NewCond(&q.mu)
	return q, nil
}

// invalidate has the next check rebuild the count from the store, and a
// rebuild reading now read again.
func (q *quota) invalidate() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.built = false
	q.gen++
}

// charge counts e's layers against its type. The caller holds mu.
func (q *quota) charge(e quotaEntry) {
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

// uncharge undoes charge. The caller holds mu.
func (q *quota) uncharge(e quotaEntry) {
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

// drop stops counting k when nothing holds it. The caller holds mu.
func (q *quota) drop(k quotaKey) {
	c := q.charges[k]
	if c == nil || c.stored || c.holds > 0 {
		return
	}
	delete(q.charges, k)
	q.uncharge(c.quotaEntry)
}

// grows returns the bytes e would add to its type's usage. The caller holds mu.
func (q *quota) grows(e quotaEntry) int64 {
	var n int64
	bs := q.blobs[e.artifactType]
	for d, size := range e.layers {
		if bs[d] == nil {
			n += size
		}
	}
	return n
}

// hold admits one PUT of k, or refuses it with the quota's error when k is not
// counted and its layers would take the type past limit. The caller holds mu.
func (q *quota) hold(k quotaKey, e quotaEntry, limit int64) error {
	if c := q.charges[k]; c != nil {
		c.holds++
		return nil
	}
	if q.usage[e.artifactType]+q.grows(e) > limit {
		ae := errorf(http.StatusForbidden, codeDenied, msgQuotaExceeded)
		ae.detail = map[string]string{"artifactType": e.artifactType, "quota": strconv.FormatInt(limit, 10)}
		return ae
	}
	q.charges[k] = &quotaCharge{quotaEntry: e, holds: 1}
	q.charge(e)
	return nil
}

// unhold ends one PUT's hold on k; wrote says its row was written.
func (q *quota) unhold(k quotaKey, wrote bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	c := q.charges[k]
	if c == nil {
		return
	}
	c.holds--
	if wrote {
		q.seq++
		c.stored, c.doneSeq = true, q.seq
	}
	q.drop(k)
}

// admitQuota admits a PUT of the manifest d in n, of type artifactType naming
// layers, or refuses it when that would take the type past its quota. The
// returned finish ends the PUT's hold exactly once: finish(true) once its row is
// written, finish(false) when it is not. A type without a quota admits at no
// cost and finish does nothing.
func (s *Server) admitQuota(n ref.Name, d digest.Digest, artifactType string, layers []digest.Digest) (finish func(wrote bool), err error) {
	noop := func(bool) {}
	q := s.quota
	if q == nil {
		return noop, nil
	}
	limit, ok := q.limits[artifactType]
	if !ok {
		return noop, nil
	}
	e := quotaEntry{artifactType: artifactType, layers: make(map[digest.Digest]int64, len(layers))}
	for _, l := range layers {
		size, err := s.st.StatBlob(n, l)
		if uncountable(err) {
			continue // a non-distributable layer the store does not hold
		}
		if err != nil {
			return nil, err
		}
		e.layers[l] = size
	}
	k := quotaKey{repo: n.String(), d: d}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := s.buildQuota(); err != nil {
		return nil, err
	}
	if err := q.hold(k, e, limit); err != nil {
		return nil, err
	}
	var once sync.Once
	return func(wrote bool) { once.Do(func() { q.unhold(k, wrote) }) }, nil
}

// quotaRead is one rebuild's reading of the store.
type quotaRead struct {
	entries map[quotaKey]quotaEntry
	shapes  map[digest.Digest]quotaShape
}

// buildQuota makes the count current. The caller holds s.quota.mu, which it
// releases while the store is read and holds again on return. Only one
// rebuild runs at a time; a caller that finds one running waits for it.
func (s *Server) buildQuota() error {
	q := s.quota
	for tries := 0; !q.built; {
		if q.building {
			q.cond.Wait()
			continue
		}
		if tries == maxQuotaRebuilds {
			return errQuotaBusy
		}
		tries++
		q.building = true
		gen, seq, shapes := q.gen, q.seq, q.shapes
		q.mu.Unlock()
		read, err := s.readQuota(shapes)
		if s.quotaRead != nil {
			s.quotaRead()
		}
		q.mu.Lock()
		q.building = false
		q.cond.Broadcast()
		if err != nil {
			return err
		}
		if q.gen != gen {
			continue // a removal came while the store was read
		}
		q.install(read, seq)
	}
	return nil
}

// install replaces the count with read, keeping every key a PUT holds and every
// key a PUT wrote after seq, which read may have missed. The caller holds mu.
func (q *quota) install(read quotaRead, seq uint64) {
	old := q.charges
	q.charges = make(map[quotaKey]*quotaCharge, len(read.entries))
	q.blobs = map[string]map[digest.Digest]*quotaBlob{}
	q.usage = map[string]int64{}
	for k, e := range read.entries {
		q.charges[k] = &quotaCharge{quotaEntry: e, stored: true}
		q.charge(e)
	}
	for k, c := range old {
		wrote := c.stored && c.doneSeq > seq
		if c.holds == 0 && !wrote {
			continue
		}
		if n := q.charges[k]; n != nil {
			n.holds, n.doneSeq = c.holds, c.doneSeq
			continue
		}
		q.charges[k] = &quotaCharge{quotaEntry: c.quotaEntry, stored: wrote, holds: c.holds, doneSeq: c.doneSeq}
		q.charge(c.quotaEntry)
	}
	q.shapes = read.shapes
	q.built = true
}

// readQuota reads every repository's rows and what each manifest of a type
// with a quota counts. A manifest whose shape the last read cached is not
// read again, and one of a type without a quota is not touched beyond that. A
// repository whose index is damaged, and a manifest whose body is gone,
// damaged or not a manifest, count nothing and are logged; any other read
// error fails the check, and the next one tries again. It holds no lock.
func (s *Server) readQuota(cached map[digest.Digest]quotaShape) (quotaRead, error) {
	out := quotaRead{entries: map[quotaKey]quotaEntry{}, shapes: map[digest.Digest]quotaShape{}}
	repos, err := s.st.Repositories()
	if err != nil {
		return out, fmt.Errorf("count the registry quota: %w", err)
	}
	for _, n := range repos {
		idx, err := s.st.Index(n)
		if errors.Is(err, store.ErrRepositoryUnknown) {
			continue
		}
		if damagedIndex(err) {
			s.log.Warn("registry quota: a repository's index cannot be read; its manifests count nothing", "repository", n.String(), "err", err)
			continue
		}
		if err != nil {
			return out, fmt.Errorf("count the registry quota: %w", err)
		}
		seen := map[digest.Digest]bool{}
		for _, row := range idx.Manifests {
			if seen[row.Digest] || isIndexType(row.MediaType) {
				continue
			}
			seen[row.Digest] = true
			sh, ok := cached[row.Digest]
			if !ok {
				if sh, ok, err = s.quotaShapeOf(n, row); err != nil {
					return out, fmt.Errorf("count the registry quota: %w", err)
				}
				if !ok {
					s.log.Warn("registry quota: a manifest cannot be read; it counts nothing", "repository", n.String(), "digest", row.Digest.String())
					continue
				}
			}
			out.shapes[row.Digest] = sh
			if _, limited := s.quota.limits[sh.artifactType]; !limited {
				continue
			}
			e := quotaEntry{artifactType: sh.artifactType, layers: make(map[digest.Digest]int64, len(sh.layers))}
			for _, l := range sh.layers {
				size, err := s.st.StatBlob(n, l)
				if uncountable(err) {
					continue
				}
				if err != nil {
					return out, fmt.Errorf("count the registry quota: %w", err)
				}
				e.layers[l] = size
			}
			out.entries[quotaKey{repo: n.String(), d: row.Digest}] = e
		}
	}
	return out, nil
}

// quotaShapeOf reads the manifest row names in n and returns its shape, or
// false when its body is gone or damaged, which may change with a repair and so
// is not cached. A body that is not an image manifest has no type.
func (s *Server) quotaShapeOf(n ref.Name, row ispec.Descriptor) (quotaShape, bool, error) {
	body, err := s.readManifestBlob(n, row)
	if uncountable(err) {
		return quotaShape{}, false, nil
	}
	if err != nil {
		return quotaShape{}, false, err
	}
	var m ispec.Manifest
	if json.Unmarshal(body, &m) != nil {
		return quotaShape{}, true, nil
	}
	sh := quotaShape{artifactType: artifactv1.ArtifactType(m.ArtifactType, m.Config.MediaType)}
	if _, limited := s.quota.limits[sh.artifactType]; limited {
		for _, l := range m.Layers {
			sh.layers = append(sh.layers, l.Digest)
		}
	}
	return sh, true, nil
}

// uncountable reports whether err is a manifest or blob that stays unreadable
// until someone repairs the store, which counts nothing, rather than a read
// that may pass.
func uncountable(err error) bool {
	return errors.Is(err, store.ErrBlobUnknown) || errors.Is(err, store.ErrStoreCorrupt) || errors.Is(err, store.ErrNotRegular) ||
		errors.Is(err, ref.ErrSymlink) || errors.Is(err, ref.ErrInvalidDigest) || errors.Is(err, errManifestSize)
}

// damagedIndex reports whether err is an index.json that stays unreadable
// until someone repairs it: not a regular file, a symlink, or not JSON.
func damagedIndex(err error) bool {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	return uncountable(err) || errors.As(err, &syn) || errors.As(err, &typ)
}

// InvalidateQuota tells the server that rows were removed behind its back, by
// a garbage-collection sweep, so the quota's count is rebuilt from the store at
// the next manifest PUT that it limits. It does nothing without a quota.
func (s *Server) InvalidateQuota() { s.quota.invalidate() }
