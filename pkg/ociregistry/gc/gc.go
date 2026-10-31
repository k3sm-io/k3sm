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

package gc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// MarkerName is the file in the state directory a first, report-only sweep
// writes. Its presence lets later sweeps delete.
const MarkerName = "gc-ran"

// Sentinel errors.
var (
	// ErrTooSoon is a sweep within one grace period of the collector's start.
	ErrTooSoon = errors.New("gc: within one grace period of start")
	// ErrMassDelete is a repository sweep stopped because it would delete
	// more than half of the repository's blobs.
	ErrMassDelete = errors.New("gc: sweep would delete more than half of a repository's blobs")
	// ErrUnreadable is a repository sweep stopped because a manifest it
	// must follow is missing or does not parse.
	ErrUnreadable = errors.New("gc: manifest unreadable")
)

// Kind is the kind of object a sweep reaps.
type Kind string

// The object kinds.
const (
	KindManifest   Kind = "manifest"
	KindBlob       Kind = "blob"
	KindUpload     Kind = "upload"
	KindTemp       Kind = "temp"
	KindRepository Kind = "repository"
)

// Object is one reaped (or, in a report-only sweep, reapable) object.
type Object struct {
	Repository string
	Kind       Kind
	Name       string
	Reason     string
}

// Report is what a sweep did.
type Report struct {
	// ReportOnly is a first sweep: Objects lists what it would have reaped,
	// and nothing was deleted.
	ReportOnly bool
	Objects    []Object
	// Stopped lists the repositories whose sweep stopped on a brake.
	Stopped []string
}

// Count returns the number of objects of kind k in the report.
func (r Report) Count(k Kind) int {
	n := 0
	for _, o := range r.Objects {
		if o.Kind == k {
			n++
		}
	}
	return n
}

// Options configure a Collector.
type Options struct {
	// Grace is how old an object must be before it is reaped, and how long
	// after the collector's start no sweep runs. It must be positive.
	Grace time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Log receives a record per reaped object and per stopped repository
	// (slog.Default when nil).
	Log *slog.Logger
}

// Collector sweeps one store. One Sweep runs at a time.
type Collector struct {
	s     *store.Store
	grace time.Duration
	now   func() time.Time
	log   *slog.Logger
	start time.Time

	mu sync.Mutex // serialises Sweep
	// afterMark, when set, runs between a repository's mark and its locked
	// sweep (a seam for tests that interleave a push).
	afterMark func(ref.Name)
	// fault, when set, runs at each faultPoint in apply; an error stops the
	// sweep there, as a crash would (a seam for crash tests). i counts the
	// blobs removed so far at faultBlob.
	fault func(at faultPoint, i int) error
}

// faultPoint is a place in apply where the fault seam runs.
type faultPoint int

const (
	faultRows faultPoint = iota // after SetRows
	faultBlob                   // after each RemoveBlob
)

func (c *Collector) inject(at faultPoint, i int) error {
	if c.fault == nil {
		return nil
	}
	return c.fault(at, i)
}

// New returns a collector over s. Its start time, from which the first grace
// period counts, is now.
func New(s *store.Store, o Options) (*Collector, error) {
	if o.Grace <= 0 {
		return nil, fmt.Errorf("gc: grace %s must be positive", o.Grace)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Collector{s: s, grace: o.Grace, now: o.Now, log: o.Log, start: o.Now()}, nil
}

// Sweep runs one collection over every repository. A repository stopped by
// a brake or an error is skipped and named in the returned error; the others
// are still swept. A report-only first sweep writes the marker unless a
// repository failed for a reason other than a brake.
func (c *Collector) Sweep(ctx context.Context) (Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); now.Before(c.start.Add(c.grace)) {
		return Report{}, fmt.Errorf("%w: started %s, grace %s", ErrTooSoon, c.start.Format(time.RFC3339), c.grace)
	}
	marker := filepath.Join(c.s.StateDir(), MarkerName)
	ran, err := markerExists(marker)
	if err != nil {
		return Report{}, err
	}
	rep := Report{ReportOnly: !ran}
	repos, err := c.s.Repositories()
	if err != nil {
		return rep, err
	}
	var errs []error
	hard := false
	for _, n := range repos {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		objs, err := c.sweepRepo(ctx, n, rep.ReportOnly)
		rep.Objects = append(rep.Objects, objs...)
		if err != nil {
			if errors.Is(err, ErrMassDelete) {
				rep.Stopped = append(rep.Stopped, n.String())
			} else {
				hard = true
			}
			errs = append(errs, fmt.Errorf("gc %s: %w", n, err))
		}
	}
	if rep.ReportOnly && !hard {
		if err := writeMarker(marker, c.now()); err != nil {
			errs = append(errs, err)
		}
	}
	return rep, errors.Join(errs...)
}

// sweepRepo marks n without the lock and, unless reportOnly, deletes what a
// second, locked pass agrees on.
func (c *Collector) sweepRepo(ctx context.Context, n ref.Name, reportOnly bool) ([]Object, error) {
	p, idx, cont, err := c.mark(n, c.now().Add(-c.grace))
	if err != nil {
		return nil, err
	}
	if p.empty() {
		return nil, nil
	}
	if reportOnly {
		if err := c.brake(n, p, idx, cont); err != nil {
			return nil, err
		}
		objs := p.objects(n)
		for _, o := range objs {
			c.log.Info("registry gc: would reap", "repository", o.Repository, "kind", o.Kind, "name", o.Name, "reason", o.Reason)
		}
		return objs, nil
	}
	if c.afterMark != nil {
		c.afterMark(n)
	}
	var objs []Object
	err = c.s.WithLock(ctx, n, func(l *store.Locked) error {
		cutoff := c.now().Add(-c.grace)
		idx, err := l.Index()
		if err != nil {
			return err
		}
		cont, err := l.Contents()
		if err != nil {
			return err
		}
		q, err := makePlan(idx, cont, cutoff, c.reader(n))
		if err != nil {
			return err
		}
		final := p.intersect(q)
		if err := c.brake(n, final, idx, cont); err != nil {
			return err
		}
		objs, err = c.apply(l, n, final, idx, cutoff)
		return err
	})
	return objs, err
}

// mark plans n's sweep from an unlocked snapshot.
func (c *Collector) mark(n ref.Name, cutoff time.Time) (plan, ispec.Index, store.Contents, error) {
	idx, err := c.s.Index(n)
	if err != nil {
		return plan{}, ispec.Index{}, store.Contents{}, err
	}
	cont, err := c.s.Contents(n)
	if err != nil {
		return plan{}, ispec.Index{}, store.Contents{}, err
	}
	p, err := makePlan(idx, cont, cutoff, c.reader(n))
	return p, idx, cont, err
}

// brake applies the half-repository rule to a plan over idx and cont: a plan
// that would reap more than half of the repository's blobs stops, unless it
// empties the repository.
//
// A plan empties the repository when it leaves no row (every row, if there
// were any, is one it reaps) and every blob it reaps predates index.json's
// last write. index.json is written when a repository's layout is made, before
// its first blob, and afterwards only when its rows change. So an index
// written after every reaped blob means the rows that named those blobs were
// removed (by a delete, or by this plan, or by an earlier sweep that stopped
// after its row write), and the blobs are what a removed image left. A first
// push in progress has an index older than its blobs, so its committed but
// not yet named blobs stay under the brake however old they are. A blob
// written at the same instant as index.json counts as newer: the brake holds.
func (c *Collector) brake(n ref.Name, p plan, idx ispec.Index, cont store.Contents) error {
	if 2*len(p.blobs) <= len(cont.Blobs) || emptyingRule(p, idx, cont) {
		return nil
	}
	c.log.Error("registry gc: sweep stopped", "repository", n.String(), "reap", len(p.blobs), "blobs", len(cont.Blobs),
		"reason", "more than half of the repository's blobs")
	return fmt.Errorf("%w: %d of %d", ErrMassDelete, len(p.blobs), len(cont.Blobs))
}

// emptyingRule is the rule brake applies (a seam for the test that proves
// the brake's tests fail without it).
var emptyingRule = emptying

// emptying reports whether p empties the repository, by the rule brake
// documents.
func emptying(p plan, idx ispec.Index, cont store.Contents) bool {
	for _, r := range idx.Manifests {
		if _, tagged := r.Annotations[ispec.AnnotationRefName]; tagged || !p.rows[r.Digest] {
			return false
		}
	}
	for _, b := range cont.Blobs {
		if p.blobs[b.Digest] && !b.ModTime.Before(cont.IndexModTime) {
			return false
		}
	}
	return true
}

// apply deletes a plan under the lock: rows first, so index.json never names
// a blob the sweep removed, then blobs, sessions, temp links and, for an
// empty repository, the layout.
func (c *Collector) apply(l *store.Locked, n ref.Name, p plan, idx ispec.Index, cutoff time.Time) ([]Object, error) {
	var objs []Object
	reaped := func(k Kind, name, reason string) {
		o := Object{Repository: n.String(), Kind: k, Name: name, Reason: reason}
		objs = append(objs, o)
		c.log.Info("registry gc: reaped", "repository", o.Repository, "kind", o.Kind, "name", o.Name, "reason", o.Reason)
	}
	rows := idx.Manifests
	if len(p.rows) > 0 {
		rows = slices.DeleteFunc(slices.Clone(rows), func(r ispec.Descriptor) bool {
			_, tagged := r.Annotations[ispec.AnnotationRefName]
			return !tagged && p.rows[r.Digest]
		})
		if err := l.SetRows(rows); err != nil {
			return objs, err
		}
		for _, d := range sortedKeys(p.rows) {
			reaped(KindManifest, d.String(), reasonManifest)
		}
		if err := c.inject(faultRows, 0); err != nil {
			return objs, err
		}
	}
	for i, d := range sortedKeys(p.blobs) {
		if err := l.RemoveBlob(d); err != nil {
			return objs, err
		}
		reaped(KindBlob, d.String(), reasonBlob)
		if err := c.inject(faultBlob, i+1); err != nil {
			return objs, err
		}
	}
	for _, id := range sortedKeys(p.sessions) {
		v, err := l.ReapSession(id, cutoff)
		if err != nil {
			return objs, err
		}
		switch v {
		case store.SessionCommitted:
			reaped(KindUpload, id, reasonCommitted)
		case store.SessionIdle:
			reaped(KindUpload, id, reasonIdle)
		}
	}
	for _, k := range sortedKeys(p.temps) {
		t := p.temps[k]
		if err := l.RemoveTemp(t); err != nil && !errors.Is(err, os.ErrNotExist) {
			return objs, err
		}
		reaped(KindTemp, k, reasonTemp)
	}
	if p.emptyRepo && len(rows) == 0 {
		ok, err := l.RemoveLayout(cutoff)
		if err != nil {
			return objs, err
		}
		if ok {
			reaped(KindRepository, n.String(), reasonEmpty)
		}
	}
	return objs, nil
}

// The reasons a reaped object's record carries.
const (
	reasonManifest  = "untagged, unreferenced, past the grace"
	reasonBlob      = "unreferenced, past the grace"
	reasonIdle      = "upload idle past the grace"
	reasonCommitted = "upload committed but not removed"
	reasonTemp      = "temp link left by an interrupted blob replacement"
	reasonEmpty     = "empty repository"
)

// reader returns a function that reads manifest body d of n, verified
// against d and bounded by the manifest size cap.
func (c *Collector) reader(n ref.Name) func(digest.Digest) ([]byte, error) {
	return func(d digest.Digest) ([]byte, error) {
		f, err := c.s.OpenBlob(n, d)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, store.MaxManifestSize+1))
		if err != nil {
			return nil, err
		}
		if len(b) > store.MaxManifestSize {
			return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrUnreadable, d, store.MaxManifestSize)
		}
		if d.Algorithm().FromBytes(b) != d {
			return nil, fmt.Errorf("%w: %s does not hash to its name", ErrUnreadable, d)
		}
		return b, nil
	}
}

// plan is what one pass would reap.
type plan struct {
	rows      map[digest.Digest]bool // untagged index rows
	blobs     map[digest.Digest]bool
	sessions  map[string]bool
	committed map[string]bool       // the sessions with a second link
	temps     map[string]store.Temp // by <algorithm>/<name>
	emptyRepo bool
}

func (p plan) empty() bool {
	return len(p.rows) == 0 && len(p.blobs) == 0 && len(p.sessions) == 0 && len(p.temps) == 0 && !p.emptyRepo
}

// intersect keeps what both p and q would reap.
func (p plan) intersect(q plan) plan {
	out := plan{
		rows:      both(p.rows, q.rows),
		blobs:     both(p.blobs, q.blobs),
		sessions:  both(p.sessions, q.sessions),
		committed: both(p.committed, q.committed),
		temps:     map[string]store.Temp{},
		emptyRepo: p.emptyRepo && q.emptyRepo,
	}
	for k, t := range q.temps {
		if _, ok := p.temps[k]; ok {
			out.temps[k] = t
		}
	}
	return out
}

func both[K comparable](a, b map[K]bool) map[K]bool {
	out := map[K]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	ks := make([]K, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// objects lists a plan as report objects.
func (p plan) objects(n ref.Name) []Object {
	var out []Object
	add := func(k Kind, name, reason string) {
		out = append(out, Object{Repository: n.String(), Kind: k, Name: name, Reason: reason})
	}
	for _, d := range sortedKeys(p.rows) {
		add(KindManifest, d.String(), reasonManifest)
	}
	for _, d := range sortedKeys(p.blobs) {
		add(KindBlob, d.String(), reasonBlob)
	}
	for _, id := range sortedKeys(p.sessions) {
		if p.committed[id] {
			add(KindUpload, id, reasonCommitted)
		} else {
			add(KindUpload, id, reasonIdle)
		}
	}
	for _, k := range sortedKeys(p.temps) {
		add(KindTemp, k, reasonTemp)
	}
	if p.emptyRepo {
		add(KindRepository, n.String(), reasonEmpty)
	}
	return out
}

// The manifest media types the registry accepts at PUT, and so the only ones
// the collector knows how to follow.
const (
	mediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// refs is the part of a manifest or index body that names other content:
// image manifests (OCI and Docker v2 schema2) name a config and layers,
// indexes and manifest lists name manifests, and either may name a subject.
type refs struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType"`
	Config        *ispec.Descriptor  `json:"config"`
	Layers        []ispec.Descriptor `json:"layers"`
	Manifests     []ispec.Descriptor `json:"manifests"`
	Subject       *ispec.Descriptor  `json:"subject"`
}

// parseRefs reads what the manifest body b, stored as d, references. It
// fails closed: a body it cannot be sure it has read in full is ErrUnreadable,
// so the sweep stops for that repository instead of reaping what the body
// may still name. It accepts schemaVersion 2 and the OCI and Docker v2 image
// manifest, index and manifest list media types. A body without a mediaType
// (optional in OCI) is an image manifest when it has a config and an index
// when it has a manifests array; anything else, Docker schema1 included, is
// unreadable. An image manifest without a config is unreadable too.
func parseRefs(d digest.Digest, b []byte) (refs, error) {
	var r refs
	if err := json.Unmarshal(b, &r); err != nil {
		return refs{}, fmt.Errorf("%w: %s: %v", ErrUnreadable, d, err)
	}
	if r.SchemaVersion != 2 {
		return refs{}, fmt.Errorf("%w: %s: schemaVersion %d, want 2", ErrUnreadable, d, r.SchemaVersion)
	}
	switch r.MediaType {
	case ispec.MediaTypeImageManifest, mediaTypeDockerManifest:
		if r.Config == nil {
			return refs{}, fmt.Errorf("%w: %s: image manifest without a config", ErrUnreadable, d)
		}
	case ispec.MediaTypeImageIndex, mediaTypeDockerManifestList:
	case "":
		if r.Config == nil && r.Manifests == nil {
			return refs{}, fmt.Errorf("%w: %s: no mediaType, and neither a config nor a manifests array", ErrUnreadable, d)
		}
	default:
		return refs{}, fmt.Errorf("%w: %s: unknown mediaType %q", ErrUnreadable, d, r.MediaType)
	}
	return r, nil
}

// makePlan applies the retention rules to one repository's index and
// contents, at cutoff (an object is past the grace when its mtime is at or
// before cutoff):
//
//   - a tagged row is kept; so is an untagged row whose manifest is younger
//     than the grace, carries a subject, or has no body to judge by;
//   - every manifest a kept index names is kept, transitively;
//   - every other untagged row is reaped;
//   - a blob is kept when a kept manifest is it or references it, or when it
//     is younger than the grace; the rest are reaped;
//   - an upload session is reaped when its inode has a second link or it is
//     past the grace (the locked pass decides which, under the session's lock);
//   - every temp link is reaped;
//   - the repository is empty when nothing would remain.
//
// A kept manifest whose body is missing (other than an index child, which the
// spec does not require) or does not parse fails the plan.
func makePlan(idx ispec.Index, cont store.Contents, cutoff time.Time, read func(digest.Digest) ([]byte, error)) (plan, error) {
	mtime := make(map[digest.Digest]time.Time, len(cont.Blobs))
	for _, b := range cont.Blobs {
		mtime[b.Digest] = b.ModTime
	}
	old := func(t time.Time) bool { return !t.After(cutoff) }

	type item struct {
		d        digest.Digest
		required bool // a missing body fails the plan
	}
	var queue []item
	candidates := map[digest.Digest]bool{}
	for _, r := range idx.Manifests {
		if _, tagged := r.Annotations[ispec.AnnotationRefName]; tagged {
			queue = append(queue, item{r.Digest, true})
			continue
		}
		t, ok := mtime[r.Digest]
		if !ok || !old(t) {
			queue = append(queue, item{r.Digest, false})
			continue
		}
		b, err := read(r.Digest)
		if err != nil {
			return plan{}, fmt.Errorf("%w: untagged %s: %v", ErrUnreadable, r.Digest, err)
		}
		m, err := parseRefs(r.Digest, b)
		if err != nil {
			return plan{}, err
		}
		if m.Subject != nil {
			queue = append(queue, item{r.Digest, true})
			continue
		}
		candidates[r.Digest] = true
	}

	kept := map[digest.Digest]bool{}       // manifests reachable from a kept row
	referenced := map[digest.Digest]bool{} // blobs a kept manifest is or names
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if kept[it.d] {
			continue
		}
		kept[it.d] = true
		referenced[it.d] = true
		b, err := read(it.d)
		if errors.Is(err, store.ErrBlobUnknown) && !it.required {
			continue
		}
		if err != nil {
			return plan{}, fmt.Errorf("%w: %s: %v", ErrUnreadable, it.d, err)
		}
		m, err := parseRefs(it.d, b)
		if err != nil {
			return plan{}, err
		}
		if m.Config != nil {
			referenced[m.Config.Digest] = true
		}
		for _, l := range m.Layers {
			referenced[l.Digest] = true
		}
		for _, ch := range m.Manifests {
			referenced[ch.Digest] = true
			queue = append(queue, item{ch.Digest, false})
		}
	}

	p := plan{rows: map[digest.Digest]bool{}, blobs: map[digest.Digest]bool{}, sessions: map[string]bool{}, committed: map[string]bool{}, temps: map[string]store.Temp{}}
	remainingRows := 0
	for _, r := range idx.Manifests {
		if _, tagged := r.Annotations[ispec.AnnotationRefName]; !tagged && candidates[r.Digest] && !kept[r.Digest] {
			p.rows[r.Digest] = true
			continue
		}
		remainingRows++
	}
	for _, b := range cont.Blobs {
		if !referenced[b.Digest] && old(b.ModTime) {
			p.blobs[b.Digest] = true
		}
	}
	for _, s := range cont.Sessions {
		if s.Links > 1 {
			p.committed[s.ID] = true
		}
		if s.Links > 1 || old(s.ModTime) {
			p.sessions[s.ID] = true
		}
	}
	for _, t := range cont.Temps {
		p.temps[t.Algorithm+"/"+t.Name] = t
	}
	p.emptyRepo = remainingRows == 0 && len(p.blobs) == len(cont.Blobs) &&
		len(p.sessions) == len(cont.Sessions) && cont.Unknown == 0 && old(cont.IndexModTime)
	return p, nil
}

func markerExists(p string) (bool, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("gc marker: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("gc marker %s is not a regular file", p)
	}
	return true, nil
}

// writeMarker records that a report-only sweep ran, durably.
func writeMarker(p string, now time.Time) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("write gc marker: %w", err)
	}
	_, werr := f.WriteString(now.UTC().Format(time.RFC3339) + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("write gc marker: %w", werr)
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
