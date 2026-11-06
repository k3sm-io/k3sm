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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// MarkerName is the file in the state directory that records the repositories
// a report-only sweep has reviewed. Only those are swept for deletion.
const MarkerName = "gc-ran"

// AbandonFactor is how many grace periods old a repository with no rows must
// be, in index.json and in every blob and upload session it holds, before the
// collector treats it as an abandoned first push and lifts the half brake
// from it. Options.Abandon overrides the product.
const AbandonFactor = 24

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
	// ErrChanged is a repository sweep skipped because the repository's
	// index or manifests changed between every read and the lock.
	ErrChanged = errors.New("gc: repository kept changing during the sweep")
)

// errStale is a locked pass that found the index or a manifest it read
// without the lock changed since: the repository is planned again.
var errStale = errors.New("gc: repository changed since it was read")

// maxPlans is how many times a sweep plans one repository before it skips
// it with ErrChanged.
const maxPlans = 3

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
	// ReportOnly is a sweep in which no repository had been reviewed: Objects
	// lists what it would have reaped, and nothing was deleted.
	ReportOnly bool
	// Objects lists what the sweep reaped.
	Objects []Object
	// Stopped lists the repositories whose sweep stopped on a brake.
	Stopped []string
	// Failed lists the repositories whose sweep failed for another reason,
	// such as a manifest it could not read. Nothing was reaped in them.
	Failed []string
	// Reviewing lists the repositories this sweep only reported on, because
	// no earlier sweep had reviewed them.
	Reviewing []string
	// WouldReap lists what the repositories in Reviewing would have reaped,
	// a braked repository's included.
	WouldReap []Object
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
	// Abandon is how long a repository with no rows must have gone without a
	// write (to index.json, to any blob it holds, or to any upload session in
	// it) before the half brake no longer applies to it: a first push that
	// was abandoned before any manifest was written. Its unreferenced blobs
	// then go through the ordinary grace rule. Zero means AbandonFactor times
	// Grace; otherwise it must be longer than Grace.
	Abandon time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Log receives a record per reaped object and per stopped repository
	// (slog.Default when nil).
	Log *slog.Logger
}

// Collector sweeps one store. One Sweep runs at a time.
type Collector struct {
	s       *store.Store
	grace   time.Duration
	abandon time.Duration
	now     func() time.Time
	log     *slog.Logger
	start   time.Time

	mu sync.Mutex // serialises Sweep
	// afterMark, when set, runs between a repository's mark and its locked
	// sweep (a seam for tests that interleave a push).
	afterMark func(ref.Name)
	// onRead, when set, runs before each manifest body the collector reads
	// (a seam for tests that push while a sweep reads).
	onRead func(ref.Name, digest.Digest)
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
	switch {
	case o.Abandon == 0:
		o.Abandon = AbandonFactor * o.Grace
	case o.Abandon <= o.Grace:
		return nil, fmt.Errorf("gc: abandon horizon %s must be longer than the grace %s", o.Abandon, o.Grace)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Collector{s: s, grace: o.Grace, abandon: o.Abandon, now: o.Now, log: o.Log, start: o.Now()}, nil
}

// Sweep runs one collection over every repository. A repository stopped by
// a brake or an error is skipped, listed in the report's Stopped or Failed,
// and named in the returned error; the others are still swept.
//
// Review is per repository. The marker, bound to the store id, names the
// repositories a report-only sweep has reviewed, and only those are swept for
// deletion. Any other repository is reported on, and the sweep adds it to the
// marker when its plan was made and no brake stopped it. A repository not yet
// reviewed that is braked or failed, for any reason and however long, stays out
// of the marker: it holds no other repository, and the first sweep that can plan
// it without a brake reports what it would reap before a later one reaps it. A
// reviewed repository stays in the marker when it is braked or fails, so a
// failure that passes does not send it back to report-only. A name that has left
// the store leaves the marker, so a repository that comes back is new.
// A sweep that reviewed nothing writes no marker over a store that has none,
// so content restored into it later still gets a report-only sweep.
func (c *Collector) Sweep(ctx context.Context) (Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); now.Before(c.start.Add(c.grace)) {
		return Report{}, fmt.Errorf("%w: started %s, grace %s", ErrTooSoon, c.start.Format(time.RFC3339), c.grace)
	}
	marker := filepath.Join(c.s.StateDir(), MarkerName)
	id, _, err := c.s.ID()
	if err != nil {
		return Report{ReportOnly: true}, fmt.Errorf("gc: %w: no sweep deletes until it is repaired; remove %s and the next sweep only reports",
			err, filepath.Join(c.s.Root(), store.IDFile))
	}
	reviewed, err := c.readReviewed(marker, id)
	if err != nil {
		return Report{ReportOnly: true}, err
	}
	rep := Report{ReportOnly: len(reviewed) == 0}
	repos, err := c.s.Repositories()
	if err != nil {
		return rep, err
	}
	next := make(map[string]bool, len(repos))
	var errs []error
	if !rep.ReportOnly {
		// A layout a stopped RemoveLayout left is not listed above, so it
		// would never be reaped otherwise.
		reaped, err := c.s.ReapHalfRemovedLayouts(ctx)
		for _, n := range reaped {
			c.log.Info("registry gc: reaped a half-removed layout", "repository", n.String())
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("gc: %w", err))
		}
	}
	for _, n := range repos {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		name := n.String()
		review := !reviewed[name]
		objs, err := c.sweepRepo(ctx, n, review)
		if review {
			rep.Reviewing = append(rep.Reviewing, name)
			rep.WouldReap = append(rep.WouldReap, objs...)
		} else {
			next[name] = true
			rep.Objects = append(rep.Objects, objs...)
		}
		if err != nil {
			if errors.Is(err, ErrMassDelete) {
				rep.Stopped = append(rep.Stopped, name)
			} else {
				rep.Failed = append(rep.Failed, name)
			}
			errs = append(errs, fmt.Errorf("gc %s: %w", n, err))
			continue
		}
		next[name] = true
	}
	rep.ReportOnly = len(rep.Reviewing) == len(repos)
	if rep.ReportOnly {
		rep.Objects = rep.WouldReap
	}
	if !maps.Equal(next, reviewed) {
		if err := writeReviewed(c.s, c.now(), next); err != nil {
			errs = append(errs, fmt.Errorf("%w: the repositories under review delete nothing until this write succeeds", err))
		}
	}
	return rep, errors.Join(errs...)
}

// sweepRepo marks n without the lock and, unless reportOnly, deletes what a
// second, locked pass agrees on. The manifest bodies are read, verified and
// parsed only in the unlocked mark; the locked pass re-reads index.json and
// re-states the repository, and plans again from the mark's parsed bodies.
// When the rows or a manifest it read changed in between, nothing is deleted
// and the repository is marked again, up to maxPlans times.
func (c *Collector) sweepRepo(ctx context.Context, n ref.Name, reportOnly bool) ([]Object, error) {
	for range maxPlans {
		m, err := c.mark(ctx, n, c.now().Add(-c.grace))
		if err != nil {
			return nil, err
		}
		if m.p.empty() {
			return nil, nil
		}
		if reportOnly {
			q, err := c.brake(n, m.p, m.idx, m.cont)
			if err != nil {
				q = m.p
			}
			objs := q.objects(n)
			for _, o := range objs {
				c.log.Info("registry gc: would reap", "repository", o.Repository, "kind", o.Kind, "name", o.Name, "reason", o.Reason)
			}
			return objs, err
		}
		if c.afterMark != nil {
			c.afterMark(n)
		}
		objs, err := c.sweepLocked(ctx, n, m)
		if !errors.Is(err, errStale) {
			return objs, err
		}
		c.log.Debug("registry gc: repository changed since it was read; planning it again", "repository", n.String())
	}
	return nil, fmt.Errorf("%w: planned %d times", ErrChanged, maxPlans)
}

// sweepLocked is the locked pass over m. It returns errStale, having deleted
// nothing, when index.json's rows differ from the mark's or a manifest the
// plan follows is not the one the mark read.
func (c *Collector) sweepLocked(ctx context.Context, n ref.Name, m marked) ([]Object, error) {
	want, err := store.IndexState(m.idx.Manifests)
	if err != nil {
		return nil, err
	}
	var objs []Object
	err = c.s.WithLock(ctx, n, func(l *store.Locked) error {
		cutoff := c.now().Add(-c.grace)
		idx, err := l.Index()
		if err != nil {
			return err
		}
		got, err := store.IndexState(idx.Manifests)
		if err != nil {
			return err
		}
		if got != want {
			return errStale
		}
		cont, err := l.Contents()
		if err != nil {
			return err
		}
		q, err := makePlan(idx, cont, cutoff, m.reads.locked(cont))
		if err != nil {
			return err
		}
		final, err := c.brake(n, m.p.intersect(q), idx, cont)
		if err != nil {
			return err
		}
		objs, err = c.apply(l, n, final, idx, cutoff)
		return err
	})
	return objs, err
}

// marked is one repository's unlocked mark: the plan, the snapshot it was
// made from, and every manifest body it read.
type marked struct {
	p     plan
	idx   ispec.Index
	cont  store.Contents
	reads reads
}

// mark plans n's sweep from an unlocked snapshot, reading, verifying and
// parsing every manifest body the plan follows. It checks ctx before each body
// read and returns its error, so a cancelled sweep ends having deleted nothing.
func (c *Collector) mark(ctx context.Context, n ref.Name, cutoff time.Time) (marked, error) {
	idx, err := c.s.Index(n)
	if err != nil {
		return marked{}, err
	}
	cont, err := c.s.Contents(n)
	if err != nil {
		return marked{}, err
	}
	m := marked{idx: idx, cont: cont, reads: reads{}}
	read := c.reader(n)
	m.p, err = makePlan(idx, cont, cutoff, m.reads.unlocked(func(d digest.Digest) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return read(d)
	}))
	return m, err
}

// manifestRead is what the mark found for one manifest digest: whether the
// blob was there, its size, and what its body references (or why it could
// not be read).
type manifestRead struct {
	present bool
	size    int64
	refs    refs
	err     error
}

// sized reports whether the mark's read holds the size of the body: any read
// that got as far as the body's bytes, whatever it made of them.
func (e manifestRead) sized() bool {
	var u *unparsedError
	var v *unverifiedError
	return e.err == nil || errors.As(e.err, &u) || errors.As(e.err, &v)
}

// reads holds a mark's manifest reads by digest.
type reads map[digest.Digest]manifestRead

// unlocked returns the mark's refsOf: it reads d with read, which verifies
// the body against d, parses it, and remembers the result with the body's
// size.
func (r reads) unlocked(read func(digest.Digest) ([]byte, error)) func(digest.Digest) (refs, error) {
	return func(d digest.Digest) (refs, error) {
		if e, ok := r[d]; ok {
			return e.refs, e.err
		}
		var e manifestRead
		b, err := read(d)
		switch {
		case errors.Is(err, store.ErrBlobUnknown):
			e.err = err
		case err != nil:
			e.present, e.err = true, err
			var v *unverifiedError
			if errors.As(err, &v) {
				e.size = v.size
			}
		default:
			e.present = true
			e.size = int64(len(b))
			e.refs, e.err = parseRefs(d, b)
		}
		r[d] = e
		return e.refs, e.err
	}
}

// locked returns the locked pass's refsOf over the re-stated contents cont.
// It reads nothing: it answers from the mark's read when the blob is still
// there, or still absent, and has the size the mark read, and otherwise
// returns errStale. A digest the mark never read is errStale too. The size is
// compared for every body whose bytes the mark reached, one the strict read
// refused or that could not be verified included, since a plan can go on from
// those reads.
//
// A body is the content its digest names (the mark verified it, and the
// store writes a blob only under the digest of its bytes), so a present blob
// of the same size is the same body, and its references are the same. A body the
// mark could not verify is not known to be that content: a repair to the same
// size looks unchanged here, and the next sweep's mark reads it.
func (r reads) locked(cont store.Contents) func(digest.Digest) (refs, error) {
	sizes := make(map[digest.Digest]int64, len(cont.Blobs))
	for _, b := range cont.Blobs {
		sizes[b.Digest] = b.Size
	}
	return func(d digest.Digest) (refs, error) {
		e, ok := r[d]
		if !ok {
			return refs{}, errStale
		}
		size, present := sizes[d]
		if present != e.present || (present && e.sized() && size != e.size) {
			return refs{}, errStale
		}
		return e.refs, e.err
	}
}

// brake applies the half-repository rule to a plan over idx and cont, and
// returns the plan to apply: a plan that would reap more than half of the
// repository's blobs stops, unless it empties the repository, the repository is
// an abandoned first push, or it can go on without the blobs the rule below does
// not vouch for (see leaveNewerOut).
//
// A plan empties the repository when it leaves no row (every row, if there
// were any, is one it reaps) and every blob it reaps predates index.json's
// last write. index.json is written when a repository's layout is made, before
// its first blob, and afterwards only when its rows change. So an index
// written after every reaped blob means the rows that named those blobs were
// removed (by a delete, or by this plan, or by an earlier sweep that stopped
// after its row write), and the blobs are what a removed image left. A first
// push in progress has an index older than its blobs, so this rule does not
// free its committed but not yet named blobs. That holds only while index.json
// is unchanged: any later write to the rows (another tag pushed or deleted)
// advances index.json past those blobs, and once the rows are gone again the
// rule lets them through. The grace period, not this rule, is what protects a
// push's blobs. A blob written at the same instant as
// index.json counts as newer: the brake holds.
//
// A first push that was abandoned would stay under the brake for ever, so the
// brake does not apply to a repository with no rows whose index.json, blobs
// and upload sessions are all older than the abandon horizon (see abandoned).
//
// On a stop the plan returned is empty and the caller holds the one it passed.
func (c *Collector) brake(n ref.Name, p plan, idx ispec.Index, cont store.Contents) (plan, error) {
	if 2*len(p.blobs) <= len(cont.Blobs) || emptyingRule(p, idx, cont) || abandoned(idx, cont, c.now().Add(-c.abandon)) {
		return p, nil
	}
	if q, ok := leaveNewerOut(p, idx, cont); ok {
		c.log.Info("registry gc: leaving out blobs not older than index.json", "repository", n.String(),
			"reap", len(q.blobs), "left", len(p.blobs)-len(q.blobs))
		return q, nil
	}
	c.log.Error("registry gc: sweep stopped", "repository", n.String(), "reap", len(p.blobs), "blobs", len(cont.Blobs),
		"reason", "more than half of the repository's blobs")
	return plan{}, fmt.Errorf("%w: %d of %d", ErrMassDelete, len(p.blobs), len(cont.Blobs))
}

// emptyingRule is the rule brake applies (a seam for the test that proves
// the brake's tests fail without it).
var emptyingRule = emptying

// emptying reports whether p empties the repository, by the rule brake
// documents.
func emptying(p plan, idx ispec.Index, cont store.Contents) bool {
	if !removesEveryRow(p, idx) {
		return false
	}
	for _, b := range cont.Blobs {
		if p.blobs[b.Digest] && !b.ModTime.Before(cont.IndexModTime) {
			return false
		}
	}
	return true
}

// removesEveryRow reports whether p leaves idx with no row.
func removesEveryRow(p plan, idx ispec.Index) bool {
	for _, r := range idx.Manifests {
		if _, tagged := r.Annotations[ispec.AnnotationRefName]; tagged || !p.rows[r.Digest] {
			return false
		}
	}
	return true
}

// leaveNewerOut is what stands in for stopping a plan that removes every row but
// names a blob not older than index.json: a touch through an inode another
// repository shares, or a mount, can make one blob newer than a delete, and that
// one blob must not hold the rest of a removed image. The plan goes on with only
// the blobs older than index.json, each of which the rule in brake vouches for,
// and with the rows, whose removal moves index.json past what was left out, so the
// next sweep reaps those too.
//
// It reports false when that leaves nothing to remove, which is a first push, its
// blobs all newer than an index with no row: the brake stops it, and it waits for
// the abandon horizon. So does a blob left out of a repository with no rows, since
// nothing then moves index.json. While another repository names the inode that
// blob holds no bytes.
func leaveNewerOut(p plan, idx ispec.Index, cont store.Contents) (plan, bool) {
	if !removesEveryRow(p, idx) {
		return plan{}, false
	}
	p.blobs = maps.Clone(p.blobs)
	for _, b := range cont.Blobs {
		if !b.ModTime.Before(cont.IndexModTime) {
			delete(p.blobs, b.Digest)
		}
	}
	p.emptyRepo = false
	return p, len(p.rows) > 0 || len(p.blobs) > 0
}

// abandoned reports whether the repository is a first push nobody has
// written to since cutoff: index.json has no rows, and neither it nor any
// blob or upload session in the repository is newer than cutoff. Every write
// a push makes (a blob upload, mount or HEAD, a session write, a manifest
// row) moves one of those times past cutoff, so a push that resumes puts the
// repository back under the brake.
func abandoned(idx ispec.Index, cont store.Contents, cutoff time.Time) bool {
	if len(idx.Manifests) != 0 || cont.IndexModTime.After(cutoff) {
		return false
	}
	for _, b := range cont.Blobs {
		if b.ModTime.After(cutoff) {
			return false
		}
	}
	for _, u := range cont.Sessions {
		if u.ModTime.After(cutoff) {
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
		if c.onRead != nil {
			c.onRead(n, d)
		}
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
			fi, err := f.Stat()
			if err != nil {
				return nil, err
			}
			return nil, &unverifiedError{d: d, size: fi.Size(), why: fmt.Sprintf("is larger than %d bytes", store.MaxManifestSize)}
		}
		if d.Algorithm().FromBytes(b) != d {
			return nil, &unverifiedError{d: d, size: int64(len(b)), why: "does not hash to its name"}
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
	// FSLayers is the Docker schema1 layer list (fsLayers[].blobSum). The
	// server refuses schema1, and any body with this field, at PUT, and the
	// collector does not follow it: a body that carries the field is
	// unreadable, whatever else it says.
	FSLayers json.RawMessage `json:"fsLayers"`
}

// parseRefs reads what the manifest body b, stored as d, references. It
// fails closed: a body it cannot be sure it has read in full is ErrUnreadable,
// so the sweep stops for that repository instead of reaping what the body
// may still name. It accepts schemaVersion 2 and the OCI and Docker v2 image
// manifest, index and manifest list media types. A body without a mediaType
// (optional in OCI) is an image manifest when it has a config and an index
// when it has a manifests array; anything else, Docker schema1 included, is
// unreadable. An image manifest without a config is unreadable too, and so is
// any body with a Docker schema1 fsLayers field, even at schemaVersion 2, so
// a schema1-shaped body never reads as one that references nothing. A refusal
// is an *unparsedError, which carries every digest the body might name.
func parseRefs(d digest.Digest, b []byte) (refs, error) {
	r, err := parseBody(b)
	if err != nil {
		return refs{}, &unparsedError{d: d, cause: err, named: scanDigests(b)}
	}
	return r, nil
}

// unparsedError is a body that hashed to its digest and was within the size cap
// but that the strict read refused. It is ErrUnreadable, and unlike a body too
// large or failing its hash, its bytes are known, so named holds all a reader
// could take it to reference.
type unparsedError struct {
	d     digest.Digest
	cause error
	named []digest.Digest
}

func (e *unparsedError) Error() string {
	return fmt.Sprintf("%v: %s: %v", ErrUnreadable, e.d, e.cause)
}

func (e *unparsedError) Unwrap() error { return ErrUnreadable }

// unverifiedError is a body over the size cap or failing its hash, so its bytes
// are not known to be what d names. It is ErrUnreadable.
type unverifiedError struct {
	d    digest.Digest
	size int64
	why  string
}

func (e *unverifiedError) Error() string {
	return fmt.Sprintf("%v: %s %s", ErrUnreadable, e.d, e.why)
}

func (e *unverifiedError) Unwrap() error { return ErrUnreadable }

// scanDigests returns, once each and in order of first occurrence, every string
// in the JSON body b that ref.ParseDigest accepts, at any depth and at every occurrence of a repeated key. It stops at
// the first thing that is not JSON and returns what it found before it. Object
// keys count too: the decoder's tokens do not tell them from values, and keeping
// too much is the safe side.
//
// b is at most store.MaxManifestSize, every token consumes input, and the decoder
// does not recurse per level, so a hostile body costs time and memory linear in
// its size. Nesting past the decoder's depth limit, which json.Unmarshal shares,
// ends the scan like any other break: no reader could take such a body for a
// manifest. UseNumber keeps a number no float64 can hold, valid JSON the strict
// read skips, from ending the scan early.
func scanDigests(b []byte) []digest.Digest {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out []digest.Digest
	seen := map[digest.Digest]bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		if s, ok := tok.(string); ok {
			if d, err := ref.ParseDigest(s); err == nil && !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
}

// Readable returns why the collector could not read body as a manifest, or nil.
// The server stores nothing it refuses: a row the collector cannot read stops
// every sweep of its repository until the row is deleted, so what the server
// accepts must not be decided by a second reading of the body.
func Readable(body []byte) error {
	_, err := parseBody(body)
	return err
}

// parseBody is parseRefs without the digest and the sentinel.
func parseBody(b []byte) (refs, error) {
	var r refs
	if err := json.Unmarshal(b, &r); err != nil {
		return refs{}, err
	}
	if r.FSLayers != nil {
		return refs{}, errors.New("a Docker schema1 fsLayers field")
	}
	if r.SchemaVersion != 2 {
		return refs{}, fmt.Errorf("schemaVersion %d, want 2", r.SchemaVersion)
	}
	switch r.MediaType {
	case ispec.MediaTypeImageManifest, mediaTypeDockerManifest:
		if r.Config == nil {
			return refs{}, errors.New("image manifest without a config")
		}
	case ispec.MediaTypeImageIndex, mediaTypeDockerManifestList:
	case "":
		if r.Config == nil && r.Manifests == nil {
			return refs{}, errors.New("no mediaType, and neither a config nor a manifests array")
		}
	default:
		return refs{}, fmt.Errorf("unknown mediaType %q", r.MediaType)
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
// spec does not require) or does not parse fails the plan. refsOf returns what
// manifest d references: an error wrapping store.ErrBlobUnknown for a missing
// body, ErrUnreadable for one that does not verify or parse (an *unparsedError
// for one that verified), or errStale, which fails the plan unwrapped.
//
// An index child with no row in idx is the one exception, and only for a body
// that hashes to its digest and is within the size cap. A child is not required
// to exist at PUT and its descriptor says what the pusher likes, so any blob can
// be named as one, and failing the plan on it would let a pusher stop the
// repository's sweeps. But a body the strict read refuses may still be a real
// manifest, stored before the read grew stricter, so it says nothing about what
// is safe to delete. The child is kept, and every digest scanDigests finds in its
// body stays referenced.
//
// A digest the scan finds is also followed, when the contents hold a blob of that
// name: only a body already in the store is read. A body that reads as a manifest
// is followed as any manifest is, so its references are kept, and a readable index
// found this way holds its own children to the rule below. A body the strict read
// refuses is scanned the same way. A body too large or failing its hash is
// referenced only: it follows nothing and does not fail the plan, since a layer is
// usually too large and a pusher can name anything in a body.
//
// The kept set bounds this. A body is followed once however often it is named, so
// a cycle ends at its second visit, and a fan-out reads each blob at most once: a
// repeat of a digest, however many a body holds (about 56000 fill the size cap),
// costs one queue entry and no read (the scan returns a digest once, and the queue takes an item once). A mark so reads at most one body per blob the
// repository holds, of at most store.MaxManifestSize+1 bytes, and a sweep marks a
// repository at most maxPlans times. The locked pass reads nothing, and a digest
// it finds in the contents that the mark did not read is errStale.
//
// A child with no row that is too large or fails its hash fails the plan when a
// readable body names it, since its bytes cannot be told from a manifest damaged
// in the store. That holds whichever way the walk reached the digest first. So
// does a child with a row that is unreadable. A body with no row that does read is
// followed. A child digest that is not a digest is skipped: no blob can have it.
func makePlan(idx ispec.Index, cont store.Contents, cutoff time.Time, refsOf func(digest.Digest) (refs, error)) (plan, error) {
	mtime := make(map[digest.Digest]time.Time, len(cont.Blobs))
	for _, b := range cont.Blobs {
		mtime[b.Digest] = b.ModTime
	}
	old := func(t time.Time) bool { return !t.After(cutoff) }

	type item struct {
		d        digest.Digest
		required bool // a missing body fails the plan
		scanned  bool // found by scanDigests, not named by a readable body
	}
	var queue []item
	// queued holds the items ever enqueued, whole: an item found by the scan and
	// the same digest named by a readable body differ in scanned, so the first
	// never stands in for the second, which must still reach the check below.
	queued := map[item]bool{}
	enqueue := func(it item) {
		if !queued[it] {
			queued[it] = true
			queue = append(queue, it)
		}
	}
	candidates := map[digest.Digest]bool{}
	hasRow := make(map[digest.Digest]bool, len(idx.Manifests))
	for _, r := range idx.Manifests {
		hasRow[r.Digest] = true
	}
	for _, r := range idx.Manifests {
		if _, tagged := r.Annotations[ispec.AnnotationRefName]; tagged {
			enqueue(item{d: r.Digest, required: true})
			continue
		}
		t, ok := mtime[r.Digest]
		if !ok || !old(t) {
			enqueue(item{d: r.Digest})
			continue
		}
		m, err := refsOf(r.Digest)
		if err != nil {
			return plan{}, planError("untagged "+r.Digest.String(), err)
		}
		if m.Subject != nil {
			enqueue(item{d: r.Digest, required: true})
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
		referenced[it.d] = true
		m, err := refsOf(it.d)
		// Left unvisited: the same digest named by a readable body must still
		// fail the plan, and which of the two is walked first is the row order's
		// choice. A repeat costs no read, since refsOf remembers.
		var v *unverifiedError
		if it.scanned && !hasRow[it.d] && errors.As(err, &v) {
			continue
		}
		kept[it.d] = true
		if errors.Is(err, store.ErrBlobUnknown) && !it.required {
			continue
		}
		var u *unparsedError
		if errors.As(err, &u) && !it.required && !hasRow[it.d] {
			for _, d := range u.named {
				referenced[d] = true
				if _, stored := mtime[d]; stored && !kept[d] {
					enqueue(item{d: d, scanned: true})
				}
			}
			continue
		}
		if err != nil {
			return plan{}, planError(it.d.String(), err)
		}
		if m.Config != nil {
			referenced[m.Config.Digest] = true
		}
		for _, l := range m.Layers {
			referenced[l.Digest] = true
		}
		for _, ch := range m.Manifests {
			if _, err := ref.ParseDigest(ch.Digest.String()); err != nil {
				continue
			}
			referenced[ch.Digest] = true
			enqueue(item{d: ch.Digest})
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

// planError is the error a plan fails with when manifest what cannot be
// followed: errStale and ErrUnreadable as they are; a body that is missing,
// not a regular file or a symlink, which stays so until someone repairs the
// store, as ErrUnreadable; anything else (an I/O error, too many open files),
// which may pass, wrapped as it is.
func planError(what string, err error) error {
	switch {
	case errors.Is(err, errStale), errors.Is(err, ErrUnreadable):
		return err
	case errors.Is(err, store.ErrBlobUnknown), errors.Is(err, store.ErrNotRegular), errors.Is(err, ref.ErrSymlink):
		return fmt.Errorf("%w: %s: %w", ErrUnreadable, what, err)
	default:
		return fmt.Errorf("gc: read manifest %s: %w", what, err)
	}
}

// markerRecord is the marker's content: when a report-only sweep last changed
// it, the id of the store it ran over (store.IDFile in the root), and the
// repositories reviewed so far.
//
// The id, not the root directory's device and inode, is the binding because
// a restore by rsync or tar into the existing root keeps the root's inode.
// The id file is written the first time a marker is, so a backup taken
// before it existed restores without it, and the next sweep mints a new id
// and only reports. A backup or copy that carries the id file is the same
// store, and its sweeps delete in the repositories the state directory's
// marker names; deleting there is what they would have done before the backup.
//
// A restore merged over a live root keeps the id, and the collector cannot tell
// a restored index.json from a push: a fingerprint of the rows taken at review
// goes stale with the next push, and one that forced a report-only sweep would
// let a pusher hold the repository there by pushing once per sweep. So a merged
// repository the marker does not name reports first, one it names is swept, and
// the rule docs/user/registry.md gives is to restore into an emptied root, or
// to remove the id file before the server starts.
type markerRecord struct {
	Ran      string   `json:"ran"`
	Store    string   `json:"store"`
	Reviewed []string `json:"reviewed"`
}

// readReviewed returns the repositories the marker at p names as reviewed for
// the store with id id. A missing marker, one written for another store or in
// an older form, or an empty id (the root has no id file) names none: those
// repositories report only and the marker is written again.
//
// The read has no size bound. The set grows with the repositories, which a
// pusher can create, so a bound would be a way to turn the collector off, and
// the sweep already holds every repository's name in memory.
func (c *Collector) readReviewed(p, id string) (map[string]bool, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gc marker: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("gc marker %s is not a regular file", p)
	}
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("gc marker: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("gc marker: %w", err)
	}
	var m markerRecord
	if json.Unmarshal(b, &m) != nil || id == "" || m.Store != id {
		c.log.Warn("registry gc: the gc-ran marker was not written for this store; the next sweep only reports",
			"marker", p, "root", c.s.Root())
		return nil, nil
	}
	reviewed := make(map[string]bool, len(m.Reviewed))
	for _, n := range m.Reviewed {
		reviewed[n] = true
	}
	return reviewed, nil
}

// WriteMarker records that a report-only sweep reviewed every repository s
// holds now, so the next sweep over s deletes in them. It binds the record to
// s's store id, writing the id first when the root holds none; a store whose
// root has another id, or none, sweeps report-only again.
func WriteMarker(s *store.Store, now time.Time) error {
	repos, err := s.Repositories()
	if err != nil {
		return fmt.Errorf("write gc marker: %w", err)
	}
	reviewed := make(map[string]bool, len(repos))
	for _, n := range repos {
		reviewed[n.String()] = true
	}
	return writeReviewed(s, now, reviewed)
}

// writeReviewed records, durably and atomically, the repositories reviewed in
// s, writing the store id first when the root holds none.
func writeReviewed(s *store.Store, now time.Time, reviewed map[string]bool) error {
	id, err := s.EnsureID()
	if err != nil {
		return fmt.Errorf("write gc marker: %w", err)
	}
	names := make([]string, 0, len(reviewed))
	for n := range reviewed {
		names = append(names, n)
	}
	slices.Sort(names)
	b, err := json.Marshal(markerRecord{Ran: now.UTC().Format(time.RFC3339), Store: id, Reviewed: names})
	if err != nil {
		return fmt.Errorf("write gc marker: %w", err)
	}
	if err := atomicfile.Replace(filepath.Join(s.StateDir(), MarkerName), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write gc marker: %w", err)
	}
	return nil
}
