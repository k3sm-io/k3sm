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

package registrysvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// The dedupe loop of the server process.
//
// A pass (store.Converge) runs when the store has been idle, so a commit does no
// work for it and answers the same whether another repository holds the digest.
// The trigger is set at start and by every commit and mount, and only in memory.
// Two things set it again with no commit: a sweep that reviewed a repository the
// last pass could not rewrite, and a pass whose own limits left work.

// Timings of the dedupe loop.
const (
	// serveConvergeIdle is how long a pass waits after the last commit or live
	// upload session, plus up to serveConvergeJitter drawn once per trigger.
	serveConvergeIdle   = 60 * time.Second
	serveConvergeJitter = 60 * time.Second
	// serveConvergeBound is the latest a pass starts after the first commit that
	// set the trigger, however busy the store. Past it an upload stops no pass.
	serveConvergeBound = 15 * time.Minute
	// serveConvergeFreeEvery is how often the loop reads the volume's free space.
	serveConvergeFreeEvery = 30 * time.Second
	// serveConvergeLowFree is the free space below which a pass starts with the
	// trigger set, without the idle wait or jitter but after the rest since the last
	// pass, and no upload stops it: twice the floor where the server starts refusing
	// uploads.
	serveConvergeLowFree = 2 * api.DefaultMinFreeSpace
	// serveConvergeTick is how often the loop looks at its conditions. It reads
	// only memory, except for the free space above.
	serveConvergeTick = 5 * time.Second
	// serveConvergeMaxFruitless is how many passes in a row may get nowhere before a
	// pass stops setting its own trigger and serveConvergeFruitlessSpacing starts to
	// apply: see settle for what counts. A merge is what a further pass is for, and
	// copies are finite, so passes that merge always end. One with no merge may still
	// be worth it, as the hash budget's rotation hands the next pass another digest,
	// but a corrupt keeper or a failing volume would repeat forever.
	serveConvergeMaxFruitless = 3
	// serveConvergeFruitlessSpacing is the least time from the end of a pass that
	// reached serveConvergeMaxFruitless to the start of the next, whatever set the
	// trigger, until a pass merges something. Commits do not reset the count or
	// shorten this, so past the cap a client with push rights causes at most one pass
	// an hour, about 16 GiB of hashing against the 900 GiB an hour the hash rate would
	// allow. An hour is much longer than the 64 s a full budget takes to hash, and the
	// cost of waiting is only that a copy stays on disk a little longer on a store
	// whose last passes have merged nothing. A pass that keeps the trigger past the
	// bound still starts when the spacing ends, and no upload stops it. The budget
	// exempts a pass's first digest, so one blob larger than 16 GiB costs twice its
	// size. A merge clears the count, and a client can cause one by pushing a blob to
	// two reviewed repositories, so this limits only passes that merge nothing:
	// passes that merge run one rest apart, up to about 450 GiB an hour if each
	// spends its budget.
	serveConvergeFruitlessSpacing = time.Hour
)

// Why a pass started, as registry.log says it.
const (
	convergeWhyIdle     = "idle"
	convergeWhyBound    = "bound"
	convergeWhyLowSpace = "low-space"
)

// sweepFence keeps a dedupe pass and a sweep of this process apart, and holds
// passes back until the first sweep has had its turn, since that sweep is what
// names a store's repositories as reviewed. Without it the pass the start trigger
// allows would find nothing it may rewrite, clear the trigger and leave copies
// already on disk until the next commit.
type sweepFence struct {
	// mu is held across a sweep and across a pass.
	mu    sync.Mutex
	once  sync.Once
	first chan struct{}
}

func newSweepFence() *sweepFence { return &sweepFence{first: make(chan struct{})} }

// swept records that a sweep has finished, however it ended.
func (f *sweepFence) swept() { f.once.Do(func() { close(f.first) }) }

// hasSwept reports whether a sweep has finished.
func (f *sweepFence) hasSwept() bool {
	select {
	case <-f.first:
		return true
	default:
		return false
	}
}

// convergeLoopDeps is what the loop needs from the server. now, jitter, tick and
// freeSpace are optional and take the real ones when nil.
type convergeLoopDeps struct {
	store     *store.Store
	sessions  func() int
	freeSpace func() (uint64, error)
	now       func() time.Time
	jitter    func() time.Duration
	tick      <-chan time.Time
	grace     time.Duration
	fence     *sweepFence
	reports   statusReporter
	log       *slog.Logger
}

// convergeLoop decides when a pass runs. run owns every field but the trigger's,
// which a request sets under mu and the loop reads under it.
type convergeLoop struct {
	convergeLoopDeps
	// converge is the pass, store.Converge outside a test.
	converge func(context.Context, store.ConvergeOptions) (store.ConvergeReport, error)
	// rotation lives as long as the loop, so a digest that spent the pass's hash
	// budget does not lead the next pass too.
	rotation *store.ConvergeRotation

	// floor is the end of the grace after start, before which no pass runs.
	floor time.Time

	mu sync.Mutex
	// armed is the trigger. first is the first commit that set it, zero when no
	// commit did, and last the latest commit or re-arm, which outlives the trigger.
	armed       bool
	first, last time.Time
	// rest is the end of the spacing after the last pass or a re-arm. Low space does
	// not skip it and a commit does not clear it, since no upload stops a low-space
	// pass and a client with push rights chooses when it commits.
	rest time.Time
	// reviewed is the set the last pass or sweep read from the marker.
	reviewed map[string]bool

	// busy is the last tick that saw a live session.
	busy time.Time
	// wait is the idle wait of this trigger, jitter included, and waitDrawn says
	// it is drawn.
	wait      time.Duration
	waitDrawn bool
	// low says the last read of free space was below serveConvergeLowFree, and
	// freeRead is when that read was.
	low      bool
	freeRead time.Time
	// fruitless counts the passes in a row that got nowhere, against
	// serveConvergeMaxFruitless: see settle.
	fruitless int
	// cur is the pass running.
	cur *convergeRun
}

// convergeRun is one pass in flight.
type convergeRun struct {
	cancel context.CancelFunc
	done   chan convergeResult
	// first is the trigger's first commit, which the pass's own bound runs from.
	first time.Time
	why   string
	// stopped says an upload stopped the pass, so its trigger still stands.
	stopped bool
}

type convergeResult struct {
	rep store.ConvergeReport
	err error
}

func newConvergeLoop(d convergeLoopDeps) *convergeLoop {
	if d.now == nil {
		d.now = time.Now
	}
	if d.jitter == nil {
		d.jitter = func() time.Duration { return rand.N(serveConvergeJitter + 1) }
	}
	if d.freeSpace == nil {
		root := d.store.Root()
		d.freeSpace = func() (uint64, error) { return statfsFree(root) }
	}
	start := d.now()
	return &convergeLoop{
		convergeLoopDeps: d,
		converge:         d.store.Converge,
		rotation:         &store.ConvergeRotation{},
		floor:            start.Add(d.grace),
		armed:            true,
		last:             start,
	}
}

// statfsFree returns the bytes available to an unprivileged writer on the volume
// holding p, as the server's own 507 floor counts them.
func statfsFree(p string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// commit sets the trigger. A request calls it after its response is written.
func (l *convergeLoop) commit() {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.armed = true
	if l.first.IsZero() {
		l.first = now
	}
	l.last = now
}

// rearm sets the trigger with no commit behind it: the idle wait runs from now, and
// no bound runs, since only a commit's does. A trigger already set stands as it is.
func (l *convergeLoop) rearm(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.armed {
		return
	}
	l.armed, l.last = true, now
	if end := now.Add(serveConvergeIdle); l.rest.Before(end) {
		l.rest = end
	}
}

// sweepFinished re-arms the loop when the sweep's marker names a repository the
// last pass or sweep did not see. A marker it cannot read names nothing new, and
// the pass this would have started could not have read it either.
func (l *convergeLoop) sweepFinished() {
	reviewed, err := gc.ReadReviewed(l.store, l.log)
	if err != nil {
		l.log.Warn("registry dedupe: could not read the reviewed repositories after a sweep", "err", err)
		return
	}
	if l.noteReviewed(reviewed) {
		l.rearm(l.now())
	}
}

// noteReviewed records the marker's set and reports whether it names a repository
// the last one did not.
func (l *convergeLoop) noteReviewed(reviewed map[string]bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	added := false
	for name := range reviewed {
		if !l.reviewed[name] {
			added = true
			break
		}
	}
	l.reviewed = reviewed
	return added
}

// run drives the loop until ctx ends, and waits out a pass in flight.
func (l *convergeLoop) run(ctx context.Context) {
	tick := l.tick
	if tick == nil {
		t := time.NewTicker(serveConvergeTick)
		defer t.Stop()
		tick = t.C
	}
	for {
		var done chan convergeResult
		if l.cur != nil {
			done = l.cur.done
		}
		select {
		case <-ctx.Done():
			if l.cur != nil {
				l.finish(ctx, <-l.cur.done)
			}
			return
		case res := <-done:
			l.finish(ctx, res)
		case <-tick:
			l.step(ctx, l.now())
		}
	}
}

// step looks at the conditions once: it stops the pass in flight or starts one.
func (l *convergeLoop) step(ctx context.Context, now time.Time) {
	live := l.sessions() > 0
	if live {
		l.busy = now
	}
	l.readFree(now)
	if l.cur != nil {
		if live && !l.low && l.cur.why != convergeWhyLowSpace && !l.pastBound(l.cur.first, now) {
			l.cur.stopped = true
			l.cur.cancel()
		}
		return
	}
	l.mu.Lock()
	armed, first, last, rest := l.armed, l.first, l.last, l.rest
	l.mu.Unlock()
	if !armed || now.Before(l.floor) || now.Before(rest) || !l.fence.hasSwept() {
		return
	}
	if !l.waitDrawn {
		l.wait, l.waitDrawn = serveConvergeIdle+l.jitter(), true
	}
	var why string
	switch {
	case l.low:
		why = convergeWhyLowSpace
	case l.pastBound(first, now):
		why = convergeWhyBound
	case live || now.Before(last.Add(l.wait)) || now.Before(l.busy.Add(l.wait)):
		return
	default:
		why = convergeWhyIdle
	}
	if !l.fence.mu.TryLock() {
		return // a sweep is running; the next tick looks again
	}
	l.start(ctx, first, why)
}

// pastBound reports whether the bound from the commit first has passed. A trigger
// only the start set has no bound.
func (l *convergeLoop) pastBound(first, now time.Time) bool {
	return !first.IsZero() && !now.Before(first.Add(serveConvergeBound))
}

// readFree reads the free space when serveConvergeFreeEvery has passed. A failed
// read leaves the last answer standing.
func (l *convergeLoop) readFree(now time.Time) {
	if !l.freeRead.IsZero() && now.Sub(l.freeRead) < serveConvergeFreeEvery {
		return
	}
	l.freeRead = now
	free, err := l.freeSpace()
	if err != nil {
		l.log.Warn("registry dedupe: could not read the free space", "err", err)
		return
	}
	l.low = free < serveConvergeLowFree
}

// start clears the trigger and runs a pass; the caller holds the fence, which the
// pass releases. A commit during the pass sets the trigger again.
func (l *convergeLoop) start(ctx context.Context, first time.Time, why string) {
	l.mu.Lock()
	l.armed, l.first = false, time.Time{}
	l.mu.Unlock()
	l.waitDrawn = false
	passCtx, cancel := context.WithCancel(ctx)
	run := &convergeRun{cancel: cancel, done: make(chan convergeResult, 1), first: first, why: why}
	l.cur = run
	l.log.Info("registry dedupe: pass started", "why", why)
	go func() {
		rep, err := l.pass(passCtx)
		l.fence.mu.Unlock()
		run.done <- convergeResult{rep: rep, err: err}
	}()
}

// pass reads the marker and runs one pass over what it names. A marker it cannot
// read rewrites nothing.
func (l *convergeLoop) pass(ctx context.Context) (store.ConvergeReport, error) {
	reviewed, err := gc.ReadReviewed(l.store, l.log)
	if err != nil {
		return store.ConvergeReport{}, err
	}
	l.noteReviewed(reviewed)
	return l.converge(ctx, store.ConvergeOptions{
		Reviewed: func(n ref.Name) bool { return reviewed[n.String()] },
		Log:      l.log,
		Rotation: l.rotation,
	})
}

// finish takes a pass's result: it restores the trigger of a stopped pass, counts the
// pass and sets the rest after it, re-arms after one that left work, logs the
// outcome and reports it. A pass the server's stop ended reports nothing, as
// a sweep the stop ended does not; its merges were each logged. The store logs
// each merge and each corrupt file itself.
func (l *convergeLoop) finish(ctx context.Context, res convergeResult) {
	run := l.cur
	l.cur = nil
	run.cancel()
	if run.stopped {
		l.mu.Lock()
		l.armed = true
		if !run.first.IsZero() && (l.first.IsZero() || run.first.Before(l.first)) {
			l.first = run.first
		}
		l.mu.Unlock()
	}
	if ctx.Err() != nil {
		return
	}
	failed := res.err != nil && !(run.stopped && errors.Is(res.err, context.Canceled))
	level := slog.LevelInfo
	if failed {
		level = slog.LevelError
	}
	skipped := make(map[string]int, len(res.rep.Skipped))
	for reason, n := range res.rep.Skipped {
		skipped[string(reason)] = n
	}
	attrs := []any{
		"why", run.why, "stopped_by_upload", run.stopped, "merged", res.rep.Merged, "reclaimed_bytes", res.rep.ReclaimedBytes,
		"pending", res.rep.Pending, "corrupt_targets", res.rep.CorruptTargets, "corrupt_replaced", res.rep.CorruptReplaced,
		"corrupt_keepers", res.rep.CorruptKeepers, "hashed_bytes", res.rep.HashedBytes, "scan_truncated", res.rep.ScanTruncated,
		"skipped", skipped,
	}
	if failed {
		attrs = append(attrs, "err", res.err)
	}
	l.log.Log(ctx, level, "registry dedupe: pass finished", attrs...)
	l.settle(run, res, failed)
	if !run.stopped {
		l.rearmForWork(res)
	}
	l.reports.dedupe(DedupeStatus{
		LastPass:        l.now().UTC(),
		Merged:          res.rep.Merged,
		ReclaimedBytes:  res.rep.ReclaimedBytes,
		Pending:         res.rep.Pending,
		CorruptReplaced: res.rep.CorruptReplaced,
		Skipped:         skipped,
	})
}

// settle counts a finished pass against serveConvergeMaxFruitless and starts the rest
// after it, which at the cap is serveConvergeFruitlessSpacing. A pass that merged and
// did not fail clears the count, even one an upload stopped. Any other pass counts
// when it cost something a commit could ask for again: it failed, hashed, stood in
// the way of uploads on low space, or ran to the end and left work. A pass that did
// none of that found nothing to do, which clears the count, unless an upload stopped
// it, which says nothing either way.
func (l *convergeLoop) settle(run *convergeRun, res convergeResult, failed bool) {
	switch {
	case res.rep.Merged > 0 && !failed:
		l.fruitless = 0
	case failed, res.rep.HashedBytes > 0, run.why == convergeWhyLowSpace, !run.stopped && res.rep.LeftWork():
		l.fruitless++
	case !run.stopped:
		l.fruitless = 0
	}
	spacing := serveConvergeIdle
	if l.fruitless >= serveConvergeMaxFruitless {
		spacing = serveConvergeFruitlessSpacing
		l.log.Warn("registry dedupe: passes in a row got nowhere; the next waits, whatever commits arrive, until a pass merges something",
			"passes", l.fruitless, "spacing", spacing.String())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rest = l.now().Add(spacing)
}

// rearmForWork sets the trigger when res left work a later pass could do, until
// serveConvergeMaxFruitless passes in a row have got nowhere.
func (l *convergeLoop) rearmForWork(res convergeResult) {
	if res.rep.LeftWork() && l.fruitless < serveConvergeMaxFruitless {
		l.rearm(l.now())
	}
}

// watchCommits calls committed after each POST or PUT answered 201, which is how
// the server answers a blob commit, a mount and a manifest push, whatever the
// digest and whatever another repository holds. It adds nothing to any other
// method, so a read keeps the connection's own response writer and its sendfile.
func watchCommits(next http.Handler, committed func()) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == http.StatusCreated {
			committed()
		}
	})
}

// statusRecorder notes the first status written.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap gives http.ResponseController the response underneath, which the server
// sets its body and write deadlines through.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
