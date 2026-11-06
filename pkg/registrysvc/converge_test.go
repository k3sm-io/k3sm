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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/auth"
	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

const (
	rigGrace  = time.Hour
	rigJitter = 7 * time.Second
	// rigWait is the idle wait the rig's loop draws.
	rigWait = serveConvergeIdle + rigJitter
)

// loopRig drives a convergeLoop's step directly, so what a step decides is seen
// when it returns. The pass is a stand-in unless a test says otherwise.
type loopRig struct {
	t        *testing.T
	ctx      context.Context
	work     string
	st       *store.Store
	l        *convergeLoop
	fence    *sweepFence
	t0       time.Time
	clock    atomic.Int64
	sessions atomic.Int64
	free     atomic.Uint64
	reads    atomic.Int64
	logs     bytes.Buffer
	// passes receives the options of each pass, and release ends a held one.
	passes chan store.ConvergeOptions
	passCt chan context.Context
	hold   bool
	rep    store.ConvergeReport
	// passErr is what a pass that is not held returns.
	passErr error
}

func newLoopRig(t *testing.T) *loopRig {
	t.Helper()
	work := t.TempDir()
	st, err := store.OpenWorkDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteState(work, State{State: StateServing}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &loopRig{
		t: t, ctx: ctx, work: work, st: st, fence: newSweepFence(),
		t0:     time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC),
		passes: make(chan store.ConvergeOptions, 8), passCt: make(chan context.Context, 8),
	}
	r.free.Store(1 << 40)
	r.clock.Store(r.t0.UnixNano())
	log := slog.New(slog.NewJSONHandler(&r.logs, nil))
	r.l = newConvergeLoop(convergeLoopDeps{
		store:    st,
		sessions: func() int { return int(r.sessions.Load()) },
		freeSpace: func() (uint64, error) {
			r.reads.Add(1)
			return r.free.Load(), nil
		},
		now:     func() time.Time { return time.Unix(0, r.clock.Load()).UTC() },
		jitter:  func() time.Duration { return rigJitter },
		grace:   rigGrace,
		fence:   r.fence,
		reports: statusReporter{workDir: work, log: log},
		log:     log,
	})
	r.l.converge = func(ctx context.Context, o store.ConvergeOptions) (store.ConvergeReport, error) {
		r.passes <- o
		r.passCt <- ctx
		if r.hold {
			<-ctx.Done()
			return r.rep, ctx.Err()
		}
		return r.rep, r.passErr
	}
	return r
}

// at sets the clock to d past the rig's start and steps once.
func (r *loopRig) at(d time.Duration) {
	r.set(d)
	r.l.step(r.ctx, r.t0.Add(d))
}

func (r *loopRig) set(d time.Duration) { r.clock.Store(r.t0.Add(d).UnixNano()) }

// commitAt sets the clock to d past the rig's start and commits.
func (r *loopRig) commitAt(d time.Duration) {
	r.set(d)
	r.l.commit()
}

// wantNoPass fails when a pass is in flight.
func (r *loopRig) wantNoPass(what string) {
	r.t.Helper()
	if r.l.cur != nil {
		r.t.Fatalf("%s: a pass started (%s)", what, r.l.cur.why)
	}
}

// wantPass fails unless a pass is in flight for why.
func (r *loopRig) wantPass(what, why string) {
	r.t.Helper()
	if r.l.cur == nil {
		r.t.Fatalf("%s: no pass started", what)
	}
	if r.l.cur.why != why {
		r.t.Fatalf("%s: a pass started for %q, want %q", what, r.l.cur.why, why)
	}
}

// finish waits for the pass in flight and hands its result to the loop, as run
// does.
func (r *loopRig) finish() {
	r.t.Helper()
	bound := time.NewTimer(serveAwaitBound)
	defer bound.Stop()
	select {
	case res := <-r.l.cur.done:
		r.l.finish(r.ctx, res)
	case <-bound.C:
		r.t.Fatal("the pass did not end")
	}
}

// TestConvergeLoopSchedule pins when a pass starts.
func TestConvergeLoopSchedule(t *testing.T) {
	const after = 2 * time.Hour
	tests := []struct {
		name string
		run  func(r *loopRig)
	}{
		{"no pass within one grace of start", func(r *loopRig) {
			r.fence.swept()
			r.at(rigGrace - time.Second)
			r.wantNoPass("just inside the grace")
			r.at(rigGrace)
			r.wantPass("the start trigger, past the grace", convergeWhyIdle)
		}},
		{"no pass before the first sweep", func(r *loopRig) {
			r.at(after)
			r.wantNoPass("no sweep yet")
			r.fence.swept()
			r.at(after + time.Second)
			r.wantPass("after the first sweep", convergeWhyIdle)
		}},
		{"the idle wait and its jitter run from the last commit", func(r *loopRig) {
			r.fence.swept()
			r.commitAt(after)
			r.at(after + rigWait - time.Second)
			r.wantNoPass("a second short of the wait")
			r.commitAt(after + rigWait - time.Second)
			r.at(after + rigWait)
			r.wantNoPass("a commit moved the wait")
			r.at(after + 2*rigWait - time.Second)
			r.wantPass("the wait from the last commit", convergeWhyIdle)
		}},
		{"a live session holds a pass, and the wait runs from its end", func(r *loopRig) {
			r.fence.swept()
			r.commitAt(after)
			r.sessions.Store(1)
			r.at(after + rigWait)
			r.wantNoPass("a live session")
			r.sessions.Store(0)
			r.at(after + rigWait + time.Second)
			r.wantNoPass("the session has just gone")
			r.at(after + 2*rigWait)
			r.wantPass("idle again", convergeWhyIdle)
		}},
		{"pushing never holds a pass past the bound", func(r *loopRig) {
			r.fence.swept()
			r.commitAt(after)
			r.commitAt(after + serveConvergeBound - time.Minute)
			r.sessions.Store(1)
			r.at(after + serveConvergeBound - time.Second)
			r.wantNoPass("inside the bound")
			r.at(after + serveConvergeBound)
			r.wantPass("the bound from the first commit", convergeWhyBound)
		}},
		{"low space skips the idle wait and the jitter", func(r *loopRig) {
			r.fence.swept()
			r.free.Store(serveConvergeLowFree - 1)
			r.commitAt(after)
			r.sessions.Store(1)
			r.at(after)
			r.wantPass("low space with a live session", convergeWhyLowSpace)
		}},
		{"free space at the threshold is not low", func(r *loopRig) {
			r.fence.swept()
			r.free.Store(serveConvergeLowFree)
			r.commitAt(after)
			r.at(after)
			r.wantNoPass("at the threshold")
		}},
		{"low space does not override the grace", func(r *loopRig) {
			r.fence.swept()
			r.free.Store(1)
			r.at(rigGrace - time.Second)
			r.wantNoPass("low space inside the grace")
		}},
		{"a pass clears the trigger until a commit", func(r *loopRig) {
			r.fence.swept()
			r.at(after)
			r.wantPass("the start trigger", convergeWhyIdle)
			r.finish()
			r.at(after + 24*time.Hour)
			r.wantNoPass("no commit since")
			r.free.Store(1)
			r.at(after + 25*time.Hour)
			r.wantNoPass("low space with no commit since, which would hash for nothing")
			r.commitAt(after + 26*time.Hour)
			r.at(after + 26*time.Hour)
			r.wantPass("low space and a commit", convergeWhyLowSpace)
		}},
		{"a commit during a pass sets the trigger again", func(r *loopRig) {
			r.fence.swept()
			r.hold = true
			r.at(after)
			r.wantPass("the start trigger", convergeWhyIdle)
			r.commitAt(after + time.Second)
			r.l.cur.cancel()
			r.finish()
			r.at(after + time.Second + rigWait)
			r.wantPass("the commit during the pass", convergeWhyIdle)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.run(newLoopRig(t)) })
	}
}

// lastPass drains the rig's record of passes and returns the newest one's options.
func (r *loopRig) lastPass() store.ConvergeOptions {
	r.t.Helper()
	var o store.ConvergeOptions
	seen := false
	for {
		select {
		case o = <-r.passes:
			seen = true
			<-r.passCt
		default:
			if !seen {
				r.t.Fatal("no pass ran")
			}
			return o
		}
	}
}

// passesFrom keeps offering the loop a free store, a day between looks, and
// returns how many passes it starts on its own. The rig's clock ends at the last
// look, which is returned too.
func (r *loopRig) passesFrom(at time.Duration) (int, time.Duration) {
	r.t.Helper()
	const looks = 10
	passes := 0
	for range looks {
		at += 24 * time.Hour
		r.at(at)
		if r.l.cur == nil {
			return passes, at
		}
		passes++
		r.finish()
		r.lastPass()
	}
	r.t.Fatalf("the loop was still starting passes after %d", passes)
	return passes, at
}

// TestConvergeRearmsAfterASweepReviewsARepository: copies in a repository a sweep
// has just reviewed merge one idle wait after that sweep, with no commit, and a
// sweep that reviewed nothing new costs no pass.
func TestConvergeRearmsAfterASweepReviewsARepository(t *testing.T) {
	const after = 2 * time.Hour
	second, err := ref.ParseName("second")
	if err != nil {
		t.Fatal(err)
	}
	r := newLoopRig(t)
	r.fence.swept()
	initRepo(t, r.st, "first")
	if err := gc.WriteMarker(r.st, r.t0); err != nil {
		t.Fatal(err)
	}
	r.at(after)
	r.wantPass("the start trigger", convergeWhyIdle)
	r.finish()
	r.lastPass()
	r.at(after + 24*time.Hour)
	r.wantNoPass("nothing since the pass")

	// A real sweep through the loop's own wiring reviews the new repository.
	initRepo(t, r.st, "second")
	collector, err := gc.New(r.st, gc.Options{Grace: time.Millisecond, Log: r.l.log})
	if err != nil {
		t.Fatal(err)
	}
	swept := after + 25*time.Hour
	r.set(swept)
	ctx, cancel := context.WithCancel(r.ctx)
	finished := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sweepLoop(ctx, collector, time.Millisecond, time.Hour, r.fence, func() {
			r.l.sweepFinished()
			finished <- struct{}{}
		}, r.l.reports, r.l.log)
	}()
	bound := time.NewTimer(serveAwaitBound)
	defer bound.Stop()
	select {
	case <-finished:
	case <-bound.C:
		t.Fatal("the sweep did not finish")
	}
	cancel()
	<-done

	r.at(swept + rigWait - time.Second)
	r.wantNoPass("a second short of the idle wait from the sweep")
	r.at(swept + rigWait)
	r.wantPass("the sweep that reviewed a repository", convergeWhyIdle)
	r.finish()
	if !r.lastPass().Reviewed(second) {
		t.Fatal("the pass after the sweep does not name the repository it reviewed")
	}

	// The same set again, which is what every later sweep of an idle store finds.
	later := swept + 24*time.Hour
	r.set(later)
	r.l.sweepFinished()
	r.at(later + 24*time.Hour)
	r.wantNoPass("a sweep that reviewed nothing new")
}

// TestConvergeRearmsWhileBudgetLeavesWork: a pass its own limits stopped gets a
// later one, on the same terms as any other.
func TestConvergeRearmsWhileBudgetLeavesWork(t *testing.T) {
	const after = 2 * time.Hour
	budget := store.ConvergeReport{Merged: 1, Pending: 4, Skipped: map[store.SkipReason]int{store.SkipHashBudget: 4}}
	limit := store.ConvergeReport{Merged: 1024, Pending: 4, MergeLimited: true}
	// first starts a pass that leaves rep's work and ends it at ended.
	first := func(r *loopRig, rep store.ConvergeReport, ended time.Duration) {
		r.t.Helper()
		r.fence.swept()
		r.rep = rep
		r.at(after)
		r.wantPass("the start trigger", convergeWhyIdle)
		r.set(ended)
		r.finish()
		r.lastPass()
	}
	for name, rep := range map[string]store.ConvergeReport{"the hash budget": budget, "the merge limit": limit} {
		t.Run(name+" takes a later pass, an idle wait after this one ended", func(t *testing.T) {
			r := newLoopRig(t)
			ended := after + time.Minute
			first(r, rep, ended)
			r.at(ended + rigWait - time.Second)
			r.wantNoPass("a second short of the idle wait")
			r.rep = store.ConvergeReport{Merged: 4}
			r.at(ended + rigWait)
			r.wantPass("the work the limit left", convergeWhyIdle)
			r.finish()
			r.lastPass()
			r.at(ended + 24*time.Hour)
			r.wantNoPass("the work is done")
		})
	}
	t.Run("passes go on as long as they merge", func(t *testing.T) {
		r := newLoopRig(t)
		first(r, budget, after)
		at := after
		for i := range 3 * serveConvergeMaxFruitless {
			at += rigWait
			r.at(at)
			r.wantPass(fmt.Sprintf("later pass %d", i), convergeWhyIdle)
			r.finish()
			r.lastPass()
		}
	})
	t.Run("a live session holds the later pass, with no bound of its own", func(t *testing.T) {
		r := newLoopRig(t)
		first(r, budget, after)
		r.sessions.Store(1)
		r.at(after + 24*time.Hour)
		r.wantNoPass("a live session")
		r.sessions.Store(0)
		r.at(after + 24*time.Hour + rigWait)
		r.wantPass("idle again", convergeWhyIdle)
	})
	t.Run("low space does not skip the spacing", func(t *testing.T) {
		r := newLoopRig(t)
		first(r, budget, after)
		r.free.Store(1)
		r.at(after + serveConvergeFreeEvery)
		r.wantNoPass("low space inside the spacing")
		r.at(after + serveConvergeIdle - time.Second)
		r.wantNoPass("low space a second short of the spacing")
		r.at(after + serveConvergeIdle)
		r.wantPass("low space past the spacing", convergeWhyLowSpace)
	})
	t.Run("a commit during the pass keeps its own bound", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.rep = budget
		r.at(after)
		r.wantPass("the start trigger", convergeWhyIdle)
		r.commitAt(after + time.Second)
		r.set(after + time.Minute)
		r.finish()
		r.lastPass()
		r.sessions.Store(1)
		r.at(after + time.Second + serveConvergeBound - time.Second)
		r.wantNoPass("inside the commit's bound")
		r.at(after + time.Second + serveConvergeBound)
		r.wantPass("the commit's bound", convergeWhyBound)
	})
	t.Run("a pass an upload stopped keeps its trigger and its bound", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		r.rep = budget
		r.commitAt(after)
		r.at(after + rigWait)
		r.wantPass("idle", convergeWhyIdle)
		r.sessions.Store(1)
		r.at(after + rigWait + time.Second)
		r.finish()
		r.at(after + serveConvergeBound)
		r.wantPass("the stopped pass's bound stands", convergeWhyBound)
		r.l.cur.cancel()
		r.finish()
	})
}

// TestConvergeDoesNotSpinOnPermanentSkips: what a later pass would only repeat
// sets no trigger, and passes that leave work but get nowhere stop at the cap.
func TestConvergeDoesNotSpinOnPermanentSkips(t *testing.T) {
	const after = 2 * time.Hour
	failed := errors.New("sync failed")
	budget := map[store.SkipReason]int{store.SkipHashBudget: 4}
	t.Run("permanent skips", func(t *testing.T) {
		tests := []struct {
			name string
			rep  store.ConvergeReport
			err  error
		}{
			{"not reviewed", store.ConvergeReport{Pending: 2, Skipped: map[store.SkipReason]int{store.SkipNotReviewed: 2}}, nil},
			{"keeper full", store.ConvergeReport{Pending: 2, Skipped: map[store.SkipReason]int{store.SkipKeeperFull: 2}}, nil},
			{"no keeper", store.ConvergeReport{Pending: 2, CorruptKeepers: 1, Skipped: map[store.SkipReason]int{store.SkipNoKeeper: 2}}, nil},
			{"a sync failure with nothing else", store.ConvergeReport{Pending: 2, Skipped: map[store.SkipReason]int{store.SkipSync: 1}}, failed},
			{"a merge beside them", store.ConvergeReport{Merged: 1, Pending: 2, Skipped: map[store.SkipReason]int{store.SkipNotReviewed: 2}}, nil},
			{"the merge limit with nothing pending", store.ConvergeReport{Merged: 1024, MergeLimited: true}, nil},
			{"a truncated scan, which reads the same entries next time", store.ConvergeReport{Pending: 2, ScanTruncated: true}, nil},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				r := newLoopRig(t)
				r.fence.swept()
				r.rep, r.passErr = tt.rep, tt.err
				r.at(after)
				r.wantPass("the start trigger", convergeWhyIdle)
				r.finish()
				r.lastPass()
				if got, _ := r.passesFrom(after); got != 0 {
					t.Errorf("%d more passes with nothing a later pass could do", got)
				}
				r.free.Store(1)
				r.at(after + 365*24*time.Hour)
				r.wantNoPass("low space with no commit since")
			})
		}
	})
	t.Run("work left and nothing merged", func(t *testing.T) {
		tests := []struct {
			name string
			rep  store.ConvergeReport
			err  error
		}{
			{"a corrupt keeper", store.ConvergeReport{Pending: 4, CorruptKeepers: 1, HashedBytes: 16 << 30, Skipped: budget}, nil},
			{"a repeating failure", store.ConvergeReport{Pending: 4, Skipped: budget}, failed},
			{"a repeating failure that still merges", store.ConvergeReport{Merged: 1, Pending: 4, Skipped: budget}, failed},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				r := newLoopRig(t)
				r.fence.swept()
				r.rep, r.passErr = tt.rep, tt.err
				got, at := r.passesFrom(0)
				if got != serveConvergeMaxFruitless {
					t.Fatalf("%d passes, want the cap of %d", got, serveConvergeMaxFruitless)
				}
				r.commitAt(at + time.Hour)
				r.at(at + time.Hour + rigWait)
				r.wantPass("a commit past the cap", convergeWhyIdle)
				r.finish()
				r.lastPass()
				if more, _ := r.passesFrom(at + time.Hour); more != 0 {
					t.Errorf("%d passes of its own after the commit's, past the cap", more)
				}
			})
		}
	})
	t.Run("a merge clears the count", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.rep = store.ConvergeReport{Pending: 4, Skipped: budget}
		at := time.Duration(0)
		// One short of the cap, a merge, and then the cap's whole allowance.
		merged := make([]int, 2*serveConvergeMaxFruitless)
		merged[serveConvergeMaxFruitless-1] = 1
		for i, m := range merged {
			r.rep.Merged = m
			at += 24 * time.Hour
			r.at(at)
			r.wantPass(fmt.Sprintf("pass %d", i), convergeWhyIdle)
			r.finish()
			r.lastPass()
		}
		r.at(at + 24*time.Hour)
		r.wantNoPass("past the cap again")
	})
}

// drip commits every every and looks at the loop each tick for span from from,
// ending each pass as it starts. It returns when the passes started.
func (r *loopRig) drip(from, span, every time.Duration) []time.Duration {
	r.t.Helper()
	var starts []time.Duration
	for t := time.Duration(0); t < span; t += serveConvergeTick {
		if t%every == 0 {
			r.commitAt(from + t)
		}
		r.at(from + t)
		if r.l.cur != nil {
			starts = append(starts, from+t)
			r.finish()
			r.lastPass()
		}
	}
	return starts
}

// TestConvergeLowSpaceKeepsItsSpacing: with space low a commit starts a pass with
// no idle wait, and no upload stops that pass, so a commit must not also shorten
// the rest after the last one.
func TestConvergeLowSpaceKeepsItsSpacing(t *testing.T) {
	const after = 2 * time.Hour
	const span = 5 * time.Minute
	budget := map[store.SkipReason]int{store.SkipHashBudget: 4}
	// bound is what the rest allows: one pass per rest.
	bound := int(span / serveConvergeIdle)
	tests := []struct {
		name string
		rep  store.ConvergeReport
	}{
		{"nothing to merge", store.ConvergeReport{}},
		{"a hash budget spent for nothing", store.ConvergeReport{Pending: 4, HashedBytes: 16 << 30, Skipped: budget}},
	}
	for _, tt := range tests {
		t.Run("a commit each tick does not shorten the rest: "+tt.name, func(t *testing.T) {
			r := newLoopRig(t)
			r.fence.swept()
			r.free.Store(1)
			r.rep = tt.rep
			starts := r.drip(after, span, serveConvergeTick)
			if len(starts) > bound {
				t.Fatalf("%d low-space passes in %v, want at most %d: %v", len(starts), span, bound, starts)
			}
			for i := 1; i < len(starts); i++ {
				if gap := starts[i] - starts[i-1]; gap < serveConvergeIdle {
					t.Errorf("pass %d started %v after the last, inside the rest", i, gap)
				}
			}
			if r.l.fruitless < serveConvergeMaxFruitless {
				t.Errorf("%d low-space passes that merged nothing counted %d, want the cap of %d", len(starts), r.l.fruitless, serveConvergeMaxFruitless)
			}
		})
	}
	for name, rep := range map[string]store.ConvergeReport{
		"with work left":    {Merged: 8, ReclaimedBytes: 1 << 30, Pending: 4, Skipped: budget},
		"with no work left": {Merged: 8, ReclaimedBytes: 1 << 30},
	} {
		t.Run("a pass that frees space keeps going, one rest apart, "+name, func(t *testing.T) {
			r := newLoopRig(t)
			r.fence.swept()
			r.free.Store(1)
			r.rep = rep
			starts := r.drip(after, span, serveConvergeTick)
			if len(starts) != bound {
				t.Fatalf("%d low-space passes in %v, want %d: %v", len(starts), span, bound, starts)
			}
			if r.l.fruitless != 0 {
				t.Errorf("passes that merged counted %d", r.l.fruitless)
			}
		})
	}
	t.Run("a merge after passes that got nowhere clears the count", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.free.Store(1)
		r.drip(after, serveConvergeIdle, serveConvergeTick)
		if r.l.fruitless == 0 {
			t.Fatal("a low-space pass that merged nothing did not count")
		}
		r.rep = store.ConvergeReport{Merged: 1}
		r.commitAt(after + serveConvergeIdle)
		r.at(after + serveConvergeIdle)
		r.wantPass("past the rest", convergeWhyLowSpace)
		r.finish()
		r.lastPass()
		if r.l.fruitless != 0 {
			t.Errorf("a merge left the count at %d", r.l.fruitless)
		}
	})
}

// TestConvergeCommitsCannotDriveFruitlessPasses: past the cap, how much a pusher can
// make the loop hash is bounded by time, however many commits it sends, until a
// pass merges something.
func TestConvergeCommitsCannotDriveFruitlessPasses(t *testing.T) {
	const span = 6 * time.Hour
	// bound is one pass per spacing.
	bound := int(span / serveConvergeFruitlessSpacing)
	spent := store.ConvergeReport{Pending: 4, CorruptKeepers: 1, HashedBytes: 16 << 30, Skipped: map[store.SkipReason]int{store.SkipHashBudget: 4}}
	// atCap runs the passes that reach the cap and returns the last look's time.
	atCap := func(r *loopRig) time.Duration {
		r.t.Helper()
		r.fence.swept()
		r.rep = spent
		got, at := r.passesFrom(0)
		if got != serveConvergeMaxFruitless {
			r.t.Fatalf("%d passes, want the cap of %d", got, serveConvergeMaxFruitless)
		}
		return at
	}
	wantSpaced := func(t *testing.T, starts []time.Duration, limit int) {
		t.Helper()
		if len(starts) > limit {
			t.Fatalf("%d passes in %v, want at most %d", len(starts), span, limit)
		}
		if len(starts) == 0 {
			t.Fatal("no pass: a commit past the cap must still get one")
		}
	}
	tests := []struct {
		name  string
		every time.Duration
		low   bool
	}{
		{"a commit every 2 minutes, each followed by an idle store", 2 * time.Minute, false},
		{"a commit every tick, so that only the bound starts a pass", serveConvergeTick, false},
		{"a commit every tick on low space", serveConvergeTick, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newLoopRig(t)
			at := atCap(r)
			if tt.low {
				r.free.Store(1)
			}
			starts := r.drip(at, span, tt.every)
			wantSpaced(t, starts, bound)
			for i := 1; i < len(starts); i++ {
				if gap := starts[i] - starts[i-1]; gap < serveConvergeFruitlessSpacing {
					t.Errorf("pass %d started %v after the last, inside the spacing", i, gap)
				}
			}
		})
	}
	t.Run("a pass that hashes under the budget and leaves no work counts", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.rep = store.ConvergeReport{Pending: 2, CorruptKeepers: 1, HashedBytes: 15 << 30, Skipped: map[store.SkipReason]int{store.SkipNoKeeper: 2}}
		starts := r.drip(2*time.Hour, span, 2*time.Minute)
		wantSpaced(t, starts, serveConvergeMaxFruitless+bound)
	})
	t.Run("a failure that leaves no work counts", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.passErr = errors.New("sync failed")
		starts := r.drip(2*time.Hour, span, 2*time.Minute)
		wantSpaced(t, starts, serveConvergeMaxFruitless+bound)
	})
	t.Run("a pass an upload stops after hashing counts", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		r.rep = store.ConvergeReport{HashedBytes: 1 << 30}
		from := 2 * time.Hour
		passes := 0
		for d := time.Duration(0); d < span; d += serveConvergeTick {
			if d%(2*time.Minute) == 0 {
				r.commitAt(from + d)
			}
			r.at(from + d)
			if r.l.cur == nil {
				continue
			}
			passes++
			r.sessions.Store(1)
			r.l.step(r.ctx, r.t0.Add(from+d))
			r.sessions.Store(0)
			if !r.l.cur.stopped {
				r.l.cur.cancel() // past its bound, which no upload stops
			}
			r.finish()
			r.lastPass()
		}
		if limit := serveConvergeMaxFruitless + bound; passes > limit {
			t.Fatalf("%d passes in %v, want at most %d", passes, span, limit)
		}
	})
	t.Run("a sweep's re-arm does not shorten the spacing", func(t *testing.T) {
		r := newLoopRig(t)
		at := atCap(r)
		r.commitAt(at)
		r.at(at + rigWait)
		r.wantPass("a commit past the cap", convergeWhyIdle)
		ended := at + rigWait
		r.finish()
		r.lastPass()
		r.l.rearm(r.t0.Add(ended))
		r.at(ended + serveConvergeFruitlessSpacing - time.Second)
		r.wantNoPass("a second short of the spacing")
		r.at(ended + serveConvergeFruitlessSpacing)
		r.wantPass("past the spacing", convergeWhyIdle)
	})
	t.Run("the spacing runs from the end of the pass", func(t *testing.T) {
		r := newLoopRig(t)
		at := atCap(r)
		r.commitAt(at)
		r.at(at + rigWait)
		r.wantPass("a commit past the cap", convergeWhyIdle)
		ended := at + rigWait + 10*time.Minute
		r.set(ended)
		r.finish()
		r.lastPass()
		r.commitAt(ended)
		r.at(ended + serveConvergeFruitlessSpacing - time.Second)
		r.wantNoPass("a second short of the spacing")
		r.at(ended + serveConvergeFruitlessSpacing)
		r.wantPass("the commit's bound, past the spacing", convergeWhyBound)
	})
	t.Run("a pass that merges ends the spacing", func(t *testing.T) {
		for name, stopped := range map[string]bool{"finished": false, "stopped by an upload": true} {
			t.Run(name, func(t *testing.T) {
				r := newLoopRig(t)
				at := atCap(r)
				r.rep = store.ConvergeReport{Merged: 1}
				r.hold = stopped
				r.commitAt(at)
				r.at(at + rigWait)
				r.wantPass("a commit past the cap", convergeWhyIdle)
				ended := at + rigWait
				if stopped {
					r.sessions.Store(1)
					r.l.step(r.ctx, r.t0.Add(ended))
					r.sessions.Store(0)
				}
				r.finish()
				r.lastPass()
				if r.l.fruitless != 0 {
					t.Fatalf("a merge left the count at %d", r.l.fruitless)
				}
				r.hold = false
				r.rep = store.ConvergeReport{}
				r.commitAt(ended)
				r.at(ended + rigWait + time.Second)
				r.wantPass("the next commit, one idle wait on", convergeWhyIdle)
			})
		}
	})
}

// TestConvergeLoopStopsForAnUpload pins which passes an upload stops.
func TestConvergeLoopStopsForAnUpload(t *testing.T) {
	const after = 2 * time.Hour
	awaitCtx := func(r *loopRig) context.Context {
		r.t.Helper()
		bound := time.NewTimer(serveAwaitBound)
		defer bound.Stop()
		select {
		case ctx := <-r.passCt:
			return ctx
		case <-bound.C:
			r.t.Fatal("the pass never ran")
			return nil
		}
	}
	t.Run("an upload stops the pass, and the trigger and its bound stand", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		r.commitAt(after)
		r.at(after + rigWait)
		r.wantPass("idle", convergeWhyIdle)
		ctx := awaitCtx(r)
		if ctx.Err() != nil {
			t.Fatal("the pass began cancelled")
		}
		r.sessions.Store(1)
		r.at(after + rigWait + time.Second)
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("the upload left the pass running: %v", ctx.Err())
		}
		r.finish()
		r.wantNoPass("the pass stopped")
		if strings.Contains(r.logs.String(), `"level":"ERROR"`) {
			t.Errorf("a pass an upload stopped logged an error:\n%s", r.logs.String())
		}
		r.at(after + serveConvergeBound - time.Second)
		r.wantNoPass("still inside the first commit's bound")
		r.at(after + serveConvergeBound)
		r.wantPass("the first commit's bound still stands", convergeWhyBound)
	})
	t.Run("past the bound an upload stops nothing", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		r.commitAt(after)
		r.at(after + serveConvergeBound)
		r.wantPass("the bound", convergeWhyBound)
		ctx := awaitCtx(r)
		r.sessions.Store(1)
		r.at(after + serveConvergeBound + time.Second)
		if ctx.Err() != nil {
			t.Fatal("an upload stopped a pass past its bound")
		}
		r.l.cur.cancel()
		r.finish()
	})
	t.Run("the bound can pass during a pass", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		r.commitAt(after)
		r.at(after + rigWait)
		r.wantPass("idle", convergeWhyIdle)
		ctx := awaitCtx(r)
		r.sessions.Store(1)
		r.at(after + serveConvergeBound)
		if ctx.Err() != nil {
			t.Fatal("an upload stopped a pass past its bound")
		}
		r.l.cur.cancel()
		r.finish()
	})
	t.Run("an upload does not stop a low-space pass", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		r.free.Store(1)
		r.commitAt(after)
		r.at(after)
		r.wantPass("low space", convergeWhyLowSpace)
		ctx := awaitCtx(r)
		r.sessions.Store(1)
		r.free.Store(1 << 40)
		r.at(after + serveConvergeFreeEvery)
		if ctx.Err() != nil {
			t.Fatal("an upload stopped a low-space pass after the space came back")
		}
		r.l.cur.cancel()
		r.finish()
		r.at(after + 24*time.Hour)
		r.wantNoPass("the low-space pass cleared its trigger")
	})
	t.Run("an upload does not stop a pass while space is low", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		r.commitAt(after)
		r.at(after + rigWait)
		r.wantPass("idle", convergeWhyIdle)
		ctx := awaitCtx(r)
		r.free.Store(1)
		r.sessions.Store(1)
		r.at(after + rigWait + serveConvergeFreeEvery)
		if ctx.Err() != nil {
			t.Fatal("an upload stopped a pass with space low")
		}
		r.l.cur.cancel()
		r.finish()
	})
}

// TestConvergeLoopHoldsItsRotation fails when the wiring drops the rotation, which
// store.Converge takes silently as nil and answers with the fixed order, and when
// a pass gets a new one, which forgets the order it exists to keep.
func TestConvergeLoopHoldsItsRotation(t *testing.T) {
	r := newLoopRig(t)
	r.fence.swept()
	var seen []*store.ConvergeRotation
	for i := range 3 {
		at := time.Duration(i+1) * 24 * time.Hour
		r.commitAt(at)
		r.at(at + rigWait)
		r.wantPass(fmt.Sprintf("pass %d", i), convergeWhyIdle)
		r.finish()
		seen = append(seen, (<-r.passes).Rotation)
	}
	for i, rot := range seen {
		if rot == nil {
			t.Fatalf("pass %d ran with no rotation", i)
		}
		if rot != seen[0] {
			t.Fatalf("pass %d ran with a rotation of its own", i)
		}
	}
}

// TestConvergeLoopReadsTheMarker pins the pass's reviewed input to the GC marker
// for this store's id, read at each pass.
func TestConvergeLoopReadsTheMarker(t *testing.T) {
	name := func(s string) ref.Name {
		t.Helper()
		n, err := ref.ParseName(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	pass := func(r *loopRig, at time.Duration) (store.ConvergeOptions, bool) {
		r.t.Helper()
		r.commitAt(at)
		r.at(at + rigWait)
		r.wantPass("a commit", convergeWhyIdle)
		r.finish()
		select {
		case o := <-r.passes:
			return o, true
		default:
			return store.ConvergeOptions{}, false
		}
	}
	t.Run("names only what the marker names, read afresh", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		initRepo(t, r.st, "first")
		o, ok := pass(r, 24*time.Hour)
		if !ok {
			t.Fatal("no pass over a store with no marker")
		}
		if o.Reviewed(name("first")) {
			t.Fatal("a store with no marker names a repository")
		}
		if err := gc.WriteMarker(r.st, r.t0); err != nil {
			t.Fatal(err)
		}
		o, ok = pass(r, 48*time.Hour)
		if !ok {
			t.Fatal("no pass over a store with a marker")
		}
		if !o.Reviewed(name("first")) {
			t.Fatal("the marker's repository is not named")
		}
		if o.Reviewed(name("second")) {
			t.Fatal("a repository the marker does not name is named")
		}
	})
	t.Run("a marker for another store names none", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		initRepo(t, r.st, "first")
		if err := gc.WriteMarker(r.st, r.t0); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{"ran": r.t0, "store": strings.Repeat("0", 32), "reviewed": []string{"first"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r.st.StateDir(), gc.MarkerName), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		o, ok := pass(r, 24*time.Hour)
		if !ok {
			t.Fatal("no pass")
		}
		if o.Reviewed(name("first")) {
			t.Fatal("another store's marker named a repository")
		}
	})
	t.Run("an unreadable marker runs no pass and reports the failure", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		if err := os.Mkdir(filepath.Join(r.st.StateDir(), gc.MarkerName), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, ok := pass(r, 24*time.Hour); ok {
			t.Fatal("a pass ran on an unreadable marker")
		}
		if !strings.Contains(r.logs.String(), `"level":"ERROR","msg":"registry dedupe: pass finished"`) {
			t.Errorf("no error logged:\n%s", r.logs.String())
		}
	})
}

// initRepo gives st an empty repository.
func initRepo(t *testing.T, st *store.Store, repo string) {
	t.Helper()
	n, err := ref.ParseName(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Init(context.Background(), n); err != nil {
		t.Fatal(err)
	}
}

// TestConvergeLoopNeverBesideASweep pins the two apart in this process: a pass
// waits for a sweep, and a sweep cannot start during a pass.
func TestConvergeLoopNeverBesideASweep(t *testing.T) {
	r := newLoopRig(t)
	r.fence.swept()
	r.hold = true
	const after = 2 * time.Hour
	r.fence.mu.Lock()
	r.at(after)
	r.wantNoPass("a sweep is running")
	r.fence.mu.Unlock()
	r.at(after + time.Second)
	r.wantPass("the sweep finished", convergeWhyIdle)
	if r.fence.mu.TryLock() {
		t.Fatal("a sweep could start during the pass")
	}
	r.l.cur.cancel()
	r.finish()
	if !r.fence.mu.TryLock() {
		t.Fatal("the pass kept the fence")
	}
	r.fence.mu.Unlock()
}

// TestSweepWaitsForAPass is the other half: the sweep loop takes the fence, so a
// sweep due during a pass waits for it, and its first sweep opens the fence.
func TestSweepWaitsForAPass(t *testing.T) {
	r := newLoopRig(t)
	collector, err := gc.New(r.st, gc.Options{Grace: time.Millisecond, Log: r.l.log})
	if err != nil {
		t.Fatal(err)
	}
	r.fence.mu.Lock()
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sweepLoop(ctx, collector, time.Millisecond, time.Hour, r.fence, func() {}, r.l.reports, r.l.log)
	}()
	defer func() {
		cancel()
		<-done
	}()
	swept := func() bool {
		t.Helper()
		b, err := os.ReadFile(StatePath(r.work))
		if err != nil {
			t.Fatal(err)
		}
		st, err := ParseState(b)
		if err != nil {
			t.Fatal(err)
		}
		return st.GC != nil
	}
	// Well past the sweep's due time. This can only pass wrongly, never fail wrongly.
	held := time.NewTimer(200 * time.Millisecond)
	defer held.Stop()
	<-held.C
	if swept() {
		t.Fatal("a sweep ran beside a pass")
	}
	if r.fence.hasSwept() {
		t.Fatal("the fence opened with no sweep finished")
	}
	r.fence.mu.Unlock()
	awaitDirChange(t, filepath.Dir(StatePath(r.work)), "the sweep", swept)
}

// TestConvergeLoopReadsFreeSpaceEvery30Seconds pins the read's cadence.
func TestConvergeLoopReadsFreeSpaceEvery30Seconds(t *testing.T) {
	r := newLoopRig(t)
	for s := range 61 {
		r.at(time.Duration(s) * time.Second)
	}
	if got := r.reads.Load(); got != 3 {
		t.Errorf("%d reads over 60 s, want 3 (at 0, 30 and 60 s)", got)
	}
}

// TestConvergeLoopReportsItsPass pins the status object and the log record. The
// status holds no digest or repository name, and a pass the server's own stop
// ended reports nothing.
func TestConvergeLoopReportsItsPass(t *testing.T) {
	t.Run("a finished pass", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.rep = store.ConvergeReport{
			Merged: 3, ReclaimedBytes: 4096, Pending: 2, CorruptTargets: 1, CorruptReplaced: 1,
			Skipped: map[store.SkipReason]int{store.SkipNotReviewed: 2},
		}
		const after = 2 * time.Hour
		r.at(after)
		r.wantPass("the start trigger", convergeWhyIdle)
		r.finish()
		b, err := os.ReadFile(StatePath(r.work))
		if err != nil {
			t.Fatal(err)
		}
		st, err := ParseState(b)
		if err != nil {
			t.Fatal(err)
		}
		d := st.Dedupe
		if d == nil {
			t.Fatal("no dedupe object")
		}
		if !d.LastPass.Equal(r.t0.Add(after)) || d.Merged != 3 || d.ReclaimedBytes != 4096 || d.Pending != 2 || d.CorruptReplaced != 1 || d.Skipped["not-reviewed"] != 2 {
			t.Errorf("dedupe %+v", d)
		}
		if !strings.Contains(r.logs.String(), `"msg":"registry dedupe: pass finished"`) {
			t.Errorf("no record of the pass:\n%s", r.logs.String())
		}
	})
	t.Run("the server's stop", func(t *testing.T) {
		r := newLoopRig(t)
		r.fence.swept()
		r.hold = true
		ctx, cancel := context.WithCancel(r.ctx)
		r.ctx = ctx
		r.at(2 * time.Hour)
		r.wantPass("the start trigger", convergeWhyIdle)
		cancel()
		r.finish()
		b, err := os.ReadFile(StatePath(r.work))
		if err != nil {
			t.Fatal(err)
		}
		st, err := ParseState(b)
		if err != nil {
			t.Fatal(err)
		}
		if st.Dedupe != nil {
			t.Errorf("a pass the stop ended reported %+v", st.Dedupe)
		}
	})
}

// TestWatchCommits pins what sets the trigger: a 201 to a POST or a PUT.
func TestWatchCommits(t *testing.T) {
	tests := []struct {
		name   string
		method string
		status int
		want   bool
	}{
		{"a blob commit or manifest push", http.MethodPut, http.StatusCreated, true},
		{"a mount or a whole-blob upload", http.MethodPost, http.StatusCreated, true},
		{"a session opened", http.MethodPost, http.StatusAccepted, false},
		{"a refused commit", http.MethodPut, http.StatusBadRequest, false},
		{"a chunk", http.MethodPatch, http.StatusAccepted, false},
		{"a delete", http.MethodDelete, http.StatusAccepted, false},
		{"a read", http.MethodGet, http.StatusOK, false},
		{"a head", http.MethodHead, http.StatusOK, false},
		{"a first status of 200 written implicitly", http.MethodPut, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := false
			h := watchCommits(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
			}), func() { got = true })
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tt.method, "http://registry.test/v2/a/x", nil))
			if got != tt.want {
				t.Errorf("committed = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("a read keeps the connection's response writer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := watchCommits(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if w != http.ResponseWriter(rec) {
				t.Errorf("a read's writer is a %T", w)
			}
		}), func() {})
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://registry.test/v2/a/x", nil))
	})
	t.Run("a write's deadline reaches the response underneath", func(t *testing.T) {
		h := watchCommits(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Errorf("flush through the watch: %v", err)
			}
		}), func() {})
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "http://registry.test/v2/a/x", nil))
	})
}

// TestServeConvergeCadence pins the loop's timings.
func TestServeConvergeCadence(t *testing.T) {
	if serveConvergeIdle != time.Minute || serveConvergeJitter != time.Minute || serveConvergeBound != 15*time.Minute ||
		serveConvergeFreeEvery != 30*time.Second || serveConvergeLowFree != 4<<30 {
		t.Errorf("idle %v, jitter %v, bound %v, free every %v, low free %d", serveConvergeIdle, serveConvergeJitter,
			serveConvergeBound, serveConvergeFreeEvery, uint64(serveConvergeLowFree))
	}
	if serveConvergeMaxFruitless != 3 || serveConvergeFruitlessSpacing != time.Hour {
		t.Errorf("max fruitless passes %d, spacing %v", serveConvergeMaxFruitless, serveConvergeFruitlessSpacing)
	}
}

// pushImage pushes a tagged one-layer image through the served registry, so each
// write goes through the handler the server really runs, and returns the layer's
// digest.
func pushImage(t *testing.T, c *http.Client, repo, tag string, config, layer []byte) string {
	t.Helper()
	base := "http://registry.test/v2/" + repo
	send := func(method, url string, body []byte, contentType string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(auth.UserPush, testPushSecret)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	put := func(b []byte) string {
		t.Helper()
		sum := sha256.Sum256(b)
		d := "sha256:" + hex.EncodeToString(sum[:])
		resp := send(http.MethodPost, base+"/blobs/uploads/", nil, "")
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("open an upload in %s: %d", repo, resp.StatusCode)
		}
		resp = send(http.MethodPut, "http://registry.test"+resp.Header.Get("Location")+"?digest="+d, b, "application/octet-stream")
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("commit into %s: %d", repo, resp.StatusCode)
		}
		return d
	}
	configD, layerD := put(config), put(layer)
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configD, "size": len(config)},
		"layers":        []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layerD, "size": len(layer)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := send(http.MethodPut, base+"/manifests/"+tag, manifest, "application/vnd.oci.image.manifest.v1+json")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push a manifest to %s: %d", repo, resp.StatusCode)
	}
	return layerD
}

// TestConvergeLoopRunsWhenIdle is the loop through the running server: real
// commits over the served handler set the trigger, the marker gates the targets,
// and an idle store converges a blob pushed to two repositories into one inode,
// with the status object and the log saying so. Only the clock and the ticks are
// the test's.
func TestConvergeLoopRunsWhenIdle(t *testing.T) {
	work := writeTestServeConfig(t, nil)
	if err := WriteState(work, State{State: StateServing, Port: 6450, Addr: "127.0.0.1:6450"}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(t0.UnixNano())
	ticks := make(chan time.Time)
	l := newMemListener()
	d := testServeDeps(l)
	// The first sweep comes soon and the next never, so the marker is the test's.
	d.gcGrace, d.gcInterval = 20*time.Millisecond, time.Hour
	d.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	d.jitter = func() time.Duration { return rigJitter }
	d.convergeTick = ticks
	result, cancel := runTestServe(t, work, d)
	c := memClient(t, l)

	dedupe := func() *DedupeStatus {
		t.Helper()
		b, err := os.ReadFile(StatePath(work))
		if err != nil {
			t.Fatal(err)
		}
		st, err := ParseState(b)
		if err != nil {
			t.Fatal(err)
		}
		return st.Dedupe
	}
	awaitDirChange(t, filepath.Dir(StatePath(work)), "the first sweep", func() bool {
		b, err := os.ReadFile(StatePath(work))
		if err != nil {
			t.Fatal(err)
		}
		st, err := ParseState(b)
		if err != nil {
			t.Fatal(err)
		}
		return st.GC != nil
	})

	st, err := store.OpenWorkDir(work)
	if err != nil {
		t.Fatal(err)
	}
	blob := func(repo, d string) string {
		t.Helper()
		return filepath.Join(st.Root(), repo, "blobs", "sha256", strings.TrimPrefix(d, "sha256:"))
	}
	shared := func(d string, repos ...string) bool {
		t.Helper()
		first, err := os.Stat(blob(repos[0], d))
		if err != nil {
			t.Fatal(err)
		}
		for _, repo := range repos[1:] {
			next, err := os.Stat(blob(repo, d))
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(first, next) {
				return false
			}
		}
		return true
	}
	tick := func() {
		t.Helper()
		bound := time.NewTimer(serveAwaitBound)
		defer bound.Stop()
		select {
		case ticks <- time.Time{}:
		case <-bound.C:
			t.Fatal("the loop took no tick")
		}
	}
	// settle returns once the loop has finished the step of an earlier tick.
	settle := func() {
		t.Helper()
		tick()
		tick()
	}
	// awaitPass ticks until the record shows a pass finished after since.
	awaitPass := func(since time.Time) *DedupeStatus {
		t.Helper()
		pace := time.NewTicker(time.Millisecond)
		defer pace.Stop()
		bound := time.NewTimer(serveAwaitBound)
		defer bound.Stop()
		for {
			if s := dedupe(); s != nil && !s.LastPass.Before(since) {
				return s
			}
			select {
			case ticks <- time.Time{}:
			case <-bound.C:
				t.Fatal("no pass ran")
			}
			<-pace.C
		}
	}

	// A blob in two repositories, both reviewed, both with a tagged row.
	layer := bytes.Repeat([]byte("layer"), 4096)
	repos := []string{"team/a", "team/b"}
	var first string
	for _, repo := range repos {
		first = pushImage(t, c, repo, "v1", []byte(`{"a":1}`), layer)
	}
	if shared(first, repos...) {
		t.Fatal("the push path linked the copies")
	}
	if err := gc.WriteMarker(st, t0); err != nil {
		t.Fatal(err)
	}

	// A tick short of the idle wait does nothing.
	clock.Store(t0.Add(rigWait - time.Second).UnixNano())
	settle()
	if got := dedupe(); got != nil {
		t.Fatalf("a pass ran inside the idle wait: %+v", got)
	}
	// The wait is over.
	due := t0.Add(rigWait)
	clock.Store(due.UnixNano())
	got := awaitPass(due)
	if got.Merged == 0 || got.ReclaimedBytes < int64(len(layer)) {
		t.Errorf("the first pass: %+v, want the layer merged and its bytes reclaimed", got)
	}
	if !shared(first, repos...) {
		t.Fatal("the pass left the copies apart")
	}

	// The trigger is clear, so only a commit brings a second pass: the handler the
	// server runs is what set it. These two commits land while the clock stands
	// still, and the next pass is due a wait after them.
	t1 := due.Add(time.Hour)
	clock.Store(t1.UnixNano())
	second := bytes.Repeat([]byte("other"), 4096)
	var next string
	for _, repo := range repos {
		next = pushImage(t, c, repo, "v2", []byte(`{"a":2}`), second)
	}
	if shared(next, repos...) {
		t.Fatal("the push path linked the second copies")
	}
	clock.Store(t1.Add(rigWait - time.Second).UnixNano())
	settle()
	if shared(next, repos...) {
		t.Fatal("a pass ran inside the wait after a commit")
	}
	dueAgain := t1.Add(rigWait)
	clock.Store(dueAgain.UnixNano())
	got = awaitPass(dueAgain)
	if !shared(next, repos...) {
		t.Fatalf("the commit's pass left the copies apart: %+v", got)
	}

	// The registry still serves both, from the one inode.
	for _, repo := range repos {
		resp := do(t, c, http.MethodHead, "http://registry.test/v2/"+repo+"/blobs/"+next, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("HEAD %s after the merge: %d", repo, resp.StatusCode)
		}
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"team/a", "team/b", "sha256:", strings.TrimPrefix(next, "sha256:")} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the status object carries %q: %s", leak, raw)
		}
	}

	cancel()
	if err := awaitServeResult(t, result, "serve"); err != nil {
		t.Fatalf("serve: %v", err)
	}
	logged, err := os.ReadFile(LogPath(work))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"msg":"registry dedupe: pass started"`, `"msg":"registry dedupe: pass finished"`, `"msg":"dedupe merged a blob"`} {
		if !strings.Contains(string(logged), want) {
			t.Errorf("registry.log has no %s:\n%s", want, logged)
		}
	}
}
