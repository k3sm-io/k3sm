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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// goodRepo is a pushed repository with one orphan past the grace.
func (e *env) goodRepo(t *testing.T, repo string) digest.Digest {
	t.Helper()
	n := name(t, repo)
	e.keeper(t, n)
	return e.blob(t, n, []byte(repo+" orphan")).Digest
}

// TestFailureThatMayPassHoldsOnlyItsRepository fails one repository of a first
// sweep for a reason that does not pass by itself, and it holds no other: the
// next sweep deletes in the good one. Once the failure clears, the failed
// repository gets its own report-only sweep before anything in it goes.
func TestFailureThatMayPassHoldsOnlyItsRepository(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a mode-0 file")
	}
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	goodOrphan := e.goodRepo(t, "good")
	bad := name(t, "bad")
	img := e.keeper(t, bad)
	badOrphan := e.blob(t, bad, []byte("bad orphan")).Digest
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	p := e.blobFile(t, bad, img.manifest.Digest)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })

	rep, err := c.Sweep(e.ctx)
	if err == nil || errors.Is(err, ErrUnreadable) || !rep.ReportOnly || !slices.Equal(rep.Failed, []string{"bad"}) {
		t.Fatalf("first sweep: %+v, %v; want report-only with bad failed, not as unreadable", rep, err)
	}

	rep, err = c.Sweep(e.ctx)
	if err == nil || rep.ReportOnly || !slices.Equal(rep.Failed, []string{"bad"}) || !slices.Equal(rep.Reviewing, []string{"bad"}) {
		t.Fatalf("second sweep: %+v, %v; want good swept, bad failed and in review", rep, err)
	}
	if e.has(name(t, "good"), goodOrphan) {
		t.Fatal("a failure in another repository held the good one's orphan")
	}

	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	rep = e.sweep(t, c)
	if !slices.Equal(rep.Reviewing, []string{"bad"}) || len(rep.WouldReap) != 1 || !e.has(bad, badOrphan) {
		t.Fatalf("sweep after the repair: %+v, want bad reported on and its orphan kept", rep)
	}
	if rep := e.sweep(t, c); len(rep.Reviewing) != 0 || e.has(bad, badOrphan) {
		t.Fatalf("sweep after bad's review: %+v, want its orphan reaped", rep)
	}
}

// TestNothingReviewedWritesNoMarker fails the only repository of a first sweep:
// there is nothing to record, so the id is not minted for a store nobody has
// looked at.
func TestNothingReviewedWritesNoMarker(t *testing.T) {
	e := newEnv(t)
	n := name(t, "bad")
	e.clk.set(-2 * time.Hour)
	img := e.keeper(t, n)
	if err := os.Remove(e.blobFile(t, n, img.manifest.Digest)); err != nil {
		t.Fatal(err)
	}
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	rep, err := c.Sweep(e.ctx)
	if !errors.Is(err, ErrUnreadable) || !rep.ReportOnly {
		t.Fatalf("sweep: %+v, %v; want report-only and ErrUnreadable", rep, err)
	}
	if e.markerExists(t) {
		t.Fatal("a sweep that reviewed nothing wrote the marker")
	}
}

// TestUnreadableAtTheFirstSweepIsReviewedAfterRepair repairs a repository that
// could not be read at the first sweep. Nobody has seen what it would reap, so
// its first readable sweep only reports.
func TestUnreadableAtTheFirstSweepIsReviewedAfterRepair(t *testing.T) {
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	e.goodRepo(t, "good")
	bad := name(t, "bad")
	img := e.keeper(t, bad)
	orphan := e.blob(t, bad, []byte("bad orphan")).Digest
	p := e.blobFile(t, bad, img.manifest.Digest)
	aside := p + ".aside"
	if err := os.Rename(p, aside); err != nil {
		t.Fatal(err)
	}
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	if _, err := c.Sweep(e.ctx); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("first sweep: %v, want ErrUnreadable", err)
	}
	if err := os.Rename(aside, p); err != nil {
		t.Fatal(err)
	}

	rep := e.sweep(t, c)
	if !e.has(bad, orphan) || !slices.Equal(rep.Reviewing, []string{"bad"}) {
		t.Fatalf("sweep after the repair: %+v, want the orphan kept and bad reported on", rep)
	}
	e.sweep(t, c)
	if e.has(bad, orphan) {
		t.Fatal("the orphan survived the sweep after bad's review")
	}
}

// TestBrakedFirstSweepListsAndWaits brakes a first push at the first sweep. The
// report lists what the brake holds back, and the abandon horizon does not turn
// that into a delete nobody reviewed: the sweep where the brake lifts reports,
// and the one after it deletes.
func TestBrakedFirstSweepListsAndWaits(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	horizon := AbandonFactor * grace
	ds := e.firstPush(t, n, -horizon-6*time.Hour, -horizon-7*time.Hour)
	c := e.collector(t, -horizon-8*time.Hour)

	e.clk.set(-12 * time.Hour)
	rep, err := c.Sweep(e.ctx)
	if !errors.Is(err, ErrMassDelete) || !slices.Equal(rep.Stopped, []string{"app"}) {
		t.Fatalf("first sweep: %+v, %v; want ErrMassDelete for app", rep, err)
	}
	if !rep.ReportOnly || rep.Count(KindBlob) != len(ds) {
		t.Fatalf("first sweep: %+v, want report-only listing the %d blobs the brake holds", rep, len(ds))
	}

	e.clk.set(0)
	rep = e.sweep(t, c)
	if !rep.ReportOnly || rep.Count(KindBlob) != len(ds) || !e.hasAll(n, ds) {
		t.Fatalf("the sweep where the brake lifts: %+v, want it to report and keep the blobs", rep)
	}
	rep = e.sweep(t, c)
	if rep.ReportOnly || rep.Count(KindBlob) != len(ds) {
		t.Fatalf("the sweep after the review: %+v, want the %d blobs reaped", rep, len(ds))
	}
}

// TestReviewedSetIsNotBoundedBySize grows the marker past the old 4 KiB bound
// with nothing but repositories, which any pusher can create. A bound on the
// marker is a way to turn the collector off.
func TestReviewedSetIsNotBoundedBySize(t *testing.T) {
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	long := strings.Repeat("r", 120)
	n := name(t, "app")
	e.keeper(t, n)
	orphan := e.blob(t, n, []byte("orphan")).Digest
	for i := range 40 {
		other := name(t, fmt.Sprintf("%s%d", long, i))
		e.blob(t, other, []byte("blob"))
		e.putManifest(t, other, "v1", "application/vnd.oci.image.index.v1+json", indexBody(t))
	}
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	e.sweep(t, c)
	fi, err := os.Stat(filepath.Join(e.s.StateDir(), MarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() <= 4096 {
		t.Fatalf("the marker is %d bytes; the test exercises nothing", fi.Size())
	}
	e.sweep(t, c)
	if e.has(n, orphan) {
		t.Fatal("the orphan survived: the sweep did not read its own marker")
	}
}

// TestMarkerWithoutAReviewedSetReportsOnce reads a marker in the form an older
// k3sm wrote. It says the store was reviewed, not which repositories were, so
// every repository gets one report-only sweep.
func TestMarkerWithoutAReviewedSetReportsOnce(t *testing.T) {
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	orphan := e.goodRepo(t, "app")
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	id, err := e.s.EnsureID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]string{"ran": "2026-01-01T00:00:00Z", "store": id})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.s.StateDir(), MarkerName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	n := name(t, "app")
	if rep := e.sweep(t, c); !rep.ReportOnly || !e.has(n, orphan) {
		t.Fatalf("sweep over the older marker: %+v, want report-only and the orphan kept", rep)
	}
	if rep := e.sweep(t, c); rep.ReportOnly || e.has(n, orphan) {
		t.Fatalf("the sweep after: %+v, want the orphan reaped", rep)
	}
}

// TestRemovedRepositoryLeavesTheReviewedSet removes a reviewed repository and
// brings it back from a copy. A name the set no longer holds is new content.
func TestRemovedRepositoryLeavesTheReviewedSet(t *testing.T) {
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	e.goodRepo(t, "good")
	orphan := e.goodRepo(t, "app")
	n := name(t, "app")
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	e.sweep(t, c)

	saved := t.TempDir()
	copyTree(t, e.dir(t, n), saved)
	if err := os.RemoveAll(e.dir(t, n)); err != nil {
		t.Fatal(err)
	}
	e.sweep(t, c)
	copyTree(t, saved, e.dir(t, n))
	rep := e.sweep(t, c)
	if !e.has(n, orphan) || !slices.Equal(rep.Reviewing, []string{"app"}) {
		t.Fatalf("sweep after it came back: %+v, want app reported on and its orphan kept", rep)
	}
}

// TestSweepCountsOnlyWhatItReaped keeps a repository under review out of the
// sweep's reaped objects when another repository deletes.
func TestSweepCountsOnlyWhatItReaped(t *testing.T) {
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	e.goodRepo(t, "old")
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(-2 * time.Hour)
	newOrphan := e.goodRepo(t, "new")
	e.clk.set(0)
	rep := e.sweep(t, c)
	if rep.ReportOnly || rep.Count(KindBlob) != 1 || rep.Objects[0].Repository != "old" {
		t.Fatalf("sweep: %+v, want only old's orphan among the objects", rep)
	}
	if len(rep.WouldReap) != 1 || rep.WouldReap[0].Name != newOrphan.String() {
		t.Fatalf("would reap %+v, want new's orphan", rep.WouldReap)
	}
}

// TestMergeRestoreFollowsTheDocumentedRule pins what a sweep does after a restore
// merged over a live root, which keeps its store id. A repository the reviewed
// set does not hold reports first. In one it holds, a restored index.json with
// fewer rows than the store recorded stops the sweep (ErrRowsLost), so what the
// restored rows no longer name is kept; removing the id file first makes the
// sweep report instead.
func TestMergeRestoreFollowsTheDocumentedRule(t *testing.T) {
	// setup reviews app with a tag v1, takes a snapshot of app, pushes a tag v2,
	// and merges the snapshot back over the live root.
	setup := func(t *testing.T) (e *env, c *Collector, later image) {
		e = newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.keeper(t, n)
		c = e.collector(t, -3*time.Hour)
		e.clk.set(0)
		e.sweep(t, c)
		snapshot := t.TempDir()
		copyTree(t, e.dir(t, n), snapshot)
		e.clk.set(-2 * time.Hour)
		later = e.push(t, n, "v2", "later", []byte("later layer"))
		for _, d := range later.blobs() {
			e.backdate(t, e.blobFile(t, n, d), -2*time.Hour)
		}
		e.clk.set(0)
		copyTree(t, snapshot, e.dir(t, n))
		return e, c, later
	}

	t.Run("a merged new repository reports first", func(t *testing.T) {
		src := newEnv(t)
		src.clk.set(-2 * time.Hour)
		orphan := src.goodRepo(t, "merged")

		e := newEnv(t)
		e.clk = src.clk
		e.s.SetClock(e.clk.now)
		e.clk.set(-2 * time.Hour)
		e.goodRepo(t, "live")
		c := e.collector(t, -3*time.Hour)
		e.clk.set(0)
		e.sweep(t, c)

		copyTree(t, src.s.Root(), e.s.Root())
		rep := e.sweep(t, c)
		if !e.has(name(t, "merged"), orphan) || !slices.Equal(rep.Reviewing, []string{"merged"}) {
			t.Fatalf("sweep after the merge: %+v, want merged reported on and its orphan kept", rep)
		}
	})
	t.Run("a merge that drops rows of a reviewed repository stops its sweep", func(t *testing.T) {
		e, c, later := setup(t)
		rep, err := c.Sweep(e.ctx)
		if !errors.Is(err, ErrRowsLost) || !slices.Equal(rep.Stopped, []string{"app"}) {
			t.Fatalf("sweep: %+v, %v; want ErrRowsLost for app", rep, err)
		}
		if !e.hasAll(name(t, "app"), later.blobs()) {
			t.Fatal("the sweep reaped what the restored rows dropped")
		}
	})
	t.Run("removing the id file first makes the sweep report", func(t *testing.T) {
		e, c, later := setup(t)
		if err := os.Remove(filepath.Join(e.s.Root(), store.IDFile)); err != nil {
			t.Fatal(err)
		}
		rep := e.sweep(t, c)
		if !rep.ReportOnly || !e.hasAll(name(t, "app"), later.blobs()) {
			t.Fatalf("sweep: %+v, want report-only and the later push kept", rep)
		}
	})
}

// TestBadStoreIDSaysHowToRecover corrupts the id file. No sweep deletes; the
// error names the file and the recovery, and the recovery works: the sweep after
// the file is removed reports only, and the one after that deletes.
func TestBadStoreIDSaysHowToRecover(t *testing.T) {
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	orphan := e.goodRepo(t, "app")
	n := name(t, "app")
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)
	e.sweep(t, c)
	p := filepath.Join(e.s.Root(), store.IDFile)
	if err := os.WriteFile(p, []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := c.Sweep(e.ctx)
	if !errors.Is(err, store.ErrBadID) || !rep.ReportOnly {
		t.Fatalf("sweep over a corrupt id: %+v, %v; want report-only and ErrBadID", rep, err)
	}
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "remove") {
		t.Fatalf("the error %q does not name the file and the recovery", err)
	}
	if !e.has(n, orphan) {
		t.Fatal("a sweep over a corrupt id deleted")
	}

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if rep := e.sweep(t, c); !rep.ReportOnly || !e.has(n, orphan) {
		t.Fatalf("sweep after the recovery: %+v, want report-only", rep)
	}
	if rep := e.sweep(t, c); rep.ReportOnly || e.has(n, orphan) {
		t.Fatalf("the sweep after: %+v, want the orphan reaped", rep)
	}
}

// TestUnwritableStoreIDSaysWhyNothingDeletes makes the id file impossible to
// write, as a filesystem without link(2) does. Every sweep says so and deletes
// nothing, and it recovers by itself when the root accepts the file.
func TestUnwritableStoreIDSaysWhyNothingDeletes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	e := newEnv(t)
	e.clk.set(-2 * time.Hour)
	orphan := e.goodRepo(t, "app")
	n := name(t, "app")
	var logs bytes.Buffer
	e.clk.set(-3 * time.Hour)
	c, err := New(e.s, Options{Grace: grace, Now: e.clk.now, Log: slog.New(slog.NewTextHandler(io.MultiWriter(&logs), nil))})
	if err != nil {
		t.Fatal(err)
	}
	e.clk.set(0)
	if err := os.Chmod(e.s.Root(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.s.Root(), 0o700) })

	for range 2 {
		rep, err := c.Sweep(e.ctx)
		if err == nil || !rep.ReportOnly {
			t.Fatalf("sweep: %+v, %v; want report-only and an error", rep, err)
		}
		if !strings.Contains(err.Error(), "delete nothing") {
			t.Fatalf("the error %q does not say that nothing deletes", err)
		}
		if !e.has(n, orphan) {
			t.Fatal("a sweep that could not write the store id deleted")
		}
	}
	if err := os.Chmod(e.s.Root(), 0o700); err != nil {
		t.Fatal(err)
	}
	e.sweep(t, c)
	e.sweep(t, c)
	if e.has(n, orphan) {
		t.Fatal("the orphan survived after the root accepted the id file")
	}
}
