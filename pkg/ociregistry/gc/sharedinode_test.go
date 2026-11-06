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
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// deleted is a removed image beside a sibling that shares one of its layers
// through one inode, with the sibling's touch after the delete.
type deleted struct {
	gone, sibling ref.Name
	shared        digest.Digest
	unshared      []digest.Digest
	touchedAt     time.Time
	kept          image
	collector     *Collector
}

// sharedInodeShapes are the ways to reach a repository whose plan removes every
// row, or has none to remove.
var sharedInodeShapes = []struct {
	name string
	// push pushes the image with shared among its layers, and returns its other
	// blobs and how to remove it.
	push  func(t *testing.T, e *env, n ref.Name, shared []byte) ([]digest.Digest, func() error)
	rows  int
	stuck bool // no row to remove, so the touched name waits for the horizon
}{
	{
		// A delete by digest takes the last row.
		name: "no rows",
		push: func(t *testing.T, e *env, n ref.Name, shared []byte) ([]digest.Digest, func() error) {
			img := e.push(t, n, "v1", "gone", shared, []byte("own 1"), []byte("own 2"))
			return without(img.blobs(), img.layers[0].Digest), func() error { return e.s.DeleteDigest(e.ctx, n, img.manifest.Digest) }
		},
		stuck: true,
	},
	{
		// A tag delete leaves the manifest its untagged row.
		name: "an untagged row a tag delete left",
		push: func(t *testing.T, e *env, n ref.Name, shared []byte) ([]digest.Digest, func() error) {
			img := e.push(t, n, "v1", "gone", shared, []byte("own 1"), []byte("own 2"))
			return without(img.blobs(), img.layers[0].Digest), func() error { return e.s.DeleteTag(e.ctx, n, "v1") }
		},
		rows: 1,
	},
	{
		// A deleted multi-platform tag leaves its children's rows and its own.
		name: "the untagged rows of a deleted multi-platform tag",
		push: func(t *testing.T, e *env, n ref.Name, shared []byte) ([]digest.Digest, func() error) {
			x := e.push(t, n, "", "x", shared, []byte("own x"))
			y := e.push(t, n, "", "y", []byte("own y"))
			idx := e.putManifest(t, n, "multi", ispec.MediaTypeImageIndex, indexBody(t, x.manifest, y.manifest))
			blobs := append(without(x.blobs(), x.layers[0].Digest), y.blobs()...)
			return append(blobs, idx.Digest), func() error { return e.s.DeleteTag(e.ctx, n, "multi") }
		},
		rows: 3,
	},
}

func without(ds []digest.Digest, d digest.Digest) []digest.Digest {
	return slices.DeleteFunc(slices.Clone(ds), func(o digest.Digest) bool { return o == d })
}

// setUpDeleted makes the shape: the image and its sibling, a real merge of the
// shared layer, the delete at -4h, and the sibling's touch at -2h, so the shared
// inode is past its grace at offset 0 and newer than index.json.
func setUpDeleted(t *testing.T, e *env, s int, review bool) deleted {
	t.Helper()
	shape := sharedInodeShapes[s]
	body := []byte("shared layer")
	d := deleted{gone: name(t, "gone"), sibling: name(t, "sibling"), shared: digest.FromBytes(body)}
	e.clk.set(-5 * time.Hour)
	d.kept = e.push(t, d.sibling, "v1", "sibling", body, []byte("sibling own"))
	e.clk.set(-6 * time.Hour)
	var remove func() error
	d.unshared, remove = shape.push(t, e, d.gone, body)
	e.clk.set(0) // the pass refuses a keeper from its clock's future
	rep, err := e.converge()
	if err != nil || rep.Merged != 1 || !e.sameInode(t, d.gone, d.sibling, d.shared) {
		t.Fatalf("the pass merged %d (%v), want the shared layer", rep.Merged, err)
	}
	if err := remove(); err != nil {
		t.Fatal(err)
	}
	e.backdate(t, filepath.Join(e.dir(t, d.gone), "index.json"), -4*time.Hour)
	idx, err := e.s.Index(d.gone)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != shape.rows {
		t.Fatalf("%d rows after the delete, want %d", len(idx.Manifests), shape.rows)
	}
	for _, r := range idx.Manifests {
		if _, tagged := r.Annotations[ispec.AnnotationRefName]; tagged {
			t.Fatalf("a tagged row after the delete: %+v", r)
		}
	}
	d.collector = e.collector(t, -7*time.Hour)
	if !review {
		e.ran(t)
	}
	e.clk.set(-2 * time.Hour)
	if err := e.s.TouchBlob(e.ctx, d.sibling, d.shared); err != nil {
		t.Fatal(err)
	}
	d.touchedAt = e.mtime(t, e.blobFile(t, d.gone, d.shared))
	e.clk.set(0)
	return d
}

// TestSharedInodeDoesNotStickTheBrake: a sibling's touch after a delete leaves
// one blob newer than index.json. The sweep reaps every unshared blob and leaves
// that one out instead of stopping the repository. A repository with rows heals on
// the next sweep, because removing them moved index.json. One with none waits for
// the abandon horizon, holding no bytes while the sibling names the inode.
func TestSharedInodeDoesNotStickTheBrake(t *testing.T) {
	for s, shape := range sharedInodeShapes {
		t.Run(shape.name, func(t *testing.T) {
			e := newEnv(t)
			d := setUpDeleted(t, e, s, false)
			rep, err := d.collector.Sweep(e.ctx)
			if err != nil || len(rep.Stopped) != 0 {
				t.Fatalf("sweep: %v, stopped %v: the shared inode stuck the brake", err, rep.Stopped)
			}
			for _, b := range d.unshared {
				if e.has(d.gone, b) {
					t.Errorf("the unshared blob %s survived", b)
				}
			}
			if !e.has(d.gone, d.shared) {
				t.Fatal("a blob newer than index.json was reaped")
			}
			if slices.Contains(objectsOf(rep, KindBlob, d.gone.String()), d.shared.String()) {
				t.Errorf("report %+v names a blob the sweep left", rep)
			}
			if rep.Count(KindRepository) != 0 {
				t.Errorf("report %+v removes a repository that still holds a blob", rep)
			}
			if got := e.mtime(t, e.blobFile(t, d.gone, d.shared)); !got.Equal(d.touchedAt) {
				t.Errorf("the sweep moved the shared inode's mtime: %v, want %v", got, d.touchedAt)
			}
			if err := e.whole(d.sibling, d.kept); err != nil {
				t.Fatalf("the sibling: %v", err)
			}

			if shape.stuck {
				// Nothing moves index.json, and the name waits for the horizon, 24
				// grace periods after the touch at -2h.
				e.clk.set(21 * time.Hour)
				if _, err := d.collector.Sweep(e.ctx); !errors.Is(err, ErrMassDelete) {
					t.Fatalf("a sweep inside the horizon: %v, want ErrMassDelete", err)
				}
				if !e.has(d.gone, d.shared) {
					t.Fatal("a sweep inside the horizon reaped a blob newer than index.json")
				}
				e.clk.set(23 * time.Hour)
			} else if idx, err := e.s.Index(d.gone); err != nil || len(idx.Manifests) != 0 {
				t.Fatalf("rows after the sweep: %+v, %v; want none", idx.Manifests, err)
			}
			rep = e.sweep(t, d.collector)
			if e.has(d.gone, d.shared) {
				t.Fatalf("the touched name outlived what heals it (report %+v)", rep)
			}
			if err := e.whole(d.sibling, d.kept); err != nil {
				t.Fatalf("after the name went, the sibling: %v", err)
			}

			// One grace past the last row write, the layout goes too.
			e.clk.set(30 * time.Hour)
			e.sweep(t, d.collector)
			repos, err := e.s.Repositories()
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(repos, d.gone) {
				t.Errorf("repositories %v still hold the emptied %s", repos, d.gone)
			}
		})
	}
}

// TestSharedInodeReviewReportsWhatTheReapTakes: a report-only sweep lists what the
// delete would take, not the blob it would leave, and adds the repository to the
// marker, since no brake stopped it.
func TestSharedInodeReviewReportsWhatTheReapTakes(t *testing.T) {
	for s, shape := range sharedInodeShapes {
		t.Run(shape.name, func(t *testing.T) {
			e := newEnv(t)
			d := setUpDeleted(t, e, s, true)
			rep, err := d.collector.Sweep(e.ctx)
			if err != nil || len(rep.Stopped) != 0 || !rep.ReportOnly {
				t.Fatalf("sweep: %v, report %+v", err, rep)
			}
			var names []string
			for _, o := range rep.WouldReap {
				if o.Repository == d.gone.String() && o.Kind == KindBlob {
					names = append(names, o.Name)
				}
			}
			for _, b := range d.unshared {
				if !slices.Contains(names, b.String()) {
					t.Errorf("the report omits %s", b)
				}
				if !e.has(d.gone, b) {
					t.Errorf("a report-only sweep reaped %s", b)
				}
			}
			if slices.Contains(names, d.shared.String()) {
				t.Errorf("the report lists a blob the delete would leave: %v", names)
			}
			for _, o := range rep.WouldReap {
				if o.Kind == KindRepository {
					t.Errorf("the report lists a repository the delete would leave: %+v", o)
				}
			}
			if rep = e.sweep(t, d.collector); rep.Count(KindBlob) != len(d.unshared) {
				t.Errorf("the next sweep reaped %d blobs, want the %d reported (report %+v)", rep.Count(KindBlob), len(d.unshared), rep)
			}
		})
	}
}

// TestBrakeStillHolds: leaving the newer blobs out is only for a plan that has no
// row to keep and has something to remove.
func TestBrakeStillHolds(t *testing.T) {
	at := time.Now()
	older, newer := at.Add(-time.Hour), at.Add(time.Hour)
	d1, d2, d3 := digest.FromString("1"), digest.FromString("2"), digest.FromString("3")
	blobs := []store.Blob{{Digest: d1, ModTime: older}, {Digest: d2, ModTime: older}, {Digest: d3, ModTime: newer}}
	all := map[digest.Digest]bool{d1: true, d2: true, d3: true}
	untagged := ispec.Descriptor{Digest: d1}
	tagged := ispec.Descriptor{Digest: d1, Annotations: map[string]string{ispec.AnnotationRefName: "v1"}}
	c := &Collector{log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return at }, abandon: AbandonFactor * grace}
	for _, tc := range []struct {
		name string
		rows []ispec.Descriptor
		plan plan
		cont []store.Blob
		// blobs is what the plan goes on with; nil means it stops.
		blobs map[digest.Digest]bool
	}{
		{name: "a tagged row", rows: []ispec.Descriptor{tagged}, plan: plan{blobs: all}, cont: blobs},
		{name: "a tagged row whose digest the plan names", rows: []ispec.Descriptor{tagged}, plan: plan{rows: map[digest.Digest]bool{d1: true}, blobs: all}, cont: blobs},
		{name: "an untagged row the plan keeps", rows: []ispec.Descriptor{untagged}, plan: plan{blobs: all}, cont: blobs},
		{name: "no rows, every blob newer (a first push)", plan: plan{blobs: map[digest.Digest]bool{d3: true}}, cont: blobs[2:]},
		{name: "no rows, one blob newer", plan: plan{blobs: all, emptyRepo: true}, cont: blobs, blobs: map[digest.Digest]bool{d1: true, d2: true}},
		{name: "rows go, every blob newer", rows: []ispec.Descriptor{{Digest: d3}}, plan: plan{rows: map[digest.Digest]bool{d3: true}, blobs: map[digest.Digest]bool{d3: true}}, cont: blobs[2:], blobs: map[digest.Digest]bool{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.brake(name(t, "app"), tc.plan, ispec.Index{Manifests: tc.rows}, store.Contents{Blobs: tc.cont, IndexModTime: at})
			if tc.blobs == nil {
				if !errors.Is(err, ErrMassDelete) {
					t.Fatalf("brake: %v, want ErrMassDelete", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got.blobs) != len(tc.blobs) {
				t.Fatalf("blobs %v, want %v", got.blobs, tc.blobs)
			}
			for d := range tc.blobs {
				if !got.blobs[d] {
					t.Errorf("%s left out", d)
				}
			}
			if got.emptyRepo {
				t.Error("a plan that leaves a blob still removes the layout")
			}
		})
	}
}

// TestBrakeLeavesABlobAsNewAsTheIndex: the boundary. index.json and a blob at the
// same instant count as newer, as emptying counts them.
func TestBrakeLeavesABlobAsNewAsTheIndex(t *testing.T) {
	at := time.Now()
	d1, d2 := digest.FromString("1"), digest.FromString("2")
	c := &Collector{log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return at }, abandon: AbandonFactor * grace}
	got, err := c.brake(name(t, "app"), plan{blobs: map[digest.Digest]bool{d1: true, d2: true}}, ispec.Index{},
		store.Contents{Blobs: []store.Blob{{Digest: d1, ModTime: at.Add(-time.Nanosecond)}, {Digest: d2, ModTime: at}}, IndexModTime: at})
	if err != nil {
		t.Fatal(err)
	}
	if !got.blobs[d1] || got.blobs[d2] {
		t.Fatalf("blobs %v, want only the one older than index.json", got.blobs)
	}
}
