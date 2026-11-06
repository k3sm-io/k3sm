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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

func TestEmptying(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d1, d2, d3 := digest.FromString("1"), digest.FromString("2"), digest.FromString("3")
	untagged := func(d digest.Digest) ispec.Descriptor { return ispec.Descriptor{Digest: d} }
	tagged := func(d digest.Digest) ispec.Descriptor {
		return ispec.Descriptor{Digest: d, Annotations: map[string]string{ispec.AnnotationRefName: "v1"}}
	}
	blob := func(d digest.Digest, mt time.Time) store.Blob { return store.Blob{Digest: d, ModTime: mt} }
	set := func(ds ...digest.Digest) map[digest.Digest]bool {
		m := map[digest.Digest]bool{}
		for _, d := range ds {
			m[d] = true
		}
		return m
	}
	cases := []struct {
		name  string
		rows  []ispec.Descriptor
		plan  plan
		blobs []store.Blob
		want  bool
	}{
		{
			name:  "no rows, every reaped blob older than the index",
			plan:  plan{blobs: set(d1, d2)},
			blobs: []store.Blob{blob(d1, at.Add(-time.Second)), blob(d2, at.Add(-time.Hour))},
			want:  true,
		},
		{
			name:  "a reaped blob as new as the index: the brake holds",
			plan:  plan{blobs: set(d1, d2)},
			blobs: []store.Blob{blob(d1, at.Add(-time.Second)), blob(d2, at)},
		},
		{
			name:  "a reaped blob one nanosecond older than the index",
			plan:  plan{blobs: set(d1)},
			blobs: []store.Blob{blob(d1, at.Add(-time.Nanosecond))},
			want:  true,
		},
		{
			name:  "a reaped blob newer than the index (a first push)",
			plan:  plan{blobs: set(d1, d2)},
			blobs: []store.Blob{blob(d1, at.Add(-time.Second)), blob(d2, at.Add(time.Second))},
		},
		{
			name:  "a kept blob newer than the index does not matter",
			plan:  plan{blobs: set(d1)},
			blobs: []store.Blob{blob(d1, at.Add(-time.Second)), blob(d2, at.Add(time.Hour))},
			want:  true,
		},
		{
			name:  "every untagged row reaped",
			rows:  []ispec.Descriptor{untagged(d1), untagged(d2)},
			plan:  plan{rows: set(d1, d2), blobs: set(d1, d2, d3)},
			blobs: []store.Blob{blob(d1, at.Add(-time.Hour)), blob(d2, at.Add(-time.Hour)), blob(d3, at.Add(-time.Hour))},
			want:  true,
		},
		{
			name:  "an untagged row the plan keeps",
			rows:  []ispec.Descriptor{untagged(d1), untagged(d2)},
			plan:  plan{rows: set(d1), blobs: set(d1, d3)},
			blobs: []store.Blob{blob(d1, at.Add(-time.Hour)), blob(d3, at.Add(-time.Hour))},
		},
		{
			name:  "a tagged row, even one whose digest the plan names",
			rows:  []ispec.Descriptor{tagged(d1)},
			plan:  plan{rows: set(d1), blobs: set(d2)},
			blobs: []store.Blob{blob(d2, at.Add(-time.Hour))},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := ispec.Index{Manifests: tc.rows}
			cont := store.Contents{Blobs: tc.blobs, IndexModTime: at}
			if got := emptying(tc.plan, idx, cont); got != tc.want {
				t.Fatalf("emptying = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBrakeBoundary: the brake stops a plan over more than half of the
// blobs the rows describe, and lets exactly half through.
func TestBrakeBoundary(t *testing.T) {
	c := &Collector{log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now, abandon: AbandonFactor * grace}
	at := time.Now()
	var blobs []store.Blob
	var ds []digest.Digest
	for i := range 6 {
		d := digest.FromString(string(rune('a' + i)))
		ds = append(ds, d)
		blobs = append(blobs, store.Blob{Digest: d, ModTime: at.Add(time.Second)}) // never emptying
	}
	idx := ispec.Index{Manifests: []ispec.Descriptor{{Digest: ds[0], Annotations: map[string]string{ispec.AnnotationRefName: "v1"}}}}
	cont := store.Contents{Blobs: blobs, IndexModTime: at}
	r := reads{ds[0]: {present: true, named: ds[1:]}}
	for reap, stop := range map[int]bool{0: false, 1: false, 3: false, 4: true, 6: true} {
		p := plan{blobs: map[digest.Digest]bool{}}
		for _, d := range ds[:reap] {
			p.blobs[d] = true
		}
		_, err := c.brake(name(t, "app"), p, idx, cont, r)
		if got := errors.Is(err, ErrMassDelete); got != stop {
			t.Errorf("%d of 6: stopped %v (%v), want %v", reap, got, err, stop)
		}
	}
}

// TestSweepsExactlyHalf: a sweep of 3 of 6 blobs is not stopped.
func TestSweepsExactlyHalf(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	img := e.push(t, n, "v1", "app", []byte("layer"))
	for _, b := range []string{"o1", "o2", "o3"} {
		e.blob(t, n, []byte(b))
	}
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)
	rep := e.sweep(t, c)
	if rep.Count(KindBlob) != 3 || len(rep.Stopped) != 0 {
		t.Fatalf("report %+v, want 3 of 6 reaped and no stop", rep)
	}
	for _, d := range img.blobs() {
		if !e.has(n, d) {
			t.Errorf("%s was reaped", d)
		}
	}
}

// brakeHolds are scenarios where the brake must stop a sweep because the plan
// does not empty the repository. Each reports whether every blob survived.
var brakeHolds = []struct {
	name string
	run  func(t *testing.T, e *env) bool
}{
	{
		// Every reaped blob was written at the same instant as index.json.
		name: "blobs as new as the index",
		run: func(t *testing.T, e *env) bool {
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			a := e.push(t, n, "", "a", []byte("layer a"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			for _, d := range a.blobs() {
				e.backdate(t, e.blobFile(t, n, d), -2*time.Hour)
			}
			e.backdate(t, filepath.Join(e.dir(t, n), "index.json"), -2*time.Hour)
			e.clk.set(0)
			_, err := c.Sweep(e.ctx)
			if err != nil && !errors.Is(err, ErrMassDelete) {
				t.Fatal(err)
			}
			return e.hasAll(n, a.blobs())
		},
	},
	{
		// A first push: committed blobs newer than the index, no row yet.
		name: "a first push",
		run: func(t *testing.T, e *env) bool {
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			var ds []digest.Digest
			for _, b := range []string{"config", "l1", "l2"} {
				ds = append(ds, e.blob(t, n, []byte(b)).Digest)
			}
			e.backdate(t, filepath.Join(e.dir(t, n), "index.json"), -3*time.Hour)
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)
			_, err := c.Sweep(e.ctx)
			if err != nil && !errors.Is(err, ErrMassDelete) {
				t.Fatal(err)
			}
			return e.hasAll(n, ds)
		},
	},
}

func (e *env) hasAll(n ref.Name, ds []digest.Digest) bool {
	for _, d := range ds {
		if !e.has(n, d) {
			return false
		}
	}
	return true
}

// TestBrakeHolds runs each scenario against the collector: nothing is lost.
func TestBrakeHolds(t *testing.T) {
	for _, s := range brakeHolds {
		t.Run(s.name, func(t *testing.T) {
			if !s.run(t, newEnv(t)) {
				t.Fatal("the brake let a sweep reap blobs of a repository it does not empty")
			}
		})
	}
}

// TestBrakeHoldsIsRedWhenEmptyingAlwaysHolds runs the same scenarios with an
// emptying rule that always says yes, and requires each to lose blobs: the
// scenarios are not vacuous, and TestBrakeHolds fails on that mutation.
func TestBrakeHoldsIsRedWhenEmptyingAlwaysHolds(t *testing.T) {
	t.Cleanup(func() { emptyingRule = emptying })
	emptyingRule = func(plan, ispec.Index, store.Contents) bool { return true }
	for _, s := range brakeHolds {
		t.Run(s.name, func(t *testing.T) {
			if s.run(t, newEnv(t)) {
				t.Fatal("with emptying always true the scenario still kept every blob: it does not exercise the rule")
			}
		})
	}
}

// TestEmptyingSharedBlob covers an emptying plan that reaps a blob another
// repository links too: the emptied repository loses its name for it, and the
// other keeps its blob and its image.
func TestEmptyingSharedBlob(t *testing.T) {
	e := newEnv(t)
	gone, other := name(t, "gone"), name(t, "other")
	e.clk.set(-3 * time.Hour)
	a := e.push(t, gone, "", "a", []byte("shared layer"))
	e.clk.set(-2 * time.Hour)
	if err := e.s.MountBlob(e.ctx, other, gone, a.layers[0].Digest); err != nil {
		t.Fatal(err)
	}
	b := e.push(t, other, "v1", "b", []byte("own layer"))
	b.layers = append(b.layers, a.layers[0])
	b.body = manifestBody(t, b.config, b.layers, nil)
	b.manifest = e.putManifest(t, other, "v1", ispec.MediaTypeImageManifest, b.body)
	c := e.collector(t, -4*time.Hour)
	e.ran(t)
	e.clk.set(0)

	rep := e.sweep(t, c)
	if len(rep.Stopped) != 0 {
		t.Fatalf("report %+v: the emptying sweep stopped", rep)
	}
	for _, d := range a.blobs() {
		if e.has(gone, d) {
			t.Errorf("%s survived the emptying sweep of %s", d, gone)
		}
	}
	for _, d := range b.blobs() {
		if !e.has(other, d) {
			t.Errorf("%s:v1 lost %s", other, d)
		}
	}
	if body, err := readAll(e, other, a.layers[0].Digest); err != nil || string(body) != "shared layer" {
		t.Fatalf("the shared blob in %s: %q, %v", other, body, err)
	}
	if !slices.Contains(objectsOf(rep, KindBlob, gone.String()), a.layers[0].Digest.String()) {
		t.Fatalf("report %+v does not name the shared blob reaped from %s", rep, gone)
	}
}

func readAll(e *env, n ref.Name, d digest.Digest) ([]byte, error) {
	f, err := e.s.OpenBlob(n, d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func objectsOf(rep Report, k Kind, repo string) []string {
	var out []string
	for _, o := range rep.Objects {
		if o.Kind == k && o.Repository == repo {
			out = append(out, o.Name)
		}
	}
	return out
}

// TestPusherCannotHoldTheBrakeForGood: blobs no row names and no manifest body
// mentions do not count against the half brake while a row stays, so a pusher
// who uploads them next to a tagged image cannot stop the repository's sweeps.
// The orphans go by the grace rule, and the image stays whole. The brake still
// stops a plan that would reap more than half of what the rows describe, the
// orphans neither diluting it nor tipping it.
func TestPusherCannotHoldTheBrakeForGood(t *testing.T) {
	t.Run("orphans next to a tagged image are reaped", testOrphansNextToATag)
	t.Run("a reference the parse misses still counts", testMissedReferenceStillBrakes)
}

func testOrphansNextToATag(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	img := e.push(t, n, "v1", "app", []byte("layer"))
	var orphans []digest.Digest
	for i := range 10 {
		orphans = append(orphans, e.blob(t, n, []byte{'o', byte('0' + i)}).Digest)
	}
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	for i := range 2 {
		rep, err := c.Sweep(e.ctx)
		if err != nil || len(rep.Stopped) != 0 {
			t.Fatalf("sweep %d: %+v, %v; want no stop", i, rep, err)
		}
	}
	for _, d := range orphans {
		if e.has(n, d) {
			t.Errorf("orphan %s survived", d)
		}
	}
	if err := e.whole(n, img); err != nil {
		t.Fatal(err)
	}
}

// testMissedReferenceStillBrakes stands in for a parse that misses a reference:
// a tagged manifest names four blobs in a field the collector does not follow,
// so its plan reaps them. They are four of the seven blobs the rows describe, so
// the brake stops it, however many orphans sit beside them.
func testMissedReferenceStillBrakes(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	cfg, layer := e.blob(t, n, []byte(`{"seed":"cfg"}`)), e.blob(t, n, []byte("layer"))
	var skipped []string
	var missed []digest.Digest
	for _, b := range []string{"m1", "m2", "m3", "m4"} {
		d := e.blob(t, n, []byte(b)).Digest
		missed = append(missed, d)
		skipped = append(skipped, rawDesc(d))
	}
	body := manifestBody(t, cfg, []ispec.Descriptor{layer}, nil)
	body = append(body[:len(body)-1], []byte(`,"blobsTheParseSkips":[`+strings.Join(skipped, ",")+`]}`)...)
	if err := Readable(body); err != nil {
		t.Fatal(err)
	}
	e.putManifest(t, n, "v1", ispec.MediaTypeImageManifest, body)
	var orphans []digest.Digest
	for i := range 10 {
		orphans = append(orphans, e.blob(t, n, []byte{'o', byte('0' + i)}).Digest)
	}
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	rep, err := c.Sweep(e.ctx)
	if !errors.Is(err, ErrMassDelete) || !slices.Equal(rep.Stopped, []string{"app"}) {
		t.Fatalf("sweep: %+v, %v; want ErrMassDelete for app", rep, err)
	}
	if !strings.Contains(err.Error(), "4 of 7") {
		t.Errorf("sweep: %v; want the brake to count 4 of 7 described blobs", err)
	}
	if !e.hasAll(n, append(missed, orphans...)) {
		t.Fatal("the stopped sweep deleted a blob")
	}
}

// TestUnverifiedBodyCountsEveryBlob: a kept body that fails its hash names
// nothing the brake can see, so the brake cannot tell what the rows describe and
// counts every blob of the repository, as it did before it counted only described
// ones. Here an unreadable index child names, through the scan, a blob whose
// bytes no longer hash to its name, and orphans are more than half the blobs.
func TestUnverifiedBodyCountsEveryBlob(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	bad := e.blob(t, n, []byte("the bytes this digest names"))
	root := e.blob(t, n, unreadableBody(bad.Digest))
	root.MediaType = ispec.MediaTypeImageIndex
	e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, root))
	var orphans []digest.Digest
	for i := range 4 {
		orphans = append(orphans, e.blob(t, n, []byte{'o', byte('0' + i)}).Digest)
	}
	p := e.blobFile(t, n, bad.Digest)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.backdate(t, p, -2*time.Hour)
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	rep, err := c.Sweep(e.ctx)
	if !errors.Is(err, ErrMassDelete) || !slices.Equal(rep.Stopped, []string{"app"}) {
		t.Fatalf("sweep: %+v, %v; want ErrMassDelete for app (4 of 7 blobs)", rep, err)
	}
	if !e.hasAll(n, orphans) {
		t.Fatal("the stopped sweep reaped an orphan")
	}
}
