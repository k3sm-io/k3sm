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
// blobs, and lets exactly half through.
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
	for reap, stop := range map[int]bool{0: false, 1: false, 3: false, 4: true, 6: true} {
		p := plan{blobs: map[digest.Digest]bool{}}
		for _, d := range ds[:reap] {
			p.blobs[d] = true
		}
		err := c.brake(name(t, "app"), p, idx, cont)
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
