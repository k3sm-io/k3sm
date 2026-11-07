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
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestSweepRepositoriesSweepsOnlyTheNamed pins the per-repository sweep: it
// reaps in the named repositories on Sweep's terms and leaves every other
// repository as it was.
func TestSweepRepositoriesSweepsOnlyTheNamed(t *testing.T) {
	e := newEnv(t)
	a, b := name(t, "a"), name(t, "b")
	e.clk.set(-2 * time.Hour)
	e.push(t, a, "v1", "a-kept", []byte("a kept layer"))
	gone := e.push(t, a, "", "a-gone", []byte("a gone layer"))
	e.push(t, b, "v1", "b-kept", []byte("b kept layer"))
	other := e.push(t, b, "", "b-gone", []byte("b gone layer"))
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	rep, err := c.SweepRepositories(e.ctx, []ref.Name{a, a, name(t, "absent")})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ReportOnly || rep.Count(KindManifest) != 1 || rep.Count(KindBlob) != 3 {
		t.Fatalf("report %+v, want a's untagged manifest and its three blobs reaped", rep)
	}
	for _, d := range gone.blobs() {
		if e.has(a, d) {
			t.Errorf("%s survived in a", d)
		}
	}
	want := gone.manifest.Size + gone.config.Size + gone.layers[0].Size
	if rep.BlobBytes != want {
		t.Errorf("BlobBytes = %d, want %d", rep.BlobBytes, want)
	}
	for _, d := range other.blobs() {
		if !e.has(b, d) {
			t.Errorf("%s went from b, which was not named", d)
		}
	}
}

func TestSweepRepositoriesKeepsTheCollectorsTerms(t *testing.T) {
	t.Run("no sweep within one grace of start", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.push(t, n, "v1", "app", []byte("layer"))
		c := e.collector(t, 0)
		e.ran(t)
		e.clk.set(grace - time.Second)
		if _, err := c.SweepRepositories(e.ctx, []ref.Name{n}); !errors.Is(err, ErrTooSoon) {
			t.Fatalf("err = %v, want ErrTooSoon", err)
		}
	})

	t.Run("a repository not yet reviewed is only reported on and stays unreviewed", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.push(t, n, "v1", "kept", []byte("kept layer"))
		gone := e.push(t, n, "", "gone", []byte("gone layer"))
		c := e.collector(t, -3*time.Hour)
		e.clk.set(0)
		rep, err := c.SweepRepositories(e.ctx, []ref.Name{n})
		if err != nil {
			t.Fatal(err)
		}
		if !rep.ReportOnly || len(rep.Reviewing) != 1 || rep.BlobBytes != 0 || len(rep.WouldReap) == 0 {
			t.Fatalf("report %+v, want report-only on app", rep)
		}
		for _, d := range gone.blobs() {
			if !e.has(n, d) {
				t.Errorf("%s went in a report-only sweep", d)
			}
		}
		reviewed, err := ReadReviewed(e.s, c.log)
		if err != nil || len(reviewed) != 0 {
			t.Errorf("marker names %v (%v); a per-repository sweep must not review", reviewed, err)
		}
	})

	t.Run("the half brake stops it", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.push(t, n, "v1", "kept", []byte("kept layer"))
		gone := e.push(t, n, "", "gone", []byte("gone layer 1"), []byte("gone layer 2"))
		c := e.collector(t, -3*time.Hour)
		e.ran(t)
		e.clk.set(0)
		rep, err := c.SweepRepositories(e.ctx, []ref.Name{n})
		if !errors.Is(err, ErrMassDelete) || len(rep.Stopped) != 1 || rep.BlobBytes != 0 {
			t.Fatalf("report %+v, err %v; want the brake to stop app", rep, err)
		}
		for _, d := range gone.blobs() {
			if !e.has(n, d) {
				t.Errorf("%s went past the brake", d)
			}
		}
	})

	t.Run("a layout it reaps leaves the marker", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.push(t, n, "", "a", []byte("layer a"))
		c := e.collector(t, -3*time.Hour)
		e.ran(t)
		e.clk.set(0)
		if _, err := c.SweepRepositories(e.ctx, []ref.Name{n}); err != nil {
			t.Fatal(err)
		}
		e.backdate(t, filepath.Join(e.dir(t, n), "index.json"), -2*time.Hour)
		rep, err := c.SweepRepositories(e.ctx, []ref.Name{n})
		if err != nil || rep.Count(KindRepository) != 1 {
			t.Fatalf("report %+v, err %v; want the emptied layout reaped", rep, err)
		}
		reviewed, err := ReadReviewed(e.s, c.log)
		if err != nil || reviewed["app"] {
			t.Errorf("marker still names app (%v): a repository pushed again would skip its review", err)
		}
	})
}
