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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

var errCrash = errors.New("injected crash")

// crashAt returns a fault seam that stops apply at point at, once i blobs are
// removed for faultBlob, the first time only: the next sweep runs whole, as
// after a restart.
func crashAt(at faultPoint, i int) func(faultPoint, int) error {
	fired := false
	return func(p faultPoint, n int) error {
		if fired || p != at || (p == faultBlob && n != i) {
			return nil
		}
		fired = true
		return errCrash
	}
}

// crashRepo is a repository a sweep reaps part of: a tagged image it keeps
// and garbage it reaps.
type crashRepo struct {
	name   string
	setup  func(t *testing.T, e *env, n ref.Name) (keep []image, reap []digest.Digest)
	blobs  int // what the first sweep removes
	hasRow bool
}

var crashRepos = []crashRepo{
	{
		// Every row is untagged: the sweep empties the repository, past the
		// half brake. A crash after its row write leaves blobs no row names,
		// and the next sweep must still see it as emptying.
		name: "emptying",
		setup: func(t *testing.T, e *env, n ref.Name) ([]image, []digest.Digest) {
			a := e.push(t, n, "", "a", []byte("layer a"))
			b := e.push(t, n, "", "b", []byte("layer b"))
			return nil, slices.Concat(a.blobs(), b.blobs())
		},
		blobs:  6,
		hasRow: true,
	},
	{
		// A tagged image and an untagged one: half the blobs go.
		name: "half",
		setup: func(t *testing.T, e *env, n ref.Name) ([]image, []digest.Digest) {
			keep := e.push(t, n, "v1", "keep", []byte("kept layer"))
			u := e.push(t, n, "", "u", []byte("untagged layer"))
			return []image{keep}, u.blobs()
		},
		blobs:  3,
		hasRow: true,
	},
	{
		// Orphan blobs only, no row to rewrite.
		name: "orphans",
		setup: func(t *testing.T, e *env, n ref.Name) ([]image, []digest.Digest) {
			keep := e.push(t, n, "v1", "keep", []byte("k1"), []byte("k2"))
			var reap []digest.Digest
			for _, b := range []string{"o1", "o2"} {
				reap = append(reap, e.blob(t, n, []byte(b)).Digest)
			}
			return []image{keep}, reap
		},
		blobs: 2,
	},
}

// TestSweepConvergesAfterACrash stops a sweep after its row write, or after
// its first, middle or last blob removal, and runs a second sweep: it neither
// stalls on a brake nor finds an unreadable manifest, it finishes the reap,
// the repository is still listed, a later push into it works, and nothing a
// kept row names was removed at any point.
func TestSweepConvergesAfterACrash(t *testing.T) {
	for _, r := range crashRepos {
		var points []struct {
			at faultPoint
			i  int
		}
		if r.hasRow {
			points = append(points, struct {
				at faultPoint
				i  int
			}{faultRows, 0})
		}
		for _, i := range slices.Compact([]int{1, (r.blobs + 1) / 2, r.blobs}) {
			points = append(points, struct {
				at faultPoint
				i  int
			}{faultBlob, i})
		}
		for _, pt := range points {
			label := "after the rows"
			if pt.at == faultBlob {
				label = fmt.Sprintf("after blob %d of %d", pt.i, r.blobs)
			}
			t.Run(r.name+"/"+label, func(t *testing.T) {
				e := newEnv(t)
				n, other := name(t, "app"), name(t, "other")
				e.clk.set(-2 * time.Hour)
				keep, reap := r.setup(t, e, n)
				oimg := e.push(t, other, "v1", "other", []byte("other layer"))
				c := e.collector(t, -3*time.Hour)
				e.ran(t)
				e.clk.set(0)
				kept := func(when string) {
					t.Helper()
					for _, img := range append(slices.Clone(keep), oimg) {
						for _, d := range img.blobs() {
							if !e.has(n, d) && !e.has(other, d) {
								t.Fatalf("%s: kept blob %s was removed", when, d)
							}
						}
					}
					noDangling(t, e.s)
				}

				c.fault = crashAt(pt.at, pt.i)
				if _, err := c.Sweep(e.ctx); !errors.Is(err, errCrash) {
					t.Fatalf("first sweep: %v, want the injected crash", err)
				}
				kept("after the crash")
				if repos, err := e.s.Repositories(); err != nil || !slices.Contains(repos, n) {
					t.Fatalf("repositories after the crash: %v, %v", repos, err)
				}

				rep, err := c.Sweep(e.ctx)
				if err != nil {
					t.Fatalf("second sweep: %v (report %+v)", err, rep)
				}
				kept("after the second sweep")
				for _, d := range reap {
					if e.has(n, d) {
						t.Errorf("second sweep left %s", d)
					}
				}

				// A later push into the repository works and survives.
				img := e.push(t, n, "later", "later", []byte("later layer"))
				e.clk.set(2 * time.Hour)
				if _, err := c.Sweep(e.ctx); err != nil {
					t.Fatalf("sweep after the later push: %v", err)
				}
				keep = append(keep, img)
				kept("after the later push")
			})
		}
	}
}

// TestSweepConvergesAfterAHalfRemovedLayout covers a layout removal that
// stopped after index.json went (the state the store's own crash test shows
// RemoveLayout leaves): the directory is not a repository, sweeps skip it
// without an error, and a push makes it whole again.
func TestSweepConvergesAfterAHalfRemovedLayout(t *testing.T) {
	e := newEnv(t)
	n, other := name(t, "app"), name(t, "other")
	e.clk.set(-2 * time.Hour)
	e.push(t, n, "", "a", []byte("layer a"))
	oimg := e.push(t, other, "v1", "other", []byte("other layer"))
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)
	if rep := e.sweep(t, c); rep.Count(KindBlob) != 3 {
		t.Fatalf("report %+v, want the untagged image reaped", rep)
	}
	if err := removeIndex(e, n); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if rep := e.sweep(t, c); len(objectsOf(rep, KindRepository, n.String())) != 0 {
			t.Fatalf("report %+v names the half-removed layout", rep)
		}
	}
	if repos, err := e.s.Repositories(); err != nil || slices.Contains(repos, n) {
		t.Fatalf("repositories %v, %v; want no %s", repos, err, n)
	}
	img := e.push(t, n, "v1", "again", []byte("again"))
	e.clk.set(2 * time.Hour)
	e.sweep(t, c)
	for _, im := range []struct {
		n   ref.Name
		img image
	}{{n, img}, {other, oimg}} {
		for _, d := range im.img.blobs() {
			if !e.has(im.n, d) {
				t.Errorf("%s lost %s", im.n, d)
			}
		}
	}
	noDangling(t, e.s)
}

// removeIndex removes n's index.json, as a layout removal stopped right
// after its first step leaves it.
func removeIndex(e *env, n ref.Name) error {
	d, err := n.Dir(e.s.Root())
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(d, "index.json"))
}
