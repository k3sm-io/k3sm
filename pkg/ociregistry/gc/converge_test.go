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
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestConvergeBetweenMarkAndSweep lands a merge between a sweep's mark and its
// locked pass. target holds an unreferenced blob the mark plans to reap and a
// referenced one, both with a newer copy in keeper, which names both.
func TestConvergeBetweenMarkAndSweep(t *testing.T) {
	for _, tc := range []struct {
		name     string
		merge    bool
		keeperAt time.Duration
		reaped   bool
	}{
		// Without the merge the blob is reaped, so the mark did plan it, and what
		// saves it below is the merge.
		{name: "no merge: the mark's plan stands", keeperAt: -10 * time.Minute, reaped: true},
		{name: "a fresh keeper: the target leaves the locked plan", merge: true, keeperAt: -10 * time.Minute},
		{name: "a keeper past its grace: the target is reaped", merge: true, keeperAt: -2 * time.Hour, reaped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			target, keeper := name(t, "target"), name(t, "keeper")
			e.clk.set(-4 * time.Hour)
			img := e.push(t, target, "v1", "target", []byte("referenced layer"))
			orphan := e.blob(t, target, []byte("unreferenced layer"))
			e.clk.set(tc.keeperAt)
			k := e.push(t, keeper, "v1", "keeper", []byte("referenced layer"), []byte("unreferenced layer"))
			c := e.collector(t, -5*time.Hour)
			e.ran(t)
			e.clk.set(0)

			var once sync.Once
			c.afterMark = func(n ref.Name) {
				if n != target || !tc.merge {
					return
				}
				once.Do(func() {
					rep, err := e.converge()
					if err != nil || rep.Merged != 2 {
						t.Errorf("the pass merged %d (%v), want both of target's copies", rep.Merged, err)
					}
				})
			}
			rep := e.sweep(t, c)

			if got := e.has(target, orphan.Digest); got == tc.reaped {
				t.Errorf("the unreferenced blob in target present = %v, want %v (report %+v)", got, !tc.reaped, rep)
			}
			if got := slices.Contains(objectsOf(rep, KindBlob, target.String()), orphan.Digest.String()); got != tc.reaped {
				t.Errorf("the report names the unreferenced blob = %v, want %v (report %+v)", got, tc.reaped, rep)
			}
			if err := e.whole(target, img); err != nil {
				t.Errorf("a referenced blob: %v", err)
			}
			if err := e.whole(keeper, k); err != nil {
				t.Errorf("the keeper's repository: %v", err)
			}
			if tc.merge {
				if !e.sameInode(t, target, keeper, img.layers[0].Digest) {
					t.Error("the merge did not land on the referenced blob")
				}
				if !tc.reaped && !e.sameInode(t, target, keeper, orphan.Digest) {
					t.Error("the merge did not land on the unreferenced blob")
				}
			}
			if tc.reaped {
				return
			}
			// The survivor is held by the keeper's age, not for good: one grace on,
			// a sweep reaps it and the keeper's repository still reads its bytes.
			e.clk.set(2 * time.Hour)
			rep = e.sweep(t, c)
			if e.has(target, orphan.Digest) {
				t.Errorf("the unreferenced blob outlived the keeper's grace (report %+v)", rep)
			}
			if err := e.whole(keeper, k); err != nil {
				t.Errorf("after the later sweep, the keeper's repository: %v", err)
			}
		})
	}
}

// TestConvergeNeverRacesGC runs passes, sweeps, pushes, touches and readers at
// once over copies old and new, many times over. A tagged image stays whole in
// its bytes, no row dangles, and a name younger than its grace is never reaped
// on the strength of an older copy elsewhere. Run it under -race.
func TestConvergeNeverRacesGC(t *testing.T) {
	e := newEnv(t)
	a, b, fresh := name(t, "a"), name(t, "b"), name(t, "fresh")
	type taggedImage struct {
		n   ref.Name
		img image
	}
	var tagged []taggedImage
	own := func(s string) (ls [][]byte) {
		for i := range 8 {
			ls = append(ls, []byte(s+" own layer "+strconv.Itoa(i)))
		}
		return ls
	}
	e.clk.set(-6 * time.Hour)
	for _, n := range []ref.Name{a, b, fresh} {
		tagged = append(tagged, taggedImage{n, e.push(t, n, "base", n.String(), own(n.String())...)})
	}
	c := e.collector(t, -7*time.Hour)
	e.ran(t)

	const rounds = 6
	var young []digest.Digest
	var mu sync.Mutex
	merged, reaped := 0, 0
	sweep := func() error {
		rep, err := c.Sweep(e.ctx)
		mu.Lock()
		reaped += rep.Count(KindBlob)
		mu.Unlock()
		if err != nil && !errors.Is(err, ErrChanged) {
			return fmt.Errorf("sweep: %w", err)
		}
		return nil
	}
	pass := func() error {
		rep, err := e.converge()
		mu.Lock()
		merged += rep.Merged
		mu.Unlock()
		if err != nil {
			return fmt.Errorf("pass: %w", err)
		}
		return nil
	}
	for i := range rounds {
		is := strconv.Itoa(i)
		// Old copies, oldest in a, and in fresh a young copy of a blob a holds old.
		e.clk.set(-3 * time.Hour)
		img := e.push(t, a, "r"+is, "a"+is, []byte("layer "+is))
		e.blob(t, a, []byte("orphan "+is))
		e.blob(t, a, []byte("young "+is))
		e.clk.set(-2 * time.Hour)
		kept := e.push(t, b, "r"+is, "b"+is, []byte("layer "+is))
		e.blob(t, b, []byte("orphan "+is))
		e.clk.set(-10 * time.Minute)
		young = append(young, e.blob(t, fresh, []byte("young "+is)).Digest)
		// The last round's image in a leaves its tag, so a sweep reaps what a named
		// while b still names the same layer.
		if i > 0 {
			if err := e.s.DeleteTag(e.ctx, a, "r"+strconv.Itoa(i-1)); err != nil {
				t.Fatal(err)
			}
		}
		e.clk.set(0)

		snapshot := slices.Clone(append(tagged, taggedImage{a, img}))
		var pushed image
		err := run(
			func() error {
				for range 3 {
					if err := sweep(); err != nil {
						return err
					}
				}
				return nil
			},
			func() error {
				for range 3 {
					if err := pass(); err != nil {
						return err
					}
				}
				return nil
			},
			func() error { // a reader across the renames
				for range 3 {
					for _, k := range snapshot {
						if err := e.whole(k.n, k.img); err != nil {
							return err
						}
					}
				}
				return nil
			},
			func() error { // a HEAD through what may be a shared inode
				for _, d := range kept.blobs() {
					if err := e.s.TouchBlob(e.ctx, b, d); err != nil {
						return err
					}
				}
				return nil
			},
			func() error { // a push of a copy that may be merged next
				ls, err := pushWith(e, e.s, fresh, []byte("layer "+is), []byte(`{"seed":"pushed `+is+`"}`))
				if err != nil {
					return err
				}
				pushed, err = tagImage(e, e.s, fresh, "p"+is, ls[1], ls[:1])
				return err
			},
		)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		tagged = append(tagged, taggedImage{b, kept}, taggedImage{fresh, pushed})
		noDangling(t, e.s)
		for _, k := range tagged {
			if err := e.whole(k.n, k.img); err != nil {
				t.Errorf("round %d: %v", i, err)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
	}

	// Settle: a pass and a sweep alone. No young name has gone, and no merge has
	// aged one.
	if err := errors.Join(pass(), sweep()); err != nil {
		t.Fatal(err)
	}
	for _, d := range young {
		if !e.has(fresh, d) {
			t.Errorf("a young name was reaped: %s", d)
		}
	}
	rep, err := e.converge()
	if err != nil {
		t.Fatal(err)
	}
	merged += rep.Merged
	if rep.Pending != 0 {
		t.Errorf("%d names still hold a copy after the last pass (report %+v)", rep.Pending, rep)
	}
	// One grace on, what only old names held goes, and every tagged image stays.
	e.clk.set(2 * time.Hour)
	if err := sweep(); err != nil {
		t.Fatal(err)
	}
	noDangling(t, e.s)
	for _, k := range tagged {
		if err := e.whole(k.n, k.img); err != nil {
			t.Error(err)
		}
	}
	for _, n := range []ref.Name{a, b, fresh} {
		cont, err := e.s.Contents(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(cont.Temps) != 0 {
			t.Errorf("%s holds temp links after the settling sweep: %+v", n, cont.Temps)
		}
	}
	if merged == 0 || reaped == 0 {
		t.Fatalf("merged %d, reaped %d: the passes and the sweeps never contended", merged, reaped)
	}
	t.Logf("%d rounds, %d merged, %d reaped", rounds, merged, reaped)
}
