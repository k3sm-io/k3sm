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
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// secondStore opens another Store over e's root and state, as a second
// process would. The repository lock is a flock on a file in the state
// directory, so the two contend for it like two processes do.
func (e *env) secondStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(e.s.Root(), e.s.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(e.clk.now)
	return s
}

// noDangling requires that every row of every repository resolves to a
// manifest whose config, layers and children are all present.
func noDangling(t *testing.T, s *store.Store) {
	t.Helper()
	repos, err := s.Repositories()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range repos {
		idx, err := s.Index(n)
		if err != nil {
			t.Fatalf("index of %s: %v", n, err)
		}
		read := (&Collector{s: s}).reader(n)
		for _, r := range idx.Manifests {
			b, err := read(r.Digest)
			if err != nil {
				t.Errorf("%s row %s: %v", n, r.Digest, err)
				continue
			}
			m, err := parseRefs(r.Digest, b)
			if err != nil {
				t.Errorf("%s row %s: %v", n, r.Digest, err)
				continue
			}
			var named []digest.Digest
			if m.Config != nil {
				named = append(named, m.Config.Digest)
			}
			for _, l := range append(m.Layers, m.Manifests...) {
				named = append(named, l.Digest)
			}
			for _, d := range named {
				if _, err := s.StatBlob(n, d); err != nil {
					t.Errorf("%s row %s names %s: %v", n, r.Digest, d, err)
				}
			}
		}
	}
}

// pushWith uploads blobs to s through the session API (NewUpload, append,
// CommitUpload) and returns their descriptors.
func pushWith(e *env, s *store.Store, n ref.Name, bodies ...[]byte) ([]ispec.Descriptor, error) {
	var out []ispec.Descriptor
	for _, b := range bodies {
		id, err := s.NewUpload(e.ctx, n)
		if err != nil {
			return nil, err
		}
		half := len(b) / 2
		if _, err := s.AppendUpload(e.ctx, n, id, 0, bytes.NewReader(b[:half])); err != nil {
			return nil, err
		}
		if _, err := s.AppendUpload(e.ctx, n, id, int64(half), bytes.NewReader(b[half:])); err != nil {
			return nil, err
		}
		d := digest.FromBytes(b)
		if err := s.CommitUpload(e.ctx, n, id, d); err != nil {
			return nil, err
		}
		out = append(out, ispec.Descriptor{MediaType: ispec.MediaTypeImageLayer, Digest: d, Size: int64(len(b))})
	}
	return out, nil
}

// mountOrPush mounts d from another repository, falling back to an upload
// of body when the source no longer holds it, as a client does.
func mountOrPush(e *env, s *store.Store, n, from ref.Name, d ispec.Descriptor, body []byte) error {
	err := s.MountBlob(e.ctx, n, from, d.Digest)
	if errors.Is(err, store.ErrMountUnavailable) {
		_, err = pushWith(e, s, n, body)
	}
	return err
}

// tagImage puts a manifest naming cfg and layers under tag.
func tagImage(e *env, s *store.Store, n ref.Name, tag string, cfg ispec.Descriptor, layers []ispec.Descriptor) (image, error) {
	cfg.MediaType = ispec.MediaTypeImageConfig
	img := image{config: cfg, layers: layers}
	b, err := jsonManifest(cfg, layers)
	if err != nil {
		return img, err
	}
	img.body = b
	img.manifest, err = s.PutManifest(e.ctx, n, ref.Reference{Tag: tag}, ispec.MediaTypeImageManifest, b)
	return img, err
}

// run starts every fn at once and waits for all of them, collecting errors.
func run(fns ...func() error) error {
	start := make(chan struct{})
	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn()
		}()
	}
	close(start)
	wg.Wait()
	return errors.Join(errs...)
}

// TestConcurrentPushesAndSweeps runs pushes from two Store instances over
// one root (uploads, re-uploads of old orphans, cross-repository mounts, a
// tag of an old untagged manifest) in goroutines while sweeps run in
// another, many times over. Every tagged image stays whole and no row
// dangles, and the sweeps do reap old garbage meanwhile.
func TestConcurrentPushesAndSweeps(t *testing.T) {
	e := newEnv(t)
	s2 := e.secondStore(t)
	src, dst := name(t, "src"), name(t, "dst")
	e.clk.set(-2 * time.Hour)
	base := e.push(t, src, "base", "base", []byte("b1"), []byte("b2"), []byte("b3"), []byte("b4"), []byte("b5"), []byte("b6"))
	if _, err := tagImage(e, e.s, dst, "seed", base.config, nil); err != nil {
		t.Fatal(err)
	}
	c := e.collector(t, -3*time.Hour)
	e.ran(t)

	const iterations = 6
	var tagged []struct {
		n   ref.Name
		tag string
		img image
	}
	keep := func(n ref.Name, tag string, img image) {
		tagged = append(tagged, struct {
			n   ref.Name
			tag string
			img image
		}{n, tag, img})
	}
	var mu sync.Mutex
	reapedBlobs := 0
	for i := range iterations {
		is := strconv.Itoa(i)
		// Old garbage the sweeps will want: two orphan blobs and an
		// untagged image, all past the grace.
		e.clk.set(-2 * time.Hour)
		oa := e.blob(t, src, []byte("orphan a "+is))
		ob := e.blob(t, src, []byte("orphan b "+is))
		u := e.push(t, src, "", "untagged "+is, []byte("untagged layer "+is))
		e.clk.set(0)

		results := make([]image, 4)
		err := run(
			func() error { // sweeps
				for range 3 {
					rep, err := c.Sweep(e.ctx)
					mu.Lock()
					reapedBlobs += rep.Count(KindBlob)
					mu.Unlock()
					if err != nil && !errors.Is(err, ErrMassDelete) {
						return fmt.Errorf("sweep: %w", err)
					}
				}
				return nil
			},
			func() error { // re-upload an old orphan and name it
				ls, err := pushWith(e, e.s, src, []byte("orphan a "+is), []byte(`{"cfg":"a`+is+`"}`))
				if err != nil {
					return err
				}
				results[0], err = tagImage(e, e.s, src, "a"+is, ls[1], []ispec.Descriptor{oa})
				return err
			},
			func() error { // mount an old orphan from the second store and name it
				if err := mountOrPush(e, s2, dst, src, ob, []byte("orphan b "+is)); err != nil {
					return err
				}
				ls, err := pushWith(e, s2, dst, []byte(`{"cfg":"b`+is+`"}`))
				if err != nil {
					return err
				}
				results[1], err = tagImage(e, s2, dst, "b"+is, ls[0], []ispec.Descriptor{ob})
				return err
			},
			func() error { // tag the old untagged image, its blobs uploaded again
				if _, err := pushWith(e, s2, src, []byte(`{"seed":"untagged `+is+`"}`), []byte("untagged layer "+is)); err != nil {
					return err
				}
				var err error
				results[2], err = tagImage(e, s2, src, "u"+is, u.config, u.layers)
				return err
			},
			func() error { // mount the tagged base into dst and name it
				for _, d := range append([]ispec.Descriptor{base.config}, base.layers...) {
					if err := mountOrPush(e, e.s, dst, src, d, nil); err != nil {
						return err
					}
				}
				var err error
				results[3], err = tagImage(e, e.s, dst, "base"+is, base.config, base.layers)
				return err
			},
		)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		keep(src, "a"+is, results[0])
		keep(dst, "b"+is, results[1])
		keep(src, "u"+is, results[2])
		keep(dst, "base"+is, results[3])
		noDangling(t, e.s)
		if t.Failed() {
			t.Fatalf("iteration %d left a dangling row", i)
		}
	}
	// Settle: the pushes are past the grace now; tags keep them.
	e.clk.set(2 * time.Hour)
	for range 2 {
		if _, err := c.Sweep(e.ctx); err != nil && !errors.Is(err, ErrMassDelete) {
			t.Fatal(err)
		}
	}
	noDangling(t, e.s)
	for _, k := range append(tagged, struct {
		n   ref.Name
		tag string
		img image
	}{src, "base", base}) {
		if _, _, err := e.s.Manifest(k.n, ref.Reference{Tag: k.tag}); err != nil {
			t.Errorf("%s:%s: %v", k.n, k.tag, err)
		}
		for _, d := range k.img.blobs() {
			if !e.has(k.n, d) {
				t.Errorf("%s:%s lost %s", k.n, k.tag, d)
			}
		}
	}
	if reapedBlobs == 0 {
		t.Fatal("no sweep reaped a blob: the sweeps never contended with garbage")
	}
	t.Logf("%d iterations, %d blobs reaped during the pushes", iterations, reapedBlobs)
}

// TestRemoveLayoutRacesAPush races a sweep that would remove an empty
// repository's layout with a session start, an upload commit and a mount into
// that repository, from two Store instances. Whichever wins, the repository
// ends whole, listed, and holding what the push wrote.
func TestRemoveLayoutRacesAPush(t *testing.T) {
	e := newEnv(t)
	s2 := e.secondStore(t)
	src := name(t, "src")
	e.clk.set(-2 * time.Hour)
	base := e.push(t, src, "base", "base", []byte("layer"))
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	const iterations = 12
	removed := 0
	for i := range iterations {
		is := strconv.Itoa(i)
		n := name(t, "gone"+is)
		if err := e.s.Init(e.ctx, n); err != nil {
			t.Fatal(err)
		}
		e.backdate(t, e.dir(t, n)+"/index.json", -2*time.Hour)
		var pushed []ispec.Descriptor
		var id string
		// In even iterations the pushes start when the sweep has marked n as
		// empty and goes for its lock, which the sweep then mostly wins; in
		// odd ones they start with the sweep, which reaches n last and mostly
		// loses. Either way both contend for n's lock.
		marked, swept := make(chan struct{}), make(chan struct{})
		if i%2 == 1 {
			close(marked)
		}
		var once sync.Once
		c.afterMark = func(m ref.Name) {
			if m == n && i%2 == 0 {
				once.Do(func() { close(marked) })
			}
		}
		wait := func() {
			select {
			case <-marked:
			case <-swept:
			}
		}
		err := run(
			func() error {
				defer close(swept)
				rep, err := c.Sweep(e.ctx)
				removed += rep.Count(KindRepository)
				return err
			},
			func() error {
				wait()
				var err error
				pushed, err = pushWith(e, s2, n, []byte(`{"cfg":"`+is+`"}`))
				return err
			},
			func() error {
				wait()
				var err error
				id, err = e.s.NewUpload(e.ctx, n)
				return err
			},
			func() error { wait(); return mountOrPush(e, e.s, n, src, base.layers[0], nil) },
		)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		repos, err := e.s.Repositories()
		if err != nil || !containsName(repos, n) {
			t.Fatalf("iteration %d: %s not listed after the push: %v, %v", i, n, repos, err)
		}
		if _, err := e.s.AppendUpload(e.ctx, n, id, 0, bytes.NewReader([]byte("x"))); err != nil {
			t.Fatalf("iteration %d: the session started during the sweep: %v", i, err)
		}
		if _, err := tagImage(e, e.s, n, "v1", pushed[0], base.layers); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		noDangling(t, e.s)
		if t.Failed() {
			t.Fatalf("iteration %d", i)
		}
	}
	t.Logf("%d iterations, the sweep removed the layout first in %d", iterations, removed)
	if removed == 0 || removed == iterations {
		t.Logf("only one order of the race ran")
	}
}

func containsName(ns []ref.Name, n ref.Name) bool {
	for _, x := range ns {
		if x == n {
			return true
		}
	}
	return false
}

func jsonManifest(cfg ispec.Descriptor, layers []ispec.Descriptor) ([]byte, error) {
	return json.Marshal(ispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageManifest, Config: cfg, Layers: layers})
}
