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
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// world runs one interleaving against either the collector (guarded) or a
// variant without the on-disk guard: a store whose mount, link and commit do
// not touch the blob inode (each touch is undone), and a sweep that deletes
// what it marked from its snapshot, without re-reading index.json or
// re-stating a candidate under the lock, and without the start delay. The
// interleaving records each broken promise instead of failing, so the same
// script proves the collector keeps every one and the variant breaks some.
type world struct {
	*env
	guarded  bool
	failures []string
}

func (w *world) check(ok bool, format string, args ...any) {
	if !ok {
		w.failures = append(w.failures, fmt.Sprintf(format, args...))
	}
}

// touched is called after a store write that touched blob d of n; prev is
// the inode's mtime before it. The variant undoes the touch.
func (w *world) touched(t *testing.T, n ref.Name, d ispec.Descriptor, prev time.Time) {
	t.Helper()
	if w.guarded {
		return
	}
	if err := os.Chtimes(w.blobFile(t, n, d.Digest), prev, prev); err != nil {
		t.Fatal(err)
	}
}

// sweep runs one sweep; hook, when set, runs once, between the first
// repository's mark and its delete.
func (w *world) sweep(t *testing.T, c *Collector, hook func()) error {
	t.Helper()
	var once sync.Once
	between := func() {
		if hook != nil {
			once.Do(hook)
		}
	}
	if w.guarded {
		c.afterMark = func(ref.Name) { between() }
		_, err := c.Sweep(w.ctx)
		return err
	}
	repos, err := w.s.Repositories()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range repos {
		p, idx, _, err := c.mark(n, c.now().Add(-c.grace))
		if err != nil {
			t.Fatal(err)
		}
		between()
		err = w.s.WithLock(w.ctx, n, func(l *store.Locked) error {
			if len(p.rows) > 0 {
				rows := slices.DeleteFunc(slices.Clone(idx.Manifests), func(r ispec.Descriptor) bool { return p.rows[r.Digest] })
				if err := l.SetRows(rows); err != nil {
					return err
				}
			}
			for d := range p.blobs {
				_ = l.RemoveBlob(d) // the variant deletes on the snapshot's word
			}
			for id := range p.sessions {
				_ = os.Remove(w.sessionFile(t, n, id))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return nil
}

// mount mounts blob d of from into n, as a client's cross-repository mount.
func (w *world) mount(t *testing.T, n, from ref.Name, d ispec.Descriptor) {
	t.Helper()
	prev := w.mtime(t, w.blobFile(t, from, d.Digest))
	if err := w.s.MountBlob(w.ctx, n, from, d.Digest); err != nil {
		t.Fatal(err)
	}
	w.touched(t, n, d, prev)
}

// repush uploads an existing blob again (the commit keeps the stored file).
func (w *world) repush(t *testing.T, n ref.Name, d ispec.Descriptor, body []byte) {
	t.Helper()
	prev := w.mtime(t, w.blobFile(t, n, d.Digest))
	if err := w.s.PutBlob(w.ctx, n, d.Digest, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	w.touched(t, n, d, prev)
}

// tagManifest puts an existing manifest body under tag.
func (w *world) tagManifest(t *testing.T, n ref.Name, tag string, desc ispec.Descriptor, body []byte) {
	t.Helper()
	prev := w.mtime(t, w.blobFile(t, n, desc.Digest))
	w.putManifest(t, n, tag, ispec.MediaTypeImageManifest, body)
	w.touched(t, n, desc, prev)
}

// readable checks that n:tag resolves and every blob it names is present.
func (w *world) readable(t *testing.T, n ref.Name, tag string, img image) {
	t.Helper()
	_, _, err := w.s.Manifest(n, ref.Reference{Tag: tag})
	w.check(err == nil, "%s:%s does not resolve: %v", n, tag, err)
	for _, d := range img.blobs() {
		w.check(w.has(n, d), "%s:%s names %s, which is gone", n, tag, d)
	}
}

var interleavings = []struct {
	name string
	run  func(t *testing.T, w *world)
}{
	{
		// A client mounts layers it is about to name, then GC sweeps
		// before the manifest arrives. The source blobs are hours old;
		// the mount is what makes them young in the target.
		name: "mount then sweep",
		run: func(t *testing.T, w *world) {
			src, dst := name(t, "src"), name(t, "dst")
			w.clk.set(-2 * time.Hour)
			img := w.push(t, src, "v1", "base", []byte("layer"))
			c := w.collector(t, -3*time.Hour)
			w.ran(t)

			w.clk.set(0)
			w.mount(t, dst, src, img.config)
			w.mount(t, dst, src, img.layers[0])
			w.check(w.sweep(t, c, nil) == nil, "sweep failed")
			w.putManifest(t, dst, "v1", ispec.MediaTypeImageManifest, img.body)
			w.readable(t, dst, "v1", img)
		},
	},
	{
		// GC marks an untagged image and an idle-looking session; between
		// mark and delete the client pushes the same image again (every
		// blob already stored, so each commit keeps the existing file) and
		// sends the session another chunk.
		name: "upload during the sweep",
		run: func(t *testing.T, w *world) {
			n := name(t, "app")
			w.clk.set(-2 * time.Hour)
			img := w.push(t, n, "v1", "app", []byte("app layer"))
			if err := w.s.DeleteTag(w.ctx, n, "v1"); err != nil {
				t.Fatal(err)
			}
			id := w.session(t, n, "first chunk ")
			w.backdate(t, w.sessionFile(t, n, id), -2*time.Hour)
			c := w.collector(t, -3*time.Hour)
			w.ran(t)

			w.clk.set(0)
			err := w.sweep(t, c, func() {
				w.repush(t, n, img.config, []byte(`{"seed":"app"}`))
				w.repush(t, n, img.layers[0], []byte("app layer"))
				w.tagManifest(t, n, "v1", img.manifest, img.body)
				if _, err := w.s.AppendUpload(w.ctx, n, id, -1, bytes.NewReader([]byte("second chunk"))); err != nil {
					t.Fatal(err)
				}
			})
			w.check(err == nil, "sweep failed: %v", err)
			w.readable(t, n, "v1", img)
			size, err := w.s.UploadSize(w.ctx, n, id)
			w.check(err == nil && size == int64(len("first chunk second chunk")), "the live session was reaped: %d, %v", size, err)
		},
	},
	{
		// GC marks an orphan layer and an untagged manifest; between mark
		// and delete a client that found the layer present (and so did not
		// upload it) puts a manifest naming it, and another tags the
		// untagged manifest.
		name: "manifest PUT racing a delete",
		run: func(t *testing.T, w *world) {
			n := name(t, "app")
			w.clk.set(-2 * time.Hour)
			keep := w.push(t, n, "keep", "keep", []byte("k1"), []byte("k2"), []byte("k3"), []byte("k4"))
			orphan := w.blob(t, n, []byte("orphan layer"))
			untagged := w.push(t, n, "", "untagged", []byte("untagged layer"))
			c := w.collector(t, -3*time.Hour)
			w.ran(t)

			w.clk.set(0)
			var fresh image
			err := w.sweep(t, c, func() {
				_, err := w.s.StatBlob(n, orphan.Digest) // the client's HEAD
				if err != nil {
					t.Fatal(err)
				}
				fresh.config = w.blob(t, n, []byte(`{"seed":"fresh"}`))
				fresh.layers = []ispec.Descriptor{orphan}
				fresh.body = manifestBody(t, fresh.config, fresh.layers, nil)
				fresh.manifest = w.putManifest(t, n, "fresh", ispec.MediaTypeImageManifest, fresh.body)
				w.tagManifest(t, n, "late", untagged.manifest, untagged.body)
			})
			w.check(err == nil, "sweep failed: %v", err)
			w.readable(t, n, "fresh", fresh)
			w.readable(t, n, "late", untagged)
			w.readable(t, n, "keep", keep)
		},
	},
	{
		// The previous process mounted layers ten minutes ago; the server
		// restarts, so a new collector holds nothing in memory, and the
		// blobs themselves are two hours old. The client names them
		// fifty minutes later, inside the grace of its mount.
		name: "restart while a mounted blob is older than the grace",
		run: func(t *testing.T, w *world) {
			src, dst := name(t, "src"), name(t, "dst")
			w.clk.set(-2 * time.Hour)
			img := w.push(t, src, "v1", "base", []byte("layer"))
			w.clk.set(-10 * time.Minute)
			w.mount(t, dst, src, img.config)
			w.mount(t, dst, src, img.layers[0])
			w.ran(t)

			c := w.collector(t, -5*time.Minute) // the restart
			err := w.sweep(t, c, nil)
			if w.guarded {
				w.check(errors.Is(err, ErrTooSoon), "a sweep ran at start: %v", err)
			}
			w.clk.set(54 * time.Minute)
			err = w.sweep(t, c, nil)
			if w.guarded {
				w.check(errors.Is(err, ErrTooSoon), "a sweep ran within the grace of start: %v", err)
			}
			w.clk.set(50 * time.Minute)
			w.putManifest(t, dst, "v1", ispec.MediaTypeImageManifest, img.body)
			w.clk.set(56 * time.Minute)
			w.check(w.sweep(t, c, nil) == nil, "sweep failed")
			w.readable(t, dst, "v1", img)
		},
	},
}

// TestGCNeverRacesAPush runs each interleaving of a push with a sweep and
// requires that everything the push wrote or named survives.
func TestGCNeverRacesAPush(t *testing.T) {
	for _, il := range interleavings {
		t.Run(il.name, func(t *testing.T) {
			w := &world{env: newEnv(t), guarded: true}
			il.run(t, w)
			for _, f := range w.failures {
				t.Error(f)
			}
		})
	}
}

// TestGCNeverRacesAPushIsRedWithoutTheGuard runs the same interleavings
// against the variant without the on-disk guard and requires that each one
// loses something the push needed: the interleavings are not vacuous.
func TestGCNeverRacesAPushIsRedWithoutTheGuard(t *testing.T) {
	for _, il := range interleavings {
		t.Run(il.name, func(t *testing.T) {
			w := &world{env: newEnv(t), guarded: false}
			il.run(t, w)
			if len(w.failures) == 0 {
				t.Fatal("the unguarded variant kept everything: the interleaving does not exercise the guard")
			}
			for _, f := range w.failures {
				t.Logf("unguarded: %s", f)
			}
		})
	}
}
