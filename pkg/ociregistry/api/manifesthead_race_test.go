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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// lockWaitCtx is a context that reports the first call to Done. In this
// package's request path and in a sweep, the only caller of Done is the
// store's flock wait, which calls it after a LOCK_NB attempt failed: so the
// report means "this side is now blocked on the repository lock".
type lockWaitCtx struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func newLockWaitCtx() *lockWaitCtx {
	return &lockWaitCtx{Context: context.Background(), waiting: make(chan struct{})}
}

func (c *lockWaitCtx) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

// await blocks until ch is closed. The timeout only turns a broken sequence
// into a failure instead of a hang; no step waits on time to win a race.
func await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// lockHeld reports whether another holder has repo's lock, by trying it with
// a cancelled context: a free lock is taken and released at once, a held one
// fails without waiting.
func (f *fixture) lockHeld(t *testing.T, repo string) bool {
	t.Helper()
	n, err := ref.ParseName(repo)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = f.st.WithLock(ctx, n, func(*store.Locked) error { return nil })
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	return err != nil
}

// hookedCollector is a deleting collector over f's store, as
// deletingCollector, that calls hook on every read of its clock after the
// start check.
func (f *fixture) hookedCollector(t *testing.T, grace time.Duration, hook func()) *gc.Collector {
	t.Helper()
	var mu sync.Mutex
	started := false
	start := time.Now().Add(-2 * grace)
	now := func() time.Time {
		mu.Lock()
		first := !started
		started = true
		mu.Unlock()
		if first {
			return start
		}
		hook()
		return time.Now()
	}
	c, err := gc.New(f.st, gc.Options{Grace: grace, Now: now, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.st.StateDir(), gc.MarkerName), []byte("ran\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// headRequest is a HEAD of the manifest d in repo under ctx.
func headRequest(ctx context.Context, repo string, d digest.Digest) *http.Request {
	return req(http.MethodHead, "/v2/"+repo+"/manifests/"+d.String(), nil).WithContext(ctx)
}

// TestManifestHeadTouchRacesSweep drives the two interleavings of a HEAD by
// digest of an untagged child manifest past the grace and a deleting GC sweep
// through the real repository lock, each in a fixed order:
//
//   - HEAD wins: the sweep marks the child for reaping without the lock, then
//     waits on the lock the HEAD's touch holds; the touch lands, and the
//     sweep's locked re-plan sees the fresh mtime and keeps the child, so the
//     index PUT that follows finds it.
//   - sweep wins: the HEAD reads the child, then waits on the lock the
//     sweep's locked pass holds; the sweep reaps the child and its blobs, and
//     the touch finds the child gone, so the HEAD answers 404. The store is
//     left whole: no row names a missing blob, and a re-push succeeds.
//
// Each side is known to be blocked on the lock, not assumed to be, before the
// other proceeds (lockWaitCtx, lockHeld).
func TestManifestHeadTouchRacesSweep(t *testing.T) {
	const grace = time.Hour
	setup := func(t *testing.T) (*fixture, []byte, ispec.Manifest) {
		f := newFixture(t)
		// A tagged image keeps half of the repository referenced, so the
		// half-repository brake does not hold.
		f.image(t, "app", "kept", "kept-layer")
		child := f.image(t, "app", "", "child-layer")
		var m ispec.Manifest
		if err := json.Unmarshal(child, &m); err != nil {
			t.Fatal(err)
		}
		f.age(t, "app", time.Now().Add(-2*grace), dg(child), m.Config.Digest, m.Layers[0].Digest)
		return f, child, m
	}

	t.Run("HEAD wins: the child is kept and the index PUT succeeds", func(t *testing.T) {
		f, child, m := setup(t)
		cd := dg(child)
		c := f.hookedCollector(t, grace, func() {})
		sweepCtx := newLockWaitCtx()
		swept := make(chan error, 1)
		var once sync.Once
		// The touch's clock is read under the lock, before the mtime is
		// written: start the sweep there and let the touch finish only once
		// the sweep has marked and is blocked on the lock.
		f.st.SetClock(func() time.Time {
			once.Do(func() {
				go func() {
					_, err := c.Sweep(sweepCtx)
					swept <- err
				}()
				await(t, sweepCtx.waiting, "the sweep to block on the lock")
			})
			return time.Now()
		})
		w := f.serve(headRequest(context.Background(), "app", cd))
		f.st.SetClock(time.Now)
		want(t, w, http.StatusOK, "")
		select {
		case err := <-swept:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for the sweep")
		}

		f.index(t, "app", "v1", child)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
		for _, d := range []digest.Digest{m.Config.Digest, m.Layers[0].Digest} {
			want(t, f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
		}
	})

	t.Run("sweep wins: the HEAD answers 404 and nothing is half-deleted", func(t *testing.T) {
		f, child, m := setup(t)
		cd := dg(child)
		headCtx := newLockWaitCtx()
		headed := make(chan int, 1)
		var once sync.Once
		// The sweep reads its clock under the lock before the locked
		// re-plan: start the HEAD there and let the sweep go on only once the
		// HEAD has read the child and is blocked on the lock.
		c := f.hookedCollector(t, grace, func() {
			if !f.lockHeld(t, "app") {
				return
			}
			once.Do(func() {
				go func() { headed <- f.serve(headRequest(headCtx, "app", cd)).Code }()
				await(t, headCtx.waiting, "the HEAD to block on the lock")
			})
		})
		if _, err := c.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		select {
		case code := <-headed:
			if code != http.StatusNotFound {
				t.Fatalf("HEAD after the sweep reaped the child: status %d, want 404", code)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for the HEAD (did the sweep never take the lock?)")
		}

		// Nothing half-deleted: the row and every blob of the child are gone
		// together, and the tagged image is whole.
		if slices.ContainsFunc(f.rows(t, "app"), func(r ispec.Descriptor) bool { return r.Digest == cd }) {
			t.Error("the child's row survived the sweep that reaped its body")
		}
		for _, d := range []digest.Digest{cd, m.Config.Digest, m.Layers[0].Digest} {
			if _, err := os.Stat(f.blobFile("app", d)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("blob %s of the reaped child: stat %v, want not exist", d, err)
			}
		}
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusNotFound, codeManifestUnknown)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/kept", nil), http.StatusOK, "")
		// The client, told 404, pushes the child again, then the index.
		if got := f.image(t, "app", "", "child-layer"); dg(got) != cd {
			t.Fatalf("re-pushed child %s, want %s", dg(got), cd)
		}
		f.index(t, "app", "v1", child)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
	})
}
