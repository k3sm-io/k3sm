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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// holdLock takes repo's repository lock and holds it until the returned
// release runs (it may run more than once; the test's cleanup runs it too).
func (f *fixture) holdLock(t *testing.T, repo string) (release func()) {
	t.Helper()
	n, err := ref.ParseName(repo)
	if err != nil {
		t.Fatal(err)
	}
	locked, done, unlock := make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() {
		done <- f.st.WithLock(context.Background(), n, func(*store.Locked) error {
			close(locked)
			<-unlock
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-done:
		t.Fatalf("lock %s: %v", repo, err)
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			close(unlock)
			if err := <-done; err != nil {
				t.Errorf("lock %s: %v", repo, err)
			}
		})
	}
	t.Cleanup(release)
	return release
}

// headNoLock HEADs path while the caller holds the repository lock and fails
// the test when the HEAD waits on that lock; release lets a waiting HEAD
// finish so its answer is still returned.
func (f *fixture) headNoLock(t *testing.T, path string, release func()) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.do(http.MethodHead, path, nil) }()
	select {
	case w := <-done:
		return w
	case <-time.After(10 * time.Second):
		t.Errorf("HEAD %s waited on the repository lock", path)
		release()
		return <-done
	}
}

// mtime is the mtime of blob d in repo.
func (f *fixture) mtime(t *testing.T, repo string, d digest.Digest) time.Time {
	t.Helper()
	fi, err := os.Stat(f.blobFile(repo, d))
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

// TestManifestHeadTouchIsBounded pins the bound on the write a HEAD makes. A
// HEAD by digest of a manifest, and a blob HEAD, restart the object's GC grace
// only when less than half of it is left, and a manifest only when its row is
// untagged; otherwise the HEAD takes no repository lock and writes nothing,
// so a looped anonymous HEAD cannot keep an object young for ever or queue
// behind pushes and sweeps. A touch that fails for a reason other than the
// object being gone is logged and the HEAD still answers 200. The positive
// cases (an untagged row and a blob past the half-grace are touched, and an
// untagged child HEADed and then named by an index PUT survives a sweep) keep
// the test from passing on a HEAD that never writes.
func TestManifestHeadTouchIsBounded(t *testing.T) {
	const grace = time.Hour
	withGrace := func(c *Config) { c.GCGrace = grace }
	// untagged pushes an untagged image and returns its manifest digest and
	// its layer's digest.
	untagged := func(t *testing.T, f *fixture, layer string) (digest.Digest, digest.Digest) {
		body := f.image(t, "app", "", layer)
		var m ispec.Manifest
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		return dg(body), m.Layers[0].Digest
	}

	t.Run("repeated HEADs inside the half-grace take no lock and write nothing", func(t *testing.T) {
		f := newFixture(t, withGrace)
		md, ld := untagged(t, f, "fresh-layer")
		young := time.Now().Add(-grace / 4).Truncate(time.Second)
		f.age(t, "app", young, md, ld)
		release := f.holdLock(t, "app")
		for range 3 {
			for _, path := range []string{"/v2/app/manifests/" + md.String(), "/v2/app/blobs/" + ld.String()} {
				want(t, f.headNoLock(t, path, release), http.StatusOK, "")
			}
		}
		release()
		for _, d := range []digest.Digest{md, ld} {
			if got := f.mtime(t, "app", d); !got.Equal(young) {
				t.Errorf("%s mtime %s after HEADs inside the half-grace, want %s", d, got, young)
			}
		}
	})

	t.Run("a HEAD by digest of a tagged row writes nothing", func(t *testing.T) {
		f := newFixture(t, withGrace)
		md := dg(f.image(t, "app", "v1", "tagged-layer"))
		old := time.Now().Add(-2 * grace).Truncate(time.Second)
		f.age(t, "app", old, md)
		release := f.holdLock(t, "app")
		want(t, f.headNoLock(t, "/v2/app/manifests/"+md.String(), release), http.StatusOK, "")
		release()
		if got := f.mtime(t, "app", md); !got.Equal(old) {
			t.Errorf("tagged manifest mtime %s after a HEAD by digest, want %s", got, old)
		}
	})

	t.Run("an untagged row and a blob past the half-grace are touched", func(t *testing.T) {
		f := newFixture(t, withGrace)
		md, ld := untagged(t, f, "old-layer")
		old := time.Now().Add(-grace * 3 / 4).Truncate(time.Second)
		f.age(t, "app", old, md, ld)
		want(t, f.do(http.MethodHead, "/v2/app/manifests/"+md.String(), nil), http.StatusOK, "")
		want(t, f.do(http.MethodHead, "/v2/app/blobs/"+ld.String(), nil), http.StatusOK, "")
		for _, d := range []digest.Digest{md, ld} {
			if got := f.mtime(t, "app", d); !got.After(old) {
				t.Errorf("%s mtime %s after a HEAD past the half-grace, want later than %s", d, got, old)
			}
		}
	})

	t.Run("HEADs on a failing store answer 200, take the lock once and log once", func(t *testing.T) {
		var logs bytes.Buffer
		var mu sync.Mutex
		f := newFixture(t, withGrace, func(c *Config) {
			c.Logger = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &mu}, nil))
		})
		md, ld := untagged(t, f, "ro-layer")
		old := time.Now().Add(-2 * grace).Truncate(time.Second)
		f.age(t, "app", old, md, ld)
		calls := 0
		f.st.SetFutimes(func(*os.File, time.Time) error { calls++; return syscall.EROFS })
		for range 5 {
			w := f.do(http.MethodHead, "/v2/app/manifests/"+md.String(), nil)
			want(t, w, http.StatusOK, "")
			if got := w.Header().Get("Docker-Content-Digest"); got != md.String() {
				t.Errorf("HEAD Docker-Content-Digest %q, want %s", got, md)
			}
			want(t, f.do(http.MethodHead, "/v2/app/blobs/"+ld.String(), nil), http.StatusOK, "")
		}
		// futimes runs under the lock, so one call per object is one lock.
		if calls != 2 {
			t.Errorf("futimes called %d times over 5 HEADs of each object, want 2 (one per object)", calls)
		}
		// Later HEADs inside the window take no lock at all.
		release := f.holdLock(t, "app")
		want(t, f.headNoLock(t, "/v2/app/manifests/"+md.String(), release), http.StatusOK, "")
		want(t, f.headNoLock(t, "/v2/app/blobs/"+ld.String(), release), http.StatusOK, "")
		release()
		mu.Lock()
		got := logs.String()
		mu.Unlock()
		if n := strings.Count(got, "grace touch failed"); n != 2 {
			t.Errorf("logged %d failed touches, want 2; log:\n%s", n, got)
		}
	})

	t.Run("a HEAD that gives up waiting for the lock is suppressed like a failed touch", func(t *testing.T) {
		var logs bytes.Buffer
		var mu sync.Mutex
		f := newFixture(t, withGrace, func(c *Config) {
			c.Logger = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &mu}, nil))
		})
		md, _ := untagged(t, f, "wait-layer")
		f.age(t, "app", time.Now().Add(-2*grace), md)
		release := f.holdLock(t, "app")
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		want(t, f.serve(req(http.MethodHead, "/v2/app/manifests/"+md.String(), nil).WithContext(ctx)), http.StatusOK, "")
		for range 3 {
			want(t, f.headNoLock(t, "/v2/app/manifests/"+md.String(), release), http.StatusOK, "")
		}
		release()
		mu.Lock()
		got := logs.String()
		mu.Unlock()
		if n := strings.Count(got, "grace touch failed"); n != 1 {
			t.Errorf("logged %d failed touches, want 1; log:\n%s", n, got)
		}
	})

	t.Run("a zero or negative grace makes New fail", func(t *testing.T) {
		st, err := store.OpenWorkDir(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range []time.Duration{0, -time.Second} {
			if _, err := New(Config{Store: st, Authorize: AllowAll, GCGrace: g}); err == nil {
				t.Errorf("New allowed a server with GC grace %s", g)
			}
		}
	})

	t.Run("a digest with both a tagged and an untagged row writes nothing", func(t *testing.T) {
		f := newFixture(t, withGrace)
		md := dg(f.image(t, "app", "v1", "both-layer"))
		p := filepath.Join(f.root, "app", "index.json")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var idx ispec.Index
		if err := json.Unmarshal(b, &idx); err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(idx.Manifests, func(d ispec.Descriptor) bool { return d.Digest == md })
		row := idx.Manifests[i]
		row.Annotations = nil
		// The untagged row first, so the HEAD resolves to it.
		idx.Manifests = append([]ispec.Descriptor{row}, idx.Manifests...)
		if b, err = json.Marshal(idx); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * grace).Truncate(time.Second)
		f.age(t, "app", old, md)
		release := f.holdLock(t, "app")
		want(t, f.headNoLock(t, "/v2/app/manifests/"+md.String(), release), http.StatusOK, "")
		release()
		if got := f.mtime(t, "app", md); !got.Equal(old) {
			t.Errorf("manifest with a tagged row has mtime %s after a HEAD by digest, want %s", got, old)
		}
	})

	t.Run("an untagged child HEADed and then named by an index PUT survives a sweep", func(t *testing.T) {
		f := newFixture(t, withGrace)
		f.image(t, "app", "kept", "kept-layer")
		child := f.image(t, "app", "", "child-layer")
		cd := dg(child)
		var m ispec.Manifest
		if err := json.Unmarshal(child, &m); err != nil {
			t.Fatal(err)
		}
		f.age(t, "app", time.Now().Add(-2*grace), cd, m.Config.Digest, m.Layers[0].Digest)
		c := f.deletingCollector(t, grace)
		want(t, f.do(http.MethodHead, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
		if _, err := c.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.index(t, "app", "v1", child)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
		for _, d := range []digest.Digest{m.Config.Digest, m.Layers[0].Digest} {
			want(t, f.do(http.MethodGet, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
		}
	})
}

// TestTouchFailsIsBounded pins the suppression map's bound: past max entries
// the one whose window ends first is evicted, and a closed window is
// forgotten.
func TestTouchFailsIsBounded(t *testing.T) {
	now := time.Now()
	tf := newTouchFails(3)
	key := func(i int) touchKey { return touchKey{repo: "app", digest: digest.FromString(strconv.Itoa(i))} }
	for i := range 4 {
		tf.add(key(i), now.Add(time.Duration(i+1)*time.Minute))
	}
	if len(tf.until) != 3 {
		t.Fatalf("map holds %d entries, want 3", len(tf.until))
	}
	if tf.suppressed(key(0), now) {
		t.Error("the entry whose window ends first was not evicted")
	}
	for i := 1; i < 4; i++ {
		if !tf.suppressed(key(i), now) {
			t.Errorf("entry %d not suppressed inside its window", i)
		}
	}
	if tf.suppressed(key(1), now.Add(2*time.Minute)) {
		t.Error("entry 1 still suppressed at the end of its window")
	}
	if _, ok := tf.until[key(1)]; ok {
		t.Error("a closed window was not forgotten")
	}
}

// lockedWriter serialises writes to w under mu.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
