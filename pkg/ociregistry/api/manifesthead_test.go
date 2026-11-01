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
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/gc"
)

// blobFile is the path of blob d in repo.
func (f *fixture) blobFile(repo string, d digest.Digest) string {
	return filepath.Join(f.root, repo, "blobs", d.Algorithm().String(), d.Encoded())
}

// age sets the mtime of each blob in ds to at.
func (f *fixture) age(t *testing.T, repo string, at time.Time, ds ...digest.Digest) {
	t.Helper()
	for _, d := range ds {
		if err := os.Chtimes(f.blobFile(repo, d), at, at); err != nil {
			t.Fatal(err)
		}
	}
}

// deletingCollector is a collector over f's store that started two grace
// periods ago and has already run its report-only first sweep, so its next
// sweep deletes.
func (f *fixture) deletingCollector(t *testing.T, grace time.Duration) *gc.Collector {
	t.Helper()
	start := time.Now().Add(-2 * grace)
	now := func() time.Time { return start }
	c, err := gc.New(f.st, gc.Options{Grace: grace, Now: func() time.Time { return now() }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	now = time.Now
	if err := os.WriteFile(filepath.Join(f.st.StateDir(), gc.MarkerName), []byte("ran\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestManifestHeadKeepsTheChildForTheIndexPut pins the server contract between
// a client pushing an index and the online garbage collector: the client HEADs
// each child manifest by digest, skips the push of every child the HEAD finds,
// and PUTs the index. A sweep that runs between the HEAD and the PUT must not
// reap a child the HEAD reported present, however old and untagged it was,
// and the PUT must answer 201 with the child kept. Without the HEAD the same
// sweep reaps the child, so the test is not vacuous; the index PUT is then
// still accepted, because an index never requires its children, and names a
// child the registry no longer holds: the dangling index the HEAD prevents.
func TestManifestHeadKeepsTheChildForTheIndexPut(t *testing.T) {
	const grace = time.Hour
	for _, tc := range []struct {
		name string
		head bool
	}{
		{"a HEAD hit by digest survives the sweep", true},
		{"without a HEAD the sweep reaps the child", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// A tagged image keeps half of the repository referenced, so the
			// sweep's half-repository brake does not hold.
			f.image(t, "app", "kept", "kept-layer")
			child := f.image(t, "app", "", "child-layer")
			cd := dg(child)
			var m ispec.Manifest
			if err := json.Unmarshal(child, &m); err != nil {
				t.Fatal(err)
			}
			// The child and its blobs are left from an index push that never
			// PUT its index, two grace periods ago.
			f.age(t, "app", time.Now().Add(-2*grace), cd, m.Config.Digest, m.Layers[0].Digest)
			c := f.deletingCollector(t, grace)

			if tc.head {
				w := f.do(http.MethodHead, "/v2/app/manifests/"+cd.String(), nil)
				want(t, w, http.StatusOK, "")
				if got := w.Header().Get("Docker-Content-Digest"); got != cd.String() {
					t.Fatalf("HEAD Docker-Content-Digest %q, want %s", got, cd)
				}
			}
			if _, err := c.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !tc.head {
				want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusNotFound, codeManifestUnknown)
			}

			f.index(t, "app", "v1", child)
			if !tc.head {
				want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusNotFound, codeManifestUnknown)
				return
			}
			want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
			for _, d := range []digest.Digest{m.Config.Digest, m.Layers[0].Digest} {
				want(t, f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
			}
			// The child is now named by a tagged index, so a later sweep keeps
			// it at any age.
			f.age(t, "app", time.Now().Add(-2*grace), cd)
			if _, err := c.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
		})
	}
}

// TestManifestReadsThatWriteNothing pins the reads that leave a tagged
// manifest's mtime alone: a HEAD by tag or by digest (a tagged row is kept at
// any age) and a GET by tag or by digest (a pull). Only a HEAD by digest of an
// untagged row touches (TestManifestHeadTouchIsBounded).
func TestManifestReadsThatWriteNothing(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	for _, tc := range []struct {
		name    string
		method  string
		byTag   bool
		touches bool
	}{
		{"HEAD by tag", http.MethodHead, true, false},
		{"GET by tag", http.MethodGet, true, false},
		{"GET by digest", http.MethodGet, false, false},
		{"HEAD by digest", http.MethodHead, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			body := f.image(t, "app", "v1", "layer")
			d := dg(body)
			f.age(t, "app", old, d)
			reference := d.String()
			if tc.byTag {
				reference = "v1"
			}
			want(t, f.do(tc.method, "/v2/app/manifests/"+reference, nil), http.StatusOK, "")
			fi, err := os.Stat(f.blobFile("app", d))
			if err != nil {
				t.Fatal(err)
			}
			if touched := !fi.ModTime().Equal(old); touched != tc.touches {
				t.Errorf("mtime %s after %s (was %s), touched %v, want %v", fi.ModTime(), tc.name, old, touched, tc.touches)
			}
		})
	}
}
