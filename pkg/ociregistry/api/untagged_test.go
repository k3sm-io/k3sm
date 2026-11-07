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
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestUntaggedManifestStaysReadableByDigest pins what a tag DELETE leaves: the
// tag is gone, and the manifest stays addressable by digest through an untagged
// index.json row, as in the registry whose store this one keeps, until a digest
// DELETE or GC removes it. A pod pinned by digest depends on that read, and
// prune and GC only ever see the manifest through that row.
func TestUntaggedManifestStaysReadableByDigest(t *testing.T) {
	const manifest = ispec.MediaTypeImageManifest
	readable := func(t *testing.T, f *fixture, repo string, body []byte, mediaType string) {
		t.Helper()
		path := "/v2/" + repo + "/manifests/" + dg(body).String()
		w := f.do(http.MethodGet, path, nil)
		want(t, w, http.StatusOK, "")
		if !bytes.Equal(w.Body.Bytes(), body) {
			t.Errorf("GET %s = %s, want %s", path, w.Body.Bytes(), body)
		}
		if got := w.Header().Get("Content-Type"); got != mediaType {
			t.Errorf("GET %s Content-Type = %q, want %q", path, got, mediaType)
		}
		if got := w.Header().Get("Docker-Content-Digest"); got != dg(body).String() {
			t.Errorf("GET %s Docker-Content-Digest = %q", path, got)
		}
		want(t, f.do(http.MethodHead, path, nil), http.StatusOK, "")
	}
	oneUntaggedRow := func(t *testing.T, f *fixture, body []byte, mediaType string) {
		t.Helper()
		rows := f.rows(t, "app")
		if len(rows) != 1 || rows[0].Digest != dg(body) || rows[0].MediaType != mediaType || rows[0].Size != int64(len(body)) || rows[0].Annotations != nil {
			t.Errorf("rows = %+v, want one untagged row of %s", rows, dg(body))
		}
	}

	t.Run("deleting the last tag leaves an untagged row, until a digest DELETE", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "v1", "l")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusAccepted, "")

		// The body was never hidden: the blob route does not go through a row.
		want(t, f.do(http.MethodGet, "/v2/app/blobs/"+dg(body).String(), nil), http.StatusOK, "")
		readable(t, f, "app", body, manifest)
		oneUntaggedRow(t, f, body, manifest)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), http.StatusNotFound, codeManifestUnknown)
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusNotFound, codeManifestUnknown)
		if tags, _ := f.tagsOf(t, "app", ""); len(tags) != 0 {
			t.Errorf("tags = %v, want none", tags)
		}

		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil), http.StatusAccepted, "")
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(body).String(), nil), http.StatusNotFound, codeManifestUnknown)
		if rows := f.rows(t, "app"); len(rows) != 0 {
			t.Errorf("rows after the digest DELETE = %+v", rows)
		}
	})

	t.Run("only the last tag of a digest leaves a row", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "v1", "l")
		want(t, f.pushManifest(t, "app", "v2", manifest, body), http.StatusCreated, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusAccepted, "")
		if rows := f.rows(t, "app"); len(rows) != 1 || rows[0].Annotations[ispec.AnnotationRefName] != "v2" {
			t.Fatalf("rows after deleting v1 = %+v, want only v2's", rows)
		}
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v2", nil), http.StatusAccepted, "")
		oneUntaggedRow(t, f, body, manifest)
	})

	t.Run("tagging the digest again replaces the untagged row", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "v1", "l")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusAccepted, "")
		want(t, f.pushManifest(t, "app", "v1", manifest, body), http.StatusCreated, "")
		if rows := f.rows(t, "app"); len(rows) != 1 || rows[0].Annotations[ispec.AnnotationRefName] != "v1" {
			t.Errorf("rows after tagging again = %+v, want only v1's", rows)
		}
	})

	t.Run("an index keeps naming its children after its last tag goes", func(t *testing.T) {
		f := newFixture(t)
		child := f.image(t, "app", "", "l")
		idx := f.index(t, "app", "v1", child)
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusAccepted, "")
		readable(t, f, "app", idx, ispec.MediaTypeImageIndex)
		readable(t, f, "app", child, manifest)
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(child).String(), nil), http.StatusMethodNotAllowed, codeDenied)
	})

	t.Run("GC keeps the row through the grace and then reclaims it and its blobs", func(t *testing.T) {
		const grace = time.Hour
		f := newFixture(t)
		body := f.image(t, "app", "v1", "l")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusAccepted, "")

		c := f.deletingCollector(t, grace)
		if _, err := c.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		readable(t, f, "app", body, manifest)

		n, err := ref.ParseName("app")
		if err != nil {
			t.Fatal(err)
		}
		cont, err := f.st.Contents(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(cont.Blobs) != 3 {
			t.Fatalf("blobs before aging = %+v, want the manifest, config and layer", cont.Blobs)
		}
		old := time.Now().Add(-2 * grace)
		for _, b := range cont.Blobs {
			if err := os.Chtimes(filepath.Join(f.root, "app", "blobs", b.Digest.Algorithm().String(), b.Digest.Encoded()), old, old); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(body).String(), nil), http.StatusNotFound, codeManifestUnknown)
		if rows := f.rows(t, "app"); len(rows) != 0 {
			t.Errorf("rows after the aged sweep = %+v", rows)
		}
		if cont, err := f.st.Contents(n); err != nil || len(cont.Blobs) != 0 {
			t.Errorf("blobs after the aged sweep = %+v, %v", cont.Blobs, err)
		}
	})
}
