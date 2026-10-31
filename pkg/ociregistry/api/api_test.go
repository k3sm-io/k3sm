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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// fixture is a server over a fresh store, driven in process.
type fixture struct {
	srv  *Server
	st   *store.Store
	root string
}

func newFixture(t testing.TB, opts ...func(*Config)) *fixture {
	t.Helper()
	st, err := store.OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Store: st, FreeSpace: func() (uint64, error) { return 1 << 40, nil }}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{srv: srv, st: st, root: st.Root()}
}

// req builds a request; hdr is header name/value pairs.
func req(method, path string, body []byte, hdr ...string) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return r
}

func (f *fixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func (f *fixture) do(method, path string, body []byte, hdr ...string) *httptest.ResponseRecorder {
	return f.serve(req(method, path, body, hdr...))
}

// want fails unless w has status and, when code is set, that error code.
func want(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, want %d; body %s", w.Code, status, w.Body.String())
	}
	if code == "" {
		return
	}
	var eb errorBody
	if err := json.Unmarshal(w.Body.Bytes(), &eb); err != nil || len(eb.Errors) != 1 || eb.Errors[0].Code != code {
		t.Fatalf("error body %s, want code %s", w.Body.String(), code)
	}
}

func dg(b []byte) digest.Digest { return digest.FromBytes(b) }

// pushBlob pushes b to repo monolithically.
func (f *fixture) pushBlob(t *testing.T, repo string, b []byte) digest.Digest {
	t.Helper()
	d := dg(b)
	w := f.do(http.MethodPost, "/v2/"+repo+"/blobs/uploads/?digest="+d.String(), b, "Content-Type", "application/octet-stream")
	want(t, w, http.StatusCreated, "")
	return d
}

// pushManifest PUTs body as a manifest of mediaType at reference.
func (f *fixture) pushManifest(t *testing.T, repo, reference, mediaType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(http.MethodPut, "/v2/"+repo+"/manifests/"+reference, body, "Content-Type", mediaType)
}

// image pushes a config and one layer and an OCI manifest naming them, tagged
// when tag is set, and returns the manifest body.
func (f *fixture) image(t *testing.T, repo, tag, layer string) []byte {
	t.Helper()
	cfg := []byte(`{"architecture":"arm64","os":"linux","seed":"` + layer + `"}`)
	cd := f.pushBlob(t, repo, cfg)
	ld := f.pushBlob(t, repo, []byte(layer))
	m := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Config:    ispec.Descriptor{MediaType: ispec.MediaTypeImageConfig, Digest: cd, Size: int64(len(cfg))},
		Layers:    []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayerGzip, Digest: ld, Size: int64(len(layer))}},
	}
	m.SchemaVersion = 2
	body, _ := json.Marshal(m)
	ref := tag
	if ref == "" {
		ref = dg(body).String()
	}
	want(t, f.pushManifest(t, repo, ref, ispec.MediaTypeImageManifest, body), http.StatusCreated, "")
	return body
}

// index pushes an OCI index of children, tagged when tag is set.
func (f *fixture) index(t *testing.T, repo, tag string, children ...[]byte) []byte {
	t.Helper()
	idx := ispec.Index{MediaType: ispec.MediaTypeImageIndex}
	idx.SchemaVersion = 2
	for _, c := range children {
		idx.Manifests = append(idx.Manifests, ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: dg(c), Size: int64(len(c))})
	}
	body, _ := json.Marshal(idx)
	ref := tag
	if ref == "" {
		ref = dg(body).String()
	}
	want(t, f.pushManifest(t, repo, ref, ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
	return body
}

func (f *fixture) tagsOf(t *testing.T, repo, query string) ([]string, http.Header) {
	t.Helper()
	w := f.do(http.MethodGet, "/v2/"+repo+"/tags/list"+query, nil)
	want(t, w, http.StatusOK, "")
	var tl struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tl); err != nil || tl.Tags == nil {
		t.Fatalf("tag list %s: %v", w.Body.String(), err)
	}
	return tl.Tags, w.Header()
}

func (f *fixture) rows(t *testing.T, repo string) []ispec.Descriptor {
	t.Helper()
	n, _ := ref.ParseName(repo)
	idx, err := f.st.Index(n)
	if err != nil {
		t.Fatal(err)
	}
	return idx.Manifests
}

// TestDistributionAPI pins the distribution API's behaviour: the delete rules,
// the manifest accept and reject table, the wire details clients depend on,
// and the client-compat cases.
func TestDistributionAPI(t *testing.T) {
	t.Run("version check", func(t *testing.T) {
		f := newFixture(t)
		for _, p := range []string{"/v2/", "/v2"} {
			w := f.do(http.MethodGet, p, nil)
			want(t, w, http.StatusOK, "")
			if got := w.Header().Get("Docker-Distribution-API-Version"); got != "registry/2.0" {
				t.Errorf("%s API version header %q", p, got)
			}
		}
	})

	t.Run("every route validates names references and ids, reads included", func(t *testing.T) {
		f := newFixture(t)
		f.image(t, "app", "v1", "l")
		cases := []struct {
			method, path string
			status       int
			code         string
		}{
			{http.MethodGet, "/v2/App/tags/list", 400, codeNameInvalid},
			{http.MethodGet, "/v2/app//x/tags/list", 400, codeNameInvalid},
			{http.MethodGet, "/v2/app/../etc/tags/list", 400, codeNameInvalid},
			{http.MethodGet, "/v2/app/blobs/x/tags/list", 400, codeNameInvalid},
			{http.MethodGet, "/v2/.hidden/manifests/v1", 400, codeNameInvalid},
			{http.MethodGet, "/v2/cache.db/manifests/v1", 400, codeNameInvalid},
			{http.MethodGet, "/v2/app/manifests/-bad", 400, codeManifestInvalid},
			{http.MethodGet, "/v2/app/manifests/sha256:abc", 400, codeDigestInvalid},
			{http.MethodHead, "/v2/app/blobs/sha256:ABC", 400, ""},
			{http.MethodGet, "/v2/app/blobs/md5:d41d8cd98f00b204e9800998ecf8427e", 400, codeDigestInvalid},
			{http.MethodGet, "/v2/app/blobs/uploads/not-a-uuid", 404, codeBlobUploadUnknown},
			{http.MethodGet, "/v2/app/referrers/latest", 400, codeDigestInvalid},
			{http.MethodGet, "/v2/nope/tags/list", 404, codeNameUnknown},
			{http.MethodGet, "/v2/app/manifests/v2", 404, codeManifestUnknown},
			{http.MethodGet, "/v2/app/blobs/" + dg([]byte("x")).String(), 404, codeBlobUnknown},
			{http.MethodPost, "/v2/app/blobs/uploads/?mount=" + dg([]byte("l")).String() + "&from=Bad", 400, codeNameInvalid},
			{http.MethodPost, "/v2/app/tags/list", 405, codeUnsupported},
			{http.MethodGet, "/v3/", 404, codeUnsupported},
		}
		for _, tc := range cases {
			w := f.do(tc.method, tc.path, nil)
			if w.Code != tc.status {
				t.Errorf("%s %s = %d, want %d (%s)", tc.method, tc.path, w.Code, tc.status, w.Body.String())
				continue
			}
			if tc.code != "" && !strings.Contains(w.Body.String(), `"`+tc.code+`"`) {
				t.Errorf("%s %s body %s, want code %s", tc.method, tc.path, w.Body.String(), tc.code)
			}
		}
	})

	// Resolution 11: delete semantics.
	t.Run("delete/a tag DELETE removes only that row", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "v1", "l")
		want(t, f.pushManifest(t, "app", "v2", ispec.MediaTypeImageManifest, body), 201, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusAccepted, "")
		tags, _ := f.tagsOf(t, "app", "")
		if !slices.Equal(tags, []string{"v2"}) {
			t.Errorf("tags after deleting v1 = %v, want [v2]", tags)
		}
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(body).String(), nil), 200, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), 404, codeManifestUnknown)
	})
	t.Run("delete/a digest DELETE removes every row of the digest, tags included", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "v1", "l")
		want(t, f.pushManifest(t, "app", "v2", ispec.MediaTypeImageManifest, body), 201, "")
		other := f.image(t, "app", "v3", "m")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil), http.StatusAccepted, "")
		rows := f.rows(t, "app")
		if len(rows) != 1 || rows[0].Digest != dg(other) {
			t.Errorf("rows after the digest delete = %v, want only v3's", rows)
		}
		want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), 404, codeManifestUnknown)
	})
	t.Run("delete/a digest DELETE is refused while an index in the repository names it", func(t *testing.T) {
		f := newFixture(t)
		child := f.image(t, "app", "", "l")
		idx := f.index(t, "app", "v1", child)
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(child).String(), nil), http.StatusMethodNotAllowed, codeDenied)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(child).String(), nil), 200, "")
		// Once the index is gone the child may go.
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(idx).String(), nil), http.StatusAccepted, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(child).String(), nil), http.StatusAccepted, "")
	})
	t.Run("delete/upload cancel needs the delete permission", func(t *testing.T) {
		var mu sync.Mutex
		var verbs []Verb
		f := newFixture(t, func(c *Config) {
			c.Authorize = func(r *http.Request, v Verb, n ref.Name) error {
				mu.Lock()
				verbs = append(verbs, v)
				mu.Unlock()
				if v == VerbDelete {
					return ErrDenied
				}
				return nil
			}
		})
		w := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil)
		want(t, w, http.StatusAccepted, "")
		loc := w.Header().Get("Location")
		mu.Lock()
		verbs = nil
		mu.Unlock()
		want(t, f.do(http.MethodDelete, loc, nil), http.StatusForbidden, codeDenied)
		mu.Lock()
		got := slices.Clone(verbs)
		mu.Unlock()
		if !slices.Equal(got, []Verb{VerbDelete}) {
			t.Errorf("an upload cancel asked for %v, want [delete]", got)
		}
		want(t, f.do(http.MethodGet, loc, nil), http.StatusNoContent, "")
	})
	t.Run("delete/an anonymous refusal is 401 with a Basic challenge", func(t *testing.T) {
		f := newFixture(t, func(c *Config) {
			c.Authorize = func(r *http.Request, v Verb, n ref.Name) error {
				if v != VerbRead {
					return ErrUnauthenticated
				}
				return nil
			}
		})
		w := f.do(http.MethodDelete, "/v2/app/manifests/v1", nil)
		want(t, w, http.StatusUnauthorized, codeUnauthorized)
		if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
			t.Errorf("WWW-Authenticate %q", w.Header().Get("WWW-Authenticate"))
		}
	})
	t.Run("delete/a blob DELETE is left to garbage collection", func(t *testing.T) {
		f := newFixture(t)
		d := f.pushBlob(t, "app", []byte("b"))
		want(t, f.do(http.MethodDelete, "/v2/app/blobs/"+d.String(), nil), http.StatusMethodNotAllowed, codeUnsupported)
		want(t, f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil), 200, "")
	})

	// Resolution 12: manifest PUT, the accept and reject table.
	t.Run("manifest-put", func(t *testing.T) {
		raw, err := os.ReadFile("testdata/manifest-put/cases.json")
		if err != nil {
			t.Fatal(err)
		}
		var table struct {
			Blobs []string `json:"blobs"`
			Cases []struct {
				Name, File, ContentType, Code string
				Status                        int
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &table); err != nil {
			t.Fatal(err)
		}
		if len(table.Cases) < 15 {
			t.Fatalf("only %d manifest PUT cases", len(table.Cases))
		}
		for _, tc := range table.Cases {
			t.Run(tc.Name, func(t *testing.T) {
				f := newFixture(t)
				for _, b := range table.Blobs {
					f.pushBlob(t, "app", []byte(b))
				}
				body, err := os.ReadFile(filepath.Join("testdata/manifest-put", tc.File))
				if err != nil {
					t.Fatal(err)
				}
				w := f.pushManifest(t, "app", "v1", tc.ContentType, body)
				want(t, w, tc.Status, tc.Code)
				get := f.do(http.MethodGet, "/v2/app/manifests/v1", nil)
				if tc.Status != http.StatusCreated {
					want(t, get, http.StatusNotFound, codeManifestUnknown)
					return
				}
				if w.Header().Get("Docker-Content-Digest") != dg(body).String() || w.Header().Get("Location") != "/v2/app/manifests/"+dg(body).String() {
					t.Errorf("PUT headers %v", w.Header())
				}
				want(t, get, 200, "")
				if !bytes.Equal(get.Body.Bytes(), body) || get.Header().Get("Content-Type") != tc.ContentType {
					t.Errorf("GET returned %s as %q", get.Body.String(), get.Header().Get("Content-Type"))
				}
				var doc struct {
					Subject *ispec.Descriptor `json:"subject"`
				}
				_ = json.Unmarshal(body, &doc)
				if doc.Subject != nil && w.Header().Get("OCI-Subject") != doc.Subject.Digest.String() {
					t.Errorf("OCI-Subject %q, want %s", w.Header().Get("OCI-Subject"), doc.Subject.Digest)
				}
			})
		}
	})
	t.Run("manifest/a blob deleted after the first check is caught under the repository lock", func(t *testing.T) {
		f := newFixture(t)
		for _, b := range []string{"cfg", "layer-1", "layer-2"} {
			f.pushBlob(t, "app", []byte(b))
		}
		body, err := os.ReadFile("testdata/manifest-put/oci-manifest-present.json")
		if err != nil {
			t.Fatal(err)
		}
		layer := dg([]byte("layer-2"))
		// What a sweep does between a client's HEAD (or the handler's first
		// check) and the index write: unlink the blob.
		f.srv.manifestChecked = func() {
			if err := os.Remove(filepath.Join(f.root, "app", "blobs", "sha256", layer.Encoded())); err != nil {
				t.Error(err)
			}
		}
		w := f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body)
		want(t, w, http.StatusBadRequest, codeManifestBlobUnknown)
		if !strings.Contains(w.Body.String(), layer.String()) {
			t.Errorf("refusal does not name %s: %s", layer, w.Body.String())
		}
		if rows := f.rows(t, "app"); len(rows) != 0 {
			t.Errorf("index names a manifest whose blob is gone: %v", rows)
		}
	})
	t.Run("manifest/a digest-addressed PUT verifies the body hash", func(t *testing.T) {
		f := newFixture(t)
		body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
		want(t, f.pushManifest(t, "app", dg([]byte("other")).String(), ispec.MediaTypeImageIndex, body), 400, codeManifestInvalid)
		want(t, f.pushManifest(t, "app", dg(body).String(), ispec.MediaTypeImageIndex, body), 201, "")
		if rows := f.rows(t, "app"); len(rows) != 1 || rows[0].Annotations != nil {
			t.Errorf("a digest PUT wrote rows %v, want one untagged row", rows)
		}
	})
	t.Run("manifest/?tag= on a digest PUT tags it", func(t *testing.T) {
		f := newFixture(t)
		body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
		w := f.pushManifest(t, "app", dg(body).String()+"?tag=a&tag=b", ispec.MediaTypeImageIndex, body)
		want(t, w, 201, "")
		if got := w.Header().Values("OCI-Tag"); !slices.Equal(got, []string{"a", "b"}) {
			t.Errorf("OCI-Tag %v", got)
		}
		tags, _ := f.tagsOf(t, "app", "")
		if !slices.Equal(tags, []string{"a", "b"}) {
			t.Errorf("tags %v", tags)
		}
		want(t, f.pushManifest(t, "app", "v1?tag=c", ispec.MediaTypeImageIndex, body), 400, codeManifestInvalid)
		want(t, f.pushManifest(t, "app", dg(body).String()+"?tag=-x", ispec.MediaTypeImageIndex, body), 400, codeManifestInvalid)
	})
	t.Run("manifest/GET and HEAD ignore Accept and return the stored media type", func(t *testing.T) {
		f := newFixture(t)
		f.pushBlob(t, "app", []byte("cfg"))
		f.pushBlob(t, "app", []byte("layer-1"))
		body, _ := os.ReadFile("testdata/manifest-put/docker-manifest-present.json")
		want(t, f.pushManifest(t, "app", "v1", "application/vnd.docker.distribution.manifest.v2+json", body), 201, "")
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			w := f.do(m, "/v2/app/manifests/v1", nil, "Accept", ispec.MediaTypeImageManifest)
			want(t, w, 200, "")
			h := w.Header()
			if h.Get("Content-Type") != "application/vnd.docker.distribution.manifest.v2+json" || h.Get("Docker-Content-Digest") != dg(body).String() || h.Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Errorf("%s headers %v", m, h)
			}
			if m == http.MethodHead && w.Body.Len() != 0 {
				t.Errorf("HEAD wrote a body")
			}
		}
	})

	t.Run("blob/GET serves Range, 206 and 416 through ServeContent", func(t *testing.T) {
		f := newFixture(t)
		b := []byte("0123456789")
		d := f.pushBlob(t, "app", b)
		p := "/v2/app/blobs/" + d.String()
		w := f.do(http.MethodHead, p, nil)
		want(t, w, 200, "")
		if w.Header().Get("Accept-Ranges") != "bytes" || w.Header().Get("Content-Length") != "10" || w.Header().Get("Docker-Content-Digest") != d.String() {
			t.Errorf("HEAD headers %v", w.Header())
		}
		w = f.do(http.MethodGet, p, nil, "Range", "bytes=2-4")
		want(t, w, http.StatusPartialContent, "")
		if w.Body.String() != "234" || w.Header().Get("Content-Range") != "bytes 2-4/10" {
			t.Errorf("206 body %q Content-Range %q", w.Body.String(), w.Header().Get("Content-Range"))
		}
		w = f.do(http.MethodGet, p, nil, "Range", "bytes=20-30")
		want(t, w, http.StatusRequestedRangeNotSatisfiable, "")
		if w.Header().Get("Content-Range") != "bytes */10" {
			t.Errorf("416 Content-Range %q", w.Header().Get("Content-Range"))
		}
		w = f.do(http.MethodGet, p, nil)
		want(t, w, 200, "")
		if !bytes.Equal(w.Body.Bytes(), b) {
			t.Errorf("GET body %q", w.Body.String())
		}
	})

	// Resolution 12: uploads.
	t.Run("upload/Location is path-only and both upload UUID headers are set", func(t *testing.T) {
		f := newFixture(t)
		w := f.do(http.MethodPost, "/v2/team/app/blobs/uploads/", nil)
		want(t, w, http.StatusAccepted, "")
		h := w.Header()
		id := h.Get("Blob-Upload-UUID")
		if _, err := ref.ParseUploadID(id); err != nil || h.Get("Docker-Upload-UUID") != id {
			t.Fatalf("upload ids %q %q", id, h.Get("Docker-Upload-UUID"))
		}
		if h.Get("Location") != "/v2/team/app/blobs/uploads/"+id || h.Get("Range") != "0-0" {
			t.Errorf("Location %q Range %q", h.Get("Location"), h.Get("Range"))
		}
		w = f.do(http.MethodPatch, h.Get("Location"), []byte("abc"))
		want(t, w, http.StatusAccepted, "")
		if w.Header().Get("Blob-Upload-UUID") != id || w.Header().Get("Docker-Upload-UUID") != id || w.Header().Get("Location") != h.Get("Location") {
			t.Errorf("PATCH headers %v", w.Header())
		}
	})
	t.Run("upload/a status GET answers 204 with Range 0-<n-1>", func(t *testing.T) {
		f := newFixture(t)
		loc := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil).Header().Get("Location")
		want(t, f.do(http.MethodPatch, loc, []byte("hello")), http.StatusAccepted, "")
		w := f.do(http.MethodGet, loc, nil)
		want(t, w, http.StatusNoContent, "")
		if w.Header().Get("Range") != "0-4" {
			t.Errorf("Range %q, want 0-4", w.Header().Get("Range"))
		}
	})
	t.Run("upload/a PATCH Content-Range is a-b and a mismatch gets 416", func(t *testing.T) {
		f := newFixture(t)
		loc := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil).Header().Get("Location")
		want(t, f.do(http.MethodPatch, loc, []byte("abc"), "Content-Range", "0-2"), http.StatusAccepted, "")
		w := f.do(http.MethodPatch, loc, []byte("def"), "Content-Range", "0-2")
		want(t, w, http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid)
		if w.Header().Get("Range") != "0-2" {
			t.Errorf("416 Range %q, want the session's 0-2", w.Header().Get("Range"))
		}
		want(t, f.do(http.MethodPatch, loc, []byte("de"), "Content-Range", "3-5"), http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid)
		want(t, f.do(http.MethodPatch, loc, []byte("def"), "Content-Range", "bytes 3-5"), http.StatusBadRequest, codeBlobUploadInvalid)
		want(t, f.do(http.MethodPatch, loc, []byte("def"), "Content-Range", "3-5"), http.StatusAccepted, "")
		d := dg([]byte("abcdef"))
		want(t, f.do(http.MethodPut, loc+"?digest="+d.String(), nil), http.StatusCreated, "")
		w = f.do(http.MethodGet, "/v2/app/blobs/"+d.String(), nil)
		if w.Body.String() != "abcdef" {
			t.Errorf("blob %q", w.Body.String())
		}
	})
	t.Run("upload/a PATCH without range headers appends", func(t *testing.T) {
		f := newFixture(t)
		loc := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil).Header().Get("Location")
		for _, c := range []string{"ab", "cd", "ef"} {
			r := req(http.MethodPatch, loc, []byte(c))
			r.ContentLength = -1 // streamed, no Content-Length
			r.Header.Del("Content-Length")
			want(t, f.serve(r), http.StatusAccepted, "")
		}
		d := dg([]byte("abcdefgh"))
		w := f.do(http.MethodPut, loc+"?digest="+d.String(), []byte("gh"))
		want(t, w, http.StatusCreated, "")
		if w.Header().Get("Location") != "/v2/app/blobs/"+d.String() || w.Header().Get("Docker-Content-Digest") != d.String() {
			t.Errorf("commit headers %v", w.Header())
		}
		want(t, f.do(http.MethodGet, loc, nil), http.StatusNotFound, codeBlobUploadUnknown)
	})
	t.Run("upload/a wrong digest keeps the session and a PUT without one is refused", func(t *testing.T) {
		f := newFixture(t)
		loc := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil).Header().Get("Location")
		want(t, f.do(http.MethodPatch, loc, []byte("abc")), http.StatusAccepted, "")
		want(t, f.do(http.MethodPut, loc, nil), http.StatusBadRequest, codeDigestInvalid)
		want(t, f.do(http.MethodPut, loc+"?digest="+dg([]byte("x")).String(), nil), http.StatusBadRequest, codeDigestInvalid)
		want(t, f.do(http.MethodGet, loc, nil), http.StatusNoContent, "")
		want(t, f.do(http.MethodPut, loc+"?digest="+dg([]byte("abc")).String(), nil), http.StatusCreated, "")
	})
	t.Run("upload/a session a commit already linked can be cancelled or committed again", func(t *testing.T) {
		for _, finish := range []string{http.MethodDelete, http.MethodPut} {
			f := newFixture(t)
			b := []byte("linked")
			d := dg(b)
			w := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil)
			loc, id := w.Header().Get("Location"), w.Header().Get("Blob-Upload-UUID")
			want(t, f.do(http.MethodPatch, loc, b), http.StatusAccepted, "")
			blob := filepath.Join(f.root, "app", "blobs", "sha256", d.Encoded())
			if err := os.MkdirAll(filepath.Dir(blob), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(f.root, "app", ".uploads", id), blob); err != nil {
				t.Fatal(err)
			}
			want(t, f.do(http.MethodPatch, loc, []byte("more")), http.StatusNotFound, codeBlobUploadUnknown)
			path := loc
			status := http.StatusNoContent
			if finish == http.MethodPut {
				path += "?digest=" + d.String()
				status = http.StatusCreated
			}
			want(t, f.do(finish, path, nil), status, "")
			want(t, f.do(http.MethodGet, loc, nil), http.StatusNotFound, codeBlobUploadUnknown)
			if got, _ := os.ReadFile(blob); !bytes.Equal(got, b) {
				t.Errorf("%s: blob %q", finish, got)
			}
		}
	})
	t.Run("upload/a monolithic POST needs a length", func(t *testing.T) {
		f := newFixture(t)
		r := req(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg([]byte("x")).String(), []byte("x"))
		r.ContentLength = -1
		want(t, f.serve(r), http.StatusBadRequest, codeBlobUploadInvalid)
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg([]byte("y")).String(), []byte("x")), http.StatusBadRequest, codeDigestInvalid)
		if n, _ := ref.ParseName("app"); true {
			if ups, _ := f.st.Uploads(n); len(ups) != 0 {
				t.Errorf("a refused monolithic upload left sessions %v", ups)
			}
		}
	})

	// Resolution 12: paging.
	t.Run("paging/n=0 is an empty list", func(t *testing.T) {
		f := newFixture(t)
		f.image(t, "app", "v1", "l")
		tags, h := f.tagsOf(t, "app", "?n=0")
		if len(tags) != 0 || h.Get("Link") != "" {
			t.Errorf("n=0 gave %v, Link %q", tags, h.Get("Link"))
		}
		want(t, f.do(http.MethodGet, "/v2/app/tags/list?n=-1", nil), 400, codePaginationInvalid)
		want(t, f.do(http.MethodGet, "/v2/app/tags/list?n=x", nil), 400, codePaginationInvalid)
	})
	t.Run("paging/last is an exclusive cursor that survives a deleted tag", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "a", "l")
		for _, tag := range []string{"b", "c", "d"} {
			want(t, f.pushManifest(t, "app", tag, ispec.MediaTypeImageManifest, body), 201, "")
		}
		tags, h := f.tagsOf(t, "app", "?n=2")
		if !slices.Equal(tags, []string{"a", "b"}) || h.Get("Link") != `</v2/app/tags/list?last=b&n=2>; rel="next"` {
			t.Fatalf("first page %v, Link %q", tags, h.Get("Link"))
		}
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/b", nil), http.StatusAccepted, "")
		tags, h = f.tagsOf(t, "app", "?n=2&last=b")
		if !slices.Equal(tags, []string{"c", "d"}) || h.Get("Link") != "" {
			t.Errorf("page after the deleted cursor %v, Link %q", tags, h.Get("Link"))
		}
	})
	t.Run("paging/the Link header is escaped", func(t *testing.T) {
		f := newFixture(t)
		for _, r := range []string{"a/b", "a/c", "d"} {
			f.pushBlob(t, r, []byte("x"))
		}
		w := f.do(http.MethodGet, "/v2/_catalog?n=1", nil)
		want(t, w, 200, "")
		if got := w.Header().Get("Link"); got != `</v2/_catalog?last=a%2Fb&n=1>; rel="next"` {
			t.Errorf("catalog Link %q", got)
		}
		w = f.do(http.MethodGet, "/v2/_catalog?n=5&last=a%2Fb", nil)
		var cat struct{ Repositories []string }
		_ = json.Unmarshal(w.Body.Bytes(), &cat)
		if !slices.Equal(cat.Repositories, []string{"a/c", "d"}) {
			t.Errorf("catalog after a/b %v", cat.Repositories)
		}
	})

	// Resolution 13: referrers.
	t.Run("referrers/a live scan with a filter and an empty answer for an unknown subject", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		cfg := f.pushBlob(t, "app", []byte("cfg"))
		mk := func(at string) []byte {
			m := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest, ArtifactType: at,
				Config:      ispec.Descriptor{MediaType: ispec.MediaTypeEmptyJSON, Digest: cfg, Size: 3},
				Layers:      []ispec.Descriptor{},
				Subject:     &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: dg(subject), Size: int64(len(subject))},
				Annotations: map[string]string{"k": at},
			}
			m.SchemaVersion = 2
			b, _ := json.Marshal(m)
			return b
		}
		sbom, sig := mk("application/vnd.example.sbom"), mk("application/vnd.example.sig")
		for _, b := range [][]byte{sbom, sig} {
			w := f.pushManifest(t, "app", dg(b).String(), ispec.MediaTypeImageManifest, b)
			want(t, w, 201, "")
			if w.Header().Get("OCI-Subject") != dg(subject).String() {
				t.Errorf("OCI-Subject %q", w.Header().Get("OCI-Subject"))
			}
		}
		get := func(path string) (ispec.Index, http.Header) {
			w := f.do(http.MethodGet, path, nil)
			want(t, w, 200, "")
			var idx ispec.Index
			if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil || w.Header().Get("Content-Type") != ispec.MediaTypeImageIndex {
				t.Fatalf("referrers %s: %v", w.Body.String(), err)
			}
			return idx, w.Header()
		}
		idx, h := get("/v2/app/referrers/" + dg(subject).String())
		if len(idx.Manifests) != 2 || h.Get("OCI-Filters-Applied") != "" {
			t.Errorf("referrers %v", idx.Manifests)
		}
		idx, h = get("/v2/app/referrers/" + dg(subject).String() + "?artifactType=application/vnd.example.sig")
		if len(idx.Manifests) != 1 || idx.Manifests[0].Digest != dg(sig) || idx.Manifests[0].ArtifactType != "application/vnd.example.sig" || h.Get("OCI-Filters-Applied") != "artifactType" {
			t.Errorf("filtered referrers %v, %v", idx.Manifests, h)
		}
		for _, p := range []string{"/v2/app/referrers/" + dg([]byte("none")).String(), "/v2/nope/referrers/" + dg(subject).String()} {
			if idx, _ := get(p); idx.Manifests == nil || len(idx.Manifests) != 0 {
				t.Errorf("%s = %v, want an empty list", p, idx.Manifests)
			}
		}
		if tags, _ := f.tagsOf(t, "app", ""); !slices.Equal(tags, []string{"v1"}) {
			t.Errorf("referrers wrote tags %v", tags)
		}
	})

	// Limits and robustness.
	t.Run("limits/a panicking handler answers 500 and the server keeps serving", func(t *testing.T) {
		boom := true
		f := newFixture(t, func(c *Config) {
			c.Authorize = func(r *http.Request, v Verb, n ref.Name) error {
				if boom && n.String() == "boom" {
					panic("handler bug")
				}
				return nil
			}
		})
		want(t, f.do(http.MethodGet, "/v2/boom/tags/list", nil), http.StatusInternalServerError, codeUnavailable)
		want(t, f.do(http.MethodGet, "/v2/", nil), 200, "")
	})
	t.Run("limits/the session cap answers 503", func(t *testing.T) {
		f := newFixture(t)
		var locs []string
		for range DefaultMaxSessions {
			w := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil)
			want(t, w, http.StatusAccepted, "")
			locs = append(locs, w.Header().Get("Location"))
		}
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil), http.StatusServiceUnavailable, codeUnavailable)
		// A session already open keeps working at the cap, and finishing one
		// frees a slot.
		want(t, f.do(http.MethodPatch, locs[0], []byte("x")), http.StatusAccepted, "")
		want(t, f.do(http.MethodDelete, locs[0], nil), http.StatusNoContent, "")
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil), http.StatusAccepted, "")
	})
	t.Run("limits/under 2 GiB free a new upload answers 507", func(t *testing.T) {
		free := uint64(DefaultMinFreeSpace - 1)
		f := newFixture(t, func(c *Config) { c.FreeSpace = func() (uint64, error) { return free, nil } })
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil), http.StatusInsufficientStorage, codeSizeInvalid)
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg([]byte("x")).String(), []byte("x")), http.StatusInsufficientStorage, codeSizeInvalid)
		f2 := newFixture(t, func(c *Config) { c.FreeSpace = func() (uint64, error) { return 0, errors.New("statfs failed") } })
		want(t, f2.do(http.MethodPost, "/v2/app/blobs/uploads/", nil), http.StatusInsufficientStorage, codeSizeInvalid)
		free = DefaultMinFreeSpace
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil), http.StatusAccepted, "")
	})
	t.Run("limits/the HTTP server bounds header reads", func(t *testing.T) {
		f := newFixture(t)
		hs := f.srv.HTTPServer("127.0.0.1:0")
		if hs.ReadHeaderTimeout != ReadHeaderTimeout || hs.ReadTimeout != 0 || hs.WriteTimeout != 0 || hs.MaxHeaderBytes != maxHeaderBytes {
			t.Errorf("http.Server timeouts %v/%v/%v, max header %d", hs.ReadHeaderTimeout, hs.ReadTimeout, hs.WriteTimeout, hs.MaxHeaderBytes)
		}
	})

	// Client compatibility.
	t.Run("client/the mount fallback", func(t *testing.T) {
		f := newFixture(t)
		d := f.pushBlob(t, "src", []byte("shared"))
		w := f.do(http.MethodPost, "/v2/dst/blobs/uploads/?mount="+d.String()+"&from=src", nil)
		want(t, w, http.StatusCreated, "")
		if w.Header().Get("Location") != "/v2/dst/blobs/"+d.String() {
			t.Errorf("mount Location %q", w.Header().Get("Location"))
		}
		a, _ := os.Stat(filepath.Join(f.root, "src", "blobs", "sha256", d.Encoded()))
		b, _ := os.Stat(filepath.Join(f.root, "dst", "blobs", "sha256", d.Encoded()))
		if !os.SameFile(a, b) {
			t.Error("a mount did not link the source inode")
		}
		// from is the only source: a repository that does not hold the blob,
		// a missing one, or no from at all is an upload session, never a
		// store-wide lookup.
		f.pushBlob(t, "other", []byte("unrelated"))
		for _, q := range []string{"&from=other", "&from=missing", ""} {
			w := f.do(http.MethodPost, "/v2/third/blobs/uploads/?mount="+d.String()+q, nil)
			want(t, w, http.StatusAccepted, "")
			if !strings.HasPrefix(w.Header().Get("Location"), "/v2/third/blobs/uploads/") {
				t.Errorf("fallback Location %q", w.Header().Get("Location"))
			}
		}
		want(t, f.do(http.MethodHead, "/v2/third/blobs/"+d.String(), nil), http.StatusNotFound, "")
	})
	t.Run("client/a Docker v2 manifest missing its config is refused and stays 404", func(t *testing.T) {
		f := newFixture(t)
		f.pushBlob(t, "app", []byte("layer-1"))
		body, _ := os.ReadFile("testdata/manifest-put/docker-manifest-missing-config.json")
		w := f.pushManifest(t, "app", "v1", "application/vnd.docker.distribution.manifest.v2+json", body)
		want(t, w, http.StatusBadRequest, codeManifestBlobUnknown)
		if !strings.Contains(w.Body.String(), "sha256:5ad38304") {
			t.Errorf("refusal does not name the missing config: %s", w.Body.String())
		}
		want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), http.StatusNotFound, codeManifestUnknown)
		want(t, f.do(http.MethodHead, "/v2/app/blobs/sha256:5ad38304b535c2987dbd24657c1a11b884984ff600d9f389deb0d4e634fee792", nil), http.StatusNotFound, "")
	})
	t.Run("client/the 4 MiB manifest boundary", func(t *testing.T) {
		f := newFixture(t)
		at := func(size int) []byte {
			head := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{"pad":"`
			tail := `"}}`
			return []byte(head + strings.Repeat("x", size-len(head)-len(tail)) + tail)
		}
		exact := at(store.MaxManifestSize)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, exact), http.StatusCreated, "")
		w := f.do(http.MethodGet, "/v2/app/manifests/v1", nil)
		want(t, w, 200, "")
		if w.Body.Len() != store.MaxManifestSize {
			t.Errorf("4 MiB manifest read back as %d bytes", w.Body.Len())
		}
		want(t, f.pushManifest(t, "app", "v2", ispec.MediaTypeImageIndex, at(store.MaxManifestSize+1)), http.StatusRequestEntityTooLarge, codeManifestInvalid)
		r := req(http.MethodPut, "/v2/app/manifests/v3", at(store.MaxManifestSize+1), "Content-Type", ispec.MediaTypeImageIndex)
		r.ContentLength = -1
		want(t, f.serve(r), http.StatusRequestEntityTooLarge, codeManifestInvalid)
	})
	t.Run("client/ggcr push and pull", func(t *testing.T) {
		testGGCRPushPull(t, newFixture(t).srv)
	})
}

// BenchmarkIndex2000Rows measures a manifest GET by tag and a full tag list
// over a repository whose index.json has 2,000 rows: the number that decides
// whether a per-repository index cache is worth adding.
func BenchmarkIndex2000Rows(b *testing.B) {
	f := newFixture(b)
	n, _ := ref.ParseName("app")
	body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	desc, err := f.st.PutManifest(b.Context(), n, ref.Reference{Tag: "t0"}, ispec.MediaTypeImageIndex, body)
	if err != nil {
		b.Fatal(err)
	}
	idx := ispec.Index{MediaType: ispec.MediaTypeImageIndex}
	idx.SchemaVersion = 2
	for i := range 2000 {
		row := desc
		row.Annotations = map[string]string{ispec.AnnotationRefName: fmt.Sprintf("t%d", i)}
		idx.Manifests = append(idx.Manifests, row)
	}
	raw, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(f.root, "app", "index.json"), raw, 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("manifest GET by the last tag", func(b *testing.B) {
		for b.Loop() {
			w := httptest.NewRecorder()
			f.srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/app/manifests/t1999", nil))
			if w.Code != 200 {
				b.Fatalf("status %d", w.Code)
			}
		}
	})
	b.Run("tag list", func(b *testing.B) {
		for b.Loop() {
			w := httptest.NewRecorder()
			f.srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/app/tags/list", nil))
			if w.Code != 200 {
				b.Fatalf("status %d", w.Code)
			}
			_, _ = io.Copy(io.Discard, w.Body)
		}
	})
}
