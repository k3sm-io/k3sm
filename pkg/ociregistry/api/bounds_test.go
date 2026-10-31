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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// nextLink returns the target of a Link rel="next" header, or "".
func nextLink(t *testing.T, h http.Header) string {
	t.Helper()
	l := h.Get("Link")
	if l == "" {
		return ""
	}
	if !strings.HasPrefix(l, "<") || !strings.HasSuffix(l, `>; rel="next"`) {
		t.Fatalf("Link %q", l)
	}
	return strings.TrimSuffix(strings.TrimPrefix(l, "<"), `>; rel="next"`)
}

// layRepos lays out repositories by hand (the files the store checks for), so
// a test can make thousands without an fsync each.
func layRepos(t *testing.T, root string, names []string) {
	t.Helper()
	for _, n := range names {
		dir := filepath.Join(root, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
			t.Fatal(err)
		}
		for f, b := range map[string]string{"oci-layout": `{"imageLayoutVersion":"1.0.0"}`, "index.json": `{"schemaVersion":2,"manifests":[]}`} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// addRows writes each body as a manifest blob of repo and appends its row to
// index.json, renamed into place as the store does.
func (f *fixture) addRows(t *testing.T, repo string, bodies [][]byte) {
	t.Helper()
	dir := filepath.Join(f.root, repo)
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx ispec.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, b := range bodies {
		d := dg(b)
		if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", d.Encoded()), b, 0o600); err != nil {
			t.Fatal(err)
		}
		idx.Manifests = append(idx.Manifests, ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: d, Size: int64(len(b))})
	}
	raw, _ = json.Marshal(idx)
	tmp := filepath.Join(dir, ".uploads", "test-index")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "index.json")); err != nil {
		t.Fatal(err)
	}
}

// referrerBody is a manifest of artifactType at whose subject is subject.
func referrerBody(subject []byte, at string, i int) []byte {
	m := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest, ArtifactType: at,
		Config:      ispec.DescriptorEmptyJSON,
		Layers:      []ispec.Descriptor{},
		Subject:     &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: dg(subject), Size: int64(len(subject))},
		Annotations: map[string]string{"i": fmt.Sprint(i)},
	}
	m.SchemaVersion = 2
	b, _ := json.Marshal(m)
	return b
}

// TestListingBounds: the catalog pages by default and caps n, and the
// referrers answer comes from a view that reads each manifest once, within a
// per-request budget, and is rebuilt when index.json changes; both keep the
// distribution-spec shapes and Link paging, at 2,000 rows.
func TestListingBounds(t *testing.T) {
	t.Run("catalog/2,000 repositories page by default and n is capped", func(t *testing.T) {
		f := newFixture(t)
		var names []string
		for i := range 2000 {
			names = append(names, fmt.Sprintf("g%d/r%04d", i%7, i))
		}
		layRepos(t, f.root, names)
		slices.Sort(names)
		var got []string
		path, pages := "/v2/_catalog", 0
		for path != "" {
			w := f.do(http.MethodGet, path, nil)
			want(t, w, 200, "")
			var cat struct{ Repositories []string }
			if err := json.Unmarshal(w.Body.Bytes(), &cat); err != nil || cat.Repositories == nil {
				t.Fatalf("catalog %s: %v", w.Body.String(), err)
			}
			if len(cat.Repositories) > defaultCatalogPage {
				t.Fatalf("a page of %d entries", len(cat.Repositories))
			}
			got = append(got, cat.Repositories...)
			path = nextLink(t, w.Header())
			if pages++; pages == 1 && !strings.Contains(path, "n=1000") {
				t.Errorf("the first Link %q does not carry the default page size", path)
			}
		}
		if pages != 2 || !slices.Equal(got, names) {
			t.Fatalf("%d pages, %d names, in order %v", pages, len(got), slices.Equal(got, names))
		}
		f.srv.catalogMax = 300
		w := f.do(http.MethodGet, "/v2/_catalog?n=999999999", nil)
		var cat struct{ Repositories []string }
		_ = json.Unmarshal(w.Body.Bytes(), &cat)
		if len(cat.Repositories) != 300 || nextLink(t, w.Header()) != "/v2/_catalog?last="+strings.ReplaceAll(names[299], "/", "%2F")+"&n=300" {
			t.Errorf("a capped page of %d, Link %q", len(cat.Repositories), w.Header().Get("Link"))
		}
		w = f.do(http.MethodGet, "/v2/_catalog?n=0", nil)
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"repositories":[]}` || w.Header().Get("Link") != "" {
			t.Errorf("n=0: %d %s %q", w.Code, w.Body.String(), w.Header().Get("Link"))
		}
	})

	t.Run("referrers/2,000 manifests are read once within the budget and the view follows index.json", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		var bodies [][]byte
		for i := range 2000 {
			at := "application/vnd.example.sbom"
			if i%2 == 1 {
				at = "application/vnd.example.sig"
			}
			bodies = append(bodies, referrerBody(subject, at, i))
		}
		f.addRows(t, "app", bodies)
		reads := 0
		f.srv.referrerRead = func(digest.Digest) { reads++ }
		f.srv.refScanRows = 600
		path := "/v2/app/referrers/" + dg(subject).String()
		// 2,001 manifests (the subject too) at 600 a request: three busy
		// answers that each keep what they read, then the whole view.
		for i := range 3 {
			reads = 0
			w := f.do(http.MethodGet, path, nil)
			want(t, w, http.StatusTooManyRequests, codeTooManyRequests)
			if reads != 600 || w.Header().Get("Retry-After") == "" {
				t.Fatalf("busy answer %d read %d manifests, Retry-After %q", i, reads, w.Header().Get("Retry-After"))
			}
		}
		collect := func(path string) ([]ispec.Descriptor, int) {
			t.Helper()
			var all []ispec.Descriptor
			pages := 0
			for path != "" {
				w := f.do(http.MethodGet, path, nil)
				want(t, w, 200, "")
				var idx ispec.Index
				if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil || idx.Manifests == nil || idx.MediaType != ispec.MediaTypeImageIndex {
					t.Fatalf("referrers %s: %v", w.Body.String(), err)
				}
				if len(idx.Manifests) > f.srv.refPage {
					t.Fatalf("a page of %d", len(idx.Manifests))
				}
				all = append(all, idx.Manifests...)
				path = nextLink(t, w.Header())
				pages++
			}
			return all, pages
		}
		reads = 0
		all, pages := collect(path)
		if reads != 201 || pages != 2 || len(all) != 2000 {
			t.Fatalf("whole view: %d reads, %d pages, %d referrers", reads, pages, len(all))
		}
		if !slices.IsSortedFunc(all, func(a, b ispec.Descriptor) int { return strings.Compare(a.Digest.String(), b.Digest.String()) }) {
			t.Error("referrers are not sorted by digest")
		}
		reads = 0
		if again, _ := collect(path); reads != 0 || len(again) != 2000 {
			t.Errorf("an unchanged index re-read %d manifests (%d referrers)", reads, len(again))
		}
		f.srv.refPage = 300
		sigs, pages := collect(path + "?artifactType=application/vnd.example.sig")
		if len(sigs) != 1000 || pages != 4 || slices.ContainsFunc(sigs, func(d ispec.Descriptor) bool { return d.ArtifactType != "application/vnd.example.sig" }) {
			t.Errorf("filtered: %d over %d pages", len(sigs), pages)
		}
		f.srv.refPage = referrersPage

		// A push changes index.json: the view is rebuilt, reading only the
		// new manifest.
		extra := referrerBody(subject, "application/vnd.example.sig", 2000)
		f.pushBlob(t, "app", ispec.DescriptorEmptyJSON.Data)
		want(t, f.pushManifest(t, "app", dg(extra).String(), ispec.MediaTypeImageManifest, extra), 201, "")
		reads = 0
		all, _ = collect(path)
		if reads != 1 || len(all) != 2001 || !slices.ContainsFunc(all, func(d ispec.Descriptor) bool { return d.Digest == dg(extra) }) {
			t.Fatalf("after a push: %d reads, %d referrers", reads, len(all))
		}
		// A delete changes it again: the deleted referrer is gone with no read.
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(bodies[0]).String(), nil), http.StatusAccepted, "")
		reads = 0
		all, _ = collect(path)
		if reads != 0 || len(all) != 2000 || slices.ContainsFunc(all, func(d ispec.Descriptor) bool { return d.Digest == dg(bodies[0]) }) {
			t.Fatalf("after a delete: %d reads, %d referrers", reads, len(all))
		}
	})

	t.Run("referrers/the byte budget and the page byte bound hold", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		var bodies [][]byte
		for i := range 50 {
			bodies = append(bodies, referrerBody(subject, "application/vnd.example.sig", i))
		}
		f.addRows(t, "app", bodies)
		reads := 0
		f.srv.referrerRead = func(digest.Digest) { reads++ }
		f.srv.refScanBytes = int64(10 * len(bodies[0]))
		path := "/v2/app/referrers/" + dg(subject).String()
		w := f.do(http.MethodGet, path, nil)
		want(t, w, http.StatusTooManyRequests, codeTooManyRequests)
		if reads > 10 {
			t.Fatalf("a %d-byte budget read %d manifests", f.srv.refScanBytes, reads)
		}
		f.srv.refScanBytes = referrersScanBytes
		f.srv.refPageBytes = 1000
		w = f.do(http.MethodGet, path, nil)
		want(t, w, 200, "")
		var idx ispec.Index
		_ = json.Unmarshal(w.Body.Bytes(), &idx)
		if len(idx.Manifests) == 0 || len(idx.Manifests) >= 50 || nextLink(t, w.Header()) == "" {
			t.Errorf("a 1000-byte page held %d descriptors, Link %q", len(idx.Manifests), w.Header().Get("Link"))
		}
	})

	t.Run("referrers/the cache drops its least recently used view past its bound", func(t *testing.T) {
		c := newReferrerCache()
		a := c.view("a")
		c.account("a", a, referrerCacheRows, 1)
		b := c.view("b")
		c.account("b", b, 1, 1)
		if _, ok := c.views["a"]; ok || c.views["b"] != b || c.rows != 1 || c.bytes != 1 {
			t.Errorf("views %v, rows %d, bytes %d", c.views, c.rows, c.bytes)
		}
		c.drop("b", b)
		if len(c.views) != 0 || c.rows != 0 || c.bytes != 0 {
			t.Errorf("after drop: views %v, rows %d, bytes %d", c.views, c.rows, c.bytes)
		}
	})
}
