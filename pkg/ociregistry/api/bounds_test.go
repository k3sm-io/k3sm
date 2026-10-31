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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
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
		// The budget counts what was read, and the read that spends it is the
		// last: the subject's own manifest, then ten referrers.
		if reads != 11 {
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
		c.account("a", a, referrerCacheRows, 1, false)
		b := c.view("b")
		c.account("b", b, 1, 1, false)
		if _, ok := c.views["a"]; ok || c.views["b"] != b || c.rows != 1 || c.bytes != 1 {
			t.Errorf("views %v, rows %d, bytes %d", c.views, c.rows, c.bytes)
		}
		c.drop("b", b)
		if len(c.views) != 0 || c.rows != 0 || c.bytes != 0 {
			t.Errorf("after drop: views %v, rows %d, bytes %d", c.views, c.rows, c.bytes)
		}
	})

	t.Run("referrers/more than 8 artifactType values are refused", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		path := "/v2/app/referrers/" + dg(subject).String() + "?"
		for i := range 8 {
			path += fmt.Sprintf("artifactType=a%d&", i)
		}
		want(t, f.do(http.MethodGet, path, nil), 200, "")
		want(t, f.do(http.MethodGet, path+"artifactType=a8", nil), http.StatusBadRequest, codeUnsupported)
		want(t, f.do(http.MethodGet, path+"artifactType=a0", nil), http.StatusBadRequest, codeUnsupported)
	})

	t.Run("referrers/touching 1,100 other repositories keeps a partial view's progress", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		var bodies [][]byte
		for i := range 2000 {
			bodies = append(bodies, referrerBody(subject, "application/vnd.example.sig", i))
		}
		f.addRows(t, "app", bodies)
		var others []string
		for i := range 1100 {
			others = append(others, fmt.Sprintf("o/r%04d", i))
		}
		layRepos(t, f.root, others)
		read := map[digest.Digest]int{}
		f.srv.referrerRead = func(d digest.Digest) { read[d]++ }
		f.srv.refScanRows = 600
		path := "/v2/app/referrers/" + dg(subject).String()
		for i := 0; ; i++ {
			w := f.do(http.MethodGet, path, nil)
			if w.Code == 200 {
				var idx ispec.Index
				_ = json.Unmarshal(w.Body.Bytes(), &idx)
				if len(idx.Manifests) != 1000 || nextLink(t, w.Header()) == "" {
					t.Fatalf("the whole view's first page: %d", len(idx.Manifests))
				}
				break
			}
			want(t, w, http.StatusTooManyRequests, codeTooManyRequests)
			if i == 4 {
				t.Fatal("the view never completed")
			}
			for _, o := range others {
				want(t, f.do(http.MethodGet, "/v2/"+o+"/referrers/"+dg(subject).String(), nil), 200, "")
			}
		}
		if len(read) != 2001 {
			t.Errorf("read %d distinct manifests, want 2,001", len(read))
		}
		for d, c := range read {
			if c != 1 {
				t.Errorf("%s read %d times", d, c)
			}
		}
		if n := len(f.srv.refs.views); n > referrerCacheViews {
			t.Errorf("%d views cached", n)
		}
	})

	t.Run("referrers/an unreadable manifest is read once and a retryable error answers busy", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		var bodies [][]byte
		for i := range 10 {
			bodies = append(bodies, referrerBody(subject, "application/vnd.example.sig", i))
		}
		f.addRows(t, "app", bodies)
		blob := func(b []byte) string { return filepath.Join(f.root, "app", "blobs", "sha256", dg(b).Encoded()) }
		if err := os.Remove(blob(bodies[3])); err != nil {
			t.Fatal(err)
		}
		read := map[digest.Digest]int{}
		f.srv.referrerRead = func(d digest.Digest) { read[d]++ }
		f.srv.refScanRows = 3
		path := "/v2/app/referrers/" + dg(subject).String()
		var w *httptest.ResponseRecorder
		for range 6 {
			if w = f.do(http.MethodGet, path, nil); w.Code == 200 {
				break
			}
			want(t, w, http.StatusTooManyRequests, codeTooManyRequests)
		}
		var idx ispec.Index
		_ = json.Unmarshal(w.Body.Bytes(), &idx)
		if w.Code != 200 || len(idx.Manifests) != 9 || read[dg(bodies[3])] != 1 {
			t.Fatalf("status %d, %d referrers, the missing manifest read %d times", w.Code, len(idx.Manifests), read[dg(bodies[3])])
		}
		// A permission error is worth retrying: the request is busy and the
		// manifest is not left out of a whole view.
		extra := referrerBody(subject, "application/vnd.example.sig", 10)
		f.addRows(t, "app", [][]byte{extra})
		if err := os.Chmod(blob(extra), 0); err != nil {
			t.Fatal(err)
		}
		want(t, f.do(http.MethodGet, path, nil), http.StatusTooManyRequests, codeTooManyRequests)
		if err := os.Chmod(blob(extra), 0o600); err != nil {
			t.Fatal(err)
		}
		w = f.do(http.MethodGet, path, nil)
		want(t, w, 200, "")
		_ = json.Unmarshal(w.Body.Bytes(), &idx)
		if len(idx.Manifests) != 10 {
			t.Errorf("after the retry: %d referrers", len(idx.Manifests))
		}
	})

	t.Run("referrers/a build needs a free slot and a cached view does not", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		f.image(t, "cold", "v1", "l")
		path := "/v2/app/referrers/" + dg(subject).String()
		want(t, f.do(http.MethodGet, path, nil), 200, "")
		for range referrersBuilds {
			f.srv.refBuilds <- struct{}{}
		}
		want(t, f.do(http.MethodGet, "/v2/cold/referrers/"+dg(subject).String(), nil), http.StatusTooManyRequests, codeTooManyRequests)
		want(t, f.do(http.MethodGet, path, nil), 200, "")
		<-f.srv.refBuilds
		want(t, f.do(http.MethodGet, "/v2/cold/referrers/"+dg(subject).String(), nil), 200, "")
	})

	t.Run("referrers/4,096 manifests, or sixteen of 4 MiB, are read by one request", func(t *testing.T) {
		f := newFixture(t)
		subject := f.image(t, "app", "v1", "l")
		var bodies [][]byte
		for i := range referrersScanRows - 1 {
			bodies = append(bodies, referrerBody(subject, "application/vnd.example.sig", i))
		}
		f.addRows(t, "app", bodies)
		w := f.do(http.MethodGet, "/v2/app/referrers/"+dg(subject).String(), nil)
		want(t, w, 200, "")

		g := newFixture(t)
		subject = g.image(t, "big", "v1", "l")
		bodies = bodies[:0]
		for i := range 16 {
			m := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest, ArtifactType: "application/vnd.example.big",
				Config: ispec.DescriptorEmptyJSON, Layers: []ispec.Descriptor{},
				Subject:     &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: dg(subject), Size: int64(len(subject))},
				Annotations: map[string]string{"pad": strings.Repeat(fmt.Sprint(i%10), 4<<20-1024)},
			}
			m.SchemaVersion = 2
			b, _ := json.Marshal(m)
			if len(b) > 4<<20 {
				t.Fatalf("a %d-byte manifest", len(b))
			}
			bodies = append(bodies, b)
		}
		g.addRows(t, "big", bodies)
		w = g.do(http.MethodGet, "/v2/big/referrers/"+dg(subject).String(), nil)
		want(t, w, 200, "")
	})

	t.Run("catalog/denied repositories count toward the visit budget and the cursor is readable", func(t *testing.T) {
		readable := map[string]bool{}
		f := newFixture(t, func(c *Config) {
			c.Authorize = func(r *http.Request, v Verb, n ref.Name) error {
				if n.String() == "" || readable[n.String()] {
					return nil
				}
				return ErrDenied
			}
		})
		var names, want []string
		for i := range 3000 {
			n := fmt.Sprintf("r%04d", i)
			names = append(names, n)
			if i%500 == 0 {
				readable[n] = true
				want = append(want, n)
			}
		}
		layRepos(t, f.root, names)
		visits := 0
		f.srv.catalogVisited = func() { visits++ }
		var got []string
		path, pages := "/v2/_catalog?n=10", 0
		for path != "" {
			visits = 0
			w := f.do(http.MethodGet, path, nil)
			if w.Code != 200 {
				t.Fatalf("status %d", w.Code)
			}
			var cat struct{ Repositories []string }
			_ = json.Unmarshal(w.Body.Bytes(), &cat)
			got = append(got, cat.Repositories...)
			if visits > catalogVisits(10)+1 {
				t.Errorf("a page visited %d repositories", visits)
			}
			path = nextLink(t, w.Header())
			if path != "" {
				last := cat.Repositories[len(cat.Repositories)-1]
				if !readable[last] || !strings.Contains(path, "last="+last+"&") {
					t.Fatalf("Link %q after a page ending %q", path, last)
				}
			}
			pages++
		}
		if !slices.Equal(got, want) || pages < 3 {
			t.Errorf("%d pages: %v", pages, got)
		}
	})
}

// TestReferrersRereadNegatives: a manifest cached as unreadable because of its
// file (missing, mismatched, not regular) is read again once index.json
// changes, and those reads count against the request's read budget; one
// unreadable because of its row (an out-of-bounds size) is not.
func TestReferrersRereadNegatives(t *testing.T) {
	f := newFixture(t)
	subject := f.image(t, "app", "v1", "l")
	var bodies [][]byte
	for i := range 6 {
		bodies = append(bodies, referrerBody(subject, "application/vnd.example.sig", i))
	}
	f.addRows(t, "app", bodies)
	// A row whose size no manifest may have.
	dir := filepath.Join(f.root, "app")
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx ispec.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	oversize := dg([]byte("oversize"))
	idx.Manifests = append(idx.Manifests, ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: oversize, Size: store.MaxManifestSize + 1})
	raw, _ = json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(dir, ".uploads", "test-index"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, ".uploads", "test-index"), filepath.Join(dir, "index.json")); err != nil {
		t.Fatal(err)
	}
	blob := func(b []byte) string { return filepath.Join(dir, "blobs", "sha256", dg(b).Encoded()) }
	saved := map[int][]byte{}
	for i := range 3 {
		saved[i] = bodies[i]
		if err := os.Remove(blob(bodies[i])); err != nil {
			t.Fatal(err)
		}
	}
	read := map[digest.Digest]int{}
	reads := 0
	f.srv.referrerRead = func(d digest.Digest) { read[d]++; reads++ }
	path := "/v2/app/referrers/" + dg(subject).String()
	count := func(w *httptest.ResponseRecorder) int {
		t.Helper()
		want(t, w, 200, "")
		var out ispec.Index
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return len(out.Manifests)
	}
	if n := count(f.do(http.MethodGet, path, nil)); n != 3 {
		t.Fatalf("with three blobs missing: %d referrers", n)
	}
	// The blobs come back, but index.json is unchanged: nothing is re-read.
	for i, b := range saved {
		if err := os.WriteFile(blob(bodies[i]), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reads = 0
	if n := count(f.do(http.MethodGet, path, nil)); n != 3 || reads != 0 {
		t.Fatalf("an unchanged index: %d referrers, %d reads", n, reads)
	}
	// index.json changes: the three negatives and the new manifest are read
	// within a budget of two a request, so the first request is busy.
	f.addRows(t, "app", [][]byte{referrerBody(subject, "application/vnd.example.sig", 6)})
	f.srv.refScanRows = 2
	reads = 0
	want(t, f.do(http.MethodGet, path, nil), http.StatusTooManyRequests, codeTooManyRequests)
	if reads != 2 {
		t.Fatalf("the first request after the change read %d manifests, want the budget of 2", reads)
	}
	reads = 0
	if n := count(f.do(http.MethodGet, path, nil)); n != 7 || reads != 2 {
		t.Fatalf("the second request: %d referrers, %d reads", n, reads)
	}
	for i := range 3 {
		if read[dg(bodies[i])] != 2 {
			t.Errorf("restored manifest %d read %d times, want 2", i, read[dg(bodies[i])])
		}
	}
	if read[oversize] != 1 {
		t.Errorf("the out-of-bounds row was read %d times, want 1", read[oversize])
	}
}

// TestReferrerCachePartialCaps: the view and byte bounds of the cache hold
// over partly read views too, dropping the least recently used one that is
// not being built, once no whole view is left to drop.
func TestReferrerCachePartialCaps(t *testing.T) {
	t.Run("views", func(t *testing.T) {
		c := newReferrerCache()
		for i := range referrerCacheViews + 10 {
			k := fmt.Sprint(i)
			c.account(k, c.view(k), 1, 1, true)
		}
		if n := len(c.views); n > referrerCacheViews {
			t.Errorf("%d partly read views cached, bound %d", n, referrerCacheViews)
		}
		if _, ok := c.views["0"]; ok {
			t.Error("the least recently used partly read view survived")
		}
		if c.rows != int64(len(c.views)) || c.partialRows != c.rows {
			t.Errorf("rows %d, partial rows %d, views %d", c.rows, c.partialRows, len(c.views))
		}
	})
	t.Run("bytes", func(t *testing.T) {
		c := newReferrerCache()
		half := int64(referrerCacheBytes/2 + 1)
		pinned := c.view("pinned")
		c.account("pinned", pinned, 1, half, true)
		c.building(pinned, true)
		a := c.view("a")
		c.account("a", a, 1, half/2, true)
		b := c.view("b")
		c.account("b", b, 1, half, true)
		if c.views["pinned"] != pinned || c.views["b"] != b {
			t.Fatal("a view being built, or the view just accounted, was dropped")
		}
		if _, ok := c.views["a"]; ok {
			t.Error("the evictable partly read view survived")
		}
		c.building(pinned, false)
		c.account("b", b, 1, half, true)
		if c.bytes > referrerCacheBytes {
			t.Errorf("%d bytes cached in partly read views, bound %d", c.bytes, referrerCacheBytes)
		}
		if c.views["b"] != b {
			t.Error("the view just accounted was dropped")
		}
	})
}

// TestCatalogCancelled: a cancelled request stops the catalog walk.
func TestCatalogCancelled(t *testing.T) {
	f := newFixture(t)
	var names []string
	for i := range 100 {
		names = append(names, fmt.Sprintf("r%04d", i))
	}
	layRepos(t, f.root, names)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	visits := 0
	f.srv.catalogVisited = func() {
		if visits++; visits == 10 {
			cancel()
		}
	}
	w := f.serve(req(http.MethodGet, "/v2/_catalog?n=2000", nil).WithContext(ctx))
	if visits != 10 {
		t.Errorf("the walk visited %d repositories, the client went away at 10", visits)
	}
	if w.Code == 200 || w.Header().Get("Link") != "" {
		t.Errorf("a cancelled walk answered %d, Link %q", w.Code, w.Header().Get("Link"))
	}
}

// TestCatalogCeiling: a walk through a run of denied names stops at its hard
// ceiling, catalogCeilingFactor times the visit budget, and answers an error
// with no Link.
func TestCatalogCeiling(t *testing.T) {
	readable := map[string]bool{"r0000": true, "r1499": true}
	f := newFixture(t, func(c *Config) {
		c.Authorize = func(r *http.Request, v Verb, n ref.Name) error {
			if n.String() == "" || readable[n.String()] {
				return nil
			}
			return ErrDenied
		}
	})
	var names []string
	for i := range 1500 {
		names = append(names, fmt.Sprintf("r%04d", i))
	}
	layRepos(t, f.root, names)
	visits := 0
	f.srv.catalogVisited = func() { visits++ }
	// At the default ceiling the 1,500 visits fit: both readable names.
	w := f.do(http.MethodGet, "/v2/_catalog?n=2", nil)
	want(t, w, 200, "")
	if !strings.Contains(w.Body.String(), "r1499") {
		t.Fatalf("catalog %s", w.Body.String())
	}
	// At a ceiling of once the budget (1,000 visits) the walk stops.
	f.srv.catalogCeil = 1
	visits = 0
	w = f.do(http.MethodGet, "/v2/_catalog?n=2", nil)
	if w.Code == 200 || w.Header().Get("Link") != "" || strings.Contains(w.Body.String(), "r0000") {
		t.Errorf("past the ceiling: %d %s, Link %q", w.Code, w.Body.String(), w.Header().Get("Link"))
	}
	if visits != catalogVisits(2) {
		t.Errorf("the walk visited %d repositories, ceiling %d", visits, catalogVisits(2))
	}
}
