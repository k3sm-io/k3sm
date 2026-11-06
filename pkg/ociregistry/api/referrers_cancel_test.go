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
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// semFree reports whether v's semaphore can be taken now.
func semFree(v *refView) bool {
	select {
	case v.sem <- struct{}{}:
		<-v.sem
		return true
	default:
		return false
	}
}

// TestReferrersBuildStopsOnCancel: a request whose client went away reads no
// further manifest of a view it is building, gives back the build slot and the
// repository's semaphore, and leaves what it read for the next request.
func TestReferrersBuildStopsOnCancel(t *testing.T) {
	const manifests, stopAt = 2000, 10
	f := newFixture(t)
	subject := f.image(t, "app", "v1", "l")
	bodies := make([][]byte, 0, manifests)
	for i := range manifests {
		bodies = append(bodies, referrerBody(subject, "application/vnd.example.sig", i))
	}
	f.addRows(t, "app", bodies)
	f.srv.refPage = manifests + 1
	path := "/v2/app/referrers/" + dg(subject).String()
	v := f.srv.refs.view("app")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	read := map[digest.Digest]int{}
	reads := 0
	f.srv.referrerRead = func(d digest.Digest) {
		read[d]++
		reads++
		if reads != stopAt {
			return
		}
		if n := len(f.srv.refBuilds); n != 1 || semFree(v) {
			t.Errorf("mid-build: %d slots in use, semaphore free %v; the build should hold both", n, semFree(v))
		}
		cancel()
	}
	w := f.serve(req(http.MethodGet, path, nil).WithContext(ctx))
	if reads != stopAt {
		t.Fatalf("%d manifests read, want the build to stop after the %dth, when the client went away", reads, stopAt)
	}
	want(t, w, http.StatusServiceUnavailable, codeUnavailable)
	if n := len(f.srv.refBuilds); n != 0 {
		t.Errorf("%d build slots still in use", n)
	}
	if !semFree(v) {
		t.Error("the repository's semaphore is still held")
	}
	f.srv.refs.mu.Lock()
	building, partial, rows := v.building, v.partial, v.rows
	f.srv.refs.mu.Unlock()
	if building || !partial || rows != stopAt {
		t.Errorf("after the cancel: building %v, partial %v, %d rows kept, want false, true, %d", building, partial, rows, stopAt)
	}

	// The next request carries on from what was read: no manifest twice.
	w = f.do(http.MethodGet, path, nil)
	want(t, w, 200, "")
	var out ispec.Index
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Manifests) != manifests {
		t.Errorf("%d referrers, want %d", len(out.Manifests), manifests)
	}
	if reads != manifests+1 {
		t.Errorf("%d reads over both requests, want %d", reads, manifests+1)
	}
	for d, n := range read {
		if n != 1 {
			t.Errorf("%s read %d times", d, n)
		}
	}
}

// TestReferrersCancelKeepsLaterEntries: a cancel keeps the entries of rows the
// walk had not reached, so a client that keeps going away cannot make the view
// read them again. New rows sort first here, which is what makes it matter.
func TestReferrersCancelKeepsLaterEntries(t *testing.T) {
	f := newFixture(t)
	subject := f.image(t, "app", "v1", "l")
	var bodies [][]byte
	for i := range 8 {
		bodies = append(bodies, referrerBody(subject, "application/vnd.example.sig", i))
	}
	f.addRows(t, "app", bodies)
	path := "/v2/app/referrers/" + dg(subject).String()
	want(t, f.do(http.MethodGet, path, nil), 200, "")

	// Two new manifests, their rows moved to the front of index.json.
	fresh := [][]byte{
		referrerBody(subject, "application/vnd.example.sig", 100),
		referrerBody(subject, "application/vnd.example.sig", 101),
	}
	f.addRows(t, "app", fresh)
	dir := filepath.Join(f.root, "app")
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx ispec.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	split := len(idx.Manifests) - len(fresh)
	idx.Manifests = append(idx.Manifests[split:len(idx.Manifests):len(idx.Manifests)], idx.Manifests[:split]...)
	raw, _ = json.Marshal(idx)
	tmp := filepath.Join(dir, ".uploads", "test-index")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "index.json")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var read []digest.Digest
	f.srv.referrerRead = func(d digest.Digest) {
		read = append(read, d)
		cancel()
	}
	want(t, f.serve(req(http.MethodGet, path, nil).WithContext(ctx)), http.StatusServiceUnavailable, codeUnavailable)
	if len(read) != 1 || read[0] != dg(fresh[0]) {
		t.Fatalf("the cancelled request read %v, want only the first new manifest", read)
	}
	read = nil
	want(t, f.do(http.MethodGet, path, nil), 200, "")
	if len(read) != 1 || read[0] != dg(fresh[1]) {
		t.Errorf("the next request read %v, want only the second new manifest", read)
	}
}

// TestReferrersCancelAfterLastRowCompletes: a client that goes away once every
// row has been read does not cost the finished view.
func TestReferrersCancelAfterLastRowCompletes(t *testing.T) {
	f := newFixture(t)
	subject := f.image(t, "app", "v1", "l")
	body := referrerBody(subject, "application/vnd.example.sig", 0)
	f.addRows(t, "app", [][]byte{body})
	path := "/v2/app/referrers/" + dg(subject).String()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reads := 0
	f.srv.referrerRead = func(d digest.Digest) {
		reads++
		if d == dg(body) {
			cancel()
		}
	}
	want(t, f.serve(req(http.MethodGet, path, nil).WithContext(ctx)), 200, "")
	if reads != 2 {
		t.Fatalf("%d reads, want the image and the referrer", reads)
	}
	reads = 0
	want(t, f.do(http.MethodGet, path, nil), 200, "")
	if reads != 0 {
		t.Errorf("the view was not whole: the next request read %d manifests", reads)
	}
}
