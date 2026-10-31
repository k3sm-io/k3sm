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
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// Bounds of one FuzzHandlers input. They keep each input to one short request,
// so the committed seeds are cheap enough to run on every go test (which runs
// only the seeds; the engine runs only under -fuzz).
const (
	fuzzMaxPath  = 512
	fuzzMaxQuery = 512
	fuzzMaxBody  = 4096
)

var (
	fuzzMethods = []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodOptions, "TRACE"}
	fuzzTypes   = []string{"", "application/octet-stream", ispec.MediaTypeImageManifest, ispec.MediaTypeImageIndex, mediaTypeDockerManifest, "text/plain"}
)

// FuzzHandlers drives one request, of any method, path, query, Content-Range,
// Content-Type and short body, at a Server over a temp store that holds a
// tagged image in "app" and an open upload session ("{u}" in the path names
// it). It asserts that the answer is not a 5xx (507, the documented low-space
// refusal, aside), that no handler panics (ServeHTTP turns a panic into a
// 500, so the status check catches it, and an abort panic escapes the fuzz
// function), and that nothing is created outside the store root and its
// state directory.
func FuzzHandlers(f *testing.F) {
	f.Fuzz(func(t *testing.T, method uint8, path, query, contentRange string, ctype uint8, body []byte) {
		if len(path) > fuzzMaxPath || len(query) > fuzzMaxQuery || len(body) > fuzzMaxBody || len(contentRange) > 128 {
			t.Skip("over the input bounds")
		}
		base := t.TempDir()
		work := filepath.Join(base, "work")
		outside := filepath.Join(base, "outside")
		if err := os.Mkdir(outside, 0o700); err != nil {
			t.Fatal(err)
		}
		st, err := store.OpenWorkDir(work)
		if err != nil {
			t.Fatal(err)
		}
		srv, err := New(Config{Store: st, Authorize: AllowAll, FreeSpace: func() (uint64, error) { return 1 << 40, nil }})
		if err != nil {
			t.Fatal(err)
		}
		fx := &fixture{srv: srv, st: st, root: st.Root()}
		fx.image(t, "app", "v1", "layer")
		w := fx.do(http.MethodPost, "/v2/app/blobs/uploads/", nil)
		want(t, w, http.StatusAccepted, "")
		upload := strings.TrimPrefix(w.Header().Get("Location"), "/v2/app/blobs/uploads/")

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		path = strings.ReplaceAll(path, "{u}", upload)
		r := httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(body))
		r.Method = fuzzMethods[int(method)%len(fuzzMethods)]
		r.URL.Path, r.URL.RawPath, r.URL.RawQuery = path, "", query
		r.RequestURI = path
		if contentRange != "" {
			r.Header.Set("Content-Range", contentRange)
		}
		if ct := fuzzTypes[int(ctype)%len(fuzzTypes)]; ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		if rec.Code >= 500 && rec.Code != http.StatusInsufficientStorage {
			t.Fatalf("%s %q ?%q: status %d, body %s", r.Method, path, query, rec.Code, rec.Body.String())
		}

		state := filepath.Join(work, "registry-state")
		err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			switch {
			case p == base, p == work, p == outside:
				return nil
			case p == st.Root(), p == state:
				return fs.SkipDir
			}
			t.Errorf("%s %q ?%q created %s outside the store", r.Method, path, query, p)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
