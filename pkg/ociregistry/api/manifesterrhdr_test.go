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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

// TestManifestErrorAnswersCarryNoManifestHeaders tables the manifest read
// errors (404, 400 and 5xx) over a real HTTP server and asserts that none
// carries Docker-Content-Digest or ETag, which name a manifest the answer does
// not deliver, and that Content-Length is absent or exactly the error body's
// length. The server is fronted by a handler that sets all three before the
// registry runs, as a header set ahead of the store call would, so a refusal
// that failed to clear them shows.
func TestManifestErrorAnswersCarryNoManifestHeaders(t *testing.T) {
	f := newFixture(t)
	body := f.image(t, "app", "v1", "layer")
	d := dg(body)
	bad := f.image(t, "app", "bad", "bad-layer")
	if err := os.WriteFile(f.blobFile("app", dg(bad)), bad[:len(bad)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	other := dg([]byte("never pushed"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Docker-Content-Digest", d.String())
		h.Set("ETag", `"`+d.String()+`"`)
		h.Set("Content-Length", strconv.Itoa(len(body)))
		f.srv.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	for _, tc := range []struct {
		name, reference string
		status          int
	}{
		{"an unknown tag", "nope", http.StatusNotFound},
		{"an unknown digest", other.String(), http.StatusNotFound},
		{"a reference outside the tag grammar", "-bad", http.StatusNotFound},
		{"a malformed digest", "sha256:xyz", http.StatusBadRequest},
		{"a manifest corrupt on disk", "bad", http.StatusInternalServerError},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				req, err := http.NewRequest(method, srv.URL+"/v2/app/manifests/"+tc.reference, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := srv.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != tc.status {
					t.Fatalf("status %d, want %d; body %s", resp.StatusCode, tc.status, got)
				}
				for _, h := range []string{"Docker-Content-Digest", "ETag"} {
					if v := resp.Header.Get(h); v != "" {
						t.Errorf("%s %q on a %d", h, v, tc.status)
					}
				}
				if v := resp.Header.Get("Content-Length"); v != "" && v != strconv.Itoa(len(got)) {
					t.Errorf("Content-Length %s with a %d byte body", v, len(got))
				}
				if method == http.MethodHead && len(got) != 0 {
					t.Errorf("HEAD body %q", got)
				}
			})
		}
	}
}
