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
	"net/http"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestGetBlobAuthorizesFirst: every handler asks the Authorizer before it
// parses caller input it could answer differently, so a caller without access
// gets the same status and error code for a malformed input as for a
// well-formed one. The name itself is parsed first because the Authorizer
// takes the parsed name (withName).
func TestGetBlobAuthorizesFirst(t *testing.T) {
	const (
		good  = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		bad   = "sha256:nothex"
		id    = "00000000-0000-0000-0000-000000000000"
		badID = "not-a-uuid"
	)
	for _, tc := range []struct {
		name         string
		method, path string
		goodPath     string
		// onlyRead denies read but allows everything else (a mount's source).
		onlyRead bool
	}{
		{"getBlob", http.MethodGet, "/v2/app/blobs/" + bad, "/v2/app/blobs/" + good, false},
		{"headBlob", http.MethodHead, "/v2/app/blobs/" + bad, "/v2/app/blobs/" + good, false},
		{"deleteBlob", http.MethodDelete, "/v2/app/blobs/" + bad, "/v2/app/blobs/" + good, false},
		{"referrers", http.MethodGet, "/v2/app/referrers/" + bad, "/v2/app/referrers/" + good, false},
		{"monolithic", http.MethodPost, "/v2/app/blobs/uploads/?digest=" + bad, "/v2/app/blobs/uploads/?digest=" + good, false},
		{"mount", http.MethodPost, "/v2/app/blobs/uploads/?from=other&mount=" + bad, "/v2/app/blobs/uploads/?from=other&mount=" + good, true},
		{"uploadStatus", http.MethodGet, "/v2/app/blobs/uploads/" + badID, "/v2/app/blobs/uploads/" + id, false},
		{"patchUpload", http.MethodPatch, "/v2/app/blobs/uploads/" + badID, "/v2/app/blobs/uploads/" + id, false},
		{"finishUpload id", http.MethodPut, "/v2/app/blobs/uploads/" + badID + "?digest=" + good, "/v2/app/blobs/uploads/" + id + "?digest=" + good, false},
		{"finishUpload digest", http.MethodPut, "/v2/app/blobs/uploads/" + id + "?digest=" + bad, "/v2/app/blobs/uploads/" + id + "?digest=" + good, false},
		{"cancelUpload", http.MethodDelete, "/v2/app/blobs/uploads/" + badID, "/v2/app/blobs/uploads/" + id, false},
		{"getManifest", http.MethodGet, "/v2/app/manifests/sha256:nothex", "/v2/app/manifests/" + good, false},
		{"putManifest", http.MethodPut, "/v2/app/manifests/sha256:nothex", "/v2/app/manifests/" + good, false},
		{"deleteManifest", http.MethodDelete, "/v2/app/manifests/sha256:nothex", "/v2/app/manifests/" + good, false},
		{"catalog", http.MethodGet, "/v2/_catalog?n=x&last=BAD%20NAME", "/v2/_catalog?n=x&last=app", false},
		{"tags", http.MethodGet, "/v2/app/tags/list?n=x&last=BAD%20TAG", "/v2/app/tags/list?n=x&last=v1", false},
	} {
		for _, refusal := range []struct {
			name   string
			err    error
			status int
		}{
			{"unauthenticated", ErrUnauthenticated, http.StatusUnauthorized},
			{"denied", ErrDenied, http.StatusForbidden},
		} {
			t.Run(tc.name+"/"+refusal.name, func(t *testing.T) {
				f := newFixture(t, func(c *Config) {
					c.Authorize = func(_ *http.Request, v Verb, _ ref.Name) error {
						if tc.onlyRead && v != VerbRead {
							return nil
						}
						return refusal.err
					}
				})
				code := codeDenied
				if refusal.status == http.StatusUnauthorized {
					code = codeUnauthorized
				}
				if tc.method == http.MethodHead {
					code = "" // a HEAD answer has no body
				}
				wellFormed := f.do(tc.method, tc.goodPath, nil)
				want(t, wellFormed, refusal.status, code)
				malformed := f.do(tc.method, tc.path, nil)
				want(t, malformed, refusal.status, code)
				if got, w := malformed.Header().Get("WWW-Authenticate") != "", refusal.status == http.StatusUnauthorized; got != w {
					t.Errorf("WWW-Authenticate set = %v, want %v", got, w)
				}
			})
		}
	}
}
