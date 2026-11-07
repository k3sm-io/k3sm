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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestEncodedPathsAreRefused pins that a percent escape in a request path is
// refused on every route, reads included, before the authorizer or a handler
// sees it: the push gate refuses every escape on a write and passes a read through
// as received, so a server that read the decoded name would act on a repository
// the raw path did not spell.
func TestEncodedPathsAreRefused(t *testing.T) {
	var reached []string
	f := newFixture(t, func(c *Config) {
		c.Authorize = func(_ *http.Request, _ Verb, n ref.Name) error {
			reached = append(reached, n.String())
			return nil
		}
	})
	layer := "layer of a/b"
	f.image(t, "a/b", "v1", layer)
	const upload = "00000000-1111-2222-3333-444444444444"
	d := dg([]byte(layer)).String()

	routes := []struct{ method, suffix string }{
		{http.MethodGet, "/tags/list"},
		{http.MethodGet, "/manifests/v1"},
		{http.MethodHead, "/manifests/v1"},
		{http.MethodPut, "/manifests/v1"},
		{http.MethodDelete, "/manifests/v1"},
		{http.MethodGet, "/blobs/" + d},
		{http.MethodHead, "/blobs/" + d},
		{http.MethodDelete, "/blobs/" + d},
		{http.MethodGet, "/referrers/" + d},
		{http.MethodPost, "/blobs/uploads/"},
		{http.MethodPost, "/blobs/uploads"},
		{http.MethodGet, "/blobs/uploads/" + upload},
		{http.MethodPatch, "/blobs/uploads/" + upload},
		{http.MethodPut, "/blobs/uploads/" + upload},
		{http.MethodDelete, "/blobs/uploads/" + upload},
	}
	// Each of these decodes to a name the store holds.
	for _, name := range []string{"a%2fb", "a%2Fb", "%61/b", "a/%62", "%61%2f%62"} {
		for _, rt := range routes {
			path := "/v2/" + name + rt.suffix
			t.Run(rt.method+" "+path, func(t *testing.T) {
				reached = nil
				code := codeNameInvalid
				if rt.method == http.MethodHead {
					code = "" // a HEAD answer carries no body
				}
				want(t, f.do(rt.method, path, nil), http.StatusBadRequest, code)
				if len(reached) != 0 {
					t.Errorf("the authorizer was asked about %q", reached)
				}
			})
		}
	}
	// An escape anywhere else could move a route word, or spell a reference the
	// name's own route then reads; the whole path is held to the one rule.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v2/a/b%2fmanifests%2fv1"},
		{http.MethodGet, "/v2/a/b/manifests/v%31"},
		{http.MethodGet, "/v2/a/b/manifests/" + strings.Replace(d, ":", "%3A", 1)},
		{http.MethodGet, "/v2/a/b/blobs/" + strings.Replace(d, ":", "%3a", 1)},
		{http.MethodPost, "/v2/a/b%2fblobs%2fuploads%2f"},
		{http.MethodPost, "/v2/a/b/blobs/%75ploads/"},
		{http.MethodPut, "/v2/a/b/manifests/x%2fy"},
		{http.MethodGet, "/v2/%5fcatalog"},
		{http.MethodGet, "/v2/a/b/tags/%6cist"},
		{http.MethodGet, "/v%32/"},
		{http.MethodGet, "/v2/a%20b/tags/list"},
		{http.MethodGet, "/v2/a%25b/tags/list"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			reached = nil
			want(t, f.do(tc.method, tc.path, nil), http.StatusBadRequest, codeNameInvalid)
			if len(reached) != 0 {
				t.Errorf("the authorizer was asked about %q", reached)
			}
		})
	}
	// The same requests spelled plainly are served, so the refusals above are
	// about the spelling and not the repository, the tag or the digest.
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/v2/a/b/tags/list", http.StatusOK},
		{http.MethodGet, "/v2/a/b/manifests/v1", http.StatusOK},
		{http.MethodGet, "/v2/a/b/blobs/" + d, http.StatusOK},
		{http.MethodPost, "/v2/a/b/blobs/uploads/", http.StatusAccepted},
		{http.MethodGet, "/v2/_catalog", http.StatusOK},
		{http.MethodGet, "/v2/", http.StatusOK},
	} {
		t.Run("plain "+tc.method+" "+tc.path, func(t *testing.T) {
			want(t, f.do(tc.method, tc.path, nil), tc.status, "")
		})
	}
	// A query is not a path: a mount's source spells its slash as %2F, and
	// _catalog's last does too.
	t.Run("an escape in the query is still read", func(t *testing.T) {
		want(t, f.do(http.MethodGet, "/v2/_catalog?last=a%2Fb", nil), http.StatusOK, "")
		w := f.do(http.MethodPost, "/v2/c/d/blobs/uploads/?mount="+d+"&from=a%2Fb", nil)
		want(t, w, http.StatusCreated, "")
	})
}
