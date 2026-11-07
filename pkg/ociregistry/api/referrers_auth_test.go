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
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestReferrersAuthorizeFirst: the handler asks the Authorizer before it looks
// at the digest, so a caller who may not read learns nothing from a bad one.
func TestReferrersAuthorizeFirst(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer error
		status int
		code   string
	}{
		{"unauthenticated", ErrUnauthenticated, http.StatusUnauthorized, codeUnauthorized},
		{"denied", ErrDenied, http.StatusForbidden, codeDenied},
		{"allowed", nil, http.StatusBadRequest, codeDigestInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked []Verb
			f := newFixture(t, func(c *Config) {
				c.Authorize = func(_ *http.Request, v Verb, _ ref.Name) error {
					asked = append(asked, v)
					return tc.answer
				}
			})
			w := f.do(http.MethodGet, "/v2/app/referrers/latest", nil)
			want(t, w, tc.status, tc.code)
			if !slices.Equal(asked, []Verb{VerbRead}) {
				t.Errorf("the Authorizer was asked %v, want [read]", asked)
			}
			if tc.status == http.StatusUnauthorized && !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
				t.Errorf("WWW-Authenticate %q", w.Header().Get("WWW-Authenticate"))
			}
		})
	}
}
