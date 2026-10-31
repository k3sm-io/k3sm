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

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestConditionalDelete pins If-Match on a manifest DELETE: the entity tag is
// the repository's index state, a stale or malformed one is 412 and deletes
// nothing, and the current one (or "*") deletes.
func TestConditionalDelete(t *testing.T) {
	state := func(t *testing.T, f *fixture) string {
		t.Helper()
		s, err := store.IndexState(f.rows(t, "app"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("the current state deletes", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "", "l")
		f.image(t, "app", "v1", "m")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil, "If-Match", `"`+state(t, f)+`"`), http.StatusAccepted, "")
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(body).String(), nil), http.StatusNotFound, codeManifestUnknown)
	})

	t.Run("a state a push has moved on from is refused", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "", "l")
		planned := state(t, f)
		// A push tags the planned digest after the state was read.
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body), http.StatusCreated, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil, "If-Match", `"`+planned+`"`), http.StatusPreconditionFailed, codeDenied)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), http.StatusOK, "")
	})

	t.Run("a tag DELETE is conditional too", func(t *testing.T) {
		f := newFixture(t)
		f.image(t, "app", "v1", "l")
		planned := state(t, f)
		f.image(t, "app", "v2", "m")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil, "If-Match", `"`+planned+`"`), http.StatusPreconditionFailed, codeDenied)
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil, "If-Match", `"`+state(t, f)+`"`), http.StatusAccepted, "")
	})

	for _, tc := range []struct {
		name, ifMatch string
		status        int
	}{
		{"star matches any state", "*", http.StatusAccepted},
		{"a list matches on any member", `"sha256:nope", "<state>"`, http.StatusAccepted},
		{"a weak tag never matches", `W/"<state>"`, http.StatusPreconditionFailed},
		{"an unquoted tag never matches", `<state>`, http.StatusPreconditionFailed},
		{"an empty quoted tag never matches", `""`, http.StatusPreconditionFailed},
		{"a weak tag of a stranger never matches", `W/"x"`, http.StatusPreconditionFailed},
		{"a quoted value containing a comma is one tag, not the state", `"<state>,"`, http.StatusPreconditionFailed},
		{"a quoted value containing a comma before the state is not the state", `"x,<state>"`, http.StatusPreconditionFailed},
		{"a list matches after a quoted value containing a comma", `"a,b", "<state>"`, http.StatusAccepted},
		{"an empty field value is a condition no state meets", ``, http.StatusPreconditionFailed},
		{"a blank field value is a condition no state meets", `   `, http.StatusPreconditionFailed},
		{"a list of empty members is a condition no state meets", `, ,`, http.StatusPreconditionFailed},
		{"a star inside a quoted value is no star", `"x,*,y"`, http.StatusPreconditionFailed},
		{"a malformed member fails the whole list", `"<state>", bogus`, http.StatusPreconditionFailed},
		{"an unterminated tag fails the whole list", `"<state>", "x`, http.StatusPreconditionFailed},
		{"a tag run into the next member fails the whole list", `"<state>""x"`, http.StatusPreconditionFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			body := f.image(t, "app", "", "l")
			v := strings.ReplaceAll(tc.ifMatch, "<state>", state(t, f))
			want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil, "If-Match", v), tc.status, "")
		})
	}

	// Several If-Match field lines are one list (RFC 9110 section 5.3): an
	// empty first line must not turn the condition off for the lines after it.
	for _, tc := range []struct {
		name   string
		lines  []string
		status int
	}{
		{"an empty line then a stale tag is refused", []string{"", `"<stale>"`}, http.StatusPreconditionFailed},
		{"an empty line then a weak tag is refused", []string{"", `W/"<state>"`}, http.StatusPreconditionFailed},
		{"an empty line then the current state deletes", []string{"", `"<state>"`}, http.StatusAccepted},
		{"only empty lines are refused", []string{"", ""}, http.StatusPreconditionFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			body := f.image(t, "app", "", "l")
			stale := state(t, f)
			f.image(t, "app", "v1", "m")
			cur := state(t, f)
			r := req(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil)
			for _, l := range tc.lines {
				r.Header.Add("If-Match", strings.NewReplacer("<state>", cur, "<stale>", stale).Replace(l))
			}
			want(t, f.serve(r), tc.status, "")
			wantGone := tc.status == http.StatusAccepted
			got := f.do(http.MethodGet, "/v2/app/manifests/"+dg(body).String(), nil).Code
			if gone := got == http.StatusNotFound; gone != wantGone {
				t.Errorf("after the DELETE the manifest GET is %d; want it gone=%v", got, wantGone)
			}
		})
	}
}
