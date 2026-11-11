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

	t.Run("a conditional digest DELETE refuses a digest a row tags", func(t *testing.T) {
		f := newFixture(t)
		body := f.image(t, "app", "v1", "l")
		// The state is current: only the tag can refuse this, and only the
		// tag's own DELETE removes it.
		for _, cond := range []string{`"` + state(t, f) + `"`, "*"} {
			want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil, "If-Match", cond), http.StatusPreconditionFailed, codeDenied)
			want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), http.StatusOK, "")
		}
		// One tagged row of several refuses the digest.
		want(t, f.pushManifest(t, "app", "v2", ispec.MediaTypeImageManifest, body), http.StatusCreated, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil, "If-Match", `"`+state(t, f)+`"`), http.StatusAccepted, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil, "If-Match", `"`+state(t, f)+`"`), http.StatusPreconditionFailed, codeDenied)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/v2", nil), http.StatusOK, "")
		// A request with no condition keeps the behaviour clients rely on.
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(body).String(), nil), http.StatusAccepted, "")
		want(t, f.do(http.MethodGet, "/v2/app/manifests/v2", nil), http.StatusNotFound, codeManifestUnknown)
	})

	t.Run("a tag DELETE is conditional too", func(t *testing.T) {
		f := newFixture(t)
		f.image(t, "app", "v1", "l")
		planned := state(t, f)
		f.image(t, "app", "v2", "m")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil, "If-Match", `"`+planned+`"`), http.StatusPreconditionFailed, codeDenied)
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil, "If-Match", `"`+state(t, f)+`"`), http.StatusAccepted, "")
	})

	// The table cases each delete from their own copy of one pushed state.
	oneImage := newFixture(t)
	oneBody := oneImage.image(t, "app", "", "l")
	oneState := state(t, oneImage)
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
			f := oneImage.clone(t)
			v := strings.ReplaceAll(tc.ifMatch, "<state>", oneState)
			want(t, f.do(http.MethodDelete, "/v2/app/manifests/"+dg(oneBody).String(), nil, "If-Match", v), tc.status, "")
		})
	}

	// A tag DELETE also matches the tag's own entity tag, its manifest
	// digest; a by-digest DELETE gains nothing from a digest condition.
	tagged := newFixture(t)
	oldBody := tagged.image(t, "app", "v1", "l")
	newBody := tagged.image(t, "app", "", "m")
	for _, tc := range []struct {
		name, path, ifMatch string
		status              int
		gone                bool
	}{
		{"a tag delete matching the tag's digest deletes", "/v2/app/manifests/v1", `"<old>"`, http.StatusAccepted, true},
		{"a tag delete with a star deletes", "/v2/app/manifests/v1", "*", http.StatusAccepted, true},
		{"a tag delete matching the digest in a list deletes", "/v2/app/manifests/v1", `"sha256:nope", "<old>"`, http.StatusAccepted, true},
		{"a tag delete naming a digest the tag does not name is refused", "/v2/app/manifests/v1", `"<new>"`, http.StatusPreconditionFailed, false},
		{"a weak tag of the digest never matches", "/v2/app/manifests/v1", `W/"<old>"`, http.StatusPreconditionFailed, false},
		{"a malformed list naming the digest fails whole", "/v2/app/manifests/v1", `"<old>", bogus`, http.StatusPreconditionFailed, false},
		{"a digest delete naming its own digest is refused", "/v2/app/manifests/<new>", `"<new>"`, http.StatusPreconditionFailed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tagged.clone(t)
			r := strings.NewReplacer("<old>", dg(oldBody).String(), "<new>", dg(newBody).String())
			want(t, f.do(http.MethodDelete, r.Replace(tc.path), nil, "If-Match", r.Replace(tc.ifMatch)), tc.status, "")
			if tc.gone {
				want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), http.StatusNotFound, codeManifestUnknown)
				return
			}
			want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), http.StatusOK, "")
			want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(newBody).String(), nil), http.StatusOK, "")
		})
	}

	// A push that re-points the tag after a client read it makes the digest
	// the client read stale: the tag stays on the new manifest.
	t.Run("a tag re-pointed since it was read is refused", func(t *testing.T) {
		f := newFixture(t)
		read := f.image(t, "app", "v1", "l")
		moved := f.image(t, "app", "v1", "m")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil, "If-Match", `"`+dg(read).String()+`"`), http.StatusPreconditionFailed, codeDenied)
		w := f.do(http.MethodGet, "/v2/app/manifests/v1", nil)
		want(t, w, http.StatusOK, "")
		if got := w.Header().Get("Docker-Content-Digest"); got != dg(moved).String() {
			t.Errorf("app:v1 = %s, want the re-pointed %s", got, dg(moved))
		}
	})

	// Several If-Match field lines are one list (RFC 9110 section 5.3): an
	// empty first line must not turn the condition off for the lines after it.
	twoImages := newFixture(t)
	body := twoImages.image(t, "app", "", "l")
	stale := state(t, twoImages)
	twoImages.image(t, "app", "v1", "m")
	cur := state(t, twoImages)
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
			f := twoImages.clone(t)
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
