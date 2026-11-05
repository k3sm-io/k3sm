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
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// FuzzConditionalDelete drives a conditional manifest DELETE, of any If-Match
// value, at a Server over a temp store that holds a tagged image, an untagged
// one, and a tagged index naming an untagged child. target picks what is
// deleted: those digests, an unknown one, a tag, or ref as given. "{state}" in
// ifMatch names the repository's current index state, so a seed can reach a
// condition that holds. It asserts no 5xx, no panic (ServeHTTP turns one into a
// 500), nothing outside the store and nothing in it the layout does not name,
// and that a conditional DELETE by digest never removes a tagged row or a
// manifest an index names, whatever the condition says. FuzzHandlers does not
// reach this: it has no If-Match input.
func FuzzConditionalDelete(f *testing.F) {
	// The store every input starts from, pushed once and cloned per input.
	seeded := newFixture(f)
	tagged := seeded.image(f, "app", "v1", "tagged")
	untagged := seeded.image(f, "app", "", "untagged")
	child := seeded.image(f, "app", "", "child")
	index := seeded.index(f, "app", "idx", child)
	rows := seeded.rows(f, "app")
	state, err := store.IndexState(rows)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, target uint8, ifMatch, rawRef string) {
		if len(ifMatch) > 4096 || len(rawRef) > 512 {
			t.Skip("over the input bounds")
		}
		base := t.TempDir()
		work := filepath.Join(base, "work")
		cloneWork(t, seeded.workDir(), work)
		fx := fixtureOver(t, work)
		srv, st := fx.srv, fx.st

		reference, mustStay := "", false
		switch target % 7 {
		case 0:
			reference, mustStay = dg(tagged).String(), true
		case 1:
			reference = dg(untagged).String()
		case 2:
			reference, mustStay = dg(child).String(), true
		case 3:
			reference, mustStay = dg(index).String(), true
		case 4:
			reference = dg([]byte("no such manifest")).String()
		case 5:
			reference = "v1"
		default:
			reference = rawRef
		}
		path := "/v2/app/manifests/" + reference
		r := httptest.NewRequest(http.MethodDelete, "/", nil)
		r.URL.Path, r.URL.RawPath, r.RequestURI = path, "", path
		r.Header["If-Match"] = []string{strings.ReplaceAll(ifMatch, "{state}", state)}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		if rec.Code >= 500 {
			t.Fatalf("DELETE %q If-Match %q: status %d, body %s", path, ifMatch, rec.Code, rec.Body.String())
		}
		if rec.Code < 300 && mustStay {
			t.Fatalf("DELETE %q If-Match %q: status %d, want it refused", path, ifMatch, rec.Code)
		}
		if mustStay {
			if got := fx.rows(t, "app"); len(got) != len(rows) {
				t.Fatalf("DELETE %q If-Match %q: %d rows left of %d", path, ifMatch, len(got), len(rows))
			}
		}
		for _, bad := range strayEntries(t, base, map[string]bool{work: true}, st.Root(), filepath.Join(work, "registry-state")) {
			t.Errorf("DELETE %q If-Match %q: %s", path, ifMatch, bad)
		}
	})
}
