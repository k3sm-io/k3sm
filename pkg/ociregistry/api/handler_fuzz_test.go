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

	"k3sm.io/k3sm/pkg/ociregistry/ref"
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
// tagged image in "app" with a referrer of it, an image in the nested
// "team/app", and an open upload session ("{u}" in the path names it, "{s}"
// the image's digest). It asserts that the answer is not a 5xx (507, the
// documented low-space refusal, aside), that no handler panics (ServeHTTP
// turns a panic into a 500, so the status check catches it, and an abort panic
// escapes the fuzz function), that nothing is created outside the store root
// and its state directory, and that inside them every entry is one the store
// layout names and none is a symlink.
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
		subject := fx.image(t, "app", "v1", "layer")
		fx.pushBlob(t, "app", ispec.DescriptorEmptyJSON.Data)
		sig := referrerBody(subject, "application/vnd.example.sig", 0)
		want(t, fx.pushManifest(t, "app", dg(sig).String(), ispec.MediaTypeImageManifest, sig), http.StatusCreated, "")
		fx.image(t, "team/app", "v1", "nested")
		w := fx.do(http.MethodPost, "/v2/app/blobs/uploads/", nil)
		want(t, w, http.StatusAccepted, "")
		upload := strings.TrimPrefix(w.Header().Get("Location"), "/v2/app/blobs/uploads/")

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		path = strings.ReplaceAll(strings.ReplaceAll(path, "{u}", upload), "{s}", dg(subject).String())
		query = strings.ReplaceAll(query, "{s}", dg(subject).String())
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
		for _, bad := range strayEntries(t, base, map[string]bool{work: true, outside: true}, st.Root(), state) {
			t.Errorf("%s %q ?%q: %s", r.Method, path, query, bad)
		}
	})
}

// strayEntries walks base and returns every entry that is a symlink, or is not
// one of: a directory in dirs, the store root and state directory, a
// directory whose path below root is a repository name (or a name's parent),
// a repository's oci-layout, index.json, blobs/<algorithm>/<hex> and
// .uploads/<id>, and the state directory's locks/<hex>.
func strayEntries(t *testing.T, base string, dirs map[string]bool, root, state string) []string {
	t.Helper()
	var bad []string
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			bad = append(bad, "a symlink at "+p)
			return nil
		}
		if p == base || p == root || p == state || dirs[p] {
			if !d.IsDir() {
				bad = append(bad, "not a directory: "+p)
			}
			return nil
		}
		if !storeEntry(p, d.IsDir(), root, state) {
			bad = append(bad, "an entry the store layout does not name: "+p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bad
}

func storeEntry(p string, isDir bool, root, state string) bool {
	hex := func(s string) bool {
		if s == "" {
			return false
		}
		for _, c := range s {
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
				return false
			}
		}
		return true
	}
	if rel, err := filepath.Rel(state, p); err == nil && !strings.HasPrefix(rel, "..") {
		e := strings.Split(rel, string(filepath.Separator))
		return (len(e) == 1 && e[0] == "locks" && isDir) || (len(e) == 2 && e[0] == "locks" && !isDir && hex(e[1]))
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	e := strings.Split(rel, string(filepath.Separator))
	// The repository directory is the longest prefix before a layout entry.
	for i, c := range e {
		switch c {
		case "oci-layout", "index.json":
			return i == len(e)-1 && i > 0 && !isDir
		case "blobs":
			rest := e[i+1:]
			return i > 0 && (len(rest) == 0 && isDir ||
				len(rest) == 1 && isDir && (rest[0] == "sha256" || rest[0] == "sha512") ||
				len(rest) == 2 && !isDir && hex(rest[1]))
		case ".uploads":
			rest := e[i+1:]
			return i > 0 && (len(rest) == 0 && isDir || len(rest) == 1 && !isDir)
		}
	}
	if !isDir {
		return false
	}
	_, err = ref.ParseName(filepath.ToSlash(rel))
	return err == nil
}

// TestStrayEntries: the fuzz target's layout check is not vacuous.
func TestStrayEntries(t *testing.T) {
	base := t.TempDir()
	root, state := filepath.Join(base, "work", "registry"), filepath.Join(base, "work", "registry-state")
	for _, d := range []string{filepath.Join(root, "app", "blobs", "sha256"), filepath.Join(root, "app", ".uploads"), filepath.Join(state, "locks")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(root, "app", "index.json"), filepath.Join(root, "app", "blobs", "sha256", "ab12"), filepath.Join(root, "app", ".uploads", "x"), filepath.Join(state, "locks", "ff")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dirs := map[string]bool{filepath.Join(base, "work"): true}
	if bad := strayEntries(t, base, dirs, root, state); len(bad) != 0 {
		t.Fatalf("a clean layout: %v", bad)
	}
	for _, p := range []string{filepath.Join(root, "app", "stray"), filepath.Join(root, "app", "blobs", "sha256", "XYZ"), filepath.Join(state, "other"), filepath.Join(base, "outside-file")} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if bad := strayEntries(t, base, dirs, root, state); len(bad) != 1 {
			t.Errorf("%s: %v", p, bad)
		}
		_ = os.Remove(p)
	}
	if err := os.Symlink("/etc", filepath.Join(root, "app", "link")); err != nil {
		t.Fatal(err)
	}
	if bad := strayEntries(t, base, dirs, root, state); len(bad) != 1 || !strings.HasPrefix(bad[0], "a symlink") {
		t.Errorf("a symlink: %v", bad)
	}
}
