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

package registrysvc

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// differentialServer is the registry server over a fresh store, recording the
// repository each request was authorized against and every record it logs.
type differentialServer struct {
	h   *api.Server
	log *bytes.Buffer
	// mu guards names.
	mu    sync.Mutex
	names []string
}

func newDifferentialServer(t *testing.T) *differentialServer {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "registry"), filepath.Join(dir, "registry-state"))
	if err != nil {
		t.Fatal(err)
	}
	d := &differentialServer{log: &bytes.Buffer{}}
	h, err := api.New(api.Config{
		Store:     st,
		GCGrace:   time.Hour,
		FreeSpace: plentyFree,
		Logger:    slog.New(slog.NewJSONHandler(d.log, nil)),
		Authorize: func(_ *http.Request, _ api.Verb, n ref.Name) error {
			d.mu.Lock()
			defer d.mu.Unlock()
			d.names = append(d.names, n.String())
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.h = h
	return d
}

// serve runs one request and returns its status and the repository it was
// authorized against, "" when it never reached the authorizer. ok is false for a
// path no client can put on the wire.
func (d *differentialServer) serve(method, path, query string, body string) (status int, repo string, ok bool) {
	target := "http://registry.test" + path
	if query != "" {
		target += "?" + query
	}
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		return 0, "", false
	}
	d.mu.Lock()
	d.names = nil
	d.mu.Unlock()
	rec := httptest.NewRecorder()
	d.h.ServeHTTP(rec, req)
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.names) > 0 {
		repo = d.names[0]
	}
	return rec.Code, repo, true
}

// mounted lists the (repository, from) pairs the server logged a mount of.
func (d *differentialServer) mounted(t *testing.T) [][2]string {
	t.Helper()
	var out [][2]string
	dec := json.NewDecoder(bytes.NewReader(d.log.Bytes()))
	for {
		var rec struct{ Msg, Repository, From string }
		if err := dec.Decode(&rec); err == io.EOF {
			return out
		} else if err != nil {
			t.Fatal(err)
		}
		if rec.Msg == "registry blob mounted" {
			out = append(out, [2]string{rec.Repository, rec.From})
		}
	}
}

// push commits a blob to repo through the server.
func (d *differentialServer) push(t *testing.T, repo, body string) digest.Digest {
	t.Helper()
	dg := digest.FromString(body)
	q := url.Values{"digest": {dg.String()}}.Encode()
	if code, _, _ := d.serve(http.MethodPost, "/v2/"+repo+"/blobs/uploads/", q, body); code != http.StatusCreated {
		t.Fatalf("seed a blob in %s: %d", repo, code)
	}
	return dg
}

// nearMissNames are spellings one character from a valid repository name, or
// valid in one reader's grammar only if it is careless: the shapes that would let
// the gate authorize one repository and the server act on another.
var nearMissNames = []string{
	"A", "a/B", "a//b", "/a", "a/", "a/./b", "a/../b", "..", ".", ".a", "a/.b", "a.", "a-", "-a", "a_", "_a",
	"a___b", "a..b", "a%2fb", "a%2Fb", "%61", "a%00", "a\\b", "a b", "a+b", "a@b", "a:b", "a;b",
	"blobs", "a/blobs", "manifests", "a/manifests", "uploads", "a/uploads", "blobs/a",
	"index.json", "a/index.json", "oci-layout", "a/oci-layout", ".uploads", "a/.uploads",
	strings.Repeat("a", 256),
}

// gateOnlyNames are the near-miss names the gate admits and the server refuses as
// reserved. Nothing else may join them: a name the gate admits and the server
// refuses is a push that fails with the gate's credential already attached.
var gateOnlyNames = []string{"index.json", "a/index.json", "oci-layout", "a/oci-layout"}

// differentialUpload is an upload id in the server's own form. The gate's corpus
// spells ids loosely because it does not read them; the server refuses any other
// form before it looks at the repository, which would hide what it authorized.
const differentialUpload = "00000000-1111-2222-3333-444444444444"

func withServerUpload(path string) string {
	return strings.Replace(path, "/u-1", "/"+differentialUpload, 1)
}

// TestGateAndServerAgree feeds the push gate and the registry server the same
// requests: the classifier's whole corpus and the near-miss names. A write the
// gate admits and the server serves is authorized for the repository the gate
// read, and a mount links from the source the gate read. The server may refuse
// what the gate admits (index.json is a reserved name to it and a plain name to
// the gate), which fails closed, and gateOnlyNames is the whole of that set. Fed a
// spelling the gate refuses, the server refuses it too, or reads the name as
// written after its one percent-decode, and authorizes the name it then acts on.
func TestGateAndServerAgree(t *testing.T) {
	t.Run("the classifier's corpus", func(t *testing.T) {
		for _, tc := range classifyCorpus() {
			r := classify(tc.method, tc.path, tc.query)
			if !r.op.isWrite() {
				continue
			}
			d := newDifferentialServer(t)
			_, repo, ok := d.serve(tc.method, withServerUpload(r.path), r.query, "")
			if !ok {
				t.Errorf("%s %s?%s: the gate forwards what no client can send", tc.method, r.path, r.query)
				continue
			}
			// Every name in this corpus is one the server takes too, so the
			// comparison cannot pass by never reaching the authorizer.
			if repo != r.repo {
				t.Errorf("%s %s?%s: the gate authorized %q, the server %q", tc.method, tc.path, tc.query, r.repo, repo)
			}
		}
	})
	t.Run("near-miss names on every write route", func(t *testing.T) {
		const d0 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		routes := []struct{ method, suffix, query string }{
			{http.MethodPost, "/blobs/uploads/", ""},
			{http.MethodPatch, "/blobs/uploads/" + differentialUpload, ""},
			{http.MethodPut, "/blobs/uploads/" + differentialUpload, "digest=" + d0},
			{http.MethodPut, "/manifests/v1", ""},
			{http.MethodGet, "/blobs/uploads/" + differentialUpload, ""},
		}
		d := newDifferentialServer(t)
		for _, name := range nearMissNames {
			for _, rt := range routes {
				path := "/v2/" + name + rt.suffix
				r := classify(rt.method, path, rt.query)
				if r.op.isWrite() {
					code, repo, ok := d.serve(rt.method, r.path, r.query, "")
					if !ok {
						t.Errorf("%s %s: the gate forwards what no client can send", rt.method, path)
						continue
					}
					if slices.Contains(gateOnlyNames, name) {
						if repo != "" || code < 400 {
							t.Errorf("%s %s: the server took a reserved name: %d, authorized %q", rt.method, path, code, repo)
						}
						continue
					}
					if repo != r.repo {
						t.Errorf("%s %s: the gate authorized %q, the server %q", rt.method, path, r.repo, repo)
					}
					continue
				}
				// The gate refuses it and nothing is forwarded. Fed directly, the
				// server refuses it too, or reads the name as written.
				_, repo, ok := d.serve(rt.method, path, rt.query, "")
				if !ok || repo == "" {
					continue
				}
				if decoded, err := url.PathUnescape(name); err != nil || repo != decoded {
					t.Errorf("%s %s: gate-refused, and the server authorized %q", rt.method, path, repo)
				}
			}
		}
	})
	t.Run("a mount links from the source the gate authorized", func(t *testing.T) {
		for _, tc := range []struct{ repo, from string }{
			{"a", "b"},
			{"a/b", "c/d"},
			{"a/b/c", "a/b"},
			{"a__b/c-d.e", "x_y/z--w"},
		} {
			d := newDifferentialServer(t)
			dg := d.push(t, tc.from, "layer of "+tc.from)
			q := url.Values{"from": {tc.from}, "mount": {dg.String()}}.Encode()
			path := "/v2/" + tc.repo + "/blobs/uploads/"
			r := classify(http.MethodPost, path, q)
			if r.op != opUploadStart || r.repo != tc.repo || r.from != tc.from {
				t.Fatalf("the gate read %q from %q as %+v", tc.repo, tc.from, r)
			}
			code, repo, _ := d.serve(http.MethodPost, r.path, r.query, "")
			if code != http.StatusCreated || repo != r.repo {
				t.Errorf("mount into %s: %d, authorized %q", tc.repo, code, repo)
			}
			got := d.mounted(t)
			if len(got) != 1 || got[0] != [2]string{r.repo, r.from} {
				t.Errorf("mounted %v, the gate authorized %s from %s", got, r.repo, r.from)
			}
		}
	})
	t.Run("a near-miss source is never linked from", func(t *testing.T) {
		for _, from := range nearMissNames {
			d := newDifferentialServer(t)
			// The name a careless reader would clean or fold the spelling to.
			dg := d.push(t, "a", "layer")
			q := "mount=" + dg.String() + "&from=" + url.QueryEscape(from)
			r := classify(http.MethodPost, "/v2/target/blobs/uploads/", q)
			fwd := r.query
			if !r.op.isWrite() {
				// The gate refused it; the server's own reading must not link either.
				fwd = q
			}
			if _, _, ok := d.serve(http.MethodPost, "/v2/target/blobs/uploads/", fwd, ""); !ok {
				continue
			}
			if got := d.mounted(t); len(got) != 0 {
				t.Errorf("from=%q (gate op %s) linked: %v", from, r.op, got)
			}
		}
	})
}
