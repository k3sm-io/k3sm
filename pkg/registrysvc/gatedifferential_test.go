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

func newDifferentialServer(t testing.TB) *differentialServer {
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

// acceptedNames are valid repository names the gate and the server both take,
// route words among them: the router and the gate read a name as everything before
// the route, so each has one reading.
var acceptedNames = []string{
	"a", "a/b", "a/b/c", "a__b/c-d.e", "x_y/z--w", "foo.com/bar", "localhost/a", "v2", "tags/list", "referrers",
	"manifests", "a/manifests", "manifests/a", "a/manifests/manifests", "uploads", "a/uploads", "uploads/a",
	"a/cache.db", "a/htpasswd", strings.Repeat("a", 255),
}

// nearMissNames are spellings one character from a valid repository name, or
// valid in one reader's grammar only if it is careless, and the store's own words:
// the shapes that would let the gate authorize one repository and the server act
// on another. Neither reader takes any of them.
var nearMissNames = []string{
	"A", "a/B", "a//b", "/a", "a/", "a/./b", "a/../b", "..", ".", ".a", "a/.b", "a.", "a-", "-a", "a_", "_a",
	"a___b", "a..b", "a%2fb", "a%2Fb", "%61", "%61/b", "a/%62", "%61%2f%62", "a%00", "%2e%2e", "a/%2e%2e/b", "a%2f..%2fb",
	"a%2fblobs%2fuploads", "a%2fmanifests", "a\\b", "a b", "a+b", "a@b", "a:b", "a;b",
	"blobs", "a/blobs", "blobs/a", "index.json", "a/index.json", "index.json/a", "oci-layout", "a/oci-layout", "oci-layout/a",
	".uploads", "a/.uploads", "cache.db", "cache.db/a", "meta.db", "config.json", "htpasswd", "htpasswd/a", "push-credential.json",
	strings.Repeat("a", 256),
}

// differentialUpload is an upload id in the server's own form. The gate's corpus
// spells ids loosely because it does not read them; the server refuses any other
// form before it looks at the repository, which would hide what it authorized.
const differentialUpload = "00000000-1111-2222-3333-444444444444"

func withServerUpload(path string) string {
	return strings.Replace(path, "/u-1", "/"+differentialUpload, 1)
}

// differentialRoutes are the routes the gate authorizes, with the request that
// reaches the authorizer on each.
var differentialRoutes = []struct{ method, suffix, query string }{
	{http.MethodPost, "/blobs/uploads/", ""},
	{http.MethodPatch, "/blobs/uploads/" + differentialUpload, ""},
	{http.MethodPut, "/blobs/uploads/" + differentialUpload, "digest=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{http.MethodPut, "/manifests/v1", ""},
	{http.MethodGet, "/blobs/uploads/" + differentialUpload, ""},
}

// agree feeds one write to the gate and the server. The gate admits it exactly
// when the server authorizes it, for the same repository; refused by the gate, it
// never reaches the server's authorizer. It reports whether the gate admitted it.
func agree(t *testing.T, d *differentialServer, method, path, query string) (admitted bool) {
	t.Helper()
	r := classify(method, path, query)
	if !r.op.isWrite() {
		if code, repo, ok := d.serve(method, path, query, ""); ok && (repo != "" || code < 400) {
			t.Errorf("%s %s?%s: gate %s, and the server answered %d, authorized %q", method, path, query, r.op, code, repo)
		}
		return false
	}
	code, repo, ok := d.serve(method, r.path, r.query, "")
	if !ok {
		t.Errorf("%s %s?%s: the gate forwards what no client can send", method, path, query)
		return true
	}
	if repo != r.repo {
		t.Errorf("%s %s?%s: the gate authorized %q, the server %q (%d)", method, path, query, r.repo, repo, code)
	}
	return true
}

// TestGateAndServerAgree feeds the push gate and the registry server the same
// requests: the classifier's whole corpus, valid names and the near-miss names.
// There is no exception set. A write the gate admits is authorized by the server
// for the repository the gate read, and a mount links from the source the gate
// read. A spelling the gate refuses never reaches the server's authorizer. A read
// the gate passes through anonymously is authorized by the server for the name as
// the path spells it, or refused.
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
			if repo != r.repo {
				t.Errorf("%s %s?%s: the gate authorized %q, the server %q", tc.method, tc.path, tc.query, r.repo, repo)
			}
		}
	})
	t.Run("the classifier's refused rows", func(t *testing.T) {
		d := newDifferentialServer(t)
		for _, tc := range classifyCorpus() {
			if op := classify(tc.method, tc.path, tc.query).op; op == opRead || op.isWrite() {
				continue
			}
			// The gate refuses these for their shape, method or query as well as
			// for their name, so the server may serve a shape the gate does not.
			// It never reads another repository than the path spells.
			_, repo, ok := d.serve(tc.method, withServerUpload(tc.path), tc.query, "")
			if !ok || repo == "" {
				continue
			}
			if strings.Contains(tc.path, "%") || !strings.HasPrefix(tc.path, "/v2/"+repo+"/") {
				t.Errorf("%s %s?%s: the server authorized %q", tc.method, tc.path, tc.query, repo)
			}
		}
	})
	t.Run("accepted names on every write route", func(t *testing.T) {
		d := newDifferentialServer(t)
		for _, name := range acceptedNames {
			for _, rt := range differentialRoutes {
				if !agree(t, d, rt.method, "/v2/"+name+rt.suffix, rt.query) {
					t.Errorf("%s /v2/%s%s: the gate refused a valid name", rt.method, name, rt.suffix)
				}
			}
		}
	})
	t.Run("near-miss names on every write route", func(t *testing.T) {
		d := newDifferentialServer(t)
		for _, name := range nearMissNames {
			for _, rt := range differentialRoutes {
				if agree(t, d, rt.method, "/v2/"+name+rt.suffix, rt.query) {
					t.Errorf("%s /v2/%s%s: the gate admitted a near miss", rt.method, name, rt.suffix)
				}
			}
		}
	})
	t.Run("a read names only the repository the path spells", func(t *testing.T) {
		d := newDifferentialServer(t)
		for _, name := range slices.Concat(acceptedNames, nearMissNames) {
			for _, suffix := range []string{"/tags/list", "/manifests/v1", "/blobs/" + digest.FromString("x").String(), "/referrers/" + digest.FromString("x").String()} {
				path := "/v2/" + name + suffix
				if r := classify(http.MethodGet, path, ""); r.op != opRead && r.op != opInvalid {
					t.Errorf("GET %s: gate %s", path, r.op)
				}
				_, repo, ok := d.serve(http.MethodGet, path, "", "")
				if !ok {
					continue
				}
				if _, err := ref.ParseName(name); err != nil && repo != "" {
					t.Errorf("GET %s: the server authorized %q for a name the validator refuses", path, repo)
				}
				if slices.Contains(acceptedNames, name) && repo != name {
					t.Errorf("GET %s: the server authorized %q", path, repo)
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
			{"a/uploads", "b/manifests"},
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
	t.Run("an escape in a mount source reads as one name", func(t *testing.T) {
		// A query value decodes once for both readers, so these name a valid
		// source; the gate forwards the decoded form and the server links from it.
		for _, tc := range []struct{ rawFrom, from string }{{"%61", "a"}, {"a%2Fb", "a/b"}, {"a%2fb", "a/b"}} {
			d := newDifferentialServer(t)
			dg := d.push(t, tc.from, "layer")
			q := "mount=" + dg.String() + "&from=" + tc.rawFrom
			r := classify(http.MethodPost, "/v2/target/blobs/uploads/", q)
			if r.op != opUploadStart || r.from != tc.from {
				t.Fatalf("from=%s: the gate read %+v", tc.rawFrom, r)
			}
			// Fed the client's spelling or the gate's, the server links from one source.
			for _, query := range []string{r.query, q} {
				d := newDifferentialServer(t)
				d.push(t, tc.from, "layer")
				d.serve(http.MethodPost, "/v2/target/blobs/uploads/", query, "")
				if got := d.mounted(t); len(got) != 1 || got[0] != [2]string{"target", r.from} {
					t.Errorf("from=%s, query %q: mounted %v, the gate authorized %s", tc.rawFrom, query, got, r.from)
				}
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
			if r.op.isWrite() {
				t.Errorf("from=%q: the gate admitted a near-miss source as %+v", from, r)
			}
			if _, _, ok := d.serve(http.MethodPost, "/v2/target/blobs/uploads/", q, ""); !ok {
				continue
			}
			if got := d.mounted(t); len(got) != 0 {
				t.Errorf("from=%q (gate op %s) linked: %v", from, r.op, got)
			}
		}
	})
}

// FuzzGateAndServerAgree holds the agreement on arbitrary names and mount
// sources, on the write routes. Only the name or the source varies, so the gate
// refuses a request with no source for its name alone.
func FuzzGateAndServerAgree(f *testing.F) {
	f.Fuzz(func(t *testing.T, name, from string, route uint8) {
		if strings.ContainsAny(name+from, "?#") || len(name) > 512 || len(from) > 512 {
			t.Skip("not one path and query, or over the input bounds")
		}
		d := newDifferentialServer(t)
		dg := d.push(t, "a", "layer")
		if from == "" {
			rt := differentialRoutes[int(route)%len(differentialRoutes)]
			admitted := agree(t, d, rt.method, "/v2/"+name+rt.suffix, rt.query)
			_, err := ref.ParseName(name)
			if admitted != (err == nil) {
				t.Errorf("%q: the gate admitted %v, the validator said %v", name, admitted, err)
			}
			if got := d.mounted(t); len(got) != 0 {
				t.Errorf("%q: a request with no source linked %v", name, got)
			}
			return
		}
		path, query := "/v2/"+name+"/blobs/uploads/", "mount="+dg.String()+"&from="+from
		r := classify(http.MethodPost, path, query)
		fwd := query
		if r.op.isWrite() {
			fwd = r.query
		}
		if _, repo, ok := d.serve(http.MethodPost, path, fwd, ""); r.op.isWrite() && (!ok || repo != r.repo) {
			t.Errorf("%q from %q: the gate authorized %q, the server %q", name, from, r.repo, repo)
		}
		// The gate also refuses a valid source for the query around it (a mount
		// that is an upload too), so a link it did not admit is held to the path's
		// name and a source the validator takes, which is the source it would read.
		for _, got := range d.mounted(t) {
			_, err := ref.ParseName(got[1])
			if got[0] != name || err != nil || (r.op.isWrite() && got != [2]string{r.repo, r.from}) {
				t.Errorf("%q from %q linked %v, the gate read %+v", name, from, got, r)
			}
		}
	})
}
