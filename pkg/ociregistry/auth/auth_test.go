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

package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

const (
	pushSecret = "push-secret-0123456789abcdefghijklmnopqrstu"
	gateSecret = "gate-secret-0123456789abcdefghijklmnopqrstu"
)

func principals() []Principal {
	return []Principal{
		{User: UserPush, SecretSHA256: HashSecret(pushSecret)},
		{User: UserGate, SecretSHA256: HashSecret(gateSecret)},
	}
}

func newAccess(t testing.TB, opts ...func(*Config)) *Access {
	t.Helper()
	cfg := Config{Principals: principals()}
	for _, o := range opts {
		o(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func basic(user, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
}

// caller is a principal a request is made as; auth is its Authorization
// header ("" sends none).
type caller struct {
	name string
	auth string
}

var (
	anonymous = caller{"anonymous", ""}
	asPush    = caller{"k3sm", basic(UserPush, pushSecret)}
	asGate    = caller{"k3sm-gate", basic(UserGate, gateSecret)}
	wrong     = caller{"k3sm with a wrong secret", basic(UserPush, gateSecret)}
	unknown   = caller{"an unknown user", basic("admin", pushSecret)}
)

// registry is a server over a fresh store with the Access in front, seeded
// with repository app (an image tagged v1 and an open upload session) and
// repository src (a blob to mount).
type registry struct {
	srv      *api.Server
	manifest digest.Digest
	config   digest.Digest
	mountee  digest.Digest
	upload   string
}

func (g *registry) do(c caller, method, path string, body []byte, hdr ...string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	if c.auth != "" {
		r.Header.Set("Authorization", c.auth)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	g.srv.ServeHTTP(w, r)
	return w
}

func (g *registry) must(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("seed: status %d, want %d; body %s", w.Code, status, w.Body.String())
	}
}

func (g *registry) blob(t *testing.T, repo string, b []byte) digest.Digest {
	t.Helper()
	d := digest.FromBytes(b)
	g.must(t, g.do(asPush, http.MethodPost, "/v2/"+repo+"/blobs/uploads/?digest="+d.String(), b, "Content-Type", "application/octet-stream"), http.StatusCreated)
	return d
}

func newRegistry(t *testing.T) *registry {
	t.Helper()
	st, err := store.OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Config{Store: st, GCGrace: time.Hour, Authorize: newAccess(t).Authorize, FreeSpace: func() (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	g := &registry{srv: srv}
	cfg := []byte(`{"architecture":"arm64","os":"linux"}`)
	layer := []byte("layer")
	g.config = g.blob(t, "app", cfg)
	ld := g.blob(t, "app", layer)
	m := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Config:    ispec.Descriptor{MediaType: ispec.MediaTypeImageConfig, Digest: g.config, Size: int64(len(cfg))},
		Layers:    []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayerGzip, Digest: ld, Size: int64(len(layer))}},
	}
	m.SchemaVersion = 2
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	g.manifest = digest.FromBytes(body)
	g.must(t, g.do(asPush, http.MethodPut, "/v2/app/manifests/v1", body, "Content-Type", ispec.MediaTypeImageManifest), http.StatusCreated)
	g.mountee = g.blob(t, "src", []byte("mount me"))
	w := g.do(asPush, http.MethodPost, "/v2/app/blobs/uploads/", nil)
	g.must(t, w, http.StatusAccepted)
	g.upload = w.Header().Get("Location")
	return g
}

// endpoint is one request against a seeded registry, the verb it needs and
// the answer an allowed caller gets.
type endpoint struct {
	name string
	verb api.Verb
	ok   int
	send func(g *registry, c caller) *httptest.ResponseRecorder
}

func endpoints() []endpoint {
	octet := []string{"Content-Type", "application/octet-stream"}
	return []endpoint{
		{"GET /v2/", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodGet, "/v2/", nil)
		}},
		{"GET catalog", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodGet, "/v2/_catalog", nil)
		}},
		{"GET tags", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodGet, "/v2/app/tags/list", nil)
		}},
		{"GET manifest by tag", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodGet, "/v2/app/manifests/v1", nil)
		}},
		{"HEAD manifest by digest", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodHead, "/v2/app/manifests/"+g.manifest.String(), nil)
		}},
		{"GET blob", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodGet, "/v2/app/blobs/"+g.config.String(), nil)
		}},
		{"HEAD blob", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodHead, "/v2/app/blobs/"+g.config.String(), nil)
		}},
		{"GET referrers", api.VerbRead, 200, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodGet, "/v2/app/referrers/"+g.manifest.String(), nil)
		}},
		{"GET upload status", api.VerbRead, 204, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodGet, g.upload, nil)
		}},
		{"POST upload session", api.VerbWrite, 202, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodPost, "/v2/app/blobs/uploads/", nil)
		}},
		{"POST monolithic upload", api.VerbWrite, 201, func(g *registry, c caller) *httptest.ResponseRecorder {
			b := []byte("monolithic")
			return g.do(c, http.MethodPost, "/v2/app/blobs/uploads/?digest="+digest.FromBytes(b).String(), b, octet...)
		}},
		{"POST mount", api.VerbWrite, 201, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodPost, "/v2/app/blobs/uploads/?mount="+g.mountee.String()+"&from=src", nil)
		}},
		{"PATCH upload chunk", api.VerbWrite, 202, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodPatch, g.upload, []byte("chunk"), octet...)
		}},
		{"PUT upload commit", api.VerbWrite, 201, func(g *registry, c caller) *httptest.ResponseRecorder {
			b := []byte("committed")
			return g.do(c, http.MethodPut, g.upload+"?digest="+digest.FromBytes(b).String(), b, octet...)
		}},
		{"PUT manifest", api.VerbWrite, 201, func(g *registry, c caller) *httptest.ResponseRecorder {
			w := g.do(asPush, http.MethodGet, "/v2/app/manifests/v1", nil)
			return g.do(c, http.MethodPut, "/v2/app/manifests/v2", w.Body.Bytes(), "Content-Type", ispec.MediaTypeImageManifest)
		}},
		{"DELETE tag", api.VerbDelete, 202, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodDelete, "/v2/app/manifests/v1", nil)
		}},
		{"DELETE manifest by digest", api.VerbDelete, 202, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodDelete, "/v2/app/manifests/"+g.manifest.String(), nil)
		}},
		{"DELETE upload (cancel)", api.VerbDelete, 204, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodDelete, g.upload, nil)
		}},
		// Blobs are removed by garbage collection only: an allowed caller gets
		// 405, and a caller without delete is refused before that.
		{"DELETE blob", api.VerbDelete, 405, func(g *registry, c caller) *httptest.ResponseRecorder {
			return g.do(c, http.MethodDelete, "/v2/app/blobs/"+g.config.String(), nil)
		}},
	}
}

// errorCode returns the single error code of a JSON error body, or "".
func errorCode(w *httptest.ResponseRecorder) string {
	var eb struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if json.Unmarshal(w.Body.Bytes(), &eb) != nil || len(eb.Errors) != 1 {
		return ""
	}
	return eb.Errors[0].Code
}

// TestAccessControl drives every endpoint of the server as every principal,
// plus a wrong secret and an unknown user, and checks the matrix: anonymous
// reads, k3sm everything, k3sm-gate everything but delete; a missing or bad
// credential where one is needed is 401 with a Basic challenge, and a
// principal without the permission is 403 DENIED.
func TestAccessControl(t *testing.T) {
	for _, ep := range endpoints() {
		for _, c := range []caller{anonymous, asPush, asGate, wrong, unknown} {
			var wantStatus int
			var wantCode string
			switch {
			case c == wrong || c == unknown:
				wantStatus, wantCode = 401, "UNAUTHORIZED"
			case permissions[userOf(c)][ep.verb]:
				wantStatus = ep.ok
			case c == anonymous:
				wantStatus, wantCode = 401, "UNAUTHORIZED"
			default:
				wantStatus, wantCode = 403, "DENIED"
			}
			t.Run(ep.name+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				g := newRegistry(t)
				w := ep.send(g, c)
				if w.Code != wantStatus {
					t.Fatalf("%s as %s: status %d, want %d; body %s", ep.name, c.name, w.Code, wantStatus, w.Body.String())
				}
				// A HEAD answer has no body to carry the code.
				if wantCode != "" && !strings.HasPrefix(ep.name, "HEAD") && errorCode(w) != wantCode {
					t.Errorf("%s as %s: body %s, want code %s", ep.name, c.name, w.Body.String(), wantCode)
				}
				challenge := w.Header().Get("WWW-Authenticate")
				if (wantStatus == 401) != (challenge == `Basic realm="k3sm registry"`) {
					t.Errorf("%s as %s: WWW-Authenticate %q with status %d", ep.name, c.name, challenge, w.Code)
				}
			})
		}
	}
	// The matrix itself, pinned so a change to it is a change to this test.
	t.Run("the permission matrix", func(t *testing.T) {
		want := map[string][3]bool{
			"":       {true, false, false},
			UserPush: {true, true, true},
			UserGate: {true, true, false},
		}
		for user, row := range want {
			for i, v := range []api.Verb{api.VerbRead, api.VerbWrite, api.VerbDelete} {
				if permissions[user][v] != row[i] {
					t.Errorf("%q may %s = %v, want %v", user, v, permissions[user][v], row[i])
				}
			}
		}
		if len(permissions) != len(want) {
			t.Errorf("the matrix has %d principals, want %d", len(permissions), len(want))
		}
	})
	t.Run("the catalog lists every repository to a reader", func(t *testing.T) {
		g := newRegistry(t)
		for _, c := range []caller{anonymous, asPush, asGate} {
			w := g.do(c, http.MethodGet, "/v2/_catalog", nil)
			if !strings.Contains(w.Body.String(), `"app"`) || !strings.Contains(w.Body.String(), `"src"`) {
				t.Errorf("catalog as %s = %s, want app and src", c.name, w.Body.String())
			}
		}
	})
	t.Run("a mount needs read on its source", func(t *testing.T) {
		var mu sync.Mutex
		var asked []string
		a := newAccess(t)
		st, err := store.OpenWorkDir(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		srv, err := api.New(api.Config{Store: st, GCGrace: time.Hour, FreeSpace: func() (uint64, error) { return 1 << 40, nil },
			Authorize: func(r *http.Request, v api.Verb, n ref.Name) error {
				mu.Lock()
				asked = append(asked, v.String()+" "+n.String())
				mu.Unlock()
				return a.Authorize(r, v, n)
			}})
		if err != nil {
			t.Fatal(err)
		}
		g := &registry{srv: srv}
		d := g.blob(t, "src", []byte("x"))
		mu.Lock()
		asked = nil
		mu.Unlock()
		g.must(t, g.do(asGate, http.MethodPost, "/v2/app/blobs/uploads/?mount="+d.String()+"&from=src", nil), http.StatusCreated)
		mu.Lock()
		defer mu.Unlock()
		if strings.Join(asked, ",") != "write app,read src" {
			t.Errorf("a mount asked for %v, want [write app, read src]", asked)
		}
	})
}

// userOf is the user a caller authenticates as ("" for anonymous).
func userOf(c caller) string {
	switch c {
	case asPush:
		return UserPush
	case asGate:
		return UserGate
	}
	return ""
}

// TestAuthenticate checks the Authorization header limits and that anything
// not a well-formed Basic credential of a known principal fails closed.
func TestAuthenticate(t *testing.T) {
	long := strings.Repeat("a", MaxSecretBytes+1)
	cases := []struct {
		name string
		hdr  []string
		user string
		ok   bool
	}{
		{"no header", nil, "", true},
		{"k3sm", []string{basic(UserPush, pushSecret)}, UserPush, true},
		{"k3sm-gate", []string{basic(UserGate, gateSecret)}, UserGate, true},
		{"the scheme is case-insensitive", []string{"basic " + strings.TrimPrefix(basic(UserPush, pushSecret), "Basic ")}, UserPush, true},
		{"the gate's secret as k3sm", []string{basic(UserPush, gateSecret)}, "", false},
		{"an unknown user with a real secret", []string{basic("root", pushSecret)}, "", false},
		{"an empty secret", []string{basic(UserPush, "")}, "", false},
		{"an empty user", []string{basic("", pushSecret)}, "", false},
		{"no colon", []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(UserPush+pushSecret))}, "", false},
		{"not base64", []string{"Basic !!!"}, "", false},
		{"a bearer token", []string{"Bearer " + pushSecret}, "", false},
		{"an empty header", []string{""}, "", false},
		{"two headers", []string{basic(UserPush, pushSecret), basic(UserPush, pushSecret)}, "", false},
		{"a secret one past the limit", []string{basic(UserPush, long)}, "", false},
		{"a user one past the limit", []string{basic(strings.Repeat("u", MaxUserBytes+1), pushSecret)}, "", false},
		{"a header past the limit", []string{basic(UserPush, pushSecret) + strings.Repeat("=", MaxAuthorizationBytes)}, "", false},
		{"a hash instead of the secret", []string{basic(UserPush, HashSecret(pushSecret))}, "", false},
		{"the secret with a trailing newline", []string{basic(UserPush, pushSecret+"\n")}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAccess(t)
			r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
			if tc.hdr != nil {
				r.Header["Authorization"] = tc.hdr
			}
			user, err := a.authenticate(r)
			if tc.ok != (err == nil) || user != tc.user {
				t.Fatalf("authenticate = %q, %v; want %q, ok=%v", user, err, tc.user, tc.ok)
			}
			if err != nil && !errors.Is(err, errBadCredential) {
				t.Errorf("err = %v, want errBadCredential", err)
			}
			// The refusal is a 401 for a read, too: a bad credential is never
			// downgraded to anonymous.
			if err != nil {
				if got := a.Authorize(r, api.VerbRead, ref.Name{}); !errors.Is(got, api.ErrUnauthenticated) {
					t.Errorf("Authorize(read) = %v, want ErrUnauthenticated", got)
				}
			}
		})
	}
}

// TestFailureBucket checks the per-source token bucket: failures spend it, an
// empty bucket refuses every credentialed request before comparing (429), a
// request without credentials never draws on it, it refills with time, sources
// are separate, and the tracked set is bounded.
func TestFailureBucket(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	from := func(src string, c caller) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		r.RemoteAddr = src + ":40000"
		if c.auth != "" {
			r.Header.Set("Authorization", c.auth)
		}
		return r
	}
	a := newAccess(t, func(c *Config) { c.Burst, c.Refill, c.Now = 3, time.Second, clock })

	for i := range 3 {
		if err := a.Authorize(from("10.0.0.1", wrong), api.VerbRead, ref.Name{}); !errors.Is(err, api.ErrUnauthenticated) {
			t.Fatalf("failure %d: %v, want ErrUnauthenticated", i+1, err)
		}
	}
	if err := a.Authorize(from("10.0.0.1", wrong), api.VerbRead, ref.Name{}); !errors.Is(err, api.ErrRateLimited) {
		t.Fatalf("over the burst: %v, want ErrRateLimited", err)
	}
	// An empty bucket refuses a valid credential too: nothing is compared, so
	// a guess cannot be told from a hit.
	if err := a.Authorize(from("10.0.0.1", asPush), api.VerbWrite, ref.Name{}); !errors.Is(err, api.ErrRateLimited) {
		t.Fatalf("a valid credential from an empty bucket: %v, want ErrRateLimited", err)
	}
	// A request without credentials does not draw on the bucket.
	if err := a.Authorize(from("10.0.0.1", anonymous), api.VerbRead, ref.Name{}); err != nil {
		t.Fatalf("an anonymous read from an empty bucket: %v", err)
	}
	if err := a.Authorize(from("10.0.0.1", anonymous), api.VerbWrite, ref.Name{}); !errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("an anonymous write from an empty bucket: %v, want ErrUnauthenticated", err)
	}
	// Another source has its own bucket.
	if err := a.Authorize(from("10.0.0.2", asPush), api.VerbWrite, ref.Name{}); err != nil {
		t.Fatalf("another source: %v", err)
	}
	// One token back per Refill.
	advance(time.Second)
	if err := a.Authorize(from("10.0.0.1", asPush), api.VerbWrite, ref.Name{}); err != nil {
		t.Fatalf("after a refill: %v", err)
	}
	if err := a.Authorize(from("10.0.0.1", wrong), api.VerbRead, ref.Name{}); !errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("one failure after a refill: %v, want ErrUnauthenticated", err)
	}
	if err := a.Authorize(from("10.0.0.1", wrong), api.VerbRead, ref.Name{}); !errors.Is(err, api.ErrRateLimited) {
		t.Fatalf("the refilled token spent: %v, want ErrRateLimited", err)
	}
	// Successes are free.
	advance(10 * time.Second)
	for i := range 20 {
		if err := a.Authorize(from("10.0.0.1", asGate), api.VerbWrite, ref.Name{}); err != nil {
			t.Fatalf("success %d: %v", i+1, err)
		}
	}

	t.Run("the server answers 429", func(t *testing.T) {
		st, err := store.OpenWorkDir(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		b := newAccess(t, func(c *Config) { c.Burst = 1 })
		srv, err := api.New(api.Config{Store: st, GCGrace: time.Hour, Authorize: b.Authorize, FreeSpace: func() (uint64, error) { return 1 << 40, nil }})
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range []int{401, 429} {
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, from("10.0.0.9", wrong))
			if w.Code != want {
				t.Fatalf("request %d: status %d, want %d", i+1, w.Code, want)
			}
			if want == 429 && errorCode(w) != "TOOMANYREQUESTS" {
				t.Errorf("429 body %s", w.Body.String())
			}
		}
	})

	t.Run("the tracked sources are bounded", func(t *testing.T) {
		c := newAccess(t, func(c *Config) { c.Burst, c.Refill, c.Now = 1, time.Second, clock })
		for i := range MaxSources {
			_ = c.Authorize(from(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), wrong), api.VerbRead, ref.Name{})
		}
		if len(c.sources) != MaxSources {
			t.Fatalf("tracked %d sources, want %d", len(c.sources), MaxSources)
		}
		// Every bucket is empty, so a new failing source finds no room and is
		// refused rather than tracked.
		if err := c.Authorize(from("192.0.2.1", wrong), api.VerbRead, ref.Name{}); !errors.Is(err, api.ErrRateLimited) {
			t.Fatalf("a new source with the table full: %v, want ErrRateLimited", err)
		}
		if len(c.sources) != MaxSources {
			t.Fatalf("tracked %d sources, want %d", len(c.sources), MaxSources)
		}
		// Once they refill they are forgotten and the new source fits.
		advance(time.Second)
		if err := c.Authorize(from("192.0.2.1", wrong), api.VerbRead, ref.Name{}); !errors.Is(err, api.ErrUnauthenticated) {
			t.Fatalf("a new source after the refill: %v, want ErrUnauthenticated", err)
		}
		if len(c.sources) != 1 {
			t.Errorf("tracked %d sources after the refill, want 1", len(c.sources))
		}
	})
}

// TestNewRefuses checks that New takes exactly the two principals with
// well-formed hashes.
func TestNewRefuses(t *testing.T) {
	good := HashSecret(pushSecret)
	cases := []struct {
		name string
		ps   []Principal
	}{
		{"none", nil},
		{"only k3sm", []Principal{{UserPush, good}}},
		{"only k3sm-gate", []Principal{{UserGate, good}}},
		{"a duplicate", []Principal{{UserPush, good}, {UserGate, good}, {UserPush, good}}},
		{"an unknown principal", []Principal{{UserPush, good}, {UserGate, good}, {"admin", good}}},
		{"the anonymous principal", []Principal{{UserPush, good}, {UserGate, good}, {"", good}}},
		{"an uppercase hash", []Principal{{UserPush, strings.ToUpper(good)}, {UserGate, good}}},
		{"a short hash", []Principal{{UserPush, good[:62]}, {UserGate, good}}},
		{"a non-hex hash", []Principal{{UserPush, "zz" + good[2:]}, {UserGate, good}}},
		{"a zero hash", []Principal{{UserPush, strings.Repeat("0", 64)}, {UserGate, good}}},
		{"a plaintext secret", []Principal{{UserPush, pushSecret}, {UserGate, good}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Config{Principals: tc.ps}); err == nil {
				t.Fatal("New accepted it")
			}
		})
	}
	if _, err := New(Config{Principals: principals()}); err != nil {
		t.Fatalf("New refused the two principals: %v", err)
	}
	if got := HashSecret("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("HashSecret(abc) = %s", got)
	}
}

// FuzzAuthorization feeds arbitrary Authorization values through verify, the
// part of authenticate past the failure bucket: it never panics, and only the
// two real credentials verify.
func FuzzAuthorization(f *testing.F) {
	for _, s := range []string{
		"", "Basic", "Basic ", "basic Og==", basic(UserPush, pushSecret), basic(UserGate, gateSecret),
		basic(UserPush, gateSecret), basic("admin", "x"), "Bearer x", "Basic " + strings.Repeat("A", 2000),
	} {
		f.Add(s)
	}
	a := newAccess(f)
	f.Fuzz(func(t *testing.T, v string) {
		user, ok := a.verify([]string{v})
		if !ok {
			return
		}
		r := http.Request{Header: http.Header{"Authorization": {v}}}
		u, s, _ := r.BasicAuth()
		if len(v) > MaxAuthorizationBytes || u != user ||
			!(u == UserPush && s == pushSecret || u == UserGate && s == gateSecret) {
			t.Fatalf("verify(%q) accepted %q", v, user)
		}
	})
}

// TestFailureBucketPerConnection checks that the failure bucket is keyed on
// the connection, not the host: every native pod and the push gate reach the
// registry from loopback, so a client sending wrong secrets on its own
// connections must not make another connection's valid credential get 429,
// even with every tracked slot held by an empty bucket.
func TestFailureBucketPerConnection(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	conn := func(port int, c caller) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/v2/x/manifests/latest", nil)
		r.RemoteAddr = fmt.Sprintf("127.0.0.1:%d", port)
		if c.auth != "" {
			r.Header.Set("Authorization", c.auth)
		}
		return r
	}

	t.Run("an exhausted connection leaves the others alone", func(t *testing.T) {
		a := newAccess(t, func(c *Config) { c.Burst, c.Refill, c.Now = 2, time.Hour, clock })
		for range 5 {
			_ = a.Authorize(conn(50001, wrong), api.VerbWrite, ref.Name{})
		}
		if err := a.Authorize(conn(50001, asPush), api.VerbWrite, ref.Name{}); !errors.Is(err, api.ErrRateLimited) {
			t.Fatalf("the exhausted connection: %v, want ErrRateLimited", err)
		}
		for i, c := range []caller{asPush, asGate} {
			if err := a.Authorize(conn(50002+i, c), api.VerbWrite, ref.Name{}); err != nil {
				t.Errorf("%s on another loopback connection: %v", c.name, err)
			}
		}
	})

	t.Run("a full table does not refuse a good credential", func(t *testing.T) {
		a := newAccess(t, func(c *Config) { c.Burst, c.Refill, c.Now = 1, time.Hour, clock })
		for i := range MaxSources {
			_ = a.Authorize(conn(10000+i, wrong), api.VerbWrite, ref.Name{})
		}
		if len(a.sources) != MaxSources {
			t.Fatalf("tracked %d sources, want %d", len(a.sources), MaxSources)
		}
		for i, c := range []caller{asPush, asGate} {
			if err := a.Authorize(conn(60000+i, c), api.VerbWrite, ref.Name{}); err != nil {
				t.Errorf("%s on a new connection with the table full: %v", c.name, err)
			}
		}
		// A new failing connection finds no slot: it is refused, and the
		// table stays bounded.
		if err := a.Authorize(conn(60010, wrong), api.VerbWrite, ref.Name{}); !errors.Is(err, api.ErrRateLimited) {
			t.Fatalf("a new failing connection with the table full: %v, want ErrRateLimited", err)
		}
		if len(a.sources) != MaxSources {
			t.Errorf("tracked %d sources, want %d", len(a.sources), MaxSources)
		}
	})
}
