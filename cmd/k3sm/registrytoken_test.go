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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// The credential the operator holds and the token the realm issues for it. Both
// are secrets: neither may appear in any output, error or log line.
const (
	exchangePAT    = "pat-0123456789-operator-credential"
	exchangeIssued = "issued-9876543210-scoped"
)

// TestTokenExchange is the B653 gate. ghcr, Docker Hub and most hosted
// registries refuse a credential presented directly as a bearer: they answer
// 401 with a `WWW-Authenticate: Bearer realm=…,service=…,scope=…` challenge, and
// the client must trade the credential at the realm for a token scoped to the
// repository. K3SM_REGISTRY_TOKEN is therefore resolved as a username/password
// credential, which go-containerregistry's own exchange presents to the realm as
// basic auth; the fake registry accepts only the token its realm issued, for
// the scope the request needs. Registry and realm are served in memory over
// https, the scheme a real hosted registry is reached by.
func TestTokenExchange(t *testing.T) {
	logged := captureAllLogs(t)

	t.Run("a-bearer-challenge-is-answered-with-the-issued-token", func(t *testing.T) {
		for _, tc := range []struct{ name, envUser, wantUser string }{
			{"default-user", "", defaultRegistryUser},
			{"named-user", "octocat", "octocat"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Setenv(registryTokenEnv, exchangePAT)
				t.Setenv(registryUserEnv, tc.envUser)
				realm, mem := tokenRegistry("https://realm.test/token", tc.wantUser)
				if err := pushThrough(t, mem); err != nil {
					t.Fatalf("push through a token-exchange registry: %v", err)
				}
				exchanges := realm.exchanges()
				if len(exchanges) == 0 {
					t.Fatal("the realm was never asked for a token")
				}
				pushScope := false
				for _, e := range exchanges {
					if e.service != "test-registry" {
						t.Errorf("exchange named service %q, want the challenge's test-registry", e.service)
					}
					pushScope = pushScope || strings.Contains(e.scope, "repository:team/app:push")
				}
				if !pushScope {
					t.Errorf("no exchange asked for the push scope; exchanges = %v", exchanges)
				}
				assertNoSecret(t, "", logged)
			})
		}
	})

	t.Run("a-realm-on-a-private-address-is-refused", func(t *testing.T) {
		t.Setenv(registryTokenEnv, exchangePAT)
		t.Setenv(registryUserEnv, "")
		realm, mem := tokenRegistry("https://10.0.0.1/token", defaultRegistryUser)
		err := pushThrough(t, mem)
		if err == nil {
			t.Fatal("push succeeded with a realm on a private address")
		}
		if n := realm.requests(); n != 0 {
			t.Errorf("the credential was sent to a private-address realm %d times", n)
		}
		assertNoSecret(t, err.Error(), logged)
	})

	t.Run("a-basic-challenge-gets-the-same-user-and-token", func(t *testing.T) {
		t.Setenv(registryTokenEnv, exchangePAT)
		t.Setenv(registryUserEnv, "octocat")
		mem := memTransport{"registry.test": &authProbe{inner: newTestRegistry(), require: basicHeader("octocat", exchangePAT)}}
		if err := pushThrough(t, mem); err != nil {
			t.Fatalf("push to a basic-challenge registry: %v", err)
		}
	})

	t.Run("the-realm-refuses-the-credential", func(t *testing.T) {
		t.Setenv(registryTokenEnv, exchangePAT)
		t.Setenv(registryUserEnv, "")
		_, mem := tokenRegistry("https://realm.test/token", "someone-else")
		err := pushThrough(t, mem)
		if !errors.Is(err, errPushAuth) {
			t.Errorf("push with a refused credential = %v, want errPushAuth", err)
		}
		if err != nil {
			assertNoSecret(t, err.Error(), logged)
		}
	})
}

// pushThrough pushes a built fixture to registry.test with the credential
// registryAuth resolves, over the in-memory transport, and classifies a failure
// the way pushImage does.
func pushThrough(t *testing.T, mem memTransport) error {
	t.Helper()
	ref, err := name.ParseReference("registry.test/team/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	img, err := layoutImage(fixtureLayout(t, "example.com/app:v1", "exchange-"+t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := registryAuth(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img, remote.WithContext(t.Context()), remote.WithAuth(auth), remote.WithTransport(mem)); err != nil {
		return pushError(ref, err)
	}
	return nil
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// captureAllLogs routes every logger the push could reach (slog, the standard
// log package and go-containerregistry's own) into one buffer for the duration
// of the test, so the gate can assert that no credential is ever written.
func captureAllLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prevSlog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	prevLog := log.Writer()
	log.SetOutput(buf)
	logs.Warn.SetOutput(buf)
	logs.Progress.SetOutput(buf)
	logs.Debug.SetOutput(buf)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
		logs.Warn.SetOutput(io.Discard)
		logs.Progress.SetOutput(io.Discard)
		logs.Debug.SetOutput(io.Discard)
	})
	return buf
}

func assertNoSecret(t *testing.T, text string, logged *lockedBuffer) {
	t.Helper()
	for _, secret := range []string{exchangePAT, exchangeIssued} {
		if strings.Contains(text, secret) {
			t.Errorf("an error contains a secret: %q", text)
		}
		if strings.Contains(logged.String(), secret) {
			t.Error("a log line contains a secret")
		}
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type exchange struct{ service, scope string }

// tokenRealm is the fake token endpoint, modelled on ghcr: it accepts the
// credential only as basic auth with the expected user, and binds each issued
// token to the scope it was issued for, so the registry can refuse a pull token
// on a push.
type tokenRealm struct {
	user string

	mu     sync.Mutex
	hits   int
	seen   []exchange
	scopes map[string]bool
}

func (r *tokenRealm) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.hits++
	r.mu.Unlock()
	if req.Header.Get("Authorization") != basicHeader(r.user, exchangePAT) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	e := exchange{service: req.URL.Query().Get("service"), scope: strings.Join(req.URL.Query()["scope"], " ")}
	r.mu.Lock()
	r.seen = append(r.seen, e)
	for _, s := range req.URL.Query()["scope"] {
		r.scopes[s] = true
	}
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	// access_token rather than token: both spellings are in the wild.
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": exchangeIssued}) // a failed write fails the client's parse, which the test sees
}

func (r *tokenRealm) exchanges() []exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]exchange(nil), r.seen...)
}

func (r *tokenRealm) requests() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

func (r *tokenRealm) grants(scope string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return scope == "" || r.scopes[scope]
}

// tokenRegistry serves registry.test, which accepts only the realm's issued
// token for the scope a request needs, and the realm at realmURL beside it.
func tokenRegistry(realmURL, realmUser string) (*tokenRealm, memTransport) {
	realm := &tokenRealm{user: realmUser, scopes: map[string]bool{}}
	inner := newTestRegistry()
	reg := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		scope := requiredScope(req)
		if req.Header.Get("Authorization") != "Bearer "+exchangeIssued || !realm.grants(scope) {
			chal := `Bearer realm="` + realmURL + `",service="test-registry"`
			if scope != "" {
				chal += `,scope="` + scope + `"`
			}
			w.Header().Set("WWW-Authenticate", chal)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, req)
	})
	realmHost := strings.TrimPrefix(strings.TrimSuffix(realmURL, "/token"), "https://")
	return realm, memTransport{"registry.test": reg, realmHost: realm}
}

func newTestRegistry() http.Handler {
	return registry.New(registry.Logger(log.New(io.Discard, "", 0)))
}

// requiredScope is the scope a real registry demands for req: none for the
// version probe, pull for reads, push,pull for writes.
func requiredScope(req *http.Request) string {
	rest, ok := strings.CutPrefix(req.URL.Path, "/v2/")
	if !ok {
		return ""
	}
	repo := ""
	for _, kind := range []string{"/blobs/", "/manifests/", "/tags/"} {
		if i := strings.LastIndex(rest, kind); i > 0 {
			repo = rest[:i]
			break
		}
	}
	if repo == "" {
		return ""
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		return "repository:" + repo + ":pull"
	}
	return "repository:" + repo + ":push,pull"
}

// memTransport answers each https request with the handler for its host, so no
// socket is opened.
type memTransport map[string]http.Handler

func (m memTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h, ok := m[req.URL.Host]
	if !ok {
		return nil, fmt.Errorf("no in-memory host %s", req.URL.Host)
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("in-memory host %s reached over %s, want https", req.URL.Host, req.URL.Scheme)
	}
	in := req.Clone(req.Context())
	if in.Body == nil {
		in.Body = http.NoBody
	}
	in.RequestURI = req.URL.RequestURI()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, in)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}
