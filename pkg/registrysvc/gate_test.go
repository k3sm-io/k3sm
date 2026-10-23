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
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// --- fixture ---------------------------------------------------------------

// zotRequest is what the fake registry saw.
type zotRequest struct {
	method, uri, auth, cookie, rng string
	body                           string
}

// fakeZot stands in for the loopback registry and records every request.
type fakeZot struct {
	mu   sync.Mutex
	seen []zotRequest
	h    http.Handler
}

// fakeZotHost is the upstream address the gate under test is pointed at. It is
// never dialled: the gate's Transport is the fake's RoundTrip.
const fakeZotHost = "zot.test:5000"

// RoundTrip serves a request on the fake registry in-process, without a socket.
func (z *fakeZot) RoundTrip(req *http.Request) (*http.Response, error) {
	in := req.Clone(req.Context())
	in.RequestURI = req.URL.RequestURI()
	if in.Body == nil {
		in.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	z.h.ServeHTTP(rec, in)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// memListener is an in-memory net.Listener: a connection is a net.Pipe, so the
// gate is served by a real http.Server with no socket.
type memListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "gate.test" }

func (l *memListener) Addr() net.Addr { return memAddr{} }

// dial returns the client end of a new in-memory connection.
func (l *memListener) dial() (net.Conn, error) {
	c, s := net.Pipe()
	select {
	case l.conns <- s:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// serveMem serves h on a memListener until the test ends.
func serveMem(t *testing.T, h http.Handler) *memListener {
	t.Helper()
	l := newMemListener()
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close() })
	return l
}

func newFakeZot(t *testing.T) *fakeZot {
	t.Helper()
	z := &fakeZot{}
	z.h = (http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		z.mu.Lock()
		z.seen = append(z.seen, zotRequest{
			method: r.Method, uri: r.RequestURI, auth: r.Header.Get("Authorization"),
			cookie: r.Header.Get("Cookie"), rng: r.Header.Get("Range"), body: string(b),
		})
		z.mu.Unlock()
		w.Header().Set("Set-Cookie", "session=zot")
		switch r.Method {
		case "POST", "PATCH":
			w.Header().Set("Location", "http://"+fakeZotHost+"/v2/x/blobs/uploads/abc")
			w.WriteHeader(http.StatusAccepted)
		case "PUT":
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "content")
		}
	}))
	return z
}

func (z *fakeZot) requests() []zotRequest {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]zotRequest(nil), z.seen...)
}

// fakeTokens is a TokenReviewer over a table of tokens.
type fakeTokens struct {
	mu        sync.Mutex
	calls     int
	err       error
	statuses  map[string]authnv1.TokenReviewStatus
	audiences [][]string
}

func (f *fakeTokens) Create(_ context.Context, tr *authnv1.TokenReview, _ metav1.CreateOptions) (*authnv1.TokenReview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.audiences = append(f.audiences, tr.Spec.Audiences)
	if f.err != nil {
		return nil, f.err
	}
	return &authnv1.TokenReview{Status: f.statuses[tr.Spec.Token]}, nil
}

func (f *fakeTokens) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

// fakeAccess is an AccessReviewer whose answer is a function of the request.
type fakeAccess struct {
	mu    sync.Mutex
	calls int
	err   error
	allow func(*authzv1.SubjectAccessReview) bool
	seen  []*authzv1.SubjectAccessReview
}

func (f *fakeAccess) Create(_ context.Context, sar *authzv1.SubjectAccessReview, _ metav1.CreateOptions) (*authzv1.SubjectAccessReview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.seen = append(f.seen, sar.DeepCopy())
	if f.err != nil {
		return nil, f.err
	}
	out := sar.DeepCopy()
	out.Status.Allowed = f.allow(sar)
	return out, nil
}

func (f *fakeAccess) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

// fakeNamespaces is a NamespaceLabels over a table of label sets.
type fakeNamespaces struct {
	mu     sync.Mutex
	calls  int
	err    error
	labels map[string]map[string]string
}

func (f *fakeNamespaces) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.Namespace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	l, ok := f.labels[name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, name)
	}
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l}}, nil
}

// fakeClock is the caches' clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// gateCred is the gate's registry credential in every test.
var gateCred = Credential{Address: "127.0.0.1:6450", Username: gateUser, Password: "gate-secret"}

// wantGateAuth is the Authorization header zot must see on a forwarded write.
var wantGateAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(gateUser+":gate-secret"))

// The default world: namespace team opts in with prefix team, its builder
// ServiceAccount is bound to push, and tokTeam is that ServiceAccount's token.
type gateFixture struct {
	zot        *fakeZot
	tokens     *fakeTokens
	access     *fakeAccess
	namespaces *fakeNamespaces
	clock      *fakeClock
	gate       *gate
	front      *memListener
}

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var testEpoch = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// mkToken builds a JWT-shaped token whose exp claim is exp. Its signature is
// meaningless: the fake TokenReviewer is what decides validity.
func mkToken(name string, exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString
	payload, _ := json.Marshal(map[string]any{"sub": name, "exp": exp.Unix()})
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(payload) + "." + enc([]byte("sig-"+name))
}

var (
	tokTeam    = mkToken("team-builder", testEpoch.Add(time.Hour))
	tokOther   = mkToken("other-builder", testEpoch.Add(time.Hour))
	tokWrongAu = mkToken("wrong-audience", testEpoch.Add(time.Hour))
	tokUnauth  = mkToken("unauthenticated", testEpoch.Add(time.Hour))
	tokUser    = mkToken("a-user", testEpoch.Add(time.Hour))
	tokShort   = mkToken("short-lived", testEpoch.Add(3*time.Second))
)

func saStatus(ns, sa string) authnv1.TokenReviewStatus {
	return authnv1.TokenReviewStatus{
		Authenticated: true,
		Audiences:     []string{RegistryAudience},
		User: authnv1.UserInfo{
			Username: "system:serviceaccount:" + ns + ":" + sa,
			UID:      "uid-" + sa,
			Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"},
			Extra:    map[string]authnv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"builder-0"}},
		},
	}
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	f := &gateFixture{
		zot: newFakeZot(t),
		tokens: &fakeTokens{statuses: map[string]authnv1.TokenReviewStatus{
			tokTeam:    saStatus("team", "builder"),
			tokShort:   saStatus("team", "builder"),
			tokOther:   saStatus("other", "builder"),
			tokWrongAu: {Authenticated: true, Audiences: []string{"https://kubernetes.default.svc"}, User: saStatus("team", "builder").User},
			tokUnauth:  {Authenticated: false, Error: "token has expired"},
			tokUser:    {Authenticated: true, Audiences: []string{RegistryAudience}, User: authnv1.UserInfo{Username: "alice"}},
		}},
		access: &fakeAccess{allow: func(sar *authzv1.SubjectAccessReview) bool {
			return sar.Spec.User == "system:serviceaccount:team:builder"
		}},
		namespaces: &fakeNamespaces{labels: map[string]map[string]string{
			"team":  {PushLabel: "team"},
			"other": {},
		}},
		clock: &fakeClock{t: testEpoch},
	}
	f.gate = newGate(gateConfig{
		Upstream:   fakeZotHost,
		Transport:  f.zot,
		Auth:       GateAuth{Tokens: f.tokens, Access: f.access, Namespaces: f.namespaces},
		Credential: gateCred,
		Logger:     quietLogger(),
		Now:        f.clock.now,
	})
	f.front = serveMem(t, f.gate)
	return f
}

// basic is a client's Basic Authorization header carrying tok as the password.
func basic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("whoever:"+tok))
}

// rawResponse is what a raw request got back.
type rawResponse struct {
	status int
	header http.Header
	body   string
}

// rawDo writes one request with exactly target on its request line, so path
// tricks reach the gate unnormalized, and reads the response.
func rawDo(t *testing.T, l *memListener, method, target string, headers map[string]string, body string) rawResponse {
	t.Helper()
	c, err := l.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return rawOn(t, c, method, target, headers, body)
}

// rawOn is rawDo over a connection the caller dialled; it closes c.
func rawOn(t *testing.T, c net.Conn, method, target string, headers map[string]string, body string) rawResponse {
	t.Helper()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\n", method, target)
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if body != "" || method == "PUT" || method == "PATCH" || method == "POST" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response to %s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return rawResponse{status: resp.StatusCode, header: resp.Header, body: string(rb)}
}

func (f *gateFixture) do(t *testing.T, method, target, auth, body string, extra map[string]string) rawResponse {
	t.Helper()
	h := map[string]string{}
	for k, v := range extra {
		h[k] = v
	}
	if auth != "" {
		h["Authorization"] = auth
	}
	return rawDo(t, f.front, method, target, h, body)
}

// --- the named gate --------------------------------------------------------

// TestPushAuthorizesServiceAccountTokenUnderNamespacePrefix is the push gate's
// contract, one row per decision. A write reaches the registry only for a
// ServiceAccount token reviewed for the registry audience, in a namespace
// labelled with a prefix the repository sits strictly under, with an RBAC
// grant to push it; it reaches the registry with the gate's credential and
// never the client's. A read reaches the registry anonymously and costs no
// review. Everything else is refused before anything is forwarded.
func TestPushAuthorizesServiceAccountTokenUnderNamespacePrefix(t *testing.T) {
	type tc struct {
		name   string
		method string
		target string
		auth   string
		body   string
		header map[string]string
		setup  func(*gateFixture)
		status int
		// forward is the request zot must see, or "" for none.
		forward string
		// asWrite: the forwarded request carries the gate credential (else none).
		asWrite     bool
		reviews     int // TokenReview calls; -1 skips the check
		sars        int // SubjectAccessReview calls; -1 skips the check
		challenge   bool
		check       func(*testing.T, *gateFixture, rawResponse)
		forwardBody string
	}
	label := func(v string) func(*gateFixture) {
		return func(f *gateFixture) { f.namespaces.labels["team"] = map[string]string{PushLabel: v} }
	}
	rows := []tc{
		// Allowed writes.
		{name: "blob upload start is forwarded with the gate credential", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam),
			status: 202, forward: "POST /v2/team/app/blobs/uploads/", asWrite: true, reviews: 1, sars: 1,
			check: func(t *testing.T, f *gateFixture, r rawResponse) {
				if loc := r.header.Get("Location"); loc != "/v2/x/blobs/uploads/abc" {
					t.Errorf("Location = %q, want the upstream host stripped", loc)
				}
				if r.header.Get("Set-Cookie") != "" {
					t.Error("the registry's session cookie reached the client")
				}
			}},
		{name: "blob chunk PATCH is forwarded with its body", method: "PATCH", target: "/v2/team/app/blobs/uploads/abc-123", auth: basic(tokTeam), body: "layer-bytes",
			status: 202, forward: "PATCH /v2/team/app/blobs/uploads/abc-123", asWrite: true, reviews: 1, sars: 1, forwardBody: "layer-bytes"},
		{name: "blob upload PUT keeps its digest query", method: "PUT", target: "/v2/team/app/blobs/uploads/abc-123?digest=" + digestA, auth: basic(tokTeam),
			status: 201, forward: "PUT /v2/team/app/blobs/uploads/abc-123?digest=sha256%3A" + digestA[7:], asWrite: true, reviews: 1, sars: 1},
		{name: "manifest PUT by tag is forwarded", method: "PUT", target: "/v2/team/app/manifests/V1.0", auth: basic(tokTeam), body: "{}",
			status: 201, forward: "PUT /v2/team/app/manifests/V1.0", asWrite: true, reviews: 1, sars: 1, forwardBody: "{}"},
		{name: "a deeper repository under the prefix is allowed", method: "PUT", target: "/v2/team/tools/app/manifests/" + digestA, auth: basic(tokTeam),
			status: 201, forward: "PUT /v2/team/tools/app/manifests/" + digestA, asWrite: true, reviews: 1, sars: 1},

		// Authentication.
		{name: "no Authorization: 401 and nothing reaches the registry", method: "POST", target: "/v2/team/app/blobs/uploads/",
			status: 401, challenge: true, reviews: 0, sars: 0},
		{name: "a Bearer header is not a Basic login", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: "Bearer " + tokTeam,
			status: 401, challenge: true, reviews: 0, sars: 0},
		{name: "a garbage token is refused without a review", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic("not-a-token"),
			status: 401, challenge: true, reviews: 0, sars: 0},
		{name: "an oversize token is refused without a review", method: "POST", target: "/v2/team/app/blobs/uploads/",
			auth:   basic(strings.Repeat("a", 3000) + "." + strings.Repeat("b", 3000) + "." + strings.Repeat("c", 3000)),
			status: 401, challenge: true, reviews: 0, sars: 0},
		{name: "a token for another audience is refused", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokWrongAu),
			status: 401, challenge: true, reviews: 1, sars: 0},
		{name: "an unauthenticated token is refused", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokUnauth),
			status: 401, challenge: true, reviews: 1, sars: 0},
		{name: "an authenticated user that is not a ServiceAccount is denied", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokUser),
			status: 403, reviews: 1, sars: 0},
		{name: "an apiserver that cannot review is 503", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam),
			setup: func(f *gateFixture) { f.tokens.err = errors.New("connection refused") }, status: 503, reviews: 1, sars: 0},
		{name: "an apiserver that cannot read the namespace is 503", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam),
			setup: func(f *gateFixture) { f.namespaces.err = errors.New("connection refused") }, status: 503, reviews: 1, sars: 0},
		{name: "an apiserver that cannot authorize is 503", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam),
			setup: func(f *gateFixture) { f.access.err = errors.New("connection refused") }, status: 503, reviews: 1, sars: 1},

		// The namespace opt-in.
		{name: "an unlabelled namespace is denied with no access review", method: "POST", target: "/v2/other/app/blobs/uploads/", auth: basic(tokOther),
			status: 403, reviews: 1, sars: 0},
		{name: "a namespace that does not exist is denied", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam),
			setup: func(f *gateFixture) { delete(f.namespaces.labels, "team") }, status: 403, reviews: 1, sars: 0},
		{name: "label value with uppercase is invalid", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam), setup: label("Team"), status: 403, reviews: 1, sars: 0},
		{name: "label value with a slash is invalid", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam), setup: label("team/app"), status: 403, reviews: 1, sars: 0},
		{name: "label value with a leading separator is invalid", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam), setup: label("-team"), status: 403, reviews: 1, sars: 0},
		{name: "an empty label value is invalid", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam), setup: label(""), status: 403, reviews: 1, sars: 0},
		{name: "a wildcard label value is invalid", method: "POST", target: "/v2/team/app/blobs/uploads/", auth: basic(tokTeam), setup: label("*"), status: 403, reviews: 1, sars: 0},

		// The prefix.
		{name: "the prefix itself is not a repository under it", method: "POST", target: "/v2/team/blobs/uploads/", auth: basic(tokTeam), status: 403, reviews: 1, sars: 0},
		{name: "p-x/app is not under p", method: "POST", target: "/v2/p-x/app/blobs/uploads/", auth: basic(tokTeam), setup: label("p"), status: 403, reviews: 1, sars: 0},
		{name: "p.evil/app is not under p", method: "POST", target: "/v2/p.evil/app/blobs/uploads/", auth: basic(tokTeam), setup: label("p"), status: 403, reviews: 1, sars: 0},
		{name: "pX/app is not a valid repository", method: "POST", target: "/v2/pX/app/blobs/uploads/", auth: basic(tokTeam), setup: label("p"), status: 400, reviews: 0, sars: 0},
		{name: "another namespace's prefix is denied", method: "PUT", target: "/v2/other/app/manifests/v1", auth: basic(tokTeam), status: 403, reviews: 1, sars: 0},
		{name: "teamx is not under team", method: "PUT", target: "/v2/teamx/app/manifests/v1", auth: basic(tokTeam), status: 403, reviews: 1, sars: 0},

		// RBAC.
		{name: "an access review that denies is 403", method: "PUT", target: "/v2/team/app/manifests/v1", auth: basic(tokTeam),
			setup: func(f *gateFixture) { f.access.allow = func(*authzv1.SubjectAccessReview) bool { return false } }, status: 403, reviews: 1, sars: 1},

		// Path tricks: never forwarded, never reviewed.
		{name: "a dot-dot segment", method: "POST", target: "/v2/team/../other/app/blobs/uploads/", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "an escaped dot-dot", method: "POST", target: "/v2/team/%2e%2e/other/blobs/uploads/", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "an escaped slash", method: "PUT", target: "/v2/team%2fapp/manifests/v1", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "an uppercase repository", method: "PUT", target: "/v2/Team/app/manifests/v1", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "a double slash", method: "PUT", target: "/v2/team//app/manifests/v1", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "a dot segment", method: "PUT", target: "/v2/team/./app/manifests/v1", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "a backslash", method: "PUT", target: `/v2/team\app/manifests/v1`, auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "an absolute-form target", method: "PUT", target: "http://registry.test/v2/team/app/manifests/v1", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "an unknown query key", method: "PUT", target: "/v2/team/app/manifests/v1?tag=x", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "a route word as a repository component", method: "PUT", target: "/v2/team/manifests/manifests/v1", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},

		// Refused shapes.
		{name: "DELETE is refused unauthenticated", method: "DELETE", target: "/v2/team/app/manifests/" + digestA, status: 405, reviews: 0, sars: 0},
		{name: "DELETE is refused authenticated", method: "DELETE", target: "/v2/team/app/manifests/" + digestA, auth: basic(tokTeam), status: 405, reviews: 0, sars: 0},
		{name: "DELETE of an upload is refused", method: "DELETE", target: "/v2/team/app/blobs/uploads/abc", auth: basic(tokTeam), status: 405, reviews: 0, sars: 0},
		{name: "a zot extension write is refused", method: "POST", target: "/v2/_zot/ext/userprefs?action=toggleStar&repo=team/app", auth: basic(tokTeam), status: 405, reviews: 0, sars: 0},
		{name: "a tags PUT is refused", method: "PUT", target: "/v2/team/app/tags/list", auth: basic(tokTeam), status: 405, reviews: 0, sars: 0},
		{name: "OPTIONS is refused", method: "OPTIONS", target: "/v2/team/app/manifests/v1", status: 405, reviews: 0, sars: 0},

		// Cross-repository mount.
		{name: "a mount from a foreign repository is denied", method: "POST", target: "/v2/team/app/blobs/uploads/?mount=" + digestA + "&from=other/base", auth: basic(tokTeam),
			status: 403, reviews: 1, sars: 0},
		{name: "a mount from inside the prefix authorizes both names", method: "POST", target: "/v2/team/app/blobs/uploads/?mount=" + digestA + "&from=team/base", auth: basic(tokTeam),
			status: 202, forward: "POST /v2/team/app/blobs/uploads/?from=team%2Fbase&mount=sha256%3A" + digestA[7:], asWrite: true, reviews: 1, sars: 2,
			check: func(t *testing.T, f *gateFixture, _ rawResponse) {
				var names []string
				for _, s := range f.access.seen {
					names = append(names, s.Spec.ResourceAttributes.Name)
				}
				if strings.Join(names, ",") != "team/app,team/base" {
					t.Errorf("access reviews named %v, want team/app then team/base", names)
				}
			}},
		{name: "a mount without a source is refused", method: "POST", target: "/v2/team/app/blobs/uploads/?mount=" + digestA, auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "a source without a mount is refused", method: "POST", target: "/v2/team/app/blobs/uploads/?from=team/base", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "a duplicated mount is refused", method: "POST", target: "/v2/team/app/blobs/uploads/?mount=" + digestA + "&mount=" + digestB + "&from=team/base", auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},
		{name: "a duplicated digest is refused", method: "PUT", target: "/v2/team/app/blobs/uploads/abc?digest=" + digestA + "&digest=" + digestB, auth: basic(tokTeam), status: 400, reviews: 0, sars: 0},

		// Upload status is a write.
		{name: "upload status needs a login", method: "GET", target: "/v2/team/app/blobs/uploads/abc-123", status: 401, challenge: true, reviews: 0, sars: 0},
		{name: "upload status with a login is forwarded as the gate", method: "GET", target: "/v2/team/app/blobs/uploads/abc-123", auth: basic(tokTeam),
			status: 200, forward: "GET /v2/team/app/blobs/uploads/abc-123", asWrite: true, reviews: 1, sars: 1},
		{name: "an escaped upload path is still an upload", method: "GET", target: "/v2/team/app/blobs/%75ploads/abc", status: 400, reviews: 0, sars: 0},
		{name: "a case-folded upload path is still an upload", method: "HEAD", target: "/v2/team/app/BLOBS/Uploads/abc", status: 400, reviews: 0, sars: 0},

		// Anonymous reads.
		{name: "the base endpoint stays anonymous", method: "GET", target: "/v2/", status: 200, forward: "GET /v2/", reviews: 0, sars: 0},
		{name: "a blob read with a Range is forwarded with no credential", method: "GET", target: "/v2/team/app/blobs/" + digestA,
			header: map[string]string{"Range": "bytes=0-99"}, status: 200, forward: "GET /v2/team/app/blobs/" + digestA, reviews: 0, sars: 0,
			check: func(t *testing.T, f *gateFixture, r rawResponse) {
				if got := f.zot.requests()[0].rng; got != "bytes=0-99" {
					t.Errorf("Range reached the registry as %q", got)
				}
				if r.body != "content" {
					t.Errorf("read body = %q", r.body)
				}
			}},
		{name: "a read carrying Authorization has it stripped", method: "GET", target: "/v2/team/app/manifests/v1?x=1", auth: basic(tokTeam),
			header: map[string]string{"Cookie": "session=stolen"}, status: 200, forward: "GET /v2/team/app/manifests/v1?x=1", reviews: 0, sars: 0,
			check: func(t *testing.T, f *gateFixture, _ rawResponse) {
				if c := f.zot.requests()[0].cookie; c != "" {
					t.Errorf("a client cookie reached the registry: %q", c)
				}
			}},
		{name: "a zot extension read passes through", method: "GET", target: "/v2/_zot/ext/search?query=x", status: 200, forward: "GET /v2/_zot/ext/search?query=x", reviews: 0, sars: 0},
		{name: "a HEAD of a manifest passes through", method: "HEAD", target: "/v2/other/app/manifests/v1", status: 200, forward: "HEAD /v2/other/app/manifests/v1", reviews: 0, sars: 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := newGateFixture(t)
			if row.setup != nil {
				row.setup(f)
			}
			resp := f.do(t, row.method, row.target, row.auth, row.body, row.header)
			if resp.status != row.status {
				t.Fatalf("status = %d, want %d (body %s)", resp.status, row.status, resp.body)
			}
			seen := f.zot.requests()
			if row.forward == "" {
				if len(seen) != 0 {
					t.Fatalf("the registry saw %+v; nothing must be forwarded", seen)
				}
			} else {
				if len(seen) != 1 {
					t.Fatalf("the registry saw %d requests %+v, want exactly one", len(seen), seen)
				}
				if got := seen[0].method + " " + seen[0].uri; got != row.forward {
					t.Errorf("forwarded %q, want %q", got, row.forward)
				}
				wantAuth := ""
				if row.asWrite {
					wantAuth = wantGateAuth
				}
				if seen[0].auth != wantAuth {
					t.Errorf("the registry saw Authorization %q, want %q", seen[0].auth, wantAuth)
				}
				if row.forwardBody != "" && seen[0].body != row.forwardBody {
					t.Errorf("forwarded body %q, want %q", seen[0].body, row.forwardBody)
				}
			}
			if row.reviews >= 0 && f.tokens.count() != row.reviews {
				t.Errorf("token reviews = %d, want %d", f.tokens.count(), row.reviews)
			}
			if row.sars >= 0 && f.access.count() != row.sars {
				t.Errorf("access reviews = %d, want %d", f.access.count(), row.sars)
			}
			if got := resp.header.Get("WWW-Authenticate"); row.challenge != (got != "") {
				t.Errorf("WWW-Authenticate = %q, want challenge %v", got, row.challenge)
			} else if row.challenge && got != `Basic realm="k3sm-registry"` {
				t.Errorf("WWW-Authenticate = %q", got)
			}
			if row.status >= 400 && row.method != "HEAD" {
				var e struct {
					Errors []struct{ Code, Message string } `json:"errors"`
				}
				if err := json.Unmarshal([]byte(resp.body), &e); err != nil || len(e.Errors) != 1 || e.Errors[0].Code == "" {
					t.Errorf("error body %q is not an OCI error", resp.body)
				}
			}
			if row.check != nil {
				row.check(t, f, resp)
			}
		})
	}

	t.Run("the reviews ask exactly the questions the design names", func(t *testing.T) {
		f := newGateFixture(t)
		if r := f.do(t, "PUT", "/v2/team/app/manifests/v1", basic(tokTeam), "{}", nil); r.status != 201 {
			t.Fatalf("status = %d", r.status)
		}
		if a := f.tokens.audiences; len(a) != 1 || len(a[0]) != 1 || a[0][0] != RegistryAudience {
			t.Errorf("token review audiences = %v, want [[%s]]", a, RegistryAudience)
		}
		s := f.access.seen[0].Spec
		ra := s.ResourceAttributes
		if ra.Group != "registry.k3sm.io" || ra.Resource != "repositories" || ra.Verb != "push" || ra.Namespace != "team" || ra.Name != "team/app" {
			t.Errorf("access review attributes = %+v", ra)
		}
		want := saStatus("team", "builder").User
		if s.User != want.Username || s.UID != want.UID || strings.Join(s.Groups, ",") != strings.Join(want.Groups, ",") ||
			len(s.Extra["authentication.kubernetes.io/pod-name"]) != 1 {
			t.Errorf("access review subject = %+v, want the reviewed user %+v", s, want)
		}
	})

	t.Run("caches expire and a revocation lands", func(t *testing.T) {
		f := newGateFixture(t)
		push := func() int { return f.do(t, "PUT", "/v2/team/app/manifests/v1", basic(tokTeam), "{}", nil).status }
		if s := push(); s != 201 {
			t.Fatalf("first push = %d", s)
		}
		f.access.mu.Lock()
		f.access.allow = func(*authzv1.SubjectAccessReview) bool { return false }
		f.access.mu.Unlock()
		f.clock.advance(5 * time.Second)
		if s := push(); s != 201 {
			t.Errorf("push inside the access cache = %d, want 201 (cached)", s)
		}
		if f.tokens.count() != 1 || f.access.count() != 1 {
			t.Errorf("reviews = %d/%d inside the caches, want 1/1", f.tokens.count(), f.access.count())
		}
		f.clock.advance(6 * time.Second) // 11 s: past the access TTL
		if s := push(); s != 403 {
			t.Errorf("push after the access TTL = %d, want 403 (revoked)", s)
		}
		if f.access.count() != 2 || f.tokens.count() != 1 {
			t.Errorf("reviews = %d/%d after the access TTL, want 1 token, 2 access", f.tokens.count(), f.access.count())
		}
		f.clock.advance(20 * time.Second) // 31 s: past the token TTL
		_ = push()
		if f.tokens.count() != 2 {
			t.Errorf("token reviews after the token TTL = %d, want 2", f.tokens.count())
		}
		// A removed label lands within the namespace TTL.
		f.access.mu.Lock()
		f.access.allow = func(*authzv1.SubjectAccessReview) bool { return true }
		f.access.mu.Unlock()
		f.clock.advance(11 * time.Second)
		if s := push(); s != 201 {
			t.Fatalf("push with the grant restored = %d", s)
		}
		f.namespaces.mu.Lock()
		f.namespaces.labels["team"] = map[string]string{}
		f.namespaces.mu.Unlock()
		f.clock.advance(6 * time.Second)
		if s := push(); s != 403 {
			t.Errorf("push after the label was removed = %d, want 403", s)
		}
	})

	t.Run("a positive token review is never cached past the token's expiry", func(t *testing.T) {
		f := newGateFixture(t)
		push := func() { _ = f.do(t, "PUT", "/v2/team/app/manifests/v1", basic(tokShort), "{}", nil) }
		push()
		f.clock.advance(2 * time.Second)
		push()
		if f.tokens.count() != 1 {
			t.Fatalf("token reviews inside the token's life = %d, want 1", f.tokens.count())
		}
		f.clock.advance(2 * time.Second) // past exp, well inside the 30 s TTL
		push()
		if f.tokens.count() != 2 {
			t.Errorf("token reviews after the token expired = %d, want 2", f.tokens.count())
		}
	})

	t.Run("a refused token is cached briefly", func(t *testing.T) {
		f := newGateFixture(t)
		for range 3 {
			_ = f.do(t, "POST", "/v2/team/app/blobs/uploads/", basic(tokUnauth), "", nil)
		}
		if f.tokens.count() != 1 {
			t.Errorf("reviews of a refused token = %d, want 1 inside the negative TTL", f.tokens.count())
		}
		f.clock.advance(6 * time.Second)
		_ = f.do(t, "POST", "/v2/team/app/blobs/uploads/", basic(tokUnauth), "", nil)
		if f.tokens.count() != 2 {
			t.Errorf("reviews after the negative TTL = %d, want 2", f.tokens.count())
		}
	})

	t.Run("token reviews are rate limited across tokens", func(t *testing.T) {
		f := newGateFixture(t)
		limited := 0
		for i := range int(tokenReviewBurst) + 5 {
			r := f.do(t, "POST", "/v2/team/app/blobs/uploads/", basic(mkToken("t"+strconv.Itoa(i), testEpoch.Add(time.Hour))), "", nil)
			if r.status == http.StatusTooManyRequests {
				limited++
			}
		}
		if f.tokens.count() != int(tokenReviewBurst) || limited != 5 {
			t.Errorf("reviews = %d, limited = %d; want %d reviews and 5 refusals", f.tokens.count(), limited, int(tokenReviewBurst))
		}
	})

	t.Run("a refused request's body is never read", func(t *testing.T) {
		for _, c := range []struct{ name, target, auth string }{
			{"unauthenticated", "/v2/team/app/blobs/uploads/abc", ""},
			{"unlabelled", "/v2/other/app/blobs/uploads/abc", basic(tokOther)},
			{"outside the prefix", "/v2/other/app/blobs/uploads/abc", basic(tokTeam)},
		} {
			t.Run(c.name, func(t *testing.T) {
				f := newGateFixture(t)
				body := &tripwireBody{}
				req := httptest.NewRequest("PATCH", c.target, body)
				req.ContentLength = 1 << 20
				req.Header.Set("Expect", "100-continue")
				if c.auth != "" {
					req.Header.Set("Authorization", c.auth)
				}
				rec := httptest.NewRecorder()
				f.gate.ServeHTTP(rec, req)
				if rec.Code < 400 {
					t.Fatalf("status = %d, want a refusal", rec.Code)
				}
				if body.reads != 0 {
					t.Errorf("the refused request's body was read %d times", body.reads)
				}
				if rec.Header().Get("Connection") != "close" {
					t.Errorf("Connection = %q, want close on a refusal with a body", rec.Header().Get("Connection"))
				}
			})
		}
	})

	t.Run("a refused client is never sent 100 Continue", func(t *testing.T) {
		f := newGateFixture(t)
		line := expectContinue(t, f.front, "/v2/team/app/blobs/uploads/abc", "")
		if !strings.HasPrefix(line, "HTTP/1.1 401") {
			t.Errorf("first response line = %q, want the 401 and no 100 Continue", line)
		}
	})

	t.Run("an authorized client is sent 100 Continue and its body is forwarded", func(t *testing.T) {
		f := newGateFixture(t)
		line := expectContinue(t, f.front, "/v2/team/app/blobs/uploads/abc", basic(tokTeam))
		if !strings.HasPrefix(line, "HTTP/1.1 202") {
			t.Errorf("final response line = %q, want 202", line)
		}
		if seen := f.zot.requests(); len(seen) != 1 || seen[0].body != "0123456789" {
			t.Errorf("the registry saw %+v, want the 10-byte body", seen)
		}
	})

	t.Run("a gate with no apiserver identity serves reads and refuses writes", func(t *testing.T) {
		z := newFakeZot(t)
		g := newGate(gateConfig{Upstream: fakeZotHost, Transport: z, Credential: gateCred, Logger: quietLogger()})
		addr := serveMem(t, g)
		if r := rawDo(t, addr, "GET", "/v2/team/app/manifests/v1", nil, ""); r.status != 200 {
			t.Errorf("read = %d, want 200", r.status)
		}
		if r := rawDo(t, addr, "PUT", "/v2/team/app/manifests/v1", map[string]string{"Authorization": basic(tokTeam)}, "{}"); r.status != 503 {
			t.Errorf("write = %d, want 503", r.status)
		}
		if n := len(z.requests()); n != 1 {
			t.Errorf("the registry saw %d requests, want only the read", n)
		}
	})
}

// tripwireBody fails the test's assertion by counting any Read.
type tripwireBody struct{ reads int }

func (b *tripwireBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("the body of a refused request must never be read")
}

// expectContinue sends a PATCH with Expect: 100-continue and withholds its
// 10-byte body until the server says 100 Continue. It returns the final status
// line: for a refusal, the very first line the server sent.
func expectContinue(t *testing.T, l *memListener, target, auth string) string {
	t.Helper()
	c, err := l.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req := "PATCH " + target + " HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: 10\r\n"
	if auth != "" {
		req += "Authorization: " + auth + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 100") {
		return strings.TrimSpace(line)
	}
	// Skip the blank line closing the interim response, send the body.
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := io.WriteString(c, "0123456789"); err != nil {
		t.Fatalf("write body: %v", err)
	}
	line, err = br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimSpace(line)
}
