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

package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/certs"
)

// delegatedTestNode is the node the endpoint under test serves; every allowing
// SAR in the fake names it, so a review against any other name is a denial.
const delegatedTestNode = "k3sm-node"

// Tokens the fake TokenReviewer knows. Each stands for one row of the matrix.
const (
	tokenMetrics     = "token-metrics-server"  // authenticated; may get nodes/metrics
	tokenStats       = "token-stats-reader"    // authenticated; may get nodes/stats
	tokenNoGrant     = "token-no-grant"        // authenticated; may get nothing
	tokenOtherNode   = "token-other-node"      // authenticated; may get nodes/metrics on ANOTHER node
	tokenSARError    = "token-sar-error"       // authenticated; the SAR call errors
	tokenSARDenied   = "token-sar-denied"      // authenticated; allowed AND explicitly denied
	tokenExpired     = "token-expired"         // the apiserver says: not authenticated (expired)
	tokenNoUsername  = "token-no-username"     // authenticated with an empty username
	tokenReviewError = "token-tokenreview-err" // the TokenReview call errors
)

// fakeTokenReviewer answers TokenReviews from a fixed table and counts calls.
type fakeTokenReviewer struct {
	calls atomic.Int64
	// failNext, when set, makes the next N calls error regardless of the token.
	failNext atomic.Int64
}

func (f *fakeTokenReviewer) Create(_ context.Context, tr *authnv1.TokenReview, _ metav1.CreateOptions) (*authnv1.TokenReview, error) {
	f.calls.Add(1)
	if f.failNext.Load() > 0 {
		f.failNext.Add(-1)
		return nil, errors.New("apiserver unavailable")
	}
	out := tr.DeepCopy()
	user := func(name string) authnv1.UserInfo {
		return authnv1.UserInfo{Username: name, UID: name + "-uid", Groups: []string{"system:serviceaccounts", "system:authenticated"},
			Extra: map[string]authnv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"p"}}}
	}
	switch tr.Spec.Token {
	case tokenMetrics:
		out.Status = authnv1.TokenReviewStatus{Authenticated: true, User: user("system:serviceaccount:kube-system:metrics-server")}
	case tokenStats:
		out.Status = authnv1.TokenReviewStatus{Authenticated: true, User: user("stats-reader")}
	case tokenNoGrant:
		out.Status = authnv1.TokenReviewStatus{Authenticated: true, User: user("nobody-special")}
	case tokenOtherNode:
		out.Status = authnv1.TokenReviewStatus{Authenticated: true, User: user("other-node-reader")}
	case tokenSARError:
		out.Status = authnv1.TokenReviewStatus{Authenticated: true, User: user("sar-error")}
	case tokenSARDenied:
		out.Status = authnv1.TokenReviewStatus{Authenticated: true, User: user("sar-denied")}
	case tokenNoUsername:
		out.Status = authnv1.TokenReviewStatus{Authenticated: true}
	case tokenExpired:
		out.Status = authnv1.TokenReviewStatus{Authenticated: false, Error: "token has expired"}
	case tokenReviewError:
		return nil, errors.New("tokenreviews.authentication.k8s.io: context deadline exceeded")
	default:
		out.Status = authnv1.TokenReviewStatus{Authenticated: false, Error: "invalid bearer token"}
	}
	return out, nil
}

// fakeSARReviewer answers SubjectAccessReviews from a fixed grant table and
// records every request so the test can assert what was asked.
type fakeSARReviewer struct {
	calls atomic.Int64
	mu    sync.Mutex
	seen  []authzv1.SubjectAccessReviewSpec
}

func (f *fakeSARReviewer) Create(_ context.Context, sar *authzv1.SubjectAccessReview, _ metav1.CreateOptions) (*authzv1.SubjectAccessReview, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.seen = append(f.seen, *sar.Spec.DeepCopy())
	f.mu.Unlock()
	ra := sar.Spec.ResourceAttributes
	if ra == nil {
		return nil, errors.New("non-resource SAR")
	}
	out := sar.DeepCopy()
	onNode := func(user, sub, node string) bool {
		return sar.Spec.User == user && ra.Verb == "get" && ra.Group == "" && ra.Resource == "nodes" && ra.Subresource == sub && ra.Name == node
	}
	switch {
	case sar.Spec.User == "sar-error":
		return nil, errors.New("subjectaccessreviews.authorization.k8s.io: connection refused")
	case sar.Spec.User == "sar-denied":
		out.Status = authzv1.SubjectAccessReviewStatus{Allowed: true, Denied: true}
	case onNode("system:serviceaccount:kube-system:metrics-server", "metrics", delegatedTestNode),
		onNode("stats-reader", "stats", delegatedTestNode),
		onNode("other-node-reader", "metrics", "some-other-node"):
		out.Status = authzv1.SubjectAccessReviewStatus{Allowed: true}
	default:
		out.Status = authzv1.SubjectAccessReviewStatus{Allowed: false, Reason: "no RBAC policy matched"}
	}
	return out, nil
}

// delegatedRoutes are the routes the test mux serves: the two token routes and
// the four interactive or log routes the token path must never reach.
var delegatedRoutes = []string{
	"/metrics/resource",
	"/stats/summary",
	"/exec/default/web/app",
	"/attach/default/web/app",
	"/portForward/default/web",
	"/containerLogs/default/web/app",
}

// TestKubeletDelegatedAuth is the B93 gate on the kubelet endpoint: a bearer
// token is admitted ONLY on the read-only resource-metrics routes, ONLY after
// the apiserver authenticated it (TokenReview) and authorized nodes/metrics or
// nodes/stats on this node (SubjectAccessReview), and every review failure is a
// denial. The client-certificate half is unchanged: the apiserver's CN is served
// everywhere, any other cluster identity is 403 everywhere, even with a valid
// token beside it.
//
// It drives a real TLS handshake (over an in-memory pipe) configured by the production path (NewKubeletEndpointAuth
// → WithDelegatedAuth → ServingTLS → Handler). Each handler records whether it ran,
// because on this surface the load-bearing claim is that a refused caller never
// reaches the route, not only that the status code is right.
//
// Before B93 the token rows could not be expressed: ServingTLS required a client
// certificate, so a cert-less metrics-server scrape failed the handshake and every
// "200" row below failed.
func TestKubeletDelegatedAuth(t *testing.T) {
	pki := newKubeletTestPKI(t)
	tokens := &fakeTokenReviewer{}
	access := &fakeSARReviewer{}
	auth := newDelegatedTestAuth(t, pki, tokens, access)

	var served sync.Map // path -> *atomic.Int64
	mux := http.NewServeMux()
	for _, p := range delegatedRoutes {
		c := &atomic.Int64{}
		served.Store(p, c)
		mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
			c.Add(1)
			_, _ = io.WriteString(w, "ok")
		})
	}
	servedCount := func(p string) int64 {
		v, _ := served.Load(p)
		return v.(*atomic.Int64).Load()
	}

	srv := startDelegatedTestServer(t, auth, mux)

	apiserverCert := clientCert(t, pki.signing, certs.APIServerKubeletClientCN, nil)
	nodeCert := clientCert(t, pki.signing, "system:node:worker-2", []string{"system:nodes"})

	type row struct {
		name   string
		cert   *tls.Certificate
		token  string
		method string
		path   string
		want   int
	}
	var rows []row
	add := func(r row) { rows = append(rows, r) }

	add(row{name: "anonymous: no certificate, no token", path: "/metrics/resource", want: http.StatusUnauthorized})
	add(row{name: "anonymous on exec", path: "/exec/default/web/app", want: http.StatusUnauthorized})
	add(row{name: "a bad token", token: "garbage", path: "/metrics/resource", want: http.StatusUnauthorized})
	add(row{name: "an expired token", token: tokenExpired, path: "/metrics/resource", want: http.StatusUnauthorized})
	add(row{name: "an authenticated token with no username", token: tokenNoUsername, path: "/metrics/resource", want: http.StatusUnauthorized})
	add(row{name: "a TokenReview error", token: tokenReviewError, path: "/metrics/resource", want: http.StatusUnauthorized})
	add(row{name: "a valid token without nodes/metrics", token: tokenNoGrant, path: "/metrics/resource", want: http.StatusForbidden})
	add(row{name: "a valid token allowed nodes/metrics on another node only", token: tokenOtherNode, path: "/metrics/resource", want: http.StatusForbidden})
	add(row{name: "a SubjectAccessReview error", token: tokenSARError, path: "/metrics/resource", want: http.StatusForbidden})
	add(row{name: "a SubjectAccessReview that allows and denies", token: tokenSARDenied, path: "/metrics/resource", want: http.StatusForbidden})
	add(row{name: "metrics-server's token on /metrics/resource", token: tokenMetrics, path: "/metrics/resource", want: http.StatusOK})
	add(row{name: "metrics-server's token on /stats/summary (nodes/stats not granted)", token: tokenMetrics, path: "/stats/summary", want: http.StatusForbidden})
	add(row{name: "a nodes/stats token on /stats/summary", token: tokenStats, path: "/stats/summary", want: http.StatusOK})
	add(row{name: "a nodes/stats token on /metrics/resource", token: tokenStats, path: "/metrics/resource", want: http.StatusForbidden})
	add(row{name: "metrics-server's token with a non-GET method", token: tokenMetrics, method: http.MethodPost, path: "/metrics/resource", want: http.StatusForbidden})
	for _, p := range []string{"/exec/default/web/app", "/attach/default/web/app", "/portForward/default/web", "/containerLogs/default/web/app"} {
		add(row{name: "metrics-server's token on " + p, token: tokenMetrics, path: p, want: http.StatusForbidden})
	}
	for _, p := range delegatedRoutes {
		add(row{name: "a system:node client certificate on " + p, cert: &nodeCert, path: p, want: http.StatusForbidden})
	}
	add(row{name: "a system:node certificate with a valid metrics token never falls through to the token path", cert: &nodeCert, token: tokenMetrics, path: "/metrics/resource", want: http.StatusForbidden})
	for _, p := range delegatedRoutes {
		add(row{name: "the apiserver's client certificate on " + p, cert: &apiserverCert, path: p, want: http.StatusOK})
	}

	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			before := servedCount(tt.path)
			status := delegatedDo(t, srv, tt.cert, tt.token, tt.method, tt.path)
			if status != tt.want {
				t.Errorf("status = %d, want %d", status, tt.want)
			}
			ran := servedCount(tt.path) != before
			if ran != (tt.want == http.StatusOK) {
				t.Errorf("route %s ran = %v, want %v", tt.path, ran, tt.want == http.StatusOK)
			}
		})
	}

	t.Run("the SubjectAccessReview carries the reviewed user and this node's metrics subresource", func(t *testing.T) {
		access.mu.Lock()
		defer access.mu.Unlock()
		found := false
		for _, s := range access.seen {
			if s.User != "system:serviceaccount:kube-system:metrics-server" || s.ResourceAttributes.Subresource != "metrics" {
				continue
			}
			found = true
			ra := s.ResourceAttributes
			if ra.Verb != "get" || ra.Resource != "nodes" || ra.Group != "" || ra.Name != delegatedTestNode {
				t.Errorf("SAR attributes = %+v, want get nodes/metrics name=%s", *ra, delegatedTestNode)
			}
			if s.UID == "" || len(s.Groups) == 0 || len(s.Extra) == 0 {
				t.Errorf("SAR dropped the reviewed identity: uid=%q groups=%v extra=%v", s.UID, s.Groups, s.Extra)
			}
		}
		if !found {
			t.Fatal("no SubjectAccessReview for metrics-server's nodes/metrics was issued")
		}
	})
}

// TestKubeletDelegatedAuthReviewDiscipline pins the parts of the bearer path the
// status matrix cannot see: which requests cost an apiserver round trip, what the
// cache may and may not remember, and the handshake posture.
func TestKubeletDelegatedAuthReviewDiscipline(t *testing.T) {
	pki := newKubeletTestPKI(t)

	t.Run("a token on a non-metrics route is refused without any review", func(t *testing.T) {
		tokens, access := &fakeTokenReviewer{}, &fakeSARReviewer{}
		d := mustDelegated(t, tokens, access)
		for _, p := range []string{"/exec/default/web/app", "/attach/x/y/z", "/portForward/x/y", "/containerLogs/x/y/z", "/pods", "/runningpods/", "/metrics/resource/../../exec/a/b/c", "/metrics/resourcex"} {
			r := httptest.NewRequest(http.MethodGet, "https://node"+p, nil)
			r.URL.Path = p
			if got := d.admit(context.Background(), r, tokenMetrics); got != http.StatusForbidden {
				t.Errorf("admit(%s) = %d, want 403", p, got)
			}
		}
		if n := tokens.calls.Load() + access.calls.Load(); n != 0 {
			t.Errorf("%d review calls for non-metrics routes, want 0", n)
		}
	})

	t.Run("an escaped path is never a token route", func(t *testing.T) {
		tokens, access := &fakeTokenReviewer{}, &fakeSARReviewer{}
		d := mustDelegated(t, tokens, access)
		r := httptest.NewRequest(http.MethodGet, "https://node/metrics%2Fresource", nil)
		if r.URL.RawPath == "" {
			t.Fatalf("test premise: %q parsed with no RawPath", r.URL.String())
		}
		if got := d.admit(context.Background(), r, tokenMetrics); got != http.StatusForbidden {
			t.Errorf("admit(escaped) = %d, want 403", got)
		}
	})

	t.Run("an allow is cached per token and path, and expires", func(t *testing.T) {
		tokens, access := &fakeTokenReviewer{}, &fakeSARReviewer{}
		d := mustDelegated(t, tokens, access)
		now := time.Unix(1_800_000_000, 0)
		d.now = func() time.Time { return now }
		get := func(p, tok string) int {
			return d.admit(context.Background(), httptest.NewRequest(http.MethodGet, "https://node"+p, nil), tok)
		}
		if got := get("/metrics/resource", tokenMetrics); got != http.StatusOK {
			t.Fatalf("first admit = %d, want 200", got)
		}
		if got := get("/metrics/resource", tokenMetrics); got != http.StatusOK || tokens.calls.Load() != 1 {
			t.Errorf("second admit = %d with %d TokenReviews, want 200 from cache (1 review)", got, tokens.calls.Load())
		}
		// A different path is a different key: it is reviewed, not served from the
		// metrics allow.
		if got := get("/stats/summary", tokenMetrics); got != http.StatusForbidden || tokens.calls.Load() != 2 {
			t.Errorf("stats admit = %d with %d TokenReviews, want a fresh review and 403", got, tokens.calls.Load())
		}
		now = now.Add(delegatedAllowTTL)
		if got := get("/metrics/resource", tokenMetrics); got != http.StatusOK || tokens.calls.Load() != 3 {
			t.Errorf("after TTL admit = %d with %d TokenReviews, want a fresh review", got, tokens.calls.Load())
		}
	})

	t.Run("a review error is never cached and never an allow", func(t *testing.T) {
		tokens, access := &fakeTokenReviewer{}, &fakeSARReviewer{}
		d := mustDelegated(t, tokens, access)
		tokens.failNext.Store(1)
		r := func() *http.Request { return httptest.NewRequest(http.MethodGet, "https://node/metrics/resource", nil) }
		if got := d.admit(context.Background(), r(), tokenMetrics); got != http.StatusUnauthorized {
			t.Fatalf("admit during a TokenReview outage = %d, want 401", got)
		}
		if got := d.admit(context.Background(), r(), tokenMetrics); got != http.StatusOK || tokens.calls.Load() != 2 {
			t.Errorf("admit after the outage = %d with %d TokenReviews, want a fresh review and 200 (the error must not be cached)", got, tokens.calls.Load())
		}
		if got := d.admit(context.Background(), r(), tokenSARError); got != http.StatusForbidden {
			t.Errorf("admit on a SAR error = %d, want 403", got)
		}
		if got := d.admit(context.Background(), r(), tokenSARError); got != http.StatusForbidden || access.calls.Load() != 3 {
			t.Errorf("repeat SAR error = %d with %d SARs, want 403 and a fresh SAR (not cached)", got, access.calls.Load())
		}
	})

	t.Run("a hung review times out to a denial", func(t *testing.T) {
		d := mustDelegated(t, blockingTokenReviewer{}, &fakeSARReviewer{})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		r := httptest.NewRequest(http.MethodGet, "https://node/metrics/resource", nil).WithContext(ctx)
		if got := d.admit(ctx, r, tokenMetrics); got != http.StatusUnauthorized {
			t.Errorf("admit on a hung TokenReview = %d, want 401", got)
		}
	})

	t.Run("the cache is bounded", func(t *testing.T) {
		d := mustDelegated(t, &fakeTokenReviewer{}, &fakeSARReviewer{})
		for i := 0; i < delegatedCacheMax*3; i++ {
			tok := "garbage-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + time.Duration(i).String()
			d.admit(context.Background(), httptest.NewRequest(http.MethodGet, "https://node/metrics/resource", nil), tok)
		}
		d.mu.Lock()
		n := len(d.cache)
		d.mu.Unlock()
		if n > delegatedCacheMax {
			t.Errorf("cache holds %d entries, want <= %d", n, delegatedCacheMax)
		}
	})

	t.Run("delegation relaxes the handshake to verify-if-given, and only then", func(t *testing.T) {
		base, err := NewKubeletEndpointAuth(pki.signing.CertPEM, nil)
		if err != nil {
			t.Fatalf("NewKubeletEndpointAuth: %v", err)
		}
		if got := base.ServingTLS(&tls.Config{}).ClientAuth; got != tls.RequireAndVerifyClientCert {
			t.Errorf("certificate-only ClientAuth = %v, want RequireAndVerifyClientCert", got)
		}
		if base.TokenRoutes() != nil {
			t.Errorf("certificate-only TokenRoutes = %v, want nil", base.TokenRoutes())
		}
		del, err := base.WithDelegatedAuth(mustDelegated(t, &fakeTokenReviewer{}, &fakeSARReviewer{}))
		if err != nil {
			t.Fatalf("WithDelegatedAuth: %v", err)
		}
		if got := del.ServingTLS(&tls.Config{}).ClientAuth; got != tls.VerifyClientCertIfGiven {
			t.Errorf("delegated ClientAuth = %v, want VerifyClientCertIfGiven", got)
		}
		if base.delegated != nil {
			t.Error("WithDelegatedAuth mutated the receiver")
		}
		if _, err := base.WithDelegatedAuth(nil); !errors.Is(err, ErrNoDelegatedAuth) {
			t.Errorf("WithDelegatedAuth(nil) = %v, want ErrNoDelegatedAuth", err)
		}
		if _, err := NewDelegatedAuth("", &fakeTokenReviewer{}, &fakeSARReviewer{}); !errors.Is(err, ErrDelegatedAuthIncomplete) {
			t.Errorf("NewDelegatedAuth with no node name = %v, want ErrDelegatedAuthIncomplete", err)
		}
	})

	t.Run("a foreign-CA certificate is still refused at the handshake under delegation", func(t *testing.T) {
		auth := newDelegatedTestAuth(t, pki, &fakeTokenReviewer{}, &fakeSARReviewer{})
		srv := startDelegatedTestServer(t, auth, http.NotFoundHandler())
		foreign := clientCert(t, pki.foreign, certs.APIServerKubeletClientCN, nil)
		if _, err := delegatedDoErr(srv, &foreign, tokenMetrics, "", "/metrics/resource"); err == nil {
			t.Error("a certificate from a foreign CA completed the handshake")
		}
	})
}

// blockingTokenReviewer never answers until its context ends.
type blockingTokenReviewer struct{}

func (blockingTokenReviewer) Create(ctx context.Context, _ *authnv1.TokenReview, _ metav1.CreateOptions) (*authnv1.TokenReview, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func mustDelegated(t *testing.T, tokens TokenReviewer, access SubjectAccessReviewer) *DelegatedAuth {
	t.Helper()
	d, err := NewDelegatedAuth(delegatedTestNode, tokens, access)
	if err != nil {
		t.Fatalf("NewDelegatedAuth: %v", err)
	}
	return d
}

func newDelegatedTestAuth(t *testing.T, pki kubeletTestPKI, tokens TokenReviewer, access SubjectAccessReviewer) *KubeletEndpointAuth {
	t.Helper()
	base, err := NewKubeletEndpointAuth(pki.signing.CertPEM, nil)
	if err != nil {
		t.Fatalf("NewKubeletEndpointAuth: %v", err)
	}
	auth, err := base.WithDelegatedAuth(mustDelegated(t, tokens, access))
	if err != nil {
		t.Fatalf("WithDelegatedAuth: %v", err)
	}
	return auth
}

// pipeServer is the kubelet endpoint under test, served by a real http.Server
// over a real TLS handshake, carried on in-memory net.Pipe connections instead of
// a kernel socket (the repo's untagged-test rule).
type pipeServer struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
	roots *x509.CertPool
}

// Accept hands the server the far end of the next dialed pipe.
func (p *pipeServer) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	case <-p.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept.
func (p *pipeServer) Close() error {
	p.once.Do(func() { close(p.done) })
	return nil
}

// Addr is a placeholder; nothing routes by it.
func (p *pipeServer) Addr() net.Addr { return pipeAddr{} }

// dial opens a new in-memory connection to the server.
func (p *pipeServer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case p.conns <- server:
		return client, nil
	case <-p.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// startDelegatedTestServer serves next behind auth with the TLS config the
// production path builds (auth.ServingTLS over a serving keypair), and returns
// the server with its client-side trust.
func startDelegatedTestServer(t *testing.T, auth *KubeletEndpointAuth, next http.Handler) *pipeServer {
	t.Helper()
	serving, err := certs.SelfSignedServing([]string{"k3sm-node", "localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("serving cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(serving.Certificate[0])
	if err != nil {
		t.Fatalf("parse serving leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	ps := &pipeServer{conns: make(chan net.Conn), done: make(chan struct{}), roots: roots}
	srvTLS := auth.ServingTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serving}})
	srv := &http.Server{Handler: auth.Handler(next), ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 10 * time.Second}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(tls.NewListener(ps, srvTLS)) // returns on Close; the error is the close
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
	})
	return ps
}

// delegatedDo issues one request and returns its status, failing the test on a
// transport error.
func delegatedDo(t *testing.T, ps *pipeServer, cert *tls.Certificate, token, method, path string) int {
	t.Helper()
	status, err := delegatedDoErr(ps, cert, token, method, path)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, path, err)
	}
	return status
}

// delegatedDoErr issues one request presenting cert (nil = none) and token
// (empty = none). The certificate is offered through GetClientCertificate so a
// foreign one is really sent rather than filtered out by the client (see
// TestKubeletEndpointRequiresClientCert).
func delegatedDoErr(ps *pipeServer, cert *tls.Certificate, token, method, path string) (int, error) {
	if method == "" {
		method = http.MethodGet
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ps.roots, ServerName: "localhost"}
	if cert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DialContext: ps.dial}}
	defer c.CloseIdleConnections()
	req, err := http.NewRequest(method, "https://localhost"+path, nil)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}
