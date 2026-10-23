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
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The PUSH GATE: the HTTP handler every relay address serves. Reads pass
// through to the loopback registry anonymously, exactly as the raw relay
// carried them before; a write is admitted only for a pod's ServiceAccount
// token the apiserver vouches for (gateauth.go), and is then forwarded with the
// gate's own registry credential, which never leaves this process.
//
// ORDER IS THE SECURITY PROPERTY. A write is classified, authenticated and
// authorized from its request line and headers alone, BEFORE a byte of its body
// is read: Go's server sends "100 Continue" only when a handler first reads the
// body, so a refused client is never invited to upload, and a refusal on a
// request that carries a body closes the connection rather than draining it.

// gateRealm is the Basic realm a 401 challenges with.
const gateRealm = "k3sm-registry"

// The OCI distribution error codes the gate answers with.
const (
	codeUnauthorized = "UNAUTHORIZED"
	codeDenied       = "DENIED"
	codeUnsupported  = "UNSUPPORTED"
	codeNameInvalid  = "NAME_INVALID"
	codeTooMany      = "TOOMANYREQUESTS"
	codeUnavailable  = "UNAVAILABLE"
)

// gate is the push gate's handler.
type gate struct {
	upstream string // the loopback registry, host:port
	log      *slog.Logger
	// auth is nil when the gate's apiserver clients could not be built: reads
	// are served and every write is 503.
	auth *authorizer
	// cred is the registry credential writes are forwarded with. Empty means
	// writes are 503, like a missing auth.
	cred Credential

	read, write *httputil.ReverseProxy
}

// gateConfig configures a gate.
type gateConfig struct {
	Upstream   string
	Auth       GateAuth
	Credential Credential
	Logger     *slog.Logger
	// Now is the clock the caches read; nil means time.Now.
	Now func() time.Time
	// Transport is the round tripper to the upstream; nil means a loopback
	// transport.
	Transport http.RoundTripper
}

// newGate builds a gate.
func newGate(cfg gateConfig) *gate {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Transport == nil {
		d := &net.Dialer{Timeout: relayDialTimeout}
		cfg.Transport = &http.Transport{
			DialContext:           d.DialContext,
			DisableCompression:    true,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	g := &gate{upstream: cfg.Upstream, log: cfg.Logger, cred: cfg.Credential}
	if cfg.Auth.complete() {
		g.auth = newAuthorizer(cfg.Auth, cfg.Now)
	}
	errLog := slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug)
	g.read = &httputil.ReverseProxy{
		Rewrite:        func(pr *httputil.ProxyRequest) { g.rewrite(pr, false) },
		FlushInterval:  -1,
		Transport:      cfg.Transport,
		ModifyResponse: g.modifyResponse,
		ErrorHandler:   g.readError,
		ErrorLog:       errLog,
	}
	g.write = &httputil.ReverseProxy{
		Rewrite:        func(pr *httputil.ProxyRequest) { g.rewrite(pr, true) },
		FlushInterval:  -1,
		Transport:      cfg.Transport,
		ModifyResponse: g.modifyResponse,
		ErrorHandler:   g.writeError,
		ErrorLog:       errLog,
	}
	return g
}

// rewrite points the outbound request at the loopback registry. Every client
// credential is dropped, and so is zot's UI session header, so a forwarded
// request authenticates as exactly what the gate decided: nothing for a read,
// the gate's credential for an authorized write. The path and query are left
// as the handler set them, and the Host header as the client sent it.
func (g *gate) rewrite(pr *httputil.ProxyRequest, attach bool) {
	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = g.upstream
	pr.Out.Header.Del("Authorization")
	pr.Out.Header.Del("Proxy-Authorization")
	pr.Out.Header.Del("Cookie")
	pr.Out.Header.Del("X-Zot-Api-Client")
	if attach {
		pr.Out.SetBasicAuth(g.cred.Username, g.cred.Password)
	}
}

// modifyResponse keeps the registry's session cookies inside this process and
// turns an absolute Location naming the loopback upstream into a path, so a
// client keeps talking to the gate.
func (g *gate) modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && u.Host == g.upstream {
			u.Scheme, u.Host = "", ""
			resp.Header.Set("Location", u.String())
		}
	}
	return nil
}

// readError ends a read whose upstream could not be reached by closing the
// connection without a response: what the raw relay did, and what a peer's
// puller already reads as "this mirror does not have it".
func (g *gate) readError(w http.ResponseWriter, r *http.Request, err error) {
	g.log.Debug("ingest registry gate could not reach the local registry", "target", g.upstream, "err", err)
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, herr := hj.Hijack(); herr == nil {
			_ = c.Close()
			return
		}
	}
	w.WriteHeader(http.StatusBadGateway)
}

// writeError answers an authorized write the registry did not take.
func (g *gate) writeError(w http.ResponseWriter, r *http.Request, err error) {
	g.log.Warn("ingest registry gate could not forward an authorized write", "target", g.upstream, "err", err)
	ociError(w, r, http.StatusBadGateway, codeUnavailable, "the node's registry is not answering")
}

// ServeHTTP is the gate. It is mounted directly on the server, never behind a
// ServeMux, whose path cleaning would decide what a path means before the gate
// does.
func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rawPath, rawQuery, ok := splitRequestURI(r.RequestURI)
	if !ok {
		ociError(w, r, http.StatusBadRequest, codeNameInvalid, "the request target is not an origin-form path")
		return
	}
	route := classify(r.Method, rawPath, rawQuery)
	switch {
	case route.op == opRead:
		g.read.ServeHTTP(w, r)
		return
	case route.op == opRefused:
		g.audit(r, route, pushIdentity{}, "refused", http.StatusMethodNotAllowed)
		ociError(w, r, http.StatusMethodNotAllowed, codeUnsupported, "this registry accepts blob uploads and manifest pushes only")
		return
	case route.op == opInvalid || r.URL.Path != rawPath:
		// The second clause is the differential guard: what Go decoded must be
		// exactly what was parsed, or the two disagree about the repository.
		g.audit(r, route, pushIdentity{}, "invalid", http.StatusBadRequest)
		ociError(w, r, http.StatusBadRequest, codeNameInvalid, "the request path or query is not one this registry accepts")
		return
	}
	g.authorizeWrite(w, r, route)
}

// splitRequestURI splits the request target as it appeared on the request
// line. Only origin form ("/path?query") is a registry request.
func splitRequestURI(uri string) (rawPath, rawQuery string, ok bool) {
	if !strings.HasPrefix(uri, "/") {
		return "", "", false
	}
	p, q, _ := strings.Cut(uri, "?")
	return p, q, true
}

// authorizeWrite runs the three questions and forwards an allowed write.
func (g *gate) authorizeWrite(w http.ResponseWriter, r *http.Request, route gateRoute) {
	if g.auth == nil || g.cred.Username == "" || g.cred.Password == "" {
		g.audit(r, route, pushIdentity{}, "unavailable: no apiserver identity", http.StatusServiceUnavailable)
		ociError(w, r, http.StatusServiceUnavailable, codeUnavailable, "pushing to this node's registry from the cluster is unavailable")
		return
	}
	tok, ok := basicPassword(r)
	if !ok || !tokenShapeOK(tok) {
		g.audit(r, route, pushIdentity{}, "unauthenticated: no token", http.StatusUnauthorized)
		g.challenge(w, r, "a push needs a ServiceAccount token as the password of a Basic login")
		return
	}
	tr, err := g.auth.reviewToken(r.Context(), tok)
	if err != nil {
		g.refuseUnavailable(w, r, route, pushIdentity{}, err)
		return
	}
	if tr.reason != "" {
		g.audit(r, route, pushIdentity{}, "unauthenticated: "+tr.reason, http.StatusUnauthorized)
		g.challenge(w, r, tr.reason)
		return
	}
	id := tr.id
	if id.namespace == "" {
		g.audit(r, route, id, "denied: not a ServiceAccount", http.StatusForbidden)
		ociError(w, r, http.StatusForbidden, codeDenied, "only a ServiceAccount may push")
		return
	}
	ns, err := g.auth.namespacePrefix(r.Context(), id.namespace)
	if err != nil {
		g.refuseUnavailable(w, r, route, id, err)
		return
	}
	if ns.prefix == "" {
		g.audit(r, route, id, "denied: "+ns.reason, http.StatusForbidden)
		ociError(w, r, http.StatusForbidden, codeDenied, ns.reason)
		return
	}
	repos := []string{route.repo}
	if route.from != "" {
		repos = append(repos, route.from)
	}
	for _, repo := range repos {
		if !underPrefix(repo, ns.prefix) {
			g.audit(r, route, id, "denied: "+repo+" is outside the namespace prefix "+ns.prefix+"/", http.StatusForbidden)
			ociError(w, r, http.StatusForbidden, codeDenied, "the repository is outside this namespace's prefix "+ns.prefix+"/")
			return
		}
	}
	for _, repo := range repos {
		allowed, err := g.auth.mayPush(r.Context(), id, repo)
		if err != nil {
			g.refuseUnavailable(w, r, route, id, err)
			return
		}
		if !allowed {
			g.audit(r, route, id, "denied: RBAC does not allow push on "+repo, http.StatusForbidden)
			ociError(w, r, http.StatusForbidden, codeDenied, "this ServiceAccount may not push "+repo)
			return
		}
	}
	g.audit(r, route, id, "allowed", 0)
	out := r.Clone(r.Context())
	out.URL.Path, out.URL.RawPath, out.URL.RawQuery = route.path, "", route.query
	g.write.ServeHTTP(w, out)
}

// refuseUnavailable answers an apiserver that could not, or was not allowed
// to, answer.
func (g *gate) refuseUnavailable(w http.ResponseWriter, r *http.Request, route gateRoute, id pushIdentity, err error) {
	if errors.Is(err, errRateLimited) {
		g.audit(r, route, id, "refused: token review rate limit", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "1")
		ociError(w, r, http.StatusTooManyRequests, codeTooMany, "too many pushes are being authorized; retry")
		return
	}
	g.log.Warn("ingest registry gate: the apiserver could not answer an authorization", "err", err)
	g.audit(r, route, id, "unavailable: apiserver", http.StatusServiceUnavailable)
	ociError(w, r, http.StatusServiceUnavailable, codeUnavailable, "the cluster could not authorize this push; retry")
}

// basicPassword returns the password of the request's one Basic Authorization
// header. The username is ignored: the token is the whole credential.
func basicPassword(r *http.Request) (string, bool) {
	hs := r.Header.Values("Authorization")
	if len(hs) != 1 {
		return "", false
	}
	scheme, enc, ok := strings.Cut(hs[0], " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	// A base64 encoding of an 8 KiB token plus a username: anything longer is
	// not one, and is refused before it is decoded.
	if len(enc) > 2*maxTokenBytes {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", false
	}
	_, pass, ok := strings.Cut(string(raw), ":")
	if !ok || pass == "" {
		return "", false
	}
	return pass, true
}

// challenge answers 401 with the Basic challenge a registry client logs in on.
func (g *gate) challenge(w http.ResponseWriter, r *http.Request, msg string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+gateRealm+`"`)
	ociError(w, r, http.StatusUnauthorized, codeUnauthorized, msg)
}

// audit writes the one line a write decision leaves: who, which namespace and
// repository, what, and the outcome. Never the token, never a header.
func (g *gate) audit(r *http.Request, route gateRoute, id pushIdentity, decision string, status int) {
	attrs := []any{
		"decision", decision,
		"op", route.op.String(),
		"method", r.Method,
		"repo", route.repo,
		"user", id.username,
		"namespace", id.namespace,
		"remote", r.RemoteAddr,
	}
	if route.from != "" {
		attrs = append(attrs, "from", route.from)
	}
	if status != 0 {
		attrs = append(attrs, "status", status)
	}
	g.log.Info("ingest registry push decision", attrs...)
}

// ociError writes an OCI distribution error body. A refusal of a request that
// carries a body closes the connection: the body was never read, and draining
// it would be reading an upload nobody authorized.
func ociError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	if r.ContentLength != 0 || r.Header.Get("Expect") != "" {
		w.Header().Set("Connection", "close")
	}
	body, _ := json.Marshal(map[string]any{
		"errors": []map[string]any{{"code": code, "message": msg}},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
