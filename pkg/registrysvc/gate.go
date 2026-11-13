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
	"context"
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

	"k3sm.io/k3sm/pkg/ociregistry/api"
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

// gateUpstreamHeaderTimeout bounds how long the gate waits for the loopback
// registry's response headers once a request, body included, has been written
// (http.Transport.ResponseHeaderTimeout starts its clock only then, so a blob
// streaming for minutes is not cut off). A registry that accepted the
// connection and has not answered in this long is wedged: the client gets a
// 502, which frees the gate's connection and goroutine instead of holding them
// until the client gives up.
// It holds reads, upload status and every other request the registry answers
// from what it already has; 30s rather than the dial's 1s leaves room for a
// busy disk. A manifest PUT and the blob upload requests wait on work the
// registry does before it answers, and have their own bounds: see
// gateManifestHeaderTimeout and gateUploadHeaderTimeout.
const gateUpstreamHeaderTimeout = 30 * time.Second

// gateManifestHeaderTimeout is the response-header bound of a manifest PUT.
// The registry answers one only after it holds the repository's lock, which a
// collection sweep of that repository holds for the whole sweep, and after it
// links every blob the manifest names, which can re-hash a large blob from
// disk; a healthy push can wait well past 30s on its last request.
// Invariant: it is CollectTimeout plus gateManifestCollectMargin. A sweep
// holds the lock for up to CollectTimeout, and a PUT queued behind a full
// sweep still has to link and re-hash its blobs after it gets the lock, so a
// bound of exactly CollectTimeout would cut a healthy PUT; the margin is the
// room for that work. Past the bound a registry still doing it is taken to be
// hung, so the PUT is cut there with a 502. The relation is in code so tuning
// CollectTimeout moves the bound with it; TestGateManifestBoundCoversCollect
// holds the invariant.
const gateManifestHeaderTimeout = CollectTimeout + gateManifestCollectMargin

// gateManifestCollectMargin is how long past CollectTimeout a manifest PUT
// may wait for headers: the link and re-hash work it does after waiting out a
// full collection sweep for the repository's lock.
const gateManifestCollectMargin = 5 * time.Minute

// gateUploadHeaderTimeout is the response-header bound of a blob upload
// request (the POST that starts or mounts, a PATCH, the final PUT). The
// registry commits an upload before it writes a header, and a commit whose
// streamed hash does not cover the session re-hashes the file from disk, so a
// healthy commit of a large layer can take far longer than 30s. The registry
// bounds such a request itself by api.DefaultUploadTimeout (the serve child
// does not override it), and the gate uses that same bound.
const gateUploadHeaderTimeout = api.DefaultUploadTimeout

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
	// bodyProgress is how long a forwarded response body may go without a
	// byte from the registry before the gate cuts it.
	bodyProgress time.Duration

	// read forwards reads and write every authorized write not named below,
	// both over a transport with the upstream response-header bound; manifest
	// forwards manifest PUTs over one with the manifest bound, and upload blob
	// upload requests over one with the upload bound. proxyFor picks one.
	read, write, manifest, upload *httputil.ReverseProxy
}

// gateConfig configures a gate.
type gateConfig struct {
	Upstream   string
	Auth       GateAuth
	Credential Credential
	Logger     *slog.Logger
	// Now is the clock the caches read; nil means time.Now.
	Now func() time.Time
	// Transport is the round tripper to the upstream, for every request; nil
	// means three loopback transports, one per response-header bound.
	Transport http.RoundTripper
	// UpstreamHeaderTimeout bounds how long the loopback transport waits for
	// the registry's response headers to a read, an upload status or any
	// other request not named below; zero means gateUpstreamHeaderTimeout.
	// Ignored when Transport is set.
	UpstreamHeaderTimeout time.Duration
	// ManifestHeaderTimeout is that bound for a manifest PUT; zero means
	// gateManifestHeaderTimeout. Ignored when Transport is set.
	ManifestHeaderTimeout time.Duration
	// UploadHeaderTimeout is that bound for a blob upload request (start or
	// mount, chunk, finish); zero means gateUploadHeaderTimeout. Ignored when
	// Transport is set.
	UploadHeaderTimeout time.Duration
	// UpstreamBodyProgress bounds how long a registry response body, once its
	// headers have arrived, may go without a byte before the gate cuts it;
	// zero means gateUpstreamBodyProgress. It applies with any Transport.
	UpstreamBodyProgress time.Duration
}

// newGate builds a gate.
func newGate(cfg gateConfig) *gate {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.UpstreamHeaderTimeout <= 0 {
		cfg.UpstreamHeaderTimeout = gateUpstreamHeaderTimeout
	}
	if cfg.ManifestHeaderTimeout <= 0 {
		cfg.ManifestHeaderTimeout = gateManifestHeaderTimeout
	}
	if cfg.UploadHeaderTimeout <= 0 {
		cfg.UploadHeaderTimeout = gateUploadHeaderTimeout
	}
	if cfg.UpstreamBodyProgress <= 0 {
		cfg.UpstreamBodyProgress = gateUpstreamBodyProgress
	}
	manifestTransport, uploadTransport := cfg.Transport, cfg.Transport
	if cfg.Transport == nil {
		cfg.Transport = loopbackTransport(cfg.UpstreamHeaderTimeout)
		manifestTransport = loopbackTransport(cfg.ManifestHeaderTimeout)
		uploadTransport = loopbackTransport(cfg.UploadHeaderTimeout)
	}
	g := &gate{upstream: cfg.Upstream, log: cfg.Logger, cred: cfg.Credential, bodyProgress: cfg.UpstreamBodyProgress}
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
	g.manifest = &httputil.ReverseProxy{
		Rewrite:        func(pr *httputil.ProxyRequest) { g.rewrite(pr, true) },
		FlushInterval:  -1,
		Transport:      manifestTransport,
		ModifyResponse: g.modifyResponse,
		ErrorHandler:   g.writeError,
		ErrorLog:       errLog,
	}
	g.upload = &httputil.ReverseProxy{
		Rewrite:        func(pr *httputil.ProxyRequest) { g.rewrite(pr, true) },
		FlushInterval:  -1,
		Transport:      uploadTransport,
		ModifyResponse: g.modifyResponse,
		ErrorHandler:   g.writeError,
		ErrorLog:       errLog,
	}
	return g
}

// proxyFor is the reverse proxy a request of class op is forwarded through,
// and so the response-header bound it is held to: a read anonymously, a
// manifest PUT and the blob upload requests over their own transports, an
// upload status as an authorized write over the upstream one. opInvalid and
// opRefused are never forwarded; they fall to the default.
// TestGateProxyForEveryOperation fails for an operation with no case here.
func (g *gate) proxyFor(op gateOp) *httputil.ReverseProxy {
	switch op {
	case opRead:
		return g.read
	case opManifestPut:
		return g.manifest
	case opUploadStart, opUploadChunk, opUploadFinish:
		return g.upload
	case opUploadStatus:
		return g.write
	default:
		return g.write
	}
}

// loopbackTransport is the transport to the loopback registry, waiting at
// most headerTimeout for response headers once a request is written.
func loopbackTransport(headerTimeout time.Duration) *http.Transport {
	d := &net.Dialer{Timeout: relayDialTimeout}
	return &http.Transport{
		DialContext:           d.DialContext,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
	}
}

// rewrite points the outbound request at the loopback registry. Every client
// credential is dropped, and so is the legacy zot UI session header, kept for the
// one release a reclaimed zot child may still answer, so a forwarded
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

// modifyResponse keeps the registry's session cookies inside this process,
// turns an absolute Location naming the loopback upstream into a path, so a
// client keeps talking to the gate, and puts the response body under the
// progress bound, so a registry that stops sending mid-body loses the
// connection one window later instead of holding it until the client gives up.
func (g *gate) modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && u.Host == g.upstream {
			u.Scheme, u.Host = "", ""
			resp.Header.Set("Location", u.String())
		}
	}
	if watchesBody(resp) {
		var method, path string
		if resp.Request != nil {
			method, path = resp.Request.Method, resp.Request.URL.Path
		}
		resp.Body = newProgressBody(resp.Body, g.bodyProgress, func(passed int64, elapsed time.Duration) {
			g.log.Warn("ingest registry gate cut a local registry response that stopped sending",
				"target", g.upstream, "method", method, "path", path, "window", g.bodyProgress,
				"bytes", passed, "elapsed", elapsed)
		})
	}
	return nil
}

// readError ends a read whose upstream could not be reached by closing the
// connection without a response: what the raw relay did, and what a peer's
// puller already reads as "this mirror does not have it". A read the client
// itself abandoned is no fault of the registry and is logged at Debug.
func (g *gate) readError(w http.ResponseWriter, r *http.Request, err error) {
	level := slog.LevelWarn
	if errors.Is(err, context.Canceled) {
		level = slog.LevelDebug
	}
	g.log.Log(r.Context(), level, "ingest registry gate could not reach the local registry",
		"target", g.upstream, "method", r.Method, "path", r.URL.Path, "err", err)
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, herr := hj.Hijack(); herr == nil {
			_ = c.Close()
			return
		}
	}
	w.WriteHeader(http.StatusBadGateway)
}

// writeError answers an authorized write the registry did not take. A write
// the client itself abandoned is no fault of the registry and is logged at
// Debug.
func (g *gate) writeError(w http.ResponseWriter, r *http.Request, err error) {
	level := slog.LevelWarn
	if errors.Is(err, context.Canceled) {
		level = slog.LevelDebug
	}
	g.log.Log(r.Context(), level, "ingest registry gate could not forward an authorized write",
		"target", g.upstream, "method", r.Method, "path", r.URL.Path, "err", err)
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
		g.proxyFor(opRead).ServeHTTP(w, r)
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
	repos := []string{route.repo}
	if route.from != "" {
		repos = append(repos, route.from)
	}
	// The builder is authorized cluster-wide (mayPush asks with no namespace),
	// so it skips the namespace label and prefix, and only it does: every other
	// ServiceAccount is held to its namespace's opt-in and prefix.
	if !id.isBuilder() {
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
		for _, repo := range repos {
			if !underPrefix(repo, ns.prefix) {
				g.audit(r, route, id, "denied: "+repo+" is outside the namespace prefix "+ns.prefix+"/", http.StatusForbidden)
				ociError(w, r, http.StatusForbidden, codeDenied, "the repository is outside this namespace's prefix "+ns.prefix+"/")
				return
			}
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
	g.proxyFor(route.op).ServeHTTP(w, out)
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
