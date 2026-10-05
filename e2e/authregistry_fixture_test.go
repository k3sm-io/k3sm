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

package e2e

// This file carries NO build tag on purpose, and is a _test.go file so the
// fixture never enters a non-test build. It is the fixture behind
// TestM10_ImagePullSecret (an e2e criterion), and it is also exercised by a
// unit-tier test (authregistry_test.go) that needs no cluster, so the fixture is
// proven on any machine before the lab run depends on it.

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/oci"
)

// registryRealm is the realm the fixture's basic-auth challenge names.
const registryRealm = "k3sm-e2e"

// registryRequest is one request the fixture registry answered, recorded so a
// criterion can prove WHO reached the registry and what they were told — the
// evidence that separates "the node was refused" from "the node never got here".
type registryRequest struct {
	Method string
	Path   string
	// Authed reports whether the request carried the fixture's own credential.
	Authed bool
	// Status is the HTTP status the fixture wrote.
	Status int
}

// memRegistryHost is the authority an authRegistry answers to before (or
// without) being given a listener. It is never dialled: the unit tier reaches
// the registry through authRegistry.RoundTrip, in memory. It is a loopback
// spelling so go-containerregistry infers plain http for it, exactly as it does
// for the real listener the e2e criterion binds.
const memRegistryHost = "127.0.0.1:5000"

// authRegistry is an in-process OCI distribution registry (go-containerregistry's
// pkg/registry) behind HTTP basic auth. Every request, /v2/ included, needs the
// one configured credential; anything else gets 401 with a
// `WWW-Authenticate: Basic` challenge, which is the shape a docker-config
// credential answers.
//
// It is an http.Handler and owns no socket. The unit tier talks to it through
// RoundTrip (in memory); the e2e criterion serves it on 127.0.0.1 over plain
// HTTP (listenAuthRegistry, e2e-tagged). go-containerregistry, and therefore
// runtimed's puller, infers http for a loopback registry authority, so that
// address is pullable by an image puller on the SAME host and by nothing else.
type authRegistry struct {
	inner http.Handler
	user  string
	pass  string

	// Host is the registry authority: memRegistryHost until a listener sets
	// the real "127.0.0.1:<port>".
	Host string

	// mu guards reqs; the handler appends from server goroutines.
	mu   sync.Mutex
	reqs []registryRequest
}

// newAuthRegistry builds the fixture registry. It opens nothing.
func newAuthRegistry(user, pass string) *authRegistry {
	return &authRegistry{
		// The registry's request log is discarded: it would only add noise to
		// a test's output, and nothing a pull sends should be echoed anywhere.
		inner: registry.New(registry.Logger(log.New(io.Discard, "", 0))),
		user:  user,
		pass:  pass,
		Host:  memRegistryHost,
	}
}

// ServeHTTP answers one registry request, refusing any that lacks the
// credential, and records it.
func (r *authRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	authed := r.authorized(req)
	if !authed {
		rec.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", registryRealm))
		http.Error(rec, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`, http.StatusUnauthorized)
	} else {
		r.inner.ServeHTTP(rec, req)
	}
	r.mu.Lock()
	r.reqs = append(r.reqs, registryRequest{Method: req.Method, Path: req.URL.Path, Authed: authed, Status: rec.status})
	r.mu.Unlock()
}

// RoundTrip serves req in memory, making the registry its own
// http.RoundTripper: the unit tier's seam in place of a socket.
//
// It answers only http, as the plain-HTTP listener the e2e criterion binds
// does: go-containerregistry probes a loopback registry over https first and
// falls back to http, and an in-memory registry that also answered https would
// let a test pass on a path the real one never takes.
func (r *authRegistry) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "http" {
		return nil, fmt.Errorf("%s: the fixture registry serves plain HTTP only", req.URL.Redacted())
	}
	in := req.Clone(req.Context())
	if in.Body == nil {
		in.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, in)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// authorized reports whether req carries exactly the fixture credential. The
// comparison is constant-time out of habit; the credential is a fake.
func (r *authRegistry) authorized(req *http.Request) bool {
	u, p, ok := req.BasicAuth()
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(u), []byte(r.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(p), []byte(r.pass)) == 1
	return userOK && passOK
}

// Requests returns a copy of every request answered so far.
func (r *authRegistry) Requests() []registryRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]registryRequest(nil), r.reqs...)
}

// ManifestRequests returns the recorded requests for repo's manifest at tag,
// skipping the first since requests (pass a len(Requests()) taken earlier to
// exclude, for example, the test's own push).
func (r *authRegistry) ManifestRequests(repo, tag string, since int) []registryRequest {
	want := "/v2/" + repo + "/manifests/" + tag
	all := r.Requests()
	if since > len(all) {
		since = len(all)
	}
	var out []registryRequest
	for _, q := range all[since:] {
		if q.Path == want {
			out = append(out, q)
		}
	}
	return out
}

// Ref returns the full image reference for repo:tag on this registry.
func (r *authRegistry) Ref(repo, tag string) string {
	return r.Host + "/" + repo + ":" + tag
}

// Push uploads img as repo:tag using the fixture credential. opts are extra
// remote options; the unit tier passes remote.WithTransport(r).
func (r *authRegistry) Push(ctx context.Context, repo, tag string, img ggcrv1.Image, opts ...remote.Option) error {
	ref, err := name.ParseReference(r.Ref(repo, tag))
	if err != nil {
		return fmt.Errorf("parse %s: %w", r.Ref(repo, tag), err)
	}
	auth := &authn.Basic{Username: r.user, Password: r.pass}
	opts = append([]remote.Option{remote.WithContext(ctx), remote.WithAuth(auth)}, opts...)
	if err := remote.Write(ref, img, opts...); err != nil {
		return fmt.Errorf("push %s: %w", ref, err)
	}
	return nil
}

// statusRecorder captures the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records code and forwards it.
func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// dockerConfigJSON renders the `.dockerconfigjson` payload of a
// kubernetes.io/dockerconfigjson Secret for one registry, in the shape
// `kubectl create secret docker-registry` writes: username, password and the
// base64 "user:pass" auth string.
func dockerConfigJSON(host, user, pass string) ([]byte, error) {
	type entry struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Auth     string `json:"auth"`
	}
	return json.Marshal(struct {
		Auths map[string]entry `json:"auths"`
	}{Auths: map[string]entry{host: {Username: user, Password: pass, Auth: basicAuthToken(user, pass)}}})
}

// basicAuthToken is the base64("user:pass") form a docker config stores.
func basicAuthToken(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// buildNativeImage packages one host file as a native darwin/arm64 OCI image with
// the same packager `k3sm build` uses (pkg/oci), so the artifact is exactly what
// an operator's image would be: one uncompressed layer holding the file at /name
// (mode normalised to 0755 when executable), ENTRYPOINT ["/name"], and a label
// carrying runLabel so each call with a distinct label yields a distinct digest.
//
// contextDir must contain name; a Dockerfile is written beside it. tmpDir stages
// the layer tar and MUST outlive every use of the returned image, because the
// layer is read back from that file on push.
func buildNativeImage(contextDir, fileName, runLabel, tmpDir string) (ggcrv1.Image, error) {
	dockerfile := strings.Join([]string{
		"FROM scratch",
		fmt.Sprintf("COPY %s /%s", fileName, fileName),
		fmt.Sprintf("LABEL io.k3sm.e2e.run=%s", runLabel),
		fmt.Sprintf(`ENTRYPOINT ["/%s"]`, fileName),
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(contextDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return nil, fmt.Errorf("write Dockerfile: %w", err)
	}
	df, err := oci.Parse(strings.NewReader(dockerfile))
	if err != nil {
		return nil, fmt.Errorf("parse Dockerfile: %w", err)
	}
	bctx, err := oci.NewContext(contextDir)
	if err != nil {
		return nil, err
	}
	img, err := oci.Build(oci.Request{Dockerfile: df, Context: bctx, TmpDir: tmpDir})
	if err != nil {
		return nil, fmt.Errorf("build image: %w", err)
	}
	return img, nil
}
