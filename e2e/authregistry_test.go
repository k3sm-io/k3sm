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

// No build tag: this is the unit-tier proof of the TestM10_ImagePullSecret
// fixture. It needs no cluster and no network beyond loopback.

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestAuthRegistryFixture proves the authed-registry and native-image fixture
// without a cluster: the registry refuses anonymous and wrong-credential access
// with a Basic challenge, serves an authenticated pull of an image pushed to it,
// and the image is a darwin/arm64 OCI image whose single layer holds the payload
// at /<name>, executable, with the entrypoint and run label the criterion relies on.
func TestAuthRegistryFixture(t *testing.T) {
	const (
		user    = "testuser"
		pass    = "testpass"
		repo    = "e2e/pullprobe"
		tag     = "unit"
		payload = "pullprobe"
	)
	ctx := context.Background()
	reg := newAuthRegistry(user, pass)
	// Every round trip below goes through reg itself, in memory: the unit tier
	// opens no socket (internal/testgate's real-socket gate).
	mem := remote.WithTransport(reg)

	contextDir := t.TempDir()
	content := []byte("\xcf\xfa\xed\xfe fixture payload, not a real Mach-O")
	if err := os.WriteFile(filepath.Join(contextDir, payload), content, 0o755); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	img, err := buildNativeImage(contextDir, payload, "unit-run", t.TempDir())
	if err != nil {
		t.Fatalf("buildNativeImage: %v", err)
	}
	if err := reg.Push(ctx, repo, tag, img, mem); err != nil {
		t.Fatalf("push: %v", err)
	}
	ref, err := name.ParseReference(reg.Ref(repo, tag))
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}

	t.Run("v2 ping without credentials is challenged", func(t *testing.T) {
		resp, err := (&http.Client{Transport: reg}).Get("http://" + reg.Host + "/v2/")
		if err != nil {
			t.Fatalf("GET /v2/: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous /v2/: status %d, want 401", resp.StatusCode)
		}
		if got, want := resp.Header.Get("WWW-Authenticate"), `Basic realm="`+registryRealm+`"`; got != want {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
		}
	})

	for _, tc := range []struct {
		name string
		auth authn.Authenticator
	}{
		{"anonymous pull is refused", authn.Anonymous},
		{"wrong password is refused", &authn.Basic{Username: user, Password: "wrong"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuth(tc.auth), mem)
			var terr *transport.Error
			if !errors.As(err, &terr) || terr.StatusCode != http.StatusUnauthorized {
				t.Fatalf("pull: err = %v, want a 401 transport error", err)
			}
			for _, q := range reg.ManifestRequests(repo, tag, 0) {
				if !q.Authed && q.Status != http.StatusUnauthorized {
					t.Fatalf("unauthenticated manifest request answered %d: %+v", q.Status, q)
				}
			}
		})
	}

	t.Run("authenticated pull serves the native image", func(t *testing.T) {
		before := len(reg.Requests())
		got, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuth(&authn.Basic{Username: user, Password: pass}), mem)
		if err != nil {
			t.Fatalf("authed pull: %v", err)
		}
		wantDigest, err := img.Digest()
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		gotDigest, err := got.Digest()
		if err != nil {
			t.Fatalf("pulled digest: %v", err)
		}
		if gotDigest != wantDigest {
			t.Fatalf("pulled digest %s, pushed %s", gotDigest, wantDigest)
		}
		served := false
		for _, q := range reg.ManifestRequests(repo, tag, before) {
			if q.Authed && q.Method == http.MethodGet && q.Status == http.StatusOK {
				served = true
			}
		}
		if !served {
			t.Fatalf("no authed 200 GET of the manifest recorded: %+v", reg.Requests())
		}

		cfg, err := got.ConfigFile()
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		if cfg.OS != "darwin" || cfg.Architecture != "arm64" {
			t.Fatalf("platform %s/%s, want darwin/arm64", cfg.OS, cfg.Architecture)
		}
		if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != "/"+payload {
			t.Fatalf("entrypoint %q, want [/%s]", cfg.Config.Entrypoint, payload)
		}
		if cfg.Config.Labels["io.k3sm.e2e.run"] != "unit-run" {
			t.Fatalf("labels %v, want io.k3sm.e2e.run=unit-run", cfg.Config.Labels)
		}

		layers, err := got.Layers()
		if err != nil {
			t.Fatalf("layers: %v", err)
		}
		if len(layers) != 1 {
			t.Fatalf("%d layers, want 1", len(layers))
		}
		rc, err := layers[0].Uncompressed()
		if err != nil {
			t.Fatalf("open layer: %v", err)
		}
		defer func() { _ = rc.Close() }()
		tr := tar.NewReader(rc)
		found := false
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("read layer: %v", err)
			}
			if hdr.Name != payload && hdr.Name != "/"+payload && hdr.Name != "./"+payload {
				continue
			}
			found = true
			if hdr.Typeflag != tar.TypeReg || hdr.Mode&0o111 == 0 {
				t.Fatalf("layer entry %q: type %c mode %o, want an executable regular file", hdr.Name, hdr.Typeflag, hdr.Mode)
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read layer entry: %v", err)
			}
			if !bytes.Equal(b, content) {
				t.Fatalf("layer entry content differs from the payload")
			}
		}
		if !found {
			t.Fatalf("layer carries no %s entry", payload)
		}
	})

	// The node's own fetcher, not just ggcr: runtimed's production FetchFunc is
	// what the e2e pod's pull goes through, so this is the unit-tier proof that
	// it speaks plain HTTP to a loopback registry authority (ggcr infers http
	// for one; nothing is configured), presents a docker-config credential, and
	// is refused without one. RemoteFetch takes no transport option, so the seam
	// is go-containerregistry's package-level remote.DefaultTransport, swapped
	// for the in-memory registry and restored. The registry refuses https, as
	// the real plain-HTTP listener does, so a successful fetch here is the
	// https-then-http fallback the node's pull takes.
	t.Run("runtimed RemoteFetch pulls with the credential and is refused without", func(t *testing.T) {
		saved := remote.DefaultTransport
		t.Cleanup(func() { remote.DefaultTransport = saved })
		var (
			mu      sync.Mutex // guards schemes; ggcr may fetch concurrently
			schemes []string
		)
		remote.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			schemes = append(schemes, req.URL.Scheme+"://"+req.URL.Host)
			mu.Unlock()
			return reg.RoundTrip(req)
		})
		policy := image.PlatformPolicy{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC}
		cred := &image.RegistryCredential{Auth: basicAuthToken(user, pass)}
		got, err := image.RemoteFetch(ctx, reg.Ref(repo, tag), cred, policy)
		if err != nil {
			t.Fatalf("RemoteFetch with credential: %v", err)
		}
		gotDigest, err := got.Digest()
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		wantDigest, _ := img.Digest()
		if gotDigest != wantDigest {
			t.Fatalf("fetched %s, pushed %s", gotDigest, wantDigest)
		}
		_, err = image.RemoteFetch(ctx, reg.Ref(repo, tag), nil, policy)
		var terr *transport.Error
		if !errors.As(err, &terr) || terr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous RemoteFetch: err = %v, want a 401 transport error", err)
		}
		// The e2e negative control's non-vacuity predicate: an anonymous pull
		// reaches the MANIFEST and is refused there, not only at the /v2/ ping.
		refused := false
		for _, q := range reg.ManifestRequests(repo, tag, 0) {
			if !q.Authed && q.Status == http.StatusUnauthorized {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("no refused anonymous manifest request recorded: %+v", reg.Requests())
		}
		mu.Lock()
		defer mu.Unlock()
		plain := false
		for _, sch := range schemes {
			if sch == "http://"+reg.Host {
				plain = true
			}
		}
		if !plain {
			t.Fatalf("RemoteFetch never reached http://%s (plain HTTP to the loopback authority); round trips: %v", reg.Host, schemes)
		}
	})

	t.Run("distinct run labels give distinct digests", func(t *testing.T) {
		other, err := buildNativeImage(contextDir, payload, "unit-run-2", t.TempDir())
		if err != nil {
			t.Fatalf("buildNativeImage: %v", err)
		}
		a, _ := img.Digest()
		b, _ := other.Digest()
		if a == b {
			t.Fatalf("two run labels produced one digest %s; a negative control could be served from cache", a)
		}
	})

	t.Run("dockerconfigjson carries the credential for the registry host", func(t *testing.T) {
		raw, err := dockerConfigJSON(reg.Host, user, pass)
		if err != nil {
			t.Fatalf("dockerConfigJSON: %v", err)
		}
		var cfg struct {
			Auths map[string]struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Auth     string `json:"auth"`
			} `json:"auths"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		e, ok := cfg.Auths[reg.Host]
		if !ok || len(cfg.Auths) != 1 {
			t.Fatalf("auths %v, want exactly %s", cfg.Auths, reg.Host)
		}
		if e.Username != user || e.Password != pass || e.Auth != "dGVzdHVzZXI6dGVzdHBhc3M=" {
			t.Fatalf("entry %+v does not carry %s/%s", e, user, pass)
		}
	})
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
