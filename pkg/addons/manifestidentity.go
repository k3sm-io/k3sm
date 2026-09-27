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

package addons

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

// manifestTokenLifetime is the lifetime the reconciler asks for on each
// TokenRequest. The token lives only in this process's memory and is re-requested
// before it expires.
const manifestTokenLifetime = time.Hour

// NewManifestDirFromAdmin builds the manifest-directory reconciler for dir with a
// BOUNDED identity: every request it makes authenticates as the
// namespace/serviceAccount ServiceAccount, with a token minted by a TokenRequest
// through admin. The admin client is used for that TokenRequest and for nothing
// else; the admin config's credentials are stripped (rest.AnonymousClientConfig)
// before the reconciler's own clients are built from it, so an apply can never
// ride the system:masters identity.
//
// Nothing is contacted here: discovery is deferred to the first sweep, and the
// first token is requested on the first request.
func NewManifestDirFromAdmin(dir string, adminCfg *rest.Config, admin kubernetes.Interface, namespace, serviceAccount string, logger *slog.Logger) (*ManifestDir, error) {
	cfg := manifestRESTConfig(adminCfg, &saTokenSource{
		admin:     admin,
		namespace: namespace,
		name:      serviceAccount,
		now:       time.Now,
	})
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build manifest dynamic client: %w", err)
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build manifest discovery client: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build manifest event client: %w", err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	return NewManifestDir(dir, dyn, mapper, cs, logger), nil
}

// manifestRESTConfig derives the reconciler's client config from the admin one:
// the same apiserver and CA, NONE of the admin credentials, and a bearer token
// from src on every request.
func manifestRESTConfig(adminCfg *rest.Config, src *saTokenSource) *rest.Config {
	cfg := rest.AnonymousClientConfig(adminCfg)
	cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		return &bearerRoundTripper{next: rt, src: src}
	}
	return cfg
}

// saTokenSource mints and caches a ServiceAccount token through the TokenRequest
// API, re-requesting it once four fifths of its lifetime has passed.
type saTokenSource struct {
	admin     kubernetes.Interface
	namespace string
	name      string
	now       func() time.Time

	// mu guards token and refreshAt.
	mu        sync.Mutex
	token     string
	refreshAt time.Time
}

// Token returns a live token for the ServiceAccount, requesting a new one when
// none is cached or the cached one is due for refresh.
func (s *saTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Before(s.refreshAt) {
		return s.token, nil
	}
	seconds := int64(manifestTokenLifetime / time.Second)
	tr, err := s.admin.CoreV1().ServiceAccounts(s.namespace).CreateToken(ctx, s.name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &seconds},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("request a token for %s/%s: %w", s.namespace, s.name, err)
	}
	if tr.Status.Token == "" {
		return "", fmt.Errorf("request a token for %s/%s: empty token", s.namespace, s.name)
	}
	expiry := tr.Status.ExpirationTimestamp.Time
	if expiry.IsZero() || !expiry.After(now) {
		expiry = now.Add(manifestTokenLifetime)
	}
	s.token = tr.Status.Token
	s.refreshAt = now.Add(expiry.Sub(now) * 4 / 5)
	return s.token, nil
}

// bearerRoundTripper sets the ServiceAccount's bearer token on every request.
type bearerRoundTripper struct {
	next http.RoundTripper
	src  *saTokenSource
}

// RoundTrip authenticates req as the ServiceAccount and forwards it.
func (b *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := b.src.Token(req.Context())
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close() // RoundTrip must close the body even when it fails
		}
		return nil, fmt.Errorf("manifest identity: %w", err)
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return b.next.RoundTrip(r)
}
