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
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// TokenReviewer is the one call DelegatedAuth makes to authenticate a bearer
// token: the apiserver's TokenReview API. The node's own clientset satisfies it
// (AuthenticationV1().TokenReviews()); tests bind a fake.
type TokenReviewer interface {
	Create(ctx context.Context, tr *authnv1.TokenReview, opts metav1.CreateOptions) (*authnv1.TokenReview, error)
}

// SubjectAccessReviewer is the one call DelegatedAuth makes to authorize an
// authenticated user: the apiserver's SubjectAccessReview API. The node's own
// clientset satisfies it (AuthorizationV1().SubjectAccessReviews()); tests bind
// a fake.
type SubjectAccessReviewer interface {
	Create(ctx context.Context, sar *authzv1.SubjectAccessReview, opts metav1.CreateOptions) (*authzv1.SubjectAccessReview, error)
}

// Delegated-auth tunables. Each is a bound, not a knob: none is operator-settable.
const (
	// delegatedReviewTimeout bounds each TokenReview and SubjectAccessReview call.
	// A review that has not answered by then is a denial, never an allow.
	delegatedReviewTimeout = 5 * time.Second
	// delegatedAllowTTL is how long an ALLOW is reused. It is short on purpose: a
	// revoked token or a removed binding keeps reading node metrics for at most
	// this long. Two scrapes at metrics-server's pinned 15s resolution share one
	// pair of reviews.
	delegatedAllowTTL = 30 * time.Second
	// delegatedDenyTTL is how long a DEFINITIVE denial (the apiserver answered
	// "not authenticated" or "not allowed") is reused, so a caller retrying a bad
	// token cannot turn the node into a TokenReview amplifier. An error is never a
	// definitive denial and is never cached.
	delegatedDenyTTL = 5 * time.Second
	// delegatedCacheMax bounds the cache. The legitimate population is one or two
	// metrics-server replicas, so the bound only matters under abuse.
	delegatedCacheMax = 256
)

// DelegatedAuth admits a bearer token on the kubelet endpoint's read-only
// resource-metrics routes, and nowhere else, by asking the apiserver: a
// TokenReview authenticates the token, then a SubjectAccessReview asks whether
// that user may get nodes/metrics (on /metrics/resource) or nodes/stats (on
// /stats/summary) for THIS node by name. That is upstream kubelet's webhook
// authn/authz shape (--authentication-token-webhook, --authorization-mode=Webhook),
// as k3s runs it, restricted to the two routes metrics-server scrapes.
//
// Every failure denies: a review error, a timeout, an unauthenticated token, an
// empty username, a SAR that does not allow or that explicitly denies. There is
// no anonymous access. It is reachable only through KubeletEndpointAuth.Handler,
// which consults it only when the request presented NO client certificate.
//
// The node calls both review APIs with its own system:node:<name> identity. The
// apiserver's Node authorizer grants that identity create on tokenreviews and
// subjectaccessreviews through its static node rules (upstream
// bootstrappolicy.NodeRules, "needed to check API access"), so no RBAC object is
// added for this path.
type DelegatedAuth struct {
	nodeName string
	tokens   TokenReviewer
	access   SubjectAccessReviewer
	now      func() time.Time

	// mu guards cache. Reviews run with mu released, so a slow apiserver never
	// serializes the endpoint.
	mu    sync.Mutex
	cache map[delegatedKey]delegatedEntry
}

// delegatedKey identifies one cached decision: the token (by digest, so the
// cache never holds a credential) and the exact request path.
type delegatedKey struct {
	token [sha256.Size]byte
	path  string
}

// delegatedEntry is one cached definitive decision.
type delegatedEntry struct {
	status  int // http.StatusOK, StatusUnauthorized or StatusForbidden
	expires time.Time
}

// ErrDelegatedAuthIncomplete reports a DelegatedAuth built without a node name or
// without one of its two reviewers. Compare with errors.Is.
var ErrDelegatedAuthIncomplete = errors.New("provider: delegated kubelet auth needs a node name, a TokenReviewer and a SubjectAccessReviewer")

// NewDelegatedAuth returns the bearer-token admission for node nodeName, calling
// tokens and access for every review. All three are required.
func NewDelegatedAuth(nodeName string, tokens TokenReviewer, access SubjectAccessReviewer) (*DelegatedAuth, error) {
	if nodeName == "" || tokens == nil || access == nil {
		return nil, ErrDelegatedAuthIncomplete
	}
	return &DelegatedAuth{
		nodeName: nodeName,
		tokens:   tokens,
		access:   access,
		now:      time.Now,
		cache:    make(map[delegatedKey]delegatedEntry),
	}, nil
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
// ok is false when the header is absent or is not a bearer credential.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

// admit decides one bearer-token request and returns the HTTP status to answer
// with: http.StatusOK to serve it, else 401 or 403.
//
// The route gate comes first and makes no API call: a path outside
// vkadapter.TokenRouteSubresource, a non-GET method, or an escaped path is 403
// before the token is ever reviewed, so the token path cannot be used to reach
// exec, attach, port-forward or logs, and cannot be used as a TokenReview oracle
// on them either.
func (d *DelegatedAuth) admit(ctx context.Context, r *http.Request, token string) int {
	if r.Method != http.MethodGet || r.URL.RawPath != "" {
		return http.StatusForbidden
	}
	subresource, ok := vkadapter.TokenRouteSubresource(r.URL.Path)
	if !ok {
		return http.StatusForbidden
	}

	key := delegatedKey{token: sha256.Sum256([]byte(token)), path: r.URL.Path}
	if status, hit := d.lookup(key); hit {
		return status
	}

	status, definitive := d.review(ctx, token, subresource)
	if definitive {
		d.store(key, status)
	}
	return status
}

// review runs the TokenReview then the SubjectAccessReview. definitive is true
// only when the apiserver ANSWERED both questions it was asked; an error or a
// timeout is never definitive and so is never cached.
func (d *DelegatedAuth) review(ctx context.Context, token, subresource string) (status int, definitive bool) {
	rctx, cancel := context.WithTimeout(ctx, delegatedReviewTimeout)
	defer cancel()

	tr, err := d.tokens.Create(rctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token},
	}, metav1.CreateOptions{})
	if err != nil || tr == nil {
		return http.StatusUnauthorized, false
	}
	if !tr.Status.Authenticated || tr.Status.User.Username == "" {
		return http.StatusUnauthorized, true
	}

	user := tr.Status.User
	extra := make(map[string]authzv1.ExtraValue, len(user.Extra))
	for k, v := range user.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}
	sar, err := d.access.Create(rctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   user.Username,
			UID:    user.UID,
			Groups: user.Groups,
			Extra:  extra,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:        "get",
				Group:       "",
				Version:     "v1",
				Resource:    "nodes",
				Subresource: subresource,
				Name:        d.nodeName,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil || sar == nil {
		return http.StatusForbidden, false
	}
	if !sar.Status.Allowed || sar.Status.Denied {
		return http.StatusForbidden, true
	}
	return http.StatusOK, true
}

// lookup returns a cached, unexpired decision for key.
func (d *DelegatedAuth) lookup(key delegatedKey) (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.cache[key]
	if !ok {
		return 0, false
	}
	if !d.now().Before(e.expires) {
		delete(d.cache, key)
		return 0, false
	}
	return e.status, true
}

// store caches a definitive decision, allows for delegatedAllowTTL and denials
// for delegatedDenyTTL. At the size bound it first drops expired entries, then,
// if still full, an arbitrary one, so the map never grows past
// delegatedCacheMax.
func (d *DelegatedAuth) store(key delegatedKey, status int) {
	ttl := delegatedDenyTTL
	if status == http.StatusOK {
		ttl = delegatedAllowTTL
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if _, exists := d.cache[key]; !exists && len(d.cache) >= delegatedCacheMax {
		for k, e := range d.cache {
			if !now.Before(e.expires) {
				delete(d.cache, k)
			}
		}
		for k := range d.cache {
			if len(d.cache) < delegatedCacheMax {
				break
			}
			delete(d.cache, k)
		}
	}
	d.cache[key] = delegatedEntry{status: status, expires: now.Add(ttl)}
}
