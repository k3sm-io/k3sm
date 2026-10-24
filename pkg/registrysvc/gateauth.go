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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The push gate's authorization: a pod pushes with its own projected
// ServiceAccount token, and the gate asks the apiserver, never a stored
// password, whether that push is allowed. Three questions, in order, each only
// when the one before it said yes:
//
//  1. Is the token valid FOR THIS REGISTRY? A TokenReview bound to
//     RegistryAudience, so a token minted for anything else (the default API
//     token among them) is refused, and the namespace is read from the
//     reviewed username and nowhere else.
//  2. Does the namespace opt in, and does the repository sit under the prefix
//     it opted in with? The PushLabel on the namespace must carry the
//     namespace's own name, which is its one prefix, so a prefix is held by
//     exactly one namespace; a repository must have at least one component
//     below it.
//  3. May this identity push this repository? A SubjectAccessReview for the
//     virtual resource PushAPIGroup/PushResource, verb PushVerb, in the
//     token's namespace, named for the repository: ordinary RBAC, bound by the
//     namespace to the ServiceAccounts it chooses (pkg/rbac's
//     k3sm:registry-pusher role).
//
// The answers are cached for seconds (a positive token review never beyond the
// token's own expiry), so a revoked binding or a removed label takes effect
// within those seconds and the apiserver sees one review per burst, not one per
// blob chunk.
const (
	// RegistryAudience is the audience a pod's projected token must be minted
	// for to push.
	RegistryAudience = "k3sm-registry"
	// PushLabel is the namespace label that opts a namespace in. Its value
	// must be the namespace's own name, which is the one repository prefix the
	// namespace may push under.
	PushLabel = "k3sm.io/registry-push"
	// PushAPIGroup, PushResource and PushVerb are the SubjectAccessReview's
	// virtual resource and verb. pkg/rbac's k3sm:registry-pusher grants them.
	PushAPIGroup = "registry.k3sm.io"
	PushResource = "repositories"
	PushVerb     = "push"
)

const (
	// maxTokenBytes bounds the password a push presents before it is ever sent
	// for review. A projected token is well under 2 KiB.
	maxTokenBytes = 8 << 10
	// tokenPositiveTTL, tokenNegativeTTL, namespaceTTL and accessTTL are the
	// cache lifetimes: how long a revocation can take to land, per question.
	tokenPositiveTTL = 30 * time.Second
	tokenNegativeTTL = 5 * time.Second
	namespaceTTL     = 5 * time.Second
	accessTTL        = 10 * time.Second
	// reviewTimeout bounds one call to the apiserver.
	reviewTimeout = 5 * time.Second
	// tokenReviewRate and tokenReviewBurst bound the TokenReviews the gate
	// sends, across every caller: a flood of distinct garbage tokens costs the
	// apiserver this much and no more.
	tokenReviewRate  = 20.0
	tokenReviewBurst = 40.0
	// cacheMaxEntries bounds each cache's memory. A full cache drops its
	// expired entries and, if still full, starts over: the cost is extra
	// reviews, never a wrong answer.
	cacheMaxEntries = 4096
)

// TokenReviewer is the slice of the Kubernetes API the gate validates a token
// through. cs.AuthenticationV1().TokenReviews() satisfies it.
type TokenReviewer interface {
	Create(ctx context.Context, tr *authnv1.TokenReview, opts metav1.CreateOptions) (*authnv1.TokenReview, error)
}

// AccessReviewer is the slice the gate authorizes a push through.
// cs.AuthorizationV1().SubjectAccessReviews() satisfies it.
type AccessReviewer interface {
	Create(ctx context.Context, sar *authzv1.SubjectAccessReview, opts metav1.CreateOptions) (*authzv1.SubjectAccessReview, error)
}

// NamespaceLabels is the slice the gate reads a namespace's push label
// through: a Get by name, never a list or a watch.
// cs.CoreV1().Namespaces() satisfies it.
type NamespaceLabels interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Namespace, error)
}

// GateAuth is the gate's three apiserver clients, all of which must run under
// the gate's own narrow identity. A GateAuth missing any of them serves reads
// and refuses every write with 503.
type GateAuth struct {
	Tokens     TokenReviewer
	Access     AccessReviewer
	Namespaces NamespaceLabels
}

// complete reports whether every client is present.
func (a GateAuth) complete() bool {
	return a.Tokens != nil && a.Access != nil && a.Namespaces != nil
}

// pushIdentity is a reviewed ServiceAccount token's user.
type pushIdentity struct {
	username, uid string
	groups        []string
	extra         map[string]authzv1.ExtraValue
	namespace     string
}

// errUnavailable marks an apiserver that could not answer: the request is
// refused with 503, and nothing is cached.
var errUnavailable = errors.New("the apiserver could not answer")

// errRateLimited marks a TokenReview the global limiter refused.
var errRateLimited = errors.New("too many token reviews")

// tokenResult is a token review's cached outcome: an identity, or the reason
// it is not one.
type tokenResult struct {
	id     pushIdentity
	reason string // non-empty: refuse with 401 and this reason
}

// namespaceResult is a namespace's cached push prefix; "" means the namespace
// does not opt in (absent, unlabelled, or labelled with an invalid value).
type namespaceResult struct {
	prefix string
	reason string
}

// authorizer holds the caches in front of GateAuth.
type authorizer struct {
	auth GateAuth
	now  func() time.Time

	tokens     *ttlCache[tokenResult]
	namespaces *ttlCache[namespaceResult]
	access     *ttlCache[bool]
	flight     singleflight.Group
	limiter    *tokenBucket
}

func newAuthorizer(auth GateAuth, now func() time.Time) *authorizer {
	return &authorizer{
		auth:       auth,
		now:        now,
		tokens:     newTTLCache[tokenResult](cacheMaxEntries),
		namespaces: newTTLCache[namespaceResult](cacheMaxEntries),
		access:     newTTLCache[bool](cacheMaxEntries),
		limiter:    newTokenBucket(tokenReviewRate, tokenReviewBurst, now),
	}
}

// tokenShapeOK is the precheck that runs before any review: a JWT is three
// non-empty base64url segments, and a password longer than maxTokenBytes is
// not one.
func tokenShapeOK(tok string) bool {
	if tok == "" || len(tok) > maxTokenBytes {
		return false
	}
	segs := strings.Split(tok, ".")
	if len(segs) != 3 {
		return false
	}
	for _, s := range segs {
		if s == "" {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// tokenExpiry reads the exp claim of a JWT WITHOUT verifying it. It is used
// only to SHORTEN how long a review is cached, never to accept a token, so an
// unverified claim can do no harm: a forged far-future exp is capped by
// tokenPositiveTTL, and a forged past exp only costs a review.
func tokenExpiry(tok string) (time.Time, bool) {
	segs := strings.Split(tok, ".")
	if len(segs) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// serviceAccountUser parses system:serviceaccount:<namespace>:<name>, the only
// username a pushing identity may carry.
var serviceAccountUser = regexp.MustCompile(`^system:serviceaccount:([a-z0-9]([-a-z0-9]*[a-z0-9])?):([a-z0-9]([-a-z0-9.]*[a-z0-9])?)$`)

// reviewToken validates tok for RegistryAudience, through the cache.
func (a *authorizer) reviewToken(ctx context.Context, tok string) (tokenResult, error) {
	sum := sha256.Sum256([]byte(tok))
	key := hex.EncodeToString(sum[:])
	if r, ok := a.tokens.get(key, a.now()); ok {
		return r, nil
	}
	v, err, _ := a.flight.Do(key, func() (any, error) {
		if r, ok := a.tokens.get(key, a.now()); ok {
			return r, nil
		}
		if !a.limiter.allow() {
			return tokenResult{}, errRateLimited
		}
		// Detached from the first caller's cancellation, because every caller
		// sharing this flight waits on the one review.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reviewTimeout)
		defer cancel()
		resp, err := a.auth.Tokens.Create(rctx, &authnv1.TokenReview{
			Spec: authnv1.TokenReviewSpec{Token: tok, Audiences: []string{RegistryAudience}},
		}, metav1.CreateOptions{})
		if err != nil {
			return tokenResult{}, fmt.Errorf("%w: token review: %v", errUnavailable, err)
		}
		r := judgeTokenReview(resp)
		now := a.now()
		until := now.Add(tokenNegativeTTL)
		if r.reason == "" {
			until = now.Add(tokenPositiveTTL)
			if exp, ok := tokenExpiry(tok); ok && exp.Before(until) {
				until = exp
			}
		}
		a.tokens.put(key, r, until, now)
		return r, nil
	})
	if err != nil {
		return tokenResult{}, err
	}
	return v.(tokenResult), nil
}

// judgeTokenReview turns a TokenReview's status into an identity or a refusal.
func judgeTokenReview(resp *authnv1.TokenReview) tokenResult {
	if resp == nil || !resp.Status.Authenticated || resp.Status.Error != "" {
		return tokenResult{reason: "the token is not valid"}
	}
	if !slices.Contains(resp.Status.Audiences, RegistryAudience) {
		return tokenResult{reason: "the token is not minted for the " + RegistryAudience + " audience"}
	}
	u := resp.Status.User
	m := serviceAccountUser.FindStringSubmatch(u.Username)
	if m == nil {
		// Authenticated, but not as a ServiceAccount: there is no namespace to
		// authorize against. Kept as an identity with no namespace, so the
		// caller refuses it with 403 rather than asking for a different token.
		return tokenResult{id: pushIdentity{username: u.Username}}
	}
	extra := make(map[string]authzv1.ExtraValue, len(u.Extra))
	for k, v := range u.Extra {
		extra[k] = authzv1.ExtraValue(slices.Clone(v))
	}
	return tokenResult{id: pushIdentity{
		username:  u.Username,
		uid:       u.UID,
		groups:    slices.Clone(u.Groups),
		extra:     extra,
		namespace: m[1],
	}}
}

// pushPrefixValue is the grammar of a PushLabel value: one repository
// component.
var pushPrefixValue = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)

// namespacePrefix returns ns's push prefix, through the cache. "" with a
// reason means the namespace does not opt in.
func (a *authorizer) namespacePrefix(ctx context.Context, ns string) (namespaceResult, error) {
	if r, ok := a.namespaces.get(ns, a.now()); ok {
		return r, nil
	}
	rctx, cancel := context.WithTimeout(ctx, reviewTimeout)
	defer cancel()
	obj, err := a.auth.Namespaces.Get(rctx, ns, metav1.GetOptions{})
	var r namespaceResult
	switch {
	case apierrors.IsNotFound(err):
		r = namespaceResult{reason: "the namespace does not exist"}
	case err != nil:
		return namespaceResult{}, fmt.Errorf("%w: get namespace: %v", errUnavailable, err)
	default:
		v, ok := obj.Labels[PushLabel]
		switch {
		case !ok:
			r = namespaceResult{reason: "the namespace does not carry the " + PushLabel + " label"}
		case v != ns:
			// The value must name the namespace itself. Namespace names are
			// unique, so no two namespaces can hold one prefix, and the gate
			// needs no read of any namespace but the pushing one.
			r = namespaceResult{reason: "the namespace's " + PushLabel + " label must equal the namespace name: run kubectl label namespace " + ns + " " + PushLabel + "=" + ns + " --overwrite"}
		case !pushPrefixValue.MatchString(v) || len(v) > maxRepoNameLen:
			r = namespaceResult{reason: "the namespace's " + PushLabel + " label is not a valid repository prefix"}
		default:
			r = namespaceResult{prefix: v}
		}
	}
	now := a.now()
	a.namespaces.put(ns, r, now.Add(namespaceTTL), now)
	return r, nil
}

// underPrefix reports whether repo sits strictly below prefix: the prefix
// followed by '/' and at least one more component. repo == prefix is refused.
func underPrefix(repo, prefix string) bool {
	return prefix != "" && strings.HasPrefix(repo, prefix+"/") && len(repo) > len(prefix)+1
}

// mayPush asks whether id may push repo, through the cache.
func (a *authorizer) mayPush(ctx context.Context, id pushIdentity, repo string) (bool, error) {
	groups := slices.Clone(id.groups)
	slices.Sort(groups)
	key := strings.Join([]string{id.username, id.uid, strings.Join(groups, ","), id.namespace, repo}, "\x00")
	if ok, hit := a.access.get(key, a.now()); hit {
		return ok, nil
	}
	rctx, cancel := context.WithTimeout(ctx, reviewTimeout)
	defer cancel()
	resp, err := a.auth.Access.Create(rctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: id.namespace,
				Verb:      PushVerb,
				Group:     PushAPIGroup,
				Resource:  PushResource,
				Name:      repo,
			},
			User:   id.username,
			Groups: slices.Clone(id.groups),
			UID:    id.uid,
			Extra:  id.extra,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("%w: subject access review: %v", errUnavailable, err)
	}
	allowed := resp != nil && resp.Status.Allowed && !resp.Status.Denied
	now := a.now()
	a.access.put(key, allowed, now.Add(accessTTL), now)
	return allowed, nil
}

// ttlCache is a bounded map whose entries expire.
type ttlCache[V any] struct {
	mu  sync.Mutex // guards m
	m   map[string]ttlEntry[V]
	max int
}

type ttlEntry[V any] struct {
	v     V
	until time.Time
}

func newTTLCache[V any](max int) *ttlCache[V] {
	return &ttlCache[V]{m: map[string]ttlEntry[V]{}, max: max}
}

func (c *ttlCache[V]) get(key string, now time.Time) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || !now.Before(e.until) {
		var zero V
		return zero, false
	}
	return e.v, true
}

func (c *ttlCache[V]) put(key string, v V, until, now time.Time) {
	if !now.Before(until) {
		return // already expired: nothing to cache
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for k, e := range c.m {
			if !now.Before(e.until) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= c.max {
			c.m = map[string]ttlEntry[V]{}
		}
	}
	c.m[key] = ttlEntry[V]{v: v, until: until}
}

// tokenBucket is a minimal token-bucket rate limiter.
type tokenBucket struct {
	mu          sync.Mutex // guards tokens, last
	tokens      float64
	last        time.Time
	rate, burst float64
	now         func() time.Time
}

func newTokenBucket(rate, burst float64, now func() time.Time) *tokenBucket {
	return &tokenBucket{tokens: burst, last: now(), rate: rate, burst: burst, now: now}
}

// allow takes one token if one is available.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(b.burst, b.tokens+el*b.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
