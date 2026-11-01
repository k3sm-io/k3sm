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

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// The principals.
const (
	// UserPush is the local CLI's principal: read, write and delete.
	UserPush = "k3sm"
	// UserGate is the push gate's principal: read and write, never delete.
	UserGate = "k3sm-gate"
)

// Limits on what a request may present.
const (
	// MaxAuthorizationBytes is the longest Authorization header accepted.
	MaxAuthorizationBytes = 1024
	// MaxUserBytes is the longest user name accepted.
	MaxUserBytes = 64
	// MaxSecretBytes is the longest secret accepted.
	MaxSecretBytes = 256
	// MaxSources is the most sources whose failures are tracked at once.
	MaxSources = 4096
)

// Defaults for the failure bucket.
const (
	// DefaultBurst is how many failed authentications a source may make
	// before it is rate limited.
	DefaultBurst = 10
	// DefaultRefill is the time one failure token takes to come back.
	DefaultRefill = time.Second
)

// errBadCredential is a presented credential that does not verify, or an
// Authorization header this package does not accept. It is answered as
// api.ErrUnauthenticated.
var errBadCredential = errors.New("credential not accepted")

// Principal is one principal of the serve config: a user and the lowercase
// hex SHA-256 of its secret.
type Principal struct {
	User         string `json:"user"`
	SecretSHA256 string `json:"secretSHA256"`
}

// HashSecret returns the lowercase hex SHA-256 of secret, the form a
// Principal carries.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// permissions is the fixed matrix; anonymous is the empty user.
var permissions = map[string]map[api.Verb]bool{
	"":       {api.VerbRead: true},
	UserPush: {api.VerbRead: true, api.VerbWrite: true, api.VerbDelete: true},
	UserGate: {api.VerbRead: true, api.VerbWrite: true},
}

// Config configures an Access.
type Config struct {
	// Principals are the k3sm and k3sm-gate principals, exactly once each.
	Principals []Principal
	// Logger receives a record for every authentication failure, denial and
	// rate-limited request; nil discards them.
	Logger *slog.Logger
	// Burst and Refill shape each source's failure bucket (DefaultBurst and
	// DefaultRefill when zero).
	Burst  int
	Refill time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

// Access authorizes registry requests. It is safe for concurrent use.
type Access struct {
	secrets map[string][sha256.Size]byte
	dummy   [sha256.Size]byte
	log     *slog.Logger
	burst   float64
	refill  time.Duration
	now     func() time.Time

	// mu guards sources.
	mu      sync.Mutex
	sources map[string]*bucket
}

// bucket is one source's failure tokens as of at.
type bucket struct {
	tokens float64
	at     time.Time
}

// New returns an Access over cfg.Principals. It refuses a set that is not
// exactly the two named principals, each with a well-formed hash.
func New(cfg Config) (*Access, error) {
	a := &Access{
		secrets: make(map[string][sha256.Size]byte, 2),
		log:     cfg.Logger,
		burst:   float64(DefaultBurst),
		refill:  DefaultRefill,
		now:     cfg.Now,
		sources: make(map[string]*bucket),
	}
	if a.log == nil {
		a.log = slog.New(slog.DiscardHandler)
	}
	if cfg.Burst > 0 {
		a.burst = float64(cfg.Burst)
	}
	if cfg.Refill > 0 {
		a.refill = cfg.Refill
	}
	if a.now == nil {
		a.now = time.Now
	}
	for _, p := range cfg.Principals {
		if p.User != UserPush && p.User != UserGate {
			return nil, fmt.Errorf("registry auth: unknown principal %q", p.User)
		}
		if _, dup := a.secrets[p.User]; dup {
			return nil, fmt.Errorf("registry auth: principal %q given twice", p.User)
		}
		h, err := parseHash(p.SecretSHA256)
		if err != nil {
			return nil, fmt.Errorf("registry auth: principal %q: %w", p.User, err)
		}
		a.secrets[p.User] = h
	}
	for _, u := range []string{UserPush, UserGate} {
		if _, ok := a.secrets[u]; !ok {
			return nil, fmt.Errorf("registry auth: principal %q is missing", u)
		}
	}
	if _, err := rand.Read(a.dummy[:]); err != nil {
		return nil, fmt.Errorf("registry auth: %w", err)
	}
	return a, nil
}

// parseHash decodes a lowercase hex SHA-256.
func parseHash(s string) ([sha256.Size]byte, error) {
	var h [sha256.Size]byte
	if len(s) != hex.EncodedLen(sha256.Size) || strings.ToLower(s) != s {
		return h, errors.New("secret hash is not a lowercase hex SHA-256")
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, errors.New("secret hash is not a lowercase hex SHA-256")
	}
	if h == ([sha256.Size]byte{}) {
		return h, errors.New("secret hash is all zero")
	}
	return h, nil
}

// Authorize is the api.Authorizer: it decides whether r may do verb on n.
func (a *Access) Authorize(r *http.Request, verb api.Verb, n ref.Name) error {
	user, err := a.authenticate(r)
	if err != nil {
		a.log.Warn("registry request refused", "reason", reasonOf(err), "source", source(r), "method", r.Method, "path", r.URL.Path, "verb", verb.String())
		if errors.Is(err, errBadCredential) {
			return fmt.Errorf("%w: %w", api.ErrUnauthenticated, err)
		}
		return err
	}
	if permissions[user][verb] {
		return nil
	}
	if user == "" {
		a.log.Debug("registry request refused", "reason", "anonymous", "source", source(r), "method", r.Method, "path", r.URL.Path, "verb", verb.String(), "repository", n.String())
		return api.ErrUnauthenticated
	}
	a.log.Warn("registry request refused", "reason", "denied", "user", user, "source", source(r), "method", r.Method, "path", r.URL.Path, "verb", verb.String(), "repository", n.String())
	return api.ErrDenied
}

// reasonOf names a refusal for the log.
func reasonOf(err error) string {
	if errors.Is(err, api.ErrRateLimited) {
		return "rate limited"
	}
	return "bad credential"
}

// authenticate returns the verified user of r, or "" for a request without
// credentials. A presented credential is checked against the source's bucket
// first, and a failure is charged to it.
func (a *Access) authenticate(r *http.Request) (string, error) {
	hdr, present := r.Header["Authorization"]
	if !present {
		return "", nil
	}
	src := source(r)
	if !a.take(src, false) {
		return "", api.ErrRateLimited
	}
	user, ok := a.verify(hdr)
	if !ok {
		if !a.take(src, true) {
			return "", api.ErrRateLimited
		}
		return "", errBadCredential
	}
	return user, nil
}

// verify checks the Authorization header values and reports the user whose
// secret they carry. It runs the digest compare on every path that gets as far
// as a user and a secret, so a known and an unknown user cost the same.
func (a *Access) verify(hdr []string) (string, bool) {
	if len(hdr) != 1 || len(hdr[0]) > MaxAuthorizationBytes {
		return "", false
	}
	// net/http's parser: the "Basic" scheme case-insensitively, standard
	// base64, a colon between user and secret.
	r := http.Request{Header: http.Header{"Authorization": hdr}}
	user, secret, ok := r.BasicAuth()
	if !ok || user == "" || secret == "" || len(user) > MaxUserBytes || len(secret) > MaxSecretBytes {
		return "", false
	}
	want, known := a.secrets[user]
	if !known {
		want = a.dummy
	}
	got := sha256.Sum256([]byte(secret))
	match := subtle.ConstantTimeCompare(got[:], want[:]) == 1
	return user, match && known
}

// take reports whether src has a failure token. With charge it spends one;
// without, it only looks. A source not yet tracked has a full bucket, so a
// look at it always succeeds and takes no slot. Charging a new source needs a
// slot: when MaxSources are tracked, sources whose buckets have refilled are
// forgotten first, and a new source that still finds no room is refused.
func (a *Access) take(src string, charge bool) bool {
	t := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.sources[src]
	if !ok {
		if !charge {
			return true
		}
		if len(a.sources) >= MaxSources {
			a.forgetFull(t)
			if len(a.sources) >= MaxSources {
				return false
			}
		}
		b = &bucket{tokens: a.burst, at: t}
		a.sources[src] = b
	}
	a.refillAt(b, t)
	if b.tokens < 1 {
		return false
	}
	if charge {
		b.tokens--
	}
	return true
}

// refillAt brings b up to date at t.
func (a *Access) refillAt(b *bucket, t time.Time) {
	if d := t.Sub(b.at); d > 0 {
		b.tokens = min(a.burst, b.tokens+float64(d)/float64(a.refill))
		b.at = t
	}
}

// forgetFull drops every source whose bucket has refilled at t. It is called
// with mu held.
func (a *Access) forgetFull(t time.Time) {
	for k, b := range a.sources {
		a.refillAt(b, t)
		if b.tokens >= a.burst {
			delete(a.sources, k)
		}
	}
}

// source is r's RemoteAddr, host and port: the connection the request came
// on, never a header the client wrote. Keying on the connection rather than
// the host keeps one loopback client's failures off every other loopback
// client's bucket.
func source(r *http.Request) string { return r.RemoteAddr }

// NewServer returns the registry API server over cfg with a as its access
// check: it sets both cfg.Authorize and cfg.ConnClosed, so a server built
// here never keeps a closed connection's bucket. It refuses a cfg that
// already names either, so a caller cannot half-wire them. It lives here
// rather than in package api because this package imports api.
func NewServer(a *Access, cfg api.Config) (*api.Server, error) {
	if a == nil {
		return nil, errors.New("registry auth: no access check")
	}
	if cfg.Authorize != nil || cfg.ConnClosed != nil {
		return nil, errors.New("registry auth: the server config already names an authorizer or a connection hook")
	}
	cfg.Authorize = a.Authorize
	cfg.ConnClosed = a.ConnClosed
	return api.New(cfg)
}

// ConnClosed forgets the failure bucket of the connection whose remote
// address is remoteAddr. It is the api.Config ConnClosed hook: a bucket keyed
// on a connection ends with it, so a later connection the kernel gives the
// same ephemeral port does not inherit a bucket another client spent.
func (a *Access) ConnClosed(remoteAddr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sources, remoteAddr)
}
