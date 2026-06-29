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

package bootstrap

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// tokenPrefix is the K10 join-token prefix (k3s-compatible). A full token is
// K10<caHash>::<user>:<secret> — the pinned cluster-CA SHA-256 followed by the
// bootstrap credential.
const tokenPrefix = "K10"

// BootstrapUser / BootstrapGroup are the identity a join token authenticates as on
// the bootstrap endpoint. It is DELIBERATELY NOT admin / system:masters: a join
// token grants only the right to submit a node-password + CSR and receive a
// node-scoped credential, never the cluster-admin kubeconfig (docs/m3-plan.md).
const (
	BootstrapUser  = "system:k3sm-bootstrap"
	BootstrapGroup = "system:k3sm-bootstrappers"
)

// AdminUser / AdminGroup are the cluster-admin identity the executor's static token
// grants (the system:masters group). They are named here only so the join path can
// assert it never issues this identity to an agent.
const (
	AdminUser  = "admin"
	AdminGroup = "system:masters"
)

// Sentinel errors. Compare with errors.Is, never by string match.
var (
	// ErrMalformedToken is returned by ParseToken for input that is not a
	// well-formed K10<caHash>::<user>:<secret> token.
	ErrMalformedToken = errors.New("bootstrap: malformed join token")
	// ErrTokenUnknown is returned by Verify when the user has no minted token.
	ErrTokenUnknown = errors.New("bootstrap: unknown bootstrap token")
	// ErrTokenExpired is returned by Verify when the token's TTL has elapsed.
	ErrTokenExpired = errors.New("bootstrap: bootstrap token expired")
	// ErrTokenMismatch is returned by Verify when the secret does not match.
	ErrTokenMismatch = errors.New("bootstrap: bootstrap token secret mismatch")
)

// Token is a parsed K10 join token.
type Token struct {
	// CAHash is the lowercase-hex SHA-256 of the cluster CA certificate — the pin
	// the join client verifies the server's presented chain against
	// (certs.VerifyPinnedChain).
	CAHash string
	// User is the bootstrap-credential username.
	User string
	// Secret is the bootstrap-credential secret.
	Secret string
}

// FormatToken renders K10<caHash>::<user>:<secret>. caHash is the pinned cluster-CA
// SHA-256 (certs.CA.PinHash); user/secret are the bootstrap credential.
func FormatToken(caHash, user, secret string) string {
	return fmt.Sprintf("%s%s::%s:%s", tokenPrefix, caHash, user, secret)
}

// ParseToken parses a K10<caHash>::<user>:<secret> join token. The credential is
// split on its FIRST ':' (the minted secret is hex, so it carries no ':'). It errors
// (wrapping ErrMalformedToken) on any missing component.
func ParseToken(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, tokenPrefix) {
		return Token{}, fmt.Errorf("%w: missing %q prefix", ErrMalformedToken, tokenPrefix)
	}
	rest := strings.TrimPrefix(s, tokenPrefix)
	sep := strings.Index(rest, "::")
	if sep < 0 {
		return Token{}, fmt.Errorf("%w: missing '::' after CA hash", ErrMalformedToken)
	}
	caHash := rest[:sep]
	cred := rest[sep+2:]
	colon := strings.Index(cred, ":")
	if colon < 0 {
		return Token{}, fmt.Errorf("%w: credential is not user:secret", ErrMalformedToken)
	}
	t := Token{CAHash: caHash, User: cred[:colon], Secret: cred[colon+1:]}
	if t.CAHash == "" || t.User == "" || t.Secret == "" {
		return Token{}, fmt.Errorf("%w: empty CA hash, user, or secret", ErrMalformedToken)
	}
	return t, nil
}

// tokenRecord is one minted bootstrap token: the bcrypt hash of its secret (never
// the cleartext) and its expiry.
type tokenRecord struct {
	secretHash []byte
	expiry     time.Time
}

// TokenStore mints and verifies TTL-bounded bootstrap tokens. Secrets are stored
// ONLY as bcrypt hashes; Verify compares in constant time (bcrypt.CompareHashAndPassword)
// and enforces expiry. The minted identity is the BootstrapUser/BootstrapGroup —
// never the system:masters admin token.
//
// Locking discipline: mu guards byUser. now is the injected clock (tests advance it
// to assert expiry without sleeping).
type TokenStore struct {
	now func() time.Time

	mu     sync.Mutex
	byUser map[string]tokenRecord
}

// NewTokenStore returns an empty TokenStore. now defaults to time.Now when nil.
func NewTokenStore(now func() time.Time) *TokenStore {
	if now == nil {
		now = time.Now
	}
	return &TokenStore{now: now, byUser: map[string]tokenRecord{}}
}

// Create mints a bootstrap token valid for ttl. It returns the credential user, the
// cleartext secret (shown to the operator once — only its bcrypt hash is retained),
// and the expiry. ttl must be positive.
func (s *TokenStore) Create(ttl time.Duration) (user, secret string, expiry time.Time, err error) {
	if ttl <= 0 {
		return "", "", time.Time{}, fmt.Errorf("bootstrap: token ttl must be positive, got %s", ttl)
	}
	u, err := randHex(6)
	if err != nil {
		return "", "", time.Time{}, err
	}
	sec, err := randHex(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(sec), bcrypt.DefaultCost)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("hash token secret: %w", err)
	}
	user = "boot-" + u
	expiry = s.now().Add(ttl)
	s.mu.Lock()
	s.byUser[user] = tokenRecord{secretHash: hash, expiry: expiry}
	s.mu.Unlock()
	return user, sec, expiry, nil
}

// Verify checks (user, secret) against a minted, unexpired token. The secret
// comparison is constant-time (bcrypt). It returns ErrTokenUnknown, ErrTokenExpired,
// or ErrTokenMismatch on failure, nil on success.
func (s *TokenStore) Verify(user, secret string) error {
	s.mu.Lock()
	rec, ok := s.byUser[user]
	s.mu.Unlock()
	if !ok {
		return ErrTokenUnknown
	}
	if !s.now().Before(rec.expiry) {
		return ErrTokenExpired
	}
	if err := bcrypt.CompareHashAndPassword(rec.secretHash, []byte(secret)); err != nil {
		return ErrTokenMismatch
	}
	return nil
}

// VerifyToken parses tok and verifies its credential against the store (the
// convenience the server uses on the raw token string a joining node sends).
func (s *TokenStore) VerifyToken(tok string) error {
	t, err := ParseToken(tok)
	if err != nil {
		return err
	}
	return s.Verify(t.User, t.Secret)
}

// randHex returns n random bytes hex-encoded (2n hex chars).
func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
