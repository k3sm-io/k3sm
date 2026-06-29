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
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Server-class bootstrap identity — DISTINCT from the worker BootstrapUser (token.go).
// A SERVER join token (K10<caHash>::server:<secret>) authorizes a joining control-plane
// server to fetch the AES-256-GCM CA bundle (reconstructing the IDENTICAL cluster +
// signing CAs), and its secret is the KDF passphrase that seals/opens that bundle. A
// WORKER token can do NEITHER: it verifies against a different store/identity, so a
// leaked worker token can NEVER reconstruct the signing CA — which would be cluster
// takeover (minting system:node:<any> / system:masters certs). This mirrors k3s's
// server-vs-agent token split.
const (
	// ServerBootstrapUser / ServerBootstrapGroup are the server-class bootstrap
	// identity, named distinct from BootstrapUser/BootstrapGroup (the worker identity)
	// so the two credential classes can never be conflated.
	ServerBootstrapUser  = "system:k3sm-server-bootstrap"
	ServerBootstrapGroup = "system:k3sm-server-bootstrappers"
	// ServerTokenUser is the literal user field of a server join token — the wire
	// marker distinguishing it from a worker token (whose user is boot-<hex>). The
	// CA-bundle endpoint accepts ONLY this class.
	ServerTokenUser = "server"
)

// Sentinel errors. Compare with errors.Is.
var (
	// ErrNotServerToken is returned when a presented token is not the server class
	// (e.g. a worker K10<caHash>::boot-...:... token offered to the CA-bundle endpoint).
	ErrNotServerToken = errors.New("bootstrap: not a server-class join token")
	// ErrServerTokenMismatch is returned when a server token's secret does not match
	// the server-bootstrap secret (constant-time compare).
	ErrServerTokenMismatch = errors.New("bootstrap: server token secret mismatch")
)

// FormatServerToken renders the server join token K10<caHash>::server:<secret>. caHash
// is the pinned cluster-CA SHA-256 (a joining server pins the supervisor's TLS chain
// just like a worker); secret is the high-entropy server-bootstrap secret.
func FormatServerToken(caHash, secret string) string {
	return FormatToken(caHash, ServerTokenUser, secret)
}

// ParseServerToken parses a server join token, returning ErrNotServerToken if the
// credential is not the server class (so a worker token is rejected before its secret
// is ever compared).
func ParseServerToken(s string) (Token, error) {
	t, err := ParseToken(s)
	if err != nil {
		return Token{}, err
	}
	if t.User != ServerTokenUser {
		return Token{}, fmt.Errorf("%w: user %q is not %q", ErrNotServerToken, t.User, ServerTokenUser)
	}
	return t, nil
}

// LoadOrCreateServerSecret reads the server-bootstrap secret persisted at path (0600),
// minting and persisting a fresh ≥256-bit one on first call (idempotent across
// restarts). The secret is MACHINE-GENERATED (not an operator passphrase) and
// high-entropy, so it is both the CA-bundle endpoint credential AND the bundle's KDF
// passphrase. It is stored cleartext at 0600 like the CA private keys it protects (the
// SEALED bundle ciphertext, not the secret, is what lives in the shared datastore).
func LoadOrCreateServerSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", fmt.Errorf("bootstrap: server-bootstrap secret at %s is empty", path)
		}
		return s, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read server-bootstrap secret: %w", err)
	}
	secret, err := randHex(32) // 256-bit, well above the ≥128-bit floor
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return "", fmt.Errorf("persist server-bootstrap secret: %w", err)
	}
	return secret, nil
}

// SaveServerSecret persists secret at path (0600). A joining server records the
// operator-provided secret (carried in its server token) so its OWN CA-bundle endpoint
// can seal + serve once it is an equal control-plane member.
func SaveServerSecret(path, secret string) error {
	if secret == "" {
		return errors.New("bootstrap: save server-bootstrap secret: empty secret")
	}
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return fmt.Errorf("persist server-bootstrap secret: %w", err)
	}
	return nil
}

// ServerAuthorizer authorizes a presented credential for the CA-bundle endpoint. Only a
// server-class token whose secret matches is authorized; a worker token is rejected.
type ServerAuthorizer interface {
	// AuthorizeServerToken returns nil iff token is a server-class join token whose
	// secret matches the server-bootstrap secret.
	AuthorizeServerToken(token string) error
}

// StaticServerSecret authorizes against a single persisted server-bootstrap secret (the
// k3s model: one stable server token, not a TTL store). Comparison is constant time.
type StaticServerSecret struct {
	secret string
}

// NewStaticServerSecret wraps the server-bootstrap secret as a ServerAuthorizer.
func NewStaticServerSecret(secret string) *StaticServerSecret {
	return &StaticServerSecret{secret: secret}
}

// AuthorizeServerToken parses token as a SERVER-class token and constant-time-compares
// its secret. A worker token (wrong user class) → ErrNotServerToken; a wrong secret →
// ErrServerTokenMismatch.
func (s *StaticServerSecret) AuthorizeServerToken(token string) error {
	t, err := ParseServerToken(token)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(t.Secret), []byte(s.secret)) != 1 {
		return ErrServerTokenMismatch
	}
	return nil
}
