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
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k3sm.io/k3sm/internal/atomicfile"
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
	// ErrServerSecretMismatch is returned when a joining server already holds a
	// server-bootstrap secret different from the one its server token carries.
	ErrServerSecretMismatch = errors.New("bootstrap: the recorded server-bootstrap secret differs from the server token's")
	// ErrBundlePredatesRequestHeaderCA is returned by ImportCABundle when the server
	// it fetched from sealed a schema-2 bundle, which carries no request-header CA:
	// that server runs an older release. Nothing is written. The joining server
	// waits for it to be upgraded; it never mints the CA itself.
	ErrBundlePredatesRequestHeaderCA = errors.New("bootstrap: the server you are joining from runs an older release (its bundle carries no request-header CA): upgrade the mint-authority server first")
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

// EnsureServerSecret records the server-bootstrap secret a joining server received in
// its server token, so its OWN CA-bundle endpoint can seal + serve once it is an equal
// control-plane member. It is idempotent across restarts and never replaces a secret:
//
//   - any temp file a killed earlier write left beside path is removed first
//     (atomicfile.ReapOrphans);
//   - path absent: the secret is written through atomicfile.WriteNew (0600), bare, with
//     no trailing newline;
//   - path present: it must be a regular file (a symlink or anything else is an error
//     naming path), and its trimmed content is compared with secret in constant time; a
//     difference is ErrServerSecretMismatch (the server was joined with another token,
//     and silently re-keying its bundle would break every peer that holds the old one).
//
// The secret itself never appears in an error.
func EnsureServerSecret(path, secret string) error {
	if secret == "" {
		return errors.New("bootstrap: record server-bootstrap secret: empty secret")
	}
	if err := atomicfile.ReapOrphans(filepath.Dir(path), filepath.Base(path)); err != nil {
		return fmt.Errorf("record server-bootstrap secret: %w", err)
	}
	err := checkServerSecret(path, secret)
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicfile.WriteNew(path, []byte(secret), 0o600); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("persist server-bootstrap secret: %w", err)
		}
		// Another writer won the link; the file now exists, so check against it.
		return checkServerSecret(path, secret)
	}
	return nil
}

// checkServerSecret verifies the secret recorded at path against secret: nil on a
// constant-time match, ErrServerSecretMismatch (wrapped with path and the remedy) on a
// difference, an error naming path when it is not a regular file, and an error
// satisfying errors.Is(err, os.ErrNotExist) when it is absent.
func checkServerSecret(path, secret string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return fmt.Errorf("stat server-bootstrap secret %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("bootstrap: server-bootstrap secret %s is not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read server-bootstrap secret %s: %w", path, err)
	}
	stored := strings.TrimSpace(string(b))
	if subtle.ConstantTimeCompare([]byte(stored), []byte(secret)) != 1 {
		return fmt.Errorf("%w: recorded at %s; remove it only after confirming the token is the one this cluster's servers share",
			ErrServerSecretMismatch, path)
	}
	return nil
}

// ServerAuthorizer authorizes a presented credential for the CA-bundle endpoint. Only a
// server-class token whose secret matches is authorized; a worker token is rejected.
type ServerAuthorizer interface {
	// AuthorizeServerToken returns nil iff token is a server-class join token whose
	// secret matches the server-bootstrap secret. ctx is checked eagerly and fails
	// closed: a cancelled request is denied, never authorized.
	AuthorizeServerToken(ctx context.Context, token string) error
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
//
// ctx is checked EAGERLY and fails closed (see TokenStore.VerifyToken): the
// constant-time compare stays synchronous and unwrapped.
func (s *StaticServerSecret) AuthorizeServerToken(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t, err := ParseServerToken(token)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(t.Secret), []byte(s.secret)) != 1 {
		return ErrServerTokenMismatch
	}
	return nil
}
