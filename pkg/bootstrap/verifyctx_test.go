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

package bootstrap_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// Compile-shaped assertion: both credential seams take a context FIRST, matching
// their sibling interfaces in the same files (Enroller.Enroll, NodePasswordStore.Ensure,
// BundleSource.SealedBundle). Written as method EXPRESSIONS rather than method values
// on a nil interface — a method value off a nil interface panics when evaluated, which
// would make this a runtime assertion instead of a compile-time one.
var (
	_ func(bootstrap.TokenVerifier, context.Context, string) error    = bootstrap.TokenVerifier.VerifyToken
	_ func(bootstrap.ServerAuthorizer, context.Context, string) error = bootstrap.ServerAuthorizer.AuthorizeServerToken
)

// TestTokenVerifierVerifyTakesContext pins the context contract on the two
// unauthenticated-route credential checks: the ctx is examined EAGERLY, before any
// parsing or comparison, and the check FAILS CLOSED — a cancelled request is denied
// with the context error, never granted. A live ctx still accepts a valid credential,
// so the eager deny cannot be satisfied by a verifier that simply rejects everything.
func TestTokenVerifierVerifyTakesContext(t *testing.T) {
	clock := &fakeClock{now: time.Unix(2_000_000, 0)}

	// TokenStore (in-memory) — mint a token so the live-ctx row has a valid credential.
	memStore := bootstrap.NewTokenStore(clock.Now)
	memUser, memSecret, _, err := memStore.Create(time.Hour)
	if err != nil {
		t.Fatalf("mem create: %v", err)
	}
	memTok := bootstrap.FormatToken("deadbeef", memUser, memSecret)

	// FileTokenStore (on-disk) — the same, over a file.
	fileStore := bootstrap.NewFileTokenStore(filepath.Join(t.TempDir(), bootstrap.BootstrapTokensFile), clock.Now)
	fileUser, fileSecret, _, err := fileStore.Create(time.Hour)
	if err != nil {
		t.Fatalf("file create: %v", err)
	}
	fileTok := bootstrap.FormatToken("deadbeef", fileUser, fileSecret)

	verifiers := []struct {
		name  string
		verif bootstrap.TokenVerifier
		tok   string
	}{
		{"TokenStore", memStore, memTok},
		{"FileTokenStore", fileStore, fileTok},
	}
	for _, tc := range verifiers {
		t.Run(tc.name, func(t *testing.T) {
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			err := tc.verif.VerifyToken(cancelled, tc.tok)
			if err == nil {
				t.Fatal("a cancelled ctx must DENY a join: VerifyToken returned nil")
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled-ctx err = %v, want context.Canceled", err)
			}
			if err := tc.verif.VerifyToken(t.Context(), tc.tok); err != nil {
				t.Errorf("live ctx must still accept a valid token: %v", err)
			}
		})
	}

	t.Run("StaticServerSecret", func(t *testing.T) {
		const secret = "server-bootstrap-secret-0123456789abcdef"
		auth := bootstrap.NewStaticServerSecret(secret)
		tok := bootstrap.FormatServerToken("deadbeef", secret)

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		err := auth.AuthorizeServerToken(cancelled, tok)
		if err == nil {
			t.Fatal("a cancelled ctx must DENY the CA-bundle endpoint: AuthorizeServerToken returned nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled-ctx err = %v, want context.Canceled", err)
		}
		if err := auth.AuthorizeServerToken(t.Context(), tok); err != nil {
			t.Errorf("live ctx must still authorize a valid server token: %v", err)
		}
	})
}
