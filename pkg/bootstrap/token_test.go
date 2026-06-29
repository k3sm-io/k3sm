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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TestJoinTokenTTLAndNotAdmin proves k3sm token create mints TTL-bounded bootstrap
// tokens whose identity is NOT the system:masters admin token: the expiry is bounded
// by the requested TTL, an expired token is rejected, a wrong secret is rejected
// (constant-time), and the bootstrap identity is distinct from admin/system:masters.
func TestJoinTokenTTLAndNotAdmin(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_000_000, 0)}
	store := bootstrap.NewTokenStore(clock.Now)

	user, secret, expiry, err := store.Create(time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// TTL-bounded: expiry is exactly now + ttl.
	if want := clock.now.Add(time.Hour); !expiry.Equal(want) {
		t.Errorf("expiry = %s, want %s (now + ttl)", expiry, want)
	}

	// NOT the admin / system:masters identity.
	if user == bootstrap.AdminUser {
		t.Errorf("bootstrap user %q must not be the admin user", user)
	}
	if bootstrap.BootstrapGroup == bootstrap.AdminGroup {
		t.Error("bootstrap group must not equal the admin group")
	}
	if strings.Contains(bootstrap.BootstrapGroup, "system:masters") {
		t.Errorf("bootstrap group %q must not grant system:masters", bootstrap.BootstrapGroup)
	}

	// Valid now.
	if err := store.Verify(user, secret); err != nil {
		t.Errorf("verify within TTL: %v", err)
	}

	// Wrong secret rejected (constant-time bcrypt compare).
	if err := store.Verify(user, "not-the-secret"); !errors.Is(err, bootstrap.ErrTokenMismatch) {
		t.Errorf("wrong secret err = %v, want ErrTokenMismatch", err)
	}

	// Unknown user rejected.
	if err := store.Verify("boot-unknown", secret); !errors.Is(err, bootstrap.ErrTokenUnknown) {
		t.Errorf("unknown user err = %v, want ErrTokenUnknown", err)
	}

	// Expired after the TTL elapses.
	clock.now = expiry.Add(time.Second)
	if err := store.Verify(user, secret); !errors.Is(err, bootstrap.ErrTokenExpired) {
		t.Errorf("expired err = %v, want ErrTokenExpired", err)
	}

	// A non-positive TTL is refused (no never-expiring token).
	if _, _, _, err := store.Create(0); err == nil {
		t.Error("Create with ttl=0 must error")
	}
}

// TestParseToken table-tests the K10<caHash>::<user>:<secret> round-trip and the
// malformed-input rejections.
func TestParseToken(t *testing.T) {
	round := bootstrap.FormatToken("abcdef0123", "boot-1", "secrethex")
	tok, err := bootstrap.ParseToken(round)
	if err != nil {
		t.Fatalf("parse round-trip: %v", err)
	}
	if tok.CAHash != "abcdef0123" || tok.User != "boot-1" || tok.Secret != "secrethex" {
		t.Errorf("round-trip = %+v", tok)
	}

	for _, bad := range []string{
		"",
		"nope",
		"K10abcdef",           // no '::'
		"K10::user:sec",       // empty CA hash
		"K10hash::user",       // no ':' in credential
		"K10hash::user:",      // empty secret
		"plainhash::user:sec", // missing K10 prefix
	} {
		if _, err := bootstrap.ParseToken(bad); !errors.Is(err, bootstrap.ErrMalformedToken) {
			t.Errorf("ParseToken(%q) err = %v, want ErrMalformedToken", bad, err)
		}
	}
}

// TestFileTokenStoreRoundTrip proves the cross-process token store: a token minted
// by one store instance (the `k3sm token create` process) verifies through a fresh
// store over the same file (the running supervisor), and is rejected after expiry.
func TestFileTokenStoreRoundTrip(t *testing.T) {
	clock := &fakeClock{now: time.Unix(2_000_000, 0)}
	path := filepath.Join(t.TempDir(), bootstrap.BootstrapTokensFile)

	creator := bootstrap.NewFileTokenStore(path, clock.Now)
	user, secret, _, err := creator.Create(time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A different store instance over the same file verifies it (separate process).
	verifier := bootstrap.NewFileTokenStore(path, clock.Now)
	tok := bootstrap.FormatToken("deadbeef", user, secret)
	if err := verifier.VerifyToken(tok); err != nil {
		t.Errorf("verify across instances: %v", err)
	}
	if err := verifier.VerifyToken(bootstrap.FormatToken("deadbeef", user, "wrong")); !errors.Is(err, bootstrap.ErrTokenMismatch) {
		t.Errorf("wrong secret err = %v, want ErrTokenMismatch", err)
	}

	// Expired after the TTL.
	clock.now = clock.now.Add(2 * time.Hour)
	if err := verifier.VerifyToken(tok); !errors.Is(err, bootstrap.ErrTokenExpired) {
		t.Errorf("expired err = %v, want ErrTokenExpired", err)
	}
}
