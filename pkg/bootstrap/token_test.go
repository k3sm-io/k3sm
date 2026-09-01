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
	"encoding/json"
	"errors"
	"os"
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

// TestFileTokenStoreSaveDoesNotUseAFixedTempName pins the atomicity the store's
// cross-process contract rests on. `k3sm token create` and the running supervisor are
// separate processes over one file, and the store's mutex serialises neither, so a
// scratch file named for the store path alone is a name BOTH processes write into —
// their writes interleave and the second rename commits the splice.
//
// The other process is stood in for by a directory occupying that fixed name: a
// stand-in, chosen because it makes the dependency fail on every run instead of on an
// unlucky interleaving. A save that needs "<path>.tmp" cannot get past it; a save that
// picks its own name never looks at it. The test also asserts the successful save
// leaves no temp litter behind for the next one to inherit.
func TestFileTokenStoreSaveDoesNotUseAFixedTempName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, bootstrap.BootstrapTokensFile)
	store := bootstrap.NewFileTokenStore(path, nil)

	if _, _, _, err := store.Create(time.Hour); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Another process holds the name a fixed-temp implementation would reach for.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatalf("occupy the fixed temp name: %v", err)
	}

	if _, _, _, err := store.Create(time.Hour); err != nil {
		t.Fatalf("second create with the fixed temp name occupied: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the store: %v", err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatalf("the committed store is not valid JSON: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("store holds %d records, want 2 — a save was lost", len(recs))
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != bootstrap.BootstrapTokensFile && e.Name() != bootstrap.BootstrapTokensFile+".tmp" {
			t.Errorf("save left a temp file behind: %s", e.Name())
		}
	}
}
