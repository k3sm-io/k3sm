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
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestTokenVerifyDoesNotRevealWhetherAnIdExists pins that both shipped
// TokenVerifiers perform exactly one bcrypt compare on every outcome (unknown
// id, known-but-expired, wrong secret, success), so response cost never
// confirms that an id exists, and that each outcome still returns its own
// sentinel. It counts compares through the compareHash seam rather than timing
// requests, so it cannot flake on a loaded host. Not parallel: it swaps a
// package var.
func TestTokenVerifyDoesNotRevealWhetherAnIdExists(t *testing.T) {
	t.Run("dummy hash is a valid bcrypt hash at DefaultCost", func(t *testing.T) {
		h := dummyTokenHash()
		cost, err := bcrypt.Cost(h)
		if err != nil {
			t.Fatalf("dummy hash is not a bcrypt hash: %v", err)
		}
		if cost != bcrypt.DefaultCost {
			t.Fatalf("dummy hash cost = %d, want bcrypt.DefaultCost (%d): an unknown id would cost differently from a known one", cost, bcrypt.DefaultCost)
		}
	})

	var mu sync.Mutex
	calls := 0
	orig := compareHash
	compareHash = func(hash, pw []byte) error {
		mu.Lock()
		calls++
		mu.Unlock()
		return orig(hash, pw)
	}
	t.Cleanup(func() { compareHash = orig })

	const caHash = "0123456789abcdef"
	type minter interface {
		TokenVerifier
		Create(ttl time.Duration) (user, secret string, expiry time.Time, err error)
	}
	stores := []struct {
		name string
		mk   func(t *testing.T, now func() time.Time) minter
	}{
		{"TokenStore", func(_ *testing.T, now func() time.Time) minter { return NewTokenStore(now) }},
		{"FileTokenStore", func(t *testing.T, now func() time.Time) minter {
			return NewFileTokenStore(filepath.Join(t.TempDir(), BootstrapTokensFile), now)
		}},
	}
	cases := []struct {
		name    string
		token   func(user, secret string) string
		advance time.Duration
		want    error
	}{
		{"known live id, wrong secret", func(u, _ string) string { return "K10" + caHash + "::" + u + ":wrong" }, 0, ErrTokenMismatch},
		{"known id, expired", func(u, s string) string { return "K10" + caHash + "::" + u + ":" + s }, 2 * time.Hour, ErrTokenExpired},
		{"unknown id", func(_, s string) string { return "K10" + caHash + "::boot-000000000000:" + s }, 0, ErrTokenUnknown},
		{"success", func(u, s string) string { return "K10" + caHash + "::" + u + ":" + s }, 0, nil},
	}
	for _, st := range stores {
		for _, tc := range cases {
			t.Run(st.name+"/"+tc.name, func(t *testing.T) {
				clock := time.Unix(1_700_000_000, 0)
				now := func() time.Time { return clock }
				s := st.mk(t, now)
				user, secret, _, err := s.Create(time.Hour)
				if err != nil {
					t.Fatalf("create: %v", err)
				}
				clock = clock.Add(tc.advance)

				mu.Lock()
				calls = 0
				mu.Unlock()
				err = s.VerifyToken(context.Background(), tc.token(user, secret))
				mu.Lock()
				got := calls
				mu.Unlock()

				if tc.want == nil && err != nil {
					t.Fatalf("VerifyToken = %v, want nil", err)
				}
				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Fatalf("VerifyToken = %v, want %v", err, tc.want)
				}
				if got != 1 {
					t.Fatalf("compareHash invoked %d times, want exactly 1: this outcome's cost differs from the others", got)
				}
			})
		}
	}
}
