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
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The work factors the package ships with, captured before TestMain lowers them.
var (
	shippedHashCost        = hashCost
	shippedBundleSealIters = bundleSealIters
)

// TestMain lowers the two deliberate work factors, the bcrypt cost and the
// bundle PBKDF2 count, to their minimums for this package's tests. Under the race
// detector one DefaultCost bcrypt hash or compare takes about a second and one
// 600k-iteration derivation about two, and the join tests pay several per
// request, which put the package near the per-package test timeout. No test here
// measures the work factor's cost; TestShippedWorkFactors pins the shipped values
// and that every hashing path reads them.
func TestMain(m *testing.M) {
	hashCost = bcrypt.MinCost
	bundleSealIters = bundleMinPBKDF2Iters
	os.Exit(m.Run())
}

// TestShippedWorkFactors pins the work factors production hashes and seals with,
// and that each hashing path takes its factor from the var TestMain lowers (so a
// path that hard-codes a weaker factor is caught, not masked).
func TestShippedWorkFactors(t *testing.T) {
	if shippedHashCost != bcrypt.DefaultCost {
		t.Errorf("shipped bcrypt cost = %d, want bcrypt.DefaultCost (%d)", shippedHashCost, bcrypt.DefaultCost)
	}
	if shippedBundleSealIters != bundlePBKDF2Iters {
		t.Errorf("shipped bundle seal iterations = %d, want bundlePBKDF2Iters (%d)", shippedBundleSealIters, bundlePBKDF2Iters)
	}

	hashCostOf := func(t *testing.T, h []byte) int {
		t.Helper()
		c, err := bcrypt.Cost(h)
		if err != nil {
			t.Fatalf("not a bcrypt hash: %v", err)
		}
		return c
	}
	t.Run("TokenStore", func(t *testing.T) {
		s := NewTokenStore(nil)
		user, _, _, err := s.Create(time.Hour)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		s.mu.Lock()
		h := s.byUser[user].secretHash
		s.mu.Unlock()
		if c := hashCostOf(t, h); c != hashCost {
			t.Errorf("token hash cost = %d, want hashCost (%d)", c, hashCost)
		}
	})
	t.Run("FileTokenStore", func(t *testing.T) {
		s := NewFileTokenStore(filepath.Join(t.TempDir(), BootstrapTokensFile), nil)
		user, _, _, err := s.Create(time.Hour)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		recs, err := s.load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		for _, r := range recs {
			if r.User == user {
				if c := hashCostOf(t, []byte(r.SecretHash)); c != hashCost {
					t.Errorf("file token hash cost = %d, want hashCost (%d)", c, hashCost)
				}
				return
			}
		}
		t.Fatalf("minted token %s not persisted", user)
	})
	t.Run("MemoryNodePasswords", func(t *testing.T) {
		s := NewMemoryNodePasswords()
		if err := s.Ensure(t.Context(), "node-a", "password-a"); err != nil {
			t.Fatalf("ensure: %v", err)
		}
		s.mu.Lock()
		h := s.byName["node-a"]
		s.mu.Unlock()
		if c := hashCostOf(t, h); c != hashCost {
			t.Errorf("node-password hash cost = %d, want hashCost (%d)", c, hashCost)
		}
	})
	t.Run("SealBundle", func(t *testing.T) {
		env, err := SealBundle("secret", []byte("plaintext"))
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		_, _, _, _, iters, err := parseBundle(env)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if iters != bundleSealIters {
			t.Errorf("sealed envelope records %d iterations, want bundleSealIters (%d)", iters, bundleSealIters)
		}
	})
}
