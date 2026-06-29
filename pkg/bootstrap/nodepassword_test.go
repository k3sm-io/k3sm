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
	"bytes"
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TestNodePasswordHashedConstantTime proves the anti-impersonation node-password is
// stored HASHED (bcrypt, never cleartext), compared in constant time (bcrypt), and
// bound first-write-wins: the first password for a name is permanent, and a later
// mismatched password for that name is rejected.
func TestNodePasswordHashedConstantTime(t *testing.T) {
	store := bootstrap.NewMemoryNodePasswords()
	ctx := context.Background()

	const nodeA, pwA = "worker-a", "password-aaaa"
	if err := store.Ensure(ctx, nodeA, pwA); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}

	// Stored HASHED, not cleartext.
	hash, ok := store.StoredHash(nodeA)
	if !ok {
		t.Fatal("no stored hash after Ensure")
	}
	if string(hash) == pwA {
		t.Fatal("node-password stored in cleartext")
	}
	if _, err := bcrypt.Cost(hash); err != nil {
		t.Fatalf("stored value is not a bcrypt hash (so not the constant-time compare path): %v", err)
	}
	// The stored hash verifies the password via the constant-time bcrypt compare.
	if err := bcrypt.CompareHashAndPassword(hash, []byte(pwA)); err != nil {
		t.Fatalf("bcrypt compare of the bound password failed: %v", err)
	}

	// Same password re-presented: accepted.
	if err := store.Ensure(ctx, nodeA, pwA); err != nil {
		t.Errorf("re-presenting the bound password must pass: %v", err)
	}

	// First-write-wins: a different password for the same name is rejected (an
	// impostor cannot rebind an existing node's name).
	if err := store.Ensure(ctx, nodeA, "impostor-pw"); !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
		t.Errorf("mismatched password err = %v, want ErrNodePasswordMismatch", err)
	}

	// A different node binds independently, with a distinct (salted) hash.
	if err := store.Ensure(ctx, "worker-b", pwA); err != nil {
		t.Fatalf("bind second node: %v", err)
	}
	hashB, _ := store.StoredHash("worker-b")
	if bytes.Equal(hash, hashB) {
		t.Error("two nodes with the same password share a hash — bcrypt salt missing")
	}

	// A freshly generated node-password is high-entropy and non-empty.
	gen, err := bootstrap.GenerateNodePassword()
	if err != nil || len(gen) < 32 {
		t.Errorf("GenerateNodePassword = %q (len %d), err %v", gen, len(gen), err)
	}
}
