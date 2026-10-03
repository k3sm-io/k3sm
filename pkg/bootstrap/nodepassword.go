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
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ErrNodePasswordMismatch is returned by a NodePasswordStore when a node presents a
// password that does not match the one already bound to its name. It is the
// anti-impersonation signal: the FIRST join for a name binds the password, and a
// later join for the same name MUST present it (so a second host cannot claim an
// existing node's identity). Compare with errors.Is.
var ErrNodePasswordMismatch = errors.New("bootstrap: node-password does not match the bound password for this node")

// NodePasswordStore binds a node name to a hashed node-password with
// first-write-wins semantics. Implementations store the bcrypt hash (NEVER the
// cleartext) and compare in constant time. It is the seam the bootstrap server uses.
// In production every control-plane server wires a datastore-backed implementation
// (one Secret per node, named <node> + NodePasswordSecretSuffix) so a binding
// survives a restart; MemoryNodePasswords is the in-process implementation tests use.
type NodePasswordStore interface {
	// Ensure binds nodeName→password on first sight (storing only the hash) and on
	// every subsequent call verifies password against the bound hash, returning
	// ErrNodePasswordMismatch on a mismatch. It is safe for concurrent use.
	Ensure(ctx context.Context, nodeName, password string) error
}

// NodePasswordSecretSuffix is appended to a node name to form the name of the
// Secret a datastore-backed NodePasswordStore keeps that node's binding in (the
// k3s <node>.node-password.k3s shape).
const NodePasswordSecretSuffix = ".node-password.k3sm"

// MaxNodeNameLength is the longest node name a join may claim: the binding's
// Secret name, the node name plus NodePasswordSecretSuffix, must itself be a
// valid DNS-1123 subdomain of at most 253 characters.
const MaxNodeNameLength = validation.DNS1123SubdomainMaxLength - len(NodePasswordSecretSuffix)

// MaxNodePasswordLength is the longest node-password, in bytes, a join may
// present: bcrypt's input limit. GenerateNodePassword's are 64 hex characters.
// A longer one cannot be hashed, so the join handler refuses it as a malformed
// request before the store is asked.
const MaxNodePasswordLength = 72

// ValidateNodeName reports whether name can be bound: it must be a DNS-1123
// subdomain (the Node object's own naming rule) and short enough that its
// binding's Secret name is one too. The join handler checks it before the store
// is touched, so a name the datastore would refuse is a 400 to the caller rather
// than a datastore error.
func ValidateNodeName(name string) error {
	if len(name) > MaxNodeNameLength {
		return fmt.Errorf("node name is %d characters, longer than the %d a node-password binding allows", len(name), MaxNodeNameLength)
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("node name %q is not a valid DNS-1123 subdomain: %s", name, strings.Join(errs, "; "))
	}
	return nil
}

// GenerateNodePassword returns a fresh high-entropy node-password (32 random bytes,
// hex-encoded). A joining node mints one once, persists it locally at 0600, and
// reuses it across restarts so the first-write-wins binding keeps matching.
func GenerateNodePassword() (string, error) {
	return randHex(32)
}

// MemoryNodePasswords is an in-memory NodePasswordStore for tests and embedders.
// No server uses it in production: its bindings die with the process, so after a
// restart every name would be claimable again. Hashes are bcrypt; comparison is
// constant-time. The first password seen for a name is bound for the life of the
// store.
//
// Locking discipline: mu guards byName.
type MemoryNodePasswords struct {
	mu     sync.Mutex
	byName map[string][]byte
}

// NewMemoryNodePasswords returns an empty in-memory node-password store.
func NewMemoryNodePasswords() *MemoryNodePasswords {
	return &MemoryNodePasswords{byName: map[string][]byte{}}
}

// Ensure implements NodePasswordStore: first-write-wins bind, then constant-time
// verify on every subsequent call.
func (s *MemoryNodePasswords) Ensure(_ context.Context, nodeName, password string) error {
	if nodeName == "" || password == "" {
		return fmt.Errorf("bootstrap: node-password Ensure needs a non-empty name and password")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, bound := s.byName[nodeName]
	if !bound {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash node-password: %w", err)
		}
		s.byName[nodeName] = h
		return nil
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return ErrNodePasswordMismatch
	}
	return nil
}

// StoredHash returns the bcrypt hash bound to nodeName (test introspection: proves
// the password is stored hashed, never in cleartext).
func (s *MemoryNodePasswords) StoredHash(nodeName string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.byName[nodeName]
	return h, ok
}
