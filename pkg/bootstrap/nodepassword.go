package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// ErrNodePasswordMismatch is returned by a NodePasswordStore when a node presents a
// password that does not match the one already bound to its name. It is the
// anti-impersonation signal: the FIRST join for a name binds the password, and a
// later join for the same name MUST present it (so a second host cannot claim an
// existing node's identity). Compare with errors.Is.
var ErrNodePasswordMismatch = errors.New("bootstrap: node-password does not match the bound password for this node")

// NodePasswordStore binds a node name to a hashed node-password with
// first-write-wins semantics. Implementations store the bcrypt hash (NEVER the
// cleartext) and compare in constant time. It is the seam the bootstrap server uses;
// MemoryNodePasswords is the in-process implementation, and a kine/Secret-backed
// implementation persists across restarts in production.
type NodePasswordStore interface {
	// Ensure binds nodeName→password on first sight (storing only the hash) and on
	// every subsequent call verifies password against the bound hash, returning
	// ErrNodePasswordMismatch on a mismatch. It is safe for concurrent use.
	Ensure(ctx context.Context, nodeName, password string) error
}

// GenerateNodePassword returns a fresh high-entropy node-password (32 random bytes,
// hex-encoded). A joining node mints one once, persists it locally at 0600, and
// reuses it across restarts so the first-write-wins binding keeps matching.
func GenerateNodePassword() (string, error) {
	return randHex(32)
}

// MemoryNodePasswords is an in-memory NodePasswordStore: the tested core, and the
// fallback when no datastore-backed store is wired. Hashes are bcrypt; comparison is
// constant-time. The first password seen for a name is bound permanently.
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
