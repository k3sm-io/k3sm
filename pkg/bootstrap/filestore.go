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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// BootstrapTokensFile is the JSON file (under the server work dir) the file-backed
// token store persists to, so `k3sm token create` (a separate process) and the
// running supervisor share bootstrap-token records on a single control-plane Mac.
const BootstrapTokensFile = "bootstrap-tokens.json"

// TokensPath returns the bootstrap-token store path for a work dir.
func TokensPath(workDir string) string { return filepath.Join(workDir, BootstrapTokensFile) }

// fileToken is one persisted bootstrap-token record. The secret is stored ONLY as a
// bcrypt hash; the expiry bounds the TTL.
type fileToken struct {
	User       string    `json:"user"`
	SecretHash string    `json:"secretHash"`
	Expiry     time.Time `json:"expiry"`
}

// FileTokenStore is a file-backed TokenStore. Create appends a record and rewrites
// the file (0600); VerifyToken reloads the file each call (the file is tiny and joins
// are infrequent), so a token minted after the server started is honored. It
// satisfies TokenVerifier.
//
// Locking discipline: mu serializes the read-modify-write in Create so two
// concurrent `token create` invocations don't clobber each other within one process;
// cross-process safety on a single Mac relies on the rewrite being atomic (temp +
// rename).
type FileTokenStore struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

// NewFileTokenStore returns a file-backed token store at path. now defaults to
// time.Now.
func NewFileTokenStore(path string, now func() time.Time) *FileTokenStore {
	if now == nil {
		now = time.Now
	}
	return &FileTokenStore{path: path, now: now}
}

// Create mints a TTL-bounded bootstrap token, appends its (hashed) record, and
// returns the cleartext credential once. ttl must be positive.
func (s *FileTokenStore) Create(ttl time.Duration) (user, secret string, expiry time.Time, err error) {
	if ttl <= 0 {
		return "", "", time.Time{}, fmt.Errorf("bootstrap: token ttl must be positive, got %s", ttl)
	}
	u, err := randHex(6)
	if err != nil {
		return "", "", time.Time{}, err
	}
	sec, err := randHex(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(sec), bcrypt.DefaultCost)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("hash token secret: %w", err)
	}
	user = "boot-" + u
	expiry = s.now().Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return "", "", time.Time{}, err
	}
	recs = append(recs, fileToken{User: user, SecretHash: string(hash), Expiry: expiry})
	if err := s.save(recs); err != nil {
		return "", "", time.Time{}, err
	}
	return user, sec, expiry, nil
}

// VerifyToken parses tok and verifies its credential against an unexpired persisted
// record (constant-time bcrypt compare).
func (s *FileTokenStore) VerifyToken(tok string) error {
	t, err := ParseToken(tok)
	if err != nil {
		return err
	}
	s.mu.Lock()
	recs, err := s.load()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.User != t.User {
			continue
		}
		if !s.now().Before(r.Expiry) {
			return ErrTokenExpired
		}
		if err := bcrypt.CompareHashAndPassword([]byte(r.SecretHash), []byte(t.Secret)); err != nil {
			return ErrTokenMismatch
		}
		return nil
	}
	return ErrTokenUnknown
}

// load reads the persisted records, treating a missing file as empty.
func (s *FileTokenStore) load() ([]fileToken, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read token store: %w", err)
	}
	var recs []fileToken
	if len(b) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("decode token store: %w", err)
	}
	return recs, nil
}

// save atomically rewrites the records at 0600: a UNIQUELY named temp file in the
// store's own directory (so the rename is same-filesystem, hence atomic), then a
// rename onto the store path.
//
// The uniqueness is the load-bearing part. This store's contract is CROSS-PROCESS —
// `k3sm token create` and the running supervisor share the file, and mu serialises
// only within one process — so a fixed "<path>.tmp" gave both processes the same
// scratch file: their writes interleave in it and whichever renames second commits a
// spliced record set over the store, losing tokens or corrupting the JSON outright.
// A per-save temp name removes the shared name the two could collide on. The temp is
// removed if anything fails before the rename, so a failed save leaves no litter for
// the next one to trip over.
func (s *FileTokenStore) save(recs []fileToken) error {
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode token store: %w", err)
	}
	// CreateTemp opens with 0600 already — the records are bcrypt hashes, but the
	// store is still a credential file and must never be world-readable, not even
	// for the moment before the rename.
	f, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".tmp*")
	if err != nil {
		return fmt.Errorf("write token store: %w", err)
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write token store: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write token store: %w", err)
	}
	// The store is CROSS-USER as well as cross-process: `sudo k3sm token create`
	// runs as root while the supervisor reads the file as the service user. A
	// root-written store must therefore keep the owner the daemon reads as —
	// otherwise the 0600 mode locks the daemon out and every join 401s with
	// "read token store: permission denied" (observed live). Root adopts the
	// owner of the existing store, else of the store's directory; a non-root
	// writer changes nothing (it could not chown anyway).
	if err := adoptStoreOwner(tmp, s.path); err != nil {
		return fmt.Errorf("commit token store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("commit token store: %w", err)
	}
	committed = true
	return nil
}

// adoptStoreOwner chowns tmp to the owner of path (or path's directory when the
// store does not exist yet) when running as root. It is a no-op for a non-root
// writer. Split out so the decision is testable without privilege.
func adoptStoreOwner(tmp, path string) error {
	if geteuid() != 0 {
		return nil
	}
	ref := path
	if _, err := os.Stat(ref); err != nil {
		ref = filepath.Dir(path)
	}
	st, err := os.Stat(ref)
	if err != nil {
		return fmt.Errorf("stat owner reference %s: %w", ref, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := chown(tmp, int(sys.Uid), int(sys.Gid)); err != nil {
		return fmt.Errorf("adopt owner of %s: %w", ref, err)
	}
	return nil
}

// geteuid and chown are seams so adoptStoreOwner's decision runs under test
// without real privilege.
var (
	geteuid = os.Geteuid
	chown   = os.Chown
)
