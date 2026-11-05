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

package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// IDFile is the file in the store root that holds the store id: 32 lowercase
// hex digits (128 bits from crypto/rand) and a newline. It is the one file
// the store keeps in the root that is not part of a repository's layout; zot
// and Repositories skip a regular file there.
const IDFile = ".k3sm-store-id"

// idLen is the store id's length in hex digits.
const idLen = 32

// ErrBadID is a store id file that is not a store id.
var ErrBadID = errors.New("malformed store id")

// ID returns the store id, and false when the root holds none.
func (s *Store) ID() (string, bool, error) {
	p := filepath.Join(s.root, IDFile)
	b, err := readRegular(p, idLen+2) // one byte over, so a long body reads as malformed
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read store id: %w", err)
	}
	id, ok := parseID(b)
	if !ok {
		return "", false, fmt.Errorf("%w: %s", ErrBadID, p)
	}
	return id, true, nil
}

// EnsureID returns the store id, first writing a new random one when the
// root holds none. The new id is written to a temp file in the root,
// F_FULLFSYNCed and hard-linked to IDFile, and the root is then synced, so
// IDFile is never seen partly written and an existing one is never replaced:
// of two concurrent writers, the one whose link fails returns the other's id.
func (s *Store) EnsureID() (string, error) {
	if id, ok, err := s.ID(); err != nil || ok {
		return id, err
	}
	var b [idLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint store id: %w", err)
	}
	id := hex.EncodeToString(b[:])
	err := s.writeNew(filepath.Join(s.root, IDFile), []byte(id+"\n"))
	if errors.Is(err, os.ErrExist) {
		return s.mustID()
	}
	if err != nil {
		return "", fmt.Errorf("write store id: %w", err)
	}
	return id, nil
}

// mustID is ID for a file another writer just created.
func (s *Store) mustID() (string, error) {
	id, ok, err := s.ID()
	if err == nil && !ok {
		err = fmt.Errorf("read store id: %s vanished after it was written", IDFile)
	}
	return id, err
}

// parseID returns the id in an IDFile body.
func parseID(b []byte) (string, bool) {
	if len(b) != idLen+1 || b[idLen] != '\n' {
		return "", false
	}
	for _, c := range b[:idLen] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return string(b[:idLen]), true
}

// writeNew creates p with body unless p exists, durably and atomically: a
// temp file beside p, F_FULLFSYNC, link(2) to p (which fails with an error
// wrapping os.ErrExist when p exists), directory sync. The temp file is
// removed on every return.
func (s *Store) writeNew(p string, body []byte) error {
	suffix, err := newID()
	if err != nil {
		return err
	}
	tmp := p + ".tmp-" + suffix
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }() // after a link, p keeps the inode
	_, werr := f.Write(body)
	if werr == nil {
		werr = fullSync(f)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp, p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}
